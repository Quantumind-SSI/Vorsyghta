"""SSO API router for Vorsyghta.

Exposes endpoints for discovering configured SSO providers, initiating
the login flow with an identity provider, and exchanging the provider's
response for a Vorsyghta JWT (via :mod:`vorsyghta.security.sso_bridge`).

Endpoints
---------
* ``GET  /api/sso/providers``           — list configured SSO providers
* ``GET  /api/sso/{provider}/authorize`` — get the IdP authorization URL
* ``POST /api/sso/{provider}/callback``  — exchange code/SAMLResponse for JWT
* ``GET  /api/sso/{provider}/metadata``  — SP metadata (SAML only)

Owner: Ibrahim Hassan — Blue Team (Foundation)
"""
from __future__ import annotations

import logging
import secrets
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from vorsyghta.core.audit_logger import (
    AuditCategory,
    AuditSeverity,
    get_audit_logger,
)
from vorsyghta.security.sso import (
    SAMLProvider,
    SSOProvider,
    get_configured_providers,
)
from vorsyghta.security.sso_bridge import SSOBridge, SSOTokenResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/sso", tags=["sso"])


# ===========================================================================
# Request / response models
# ===========================================================================

class SSOProviderInfo(BaseModel):
    """Public descriptor of a configured SSO provider."""

    name: str
    type: str  # oidc | saml
    authorization_url: Optional[str] = None


class SSOProvidersResponse(BaseModel):
    providers: List[SSOProviderInfo]
    total: int


class SSOAuthorizeResponse(BaseModel):
    provider: str
    authorization_url: str
    state: str


class SSOCallbackRequest(BaseModel):
    """Body for the SSO callback endpoint.

    For OIDC this carries the ``code`` returned by the IdP; for SAML it
    carries the base64-encoded ``SAMLResponse``.
    """

    code: Optional[str] = Field(
        None, description="OIDC authorization code or base64 SAMLResponse"
    )
    saml_response: Optional[str] = Field(
        None, description="Alternative field for a SAML response"
    )
    state: Optional[str] = Field(None, description="Opaque state value")


class SSOMetadataResponse(BaseModel):
    """SAML Service Provider metadata."""

    entity_id: str
    acs_url: str
    metadata_xml: str


# ===========================================================================
# Provider / bridge singletons (built lazily from env vars)
# ===========================================================================

_providers: Optional[Dict[str, SSOProvider]] = None
_bridge: Optional[SSOBridge] = None


def _get_providers() -> Dict[str, SSOProvider]:
    global _providers
    if _providers is None:
        _providers = get_configured_providers()
    return _providers


def _get_bridge() -> SSOBridge:
    global _bridge
    if _bridge is None:
        _bridge = SSOBridge()
    return _bridge


def _get_provider(name: str) -> SSOProvider:
    providers = _get_providers()
    provider = providers.get(name)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SSO provider '{name}' is not configured. "
            f"Available: {list(providers) or 'none'}",
        )
    return provider


def _provider_type(provider: SSOProvider) -> str:
    return "saml" if isinstance(provider, SAMLProvider) else "oidc"


# ===========================================================================
# Endpoints
# ===========================================================================

@router.get("/providers", response_model=SSOProvidersResponse)
async def list_providers() -> SSOProvidersResponse:
    """List all configured SSO providers."""
    providers = _get_providers()
    infos = [
        SSOProviderInfo(name=name, type=_provider_type(provider))
        for name, provider in providers.items()
    ]
    return SSOProvidersResponse(providers=infos, total=len(infos))


@router.get("/{provider}/authorize", response_model=SSOAuthorizeResponse)
async def authorize(
    provider: str,
    redirect_url: Optional[str] = Query(
        None, description="Optional final redirect URL after SSO completes"
    ),
) -> SSOAuthorizeResponse:
    """Return the IdP authorization URL the client should redirect to.

    A fresh opaque ``state`` value is generated and returned alongside the
    URL.  The client should persist this state (e.g. in a cookie) and
    include it in the subsequent callback request so the server can
    mitigate CSRF.
    """
    sso_provider = _get_provider(provider)
    state = secrets.token_urlsafe(24)
    try:
        url = sso_provider.get_authorization_url(state)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to build SSO authorization URL for %s: %s", provider, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not build authorization URL for provider '{provider}': {exc}",
        ) from exc
    return SSOAuthorizeResponse(provider=provider, authorization_url=url, state=state)


@router.post("/{provider}/callback", response_model=SSOTokenResponse)
async def callback(
    provider: str,
    body: SSOCallbackRequest,
) -> SSOTokenResponse:
    """Exchange an authorization code / SAML response for a Vorsyghta JWT."""
    sso_provider = _get_provider(provider)

    # Determine the payload to exchange.
    code = body.code or body.saml_response
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must include 'code' (OIDC) or 'saml_response' (SAML).",
        )

    try:
        sso_user = await sso_provider.exchange_code(code)
    except Exception as exc:  # noqa: BLE001
        logger.error("SSO exchange failed for provider %s: %s", provider, exc)
        audit = get_audit_logger()
        audit.log(
            "sso.callback.failed",
            category=AuditCategory.AUTHENTICATION,
            severity=AuditSeverity.WARNING,
            actor={"provider": provider},
            description=f"SSO callback exchange failed: {exc}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"SSO authentication failed: {exc}",
        ) from exc

    bridge = _get_bridge()
    try:
        token_response = await bridge.authenticate(sso_user)
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        logger.error("SSO bridge authenticate failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not complete SSO authentication: {exc}",
        ) from exc

    # Audit log: successful SSO login
    audit = get_audit_logger()
    audit.log(
        "sso.login.success",
        category=AuditCategory.AUTHENTICATION,
        severity=AuditSeverity.INFO,
        actor={
            "email": sso_user.email,
            "user_id": token_response.user_id,
            "provider": provider,
        },
        context={
            "tenant_id": token_response.tenant_id,
            "role": token_response.role,
            "external_id": sso_user.external_id,
        },
        description=f"SSO login: {sso_user.email} via {provider}",
    )

    return token_response


@router.get("/{provider}/metadata", response_model=SSOMetadataResponse)
async def metadata(provider: str) -> SSOMetadataResponse:
    """Return SAML Service Provider metadata (only valid for SAML providers)."""
    sso_provider = _get_provider(provider)
    if not isinstance(sso_provider, SAMLProvider):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Metadata is only available for SAML providers (provider "
            f"'{provider}' is type '{_provider_type(sso_provider)}').",
        )
    config = sso_provider.config
    return SSOMetadataResponse(
        entity_id=config.entity_id,
        acs_url=config.acs_url,
        metadata_xml=_build_sp_metadata(config),
    )


# ===========================================================================
# Helpers
# ===========================================================================

def _build_sp_metadata(config: Any) -> str:
    """Build a minimal SAML 2.0 SP metadata XML document."""
    from datetime import datetime, timezone

    valid_until = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cert_block = ""
    if config.sp_certificate:
        # Strip header/footer and whitespace for inclusion in the descriptor.
        cert = config.sp_certificate
        cert = cert.replace("-----BEGIN CERTIFICATE-----", "").replace(
            "-----END CERTIFICATE-----", ""
        ).strip().replace("\n", "").replace("\r", "")
        cert_block = (
            f'<KeyDescriptor use="signing">'
            f'<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f'<ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate>'
            f'</ds:X509Data></ds:KeyInfo></KeyDescriptor>'
        )
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{config.entity_id}" validUntil="{valid_until}">'
        f'<SPSSODescriptor protocolSupportEnumeration='
        f'"urn:oasis:names:tc:SAML:2.0:protocol">'
        f'{cert_block}'
        f'<NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        f'</NameIDFormat>'
        f'<AssertionConsumerService '
        f'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{config.acs_url}" index="0" isDefault="true"/>'
        f'</SPSSODescriptor>'
        f'</EntityDescriptor>'
    )


__all__ = ["router"]
