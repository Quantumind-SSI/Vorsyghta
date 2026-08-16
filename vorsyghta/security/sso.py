"""Single Sign-On (SSO) provider abstractions for Vorsyghta.

This module defines an abstract :class:`SSOProvider` interface plus two
concrete implementations:

* :class:`OIDCProvider` — OpenID Connect (Authorization Code flow) using
  the issuer's ``.well-known/openid-configuration`` discovery document.
* :class:`SAMLProvider` — SAML 2.0 Service Provider that builds
  ``AuthnRequest`` messages and parses SAML responses.

Both implementations return a normalised :class:`SSOUserInfo` object that
the :mod:`vorsyghta.security.sso_bridge` module converts into a Vorsyghta
JWT (see :mod:`vorsyghta.security.rbac`).

Owner: Ibrahim Hassan — Blue Team (Foundation)
"""
from __future__ import annotations

import base64
import logging
import os
import secrets
import zlib
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse
from xml.etree import ElementTree as ET

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SAML namespace map (used for XML parsing / generation)
# ---------------------------------------------------------------------------

_SAML_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

# Register prefixes so generated XML uses the conventional prefixes.
for _prefix, _uri in _SAML_NS.items():
    ET.register_namespace(_prefix, _uri)


# ===========================================================================
# Configuration models
# ===========================================================================

class OIDCConfig(BaseModel):
    """Configuration for an OpenID Connect provider."""

    client_id: str
    client_secret: str
    redirect_uri: str
    issuer_url: str
    scopes: List[str] = Field(default_factory=lambda: ["openid", "email", "profile"])


class SAMLConfig(BaseModel):
    """Configuration for a SAML 2.0 Service Provider."""

    entity_id: str
    acs_url: str
    idp_metadata_url: str
    sp_private_key: Optional[str] = None
    sp_certificate: Optional[str] = None


# ===========================================================================
# Normalised user info
# ===========================================================================

class SSOUserInfo(BaseModel):
    """Normalised user information returned by every SSO provider."""

    provider: str  # oidc, saml, azure-ad, google, okta
    external_id: str  # user ID from the provider
    email: str
    display_name: Optional[str] = None
    groups: List[str] = Field(default_factory=list)
    raw_claims: Dict[str, Any] = Field(default_factory=dict)


# ===========================================================================
# Abstract provider
# ===========================================================================

class SSOProvider(ABC):
    """Abstract base class for all SSO providers."""

    @abstractmethod
    def get_authorization_url(self, state: str) -> str:
        """Return the URL the user should be redirected to for authentication."""

    @abstractmethod
    async def exchange_code(self, code: str) -> SSOUserInfo:
        """Exchange an authorisation code / SAML response for user info."""

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the provider name (e.g. ``oidc``, ``saml``)."""


# ===========================================================================
# OpenID Connect provider
# ===========================================================================

class OIDCProvider(SSOProvider):
    """OpenID Connect provider using the Authorization Code flow.

    Endpoints are discovered from the issuer's
    ``.well-known/openid-configuration`` document on first use and cached.
    """

    def __init__(self, config: OIDCConfig) -> None:
        self.config = config
        self._discovery: Optional[Dict[str, Any]] = None

    # -- public API ---------------------------------------------------------

    def get_provider_name(self) -> str:
        return "oidc"

    def get_authorization_url(self, state: str) -> str:
        """Build the OIDC authorization endpoint URL."""
        auth_endpoint = self._discovery_get("authorization_endpoint")
        if not auth_endpoint:
            raise RuntimeError(
                "OIDC discovery document did not contain 'authorization_endpoint'"
            )
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": state,
        }
        sep = "&" if "?" in auth_endpoint else "?"
        return f"{auth_endpoint}{sep}{urlencode(params)}"

    async def exchange_code(self, code: str) -> SSOUserInfo:
        """Exchange an authorization code for tokens, then call userinfo."""
        token_endpoint = self._discovery_get("token_endpoint")
        userinfo_endpoint = self._discovery_get("userinfo_endpoint")
        if not token_endpoint:
            raise RuntimeError(
                "OIDC discovery document did not contain 'token_endpoint'"
            )

        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            token_resp = await client.post(
                token_endpoint,
                data=token_data,
                headers={"Accept": "application/json"},
            )
            token_resp.raise_for_status()
            token_json = token_resp.json()

        access_token = token_json.get("access_token")
        id_token = token_json.get("id_token")
        if not access_token and not id_token:
            raise RuntimeError("OIDC token response missing access_token and id_token")

        # Decode the id_token (without verification — the bridge trusts the
        # IdP) to extract claims.  Falls back to the userinfo endpoint.
        claims: Dict[str, Any] = {}
        if id_token:
            claims = _decode_jwt_unverified(id_token)

        if userinfo_endpoint and access_token:
            async with httpx.AsyncClient(timeout=30.0) as client:
                ui_resp = await client.get(
                    userinfo_endpoint,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json",
                    },
                )
                if ui_resp.status_code == 200:
                    claims = {**claims, **ui_resp.json()}

        return self._claims_to_user_info(claims)

    # -- helpers ------------------------------------------------------------

    def _discovery_get(self, key: str) -> Optional[str]:
        return self._ensure_discovery().get(key)

    def _ensure_discovery(self) -> Dict[str, Any]:
        if self._discovery is not None:
            return self._discovery
        # Synchronous discovery is acceptable here — it happens once at
        # startup / first request and is cached for the process lifetime.
        well_known = self.config.issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        try:
            resp = httpx.get(well_known, timeout=30.0)
            resp.raise_for_status()
            self._discovery = resp.json()
            logger.info("OIDC discovery loaded from %s", well_known)
        except Exception as exc:  # noqa: BLE001
            logger.error("OIDC discovery failed for %s: %s", well_known, exc)
            self._discovery = {}
        return self._discovery

    def _claims_to_user_info(self, claims: Dict[str, Any]) -> SSOUserInfo:
        external_id = (
            claims.get("sub")
            or claims.get("oid")  # Azure AD
            or claims.get("user_id")
            or ""
        )
        email = (
            claims.get("email")
            or claims.get("email_address")
            or claims.get("preferred_username")
            or ""
        )
        display_name = (
            claims.get("name")
            or claims.get("display_name")
            or claims.get("nickname")
        )
        groups = _extract_groups(claims)
        return SSOUserInfo(
            provider=self.get_provider_name(),
            external_id=str(external_id),
            email=str(email),
            display_name=display_name,
            groups=groups,
            raw_claims=claims,
        )


# ===========================================================================
# SAML 2.0 provider
# ===========================================================================

class SAMLProvider(SSOProvider):
    """SAML 2.0 Service Provider.

    Builds a SAML ``AuthnRequest`` (base64 + deflate encoded) and parses
    SAML responses using the standard library ``xml.etree.ElementTree``.

    NOTE: This implementation does not perform XML signature verification.
    In production, signed assertions should be validated against the IdP's
    signing certificate.  The ``sp_private_key`` / ``sp_certificate`` are
    accepted for future use (e.g. signing AuthnRequests).
    """

    def __init__(self, config: SAMLConfig) -> None:
        self.config = config
        self._idp_sso_url: Optional[str] = None

    # -- public API ---------------------------------------------------------

    def get_provider_name(self) -> str:
        return "saml"

    def get_authorization_url(self, state: str) -> str:
        """Generate a SAML AuthnRequest and return the redirect URL."""
        sso_url = self._get_idp_sso_url()
        request_xml = self._build_authn_request(state)
        encoded = _encode_saml_request(request_xml)
        params = {"SAMLRequest": encoded, "RelayState": state}
        sep = "&" if "?" in sso_url else "?"
        return f"{sso_url}{sep}{urlencode(params)}"

    async def exchange_code(self, code: str) -> SSOUserInfo:
        """Parse a base64-encoded SAML response and extract attributes.

        ``code`` here is the raw (or base64-encoded) SAML response returned
        by the IdP to the Assertion Consumer Service URL.
        """
        xml_bytes = _decode_saml_response(code)
        return self._parse_saml_response(xml_bytes)

    # -- helpers ------------------------------------------------------------

    def _get_idp_sso_url(self) -> str:
        if self._idp_sso_url:
            return self._idp_sso_url
        url = self.config.idp_metadata_url
        try:
            resp = httpx.get(url, timeout=30.0)
            resp.raise_for_status()
            self._idp_sso_url = _parse_idp_sso_url(resp.text)
            logger.info("SAML IdP SSO URL loaded from %s", url)
        except Exception as exc:  # noqa: BLE001
            logger.error("SAML IdP metadata fetch failed for %s: %s", url, exc)
            self._idp_sso_url = ""
        if not self._idp_sso_url:
            raise RuntimeError("Could not determine IdP SingleSignOnService URL")
        return self._idp_sso_url

    def _build_authn_request(self, state: str) -> str:
        """Build a SAML 2.0 AuthnRequest XML string."""
        request_id = "_" + secrets.token_hex(16)
        issue_instant = _saml_timestamp()
        sso_url = self._get_idp_sso_url()

        xml = (
            f'<samlp:AuthnRequest '
            f'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'ID="{request_id}" '
            f'Version="2.0" '
            f'IssueInstant="{issue_instant}" '
            f'Destination="{sso_url}" '
            f'AssertionConsumerServiceURL="{self.config.acs_url}" '
            f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
            f'<saml:Issuer>{_xml_escape(self.config.entity_id)}</saml:Issuer>'
            f'<samlp:NameIDPolicy AllowCreate="true" '
            f'Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>'
            f'<samlp:RequestedAuthnContext Comparison="minimum">'
            f'<saml:AuthnContextClassRef>'
            f'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
            f'</saml:AuthnContextClassRef>'
            f'</samlp:RequestedAuthnContext>'
            f'</samlp:AuthnRequest>'
        )
        return xml

    def _parse_saml_response(self, xml_bytes: bytes) -> SSOUserInfo:
        """Extract user info from a SAML response document."""
        root = ET.fromstring(xml_bytes)
        # Strip namespaces for easier querying.
        attrs = _saml_attributes(root)
        name_id = _saml_name_id(root)

        email = (
            attrs.get("email")
            or attrs.get("emailaddress")
            or attrs.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
            or name_id
            or ""
        )
        external_id = (
            attrs.get("subject")
            or attrs.get("nameidentifier")
            or attrs.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")
            or name_id
            or email
            or ""
        )
        display_name = (
            attrs.get("displayname")
            or attrs.get("cn")
            or attrs.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
        )
        groups = _saml_groups(attrs)

        raw_claims: Dict[str, Any] = dict(attrs)
        raw_claims["_name_id"] = name_id

        return SSOUserInfo(
            provider=self.get_provider_name(),
            external_id=str(external_id),
            email=str(email),
            display_name=display_name,
            groups=groups,
            raw_claims=raw_claims,
        )


# ===========================================================================
# Provider registry (built from environment variables)
# ===========================================================================

def get_configured_providers() -> Dict[str, SSOProvider]:
    """Build and return the set of SSO providers configured via env vars.

    Recognised environment variables:

    OIDC:
        OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI,
        OIDC_ISSUER_URL, OIDC_SCOPES (comma-separated, optional)

    SAML:
        SAML_ENTITY_ID, SAML_ACS_URL, SAML_IDP_METADATA_URL,
        SAML_SP_PRIVATE_KEY (optional), SAML_SP_CERTIFICATE (optional)
    """
    providers: Dict[str, SSOProvider] = {}

    # OIDC
    oidc_client_id = os.getenv("OIDC_CLIENT_ID")
    oidc_client_secret = os.getenv("OIDC_CLIENT_SECRET", "")
    oidc_issuer = os.getenv("OIDC_ISSUER_URL")
    if oidc_client_id and oidc_issuer:
        scopes_raw = os.getenv("OIDC_SCOPES", "openid,email,profile")
        providers["oidc"] = OIDCProvider(OIDCConfig(
            client_id=oidc_client_id,
            client_secret=oidc_client_secret,
            redirect_uri=os.getenv(
                "OIDC_REDIRECT_URI",
                "http://localhost:8000/api/sso/oidc/callback",
            ),
            issuer_url=oidc_issuer,
            scopes=[s.strip() for s in scopes_raw.split(",") if s.strip()],
        ))

    # SAML
    saml_entity_id = os.getenv("SAML_ENTITY_ID")
    saml_acs_url = os.getenv("SAML_ACS_URL")
    saml_idp_metadata = os.getenv("SAML_IDP_METADATA_URL")
    if saml_entity_id and saml_acs_url and saml_idp_metadata:
        providers["saml"] = SAMLProvider(SAMLConfig(
            entity_id=saml_entity_id,
            acs_url=saml_acs_url,
            idp_metadata_url=saml_idp_metadata,
            sp_private_key=os.getenv("SAML_SP_PRIVATE_KEY"),
            sp_certificate=os.getenv("SAML_SP_CERTIFICATE"),
        ))

    return providers


# ===========================================================================
# Internal helpers
# ===========================================================================

def _decode_jwt_unverified(token: str) -> Dict[str, Any]:
    """Decode a JWT's payload without signature verification."""
    try:
        from jose import jwt as _jwt
        return _jwt.get_unverified_claims(token) or {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to decode JWT claims: %s", exc)
        # Manual fallback: split and base64-decode the payload segment.
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return {}
            payload_b64 = parts[1]
            # Add padding if necessary.
            payload_b64 += "=" * (-len(payload_b64) % 4)
            import json
            return json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception:
            return {}


def _extract_groups(claims: Dict[str, Any]) -> List[str]:
    """Extract group memberships from OIDC claims (handles multiple schemas)."""
    for key in ("groups", "group", "roles", "member_of", "memberOf"):
        value = claims.get(key)
        if isinstance(value, list):
            return [str(g) for g in value]
        if isinstance(value, str):
            return [value]
    return []


def _encode_saml_request(xml: str) -> str:
    """Deflate + base64-encode a SAML request (HTTP-Redirect binding)."""
    compressed = zlib.compress(xml.encode("utf-8"))[2:-4]  # raw deflate
    return base64.b64encode(compressed).decode("ascii")


def _decode_saml_response(raw: str) -> bytes:
    """Base64-decode a SAML response.  Pass through if already XML."""
    stripped = raw.strip()
    if stripped.startswith("<"):
        return stripped.encode("utf-8")
    # Add padding if necessary.
    padded = stripped + "=" * (-len(stripped) % 4)
    return base64.b64decode(padded)


def _saml_timestamp() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _localname(tag: str) -> str:
    """Return the local part of an XML tag (strip namespace)."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _parse_idp_sso_url(metadata_xml: str) -> str:
    """Extract the IdP SingleSignOnService (Redirect) URL from metadata."""
    root = ET.fromstring(metadata_xml)
    for elem in root.iter():
        if _localname(elem.tag) != "SingleSignOnService":
            continue
        binding = elem.get("Binding", "")
        if "HTTP-Redirect" in binding:
            return elem.get("Location", "")
    # Fall back to the first SingleSignOnService found.
    for elem in root.iter():
        if _localname(elem.tag) == "SingleSignOnService":
            return elem.get("Location", "")
    return ""


def _saml_name_id(root: ET.Element) -> Optional[str]:
    """Find the NameID value inside a SAML response."""
    for elem in root.iter():
        if _localname(elem.tag) == "NameID":
            return (elem.text or "").strip() or None
    return None


def _saml_attributes(root: ET.Element) -> Dict[str, str]:
    """Collect all AttributeStatement Attribute values into a dict.

    Multi-valued attributes are joined with a comma for the simple dict
    view; the raw list is preserved in :meth:`SAMLProvider._parse_saml_response`
    via the groups extraction.
    """
    attrs: Dict[str, str] = {}
    for elem in root.iter():
        if _localname(elem.tag) != "Attribute":
            continue
        name = elem.get("Name")
        if not name:
            continue
        values = []
        for child in elem:
            if _localname(child.tag) == "AttributeValue" and child.text:
                values.append(child.text.strip())
        if values:
            attrs[name] = values[0] if len(values) == 1 else ",".join(values)
            # Preserve multi-valued form for group extraction.
            if len(values) > 1:
                attrs[f"{name}__list"] = ",".join(values)
    return attrs


def _saml_groups(attrs: Dict[str, str]) -> List[str]:
    """Extract group memberships from SAML attributes."""
    for key in (
        "groups",
        "group",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
        "memberOf",
        "member_of",
        "roles",
    ):
        if key in attrs:
            raw = attrs[key]
            if raw:
                return [g.strip() for g in raw.split(",") if g.strip()]
    return []


__all__ = [
    "SSOProvider",
    "SSOUserInfo",
    "OIDCConfig",
    "SAMLConfig",
    "OIDCProvider",
    "SAMLProvider",
    "get_configured_providers",
]
