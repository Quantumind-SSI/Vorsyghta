"""Secret Management API Router.

Exposes endpoints for inspecting the configured secret provider chain,
retrieving secret values (admin-only), validating that required secrets
are accessible, and requesting secret rotation where the underlying
provider supports it.

Security note: secret *values* are never logged. Only metadata such as
secret names, found/not-found status, and the provider that resolved a
secret are recorded.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from vorsyghta.security.rbac import CurrentUser, require_admin
from vorsyghta.security.secret_manager import SecretManager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/secrets", tags=["Secret Management"])


# ---------------------------------------------------------------------------
# Singleton manager
# ---------------------------------------------------------------------------
_manager: Optional[SecretManager] = None


def get_secret_manager() -> SecretManager:
    """Return the process-wide :class:`SecretManager`, building it on demand."""
    global _manager
    if _manager is None:
        _manager = SecretManager.from_env()
    return _manager


def reset_secret_manager() -> None:
    """Reset the cached manager (primarily for tests)."""
    global _manager
    _manager = None


# ---------------------------------------------------------------------------
# Response / request models
# ---------------------------------------------------------------------------
class ProviderInfo(BaseModel):
    priority: str
    name: str
    type: str
    vault_url: Optional[str] = None
    mount_path: Optional[str] = None
    region: Optional[str] = None


class ProvidersResponse(BaseModel):
    total: int
    providers: List[ProviderInfo]


class SecretResponse(BaseModel):
    name: str
    found: bool
    provider: Optional[str] = None
    # The actual value is intentionally excluded from structured responses
    # to avoid accidental leakage in logs/audit trails. Admin callers that
    # need the raw value receive it via the ``value`` field below.


class SecretValueResponse(BaseModel):
    name: str
    found: bool
    provider: Optional[str] = None
    value: Optional[str] = None


class ValidateRequest(BaseModel):
    names: List[str] = Field(..., description="Secret names to validate")


class ValidateResult(BaseModel):
    name: str
    accessible: bool
    provider: Optional[str] = None


class ValidateResponse(BaseModel):
    total: int
    accessible: int
    missing: List[str]
    results: List[ValidateResult]


class RotateResponse(BaseModel):
    name: str
    rotated: bool
    provider: Optional[str] = None
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _resolve_with_provider(
    manager: SecretManager, name: str, version: Optional[str]
) -> tuple[Optional[str], Optional[str]]:
    """Resolve a secret and report which provider satisfied the request."""
    ref = __import__(
        "vorsyghta.client_data.config", fromlist=["SecretRef"]
    ).SecretRef(name=name, version=version)
    for provider in manager.providers:
        provider_name = getattr(
            provider, "provider_name", type(provider).__name__
        )
        try:
            value = await provider.get_secret(ref)
        except Exception as exc:
            logger.warning(
                "Provider %s raised resolving %s: %s", provider_name, name, exc
            )
            continue
        if value is not None:
            return value, provider_name
    return None, None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/providers", response_model=ProvidersResponse)
async def list_providers(
    current_user: CurrentUser = Depends(require_admin),
):
    """List configured secret providers and their status (admin only)."""
    manager = get_secret_manager()
    providers = manager.list_providers()
    return ProvidersResponse(
        total=len(providers),
        providers=[ProviderInfo(**p) for p in providers],
    )


@router.get("/{name}", response_model=SecretValueResponse)
async def get_secret(
    name: str,
    version: Optional[str] = None,
    current_user: CurrentUser = Depends(require_admin),
):
    """Get a secret value (admin only).

    .. warning::
        This endpoint returns the raw secret value. Access is restricted
        to administrators and the response should be treated as highly
        sensitive.
    """
    manager = get_secret_manager()
    value, provider_name = await _resolve_with_provider(manager, name, version)
    found = value is not None
    logger.info(
        "Secret access: name=%s found=%s provider=%s requested_by=%s",
        name,
        found,
        provider_name,
        current_user.user_id,
    )
    return SecretValueResponse(
        name=name,
        found=found,
        provider=provider_name,
        value=value,
    )


@router.post("/validate", response_model=ValidateResponse)
async def validate_secrets(
    req: ValidateRequest,
    current_user: CurrentUser = Depends(require_admin),
):
    """Validate that a set of required secrets is accessible (admin only)."""
    manager = get_secret_manager()
    results: List[ValidateResult] = []
    missing: List[str] = []
    for name in req.names:
        value, provider_name = await _resolve_with_provider(manager, name, None)
        accessible = value is not None
        if not accessible:
            missing.append(name)
        results.append(
            ValidateResult(name=name, accessible=accessible, provider=provider_name)
        )
    logger.info(
        "Secret validation: total=%d accessible=%d missing=%d requested_by=%s",
        len(results),
        len(results) - len(missing),
        len(missing),
        current_user.user_id,
    )
    return ValidateResponse(
        total=len(results),
        accessible=len(results) - len(missing),
        missing=missing,
        results=results,
    )


@router.post("/rotate/{name}", response_model=RotateResponse)
async def rotate_secret(
    name: str,
    current_user: CurrentUser = Depends(require_admin),
):
    """Request rotation of a secret (admin only).

    Rotation is delegated to the underlying provider. Not all providers
    support rotation; in that case ``rotated`` is ``False`` and a
    descriptive ``message`` is returned.
    """
    manager = get_secret_manager()
    # Find the provider that owns the secret, if any.
    _, provider_name = await _resolve_with_provider(manager, name, None)

    target_provider = None
    for provider in manager.providers:
        pname = getattr(provider, "provider_name", type(provider).__name__)
        if pname == provider_name:
            target_provider = provider
            break

    if target_provider is None:
        return RotateResponse(
            name=name,
            rotated=False,
            provider=None,
            message="Secret not found in any provider; nothing to rotate",
        )

    rotate_fn = getattr(target_provider, "rotate_secret", None)
    if not callable(rotate_fn):
        return RotateResponse(
            name=name,
            rotated=False,
            provider=provider_name,
            message=f"Provider '{provider_name}' does not support rotation",
        )

    try:
        result = await rotate_fn(name)  # type: ignore[operator]
    except Exception as exc:
        logger.warning(
            "Secret rotation failed: name=%s provider=%s error=%s",
            name,
            provider_name,
            exc,
        )
        return RotateResponse(
            name=name,
            rotated=False,
            provider=provider_name,
            message=f"Rotation failed: {exc}",
        )

    rotated = bool(result)
    logger.info(
        "Secret rotation: name=%s provider=%s rotated=%s requested_by=%s",
        name,
        provider_name,
        rotated,
        current_user.user_id,
    )
    return RotateResponse(
        name=name,
        rotated=rotated,
        provider=provider_name,
        message="Rotation requested" if rotated else "Rotation not performed",
    )
