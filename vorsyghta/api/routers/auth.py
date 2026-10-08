"""Database-authoritative authentication endpoints for Vorsyghta."""

from __future__ import annotations

import hashlib
import logging
import os
from uuid import uuid4

from anyio import to_thread
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from redis.exceptions import RedisClusterException, RedisError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from vorsyghta.core.audit_logger import AuditCategory, AuditSeverity, get_audit_logger
from vorsyghta.core.redis_client import get_redis_client
from vorsyghta.db.models.auth import TenantRecord, UserRecord
from vorsyghta.db.session import get_session_dep
from vorsyghta.security.rbac import (
    CurrentUser,
    Role,
    create_access_token,
    get_current_user,
    get_password_hash,
    verify_password,
)


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_AUTH_RATE_LIMITS = {
    "login": (10, 300, 300),
    "register": (3, 3600, 60),
}
_RATE_LIMIT_SCRIPT = """
local identity_count = redis.call('INCR', KEYS[1])
if identity_count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
if identity_count > tonumber(ARGV[2]) then
  return {identity_count, -1}
end
local global_count = redis.call('INCR', KEYS[2])
if global_count == 1 then
  redis.call('EXPIRE', KEYS[2], ARGV[1])
end
return {identity_count, global_count}
"""


class RegisterRequest(BaseModel):
    """Create one isolated tenant and its initial viewer account."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(max_length=254)
    password: str = Field(min_length=12, max_length=72)
    organization_name: str = Field(min_length=2, max_length=120)

    @field_validator("organization_name")
    @classmethod
    def normalize_organization_name(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if len(normalized) < 2:
            raise ValueError("Organization name must contain at least 2 characters")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_password_bytes(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must not exceed 72 UTF-8 bytes")
        return value


class RegisterResponse(BaseModel):
    message: str = "User registered"
    tenant_id: str
    user_id: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str
    tenant_id: str


def _normalize_email(value: str) -> str:
    return value.strip().lower()


async def _enforce_auth_rate_limit(action: str, email: str) -> None:
    """Apply shared global and per-email limits to public identity endpoints."""
    per_identity_limit, window_seconds, global_limit = _AUTH_RATE_LIMITS[action]
    deployed = os.getenv("ENVIRONMENT", "development").strip().lower() in {
        "staging",
        "production",
    }
    client = await to_thread.run_sync(get_redis_client)
    if client is None:
        if deployed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication rate limiting is unavailable",
            )
        return

    identity = hashlib.sha256(email.encode("utf-8")).hexdigest()
    cluster_slot = f"{{auth:{action}}}"

    def consume() -> tuple[int, int]:
        result = client.eval(
            _RATE_LIMIT_SCRIPT,
            2,
            f"vorsyghta:{cluster_slot}:identity:{identity}",
            f"vorsyghta:{cluster_slot}:global",
            window_seconds,
            per_identity_limit,
        )
        if not isinstance(result, (list, tuple)) or len(result) != 2:
            raise RedisError("Unexpected rate-limit response")
        return int(result[0]), int(result[1])

    try:
        identity_count, global_count = await to_thread.run_sync(consume)
    except (RedisError, RedisClusterException) as exc:
        if deployed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication rate limiting is unavailable",
            ) from exc
        return

    if identity_count > per_identity_limit or global_count > global_limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts",
            headers={"Retry-After": str(window_seconds)},
        )


async def _create_tenant_and_user(
    session: AsyncSession,
    *,
    email: str,
    hashed_password: str,
    organization_name: str,
) -> tuple[str, str]:
    """Insert a tenant and viewer in the caller's transaction."""
    tenant_id = f"tenant_{uuid4().hex}"
    user_id = f"user_{uuid4().hex}"
    session.add(
        TenantRecord(
            tenant_id=tenant_id,
            name=organization_name,
            is_active=True,
        )
    )
    session.add(
        UserRecord(
            user_id=user_id,
            tenant_id=tenant_id,
            email=email,
            hashed_password=hashed_password,
            role=Role.VIEWER.value,
            is_active=True,
        )
    )
    await session.flush()
    return tenant_id, user_id


async def _load_login_identity(session: AsyncSession, email: str) -> tuple[UserRecord, TenantRecord] | None:
    result = await session.execute(
        select(UserRecord, TenantRecord)
        .join(TenantRecord, TenantRecord.tenant_id == UserRecord.tenant_id)
        .where(func.lower(UserRecord.email) == email)
    )
    row = result.one_or_none()
    return (row[0], row[1]) if row else None


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    session: AsyncSession = Depends(get_session_dep),
) -> RegisterResponse:
    """Atomically create a unique tenant and its initial viewer account."""
    email = _normalize_email(str(request.email))
    await _enforce_auth_rate_limit("register", email)
    try:
        tenant_id, user_id = await _create_tenant_and_user(
            session,
            email=email,
            hashed_password=get_password_hash(request.password),
            organization_name=request.organization_name,
        )
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=409, detail="Email is already registered") from exc
    except SQLAlchemyError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Identity storage is temporarily unavailable",
        ) from exc

    get_audit_logger().log(
        "auth.register.success",
        category=AuditCategory.AUTHENTICATION,
        severity=AuditSeverity.INFO,
        actor={"email": email, "user_id": user_id},
        context={"tenant_id": tenant_id, "role": Role.VIEWER.value},
        description="Tenant owner account registered",
    )
    return RegisterResponse(tenant_id=tenant_id, user_id=user_id)


@router.post("/token", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session_dep),
) -> TokenResponse:
    """Issue a short-lived token from current PostgreSQL identity state."""
    email = _normalize_email(form_data.username)
    await _enforce_auth_rate_limit("login", email)
    try:
        identity = await _load_login_identity(session, email)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Identity storage is temporarily unavailable",
        ) from exc

    user, tenant = identity if identity else (None, None)
    if (
        user is None
        or tenant is None
        or not user.is_active
        or not tenant.is_active
        or not verify_password(form_data.password, user.hashed_password)
    ):
        get_audit_logger().log(
            "auth.login.failed",
            category=AuditCategory.AUTHENTICATION,
            severity=AuditSeverity.WARNING,
            actor={"email": email},
            description="Failed login attempt",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        user_id=user.user_id,
        tenant_id=user.tenant_id,
        role=user.role,
        email=user.email,
    )
    get_audit_logger().log(
        "auth.login.success",
        category=AuditCategory.AUTHENTICATION,
        severity=AuditSeverity.INFO,
        actor={"email": user.email, "user_id": user.user_id},
        context={"tenant_id": user.tenant_id, "role": user.role},
        description="User logged in",
    )
    return TokenResponse(
        access_token=token,
        user_id=user.user_id,
        role=user.role,
        tenant_id=user.tenant_id,
    )


@router.get("/me", response_model=CurrentUser)
async def get_me(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Return the current database-authoritative user."""
    return current_user
