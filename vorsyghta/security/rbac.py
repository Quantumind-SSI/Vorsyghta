"""RBAC enforcement for Vorsyghta API.

Defines roles (admin, analyst, viewer, pilot_sponsor) and provides
FastAPI dependency functions for role-based access control.

Owner: Ibrahim Hassan — Blue Team (Foundation)
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import bcrypt
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from vorsyghta.db.models.auth import TenantRecord, UserRecord
from vorsyghta.db.session import get_session_dep

# ---- Config ---------------------------------------------------------------

_DEVELOPMENT_SECRET = "changeme-replace-in-production-with-256bit-secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    PILOT_SPONSOR = "pilot_sponsor"


ROLE_HIERARCHY = {
    Role.ADMIN: 4,
    Role.PILOT_SPONSOR: 3,
    Role.ANALYST: 2,
    Role.VIEWER: 1,
}


class TokenPayload(BaseModel):
    sub: str  # user_id
    tenant_id: Optional[str] = None
    role: Optional[str] = None
    email: Optional[str] = None
    exp: Optional[int] = None


class CurrentUser(BaseModel):
    user_id: str
    tenant_id: str
    role: Role
    email: Optional[str] = None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt with a generated salt."""
    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) > 72:
        raise ValueError("Password exceeds bcrypt's 72-byte limit")
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def _signing_secret() -> str:
    environment = os.getenv("ENVIRONMENT", "development").strip().lower()
    configured = os.getenv("VORSYGHTA_SECRET_KEY", "")
    if environment == "production":
        is_placeholder = configured.startswith(("your_", "change_this", "changeme", "CHANGE_ME"))
        if len(configured) < 32 or is_placeholder:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication signing is not configured",
            )
        return configured
    return configured or _DEVELOPMENT_SECRET


def _token_lifetime_minutes() -> int:
    raw = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
    if raw is None:
        return ACCESS_TOKEN_EXPIRE_MINUTES
    try:
        value = int(raw)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication token lifetime is invalid",
        ) from exc
    if not 1 <= value <= 1440:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication token lifetime is invalid",
        )
    return value


def validate_authentication_configuration() -> None:
    """Raise a controlled error when token signing settings are unusable."""
    _signing_secret()
    _token_lifetime_minutes()


def create_access_token(
    user_id: str,
    tenant_id: str,
    role: str,
    email: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=_token_lifetime_minutes()))
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "email": email,
        "exp": expire,
    }
    return jwt.encode(payload, _signing_secret(), algorithm=ALGORITHM)


def decode_token(token: str) -> TokenPayload:
    try:
        data = jwt.decode(token, _signing_secret(), algorithms=[ALGORITHM])
        return TokenPayload(**data)
    except (JWTError, ValidationError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session_dep),
) -> CurrentUser:
    """Resolve a token subject against current PostgreSQL identity state."""
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(token)
    try:
        result = await session.execute(
            select(UserRecord, TenantRecord)
            .join(TenantRecord, TenantRecord.tenant_id == UserRecord.tenant_id)
            .where(UserRecord.user_id == payload.sub)
        )
        row = result.one_or_none()
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Identity storage is temporarily unavailable",
        ) from exc
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user, tenant = row
    if not user.is_active or not tenant.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is inactive")
    try:
        role = Role(user.role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account role is invalid") from exc
    return CurrentUser(
        user_id=user.user_id,
        tenant_id=user.tenant_id,
        role=role,
        email=user.email,
    )


def require_role(minimum_role: Role):
    """Return a FastAPI dependency that requires at least *minimum_role*."""

    async def _check(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if ROLE_HIERARCHY.get(current_user.role, 0) < ROLE_HIERARCHY.get(minimum_role, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{minimum_role.value}' or higher required",
            )
        return current_user

    return _check


require_viewer = require_role(Role.VIEWER)
require_analyst = require_role(Role.ANALYST)
require_admin = require_role(Role.ADMIN)
