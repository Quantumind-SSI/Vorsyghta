"""RBAC enforcement for Vorsyghta API.

Defines roles (admin, analyst, viewer, pilot_sponsor) and provides
FastAPI dependency functions for role-based access control.

Owner: Ibrahim Hassan — Blue Team (Foundation)
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import bcrypt
from pydantic import BaseModel

# ---- Config ---------------------------------------------------------------

SECRET_KEY = os.getenv("VORSYGHTA_SECRET_KEY", "changeme-replace-in-production-with-256bit-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


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
    tenant_id: str
    role: str
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
    # bcrypt has a 72-byte limit; truncate to avoid ValueError
    pw_bytes = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def create_access_token(
    user_id: str,
    tenant_id: str,
    role: str,
    email: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "email": email,
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> TokenPayload:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenPayload(**data)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    """FastAPI dependency: resolve the JWT bearer token to a CurrentUser."""
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(token)
    return CurrentUser(
        user_id=payload.sub,
        tenant_id=payload.tenant_id,
        role=Role(payload.role),
        email=payload.email,
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
