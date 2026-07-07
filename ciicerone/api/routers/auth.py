"""Authentication router for Ciicerone API.

Provides /auth/token (login) and /auth/register endpoints.

Users are persisted in PostgreSQL (via SQLAlchemy ORM) with Redis as a
read-through cache for fast lookups across multiple Uvicorn workers.
If the database is unavailable, the router falls back to Redis-only mode.

Owner: Ajibola Shokunbi (@jiboo2022) — Core Software Lead
Phase 1 — Security & Persistence Hardening (P0-4, P0-6)
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ciicerone.security.rbac import (
    create_access_token,
    get_password_hash,
    verify_password,
    Role,
    CurrentUser,
    get_current_user,
)
from ciicerone.core.audit_logger import (
    AuditCategory,
    AuditSeverity,
    get_audit_logger,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

# =============================================================================
# Redis cache layer (shared across all uvicorn workers)
# =============================================================================

from ciicerone.core.redis_client import get_redis_client

_USER_KEY_PREFIX = "ciicerone:user:"
_USER_INDEX_KEY = "ciicerone:user_index"
_USER_TTL = 90 * 24 * 3600  # 90 days


def _get_redis():
    """Return the shared Redis client or None."""
    return get_redis_client()


# =============================================================================
# Database-backed user store (PostgreSQL via SQLAlchemy ORM)
# =============================================================================

async def _db_save_user(
    session: AsyncSession,
    email: str,
    hashed_password: str,
    tenant_id: str,
    role: str,
) -> str:
    """Persist a new user to the database and return the user_id."""
    from ciicerone.db.models.auth import UserRecord, TenantRecord
    from uuid import uuid4

    # Ensure tenant exists
    existing_tenant = await session.execute(
        select(TenantRecord).where(TenantRecord.tenant_id == tenant_id)
    )
    if existing_tenant.scalar_one_or_none() is None:
        session.add(TenantRecord(
            tenant_id=tenant_id,
            name=tenant_id.replace("_", " ").title(),
        ))

    user_id = f"user_{uuid4().hex[:12]}"
    user = UserRecord(
        user_id=user_id,
        tenant_id=tenant_id,
        email=email,
        hashed_password=hashed_password,
        role=role,
        is_active=True,
    )
    session.add(user)
    await session.commit()
    return user_id


async def _db_load_user(session: AsyncSession, email: str) -> Optional[dict]:
    """Load a user from the database by email."""
    from ciicerone.db.models.auth import UserRecord

    result = await session.execute(
        select(UserRecord).where(UserRecord.email == email)
    )
    user = result.scalar_one_or_none()
    if user is None:
        return None
    return {
        "user_id": user.user_id,
        "email": user.email,
        "hashed_password": user.hashed_password,
        "tenant_id": user.tenant_id,
        "role": user.role,
        "is_active": user.is_active,
    }


async def _db_user_count(session: AsyncSession) -> int:
    """Count total users in the database."""
    from ciicerone.db.models.auth import UserRecord
    from sqlalchemy import func

    result = await session.execute(select(func.count(UserRecord.id)))
    return result.scalar_one()


# =============================================================================
# Cache helpers (Redis read-through cache)
# =============================================================================

def _cache_user(email: str, user_data: dict) -> None:
    r = _get_redis()
    if r is not None:
        r.setex(f"{_USER_KEY_PREFIX}{email}", _USER_TTL, json.dumps(user_data))
        r.sadd(_USER_INDEX_KEY, email)


def _cache_load_user(email: str) -> Optional[dict]:
    r = _get_redis()
    if r is not None:
        raw = r.get(f"{_USER_KEY_PREFIX}{email}")
        if raw:
            return json.loads(raw)
    return None


def _cache_invalidate_user(email: str) -> None:
    r = _get_redis()
    if r is not None:
        r.delete(f"{_USER_KEY_PREFIX}{email}")
        r.srem(_USER_INDEX_KEY, email)


# Fallback in-memory store (used only when both DB and Redis are unavailable)
_users: dict[str, dict] = {}


async def _save_user(email: str, hashed_password: str, tenant_id: str, role: str) -> str:
    """Save a user to DB (primary) and Redis (cache). Returns user_id."""
    # Try database first
    try:
        from ciicerone.db.session import get_session
        async with get_session() as session:
            user_id = await _db_save_user(session, email, hashed_password, tenant_id, role)
            # Cache in Redis
            _cache_user(email, {
                "user_id": user_id,
                "email": email,
                "hashed_password": hashed_password,
                "tenant_id": tenant_id,
                "role": role,
            })
            return user_id
    except Exception as e:
        logger.warning(f"DB save failed, falling back to Redis-only: {e}")

    # Fallback: Redis-only
    r = _get_redis()
    if r is not None:
        import json as _json
        existing = r.scard(_USER_INDEX_KEY)
        user_id = f"user_{existing + 1}"
        user_data = {
            "user_id": user_id,
            "email": email,
            "hashed_password": hashed_password,
            "tenant_id": tenant_id,
            "role": role,
        }
        r.setex(f"{_USER_KEY_PREFIX}{email}", _USER_TTL, _json.dumps(user_data))
        r.sadd(_USER_INDEX_KEY, email)
        return user_id

    # Last resort: in-memory
    user_id = f"user_{len(_users) + 1}"
    _users[email] = {
        "user_id": user_id,
        "email": email,
        "hashed_password": hashed_password,
        "tenant_id": tenant_id,
        "role": role,
    }
    return user_id


async def _load_user(email: str) -> Optional[dict]:
    """Load a user from Redis cache (fast path) or DB (slow path)."""
    # Fast path: Redis cache
    cached = _cache_load_user(email)
    if cached:
        return cached

    # Slow path: Database
    try:
        from ciicerone.db.session import get_session
        async with get_session() as session:
            user = await _db_load_user(session, email)
            if user:
                # Populate cache
                _cache_user(email, user)
                return user
    except Exception as e:
        logger.warning(f"DB load failed, falling back to in-memory: {e}")

    # Last resort: in-memory
    return _users.get(email)


# =============================================================================
# API endpoints
# =============================================================================

class RegisterRequest(BaseModel):
    email: str
    password: str
    tenant_id: str = "default"
    role: str = "analyst"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    tenant_id: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(request: RegisterRequest):
    """Register a new user.

    Users are persisted to PostgreSQL (primary) with Redis as a read-through
    cache. Falls back to Redis-only if the database is unavailable.

    Security: self-registration ALWAYS creates a ``viewer`` account in the
    ``default`` tenant. Client-supplied ``role`` and ``tenant_id`` fields are
    accepted in the request body for backward compatibility but are NEVER
    honored — they are ignored entirely. This closes the privilege-escalation
    and tenant-isolation vector where an unauthenticated caller could
    self-register as ``admin`` (or any elevated role) under an arbitrary
    tenant. Elevated roles and non-default tenants must be provisioned by an
    existing admin or via an invite/SSO context, never via this endpoint.
    """
    if await _load_user(request.email):
        raise HTTPException(status_code=400, detail="User already exists")

    # Force the only safe values for self-registration. The request fields
    # are deliberately ignored — do NOT trust client-supplied role/tenant.
    forced_role = Role.VIEWER.value
    forced_tenant_id = "default"

    hashed_password = get_password_hash(request.password)
    user_id = await _save_user(
        email=request.email,
        hashed_password=hashed_password,
        tenant_id=forced_tenant_id,
        role=forced_role,
    )

    # Audit log
    audit = get_audit_logger()
    audit.log(
        "auth.register.success",
        category=AuditCategory.AUTHENTICATION,
        severity=AuditSeverity.INFO,
        actor={"email": request.email, "user_id": user_id},
        context={"tenant_id": forced_tenant_id, "role": forced_role},
        description=f"User registered: {request.email}",
    )

    logger.info(
        "Registered user: %s (role=%s, tenant=%s)",
        request.email, forced_role, forced_tenant_id,
    )
    return {"message": "User registered", "user_id": user_id}


@router.post("/token", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Issue a JWT access token."""
    user = await _load_user(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        # Audit log: failed login
        audit = get_audit_logger()
        audit.log(
            "auth.login.failed",
            category=AuditCategory.AUTHENTICATION,
            severity=AuditSeverity.WARNING,
            actor={"email": form_data.username},
            description=f"Failed login attempt: {form_data.username}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        user_id=user["user_id"],
        tenant_id=user["tenant_id"],
        role=user["role"],
        email=user.get("email"),
    )

    # Audit log: successful login
    audit = get_audit_logger()
    audit.log(
        "auth.login.success",
        category=AuditCategory.AUTHENTICATION,
        severity=AuditSeverity.INFO,
        actor={"email": form_data.username, "user_id": user["user_id"]},
        context={"tenant_id": user["tenant_id"], "role": user["role"]},
        description=f"User logged in: {form_data.username}",
    )

    return TokenResponse(
        access_token=token,
        role=user["role"],
        tenant_id=user["tenant_id"],
    )


@router.get("/me", response_model=CurrentUser)
async def get_me(current_user: CurrentUser = Depends(get_current_user)):
    """Return the current authenticated user."""
    return current_user
