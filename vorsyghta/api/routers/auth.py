"""Database-authoritative authentication endpoints for Vorsyghta.

Extended with email verification and password reset support.
"""

from __future__ import annotations

import hashlib
import logging
import os
from uuid import uuid4

from anyio import to_thread
from fastapi import APIRouter, Depends, HTTPException, Request, status
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
from vorsyghta.utils.auth_enhancements import (
    generate_verification_token,
    is_valid_verification_token,
    generate_reset_token,
    is_valid_reset_token,
    send_verification_email,
    send_reset_email,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_AUTH_RATE_LIMITS = {
    "login": (10, 300, 300),
    "register": (3, 3600, 60),
    "reset_password": (5, 300, 30),
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
    requires_email_verification: bool = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str
    tenant_id: str
    requires_email_verification: bool = False


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordConfirmRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=12, max_length=72)


class ResetPasswordResponse(BaseModel):
    message: str


def _normalize_email(value: str) -> str:
    return value.strip().lower()


async def _enforce_auth_rate_limit(action: str, email: str) -> None:
    """Apply shared global and per-email limits to public identity endpoints."""
    per_identity_limit, window_seconds, global_limit = _AUTH_RATE_LIMITS[action]
    deployed = os.getenv("ENVIRONMENT", "development").strip().lower() in {
        "staging",
        "production",
    }
    from vorsyghta.core.redis_client import get_redis_client as get_redis
    client = await to_thread.run_sync(get_redis)
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
    set_as_verified: bool = False,
) -> tuple[str, str]:
    """Insert a tenant and viewer in the caller's transaction."""
    from vorsyghta.utils.auth_enhancements import generate_verification_token
    
    tenant_id = f"tenant_{uuid4().hex}"
    user_id = f"user_{uuid4().hex}"
    is_verified = set_as_verified  # Will be False by default; email requires verification
    
    # Generate verification token if not already verified
    verification_token = None
    if not is_verified:
        verification_token = generate_verification_token()
        send_verification_email(email, verification_token, organization_name)
    
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
            is_verified=is_verified,
            verification_token=verification_token,
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
    """Atomically create a unique tenant and its initial viewer account.

    Email verification is required. A verification email is sent upon registration.
    The account cannot be used for sign-in until email is verified.
    """
    email = _normalize_email(str(request.email))
    await _enforce_auth_rate_limit("register", email)
    try:
        tenant_id, user_id = await _create_tenant_and_user(
            session,
            email=email,
            hashed_password=get_password_hash(request.password),
            organization_name=request.organization_name,
            set_as_verified=False,  # Email verification required
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
        description="Tenant owner account registered - email verification required",
    )
    return RegisterResponse(
        tenant_id=tenant_id,
        user_id=user_id,
        requires_email_verification=True,
    )


@router.post("/resend-verification", response_model=dict)
async def resend_verification(request: ResendVerificationRequest, session: AsyncSession = Depends(get_session_dep)) -> dict:
    """Resend verification email to the specified email address."""
    from vorsyghta.utils.auth_enhancements import send_verification_email
    
    email = _normalize_email(request.email)
    
    # Find the user
    result = await session.execute(
        select(UserRecord).where(func.lower(UserRecord.email) == email)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.is_verified:
        return {"message": "Email already verified"}

    # Generate new verification token
    verification_token = generate_verification_token()
    user.verification_token = verification_token
    tenant_name = user.tenant_id or ""
    await session.commit()

    # Send verification email (never lazy-load user.tenant here: sync IO
    # in an async context raises MissingGreenlet after the commit expires
    # loaded attributes)
    send_verification_email(email, verification_token, tenant_name)
    
    return {"message": "Verification email sent"}


@router.post("/verify-email", response_model=dict)
async def verify_email(request: VerifyEmailRequest, session: AsyncSession = Depends(get_session_dep)) -> dict:
    """Verify a user's email address using a verification token."""
    from vorsyghta.utils.auth_enhancements import is_valid_verification_token
    
    # Find the user by verification token
    result = await session.execute(
        select(UserRecord).where(UserRecord.verification_token == request.token)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    if user.is_verified:
        return {"message": "Email already verified"}
    
    # Check if token is valid
    if not is_valid_verification_token(request.token, None, user):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )
    
    # Mark email as verified and clear token
    user.is_verified = True
    user.verification_token = None
    await session.commit()
    
    get_audit_logger().log(
        "auth.email_verified",
        category=AuditCategory.AUTHENTICATION,
        severity=AuditSeverity.INFO,
        actor={"email": user.email},
        description="Email address verified",
    )
    
    return {"message": "Email verified successfully"}


@router.post("/request-reset", response_model=dict)
async def request_reset(request: ResetPasswordRequest, session: AsyncSession = Depends(get_session_dep)) -> dict:
    """Request a password reset email for the specified email address."""
    from vorsyghta.utils.auth_enhancements import generate_reset_token, send_reset_email
    
    email = _normalize_email(request.email)
    
    # Find the user
    result = await session.execute(
        select(UserRecord).where(func.lower(UserRecord.email) == email)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        # Don't reveal if email exists or not (security best practice)
        return {"message": "If an account with this email exists, a reset link has been sent"}
    
    # Check if email is verified before allowing reset
    if not user.is_verified:
        return {
            "message": "Please verify your email address first. A verification link has been sent to your email.",
            "requires_verification": True,
        }
    
    # Generate reset token
    reset_token = generate_reset_token()
    user.reset_token = reset_token
    tenant_name = user.tenant_id or ""
    await session.commit()

    # Send reset email (tenant_id string, not user.tenant: post-commit
    # lazy-load would trigger sync IO in async context)
    send_reset_email(email, reset_token, tenant_name)
    
    return {"message": "Password reset link sent to your email"}


@router.post("/reset-password", response_model=ResetPasswordResponse)
async def reset_password(request: ResetPasswordConfirmRequest, session: AsyncSession = Depends(get_session_dep)) -> ResetPasswordResponse:
    """Reset password using a verification token."""
    from vorsyghta.utils.auth_enhancements import is_valid_reset_token
    
    # Find user by reset token
    result = await session.execute(
        select(UserRecord).where(UserRecord.reset_token == request.token)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        # Don't reveal if email exists (security best practice)
        return ResetPasswordResponse(message="If an account with this email exists, your password has been reset.")
    
    # Check if reset token is valid
    if not is_valid_reset_token(request.token, None, user):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )
    
    # Set new password
    user.hashed_password = get_password_hash(request.new_password)
    user.reset_token = None
    await session.commit()
    
    get_audit_logger().log(
        "auth.password_reset.success",
        category=AuditCategory.AUTHENTICATION,
        severity=AuditSeverity.INFO,
        actor={"email": user.email, "user_id": user.user_id},
        description="Password reset completed",
    )
    
    return ResetPasswordResponse(message="Password has been reset successfully")


@router.post("/login", response_model=TokenResponse)
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
    
    # Check if account exists and is active
    if (
        user is None
        or tenant is None
        or not user.is_active
        or not tenant.is_active
    ):
        get_audit_logger().log(
            "auth.login.failed",
            category=AuditCategory.AUTHENTICATION,
            severity=AuditSeverity.WARNING,
            actor={"email": email},
            description="Failed login attempt - account inactive or not found",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password. Account may require email verification.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify password
    if not verify_password(form_data.password, user.hashed_password):
        get_audit_logger().log(
            "auth.login.failed",
            category=AuditCategory.AUTHENTICATION,
            severity=AuditSeverity.WARNING,
            actor={"email": email},
            description="Failed login attempt - incorrect password",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password. Account may require email verification.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Enforce email verification
    if not user.is_verified:
        # Send verification email on failed login attempt
        try:
            from vorsyghta.utils.auth_enhancements import generate_verification_token, send_verification_email
            verification_token = generate_verification_token()
            user.verification_token = verification_token
            await session.commit()
            send_verification_email(
                user.email,
                verification_token,
                tenant.name if tenant else ""
            )
        except Exception:
            pass
        get_audit_logger().log(
            "auth.login.failed",
            category=AuditCategory.AUTHENTICATION,
            severity=AuditSeverity.WARNING,
            actor={"email": email},
            description="Failed login attempt - email not verified",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified. Please verify your email to sign in.",
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
        requires_email_verification=False,
    )


@router.get("/me", response_model=CurrentUser)
async def get_me(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Return the current database-authoritative user."""
    return current_user


class UpdateRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = Field(..., description="User role: viewer, analyst, pilot_sponsor, or admin")


@router.post("/update-role", response_model=dict)
async def update_role(
    request: UpdateRoleRequest,
    session: AsyncSession = Depends(get_session_dep),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Update the user's role after onboarding completion."""
    # Validate role
    valid_roles = ["viewer", "analyst", "pilot_sponsor", "admin"]
    if request.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}",
        )

    # Update the user's role in the database
    await session.execute(
        update(UserRecord)
        .where(UserRecord.user_id == current_user.user_id)
        .values(role=request.role)
    )
    await session.commit()

    # Refresh the current user to get the updated role
    result = await session.execute(
        select(UserRecord).where(UserRecord.user_id == current_user.user_id)
    )
    updated_user = result.scalar_one_or_none()

    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found after role update",
        )

    get_audit_logger().log(
        "auth.role_updated",
        category=AuditCategory.AUTHENTICATION,
        severity=AuditSeverity.INFO,
        actor={"email": updated_user.email, "user_id": updated_user.user_id},
        context={
            "tenant_id": updated_user.tenant_id,
            "role": updated_user.role,
        },
        description=f"User role updated to {request.role}",
    )

    return {
        "message": f"Role updated to {request.role}",
        "role": updated_user.role,
    }
