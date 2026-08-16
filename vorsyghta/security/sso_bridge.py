"""SSO-to-RBAC bridge for Vorsyghta.

Converts normalised :class:`vorsyghta.security.sso.SSOUserInfo` objects into
Vorsyghta JWT tokens by:

1. Looking up (or creating) a local :class:`UserRecord` keyed by email.
2. Mapping the SSO provider's group memberships to a Vorsyghta
   :class:`~vorsyghta.security.rbac.Role`.
3. Issuing a JWT via :func:`vorsyghta.security.rbac.create_access_token`.

This bridges external identity providers (OIDC / SAML) into the existing
JWT-based RBAC system so that downstream FastAPI dependencies
(``get_current_user``, ``require_role``) work transparently for SSO users.

Owner: Ibrahim Hassan — Blue Team (Foundation)
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Protocol
from uuid import uuid4

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vorsyghta.security.rbac import Role, create_access_token
from vorsyghta.security.sso import SSOUserInfo

logger = logging.getLogger(__name__)


# ===========================================================================
# Response model
# ===========================================================================

class SSOTokenResponse(BaseModel):
    """JWT token response issued after a successful SSO authentication."""

    access_token: str
    token_type: str = "bearer"
    user_id: str
    tenant_id: str
    role: str
    email: str


# ===========================================================================
# User store protocol
# ===========================================================================

class UserStore(Protocol):
    """Minimal interface for a user persistence backend.

    The default implementation (:func:`default_user_store`) uses the
    Vorsyghta PostgreSQL database, but any object implementing these
    async methods can be supplied to :class:`SSOBridge`.
    """

    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        ...

    async def create_user(
        self,
        email: str,
        tenant_id: str,
        role: str,
        external_id: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        ...


# ===========================================================================
# Default DB-backed user store
# ===========================================================================

class DefaultUserStore:
    """Database-backed user store using the Vorsyghta SQLAlchemy ORM."""

    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        from vorsyghta.db.models.auth import UserRecord

        try:
            from vorsyghta.db.session import get_session
            async with get_session() as session:
                result = await session.execute(
                    select(UserRecord).where(UserRecord.email == email)
                )
                user = result.scalar_one_or_none()
                if user is None:
                    return None
                return self._to_dict(user)
        except Exception as exc:  # noqa: BLE001
            logger.warning("DB user lookup failed for %s: %s", email, exc)
            return None

    async def create_user(
        self,
        email: str,
        tenant_id: str,
        role: str,
        external_id: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        from vorsyghta.db.models.auth import UserRecord, TenantRecord
        from vorsyghta.security.rbac import get_password_hash

        try:
            from vorsyghta.db.session import get_session
            async with get_session() as session:
                await self._ensure_tenant(session, tenant_id)
                user_id = f"user_{uuid4().hex[:12]}"
                # SSO users have no password — store an unusable random hash
                # so the column's NOT NULL constraint is satisfied and the
                # account cannot be used for password login.
                hashed_password = get_password_hash(uuid4().hex)
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
                logger.info(
                    "Created SSO user %s (provider=%s, role=%s, tenant=%s)",
                    email, provider, role, tenant_id,
                )
                return self._to_dict(user)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to create SSO user %s: %s", email, exc)
            raise

    # -- helpers ------------------------------------------------------------

    @staticmethod
    async def _ensure_tenant(session: AsyncSession, tenant_id: str) -> None:
        from vorsyghta.db.models.auth import TenantRecord

        existing = await session.execute(
            select(TenantRecord).where(TenantRecord.tenant_id == tenant_id)
        )
        if existing.scalar_one_or_none() is None:
            session.add(TenantRecord(
                tenant_id=tenant_id,
                name=tenant_id.replace("_", " ").title(),
            ))

    @staticmethod
    def _to_dict(user: Any) -> Dict[str, Any]:
        return {
            "user_id": user.user_id,
            "email": user.email,
            "tenant_id": user.tenant_id,
            "role": user.role,
            "is_active": user.is_active,
        }


def default_user_store() -> DefaultUserStore:
    """Return a new database-backed user store instance."""
    return DefaultUserStore()


# ===========================================================================
# Group-to-role mapping
# ===========================================================================

# A mapping rule is a (predicate, role) pair.  The first matching rule wins.
GroupRule = tuple  # (Callable[[List[str]], bool], Role)


def _contains_any(groups: List[str], keywords: List[str]) -> bool:
    lowered = [g.lower() for g in groups]
    return any(kw in g for g in lowered for kw in keywords)


def default_role_mapping() -> List[GroupRule]:
    """Return the default group-to-role mapping rules (order matters)."""
    return [
        (lambda g: _contains_any(g, ["admin"]), Role.ADMIN),
        (lambda g: _contains_any(g, ["pilot", "sponsor"]), Role.PILOT_SPONSOR),
        (lambda g: _contains_any(g, ["analyst", "security"]), Role.ANALYST),
    ]


# ===========================================================================
# Bridge
# ===========================================================================

class SSOBridge:
    """Bridges SSO user info into Vorsyghta JWT tokens.

    Args:
        user_store: Object implementing :class:`UserStore`.  Defaults to a
            :class:`DefaultUserStore` backed by PostgreSQL.
        role_mapping: Optional list of ``(predicate, Role)`` rules.  The
            first matching rule determines the role; if none match,
            :attr:`Role.VIEWER` is assigned.  Defaults to
            :func:`default_role_mapping`.
        default_tenant: Tenant ID assigned to newly created SSO users.
    """

    def __init__(
        self,
        user_store: Optional[UserStore] = None,
        role_mapping: Optional[List[GroupRule]] = None,
        default_tenant: str = "default",
    ) -> None:
        self.user_store = user_store or default_user_store()
        self.role_mapping = role_mapping or default_role_mapping()
        self.default_tenant = default_tenant

    async def authenticate(self, sso_user: SSOUserInfo) -> SSOTokenResponse:
        """Authenticate an SSO user and issue a Vorsyghta JWT.

        1. Look up or create the local user record (keyed by email).
        2. Determine the role from SSO groups (new users) or the existing
           user's stored role (returning users keep their role unless
           re-mapping is desired — see ``update_role_on_login``).
        3. Issue a JWT via :func:`create_access_token`.
        """
        if not sso_user.email:
            raise ValueError("SSOUserInfo.email is required to authenticate")

        user = await self._get_or_create_user(sso_user)
        if not user.get("is_active", True):
            raise PermissionError(f"User {sso_user.email} is inactive")

        role = self._map_groups_to_role(sso_user.groups)
        tenant_id = user.get("tenant_id") or self.default_tenant
        user_id = user["user_id"]

        token = create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            role=role.value,
            email=sso_user.email,
        )

        logger.info(
            "SSO authenticate: provider=%s email=%s role=%s tenant=%s",
            sso_user.provider, sso_user.email, role.value, tenant_id,
        )

        return SSOTokenResponse(
            access_token=token,
            user_id=user_id,
            tenant_id=tenant_id,
            role=role.value,
            email=sso_user.email,
        )

    def _map_groups_to_role(self, groups: List[str]) -> Role:
        """Map SSO group memberships to a Vorsyghta role.

        Order of precedence (first match wins):
            * Groups containing "admin"            -> ADMIN
            * Groups containing "pilot"/"sponsor"  -> PILOT_SPONSOR
            * Groups containing "analyst"/"security" -> ANALYST
            * Default                              -> VIEWER
        """
        for predicate, role in self.role_mapping:
            try:
                if predicate(groups):
                    return role
            except Exception:  # noqa: BLE001
                continue
        return Role.VIEWER

    async def _get_or_create_user(self, sso_user: SSOUserInfo) -> Dict[str, Any]:
        """Find an existing user by email or create a new one."""
        existing = await self.user_store.get_user_by_email(sso_user.email)
        if existing is not None:
            return existing

        role = self._map_groups_to_role(sso_user.groups).value
        return await self.user_store.create_user(
            email=sso_user.email,
            tenant_id=self.default_tenant,
            role=role,
            external_id=sso_user.external_id,
            provider=sso_user.provider,
        )


__all__ = [
    "SSOBridge",
    "SSOTokenResponse",
    "UserStore",
    "DefaultUserStore",
    "default_user_store",
    "default_role_mapping",
]
