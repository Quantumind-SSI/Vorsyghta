"""SQLAlchemy ORM models for API authentication and identity.

Tables:
    tenants
    users
"""

from __future__ import annotations

from datetime import datetime
from typing import List
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vorsyghta.db.base import Base


class TenantRecord(Base):
    """Persisted record of an organisational tenant."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())

    # All users in this tenant
    users: Mapped[List[UserRecord]] = relationship(
        "UserRecord",
        back_populates="tenant",
        cascade="all, delete-orphan",
        lazy="select",
        foreign_keys="UserRecord.tenant_id",
        primaryjoin="TenantRecord.tenant_id == UserRecord.tenant_id",
    )

    # Users who currently have this as their active tenant
    current_users: Mapped[List[UserRecord]] = relationship(
        "UserRecord",
        back_populates="current_tenant",
        lazy="select",
        foreign_keys="UserRecord.current_tenant_id",
        primaryjoin="TenantRecord.tenant_id == UserRecord.current_tenant_id",
    )

    def __repr__(self) -> str:
        return f"<TenantRecord tenant_id={self.tenant_id!r} name={self.name!r}>"


class UserRecord(Base):
    """Persisted record of an individual user account."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_users_user_id_tenant_id"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reset_token: Mapped[str | None] = mapped_column(String, nullable=True)
    verification_token: Mapped[str | None] = mapped_column(String, nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("tenants.tenant_id"),
        nullable=True,  # Made nullable for multi-tenancy
        index=True,
    )
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, onupdate=func.now())

    # Multi-tenant support
    # All tenants the user belongs to (via onboarding/registration)
    tenant: Mapped["TenantRecord"] = relationship(
        "TenantRecord",
        back_populates="users",
        lazy="select",
        foreign_keys=[tenant_id],
        primaryjoin="UserRecord.tenant_id == TenantRecord.tenant_id",
    )  # Primary tenant (from registration)
    
    # Currently active/selected tenant for this session
    current_tenant_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("tenants.tenant_id"),
        nullable=True,
        index=True,
    )  # Active/selected tenant for this session
    
    current_tenant: Mapped["TenantRecord | None"] = relationship(
        "TenantRecord",
        back_populates="current_users",
        lazy="select",
        foreign_keys=[current_tenant_id],
        primaryjoin="UserRecord.current_tenant_id == TenantRecord.tenant_id",
    )  # Active tenant for this session

    # Relationship to all tenants the user belongs to (many-to-many via user_tenants)
    # This is optional - we use tenant_id as the primary linking field
    # but current_tenant allows switching

    def __repr__(self) -> str:
        return f"<UserRecord user_id={self.user_id!r} email={self.email!r} role={self.role!r}>"