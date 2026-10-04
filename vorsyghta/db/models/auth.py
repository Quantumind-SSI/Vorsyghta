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

    users: Mapped[List[UserRecord]] = relationship(
        "UserRecord",
        back_populates="tenant",
        cascade="all, delete-orphan",
        lazy="select",
        foreign_keys="UserRecord.tenant_id",
        primaryjoin="TenantRecord.tenant_id == UserRecord.tenant_id",
    )

    def __repr__(self) -> str:
        return f"<TenantRecord tenant_id={self.tenant_id!r} name={self.name!r}>"


class UserRecord(Base):
    """Persisted record of an individual user account."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_users_user_id_tenant_id"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("tenants.tenant_id"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, onupdate=func.now())

    tenant: Mapped[TenantRecord] = relationship(
        "TenantRecord",
        back_populates="users",
        lazy="select",
        foreign_keys=[tenant_id],
        primaryjoin="UserRecord.tenant_id == TenantRecord.tenant_id",
    )

    def __repr__(self) -> str:
        return f"<UserRecord user_id={self.user_id!r} email={self.email!r} role={self.role!r}>"


Index("uq_users_email_lower", func.lower(UserRecord.email), unique=True)
