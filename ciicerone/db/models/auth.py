"""SQLAlchemy ORM models for API authentication and identity.

Tables:
    tenants
    users
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, String, func
from sqlalchemy.orm import relationship

from ciicerone.db.base import Base


class TenantRecord(Base):
    """Persisted record of an organisational tenant."""

    __tablename__ = "tenants"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    users = relationship(
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

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="analyst")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    tenant = relationship(
        "TenantRecord",
        back_populates="users",
        lazy="select",
        foreign_keys=[tenant_id],
        primaryjoin="UserRecord.tenant_id == TenantRecord.tenant_id",
    )

    def __repr__(self) -> str:
        return f"<UserRecord user_id={self.user_id!r} email={self.email!r} role={self.role!r}>"
