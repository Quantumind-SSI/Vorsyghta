"""Onboarding persistence models."""
from __future__ import annotations

from datetime import datetime
from typing import List
from uuid import uuid4

from sqlalchemy import JSON, String, DateTime, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vorsyghta.db.base import Base


class OnboardingProfileRecord(Base):
    __tablename__ = "onboarding_profiles"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.user_id"), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String, ForeignKey("tenants.tenant_id"), nullable=False, index=True)
    industry: Mapped[str] = mapped_column(String(80), nullable=False)
    company_size: Mapped[str] = mapped_column(String(16), nullable=False)
    regions: Mapped[str] = mapped_column(String(160), nullable=False)
    security_maturity: Mapped[str] = mapped_column(String(32), nullable=False)
    compliance_frameworks: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, onupdate=func.now())


class OnboardingUseCasesRecord(Base):
    __tablename__ = "onboarding_use_cases"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.user_id"), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String, ForeignKey("tenants.tenant_id"), nullable=False, index=True)
    capabilities: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    success_criteria: Mapped[str] = mapped_column(String(600), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, onupdate=func.now())


class OnboardingEnvironmentsRecord(Base):
    __tablename__ = "onboarding_environments"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.user_id"), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String, ForeignKey("tenants.tenant_id"), nullable=False, index=True)
    adapter_categories: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    cloud_providers: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    sanctioned_targets_only: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, onupdate=func.now())


class OnboardingReviewRecord(Base):
    __tablename__ = "onboarding_reviews"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.user_id"), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String, ForeignKey("tenants.tenant_id"), nullable=False, index=True)
    terms_accepted: Mapped[bool] = mapped_column(default=True, nullable=False)
    acceptable_use_accepted: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
