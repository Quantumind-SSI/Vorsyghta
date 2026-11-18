"""Onboarding API router.

Dedicated onboarding persistence surface, separate from the knowledge base.
"""

from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, Field
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from vorsyghta.db.session import get_session_dep
from vorsyghta.db.models.onboarding import (
    OnboardingProfileRecord,
    OnboardingUseCasesRecord,
    OnboardingEnvironmentsRecord,
    OnboardingReviewRecord,
)
from vorsyghta.db.models.auth import UserRecord

router = APIRouter(prefix="/onboarding", tags=["Onboarding"])


class OnboardingProfileIn(BaseModel):
    industry: str = Field(..., min_length=2, max_length=80)
    company_size: str = Field(..., pattern=r"^(1-10|11-50|51-200|201-1000|1000\+)$")
    regions: str = Field(..., min_length=2, max_length=160)
    security_maturity: str = Field(..., min_length=1, max_length=32)
    compliance_frameworks: List[str] = Field(default_factory=list)


class OnboardingUseCasesIn(BaseModel):
    capabilities: List[str] = Field(..., min_length=1)
    success_criteria: str = Field(..., max_length=600)


class OnboardingEnvironmentsIn(BaseModel):
    adapter_categories: List[str] = Field(default_factory=list)
    cloud_providers: List[str] = Field(default_factory=list)
    sanctioned_targets_only: bool = True


class OnboardingReviewIn(BaseModel):
    terms_accepted: bool = True
    acceptable_use_accepted: bool = True


class OnboardingOut(BaseModel):
    id: str
    message: str = "Saved."


async def get_current_user_db(db: AsyncSession) -> UserRecord:
    user = await db.scalar(select(UserRecord).limit(1))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@router.post("/profile", response_model=OnboardingOut, status_code=status.HTTP_201_CREATED)
async def create_onboarding_profile(profile: OnboardingProfileIn, db: AsyncSession = Depends(get_session_dep)):
    user = await get_current_user_db(db)
    rec = OnboardingProfileRecord(
        user_id=user.user_id,
        tenant_id=user.tenant_id or user.current_tenant_id or "",
        industry=profile.industry,
        company_size=profile.company_size,
        regions=profile.regions,
        security_maturity=profile.security_maturity,
        compliance_frameworks=profile.compliance_frameworks,
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)
    return OnboardingOut(id=rec.id)


@router.post("/use-cases", response_model=OnboardingOut, status_code=status.HTTP_201_CREATED)
async def create_onboarding_use_cases(data: OnboardingUseCasesIn, db: AsyncSession = Depends(get_session_dep)):
    user = await get_current_user_db(db)
    rec = OnboardingUseCasesRecord(
        user_id=user.user_id,
        tenant_id=user.tenant_id or user.current_tenant_id or "",
        capabilities=data.capabilities,
        success_criteria=data.success_criteria,
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)
    return OnboardingOut(id=rec.id)


@router.post("/environments", response_model=OnboardingOut, status_code=status.HTTP_201_CREATED)
async def create_onboarding_environments(data: OnboardingEnvironmentsIn, db: AsyncSession = Depends(get_session_dep)):
    user = await get_current_user_db(db)
    rec = OnboardingEnvironmentsRecord(
        user_id=user.user_id,
        tenant_id=user.tenant_id or user.current_tenant_id or "",
        adapter_categories=data.adapter_categories,
        cloud_providers=data.cloud_providers,
        sanctioned_targets_only=data.sanctioned_targets_only,
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)
    return OnboardingOut(id=rec.id)


@router.post("/review", response_model=OnboardingOut, status_code=status.HTTP_201_CREATED)
async def create_onboarding_review(data: OnboardingReviewIn, db: AsyncSession = Depends(get_session_dep)):
    user = await get_current_user_db(db)
    rec = OnboardingReviewRecord(
        user_id=user.user_id,
        tenant_id=user.tenant_id or user.current_tenant_id or "",
        terms_accepted=data.terms_accepted,
        acceptable_use_accepted=data.acceptable_use_accepted,
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)
    # Mark onboarding complete
    user.onboarding_complete = True
    await db.commit()
    return OnboardingOut(id=rec.id)
