"""Vorsyghta Threat Intelligence API Router.

This is the proprietary threat intelligence stack API — the Vorsyghta IP.
It provides endpoints for ingesting, querying, and sharing threat
intelligence across all color teams.

Endpoints:
    /api/threat-intel/actors          — CRUD for threat actors
    /api/threat-intel/campaigns       — CRUD for campaigns
    /api/threat-intel/malware         — CRUD for malware families
    /api/threat-intel/indicators      — CRUD for IOCs with lifecycle
    /api/threat-intel/ttps            — CRUD for TTPs
    /api/threat-intel/reports         — CRUD for threat reports
    /api/threat-intel/search          — Cross-entity search
    /api/threat-intel/correlate       — Correlate entities by MITRE/IOC
    /api/threat-intel/share           — Share intel with color teams
    /api/threat-intel/stats           — Intelligence statistics

Owner: Vorsyghta Core Team
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_, and_

from vorsyghta.security.rbac import CurrentUser, get_current_user, require_analyst
from vorsyghta.core.audit_logger import AuditCategory, AuditSeverity, get_audit_logger

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


# =============================================================================
# Helpers
# =============================================================================

def _json_loads(val: Optional[str], default: Any = None) -> Any:
    if val is None:
        return default if default is not None else []
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else []


def _json_dumps(val: Any) -> Optional[str]:
    if val is None:
        return None
    return json.dumps(val)


def _indicator_hash(indicator_type: str, value: str) -> str:
    """Compute a normalized hash for deduplication."""
    return hashlib.sha256(f"{indicator_type}:{value}".encode()).hexdigest()


# =============================================================================
# Request / Response Models — Threat Actor
# =============================================================================

class ThreatActorCreate(BaseModel):
    name: str
    aliases: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    actor_type: str = "apt"
    target_industries: List[str] = Field(default_factory=list)
    target_regions: List[str] = Field(default_factory=list)
    target_countries: List[str] = Field(default_factory=list)
    sophistication_level: Optional[int] = None
    primary_motivation: Optional[str] = None
    secondary_motivations: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_active: bool = True
    confidence_level: str = "medium"
    sources: List[str] = Field(default_factory=list)
    collection_method: str = "manual"
    shared_with_teams: List[str] = Field(default_factory=lambda: ["red", "blue", "purple"])


class ThreatActorResponse(BaseModel):
    actor_id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    actor_type: str
    target_industries: List[str] = Field(default_factory=list)
    target_regions: List[str] = Field(default_factory=list)
    sophistication_level: Optional[int] = None
    primary_motivation: Optional[str] = None
    is_active: bool
    confidence_level: str
    sources: List[str] = Field(default_factory=list)
    shared_with_teams: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


# =============================================================================
# Request / Response Models — Campaign
# =============================================================================

class CampaignCreate(BaseModel):
    actor_id: str
    name: str
    description: Optional[str] = None
    campaign_status: str = "active"
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    target_organizations: List[str] = Field(default_factory=list)
    target_sectors: List[str] = Field(default_factory=list)
    target_geography: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    impact_assessment: Optional[str] = None
    estimated_impact_usd: Optional[float] = None
    confidence_level: str = "medium"
    sources: List[str] = Field(default_factory=list)
    shared_with_teams: List[str] = Field(default_factory=lambda: ["red", "blue", "purple"])


class CampaignResponse(BaseModel):
    campaign_id: str
    actor_id: str
    name: str
    description: Optional[str] = None
    campaign_status: str
    mitre_techniques: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    target_sectors: List[str] = Field(default_factory=list)
    confidence_level: str
    is_active: bool = True
    created_at: datetime


# =============================================================================
# Request / Response Models — Indicator (IOC)
# =============================================================================

class IndicatorCreate(BaseModel):
    campaign_id: str
    indicator_type: str
    indicator_value: str
    description: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    mitre_technique: Optional[str] = None
    threat_score: Optional[int] = None
    confidence_level: str = "medium"
    sources: List[str] = Field(default_factory=list)
    collection_method: str = "manual"
    shared_with_teams: List[str] = Field(default_factory=lambda: ["red", "blue", "purple"])
    expires_at: Optional[datetime] = None


class IndicatorResponse(BaseModel):
    indicator_id: str
    campaign_id: str
    indicator_type: str
    indicator_value: str
    description: Optional[str] = None
    indicator_state: str
    threat_score: Optional[int] = None
    confidence_level: str
    mitre_technique: Optional[str] = None
    sources: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: datetime


# =============================================================================
# Request / Response Models — TTP
# =============================================================================

class TTPCreate(BaseModel):
    campaign_id: str
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    ttp_name: str
    ttp_category: str = "technique"
    description: Optional[str] = None
    observed_procedure: Optional[str] = None
    detection_recommendations: Optional[str] = None
    detection_data_sources: List[str] = Field(default_factory=list)
    sigma_rule: Optional[str] = None
    splunk_query: Optional[str] = None
    elastic_query: Optional[str] = None
    sentinel_query: Optional[str] = None
    mitigation_recommendations: Optional[str] = None
    simulation_applicability: Optional[str] = None
    confidence_level: str = "medium"
    sources: List[str] = Field(default_factory=list)
    shared_with_teams: List[str] = Field(default_factory=lambda: ["red", "blue", "purple"])


class TTPResponse(BaseModel):
    ttp_id: str
    campaign_id: str
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    ttp_name: str
    ttp_category: str
    description: Optional[str] = None
    observed_procedure: Optional[str] = None
    detection_recommendations: Optional[str] = None
    sigma_rule: Optional[str] = None
    splunk_query: Optional[str] = None
    mitigation_recommendations: Optional[str] = None
    confidence_level: str
    created_at: datetime


# =============================================================================
# Request / Response Models — Threat Report
# =============================================================================

class ThreatReportCreate(BaseModel):
    actor_id: Optional[str] = None
    title: str
    report_type: str = "threat_assessment"
    summary: Optional[str] = None
    body: Optional[str] = None
    classification: str = "TLP:AMBER"
    severity: str = "medium"
    affected_industries: List[str] = Field(default_factory=list)
    affected_regions: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)
    confidence_level: str = "medium"
    sources: List[str] = Field(default_factory=list)
    shared_with_teams: List[str] = Field(default_factory=lambda: ["red", "blue", "purple", "white"])


class ThreatReportResponse(BaseModel):
    report_id: str
    actor_id: Optional[str] = None
    title: str
    report_type: str
    summary: Optional[str] = None
    classification: str
    severity: str
    report_status: str
    authored_by: Optional[str] = None
    confidence_level: str
    created_at: datetime
    published_at: Optional[datetime] = None


# =============================================================================
# Threat Actor Endpoints
# =============================================================================

@router.post("/actors", response_model=ThreatActorResponse, status_code=status.HTTP_201_CREATED)
async def create_actor(
    request: ThreatActorCreate,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Create a new threat actor profile."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import ThreatActorRecord

    actor_id = f"actor_{uuid4().hex[:12]}"
    async with get_session() as session:
        actor = ThreatActorRecord(
            actor_id=actor_id,
            tenant_id=current_user.tenant_id,
            name=request.name,
            aliases=_json_dumps(request.aliases),
            description=request.description,
            actor_type=request.actor_type,
            target_industries=_json_dumps(request.target_industries),
            target_regions=_json_dumps(request.target_regions),
            target_countries=_json_dumps(request.target_countries),
            sophistication_level=request.sophistication_level,
            primary_motivation=request.primary_motivation,
            secondary_motivations=_json_dumps(request.secondary_motivations),
            first_seen=request.first_seen,
            last_seen=request.last_seen,
            is_active=request.is_active,
            confidence_level=request.confidence_level,
            sources=_json_dumps(request.sources),
            collected_by=current_user.user_id,
            collection_method=request.collection_method,
            shared_with_teams=_json_dumps(request.shared_with_teams),
        )
        session.add(actor)
        await session.commit()

        # Audit
        audit = get_audit_logger()
        audit.log(
            "threat_intel.actor.created",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO,
            actor={"user_id": current_user.user_id},
            context={"actor_id": actor_id, "name": request.name},
            description=f"Threat actor created: {request.name}",
        )

        return ThreatActorResponse(
            actor_id=actor.actor_id,
            name=actor.name,
            aliases=_json_loads(actor.aliases),
            description=actor.description,
            actor_type=actor.actor_type,
            target_industries=_json_loads(actor.target_industries),
            target_regions=_json_loads(actor.target_regions),
            sophistication_level=actor.sophistication_level,
            primary_motivation=actor.primary_motivation,
            is_active=actor.is_active,
            confidence_level=actor.confidence_level,
            sources=_json_loads(actor.sources),
            shared_with_teams=_json_loads(actor.shared_with_teams),
            first_seen=actor.first_seen,
            last_seen=actor.last_seen,
            created_at=actor.created_at,
            updated_at=actor.updated_at,
        )


@router.get("/actors", response_model=List[ThreatActorResponse])
async def list_actors(
    skip: int = 0,
    limit: int = 50,
    actor_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    current_user: CurrentUser = Depends(get_current_user),
):
    """List threat actors for the current tenant."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import ThreatActorRecord

    async with get_session() as session:
        query = select(ThreatActorRecord).where(
            ThreatActorRecord.tenant_id == current_user.tenant_id
        )
        if actor_type:
            query = query.where(ThreatActorRecord.actor_type == actor_type)
        if is_active is not None:
            query = query.where(ThreatActorRecord.is_active == is_active)
        query = query.offset(skip).limit(limit).order_by(ThreatActorRecord.created_at.desc())
        result = await session.execute(query)
        actors = result.scalars().all()
        return [
            ThreatActorResponse(
                actor_id=a.actor_id,
                name=a.name,
                aliases=_json_loads(a.aliases),
                description=a.description,
                actor_type=a.actor_type,
                target_industries=_json_loads(a.target_industries),
                target_regions=_json_loads(a.target_regions),
                sophistication_level=a.sophistication_level,
                primary_motivation=a.primary_motivation,
                is_active=a.is_active,
                confidence_level=a.confidence_level,
                sources=_json_loads(a.sources),
                shared_with_teams=_json_loads(a.shared_with_teams),
                first_seen=a.first_seen,
                last_seen=a.last_seen,
                created_at=a.created_at,
                updated_at=a.updated_at,
            )
            for a in actors
        ]


@router.get("/actors/{actor_id}", response_model=ThreatActorResponse)
async def get_actor(
    actor_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get a specific threat actor by ID, including related campaigns."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import ThreatActorRecord

    async with get_session() as session:
        result = await session.execute(
            select(ThreatActorRecord).where(
                ThreatActorRecord.actor_id == actor_id,
                ThreatActorRecord.tenant_id == current_user.tenant_id,
            )
        )
        actor = result.scalar_one_or_none()
        if not actor:
            raise HTTPException(status_code=404, detail="Threat actor not found")
        return ThreatActorResponse(
            actor_id=actor.actor_id,
            name=actor.name,
            aliases=_json_loads(actor.aliases),
            description=actor.description,
            actor_type=actor.actor_type,
            target_industries=_json_loads(actor.target_industries),
            target_regions=_json_loads(actor.target_regions),
            sophistication_level=actor.sophistication_level,
            primary_motivation=actor.primary_motivation,
            is_active=actor.is_active,
            confidence_level=actor.confidence_level,
            sources=_json_loads(actor.sources),
            shared_with_teams=_json_loads(actor.shared_with_teams),
            first_seen=actor.first_seen,
            last_seen=actor.last_seen,
            created_at=actor.created_at,
            updated_at=actor.updated_at,
        )


# =============================================================================
# Campaign Endpoints
# =============================================================================

@router.post("/campaigns", response_model=CampaignResponse, status_code=status.HTTP_201_CREATED)
async def create_campaign(
    request: CampaignCreate,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Create a new threat campaign."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import CampaignRecord

    campaign_id = f"camp_{uuid4().hex[:12]}"
    async with get_session() as session:
        campaign = CampaignRecord(
            campaign_id=campaign_id,
            tenant_id=current_user.tenant_id,
            actor_id=request.actor_id,
            name=request.name,
            description=request.description,
            campaign_status=request.campaign_status,
            start_date=request.start_date,
            end_date=request.end_date,
            target_organizations=_json_dumps(request.target_organizations),
            target_sectors=_json_dumps(request.target_sectors),
            target_geography=_json_dumps(request.target_geography),
            mitre_techniques=_json_dumps(request.mitre_techniques),
            mitre_tactics=_json_dumps(request.mitre_tactics),
            impact_assessment=request.impact_assessment,
            estimated_impact_usd=request.estimated_impact_usd,
            confidence_level=request.confidence_level,
            sources=_json_dumps(request.sources),
            collected_by=current_user.user_id,
            shared_with_teams=_json_dumps(request.shared_with_teams),
        )
        session.add(campaign)
        await session.commit()

        audit = get_audit_logger()
        audit.log(
            "threat_intel.campaign.created",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO,
            actor={"user_id": current_user.user_id},
            context={"campaign_id": campaign_id, "name": request.name},
            description=f"Threat campaign created: {request.name}",
        )

        return CampaignResponse(
            campaign_id=campaign.campaign_id,
            actor_id=campaign.actor_id,
            name=campaign.name,
            description=campaign.description,
            campaign_status=campaign.campaign_status,
            mitre_techniques=_json_loads(campaign.mitre_techniques),
            mitre_tactics=_json_loads(campaign.mitre_tactics),
            target_sectors=_json_loads(campaign.target_sectors),
            confidence_level=campaign.confidence_level,
            is_active=campaign.campaign_status == "active",
            created_at=campaign.created_at,
        )


@router.get("/campaigns", response_model=List[CampaignResponse])
async def list_campaigns(
    actor_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    current_user: CurrentUser = Depends(get_current_user),
):
    """List campaigns, optionally filtered by threat actor."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import CampaignRecord

    async with get_session() as session:
        query = select(CampaignRecord).where(
            CampaignRecord.tenant_id == current_user.tenant_id
        )
        if actor_id:
            query = query.where(CampaignRecord.actor_id == actor_id)
        query = query.offset(skip).limit(limit).order_by(CampaignRecord.created_at.desc())
        result = await session.execute(query)
        campaigns = result.scalars().all()
        return [
            CampaignResponse(
                campaign_id=c.campaign_id,
                actor_id=c.actor_id,
                name=c.name,
                description=c.description,
                campaign_status=c.campaign_status,
                mitre_techniques=_json_loads(c.mitre_techniques),
                mitre_tactics=_json_loads(c.mitre_tactics),
                target_sectors=_json_loads(c.target_sectors),
                confidence_level=c.confidence_level,
                is_active=c.campaign_status == "active",
                created_at=c.created_at,
            )
            for c in campaigns
        ]


# =============================================================================
# Indicator Endpoints
# =============================================================================

@router.post("/indicators", response_model=IndicatorResponse, status_code=status.HTTP_201_CREATED)
async def create_indicator(
    request: IndicatorCreate,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Create a new IOC (Indicator of Compromise)."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import IndicatorRecord

    indicator_id = f"ioc_{uuid4().hex[:12]}"
    ihash = _indicator_hash(request.indicator_type, request.indicator_value)

    async with get_session() as session:
        # Check for duplicate by hash
        existing = await session.execute(
            select(IndicatorRecord).where(IndicatorRecord.indicator_hash == ihash)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=409,
                detail="Duplicate indicator (same type and value already exists)",
            )

        indicator = IndicatorRecord(
            indicator_id=indicator_id,
            tenant_id=current_user.tenant_id,
            campaign_id=request.campaign_id,
            indicator_type=request.indicator_type,
            indicator_value=request.indicator_value,
            indicator_hash=ihash,
            description=request.description,
            context=_json_dumps(request.context),
            mitre_technique=request.mitre_technique,
            threat_score=request.threat_score,
            confidence_level=request.confidence_level,
            sources=_json_dumps(request.sources),
            collected_by=current_user.user_id,
            collection_method=request.collection_method,
            shared_with_teams=_json_dumps(request.shared_with_teams),
            expires_at=request.expires_at,
        )
        session.add(indicator)
        await session.commit()

        audit = get_audit_logger()
        audit.log(
            "threat_intel.indicator.created",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO,
            actor={"user_id": current_user.user_id},
            context={"indicator_id": indicator_id, "type": request.indicator_type},
            description=f"IOC created: {request.indicator_type}={request.indicator_value[:50]}",
        )

        return IndicatorResponse(
            indicator_id=indicator.indicator_id,
            campaign_id=indicator.campaign_id,
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.indicator_value,
            description=indicator.description,
            indicator_state=indicator.indicator_state,
            threat_score=indicator.threat_score,
            confidence_level=indicator.confidence_level,
            mitre_technique=indicator.mitre_technique,
            sources=_json_loads(indicator.sources),
            first_seen=indicator.first_seen,
            last_seen=indicator.last_seen,
            created_at=indicator.created_at,
        )


@router.get("/indicators", response_model=List[IndicatorResponse])
async def list_indicators(
    campaign_id: Optional[str] = None,
    indicator_type: Optional[str] = None,
    indicator_state: Optional[str] = None,
    min_threat_score: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    current_user: CurrentUser = Depends(get_current_user),
):
    """List IOCs with optional filters."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import IndicatorRecord

    async with get_session() as session:
        query = select(IndicatorRecord).where(
            IndicatorRecord.tenant_id == current_user.tenant_id
        )
        if campaign_id:
            query = query.where(IndicatorRecord.campaign_id == campaign_id)
        if indicator_type:
            query = query.where(IndicatorRecord.indicator_type == indicator_type)
        if indicator_state:
            query = query.where(IndicatorRecord.indicator_state == indicator_state)
        if min_threat_score is not None:
            query = query.where(IndicatorRecord.threat_score >= min_threat_score)
        query = query.offset(skip).limit(limit).order_by(IndicatorRecord.created_at.desc())
        result = await session.execute(query)
        indicators = result.scalars().all()
        return [
            IndicatorResponse(
                indicator_id=i.indicator_id,
                campaign_id=i.campaign_id,
                indicator_type=i.indicator_type,
                indicator_value=i.indicator_value,
                description=i.description,
                indicator_state=i.indicator_state,
                threat_score=i.threat_score,
                confidence_level=i.confidence_level,
                mitre_technique=i.mitre_technique,
                sources=_json_loads(i.sources),
                first_seen=i.first_seen,
                last_seen=i.last_seen,
                created_at=i.created_at,
            )
            for i in indicators
        ]


# =============================================================================
# TTP Endpoints
# =============================================================================

@router.post("/ttps", response_model=TTPResponse, status_code=status.HTTP_201_CREATED)
async def create_ttp(
    request: TTPCreate,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Create a new TTP (Technique, Tactic, Procedure) record."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import TTPRecord

    ttp_id = f"ttp_{uuid4().hex[:12]}"
    async with get_session() as session:
        ttp = TTPRecord(
            ttp_id=ttp_id,
            tenant_id=current_user.tenant_id,
            campaign_id=request.campaign_id,
            mitre_technique_id=request.mitre_technique_id,
            mitre_tactic=request.mitre_tactic,
            ttp_name=request.ttp_name,
            ttp_category=request.ttp_category,
            description=request.description,
            observed_procedure=request.observed_procedure,
            detection_recommendations=request.detection_recommendations,
            detection_data_sources=_json_dumps(request.detection_data_sources),
            sigma_rule=request.sigma_rule,
            splunk_query=request.splunk_query,
            elastic_query=request.elastic_query,
            sentinel_query=request.sentinel_query,
            mitigation_recommendations=request.mitigation_recommendations,
            simulation_applicability=request.simulation_applicability,
            confidence_level=request.confidence_level,
            sources=_json_dumps(request.sources),
            collected_by=current_user.user_id,
            shared_with_teams=_json_dumps(request.shared_with_teams),
        )
        session.add(ttp)
        await session.commit()

        audit = get_audit_logger()
        audit.log(
            "threat_intel.ttp.created",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO,
            actor={"user_id": current_user.user_id},
            context={"ttp_id": ttp_id, "technique": request.mitre_technique_id},
            description=f"TTP created: {request.ttp_name}",
        )

        return TTPResponse(
            ttp_id=ttp.ttp_id,
            campaign_id=ttp.campaign_id,
            mitre_technique_id=ttp.mitre_technique_id,
            mitre_tactic=ttp.mitre_tactic,
            ttp_name=ttp.ttp_name,
            ttp_category=ttp.ttp_category,
            description=ttp.description,
            observed_procedure=ttp.observed_procedure,
            detection_recommendations=ttp.detection_recommendations,
            sigma_rule=ttp.sigma_rule,
            splunk_query=ttp.splunk_query,
            mitigation_recommendations=ttp.mitigation_recommendations,
            confidence_level=ttp.confidence_level,
            created_at=ttp.created_at,
        )


@router.get("/ttps", response_model=List[TTPResponse])
async def list_ttps(
    campaign_id: Optional[str] = None,
    mitre_technique_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    current_user: CurrentUser = Depends(get_current_user),
):
    """List TTPs with optional filters."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import TTPRecord

    async with get_session() as session:
        query = select(TTPRecord).where(TTPRecord.tenant_id == current_user.tenant_id)
        if campaign_id:
            query = query.where(TTPRecord.campaign_id == campaign_id)
        if mitre_technique_id:
            query = query.where(TTPRecord.mitre_technique_id == mitre_technique_id)
        query = query.offset(skip).limit(limit).order_by(TTPRecord.created_at.desc())
        result = await session.execute(query)
        ttps = result.scalars().all()
        return [
            TTPResponse(
                ttp_id=t.ttp_id,
                campaign_id=t.campaign_id,
                mitre_technique_id=t.mitre_technique_id,
                mitre_tactic=t.mitre_tactic,
                ttp_name=t.ttp_name,
                ttp_category=t.ttp_category,
                description=t.description,
                observed_procedure=t.observed_procedure,
                detection_recommendations=t.detection_recommendations,
                sigma_rule=t.sigma_rule,
                splunk_query=t.splunk_query,
                mitigation_recommendations=t.mitigation_recommendations,
                confidence_level=t.confidence_level,
                created_at=t.created_at,
            )
            for t in ttps
        ]


# =============================================================================
# Threat Report Endpoints
# =============================================================================

@router.post("/reports", response_model=ThreatReportResponse, status_code=status.HTTP_201_CREATED)
async def create_report(
    request: ThreatReportCreate,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Create a new threat intelligence report."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import ThreatReportRecord

    report_id = f"rpt_{uuid4().hex[:12]}"
    async with get_session() as session:
        report = ThreatReportRecord(
            report_id=report_id,
            tenant_id=current_user.tenant_id,
            actor_id=request.actor_id,
            title=request.title,
            report_type=request.report_type,
            summary=request.summary,
            body=request.body,
            classification=request.classification,
            severity=request.severity,
            affected_industries=_json_dumps(request.affected_industries),
            affected_regions=_json_dumps(request.affected_regions),
            mitre_techniques=_json_dumps(request.mitre_techniques),
            recommendations=_json_dumps(request.recommendations),
            remediation_steps=_json_dumps(request.remediation_steps),
            confidence_level=request.confidence_level,
            sources=_json_dumps(request.sources),
            authored_by=current_user.user_id,
            shared_with_teams=_json_dumps(request.shared_with_teams),
        )
        session.add(report)
        await session.commit()

        audit = get_audit_logger()
        audit.log(
            "threat_intel.report.created",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO,
            actor={"user_id": current_user.user_id},
            context={"report_id": report_id, "title": request.title},
            description=f"Threat report created: {request.title}",
        )

        return ThreatReportResponse(
            report_id=report.report_id,
            actor_id=report.actor_id,
            title=report.title,
            report_type=report.report_type,
            summary=report.summary,
            classification=report.classification,
            severity=report.severity,
            report_status=report.report_status,
            authored_by=report.authored_by,
            confidence_level=report.confidence_level,
            created_at=report.created_at,
            published_at=report.published_at,
        )


@router.get("/reports", response_model=List[ThreatReportResponse])
async def list_reports(
    report_type: Optional[str] = None,
    severity: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    current_user: CurrentUser = Depends(get_current_user),
):
    """List threat reports."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import ThreatReportRecord

    async with get_session() as session:
        query = select(ThreatReportRecord).where(
            ThreatReportRecord.tenant_id == current_user.tenant_id
        )
        if report_type:
            query = query.where(ThreatReportRecord.report_type == report_type)
        if severity:
            query = query.where(ThreatReportRecord.severity == severity)
        query = query.offset(skip).limit(limit).order_by(ThreatReportRecord.created_at.desc())
        result = await session.execute(query)
        reports = result.scalars().all()
        return [
            ThreatReportResponse(
                report_id=r.report_id,
                actor_id=r.actor_id,
                title=r.title,
                report_type=r.report_type,
                summary=r.summary,
                classification=r.classification,
                severity=r.severity,
                report_status=r.report_status,
                authored_by=r.authored_by,
                confidence_level=r.confidence_level,
                created_at=r.created_at,
                published_at=r.published_at,
            )
            for r in reports
        ]


# =============================================================================
# Cross-Entity Search & Correlation
# =============================================================================

class SearchRequest(BaseModel):
    query: str = Field(..., description="Search query")
    entity_types: List[str] = Field(
        default_factory=lambda: ["actors", "campaigns", "indicators", "ttps", "reports"],
        description="Entity types to search",
    )
    limit: int = Field(20, description="Max results per entity type")


@router.post("/search")
async def search_intelligence(
    request: SearchRequest,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Search across all threat intelligence entities."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import (
        ThreatActorRecord, CampaignRecord, IndicatorRecord,
        TTPRecord, ThreatReportRecord,
    )

    results: Dict[str, List[Dict[str, Any]]] = {}
    q = f"%{request.query}%"

    async with get_session() as session:
        if "actors" in request.entity_types:
            r = await session.execute(
                select(ThreatActorRecord).where(
                    ThreatActorRecord.tenant_id == current_user.tenant_id,
                    or_(
                        ThreatActorRecord.name.ilike(q),
                        ThreatActorRecord.description.ilike(q),
                        ThreatActorRecord.aliases.ilike(q),
                    )
                ).limit(request.limit)
            )
            results["actors"] = [
                {"actor_id": a.actor_id, "name": a.name, "type": a.actor_type,
                 "confidence": a.confidence_level, "is_active": a.is_active}
                for a in r.scalars().all()
            ]

        if "campaigns" in request.entity_types:
            r = await session.execute(
                select(CampaignRecord).where(
                    CampaignRecord.tenant_id == current_user.tenant_id,
                    or_(
                        CampaignRecord.name.ilike(q),
                        CampaignRecord.description.ilike(q),
                    )
                ).limit(request.limit)
            )
            results["campaigns"] = [
                {"campaign_id": c.campaign_id, "name": c.name, "status": c.campaign_status,
                 "actor_id": c.actor_id, "confidence": c.confidence_level}
                for c in r.scalars().all()
            ]

        if "indicators" in request.entity_types:
            r = await session.execute(
                select(IndicatorRecord).where(
                    IndicatorRecord.tenant_id == current_user.tenant_id,
                    or_(
                        IndicatorRecord.indicator_value.ilike(q),
                        IndicatorRecord.description.ilike(q),
                    )
                ).limit(request.limit)
            )
            results["indicators"] = [
                {"indicator_id": i.indicator_id, "type": i.indicator_type,
                 "value": i.indicator_value[:100], "state": i.indicator_state,
                 "threat_score": i.threat_score}
                for i in r.scalars().all()
            ]

        if "ttps" in request.entity_types:
            r = await session.execute(
                select(TTPRecord).where(
                    TTPRecord.tenant_id == current_user.tenant_id,
                    or_(
                        TTPRecord.ttp_name.ilike(q),
                        TTPRecord.description.ilike(q),
                        TTPRecord.mitre_technique_id.ilike(q),
                    )
                ).limit(request.limit)
            )
            results["ttps"] = [
                {"ttp_id": t.ttp_id, "name": t.ttp_name,
                 "technique": t.mitre_technique_id, "tactic": t.mitre_tactic}
                for t in r.scalars().all()
            ]

        if "reports" in request.entity_types:
            r = await session.execute(
                select(ThreatReportRecord).where(
                    ThreatReportRecord.tenant_id == current_user.tenant_id,
                    or_(
                        ThreatReportRecord.title.ilike(q),
                        ThreatReportRecord.summary.ilike(q),
                    )
                ).limit(request.limit)
            )
            results["reports"] = [
                {"report_id": r.report_id, "title": r.title, "type": r.report_type,
                 "severity": r.severity, "status": r.report_status}
                for r in r.scalars().all()
            ]

    total = sum(len(v) for v in results.values())
    return {"query": request.query, "total": total, "results": results}


@router.get("/correlate/{mitre_technique_id}")
async def correlate_by_technique(
    mitre_technique_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Correlate all threat intelligence entities by MITRE ATT&CK technique.

    Returns campaigns, TTPs, indicators, and reports that reference
    the given MITRE technique ID. This is the key endpoint for
    cross-team intelligence sharing — Blue Team can use it to find
    detections for a technique, Red Team can use it to find observed
    procedures, and Purple Team can use it for AAR coverage analysis.
    """
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import (
        CampaignRecord, TTPRecord, IndicatorRecord, ThreatReportRecord,
    )

    result: Dict[str, Any] = {
        "mitre_technique_id": mitre_technique_id,
        "campaigns": [],
        "ttps": [],
        "indicators": [],
        "reports": [],
    }

    async with get_session() as session:
        # Campaigns using this technique
        camps = await session.execute(
            select(CampaignRecord).where(
                CampaignRecord.tenant_id == current_user.tenant_id,
                CampaignRecord.mitre_techniques.ilike(f"%{mitre_technique_id}%"),
            )
        )
        result["campaigns"] = [
            {"campaign_id": c.campaign_id, "name": c.name, "actor_id": c.actor_id}
            for c in camps.scalars().all()
        ]

        # TTPs for this technique
        ttps = await session.execute(
            select(TTPRecord).where(
                TTPRecord.tenant_id == current_user.tenant_id,
                TTPRecord.mitre_technique_id == mitre_technique_id,
            )
        )
        result["ttps"] = [
            {"ttp_id": t.ttp_id, "name": t.ttp_name,
             "detection": t.detection_recommendations,
             "sigma_rule": t.sigma_rule is not None,
             "splunk_query": t.splunk_query is not None}
            for t in ttps.scalars().all()
        ]

        # Indicators mapped to this technique
        iocs = await session.execute(
            select(IndicatorRecord).where(
                IndicatorRecord.tenant_id == current_user.tenant_id,
                IndicatorRecord.mitre_technique == mitre_technique_id,
            )
        )
        result["indicators"] = [
            {"indicator_id": i.indicator_id, "type": i.indicator_type,
             "value": i.indicator_value[:100], "state": i.indicator_state}
            for i in iocs.scalars().all()
        ]

        # Reports mentioning this technique
        reports = await session.execute(
            select(ThreatReportRecord).where(
                ThreatReportRecord.tenant_id == current_user.tenant_id,
                ThreatReportRecord.mitre_techniques.ilike(f"%{mitre_technique_id}%"),
            )
        )
        result["reports"] = [
            {"report_id": r.report_id, "title": r.title, "severity": r.severity}
            for r in reports.scalars().all()
        ]

    result["total"] = sum(len(v) for v in result.values() if isinstance(v, list))
    return result


# =============================================================================
# Statistics
# =============================================================================

@router.get("/stats")
async def intelligence_stats(
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get threat intelligence statistics for the current tenant."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.threat_intel import (
        ThreatActorRecord, CampaignRecord, IndicatorRecord,
        TTPRecord, ThreatReportRecord, MalwareFamilyRecord,
    )

    stats: Dict[str, Any] = {}
    async with get_session() as session:
        for name, model in [
            ("actors", ThreatActorRecord),
            ("campaigns", CampaignRecord),
            ("indicators", IndicatorRecord),
            ("ttps", TTPRecord),
            ("reports", ThreatReportRecord),
            ("malware_families", MalwareFamilyRecord),
        ]:
            count = await session.execute(
                select(func.count(model.id)).where(model.tenant_id == current_user.tenant_id)
            )
            stats[name] = count.scalar_one()

        # Active indicators
        active_iocs = await session.execute(
            select(func.count(IndicatorRecord.id)).where(
                IndicatorRecord.tenant_id == current_user.tenant_id,
                IndicatorRecord.indicator_state == "active",
            )
        )
        stats["active_indicators"] = active_iocs.scalar_one()

        # Active campaigns
        active_camps = await session.execute(
            select(func.count(CampaignRecord.id)).where(
                CampaignRecord.tenant_id == current_user.tenant_id,
                CampaignRecord.campaign_status == "active",
            )
        )
        stats["active_campaigns"] = active_camps.scalar_one()

    return stats
