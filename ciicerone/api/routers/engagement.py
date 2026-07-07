"""Engagement Management API Router.

Provides API endpoints for managing client engagements for zero-day
vulnerability research — including rules of engagement, target scope,
legal authorization, and engagement lifecycle.
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, status, Query
from pydantic import BaseModel, Field

from ciicerone.research.engagement import (
    EngagementManager, Engagement, RulesOfEngagement, LegalFramework,
    TargetEntry, TargetType, ResearchMethod, EngagementStatus, AuthorizationType,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/engagements", tags=["Engagement Management"])

# Singleton manager
_manager: Optional[EngagementManager] = None


def _get_manager() -> EngagementManager:
    global _manager
    if _manager is None:
        _manager = EngagementManager()
    return _manager


# =========================================================================
# Request / Response Models
# =========================================================================

class TargetEntryCreate(BaseModel):
    target_type: str = Field("ip_address", description="Type of target")
    value: str = Field(..., description="Target value (IP, domain, URL, etc.)")
    description: str = Field("", description="Description of the target")
    ports: List[int] = Field(default_factory=list, description="Specific ports (empty = all)")
    excluded: bool = Field(False, description="Is this target explicitly excluded?")
    notes: str = Field("", description="Additional notes")


class TargetEntryResponse(BaseModel):
    target_id: str
    target_type: str
    value: str
    description: str
    ports: List[int]
    excluded: bool
    notes: str


class RulesOfEngagementCreate(BaseModel):
    allowed_methods: List[str] = Field(
        default_factory=lambda: ["fuzzing", "static_analysis", "binary_analysis",
                                  "network_scanning", "web_testing", "api_testing"],
        description="Allowed research methods"
    )
    prohibited_methods: List[str] = Field(
        default_factory=lambda: ["social_engineering"],
        description="Prohibited research methods"
    )
    business_hours_only: bool = False
    business_hours_start: str = "09:00"
    business_hours_end: str = "17:00"
    timezone: str = "UTC"
    max_concurrent_tests: int = 5
    can_store_crash_inputs: bool = True
    can_retain_pii: bool = False
    data_retention_days: int = 90
    must_purge_after_completion: bool = True
    notify_before_testing: bool = False
    notify_on_critical_finding: bool = True
    notification_email: str = ""
    max_requests_per_second: int = 100
    max_bandwidth_mbps: int = 50
    no_destructive_testing: bool = True
    no_data_exfiltration: bool = True
    no_persistence: bool = True
    no_lateral_movement: bool = True
    disclosure_embargo_days: int = 90
    requires_vendor_notification: bool = True
    requires_cve_assignment: bool = False


class LegalFrameworkCreate(BaseModel):
    authorization_type: str = Field("written_contract", description="Type of authorization")
    contract_reference: str = Field("", description="Contract ID or reference")
    contract_date: Optional[str] = None
    nda_signed: bool = False
    nda_date: Optional[str] = None
    liability_limit: str = ""
    insurance_certificate: str = ""
    jurisdiction: str = ""
    authorized_representative: str = ""
    representative_email: str = ""
    representative_phone: str = ""
    additional_terms: str = ""


class EngagementCreate(BaseModel):
    client: str = Field(..., description="Client organization name")
    engagement_name: str = Field(..., description="Name for this engagement")
    targets: List[TargetEntryCreate] = Field(default_factory=list)
    rules: RulesOfEngagementCreate = Field(default_factory=RulesOfEngagementCreate)
    legal: LegalFrameworkCreate = Field(default_factory=LegalFrameworkCreate)
    start_date: Optional[str] = Field(None, description="ISO date string")
    end_date: Optional[str] = Field(None, description="ISO date string")
    created_by: str = Field("", description="User creating the engagement")
    notes: str = ""


class EngagementResponse(BaseModel):
    id: str
    client: str
    engagement_name: str
    status: str
    targets: List[TargetEntryResponse]
    start_date: Optional[str]
    end_date: Optional[str]
    created_at: str
    updated_at: str
    created_by: str
    notes: str
    findings_count: int
    critical_findings: int


class AuthorizationCheck(BaseModel):
    engagement_id: str
    target_value: str
    method: Optional[str] = None


class AuthorizationResult(BaseModel):
    authorized: bool
    reason: str
    engagement_id: str
    target_value: str


# =========================================================================
# Helpers
# =========================================================================

def _to_response(engagement: Engagement) -> EngagementResponse:
    return EngagementResponse(
        id=engagement.id,
        client=engagement.client,
        engagement_name=engagement.engagement_name,
        status=engagement.status.value,
        targets=[
            TargetEntryResponse(
                target_id=t.target_id,
                target_type=t.target_type.value,
                value=t.value,
                description=t.description,
                ports=t.ports,
                excluded=t.excluded,
                notes=t.notes,
            )
            for t in engagement.targets
        ],
        start_date=engagement.start_date,
        end_date=engagement.end_date,
        created_at=engagement.created_at,
        updated_at=engagement.updated_at,
        created_by=engagement.created_by,
        notes=engagement.notes,
        findings_count=engagement.findings_count,
        critical_findings=engagement.critical_findings,
    )


# =========================================================================
# Endpoints
# =========================================================================

@router.post("", response_model=EngagementResponse, status_code=status.HTTP_201_CREATED)
async def create_engagement(req: EngagementCreate):
    """Create a new client engagement for zero-day research."""
    manager = _get_manager()

    targets = [
        TargetEntry(
            target_type=TargetType(t.target_type),
            value=t.value,
            description=t.description,
            ports=t.ports,
            excluded=t.excluded,
            notes=t.notes,
        )
        for t in req.targets
    ]

    rules = RulesOfEngagement(
        allowed_methods=[ResearchMethod(m) for m in req.rules.allowed_methods],
        prohibited_methods=[ResearchMethod(m) for m in req.rules.prohibited_methods],
        business_hours_only=req.rules.business_hours_only,
        business_hours_start=req.rules.business_hours_start,
        business_hours_end=req.rules.business_hours_end,
        timezone=req.rules.timezone,
        max_concurrent_tests=req.rules.max_concurrent_tests,
        can_store_crash_inputs=req.rules.can_store_crash_inputs,
        can_retain_pii=req.rules.can_retain_pii,
        data_retention_days=req.rules.data_retention_days,
        must_purge_after_completion=req.rules.must_purge_after_completion,
        notify_before_testing=req.rules.notify_before_testing,
        notify_on_critical_finding=req.rules.notify_on_critical_finding,
        notification_email=req.rules.notification_email,
        max_requests_per_second=req.rules.max_requests_per_second,
        max_bandwidth_mbps=req.rules.max_bandwidth_mbps,
        no_destructive_testing=req.rules.no_destructive_testing,
        no_data_exfiltration=req.rules.no_data_exfiltration,
        no_persistence=req.rules.no_persistence,
        no_lateral_movement=req.rules.no_lateral_movement,
        disclosure_embargo_days=req.rules.disclosure_embargo_days,
        requires_vendor_notification=req.rules.requires_vendor_notification,
        requires_cve_assignment=req.rules.requires_cve_assignment,
    )

    legal = LegalFramework(
        authorization_type=AuthorizationType(req.legal.authorization_type),
        contract_reference=req.legal.contract_reference,
        contract_date=req.legal.contract_date,
        nda_signed=req.legal.nda_signed,
        nda_date=req.legal.nda_date,
        liability_limit=req.legal.liability_limit,
        insurance_certificate=req.legal.insurance_certificate,
        jurisdiction=req.legal.jurisdiction,
        authorized_representative=req.legal.authorized_representative,
        representative_email=req.legal.representative_email,
        representative_phone=req.legal.representative_phone,
        additional_terms=req.legal.additional_terms,
    )

    engagement = manager.create_engagement(
        client=req.client,
        engagement_name=req.engagement_name,
        targets=targets,
        rules=rules,
        legal=legal,
        start_date=req.start_date,
        end_date=req.end_date,
        created_by=req.created_by,
    )

    return _to_response(engagement)


@router.get("", response_model=List[EngagementResponse])
async def list_engagements(
    status_filter: Optional[str] = Query(None, alias="status"),
    client: Optional[str] = None,
):
    """List all engagements, optionally filtered by status or client."""
    manager = _get_manager()

    status_enum = None
    if status_filter:
        try:
            status_enum = EngagementStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status: {status_filter}. Valid: {[s.value for s in EngagementStatus]}"
            )

    engagements = manager.list_engagements(status=status_enum, client=client)
    return [_to_response(e) for e in engagements]


@router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(engagement_id: str):
    """Get details of a specific engagement."""
    manager = _get_manager()
    engagement = manager.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {engagement_id} not found")
    return _to_response(engagement)


@router.post("/{engagement_id}/approve", response_model=EngagementResponse)
async def approve_engagement(engagement_id: str):
    """Approve an engagement (move from pending to active)."""
    manager = _get_manager()
    try:
        engagement = manager.approve_engagement(engagement_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(engagement)


@router.post("/{engagement_id}/pause", response_model=EngagementResponse)
async def pause_engagement(engagement_id: str):
    """Pause an active engagement."""
    manager = _get_manager()
    try:
        engagement = manager.pause_engagement(engagement_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(engagement)


@router.post("/{engagement_id}/complete", response_model=EngagementResponse)
async def complete_engagement(engagement_id: str):
    """Mark an engagement as completed."""
    manager = _get_manager()
    try:
        engagement = manager.complete_engagement(engagement_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(engagement)


@router.post("/{engagement_id}/cancel", response_model=EngagementResponse)
async def cancel_engagement(engagement_id: str):
    """Cancel an engagement."""
    manager = _get_manager()
    try:
        engagement = manager.cancel_engagement(engagement_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(engagement)


@router.post("/{engagement_id}/targets", response_model=EngagementResponse)
async def add_target(engagement_id: str, target: TargetEntryCreate):
    """Add a target to an engagement's scope."""
    manager = _get_manager()
    try:
        entry = TargetEntry(
            target_type=TargetType(target.target_type),
            value=target.value,
            description=target.description,
            ports=target.ports,
            excluded=target.excluded,
            notes=target.notes,
        )
        engagement = manager.add_target(engagement_id, entry)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(engagement)


@router.delete("/{engagement_id}/targets/{target_id}", response_model=EngagementResponse)
async def remove_target(engagement_id: str, target_id: str):
    """Remove a target from an engagement's scope."""
    manager = _get_manager()
    try:
        engagement = manager.remove_target(engagement_id, target_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(engagement)


@router.post("/authorize", response_model=AuthorizationResult)
async def check_authorization(req: AuthorizationCheck):
    """Check if a target is authorized for testing under an engagement.

    This is the gatekeeper endpoint. All discovery and attack tools
    should check authorization before operating against any target.
    """
    manager = _get_manager()

    method = None
    if req.method:
        try:
            method = ResearchMethod(req.method)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid method: {req.method}"
            )

    authorized, reason = manager.is_authorized(
        engagement_id=req.engagement_id,
        target_value=req.target_value,
        method=method,
    )

    return AuthorizationResult(
        authorized=authorized,
        reason=reason,
        engagement_id=req.engagement_id,
        target_value=req.target_value,
    )


@router.get("/{engagement_id}/export")
async def export_engagement(engagement_id: str, format: str = "json"):
    """Export an engagement as JSON or markdown."""
    manager = _get_manager()
    engagement = manager.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {engagement_id} not found")

    content = manager.export_engagement(engagement_id, format=format)
    return {"format": format, "content": content}
