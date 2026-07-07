"""Disclosure Workflow API Router.

Provides API endpoints for managing vulnerability disclosure —
CVE coordination, vendor notification, embargo tracking, and
public disclosure timing.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, status, Query
from pydantic import BaseModel, Field

from ciicerone.research.disclosure import (
    DisclosureManager, DisclosureRecord, VendorContact, VendorResponse,
    DisclosureStatus,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/disclosures", tags=["Disclosure Workflow"])

# Singleton manager
_manager: Optional[DisclosureManager] = None


def _get_manager() -> DisclosureManager:
    global _manager
    if _manager is None:
        _manager = DisclosureManager()
    return _manager


# =========================================================================
# Request / Response Models
# =========================================================================

class VendorContactCreate(BaseModel):
    company: str = ""
    security_email: str = ""
    psirt_contact: str = ""
    phone: str = ""
    pgp_key_id: str = ""
    bug_bounty_program: str = ""
    disclosure_policy: str = ""
    preferred_channel: str = "email"


class DisclosureCreate(BaseModel):
    engagement_id: str = Field(..., description="Engagement ID")
    finding_id: str = Field(..., description="Finding ID")
    vendor: str = Field(..., description="Vendor name")
    product: str = Field(..., description="Product name")
    title: str = Field(..., description="Vulnerability title")
    severity: str = Field("medium", description="critical, high, medium, low")
    cvss_score: float = Field(0.0, description="CVSS score")
    cvss_vector: str = ""
    cwe_id: str = ""
    affected_versions: str = ""
    description: str = ""
    proof_of_concept: str = ""
    reproduction_steps: str = ""
    remediation_advice: str = ""
    vendor_contact: VendorContactCreate = Field(default_factory=VendorContactCreate)
    embargo_days: Optional[int] = Field(None, description="Override embargo period")
    created_by: str = ""


class DisclosureResponse(BaseModel):
    id: str
    engagement_id: str
    finding_id: str
    title: str
    cve_id: Optional[str]
    severity: str
    cvss_score: float
    vendor: str
    product: str
    status: str
    vendor_response: str
    notified_at: Optional[str]
    acknowledged_at: Optional[str]
    patch_target_date: Optional[str]
    patch_released_at: Optional[str]
    cve_assigned_at: Optional[str]
    public_disclosure_date: Optional[str]
    embargo_end_date: Optional[str]
    embargo_days: int
    days_until_disclosure: int
    is_under_embargo: bool
    created_at: str
    updated_at: str


class VendorNotificationRequest(BaseModel):
    notification_method: str = Field("email", description="email, phone, portal")
    notification_details: str = Field("", description="Details of the notification")
    actor: str = "system"


class VendorResponseRequest(BaseModel):
    response: str = Field(..., description="Vendor response type")
    details: str = ""
    vendor_tracking_id: str = ""
    actor: str = "vendor"


class CVERequest(BaseModel):
    cna: str = Field("MITRE", description="CVE Numbering Authority")
    actor: str = "system"


class CVEAssignment(BaseModel):
    cve_id: str = Field(..., description="Assigned CVE ID (e.g., CVE-2024-12345)")
    actor: str = "cna"


class ExtensionRequest(BaseModel):
    extension_days: int = Field(..., description="Days to extend embargo")
    reason: str = ""
    actor: str = "system"


class PatchTargetRequest(BaseModel):
    target_date: str = Field(..., description="ISO date string")
    actor: str = "vendor"


class PublishRequest(BaseModel):
    actor: str = "system"
    force: bool = Field(False, description="Force publication even if embargo active")


class WithdrawRequest(BaseModel):
    reason: str = ""
    actor: str = "system"


# =========================================================================
# Helpers
# =========================================================================

def _to_response(d: DisclosureRecord) -> DisclosureResponse:
    return DisclosureResponse(
        id=d.id,
        engagement_id=d.engagement_id,
        finding_id=d.finding_id,
        title=d.title,
        cve_id=d.cve_id,
        severity=d.severity,
        cvss_score=d.cvss_score,
        vendor=d.vendor,
        product=d.product,
        status=d.status.value,
        vendor_response=d.vendor_response.value,
        notified_at=d.notified_at,
        acknowledged_at=d.acknowledged_at,
        patch_target_date=d.patch_target_date,
        patch_released_at=d.patch_released_at,
        cve_assigned_at=d.cve_assigned_at,
        public_disclosure_date=d.public_disclosure_date,
        embargo_end_date=d.embargo_end_date,
        embargo_days=d.embargo_days,
        days_until_disclosure=d.days_until_disclosure(),
        is_under_embargo=d.is_under_embargo(),
        created_at=d.created_at,
        updated_at=d.updated_at,
    )


# =========================================================================
# Endpoints
# =========================================================================

@router.post("", response_model=DisclosureResponse, status_code=status.HTTP_201_CREATED)
async def create_disclosure(req: DisclosureCreate):
    """Create a new vulnerability disclosure record."""
    manager = _get_manager()

    vc = VendorContact(
        company=req.vendor_contact.company or req.vendor,
        security_email=req.vendor_contact.security_email,
        psirt_contact=req.vendor_contact.psirt_contact,
        phone=req.vendor_contact.phone,
        pgp_key_id=req.vendor_contact.pgp_key_id,
        bug_bounty_program=req.vendor_contact.bug_bounty_program,
        disclosure_policy=req.vendor_contact.disclosure_policy,
        preferred_channel=req.vendor_contact.preferred_channel,
    )

    disclosure = manager.create_disclosure(
        engagement_id=req.engagement_id,
        finding_id=req.finding_id,
        vendor=req.vendor,
        product=req.product,
        title=req.title,
        severity=req.severity,
        cvss_score=req.cvss_score,
        cvss_vector=req.cvss_vector,
        cwe_id=req.cwe_id,
        affected_versions=req.affected_versions,
        description=req.description,
        proof_of_concept=req.proof_of_concept,
        reproduction_steps=req.reproduction_steps,
        remediation_advice=req.remediation_advice,
        vendor_contact=vc,
        embargo_days=req.embargo_days,
        created_by=req.created_by,
    )

    return _to_response(disclosure)


@router.get("", response_model=List[DisclosureResponse])
async def list_disclosures(
    status_filter: Optional[str] = Query(None, alias="status"),
    vendor: Optional[str] = None,
    engagement_id: Optional[str] = None,
):
    """List all disclosures, optionally filtered."""
    manager = _get_manager()

    status_enum = None
    if status_filter:
        try:
            status_enum = DisclosureStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status: {status_filter}"
            )

    disclosures = manager.list_disclosures(
        status=status_enum,
        vendor=vendor,
        engagement_id=engagement_id,
    )
    return [_to_response(d) for d in disclosures]


@router.get("/{disclosure_id}", response_model=DisclosureResponse)
async def get_disclosure(disclosure_id: str):
    """Get details of a specific disclosure."""
    manager = _get_manager()
    disclosure = manager.get_disclosure(disclosure_id)
    if not disclosure:
        raise HTTPException(status_code=404, detail=f"Disclosure {disclosure_id} not found")
    return _to_response(disclosure)


@router.post("/{disclosure_id}/notify-vendor", response_model=DisclosureResponse)
async def notify_vendor(disclosure_id: str, req: VendorNotificationRequest):
    """Record that the vendor has been notified."""
    manager = _get_manager()
    try:
        disclosure = manager.notify_vendor(
            disclosure_id,
            notification_method=req.notification_method,
            notification_details=req.notification_details,
            actor=req.actor,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(disclosure)


@router.post("/{disclosure_id}/vendor-response", response_model=DisclosureResponse)
async def record_vendor_response(disclosure_id: str, req: VendorResponseRequest):
    """Record a vendor's response to the notification."""
    manager = _get_manager()
    try:
        response = VendorResponse(req.response)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid response: {req.response}"
        )

    try:
        disclosure = manager.record_vendor_response(
            disclosure_id,
            response=response,
            details=req.details,
            vendor_tracking_id=req.vendor_tracking_id,
            actor=req.actor,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(disclosure)


@router.post("/{disclosure_id}/request-cve", response_model=DisclosureResponse)
async def request_cve(disclosure_id: str, req: CVERequest):
    """Request a CVE ID from a CNA."""
    manager = _get_manager()
    try:
        disclosure = manager.request_cve(
            disclosure_id,
            cna=req.cna,
            actor=req.actor,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(disclosure)


@router.post("/{disclosure_id}/assign-cve", response_model=DisclosureResponse)
async def assign_cve(disclosure_id: str, req: CVEAssignment):
    """Record an assigned CVE ID."""
    manager = _get_manager()
    try:
        disclosure = manager.assign_cve(
            disclosure_id,
            cve_id=req.cve_id,
            actor=req.actor,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(disclosure)


@router.post("/{disclosure_id}/extend-embargo", response_model=DisclosureResponse)
async def grant_extension(disclosure_id: str, req: ExtensionRequest):
    """Grant an embargo extension."""
    manager = _get_manager()
    try:
        disclosure = manager.grant_extension(
            disclosure_id,
            extension_days=req.extension_days,
            reason=req.reason,
            actor=req.actor,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(disclosure)


@router.post("/{disclosure_id}/patch-target", response_model=DisclosureResponse)
async def set_patch_target(disclosure_id: str, req: PatchTargetRequest):
    """Set the vendor's target patch date."""
    manager = _get_manager()
    try:
        disclosure = manager.set_patch_target(
            disclosure_id,
            target_date=req.target_date,
            actor=req.actor,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(disclosure)


@router.post("/{disclosure_id}/publish", response_model=DisclosureResponse)
async def publish_disclosure(disclosure_id: str, req: PublishRequest):
    """Publish the vulnerability disclosure publicly."""
    manager = _get_manager()
    try:
        disclosure = manager.publish(
            disclosure_id,
            actor=req.actor,
            force=req.force,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(disclosure)


@router.post("/{disclosure_id}/withdraw", response_model=DisclosureResponse)
async def withdraw_disclosure(disclosure_id: str, req: WithdrawRequest):
    """Withdraw a disclosure."""
    manager = _get_manager()
    try:
        disclosure = manager.withdraw(
            disclosure_id,
            reason=req.reason,
            actor=req.actor,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_response(disclosure)


@router.get("/{disclosure_id}/export")
async def export_disclosure(disclosure_id: str, format: str = "json"):
    """Export a disclosure as JSON, email template, or public report."""
    manager = _get_manager()
    disclosure = manager.get_disclosure(disclosure_id)
    if not disclosure:
        raise HTTPException(status_code=404, detail=f"Disclosure {disclosure_id} not found")

    content = manager.export_disclosure(disclosure_id, format=format)
    return {"format": format, "content": content}
