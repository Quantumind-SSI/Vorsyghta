"""
Vulnerability Disclosure Workflow

Manages the responsible disclosure process for vulnerabilities
discovered during zero-day research engagements. Tracks CVE
coordination, vendor notification, embargo periods, and public
disclosure timelines.

Follows the principles of coordinated vulnerability disclosure (CVD):
    1. Notify vendor with details and PoC
    2. Agree on disclosure timeline (default 90-day embargo)
    3. CVE assignment via CNA (CVE Numbering Authority)
    4. Public disclosure after embargo or vendor patch
    5. Track vendor response and patch status

Usage:
    from vorsyghta.research.disclosure import DisclosureManager, DisclosureRecord

    manager = DisclosureManager()
    disclosure = manager.create_disclosure(
        engagement_id="abc123",
        finding_id="finding_456",
        vendor="Acme Corp",
        product="Acme Web Server",
        severity="critical",
        description="Heap buffer overflow in HTTP parser",
    )
    manager.notify_vendor(disclosure.id)
    manager.request_cve(disclosure.id)
"""

import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)


class DisclosureStatus(str, Enum):
    """Status of a vulnerability disclosure."""
    DRAFT = "draft"                         # Being prepared
    VENDOR_NOTIFIED = "vendor_notified"     # Vendor has been contacted
    VENDOR_ACKNOWLEDGED = "vendor_acknowledged"  # Vendor confirmed receipt
    VENDOR_INVESTIGATING = "vendor_investigating"  # Vendor is investigating
    PATCH_IN_PROGRESS = "patch_in_progress"  # Vendor is developing a fix
    PATCH_RELEASED = "patch_released"        # Vendor has released a fix
    CVE_ASSIGNED = "cve_assigned"            # CVE ID has been assigned
    PUBLISHED = "published"                  # Publicly disclosed
    EMBARGOED = "embargoed"                  # Under embargo
    DISPUTED = "disputed"                    # Vendor disputes the finding
    REJECTED = "rejected"                    # Finding was rejected
    WITHDRAWN = "withdrawn"                  # Researcher withdrew the finding


class VendorResponse(str, Enum):
    """Vendor response to a vulnerability notification."""
    NO_RESPONSE = "no_response"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    FIX_IN_PROGRESS = "fix_in_progress"
    FIXED = "fixed"
    DISPUTED = "disputed"
    REJECTED = "rejected"
    REQUESTED_EXTENSION = "requested_extension"
    REQUESTED_EMBARGO = "requested_embargo"


class DisclosureTimeline(str, Enum):
    """Standard disclosure timeline milestones."""
    INITIAL_NOTIFICATION = "initial_notification"
    VENDOR_ACKNOWLEDGMENT = "vendor_acknowledgment"
    CVE_REQUEST = "cve_request"
    CVE_ASSIGNED = "cve_assigned"
    PATCH_TARGET_DATE = "patch_target_date"
    PATCH_RELEASED = "patch_released"
    PUBLIC_DISCLOSURE = "public_disclosure"
    EXTENSION_GRANTED = "extension_granted"


@dataclass
class TimelineEvent:
    """An event in the disclosure timeline."""
    event_id: str = field(default_factory=lambda: str(uuid4())[:12])
    event_type: str = ""               # DisclosureTimeline value or custom
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    description: str = ""
    actor: str = ""                    # Who performed the action
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VendorContact:
    """Contact information for a vendor's security team."""
    company: str = ""
    security_email: str = ""           # security@, cert@, etc.
    psirt_contact: str = ""            # Product Security Incident Response Team
    phone: str = ""
    pgp_key_id: str = ""               # For encrypted communication
    bug_bounty_program: str = ""       # URL if they have one
    disclosure_policy: str = ""        # URL of their disclosure policy
    preferred_channel: str = "email"   # email, phone, portal

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DisclosureRecord:
    """A single vulnerability disclosure record."""
    id: str = field(default_factory=lambda: str(uuid4())[:12])
    engagement_id: str = ""            # Link to engagement
    finding_id: str = ""               # Link to specific finding

    # Vulnerability details
    title: str = ""
    cve_id: Optional[str] = None       # Assigned CVE (e.g., CVE-2024-12345)
    cve_request_id: Optional[str] = None  # CNA request tracking
    severity: str = "medium"           # critical, high, medium, low
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = ""
    affected_versions: str = ""
    description: str = ""
    proof_of_concept: str = ""
    reproduction_steps: str = ""
    remediation_advice: str = ""

    # Vendor information
    vendor: str = ""
    product: str = ""
    vendor_contact: VendorContact = field(default_factory=VendorContact)
    vendor_response: VendorResponse = VendorResponse.NO_RESPONSE
    vendor_tracking_id: str = ""       # Vendor's internal tracking number
    vendor_notes: str = ""

    # Disclosure timeline
    status: DisclosureStatus = DisclosureStatus.DRAFT
    timeline: List[TimelineEvent] = field(default_factory=list)

    # Dates
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    notified_at: Optional[str] = None
    acknowledged_at: Optional[str] = None
    patch_target_date: Optional[str] = None
    patch_released_at: Optional[str] = None
    cve_assigned_at: Optional[str] = None
    public_disclosure_date: Optional[str] = None
    embargo_end_date: Optional[str] = None

    # Embargo
    embargo_days: int = 90             # Default 90-day embargo
    embargo_extensions: int = 0        # Number of extensions granted
    max_extensions: int = 2            # Maximum extensions allowed

    # Communication log
    communication_log: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["vendor_response"] = self.vendor_response.value
        return d

    def is_under_embargo(self) -> bool:
        """Check if the disclosure is currently under embargo."""
        if self.status in [DisclosureStatus.PUBLISHED, DisclosureStatus.WITHDRAWN]:
            return False

        if self.embargo_end_date:
            now = datetime.utcnow()
            end = datetime.fromisoformat(self.embargo_end_date.replace("Z", ""))
            return now < end

        return False

    def days_until_disclosure(self) -> int:
        """Days remaining until public disclosure is permitted."""
        if not self.embargo_end_date:
            return self.embargo_days

        now = datetime.utcnow()
        end = datetime.fromisoformat(self.embargo_end_date.replace("Z", ""))
        delta = end - now
        return max(delta.days, 0)


def _safe_vendor_response(value: str) -> VendorResponse:
    """Safely parse a VendorResponse enum, falling back to NO_RESPONSE."""
    try:
        return VendorResponse(value)
    except (ValueError, TypeError):
        logger.warning(f"Invalid vendor_response in saved data: {value}")
        return VendorResponse.NO_RESPONSE


def _safe_disclosure_status(value: str) -> DisclosureStatus:
    """Safely parse a DisclosureStatus enum, falling back to DRAFT."""
    try:
        return DisclosureStatus(value)
    except (ValueError, TypeError):
        logger.warning(f"Invalid disclosure status in saved data: {value}")
        return DisclosureStatus.DRAFT


class DisclosureManager:
    """
    Manages the vulnerability disclosure lifecycle.

    Handles vendor notification, CVE coordination, embargo tracking,
    and public disclosure timing per coordinated vulnerability
    disclosure (CVD) principles.
    """

    # Default embargo periods by severity (days)
    DEFAULT_EMBARGO = {
        "critical": 90,
        "high": 90,
        "medium": 120,
        "low": 180,
    }

    def __init__(self, storage_dir: str = None):
        """
        Args:
            storage_dir: Directory to persist disclosure records.
                         Defaults to ~/.vorsyghta/disclosures/
        """
        self.storage_dir = storage_dir or os.path.expanduser(
            "~/.vorsyghta/disclosures"
        )
        os.makedirs(self.storage_dir, exist_ok=True)
        self._disclosures: Dict[str, DisclosureRecord] = {}
        self._load_all()

    def _load_all(self):
        """Load all disclosures from storage."""
        if not os.path.isdir(self.storage_dir):
            return

        for filename in os.listdir(self.storage_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(self.storage_dir, filename)
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                    disclosure = self._from_dict(data)
                    self._disclosures[disclosure.id] = disclosure
                except Exception as e:
                    logger.error(f"Failed to load disclosure {filename}: {e}")

    def _from_dict(self, data: dict) -> DisclosureRecord:
        """Reconstruct a DisclosureRecord from a dict."""
        vc_data = data.get("vendor_contact", {})
        vendor_contact = VendorContact(**vc_data)

        timeline = [
            TimelineEvent(
                event_id=e.get("event_id", str(uuid4())[:12]),
                event_type=e.get("event_type", ""),
                timestamp=e.get("timestamp", datetime.utcnow().isoformat()),
                description=e.get("description", ""),
                actor=e.get("actor", ""),
                metadata=e.get("metadata", {}),
            )
            for e in data.get("timeline", [])
        ]

        return DisclosureRecord(
            id=data.get("id", str(uuid4())[:12]),
            engagement_id=data.get("engagement_id", ""),
            finding_id=data.get("finding_id", ""),
            title=data.get("title", ""),
            cve_id=data.get("cve_id"),
            cve_request_id=data.get("cve_request_id"),
            severity=data.get("severity", "medium"),
            cvss_score=data.get("cvss_score", 0.0),
            cvss_vector=data.get("cvss_vector", ""),
            cwe_id=data.get("cwe_id", ""),
            affected_versions=data.get("affected_versions", ""),
            description=data.get("description", ""),
            proof_of_concept=data.get("proof_of_concept", ""),
            reproduction_steps=data.get("reproduction_steps", ""),
            remediation_advice=data.get("remediation_advice", ""),
            vendor=data.get("vendor", ""),
            product=data.get("product", ""),
            vendor_contact=vendor_contact,
            vendor_response=_safe_vendor_response(data.get("vendor_response", "no_response")),
            vendor_tracking_id=data.get("vendor_tracking_id", ""),
            vendor_notes=data.get("vendor_notes", ""),
            status=_safe_disclosure_status(data.get("status", "draft")),
            timeline=timeline,
            discovered_at=data.get("discovered_at", datetime.utcnow().isoformat()),
            notified_at=data.get("notified_at"),
            acknowledged_at=data.get("acknowledged_at"),
            patch_target_date=data.get("patch_target_date"),
            patch_released_at=data.get("patch_released_at"),
            cve_assigned_at=data.get("cve_assigned_at"),
            public_disclosure_date=data.get("public_disclosure_date"),
            embargo_end_date=data.get("embargo_end_date"),
            embargo_days=data.get("embargo_days", 90),
            embargo_extensions=data.get("embargo_extensions", 0),
            max_extensions=data.get("max_extensions", 2),
            communication_log=data.get("communication_log", []),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            updated_at=data.get("updated_at", datetime.utcnow().isoformat()),
            created_by=data.get("created_by", ""),
        )

    def _save(self, disclosure: DisclosureRecord):
        """Persist a disclosure to disk."""
        filepath = os.path.join(self.storage_dir, f"{disclosure.id}.json")
        with open(filepath, "w") as f:
            json.dump(disclosure.to_dict(), f, indent=2)
        logger.info(f"Disclosure {disclosure.id} saved to {filepath}")

    def _add_timeline_event(
        self,
        disclosure: DisclosureRecord,
        event_type: str,
        description: str,
        actor: str = "system",
        metadata: Dict = None,
    ):
        """Add a timeline event to a disclosure."""
        event = TimelineEvent(
            event_type=event_type,
            description=description,
            actor=actor,
            metadata=metadata or {},
        )
        disclosure.timeline.append(event)
        disclosure.updated_at = datetime.utcnow().isoformat()

    def create_disclosure(
        self,
        engagement_id: str,
        finding_id: str,
        vendor: str,
        product: str,
        title: str,
        severity: str = "medium",
        description: str = "",
        cvss_score: float = 0.0,
        cwe_id: str = "",
        affected_versions: str = "",
        proof_of_concept: str = "",
        reproduction_steps: str = "",
        remediation_advice: str = "",
        vendor_contact: VendorContact = None,
        embargo_days: int = None,
        created_by: str = "",
    ) -> DisclosureRecord:
        """Create a new disclosure record.

        Args:
            engagement_id: ID of the engagement this finding belongs to
            finding_id: ID of the specific finding
            vendor: Vendor/company name
            product: Product name
            title: Vulnerability title
            severity: critical, high, medium, low
            description: Vulnerability description
            cvss_score: CVSS score
            cwe_id: CWE identifier
            affected_versions: Affected version range
            proof_of_concept: PoC text
            reproduction_steps: How to reproduce
            remediation_advice: How to fix
            vendor_contact: Vendor security contact info
            embargo_days: Embargo period (default: 90 for critical/high)
            created_by: User creating the disclosure

        Returns:
            The created DisclosureRecord
        """
        if embargo_days is None:
            embargo_days = self.DEFAULT_EMBARGO.get(severity, 90)

        embargo_end = (
            datetime.utcnow() + timedelta(days=embargo_days)
        ).isoformat()

        disclosure = DisclosureRecord(
            engagement_id=engagement_id,
            finding_id=finding_id,
            vendor=vendor,
            product=product,
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            cwe_id=cwe_id,
            affected_versions=affected_versions,
            description=description,
            proof_of_concept=proof_of_concept,
            reproduction_steps=reproduction_steps,
            remediation_advice=remediation_advice,
            vendor_contact=vendor_contact or VendorContact(company=vendor),
            embargo_days=embargo_days,
            embargo_end_date=embargo_end,
            created_by=created_by,
        )

        self._add_timeline_event(
            disclosure,
            DisclosureTimeline.INITIAL_NOTIFICATION.value,
            f"Disclosure record created for {vendor} {product}",
            actor=created_by,
        )

        self._disclosures[disclosure.id] = disclosure
        self._save(disclosure)

        logger.info(
            f"Created disclosure {disclosure.id} for {vendor} {product} "
            f"(severity: {severity}, embargo: {embargo_days} days)"
        )
        return disclosure

    def notify_vendor(
        self,
        disclosure_id: str,
        notification_method: str = "email",
        notification_details: str = "",
        actor: str = "system",
    ) -> DisclosureRecord:
        """Record that the vendor has been notified.

        Args:
            disclosure_id: Disclosure ID
            notification_method: How the vendor was notified (email, phone, portal)
            notification_details: Details of the notification
            actor: Who sent the notification

        Returns:
            Updated DisclosureRecord
        """
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        disclosure.notified_at = datetime.utcnow().isoformat()
        disclosure.status = DisclosureStatus.VENDOR_NOTIFIED

        self._add_timeline_event(
            disclosure,
            DisclosureTimeline.INITIAL_NOTIFICATION.value,
            f"Vendor notified via {notification_method}: {notification_details}",
            actor=actor,
            metadata={"method": notification_method},
        )

        # Log the communication
        disclosure.communication_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "direction": "outbound",
            "method": notification_method,
            "details": notification_details,
            "actor": actor,
        })

        self._save(disclosure)
        logger.info(f"Vendor {disclosure.vendor} notified for disclosure {disclosure_id}")
        return disclosure

    def record_vendor_response(
        self,
        disclosure_id: str,
        response: VendorResponse,
        details: str = "",
        vendor_tracking_id: str = "",
        actor: str = "vendor",
    ) -> DisclosureRecord:
        """Record a vendor's response to the notification.

        Args:
            disclosure_id: Disclosure ID
            response: Vendor's response type
            details: Details of the response
            vendor_tracking_id: Vendor's internal tracking ID
            actor: Who recorded this response

        Returns:
            Updated DisclosureRecord
        """
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        disclosure.vendor_response = response
        disclosure.vendor_notes = details
        if vendor_tracking_id:
            disclosure.vendor_tracking_id = vendor_tracking_id

        # Update status based on response
        now = datetime.utcnow().isoformat()

        if response == VendorResponse.ACKNOWLEDGED:
            disclosure.status = DisclosureStatus.VENDOR_ACKNOWLEDGED
            disclosure.acknowledged_at = now
            self._add_timeline_event(
                disclosure,
                DisclosureTimeline.VENDOR_ACKNOWLEDGMENT.value,
                f"Vendor acknowledged: {details}",
                actor=actor,
            )
        elif response == VendorResponse.INVESTIGATING:
            disclosure.status = DisclosureStatus.VENDOR_INVESTIGATING
            self._add_timeline_event(
                disclosure,
                "vendor_investigating",
                f"Vendor is investigating: {details}",
                actor=actor,
            )
        elif response == VendorResponse.FIX_IN_PROGRESS:
            disclosure.status = DisclosureStatus.PATCH_IN_PROGRESS
            self._add_timeline_event(
                disclosure,
                "fix_in_progress",
                f"Vendor is developing a fix: {details}",
                actor=actor,
            )
        elif response == VendorResponse.FIXED:
            disclosure.status = DisclosureStatus.PATCH_RELEASED
            disclosure.patch_released_at = now
            self._add_timeline_event(
                disclosure,
                DisclosureTimeline.PATCH_RELEASED.value,
                f"Vendor released a patch: {details}",
                actor=actor,
            )
        elif response == VendorResponse.DISPUTED:
            disclosure.status = DisclosureStatus.DISPUTED
            self._add_timeline_event(
                disclosure,
                "disputed",
                f"Vendor disputes the finding: {details}",
                actor=actor,
            )
        elif response == VendorResponse.REJECTED:
            disclosure.status = DisclosureStatus.REJECTED
            self._add_timeline_event(
                disclosure,
                "rejected",
                f"Vendor rejected the finding: {details}",
                actor=actor,
            )
        elif response == VendorResponse.REQUESTED_EXTENSION:
            self._add_timeline_event(
                disclosure,
                DisclosureTimeline.EXTENSION_GRANTED.value,
                f"Vendor requested embargo extension: {details}",
                actor=actor,
            )
        elif response == VendorResponse.REQUESTED_EMBARGO:
            disclosure.status = DisclosureStatus.EMBARGOED
            self._add_timeline_event(
                disclosure,
                "embargo_requested",
                f"Vendor requested embargo: {details}",
                actor=actor,
            )

        # Log the communication
        disclosure.communication_log.append({
            "timestamp": now,
            "direction": "inbound",
            "response": response.value,
            "details": details,
            "actor": actor,
        })

        self._save(disclosure)
        logger.info(
            f"Vendor response for {disclosure_id}: {response.value}"
        )
        return disclosure

    def request_cve(
        self,
        disclosure_id: str,
        cna: str = "MITRE",
        actor: str = "system",
    ) -> DisclosureRecord:
        """Request a CVE ID from a CVE Numbering Authority (CNA).

        Args:
            disclosure_id: Disclosure ID
            cna: CNA to request from (MITRE, GitHub, etc.)
            actor: Who made the request

        Returns:
            Updated DisclosureRecord
        """
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        request_id = f"CVE-REQ-{disclosure.id}-{datetime.utcnow().strftime('%Y%m%d')}"
        disclosure.cve_request_id = request_id

        self._add_timeline_event(
            disclosure,
            DisclosureTimeline.CVE_REQUEST.value,
            f"CVE requested from {cna} (request ID: {request_id})",
            actor=actor,
            metadata={"cna": cna, "request_id": request_id},
        )

        self._save(disclosure)
        logger.info(f"CVE requested for {disclosure_id} from {cna}: {request_id}")
        return disclosure

    def assign_cve(
        self,
        disclosure_id: str,
        cve_id: str,
        actor: str = "cna",
    ) -> DisclosureRecord:
        """Record an assigned CVE ID.

        Args:
            disclosure_id: Disclosure ID
            cve_id: The assigned CVE ID (e.g., CVE-2024-12345)
            actor: Who assigned it (usually the CNA)

        Returns:
            Updated DisclosureRecord
        """
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        disclosure.cve_id = cve_id
        disclosure.cve_assigned_at = datetime.utcnow().isoformat()
        disclosure.status = DisclosureStatus.CVE_ASSIGNED

        self._add_timeline_event(
            disclosure,
            DisclosureTimeline.CVE_ASSIGNED.value,
            f"CVE assigned: {cve_id}",
            actor=actor,
            metadata={"cve_id": cve_id},
        )

        self._save(disclosure)
        logger.info(f"CVE {cve_id} assigned to disclosure {disclosure_id}")
        return disclosure

    def grant_extension(
        self,
        disclosure_id: str,
        extension_days: int,
        reason: str = "",
        actor: str = "system",
    ) -> DisclosureRecord:
        """Grant an embargo extension.

        Args:
            disclosure_id: Disclosure ID
            extension_days: Number of days to extend
            reason: Reason for extension
            actor: Who granted the extension

        Returns:
            Updated DisclosureRecord
        """
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        if disclosure.embargo_extensions >= disclosure.max_extensions:
            raise ValueError(
                f"Maximum extensions ({disclosure.max_extensions}) already granted"
            )

        # Extend embargo end date
        if disclosure.embargo_end_date:
            current_end = datetime.fromisoformat(
                disclosure.embargo_end_date.replace("Z", "")
            )
            new_end = current_end + timedelta(days=extension_days)
            disclosure.embargo_end_date = new_end.isoformat()
        else:
            # Calculate from current time if no end date was set
            new_end = datetime.utcnow() + timedelta(days=extension_days)
            disclosure.embargo_end_date = new_end.isoformat()

        disclosure.embargo_extensions += 1
        disclosure.embargo_days += extension_days

        self._add_timeline_event(
            disclosure,
            DisclosureTimeline.EXTENSION_GRANTED.value,
            f"Embargo extended by {extension_days} days (extension "
            f"{disclosure.embargo_extensions}/{disclosure.max_extensions}): {reason}",
            actor=actor,
            metadata={"extension_days": extension_days, "reason": reason},
        )

        self._save(disclosure)
        logger.info(
            f"Embargo extended for {disclosure_id} by {extension_days} days "
            f"(extension {disclosure.embargo_extensions}/{disclosure.max_extensions})"
        )
        return disclosure

    def set_patch_target(
        self,
        disclosure_id: str,
        target_date: str,
        actor: str = "vendor",
    ) -> DisclosureRecord:
        """Set the vendor's target patch date.

        Args:
            disclosure_id: Disclosure ID
            target_date: ISO date string for target patch release
            actor: Who set the target date

        Returns:
            Updated DisclosureRecord
        """
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        disclosure.patch_target_date = target_date

        self._add_timeline_event(
            disclosure,
            DisclosureTimeline.PATCH_TARGET_DATE.value,
            f"Patch target date set: {target_date}",
            actor=actor,
        )

        self._save(disclosure)
        return disclosure

    def publish(
        self,
        disclosure_id: str,
        actor: str = "system",
        force: bool = False,
    ) -> DisclosureRecord:
        """Publish the vulnerability disclosure publicly.

        Args:
            disclosure_id: Disclosure ID
            actor: Who is publishing
            force: Force publication even if embargo hasn't expired

        Returns:
            Updated DisclosureRecord

        Raises:
            ValueError: If embargo is still active and force=False
        """
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        if disclosure.is_under_embargo() and not force:
            days_left = disclosure.days_until_disclosure()
            raise ValueError(
                f"Disclosure is under embargo. {days_left} days remaining. "
                f"Use force=True to override."
            )

        disclosure.status = DisclosureStatus.PUBLISHED
        disclosure.public_disclosure_date = datetime.utcnow().isoformat()

        self._add_timeline_event(
            disclosure,
            DisclosureTimeline.PUBLIC_DISCLOSURE.value,
            f"Vulnerability publicly disclosed{' (forced)' if force else ''}",
            actor=actor,
            metadata={"forced": force},
        )

        self._save(disclosure)
        logger.info(f"Disclosure {disclosure_id} published publicly")
        return disclosure

    def withdraw(
        self,
        disclosure_id: str,
        reason: str = "",
        actor: str = "system",
    ) -> DisclosureRecord:
        """Withdraw a disclosure (e.g., finding was a false positive).

        Args:
            disclosure_id: Disclosure ID
            reason: Reason for withdrawal
            actor: Who is withdrawing

        Returns:
            Updated DisclosureRecord
        """
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        disclosure.status = DisclosureStatus.WITHDRAWN

        self._add_timeline_event(
            disclosure,
            "withdrawn",
            f"Disclosure withdrawn: {reason}",
            actor=actor,
        )

        self._save(disclosure)
        logger.info(f"Disclosure {disclosure_id} withdrawn: {reason}")
        return disclosure

    def get_disclosure(self, disclosure_id: str) -> Optional[DisclosureRecord]:
        """Get a disclosure by ID."""
        return self._disclosures.get(disclosure_id)

    def list_disclosures(
        self,
        status: DisclosureStatus = None,
        vendor: str = None,
        engagement_id: str = None,
    ) -> List[DisclosureRecord]:
        """List disclosures, optionally filtered."""
        results = list(self._disclosures.values())

        if status:
            results = [d for d in results if d.status == status]

        if vendor:
            results = [d for d in results if d.vendor.lower() == vendor.lower()]

        if engagement_id:
            results = [d for d in results if d.engagement_id == engagement_id]

        return sorted(results, key=lambda d: d.created_at, reverse=True)

    def check_embargo_expiry(self) -> List[DisclosureRecord]:
        """Check all disclosures for expired embargos.

        Returns disclosures where the embargo has expired but
        the disclosure hasn't been published yet.
        """
        expired = []
        now = datetime.utcnow()

        for disclosure in self._disclosures.values():
            if disclosure.status in [
                DisclosureStatus.PUBLISHED,
                DisclosureStatus.WITHDRAWN,
                DisclosureStatus.REJECTED,
            ]:
                continue

            if disclosure.embargo_end_date:
                try:
                    end = datetime.fromisoformat(
                        disclosure.embargo_end_date.replace("Z", "")
                    )
                    if now > end:
                        expired.append(disclosure)
                        logger.info(
                            f"Embargo expired for disclosure {disclosure.id} "
                            f"({disclosure.vendor} {disclosure.product})"
                        )
                except ValueError:
                    continue

        return expired

    def generate_notification_email(
        self,
        disclosure_id: str,
    ) -> str:
        """Generate a vendor notification email template.

        Args:
            disclosure_id: Disclosure ID

        Returns:
            Email text ready to send to the vendor
        """
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        # Generate a safe fallback email from the vendor name
        vendor_slug = ''.join(c for c in disclosure.vendor.lower() if c.isalnum())
        fallback_email = f"security@{vendor_slug}.com" if vendor_slug else "security@vendor.example.com"

        email = f"""Subject: Security Vulnerability Notification — {disclosure.product}

To: {disclosure.vendor_contact.security_email or fallback_email}

Dear {disclosure.vendor} Security Team,

We are writing to notify you of a security vulnerability that we have discovered in your product {disclosure.product}. We believe in coordinated vulnerability disclosure and would like to work with you to address this issue before public disclosure.

## Vulnerability Summary

- **Title:** {disclosure.title}
- **Severity:** {disclosure.severity.upper()} (CVSS: {disclosure.cvss_score})
- **CWE:** {disclosure.cwe_id or 'TBD'}
- **Affected Versions:** {disclosure.affected_versions or 'TBD'}

## Description

{disclosure.description}

## Proof of Concept

{disclosure.proof_of_concept or 'Available upon request'}

## Reproduction Steps

{disclosure.reproduction_steps or 'Available upon request'}

## Suggested Remediation

{disclosure.remediation_advice or 'We are available to discuss remediation options.'}

## Disclosure Timeline

We propose a {disclosure.embargo_days}-day embargo period to allow time for patch development. The embargo end date is {disclosure.embargo_end_date or 'TBD'}.

We are committed to working with you and are open to extending the embargo if needed. Please acknowledge receipt of this notification and provide a tracking ID for this issue.

## Contact

Please respond to this email or contact us through encrypted channels. Our PGP key is available upon request.

We plan to request a CVE ID from MITRE unless you prefer to use your own CNA.

Thank you for your attention to this matter.

Best regards,
The Vorsyghta Security Research Team

---
This notification was generated by the Vorsyghta platform.
Disclosure ID: {disclosure.id}
Engagement ID: {disclosure.engagement_id}
"""
        return email

    def generate_disclosure_report(self, disclosure_id: str) -> str:
        """Generate a public disclosure report (for after embargo).

        Args:
            disclosure_id: Disclosure ID

        Returns:
            Markdown report suitable for public disclosure
        """
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        report = f"""# {disclosure.title}

**CVE:** {disclosure.cve_id or 'Pending'}
**Vendor:** {disclosure.vendor}
**Product:** {disclosure.product}
**Severity:** {disclosure.severity.upper()} (CVSS: {disclosure.cvss_score})
**CWE:** {disclosure.cwe_id or 'N/A'}

## Affected Versions

{disclosure.affected_versions or 'See vendor advisory'}

## Description

{disclosure.description}

## Proof of Concept

```
{disclosure.proof_of_concept}
```

## Reproduction Steps

{disclosure.reproduction_steps}

## Remediation

{disclosure.remediation_advice or 'Update to the latest version as advised by the vendor.'}

## Timeline

| Date | Event |
|------|-------|
"""
        for event in disclosure.timeline:
            date = event.timestamp[:10]
            report += f"| {date} | {event.description} |\n"

        report += f"""
## Credits

Discovered by the Vorsyghta Security Research Team.

## References

- [CVE Detail]({f'https://nvd.nist.gov/vuln/detail/{disclosure.cve_id}' if disclosure.cve_id and disclosure.cve_id.startswith('CVE-') else 'Pending'})
- Vendor advisory: TBD

---
*This disclosure was published after a {disclosure.embargo_days}-day coordinated disclosure process.*
*Disclosure ID: {disclosure.id}*
"""
        return report

    def export_disclosure(self, disclosure_id: str, format: str = "json") -> str:
        """Export a disclosure as JSON or markdown."""
        disclosure = self._disclosures.get(disclosure_id)
        if not disclosure:
            raise ValueError(f"Disclosure {disclosure_id} not found")

        if format == "json":
            return json.dumps(disclosure.to_dict(), indent=2)
        elif format == "email":
            return self.generate_notification_email(disclosure_id)
        elif format == "report":
            return self.generate_disclosure_report(disclosure_id)
        else:
            return json.dumps(disclosure.to_dict(), indent=2)
