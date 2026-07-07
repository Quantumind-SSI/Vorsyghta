"""
Client Engagement Scope Manager

Manages the legal and operational framework for zero-day research
engagements with clients. Tracks rules of engagement, target
inventories, authorization, time windows, and ensures all research
activity stays within authorized scope.

This is the gatekeeper — no discovery or attack tool can run against
a target that is not covered by an active, authorized engagement.

Usage:
    from ciicerone.research.engagement import EngagementManager, Engagement

    manager = EngagementManager()
    engagement = manager.create_engagement(
        client="Acme Corp",
        targets=["10.0.100.10", "10.0.100.11"],
        rules=RulesOfEngagement(...),
    )
    if manager.is_authorized(engagement.id, "10.0.100.10"):
        # proceed with research
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)


class EngagementStatus(str, Enum):
    """Lifecycle status of an engagement."""
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class AuthorizationType(str, Enum):
    """Type of client authorization."""
    WRITTEN_CONTRACT = "written_contract"
    SIGNED_SOW = "signed_sow"
    EMAIL_AUTHORIZATION = "email_authorization"
    VERBAL_WITH_WRITTEN_FOLLOWUP = "verbal_with_written_followup"
    MUTUAL_NDA = "mutual_nda"


class TargetType(str, Enum):
    """Type of target in scope."""
    IP_ADDRESS = "ip_address"
    IP_RANGE = "ip_range"
    DOMAIN = "domain"
    URL = "url"
    BINARY = "binary"
    SOURCE_CODE = "source_code"
    API_ENDPOINT = "api_endpoint"
    NETWORK_SERVICE = "network_service"
    MOBILE_APP = "mobile_app"
    IOT_DEVICE = "iot_device"


class ResearchMethod(str, Enum):
    """Allowed research methods."""
    FUZZING = "fuzzing"
    STATIC_ANALYSIS = "static_analysis"
    BINARY_ANALYSIS = "binary_analysis"
    NETWORK_SCANNING = "network_scanning"
    WEB_TESTING = "web_testing"
    API_TESTING = "api_testing"
    EXPLOIT_DEVELOPMENT = "exploit_development"
    SOCIAL_ENGINEERING = "social_engineering"


@dataclass
class TargetEntry:
    """A single target within an engagement scope."""
    target_id: str = field(default_factory=lambda: str(uuid4())[:12])
    target_type: TargetType = TargetType.IP_ADDRESS
    value: str = ""                    # IP, domain, URL, file path, etc.
    description: str = ""
    ports: List[int] = field(default_factory=list)  # Empty = all ports
    excluded: bool = False             # Explicitly out of scope
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["target_type"] = self.target_type.value
        return d

    def matches(self, target_value: str) -> bool:
        """Check if a target value matches this entry."""
        if self.target_type == TargetType.IP_ADDRESS:
            return self.value == target_value
        elif self.target_type == TargetType.IP_RANGE:
            import ipaddress
            try:
                ip = ipaddress.ip_address(target_value)
                network = ipaddress.ip_network(self.value, strict=False)
                return ip in network
            except (ValueError, TypeError):
                return False
        elif self.target_type == TargetType.DOMAIN:
            return target_value == self.value or target_value.endswith(f".{self.value}")
        elif self.target_type == TargetType.URL:
            return target_value.startswith(self.value) or self.value in target_value
        else:
            return self.value == target_value


@dataclass
class RulesOfEngagement:
    """Rules governing what is and isn't allowed during an engagement."""
    # Allowed research methods
    allowed_methods: List[ResearchMethod] = field(default_factory=lambda: [
        ResearchMethod.FUZZING,
        ResearchMethod.STATIC_ANALYSIS,
        ResearchMethod.BINARY_ANALYSIS,
        ResearchMethod.NETWORK_SCANNING,
        ResearchMethod.WEB_TESTING,
        ResearchMethod.API_TESTING,
    ])

    # Prohibited methods
    prohibited_methods: List[ResearchMethod] = field(default_factory=lambda: [
        ResearchMethod.SOCIAL_ENGINEERING,
    ])

    # Time constraints
    business_hours_only: bool = False
    business_hours_start: str = "09:00"  # Local time
    business_hours_end: str = "17:00"
    timezone: str = "UTC"
    max_concurrent_tests: int = 5

    # Data handling
    can_store_crash_inputs: bool = True
    can_retain_pii: bool = False
    data_retention_days: int = 90
    must_purge_after_completion: bool = True

    # Notification requirements
    notify_before_testing: bool = False
    notify_on_critical_finding: bool = True
    notification_email: str = ""

    # Rate limiting
    max_requests_per_second: int = 100
    max_bandwidth_mbps: int = 50

    # Prohibited actions
    no_destructive_testing: bool = True
    no_data_exfiltration: bool = True
    no_persistence: bool = True
    no_lateral_movement: bool = True

    # Disclosure
    disclosure_embargo_days: int = 90
    requires_vendor_notification: bool = True
    requires_cve_assignment: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["allowed_methods"] = [m.value for m in self.allowed_methods]
        d["prohibited_methods"] = [m.value for m in self.prohibited_methods]
        return d

    def is_method_allowed(self, method: ResearchMethod) -> bool:
        """Check if a research method is allowed."""
        if method in self.prohibited_methods:
            return False
        return method in self.allowed_methods


@dataclass
class LegalFramework:
    """Legal and contractual framework for the engagement."""
    authorization_type: AuthorizationType = AuthorizationType.WRITTEN_CONTRACT
    contract_reference: str = ""       # Contract ID or reference number
    contract_date: Optional[str] = None
    nda_signed: bool = False
    nda_date: Optional[str] = None
    liability_limit: str = ""         # e.g., "$1,000,000"
    insurance_certificate: str = ""   # Reference to insurance cert
    jurisdiction: str = ""             # Legal jurisdiction
    authorized_representative: str = ""  # Client contact who authorized
    representative_email: str = ""
    representative_phone: str = ""
    additional_terms: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["authorization_type"] = self.authorization_type.value
        return d

    def is_valid(self) -> bool:
        """Check if legal framework is sufficient for engagement."""
        if self.authorization_type == AuthorizationType.WRITTEN_CONTRACT:
            return bool(self.contract_reference and self.authorized_representative)
        elif self.authorization_type == AuthorizationType.SIGNED_SOW:
            return bool(self.contract_reference)
        elif self.authorization_type == AuthorizationType.EMAIL_AUTHORIZATION:
            return bool(self.representative_email)
        return False


@dataclass
class Engagement:
    """A client engagement for zero-day research."""
    id: str = field(default_factory=lambda: str(uuid4())[:12])
    client: str = ""
    engagement_name: str = ""
    status: EngagementStatus = EngagementStatus.DRAFT
    targets: List[TargetEntry] = field(default_factory=list)
    rules: RulesOfEngagement = field(default_factory=RulesOfEngagement)
    legal: LegalFramework = field(default_factory=LegalFramework)

    # Time window
    start_date: Optional[str] = None
    end_date: Optional[str] = None

    # Metadata
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by: str = ""
    notes: str = ""

    # Findings count (updated as findings are discovered)
    findings_count: int = 0
    critical_findings: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "client": self.client,
            "engagement_name": self.engagement_name,
            "status": self.status.value,
            "targets": [t.to_dict() for t in self.targets],
            "rules": self.rules.to_dict(),
            "legal": self.legal.to_dict(),
            "start_date": self.start_date,
            "end_date": self.end_date,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "created_by": self.created_by,
            "notes": self.notes,
            "findings_count": self.findings_count,
            "critical_findings": self.critical_findings,
        }

    def is_active(self) -> bool:
        """Check if engagement is currently active and within time window."""
        if self.status != EngagementStatus.ACTIVE:
            return False

        now = datetime.utcnow()

        if self.start_date:
            try:
                start_str = self.start_date.replace("Z", "+00:00")
                start = datetime.fromisoformat(start_str)
                if start.tzinfo is not None:
                    start = start.replace(tzinfo=None)  # normalize to naive UTC
                if now < start:
                    return False
            except ValueError:
                logger.warning(f"Invalid start_date format: {self.start_date}")

        if self.end_date:
            try:
                end_str = self.end_date.replace("Z", "+00:00")
                end = datetime.fromisoformat(end_str)
                if end.tzinfo is not None:
                    end = end.replace(tzinfo=None)  # normalize to naive UTC
                if now > end:
                    return False
            except ValueError:
                logger.warning(f"Invalid end_date format: {self.end_date}")

        return True

    def is_target_in_scope(self, target_value: str) -> bool:
        """Check if a target value is within the engagement scope."""
        for target in self.targets:
            if target.excluded:
                if target.matches(target_value):
                    return False  # Explicitly excluded
                continue
            if target.matches(target_value):
                return True

        # If no targets match, not in scope
        return False

    def is_method_allowed(self, method: ResearchMethod) -> bool:
        """Check if a research method is allowed by the rules of engagement."""
        return self.rules.is_method_allowed(method)


class EngagementManager:
    """
    Manages client engagements for zero-day research.

    This is the authorization gatekeeper. All discovery and attack
    tools must check with the engagement manager before operating
    against any target.
    """

    def __init__(self, storage_dir: str = None):
        """
        Args:
            storage_dir: Directory to persist engagement data.
                         Defaults to ~/.ciicerone/engagements/
        """
        self.storage_dir = storage_dir or os.path.expanduser(
            "~/.ciicerone/engagements"
        )
        os.makedirs(self.storage_dir, exist_ok=True)
        self._engagements: Dict[str, Engagement] = {}
        self._load_all()

    def _load_all(self):
        """Load all engagements from storage."""
        if not os.path.isdir(self.storage_dir):
            return

        for filename in os.listdir(self.storage_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(self.storage_dir, filename)
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                    engagement = self._from_dict(data)
                    self._engagements[engagement.id] = engagement
                except Exception as e:
                    logger.error(f"Failed to load engagement {filename}: {e}")

    def _from_dict(self, data: dict) -> Engagement:
        """Reconstruct an Engagement from a dict."""
        targets = [
            TargetEntry(
                target_id=t.get("target_id", str(uuid4())[:12]),
                target_type=TargetType(t.get("target_type", "ip_address")),
                value=t.get("value", ""),
                description=t.get("description", ""),
                ports=t.get("ports", []),
                excluded=t.get("excluded", False),
                notes=t.get("notes", ""),
            )
            for t in data.get("targets", [])
        ]

        rules_data = data.get("rules", {})

        # Safely parse enum lists (skip invalid values)
        allowed_methods = []
        for m in rules_data.get("allowed_methods", []):
            try:
                allowed_methods.append(ResearchMethod(m))
            except ValueError:
                logger.warning(f"Invalid allowed_method in saved data: {m}")

        prohibited_methods = []
        for m in rules_data.get("prohibited_methods", []):
            try:
                prohibited_methods.append(ResearchMethod(m))
            except ValueError:
                logger.warning(f"Invalid prohibited_method in saved data: {m}")

        rules = RulesOfEngagement(
            allowed_methods=allowed_methods,
            prohibited_methods=prohibited_methods,
            business_hours_only=rules_data.get("business_hours_only", False),
            business_hours_start=rules_data.get("business_hours_start", "09:00"),
            business_hours_end=rules_data.get("business_hours_end", "17:00"),
            timezone=rules_data.get("timezone", "UTC"),
            max_concurrent_tests=rules_data.get("max_concurrent_tests", 5),
            can_store_crash_inputs=rules_data.get("can_store_crash_inputs", True),
            can_retain_pii=rules_data.get("can_retain_pii", False),
            data_retention_days=rules_data.get("data_retention_days", 90),
            must_purge_after_completion=rules_data.get("must_purge_after_completion", True),
            notify_before_testing=rules_data.get("notify_before_testing", False),
            notify_on_critical_finding=rules_data.get("notify_on_critical_finding", True),
            notification_email=rules_data.get("notification_email", ""),
            max_requests_per_second=rules_data.get("max_requests_per_second", 100),
            max_bandwidth_mbps=rules_data.get("max_bandwidth_mbps", 50),
            no_destructive_testing=rules_data.get("no_destructive_testing", True),
            no_data_exfiltration=rules_data.get("no_data_exfiltration", True),
            no_persistence=rules_data.get("no_persistence", True),
            no_lateral_movement=rules_data.get("no_lateral_movement", True),
            disclosure_embargo_days=rules_data.get("disclosure_embargo_days", 90),
            requires_vendor_notification=rules_data.get("requires_vendor_notification", True),
            requires_cve_assignment=rules_data.get("requires_cve_assignment", False),
        )

        legal_data = data.get("legal", {})
        legal = LegalFramework(
            authorization_type=AuthorizationType(legal_data.get("authorization_type", "written_contract")),
            contract_reference=legal_data.get("contract_reference", ""),
            contract_date=legal_data.get("contract_date"),
            nda_signed=legal_data.get("nda_signed", False),
            nda_date=legal_data.get("nda_date"),
            liability_limit=legal_data.get("liability_limit", ""),
            insurance_certificate=legal_data.get("insurance_certificate", ""),
            jurisdiction=legal_data.get("jurisdiction", ""),
            authorized_representative=legal_data.get("authorized_representative", ""),
            representative_email=legal_data.get("representative_email", ""),
            representative_phone=legal_data.get("representative_phone", ""),
            additional_terms=legal_data.get("additional_terms", ""),
        )

        return Engagement(
            id=data.get("id", str(uuid4())[:12]),
            client=data.get("client", ""),
            engagement_name=data.get("engagement_name", ""),
            status=EngagementStatus(data.get("status", "draft")),
            targets=targets,
            rules=rules,
            legal=legal,
            start_date=data.get("start_date"),
            end_date=data.get("end_date"),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            updated_at=data.get("updated_at", datetime.utcnow().isoformat()),
            created_by=data.get("created_by", ""),
            notes=data.get("notes", ""),
            findings_count=data.get("findings_count", 0),
            critical_findings=data.get("critical_findings", 0),
        )

    def _save(self, engagement: Engagement):
        """Persist an engagement to disk."""
        filepath = os.path.join(self.storage_dir, f"{engagement.id}.json")
        with open(filepath, "w") as f:
            json.dump(engagement.to_dict(), f, indent=2)
        logger.info(f"Engagement {engagement.id} saved to {filepath}")

    def create_engagement(
        self,
        client: str,
        engagement_name: str,
        targets: List[TargetEntry] = None,
        rules: RulesOfEngagement = None,
        legal: LegalFramework = None,
        start_date: str = None,
        end_date: str = None,
        created_by: str = "",
    ) -> Engagement:
        """Create a new engagement.

        Args:
            client: Client organization name
            engagement_name: Name/title for this engagement
            targets: List of targets in scope
            rules: Rules of engagement
            legal: Legal framework
            start_date: ISO date string for engagement start
            end_date: ISO date string for engagement end
            created_by: User creating the engagement

        Returns:
            The created Engagement
        """
        engagement = Engagement(
            client=client,
            engagement_name=engagement_name,
            targets=targets or [],
            rules=rules or RulesOfEngagement(),
            legal=legal or LegalFramework(),
            start_date=start_date,
            end_date=end_date,
            created_by=created_by,
        )

        # Check if legal framework is valid
        if engagement.legal.is_valid():
            engagement.status = EngagementStatus.PENDING_APPROVAL
        else:
            engagement.status = EngagementStatus.DRAFT

        self._engagements[engagement.id] = engagement
        self._save(engagement)

        logger.info(
            f"Created engagement {engagement.id} for {client}: "
            f"{engagement_name} ({engagement.status.value})"
        )
        return engagement

    def approve_engagement(self, engagement_id: str) -> Engagement:
        """Approve an engagement, moving it from pending to active."""
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")

        if engagement.status != EngagementStatus.PENDING_APPROVAL:
            raise ValueError(
                f"Engagement is {engagement.status.value}, must be pending_approval"
            )

        if not engagement.legal.is_valid():
            raise ValueError("Legal framework is not valid — cannot approve")

        engagement.status = EngagementStatus.ACTIVE
        engagement.updated_at = datetime.utcnow().isoformat()
        self._save(engagement)

        logger.info(f"Engagement {engagement_id} approved and active")
        return engagement

    def pause_engagement(self, engagement_id: str) -> Engagement:
        """Pause an active engagement."""
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")

        engagement.status = EngagementStatus.PAUSED
        engagement.updated_at = datetime.utcnow().isoformat()
        self._save(engagement)
        return engagement

    def complete_engagement(self, engagement_id: str) -> Engagement:
        """Mark an engagement as completed."""
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")

        engagement.status = EngagementStatus.COMPLETED
        engagement.updated_at = datetime.utcnow().isoformat()
        self._save(engagement)

        # Check if data purge is required
        if engagement.rules.must_purge_after_completion:
            logger.info(
                f"Engagement {engagement_id} completed — "
                f"data purge required per rules of engagement"
            )

        return engagement

    def cancel_engagement(self, engagement_id: str) -> Engagement:
        """Cancel an engagement."""
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")

        engagement.status = EngagementStatus.CANCELLED
        engagement.updated_at = datetime.utcnow().isoformat()
        self._save(engagement)
        return engagement

    def add_target(self, engagement_id: str, target: TargetEntry) -> Engagement:
        """Add a target to an engagement's scope."""
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")

        engagement.targets.append(target)
        engagement.updated_at = datetime.utcnow().isoformat()
        self._save(engagement)
        return engagement

    def remove_target(self, engagement_id: str, target_id: str) -> Engagement:
        """Remove a target from an engagement's scope."""
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")

        engagement.targets = [t for t in engagement.targets if t.target_id != target_id]
        engagement.updated_at = datetime.utcnow().isoformat()
        self._save(engagement)
        return engagement

    def is_authorized(
        self,
        engagement_id: str,
        target_value: str,
        method: ResearchMethod = None,
    ) -> Tuple[bool, str]:
        """Check if a target is authorized for testing under an engagement.

        This is the primary gatekeeper method. All discovery and attack
        tools should call this before operating against any target.

        Args:
            engagement_id: ID of the engagement
            target_value: Target IP, domain, URL, etc.
            method: Research method to be used (optional)

        Returns:
            Tuple of (is_authorized: bool, reason: str)
        """
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            return False, f"Engagement {engagement_id} not found"

        if not engagement.is_active():
            return False, f"Engagement is {engagement.status.value}, not active"

        if not engagement.is_target_in_scope(target_value):
            return False, f"Target {target_value} is not in scope for engagement {engagement_id}"

        if method and not engagement.is_method_allowed(method):
            return False, f"Method {method.value} is not allowed by rules of engagement"

        # Check business hours if required
        if engagement.rules.business_hours_only:
            now = datetime.utcnow()
            hour = now.hour
            try:
                start_hour = int(engagement.rules.business_hours_start.split(":")[0])
                end_hour = int(engagement.rules.business_hours_end.split(":")[0])
            except (ValueError, AttributeError):
                start_hour, end_hour = 9, 17
            # Note: This uses UTC. For proper timezone support, install pytz
            # and convert to the engagement's local timezone before checking.
            if hour < start_hour or hour >= end_hour:
                return False, (
                    f"Outside business hours per rules of engagement "
                    f"({start_hour}:00-{end_hour}:00 {engagement.rules.timezone})"
                )

        return True, "Authorized"

    def get_engagement(self, engagement_id: str) -> Optional[Engagement]:
        """Get an engagement by ID."""
        return self._engagements.get(engagement_id)

    def list_engagements(
        self,
        status: EngagementStatus = None,
        client: str = None,
    ) -> List[Engagement]:
        """List engagements, optionally filtered."""
        results = list(self._engagements.values())

        if status:
            results = [e for e in results if e.status == status]

        if client:
            results = [e for e in results if e.client.lower() == client.lower()]

        return sorted(results, key=lambda e: e.created_at, reverse=True)

    def update_findings_count(
        self,
        engagement_id: str,
        total: int,
        critical: int,
    ) -> Engagement:
        """Update the findings count for an engagement."""
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")

        engagement.findings_count = total
        engagement.critical_findings = critical
        engagement.updated_at = datetime.utcnow().isoformat()
        self._save(engagement)
        return engagement

    def check_expiry(self) -> List[Engagement]:
        """Check all active engagements for expiry and update status."""
        expired = []
        now = datetime.utcnow()

        for engagement in self._engagements.values():
            if engagement.status != EngagementStatus.ACTIVE:
                continue

            if engagement.end_date:
                try:
                    end = datetime.fromisoformat(engagement.end_date.replace("Z", ""))
                    if now > end:
                        engagement.status = EngagementStatus.EXPIRED
                        engagement.updated_at = now.isoformat()
                        self._save(engagement)
                        expired.append(engagement)
                        logger.info(f"Engagement {engagement.id} expired")
                except ValueError:
                    continue

        return expired

    def export_engagement(self, engagement_id: str, format: str = "json") -> str:
        """Export an engagement as JSON or markdown."""
        engagement = self._engagements.get(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")

        if format == "json":
            return json.dumps(engagement.to_dict(), indent=2)
        else:
            return self._to_markdown(engagement)

    def _to_markdown(self, engagement: Engagement) -> str:
        """Render engagement as markdown."""
        md = f"""# Engagement: {engagement.engagement_name}

| Field | Value |
|-------|-------|
| ID | {engagement.id} |
| Client | {engagement.client} |
| Status | {engagement.status.value} |
| Start Date | {engagement.start_date or 'N/A'} |
| End Date | {engagement.end_date or 'N/A'} |
| Created | {engagement.created_at} |
| Created By | {engagement.created_by} |
| Findings | {engagement.findings_count} ({engagement.critical_findings} critical) |

## Targets in Scope

| ID | Type | Value | Description | Excluded |
|----|------|-------|-------------|----------|
"""
        for t in engagement.targets:
            md += f"| {t.target_id} | {t.target_type.value} | {t.value} | {t.description} | {'Yes' if t.excluded else 'No'} |\n"

        md += f"""
## Rules of Engagement

**Allowed Methods:** {', '.join(m.value for m in engagement.rules.allowed_methods)}

**Prohibited Methods:** {', '.join(m.value for m in engagement.rules.prohibited_methods)}

**Constraints:**
- Business hours only: {engagement.rules.business_hours_only}
- Max concurrent tests: {engagement.rules.max_concurrent_tests}
- Max requests/sec: {engagement.rules.max_requests_per_second}
- No destructive testing: {engagement.rules.no_destructive_testing}
- No data exfiltration: {engagement.rules.no_data_exfiltration}
- No persistence: {engagement.rules.no_persistence}
- No lateral movement: {engagement.rules.no_lateral_movement}
- Data retention: {engagement.rules.data_retention_days} days
- Disclosure embargo: {engagement.rules.disclosure_embargo_days} days
- Requires vendor notification: {engagement.rules.requires_vendor_notification}

## Legal Framework

| Field | Value |
|-------|-------|
| Authorization Type | {engagement.legal.authorization_type.value} |
| Contract Reference | {engagement.legal.contract_reference or 'N/A'} |
| NDA Signed | {'Yes' if engagement.legal.nda_signed else 'No'} |
| Authorized Representative | {engagement.legal.authorized_representative or 'N/A'} |
| Jurisdiction | {engagement.legal.jurisdiction or 'N/A'} |
| Liability Limit | {engagement.legal.liability_limit or 'N/A'} |

## Notes

{engagement.notes or 'None'}
"""
        return md
