"""Threat Hunting Frameworks for Vorsyghta.

Implements structured threat hunting methodologies:
- PEAK (Prepare, Execute, Act with Knowledge)
- TaHiTI (Targeted Hunting integrating Threat Intelligence)
- OTHF (Open Threat Hunting Framework)
- HMM (Hunting Maturity Model)
- Compliance-aligned hunting profiles (PCI-DSS, HIPAA, SOC 2, etc.)
- IOC-based hunting profiles
- TTP-based hunting profiles
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class HuntingFramework(str, Enum):
    PEAK = "PEAK"
    TAHITI = "TaHiTI"
    OTHF = "OTHF"
    HMM = "HMM"
    MITRE_ATTACK = "MITRE_ATT&CK"


class PEAKPhase(str, Enum):
    PREPARE = "prepare"
    EXECUTE = "execute"
    ACT = "act"


class TaHiTIStage(str, Enum):
    TRIGGER = "trigger"
    HUNT = "hunt"
    INVESTIGATE = "investigate"
    ACT = "act"


class HMMLevel(str, Enum):
    LEVEL_0 = "HMM-0"  # Initial — no repeatable process
    LEVEL_1 = "HMM-1"  # Minimal — ad-hoc hunting
    LEVEL_2 = "HMM-2"  # Procedural — follows defined procedures
    LEVEL_3 = "HMM-3"  # Innovative — creates novel procedures
    LEVEL_4 = "HMM-4"  # Leading — automates hunting at scale


class TTPCategory(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ComplianceFramework(str, Enum):
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    SOC2 = "SOC 2"
    ISO27001 = "ISO 27001"
    NIST_CSF = "NIST CSF"
    GDPR = "GDPR"
    CMMC = "CMMC"
    CIS = "CIS Controls"


class ComplianceViolationType(str, Enum):
    UNAUTHORISED_ACCESS = "unauthorised_access"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ABUSE = "privilege_abuse"
    POLICY_VIOLATION = "policy_violation"
    AUDIT_TAMPERING = "audit_tampering"
    INSECURE_TRANSMISSION = "insecure_transmission"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    FILENAME = "filename"


# =============================================================================
# PEAK Framework
# =============================================================================

class PEAKPhaseData(BaseModel):
    """Data for a single phase in a PEAK hunt cycle."""

    phase: PEAKPhase
    objectives: List[str] = Field(default_factory=list)
    activities: List[str] = Field(default_factory=list)
    outputs: List[str] = Field(default_factory=list)
    success_criteria: List[str] = Field(default_factory=list)
    tools: List[str] = Field(default_factory=list)
    duration_estimate_hours: Optional[float] = None


class PEAKHuntCycle(BaseModel):
    """A complete PEAK hunt cycle with Prepare → Execute → Act phases."""

    cycle_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    target_environment: str
    hunt_rationale: str
    threat_context: str = ""
    phases: Dict[str, PEAKPhaseData] = Field(default_factory=dict)
    mitre_techniques: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def create(
        cls,
        name: str,
        target_environment: str,
        hunt_rationale: str,
        threat_context: str = "",
        mitre_techniques: Optional[List[str]] = None,
    ) -> "PEAKHuntCycle":
        """Create a PEAK cycle with default phase structure."""
        phases = {
            PEAKPhase.PREPARE.value: PEAKPhaseData(
                phase=PEAKPhase.PREPARE,
                objectives=[
                    "Define hunt scope and threat model",
                    "Identify relevant data sources",
                    "Prepare hunting hypothesis",
                    "Ensure tooling and data access is ready",
                ],
                activities=[
                    "Review threat intelligence for target",
                    "Map MITRE ATT&CK techniques to environment",
                    "Validate log source coverage",
                    "Define success and failure criteria",
                ],
                outputs=["Hunting hypothesis", "Data source inventory", "Query templates"],
            ),
            PEAKPhase.EXECUTE.value: PEAKPhaseData(
                phase=PEAKPhase.EXECUTE,
                objectives=[
                    "Run queries across identified data sources",
                    "Identify anomalies and suspicious patterns",
                    "Triage and enrich findings",
                ],
                activities=[
                    "Execute baseline and anomaly queries",
                    "Correlate events across data sources",
                    "Document findings and artefacts",
                    "Escalate confirmed threats",
                ],
                outputs=["Finding report", "Artefact list", "Timeline of activity"],
            ),
            PEAKPhase.ACT.value: PEAKPhaseData(
                phase=PEAKPhase.ACT,
                objectives=[
                    "Respond to confirmed findings",
                    "Improve detection coverage",
                    "Document lessons learned",
                ],
                activities=[
                    "Create or tune detection rules",
                    "File incident tickets for confirmed threats",
                    "Update threat model with new intelligence",
                    "Share findings with team",
                ],
                outputs=["Detection rules", "Lessons learned", "Updated threat model"],
            ),
        }
        return cls(
            name=name,
            target_environment=target_environment,
            hunt_rationale=hunt_rationale,
            threat_context=threat_context,
            phases=phases,
            mitre_techniques=mitre_techniques or [],
        )


# =============================================================================
# TaHiTI Framework
# =============================================================================

class TaHiTIHuntProcess(BaseModel):
    """A TaHiTI-structured hunting process."""

    process_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    trigger: str = Field(..., description="What initiated this hunt (intel, alert, scheduled)")
    trigger_source: str = ""
    hunt_hypothesis: str = ""
    hunt_queries: List[str] = Field(default_factory=list)
    investigation_notes: str = ""
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    actions_taken: List[str] = Field(default_factory=list)
    current_stage: TaHiTIStage = TaHiTIStage.TRIGGER
    mitre_techniques: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def advance_stage(self) -> None:
        """Move to the next TaHiTI stage in sequence."""
        order = [
            TaHiTIStage.TRIGGER,
            TaHiTIStage.HUNT,
            TaHiTIStage.INVESTIGATE,
            TaHiTIStage.ACT,
        ]
        idx = order.index(self.current_stage)
        if idx < len(order) - 1:
            self.current_stage = order[idx + 1]
            self.updated_at = datetime.now(timezone.utc)


# =============================================================================
# OTHF (Open Threat Hunting Framework)
# =============================================================================

class OTHFPlaybookStatus(str, Enum):
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    ACTIVE = "active"
    DEPRECATED = "deprecated"


class OTHFPlaybook(BaseModel):
    """An OTHF-structured hunt playbook."""

    playbook_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: str
    version: str = "1.0"
    status: OTHFPlaybookStatus = OTHFPlaybookStatus.DRAFT

    # Threat context
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    affected_platforms: List[str] = Field(default_factory=list)

    # Hunt data
    data_requirements: List[str] = Field(default_factory=list)
    hunt_queries: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)

    # Response
    false_positive_guidance: str = ""
    escalation_criteria: str = ""
    response_actions: List[str] = Field(default_factory=list)

    # Detection outputs
    detection_rules: List[str] = Field(default_factory=list)
    sigma_rules: List[str] = Field(default_factory=list)

    author: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# HMM (Hunting Maturity Model)
# =============================================================================

class HMMAssessment(BaseModel):
    """Maturity assessment against the Hunting Maturity Model."""

    assessment_id: str = Field(default_factory=lambda: str(uuid4()))
    organisation: str
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    current_level: HMMLevel = HMMLevel.LEVEL_0

    # Dimension scores (0–4)
    data_collection_score: int = Field(0, ge=0, le=4)
    tooling_score: int = Field(0, ge=0, le=4)
    process_score: int = Field(0, ge=0, le=4)
    automation_score: int = Field(0, ge=0, le=4)
    knowledge_score: int = Field(0, ge=0, le=4)

    strengths: List[str] = Field(default_factory=list)
    gaps: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    next_level_requirements: List[str] = Field(default_factory=list)

    @property
    def average_score(self) -> float:
        scores = [
            self.data_collection_score,
            self.tooling_score,
            self.process_score,
            self.automation_score,
            self.knowledge_score,
        ]
        return sum(scores) / len(scores)

    def determine_level(self) -> HMMLevel:
        """Derive the HMM level from dimension scores."""
        avg = self.average_score
        if avg < 1:
            return HMMLevel.LEVEL_0
        if avg < 2:
            return HMMLevel.LEVEL_1
        if avg < 3:
            return HMMLevel.LEVEL_2
        if avg < 3.5:
            return HMMLevel.LEVEL_3
        return HMMLevel.LEVEL_4


# =============================================================================
# Lifecycle / generic wrapper
# =============================================================================

class HuntingLifecyclePhase(str, Enum):
    PLANNING = "planning"
    DATA_COLLECTION = "data_collection"
    HYPOTHESIS_GENERATION = "hypothesis_generation"
    INVESTIGATION = "investigation"
    RESPONSE = "response"
    DOCUMENTATION = "documentation"


class HuntingLifecycle(BaseModel):
    """Generic hunt lifecycle that can wrap any framework."""

    lifecycle_id: str = Field(default_factory=lambda: str(uuid4()))
    framework: HuntingFramework
    name: str
    current_phase: HuntingLifecyclePhase = HuntingLifecyclePhase.PLANNING
    phase_history: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def transition(self, new_phase: HuntingLifecyclePhase, notes: str = "") -> None:
        """Transition to a new lifecycle phase, recording the change."""
        self.phase_history.append({
            "from": self.current_phase.value,
            "to": new_phase.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "notes": notes,
        })
        self.current_phase = new_phase
        self.updated_at = datetime.now(timezone.utc)


# =============================================================================
# TTP hunt profiles
# =============================================================================

class TTPHuntProfile(BaseModel):
    """A hunt profile focused on a specific TTP category."""

    profile_id: str = Field(default_factory=lambda: str(uuid4()))
    category: TTPCategory
    mitre_technique_ids: List[str] = Field(default_factory=list)
    description: str
    data_sources: List[str] = Field(default_factory=list)
    hunt_queries: List[str] = Field(default_factory=list)
    behavioural_indicators: List[str] = Field(default_factory=list)
    false_positive_notes: str = ""
    priority: str = "medium"

    @classmethod
    def for_lateral_movement(cls) -> "TTPHuntProfile":
        """Create a pre-built lateral movement hunt profile."""
        return cls(
            category=TTPCategory.LATERAL_MOVEMENT,
            mitre_technique_ids=["T1021", "T1021.001", "T1021.002", "T1550", "T1534"],
            description="Hunt for lateral movement using SMB, RDP, WMI, Pass-the-Hash/Ticket.",
            data_sources=["Windows Event Logs", "Network Flow", "EDR Process Events", "DNS"],
            hunt_queries=[
                "event_id:4624 AND logon_type:3 | stats count by src_ip, dest_host",
                "event_id:4648 AND target_user_name:* | rare target_user_name",
                "process_name:wmic.exe AND parent_process_name:* | where parent_process_name!='explorer.exe'",
                "dest_port:(445 OR 3389) | stats dc(src_ip) as unique_sources by dest_ip | where unique_sources > 10",
            ],
            behavioural_indicators=[
                "Unusual SMB connections from workstation-to-workstation",
                "Admin shares accessed outside business hours",
                "Multiple failed then successful authentications",
                "WMI process spawning on remote hosts",
            ],
            priority="high",
        )

    @classmethod
    def for_credential_access(cls) -> "TTPHuntProfile":
        """Create a pre-built credential access hunt profile."""
        return cls(
            category=TTPCategory.CREDENTIAL_ACCESS,
            mitre_technique_ids=["T1003", "T1110", "T1555", "T1212", "T1606"],
            description="Hunt for credential dumping, brute force, and password store access.",
            data_sources=["Windows Event Logs", "LSASS Memory", "EDR", "Auth Logs"],
            hunt_queries=[
                "event_id:4625 | stats count by src_ip | where count > 50",
                "process_name:lsass.exe AND event:memory_access | rare accessing_process",
                "event_id:4688 AND command_line:(*sekurlsa* OR *mimikatz* OR *procdump*)",
                "vault_access:* AND user:* | rare user",
            ],
            behavioural_indicators=[
                "LSASS memory access from non-system processes",
                "High volume of authentication failures",
                "Credential dumping tool signatures",
                "Access to SAM/NTDS.dit files",
            ],
            priority="critical",
        )


# =============================================================================
# Compliance hunt profiles
# =============================================================================

class ComplianceFinding(BaseModel):
    """A finding identified during a compliance-focused hunt."""

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    violation_type: ComplianceViolationType
    description: str
    severity: str = "medium"
    affected_assets: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    remediation: str = ""
    compliance_controls: List[str] = Field(default_factory=list)
    identified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ComplianceHuntProfile(BaseModel):
    """Hunt profile aligned to a compliance framework."""

    profile_id: str = Field(default_factory=lambda: str(uuid4()))
    framework: ComplianceFramework
    controls: List[str] = Field(default_factory=list)
    description: str
    data_sources: List[str] = Field(default_factory=list)
    hunt_queries: List[str] = Field(default_factory=list)
    violation_indicators: List[str] = Field(default_factory=list)
    findings: List[ComplianceFinding] = Field(default_factory=list)

    @classmethod
    def for_pci_dss(cls) -> "ComplianceHuntProfile":
        """Pre-built PCI-DSS compliance hunt profile."""
        return cls(
            framework=ComplianceFramework.PCI_DSS,
            controls=["PCI-DSS 10.2", "PCI-DSS 10.3", "PCI-DSS 8.3", "PCI-DSS 7.1"],
            description=(
                "Hunt for PCI-DSS violations: unauthorised cardholder data access, "
                "unencrypted transmissions, and privilege abuse."
            ),
            data_sources=["Network Flow", "DLP Logs", "Auth Logs", "Database Audit"],
            hunt_queries=[
                "dest_port:443 AND unencrypted_cardholder_data:* | alert",
                "event:database_access AND user:* AND table:*card* | rare user",
                "src_ip:outside_CDE AND dest_ip:CDE | stats count by src_ip",
                "admin_access:* AND outside_hours:true AND user:*",
            ],
            violation_indicators=[
                "Clear-text PAN data in logs",
                "Database access from non-production IPs",
                "Admin privileges used outside change window",
                "Missing audit logs for cardholder data access",
            ],
        )

    @classmethod
    def for_hipaa(cls) -> "ComplianceHuntProfile":
        """Pre-built HIPAA compliance hunt profile."""
        return cls(
            framework=ComplianceFramework.HIPAA,
            controls=["HIPAA §164.312(b)", "HIPAA §164.308(a)(1)", "HIPAA §164.312(e)(1)"],
            description=(
                "Hunt for HIPAA violations: unauthorised PHI access, "
                "audit log gaps, and insecure PHI transmission."
            ),
            data_sources=["EMR Access Logs", "Network Flow", "Auth Logs", "Email DLP"],
            hunt_queries=[
                "resource:PHI AND access:* | stats dc(user) as users_accessing by resource | where users_accessing > 5",
                "email_content:*ssn* OR *dob* OR *patient_id* AND encryption:false",
                "audit_log_gap:* | stats gap_minutes by system | where gap_minutes > 5",
            ],
            violation_indicators=[
                "Bulk PHI export outside normal business hours",
                "Unencrypted PHI in email or file share",
                "Access by terminated employee accounts",
                "Gaps in EMR audit trail",
            ],
        )


# =============================================================================
# IOC hunt profiles
# =============================================================================

class IOCEntry(BaseModel):
    """A single indicator of compromise."""

    ioc_id: str = Field(default_factory=lambda: str(uuid4()))
    ioc_type: IOCType
    value: str
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source: str = ""
    description: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class IOCFinding(BaseModel):
    """Match of an IOC in environment data."""

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    ioc: IOCEntry
    matched_in: str
    matched_value: str
    context: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "medium"
    identified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IOCHuntProfile(BaseModel):
    """Profile for IOC-based hunting."""

    profile_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: str
    iocs: List[IOCEntry] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    findings: List[IOCFinding] = Field(default_factory=list)
    hunt_queries: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def add_ioc(self, ioc: IOCEntry) -> None:
        """Add an IOC and generate a corresponding hunt query."""
        self.iocs.append(ioc)
        if ioc.ioc_type == IOCType.IP:
            self.hunt_queries.append(f"src_ip:{ioc.value} OR dest_ip:{ioc.value}")
        elif ioc.ioc_type == IOCType.DOMAIN:
            self.hunt_queries.append(f"dns_query:{ioc.value} OR http_host:{ioc.value}")
        elif ioc.ioc_type in (IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256):
            self.hunt_queries.append(f"file_hash:{ioc.value}")
        elif ioc.ioc_type == IOCType.URL:
            self.hunt_queries.append(f"http_url:{ioc.value}")
        elif ioc.ioc_type == IOCType.EMAIL:
            self.hunt_queries.append(f"sender:{ioc.value} OR recipient:{ioc.value}")
