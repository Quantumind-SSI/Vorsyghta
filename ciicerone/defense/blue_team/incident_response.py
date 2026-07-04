"""Incident Response Playbooks.

NIST 800-61 based incident response with automated playbook execution,
containment, eradication, and recovery procedures.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable

from ciicerone.core.event_types import BlueTeamIncidentCreatedEvent, BusEvent, EventType

logger = logging.getLogger(__name__)


@dataclass
class IRStep:
    """A single step in an incident response playbook."""
    step_id: str
    phase: str  # preparation, detection, containment, eradication, recovery, post_incident
    action: str
    description: str
    automated: bool = False
    completed: bool = False
    completed_at: Optional[str] = None
    result: Optional[str] = None
    artifacts: List[str] = field(default_factory=list)


@dataclass
class Incident:
    """Represents a security incident."""
    incident_id: str
    title: str
    severity: str  # critical, high, medium, low
    status: str  # open, investigating, contained, eradicated, resolved, closed
    category: str  # malware, intrusion, phishing, data_breach, insider, ddos
    created_at: str
    updated_at: Optional[str] = None
    description: str = ""
    affected_systems: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    steps: List[IRStep] = field(default_factory=list)
    assigned_to: Optional[str] = None
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)


class IncidentResponse:
    """Incident Response engine with NIST 800-61 playbooks.

    Provides:
        - Pre-built IR playbooks for common incident types
        - Automated containment actions
        - Step-by-step response tracking
        - Post-incident review generation

    Example:
        ir = IncidentResponse()
        incident = ir.create_incident(
            title="SQL Injection Attack",
            severity="critical",
            category="intrusion",
            affected_systems=["web-server-01"],
            mitre_techniques=["T1190"],
        )
        ir.execute_playbook(incident)
    """

    PLAYBOOKS: Dict[str, List[Dict[str, Any]]] = {
        "intrusion": [
            {"step_id": "IR-001", "phase": "detection", "action": "Identify entry point", "description": "Determine how the attacker gained access", "automated": False},
            {"step_id": "IR-002", "phase": "detection", "action": "Assess scope", "description": "Identify all affected systems and data", "automated": False},
            {"step_id": "IR-003", "phase": "containment", "action": "Isolate affected systems", "description": "Network isolate compromised hosts", "automated": True},
            {"step_id": "IR-004", "phase": "containment", "action": "Block attacker IPs", "description": "Add attacker IPs to firewall blocklist", "automated": True},
            {"step_id": "IR-005", "phase": "containment", "action": "Disable compromised accounts", "description": "Disable accounts used by attacker", "automated": True},
            {"step_id": "IR-006", "phase": "eradication", "action": "Remove malware/backdoors", "description": "Scan for and remove malicious software", "automated": False},
            {"step_id": "IR-007", "phase": "eradication", "action": "Patch vulnerabilities", "description": "Apply patches for exploited vulnerabilities", "automated": False},
            {"step_id": "IR-008", "phase": "eradication", "action": "Reset credentials", "description": "Force password reset for all affected accounts", "automated": True},
            {"step_id": "IR-009", "phase": "recovery", "action": "Restore from backup", "description": "Restore affected systems from known-good backups", "automated": False},
            {"step_id": "IR-010", "phase": "recovery", "action": "Verify system integrity", "description": "Run integrity checks on restored systems", "automated": False},
            {"step_id": "IR-011", "phase": "recovery", "action": "Monitor for re-infection", "description": "Enhanced monitoring for 72 hours post-recovery", "automated": True},
            {"step_id": "IR-012", "phase": "post_incident", "action": "Conduct post-incident review", "description": "Document timeline, root cause, and lessons learned", "automated": False},
            {"step_id": "IR-013", "phase": "post_incident", "action": "Update detection rules", "description": "Create new SIEM/IDS rules based on this incident", "automated": False},
        ],
        "malware": [
            {"step_id": "MAL-001", "phase": "detection", "action": "Identify malware type", "description": "Classify malware and determine capabilities", "automated": False},
            {"step_id": "MAL-002", "phase": "detection", "action": "Identify patient zero", "description": "Find initial infection vector", "automated": False},
            {"step_id": "MAL-003", "phase": "containment", "action": "Isolate infected hosts", "description": "Network quarantine all infected endpoints", "automated": True},
            {"step_id": "MAL-004", "phase": "containment", "action": "Block C2 domains", "description": "Add C2 domains to DNS blocklist", "automated": True},
            {"step_id": "MAL-005", "phase": "eradication", "action": "Run anti-malware scan", "description": "Full system scan with updated signatures", "automated": True},
            {"step_id": "MAL-006", "phase": "eradication", "action": "Remove persistence mechanisms", "description": "Remove scheduled tasks, services, registry entries", "automated": False},
            {"step_id": "MAL-007", "phase": "recovery", "action": "Rebuild critical systems", "description": "Rebuild from gold image if cleaning fails", "automated": False},
            {"step_id": "MAL-008", "phase": "recovery", "action": "Verify cleanup", "description": "Confirm no traces of malware remain", "automated": False},
            {"step_id": "MAL-009", "phase": "post_incident", "action": "Update AV signatures", "description": "Submit samples to AV vendor", "automated": False},
            {"step_id": "MAL-010", "phase": "post_incident", "action": "User awareness", "description": "Notify users about infection vector", "automated": False},
        ],
        "phishing": [
            {"step_id": "PHISH-001", "phase": "detection", "action": "Identify phishing scope", "description": "Determine how many users received/clicked", "automated": False},
            {"step_id": "PHISH-002", "phase": "containment", "action": "Block phishing URL", "description": "Add URL to web filter blocklist", "automated": True},
            {"step_id": "PHISH-003", "phase": "containment", "action": "Quarantine emails", "description": "Remove phishing emails from all mailboxes", "automated": True},
            {"step_id": "PHISH-004", "phase": "containment", "action": "Reset compromised credentials", "description": "Force password reset for users who clicked", "automated": True},
            {"step_id": "PHISH-005", "phase": "eradication", "action": "Block sender domain", "description": "Add sender domain to email blocklist", "automated": True},
            {"step_id": "PHISH-006", "phase": "eradication", "action": "Revoke active sessions", "description": "Revoke OAuth tokens and active sessions", "automated": True},
            {"step_id": "PHISH-007", "phase": "recovery", "action": "Monitor for account compromise", "description": "Enhanced monitoring on affected accounts for 7 days", "automated": True},
            {"step_id": "PHISH-008", "phase": "post_incident", "action": "Phishing awareness training", "description": "Targeted training for users who clicked", "automated": False},
        ],
        "data_breach": [
            {"step_id": "DB-001", "phase": "detection", "action": "Identify breached data", "description": "Determine what data was accessed/exfiltrated", "automated": False},
            {"step_id": "DB-002", "phase": "detection", "action": "Assess regulatory impact", "description": "Determine notification requirements (GDPR, HIPAA, etc.)", "automated": False},
            {"step_id": "DB-003", "phase": "containment", "action": "Seal data exfiltration path", "description": "Block the channel used for data theft", "automated": True},
            {"step_id": "DB-004", "phase": "containment", "action": "Revoke all access tokens", "description": "Revoke API keys, OAuth tokens, session tokens", "automated": True},
            {"step_id": "DB-005", "phase": "eradication", "action": "Remove attacker access", "description": "Close all backdoors and attacker-created accounts", "automated": False},
            {"step_id": "DB-006", "phase": "eradication", "action": "Audit access controls", "description": "Review and tighten all access permissions", "automated": False},
            {"step_id": "DB-007", "phase": "recovery", "action": "Restore data integrity", "description": "Verify data hasn't been tampered with", "automated": False},
            {"step_id": "DB-008", "phase": "post_incident", "action": "Notify stakeholders", "description": "Notify affected individuals and regulators", "automated": False},
            {"step_id": "DB-009", "phase": "post_incident", "action": "Implement data loss prevention", "description": "Deploy DLP rules to prevent recurrence", "automated": False},
        ],
        "ddos": [
            {"step_id": "DDOS-001", "phase": "detection", "action": "Classify attack type", "description": "Determine if volumetric, protocol, or application layer", "automated": False},
            {"step_id": "DDOS-002", "phase": "containment", "action": "Activate DDoS protection", "description": "Enable traffic scrubbing/CDN absorption", "automated": True},
            {"step_id": "DDOS-003", "phase": "containment", "action": "Rate limit sources", "description": "Apply rate limiting to attacking IPs", "automated": True},
            {"step_id": "DDOS-004", "phase": "containment", "action": "Block attack traffic", "description": "Add attacking IP ranges to blocklist", "automated": True},
            {"step_id": "DDOS-005", "phase": "eradication", "action": "Identify botnet C2", "description": "Trace attack traffic to C2 infrastructure", "automated": False},
            {"step_id": "DDOS-006", "phase": "recovery", "action": "Gradually remove blocks", "description": "Lift rate limits as attack subsides", "automated": False},
            {"step_id": "DDOS-007", "phase": "post_incident", "action": "Tune DDoS protections", "description": "Update thresholds based on attack patterns", "automated": False},
        ],
    }

    def __init__(self):
        self._incidents: Dict[str, Incident] = {}
        self._incident_counter = 0

    def create_incident(
        self,
        title: str,
        severity: str,
        category: str,
        affected_systems: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        description: str = "",
    ) -> Incident:
        """Create a new security incident and attach the appropriate playbook."""
        self._incident_counter += 1
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{self._incident_counter:04d}"

        incident = Incident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            status="open",
            category=category,
            created_at=datetime.utcnow().isoformat(),
            description=description,
            affected_systems=affected_systems or [],
            mitre_techniques=mitre_techniques or [],
        )

        playbook = self.PLAYBOOKS.get(category, self.PLAYBOOKS["intrusion"])
        for step_def in playbook:
            incident.steps.append(IRStep(**step_def))

        incident.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": "Incident created",
            "detail": f"Category: {category}, Severity: {severity}",
        })

        self._incidents[incident_id] = incident
        return incident

    def execute_playbook(
        self,
        incident: Incident,
        auto_execute: bool = False,
    ) -> Incident:
        """Execute the incident response playbook.

        Args:
            incident: The incident to execute the playbook for
            auto_execute: If True, automatically complete automated steps

        Returns:
            Updated incident
        """
        incident.status = "investigating"
        incident.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": "Playbook execution started",
            "detail": f"Category: {incident.category}",
        })

        for step in incident.steps:
            if auto_execute and step.automated:
                self._execute_step(incident, step)
            elif not step.completed:
                incident.timeline.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "event": f"Step pending: {step.action}",
                    "detail": step.description,
                })

        if all(s.completed for s in incident.steps):
            incident.status = "resolved"
            incident.timeline.append({
                "timestamp": datetime.utcnow().isoformat(),
                "event": "All steps completed",
                "detail": "Incident resolved",
            })

        incident.updated_at = datetime.utcnow().isoformat()
        return incident

    def execute_step(self, incident_id: str, step_id: str, result: str = "") -> bool:
        """Manually execute a specific step."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False

        step = next((s for s in incident.steps if s.step_id == step_id), None)
        if not step or step.completed:
            return False

        self._execute_step(incident, step, result)
        return True

    def _execute_step(
        self,
        incident: Incident,
        step: IRStep,
        result: str = "",
    ) -> None:
        """Execute a single IR step."""
        step.completed = True
        step.completed_at = datetime.utcnow().isoformat()
        step.result = result or f"Automated execution: {step.action}"

        incident.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": f"Step completed: {step.action}",
            "detail": step.result,
            "phase": step.phase,
        })

        if step.phase == "containment" and incident.status == "investigating":
            incident.status = "contained"
        elif step.phase == "eradication" and incident.status == "contained":
            incident.status = "eradicated"
        elif step.phase == "recovery" and incident.status == "eradicated":
            incident.status = "resolved"

        incident.updated_at = datetime.utcnow().isoformat()

    def add_lesson_learned(self, incident_id: str, lesson: str) -> bool:
        """Add a lesson learned to an incident."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        incident.lessons_learned.append(lesson)
        return True

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Incident]:
        incidents = list(self._incidents.values())
        if status:
            incidents = [i for i in incidents if i.status == status]
        if severity:
            incidents = [i for i in incidents if i.severity == severity]
        incidents.sort(key=lambda i: i.created_at, reverse=True)
        return incidents

    def get_stats(self) -> Dict[str, Any]:
        status_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        for inc in self._incidents.values():
            status_counts[inc.status] = status_counts.get(inc.status, 0) + 1
            severity_counts[inc.severity] = severity_counts.get(inc.severity, 0) + 1

        return {
            "total_incidents": len(self._incidents),
            "by_status": status_counts,
            "by_severity": severity_counts,
            "categories": list({i.category for i in self._incidents.values()}),
        }

    def generate_report(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Generate a post-incident report."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        completed = sum(1 for s in incident.steps if s.completed)
        total = len(incident.steps)

        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "category": incident.category,
            "status": incident.status,
            "created_at": incident.created_at,
            "updated_at": incident.updated_at,
            "description": incident.description,
            "affected_systems": incident.affected_systems,
            "mitre_techniques": incident.mitre_techniques,
            "timeline": incident.timeline,
            "steps_completed": f"{completed}/{total}",
            "steps": [
                {
                    "step_id": s.step_id,
                    "phase": s.phase,
                    "action": s.action,
                    "completed": s.completed,
                    "result": s.result,
                }
                for s in incident.steps
            ],
            "lessons_learned": incident.lessons_learned,
            "artifacts": incident.artifacts,
        }

    def subscribe_to_event_bus(
        self,
        bus: Any,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> None:
        """Subscribe incident response to blue team alert events on the shared event bus.

        When a critical blue team alert is received, an incident is created and
        a ``BlueTeamIncidentCreatedEvent`` is published.

        Args:
            bus: The shared :class:`EventBus`.
            tenant_id: Tenant scope for events to process.
            exercise_id: Optional exercise identifier to include in published events.
        """
        from ciicerone.core.event_bus import EventBus

        if not isinstance(bus, EventBus):
            raise TypeError("bus must be an EventBus instance")

        async def _handler(event: BusEvent) -> None:
            if event.tenant_id != tenant_id:
                return
            if event.event_type != EventType.BLUE_TEAM_ALERT:
                return

            payload = event.payload
            if payload.get("severity") != "critical":
                return

            technique_id = payload.get("technique_id", "")
            category = self._incident_category_from_technique(technique_id)
            description = payload.get("description", "")

            try:
                incident = self.create_incident(
                    title=payload.get("raw_data", {}).get("title", "Blue team critical alert"),
                    severity="critical",
                    category=category,
                    description=description,
                    affected_systems=[payload.get("source_module", "blue_team")],
                    mitre_techniques=[technique_id] if technique_id else [],
                )

                await bus.publish(
                    BlueTeamIncidentCreatedEvent(
                        tenant_id=tenant_id,
                        exercise_id=exercise_id,
                        simulation_id=event.simulation_id,
                        incident_id=incident.incident_id,
                        title=incident.title,
                        severity=incident.severity,
                        category=incident.category,
                        mitre_techniques=incident.mitre_techniques,
                    )
                )
            except Exception as exc:
                logger.warning("Incident creation failed: %s", exc)

        bus.subscribe(EventType.BLUE_TEAM_ALERT, _handler)

    def _incident_category_from_technique(self, technique_id: str) -> str:
        """Map a MITRE technique to a coarse incident category."""
        if technique_id.startswith("T1566"):
            return "phishing"
        if technique_id in {"T1003", "T1078", "T1110"}:
            return "credential_access"
        if technique_id in {"T1190", "T1133"}:
            return "intrusion"
        if technique_id in {"T1041", "T1048", "T1567"}:
            return "data_breach"
        return "malware"
