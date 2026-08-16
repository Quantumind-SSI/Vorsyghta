"""Threat Hunter.

Proactive threat hunting using MITRE ATT&CK hypotheses, IOC searches,
and behavioral analytics across SIEM and EDR data.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from vorsyghta.core.event_types import BlueTeamHuntEvent, BusEvent, EventType
from vorsyghta.integrations.siem_client import SIEMClient, SIEMEvent

logger = logging.getLogger(__name__)


@dataclass
class HuntHypothesis:
    """A threat hunting hypothesis based on MITRE ATT&CK."""
    hypothesis_id: str
    technique_id: str
    technique_name: str
    description: str
    query: str
    data_sources: List[str] = field(default_factory=list)
    confidence: float = 0.5
    status: str = "pending"  # pending, hunting, confirmed, disproved
    findings: List[Dict[str, Any]] = field(default_factory=list)
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class HuntResult:
    """Result of a threat hunt."""
    hypothesis: HuntHypothesis
    findings: List[Dict[str, Any]] = field(default_factory=list)
    confirmed: bool = False
    iocs_found: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    summary: str = ""


class ThreatHunter:
    """Proactive threat hunting with MITRE ATT&CK.

    Provides:
        - Hypothesis-based hunting using ATT&CK techniques
        - Pre-built hunt hypotheses for common techniques
        - IOC search across SIEM and EDR data
        - Behavioral analytics for anomaly detection

    Example:
        hunter = ThreatHunter(siem_client=client)
        result = await hunter.hunt_technique("T1003")
        result = await hunter.hunt_hypothesis("Credential dumping via LSASS access")
    """

    DEFAULT_HYPOTHESES: List[Dict[str, Any]] = [
        {
            "hypothesis_id": "HUNT-001",
            "technique_id": "T1003",
            "technique_name": "Credential Dumping",
            "description": "Adversaries may attempt to dump credentials from LSASS or SAM",
            "query": '("lsass" OR "procdump" OR "mimikatz" OR "ntds.dit" OR "reg save HKLM\\SAM")',
            "data_sources": ["edr", "siem", "windows_logs"],
            "confidence": 0.8,
        },
        {
            "hypothesis_id": "HUNT-002",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "description": "Suspicious PowerShell or cmd.exe execution patterns",
            "query": '("powershell -enc" OR "powershell -exec bypass" OR "cmd /c powershell" OR "wscript")',
            "data_sources": ["edr", "siem", "process_logs"],
            "confidence": 0.7,
        },
        {
            "hypothesis_id": "HUNT-003",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol (C2)",
            "description": "Beaconing behavior or C2 communication patterns",
            "query": '("beacon" OR "checkin" OR "heartbeat" OR periodic connections to unknown IPs)',
            "data_sources": ["ids", "siem", "network_logs"],
            "confidence": 0.6,
        },
        {
            "hypothesis_id": "HUNT-004",
            "technique_id": "T1053",
            "technique_name": "Scheduled Task/Job",
            "description": "Persistence via scheduled tasks or cron jobs",
            "query": '("schtasks /create" OR "crontab" OR "systemctl enable" OR "at command")',
            "data_sources": ["edr", "siem", "system_logs"],
            "confidence": 0.6,
        },
        {
            "hypothesis_id": "HUNT-005",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "description": "Multiple failed authentication attempts",
            "query": '("failed login" OR "authentication failed" OR "invalid password")',
            "data_sources": ["siem", "auth_logs"],
            "confidence": 0.7,
        },
        {
            "hypothesis_id": "HUNT-006",
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "description": "Large data transfers to external destinations",
            "query": '(bytes_out > 10MB AND dest_ip NOT in known_good_ranges)',
            "data_sources": ["ids", "siem", "network_logs"],
            "confidence": 0.5,
        },
        {
            "hypothesis_id": "HUNT-007",
            "technique_id": "T1070",
            "technique_name": "Indicator Removal",
            "description": "Log clearing or artifact wiping",
            "query": '("clear log" OR "wevtutil cl" OR "rm auth.log" OR "auditpol /clear")',
            "data_sources": ["edr", "siem", "system_logs"],
            "confidence": 0.8,
        },
        {
            "hypothesis_id": "HUNT-008",
            "technique_id": "T1547",
            "technique_name": "Boot or Logon Autostart Execution",
            "description": "Persistence via registry Run keys or startup folders",
            "query": '("HKLM\\...\\Run" OR "HKCU\\...\\Run" OR "Startup folder" OR "Winlogon Shell")',
            "data_sources": ["edr", "siem", "registry_logs"],
            "confidence": 0.7,
        },
    ]

    def __init__(
        self,
        siem_client: Optional[SIEMClient] = None,
        enable_default_hypotheses: bool = True,
    ):
        self.siem_client = siem_client
        self._hypotheses: Dict[str, HuntHypothesis] = {}
        self._results: List[HuntResult] = []

        if enable_default_hypotheses:
            for hyp_def in self.DEFAULT_HYPOTHESES:
                self.add_hypothesis(HuntHypothesis(
                    **hyp_def,
                    created_at=datetime.utcnow().isoformat(),
                ))

    def add_hypothesis(self, hypothesis: HuntHypothesis) -> None:
        self._hypotheses[hypothesis.hypothesis_id] = hypothesis

    def list_hypotheses(self) -> List[HuntHypothesis]:
        return list(self._hypotheses.values())

    def get_hypothesis(self, hypothesis_id: str) -> Optional[HuntHypothesis]:
        return self._hypotheses.get(hypothesis_id)

    async def hunt_technique(self, technique_id: str) -> Optional[HuntResult]:
        """Hunt for a specific MITRE ATT&CK technique."""
        hypothesis = next(
            (h for h in self._hypotheses.values() if h.technique_id == technique_id),
            None,
        )
        if not hypothesis:
            return None

        return await self._execute_hunt(hypothesis)

    async def hunt_hypothesis(self, hypothesis_id: str) -> Optional[HuntResult]:
        """Execute a specific hunt hypothesis."""
        hypothesis = self._hypotheses.get(hypothesis_id)
        if not hypothesis:
            return None
        return await self._execute_hunt(hypothesis)

    async def hunt_all(self) -> List[HuntResult]:
        """Execute all hunt hypotheses."""
        results: List[HuntResult] = []
        for hypothesis in self._hypotheses.values():
            result = await self._execute_hunt(hypothesis)
            if result:
                results.append(result)
        return results

    async def _execute_hunt(self, hypothesis: HuntHypothesis) -> HuntResult:
        """Execute a single hunt hypothesis."""
        hypothesis.status = "hunting"

        findings: List[Dict[str, Any]] = []
        iocs: List[str] = []
        systems: List[str] = []

        if self.siem_client and self.siem_client.base_url:
            events = await self.siem_client.search_logs(
                query=hypothesis.query,
                start_time=datetime.utcnow() - timedelta(hours=24),
                limit=100,
            )

            for event in events:
                findings.append({
                    "source": "siem",
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "host": event.host,
                    "raw": event.raw[:500],
                    "fields": event.fields,
                })

                if event.host and event.host not in systems:
                    systems.append(event.host)

                if event.mitre_technique:
                    iocs.append(f"{event.source_ip}:{event.source_port}")
        else:
            findings.append({
                "source": "simulated",
                "note": "No SIEM client configured. Connect SIEMClient for live hunting.",
            })

        confirmed = len(findings) > 0 and not any(
            f.get("source") == "simulated" for f in findings
        )

        hypothesis.status = "confirmed" if confirmed else "disproved"
        hypothesis.findings = findings
        hypothesis.completed_at = datetime.utcnow().isoformat()

        result = HuntResult(
            hypothesis=hypothesis,
            findings=findings,
            confirmed=confirmed,
            iocs_found=iocs,
            affected_systems=systems,
            summary=self._generate_summary(hypothesis, findings, confirmed),
        )

        self._results.append(result)
        return result

    def _generate_summary(
        self,
        hypothesis: HuntHypothesis,
        findings: List[Dict[str, Any]],
        confirmed: bool,
    ) -> str:
        if confirmed:
            return (
                f"CONFIRMED: Threat hunting for {hypothesis.technique_id} "
                f"({hypothesis.technique_name}) found {len(findings)} matching events. "
                f"Affected systems: {', '.join(hypothesis.findings and [f.get('host', '') for f in findings if f.get('host')] or ['unknown'])}. "
                f"Immediate investigation recommended."
            )
        else:
            return (
                f"DISPROVED: No evidence of {hypothesis.technique_id} "
                f"({hypothesis.technique_name}) found in the last 24 hours. "
                f"Hypothesis not confirmed with current data sources."
            )

    def search_iocs(self, ioc_list: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Search for IOCs in local findings.

        Args:
            ioc_list: List of IOCs (IPs, domains, hashes, file names)

        Returns:
            Dict mapping IOC to matching findings
        """
        results: Dict[str, List[Dict[str, Any]]] = {}

        for ioc in ioc_list:
            matches: List[Dict[str, Any]] = []
            for result in self._results:
                for finding in result.findings:
                    raw = str(finding.get("raw", "")).lower()
                    if ioc.lower() in raw:
                        matches.append(finding)
            if matches:
                results[ioc] = matches

        return results

    def get_results(self) -> List[HuntResult]:
        return list(self._results)

    def get_stats(self) -> Dict[str, Any]:
        confirmed = sum(1 for r in self._results if r.confirmed)
        return {
            "total_hypotheses": len(self._hypotheses),
            "hunts_executed": len(self._results),
            "confirmed_threats": confirmed,
            "disproved": len(self._results) - confirmed,
            "total_findings": sum(len(r.findings) for r in self._results),
            "siem_connected": self.siem_client is not None and bool(self.siem_client.base_url),
        }

    def subscribe_to_event_bus(
        self,
        bus: Any,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> None:
        """Subscribe threat hunting to blue team alert events on the shared event bus.

        When a high/critical blue team alert is received, a threat hunt is
        initiated for the associated MITRE technique and a ``BlueTeamHuntEvent``
        is published.

        Args:
            bus: The shared :class:`EventBus`.
            tenant_id: Tenant scope for events to process.
            exercise_id: Optional exercise identifier to include in published events.
        """
        from vorsyghta.core.event_bus import EventBus

        if not isinstance(bus, EventBus):
            raise TypeError("bus must be an EventBus instance")

        async def _handler(event: BusEvent) -> None:
            if event.tenant_id != tenant_id:
                return
            if event.event_type != EventType.BLUE_TEAM_ALERT:
                return

            payload = event.payload
            if payload.get("severity") not in {"critical", "high"}:
                return

            technique_id = payload.get("technique_id", "")
            if not technique_id:
                return

            try:
                result = await self.hunt_technique(technique_id)
                if result is None:
                    return

                await bus.publish(
                    BlueTeamHuntEvent(
                        tenant_id=tenant_id,
                        exercise_id=exercise_id,
                        simulation_id=event.simulation_id,
                        hypothesis_id=result.hypothesis.hypothesis_id,
                        technique_id=technique_id,
                        confirmed=result.confirmed,
                        findings=[{"summary": result.summary}],
                        iocs_found=result.iocs_found,
                    )
                )
            except Exception as exc:
                logger.warning("Threat hunt for %s failed: %s", technique_id, exc)

        bus.subscribe(EventType.BLUE_TEAM_ALERT, _handler)
