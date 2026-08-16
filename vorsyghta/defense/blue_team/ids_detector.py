"""IDS/IPS Detection Engine.

Simulates Snort/Suricata-style network intrusion detection with
rule-based signature matching and alert generation.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from vorsyghta.core.event_types import BlueTeamAlertEvent, BusEvent, EventType
from vorsyghta.integrations.siem_client import SIEMAlert

logger = logging.getLogger(__name__)


@dataclass
class IDSRule:
    """An IDS detection rule (Snort/Suricata style)."""
    rule_id: str
    name: str
    protocol: str  # tcp, udp, icmp, any
    source_ip: str = "any"
    source_port: str = "any"
    dest_ip: str = "any"
    dest_port: str = "any"
    pattern: Optional[str] = None  # Content pattern to match
    severity: str = "medium"
    mitre_technique: Optional[str] = None
    enabled: bool = True
    action: str = "alert"  # alert, drop, reject


@dataclass
class NetworkPacket:
    """Represents a network packet for IDS inspection."""
    timestamp: str
    protocol: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    payload: str = ""
    flags: List[str] = field(default_factory=list)
    length: int = 0


class IDSDetector:
    """IDS/IPS detection engine with Snort/Suricata rule simulation.

    Provides:
        - Signature-based detection with Snort-style rules
        - Network packet inspection
        - Alert generation with MITRE ATT&CK mapping
        - Port scan detection
        - Brute force detection

    Example:
        ids = IDSDetector()
        ids.inspect_packet(NetworkPacket(
            timestamp=..., protocol="tcp",
            source_ip="10.0.0.5", source_port=12345,
            dest_ip="10.0.0.10", dest_port=80,
            payload="GET /admin HTTP/1.1",
        ))
    """

    DEFAULT_RULES: List[Dict[str, Any]] = [
        {
            "rule_id": "IDS-001",
            "name": "Nmap Port Scan Detection",
            "protocol": "tcp",
            "pattern": None,
            "severity": "high",
            "mitre_technique": "T1046",
            "action": "alert",
        },
        {
            "rule_id": "IDS-002",
            "name": "SQL Injection Attempt",
            "protocol": "tcp",
            "dest_port": "any",
            "pattern": r"(?i)(union.*select|or.*1=1|';.*--|xp_cmdshell|information_schema)",
            "severity": "critical",
            "mitre_technique": "T1190",
            "action": "alert",
        },
        {
            "rule_id": "IDS-003",
            "name": "XSS Attempt",
            "protocol": "tcp",
            "pattern": r"(?i)(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)",
            "severity": "high",
            "mitre_technique": "T1185",
            "action": "alert",
        },
        {
            "rule_id": "IDS-004",
            "name": "Directory Traversal",
            "protocol": "tcp",
            "pattern": r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|..%2f)",
            "severity": "high",
            "mitre_technique": "T1083",
            "action": "alert",
        },
        {
            "rule_id": "IDS-005",
            "name": "SSH Brute Force",
            "protocol": "tcp",
            "dest_port": "22",
            "pattern": r"(?i)(failed|invalid|error).*password",
            "severity": "high",
            "mitre_technique": "T1110",
            "action": "alert",
        },
        {
            "rule_id": "IDS-006",
            "name": "Web Shell Upload",
            "protocol": "tcp",
            "pattern": r"(?i)(c99\.php|r57\.php|shell\.php|cmd\.php|eval\(|base64_decode)",
            "severity": "critical",
            "mitre_technique": "T1505",
            "action": "alert",
        },
        {
            "rule_id": "IDS-007",
            "name": "RDP Brute Force",
            "protocol": "tcp",
            "dest_port": "3389",
            "pattern": None,
            "severity": "high",
            "mitre_technique": "T1110",
            "action": "alert",
        },
        {
            "rule_id": "IDS-008",
            "name": "DNS Exfiltration",
            "protocol": "udp",
            "dest_port": "53",
            "pattern": r"(?i)([a-z0-9]{30,}\.|\.(txt|cname|ns)|base64)",
            "severity": "critical",
            "mitre_technique": "T1048",
            "action": "alert",
        },
        {
            "rule_id": "IDS-009",
            "name": "C2 Beacon",
            "protocol": "tcp",
            "pattern": r"(?i)(beacon|checkin|heartbeat|/api/v1/poll)",
            "severity": "high",
            "mitre_technique": "T1071",
            "action": "alert",
        },
        {
            "rule_id": "IDS-010",
            "name": "Credential Dumping - LSASS Access",
            "protocol": "tcp",
            "pattern": r"(?i)(lsass|procdump|comsvcs.*minidump)",
            "severity": "critical",
            "mitre_technique": "T1003",
            "action": "alert",
        },
    ]

    def __init__(self, enable_default_rules: bool = True):
        self._rules: Dict[str, IDSRule] = {}
        self._alerts: List[SIEMAlert] = []
        self._packet_log: List[NetworkPacket] = []
        self._port_scan_tracker: Dict[str, List[int]] = {}
        self._brute_force_tracker: Dict[str, List[datetime]] = {}

        if enable_default_rules:
            for rule_def in self.DEFAULT_RULES:
                self.add_rule(IDSRule(**rule_def))

    def add_rule(self, rule: IDSRule) -> None:
        self._rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def list_rules(self) -> List[IDSRule]:
        return list(self._rules.values())

    def inspect_packet(self, packet: NetworkPacket) -> List[SIEMAlert]:
        """Inspect a network packet against IDS rules.

        Returns:
            List of alerts triggered by this packet
        """
        self._packet_log.append(packet)
        triggered: List[SIEMAlert] = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            if self._match_rule(rule, packet):
                alert = SIEMAlert(
                    alert_id=f"ids-{rule.rule_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
                    title=f"[IDS] {rule.name}",
                    severity=rule.severity,
                    status="new",
                    created_at=packet.timestamp,
                    description=f"IDS rule {rule.rule_id} triggered: {rule.name}",
                    source="ids-detector",
                    mitre_techniques=[rule.mitre_technique] if rule.mitre_technique else [],
                    metadata={
                        "rule_id": rule.rule_id,
                        "protocol": packet.protocol,
                        "source_ip": packet.source_ip,
                        "source_port": packet.source_port,
                        "dest_ip": packet.dest_ip,
                        "dest_port": packet.dest_port,
                        "payload_snippet": packet.payload[:200] if packet.payload else "",
                        "action": rule.action,
                    },
                )
                triggered.append(alert)
                self._alerts.append(alert)

        port_scan_alerts = self._check_port_scan(packet)
        triggered.extend(port_scan_alerts)

        return triggered

    def inspect_traffic(self, packets: List[NetworkPacket]) -> List[SIEMAlert]:
        """Inspect multiple packets."""
        all_alerts: List[SIEMAlert] = []
        for packet in packets:
            alerts = self.inspect_packet(packet)
            all_alerts.extend(alerts)
        return all_alerts

    def _match_rule(self, rule: IDSRule, packet: NetworkPacket) -> bool:
        """Check if a packet matches an IDS rule."""
        if rule.protocol != "any" and rule.protocol != packet.protocol:
            return False

        if rule.dest_port != "any":
            try:
                if int(rule.dest_port) != packet.dest_port:
                    return False
            except ValueError:
                pass

        if rule.source_port != "any":
            try:
                if int(rule.source_port) != packet.source_port:
                    return False
            except ValueError:
                pass

        if rule.pattern:
            if not re.search(rule.pattern, packet.payload):
                return False

        return True

    def _check_port_scan(self, packet: NetworkPacket) -> List[SIEMAlert]:
        """Detect port scanning behavior."""
        alerts: List[SIEMAlert] = []
        src = packet.source_ip

        self._port_scan_tracker.setdefault(src, [])
        if packet.dest_port not in self._port_scan_tracker[src]:
            self._port_scan_tracker[src].append(packet.dest_port)

        if len(self._port_scan_tracker[src]) >= 10:
            alert = SIEMAlert(
                alert_id=f"ids-portscan-{src}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                title=f"[IDS] Port Scan from {src}",
                severity="high",
                status="new",
                created_at=packet.timestamp,
                description=f"Port scan detected from {src}: {len(self._port_scan_tracker[src])} ports scanned",
                source="ids-detector",
                mitre_techniques=["T1046"],
                metadata={
                    "source_ip": src,
                    "ports_scanned": self._port_scan_tracker[src],
                    "port_count": len(self._port_scan_tracker[src]),
                },
            )
            alerts.append(alert)
            self._alerts.append(alert)
            self._port_scan_tracker[src] = []

        return alerts

    def get_alerts(
        self,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[SIEMAlert]:
        alerts = list(self._alerts)
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        return alerts[:limit]

    def get_stats(self) -> Dict[str, Any]:
        severity_counts: Dict[str, int] = {}
        for alert in self._alerts:
            severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

        return {
            "total_packets": len(self._packet_log),
            "total_alerts": len(self._alerts),
            "active_rules": sum(1 for r in self._rules.values() if r.enabled),
            "alerts_by_severity": severity_counts,
            "tracked_sources": len(self._port_scan_tracker),
        }

    def clear(self) -> None:
        self._alerts.clear()
        self._packet_log.clear()

    def subscribe_to_event_bus(
        self,
        bus: Any,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> None:
        """Subscribe this IDS to red team attack events on the shared event bus.

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
            if event.event_type != EventType.RED_TEAM_ATTACK_STAGE:
                return

            payload = event.payload
            technique_id = payload.get("technique_id", "")
            technique_ports = {
                "T1046": 80,
                "T1190": 80,
                "T1110": 22,
                "T1003": 445,
                "T1059": 443,
                "T1071": 443,
                "T1041": 443,
                "T1048": 53,
                "T1505": 80,
                "T1136": 445,
            }
            packet = NetworkPacket(
                timestamp=datetime.now(timezone.utc).isoformat(),
                protocol="tcp",
                source_ip="10.0.0.5",
                source_port=12345,
                dest_ip="10.0.0.10",
                dest_port=technique_ports.get(technique_id, 80),
                payload=payload.get("content", "")[:1000],
            )

            for alert in self.inspect_packet(packet):
                await bus.publish(
                    BlueTeamAlertEvent(
                        tenant_id=tenant_id,
                        exercise_id=exercise_id,
                        simulation_id=event.simulation_id,
                        alert_id=alert.alert_id,
                        source_module=alert.source,
                        technique_id=alert.mitre_techniques[0] if alert.mitre_techniques else "",
                        severity=alert.severity,
                        description=alert.description,
                        detected=True,
                        stage_id=payload.get("stage_id"),
                        iocs=payload.get("iocs", []),
                        raw_data={
                            "title": alert.title,
                            "metadata": alert.metadata,
                            "related_events": alert.related_events,
                        },
                    )
                )

        bus.subscribe(EventType.RED_TEAM_ATTACK_STAGE, _handler)
        self._port_scan_tracker.clear()
        self._brute_force_tracker.clear()
