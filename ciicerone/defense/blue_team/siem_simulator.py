"""SIEM Simulator.

Simulated SIEM with log aggregation, correlation rules, and query engine.
Bridges to real SIEM platforms via SIEMClient when configured.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Callable

from ciicerone.core.event_types import BlueTeamAlertEvent, BusEvent, EventType
from ciicerone.integrations.siem_client import SIEMClient, SIEMEvent, SIEMAlert

logger = logging.getLogger(__name__)


@dataclass
class CorrelationRule:
    """A correlation rule for the SIEM simulator."""
    rule_id: str
    name: str
    description: str
    conditions: Dict[str, Any]
    severity: str = "medium"
    mitre_technique: Optional[str] = None
    enabled: bool = True
    trigger_count: int = 0
    last_triggered: Optional[datetime] = None


class SIEMSimulator:
    """Simulated SIEM with log aggregation and correlation.

    Provides:
        - Log ingestion from multiple sources
        - Correlation rule engine
        - Query interface (SPL-like syntax)
        - Alert generation
        - Bridge to real SIEM via SIEMClient

    Example:
        siem = SIEMSimulator()
        siem.ingest_log({"source": "auth", "message": "Failed login", "user": "admin"})
        alerts = siem.check_correlations()
        results = siem.query('source="auth" "failed login"')
    """

    DEFAULT_RULES: List[Dict[str, Any]] = [
        {
            "rule_id": "CORR-001",
            "name": "Multiple Failed Logins",
            "description": "More than 5 failed login attempts from same IP in 10 minutes",
            "conditions": {
                "match": {"message": ".*[Ff]ailed.*login.*"},
                "group_by": "source_ip",
                "count_threshold": 5,
                "time_window": 600,
            },
            "severity": "high",
            "mitre_technique": "T1110",
        },
        {
            "rule_id": "CORR-002",
            "name": "Privilege Escalation",
            "description": "User added to admin/root group",
            "conditions": {
                "match": {"message": ".*(added to|member of).*(admin|root|wheel|sudo).*"},
            },
            "severity": "critical",
            "mitre_technique": "T1078",
        },
        {
            "rule_id": "CORR-003",
            "name": "Suspicious Process Execution",
            "description": "Execution of known attack tools",
            "conditions": {
                "match": {"message": ".*(nmap|hydra|metasploit|mimikatz|cobalt).*"},
            },
            "severity": "high",
            "mitre_technique": "T1059",
        },
        {
            "rule_id": "CORR-004",
            "name": "Data Exfiltration",
            "description": "Large outbound transfer to unknown destination",
            "conditions": {
                "match": {"message": ".*outbound.*transfer.*"},
                "field_threshold": {"bytes_out": 10485760},
            },
            "severity": "critical",
            "mitre_technique": "T1041",
        },
        {
            "rule_id": "CORR-005",
            "name": "Lateral Movement - RDP",
            "description": "RDP connections to multiple internal hosts",
            "conditions": {
                "match": {"message": ".*rdp.*connect.*"},
                "group_by": "source_ip",
                "count_threshold": 3,
                "time_window": 1800,
            },
            "severity": "high",
            "mitre_technique": "T1021",
        },
        {
            "rule_id": "CORR-006",
            "name": "Persistence - Scheduled Task",
            "description": "Creation of scheduled task or cron job",
            "conditions": {
                "match": {"message": ".*(schtasks|crontab|systemctl enable).*"},
            },
            "severity": "medium",
            "mitre_technique": "T1053",
        },
        {
            "rule_id": "CORR-007",
            "name": "Credential Dumping",
            "description": "Access to credential stores",
            "conditions": {
                "match": {"message": ".*(LSASS|SAM|ntds.dit|/etc/shadow|reg save).*"},
            },
            "severity": "critical",
            "mitre_technique": "T1003",
        },
        {
            "rule_id": "CORR-008",
            "name": "Defense Evasion - Log Clearing",
            "description": "Attempts to clear or modify logs",
            "conditions": {
                "match": {"message": ".*(clear.*log|rm.*auth.log|wevtutil cl|auditpol).*"},
            },
            "severity": "high",
            "mitre_technique": "T1070",
        },
    ]

    def __init__(
        self,
        siem_client: Optional[SIEMClient] = None,
        enable_default_rules: bool = True,
    ):
        self.siem_client = siem_client
        self._logs: List[Dict[str, Any]] = []
        self._alerts: List[SIEMAlert] = []
        self._rules: Dict[str, CorrelationRule] = {}
        self._log_index = 0

        if enable_default_rules:
            for rule_def in self.DEFAULT_RULES:
                self.add_rule(CorrelationRule(**rule_def))

    def add_rule(self, rule: CorrelationRule) -> None:
        self._rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def list_rules(self) -> List[CorrelationRule]:
        return list(self._rules.values())

    def ingest_log(self, log_entry: Dict[str, Any]) -> None:
        """Ingest a log entry into the SIEM."""
        if "timestamp" not in log_entry:
            log_entry["timestamp"] = datetime.utcnow().isoformat()
        if "id" not in log_entry:
            log_entry["id"] = f"log-{self._log_index:06d}"
            self._log_index += 1

        self._logs.append(log_entry)

        if self.siem_client:
            asyncio.create_task(self.siem_client.ingest_log(log_entry))

    def ingest_logs(self, logs: List[Dict[str, Any]]) -> None:
        for log_entry in logs:
            self.ingest_log(log_entry)

    def query(self, query_str: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query logs with a simple SPL-like syntax.

        Supports:
            - field="value" exact match
            - "text" substring search
            - field>number, field<number comparisons
            - AND/OR operators

        Example:
            results = siem.query('source="auth" "failed login"')
        """
        results: List[Dict[str, Any]] = []

        conditions = self._parse_query(query_str)

        for log in self._logs:
            if self._match_conditions(log, conditions):
                results.append(log)
                if len(results) >= limit:
                    break

        return results

    def _parse_query(self, query_str: str) -> List[Dict[str, Any]]:
        """Parse SPL-like query into conditions."""
        conditions: List[Dict[str, Any]] = []

        tokens = re.findall(
            r'(\w+([><]=?|=)"[^"]*"|\w+([><]=?|=)\S+|"[^"]*"|\S+)',
            query_str,
        )

        for token_groups in tokens:
            token = token_groups[0]

            field_match = re.match(r'(\w+)([><]=?|=)"?([^"]*)"?', token)
            if field_match:
                field, op, value = field_match.groups()
                if op == "=":
                    conditions.append({"type": "eq", "field": field, "value": value})
                elif op == ">":
                    conditions.append({"type": "gt", "field": field, "value": float(value)})
                elif op == "<":
                    conditions.append({"type": "lt", "field": field, "value": float(value)})
                elif op == ">=":
                    conditions.append({"type": "gte", "field": field, "value": float(value)})
                elif op == "<=":
                    conditions.append({"type": "lte", "field": field, "value": float(value)})
            else:
                text = token.strip('"')
                if text and text not in ("AND", "OR"):
                    conditions.append({"type": "contains", "value": text})

        return conditions

    def _match_conditions(
        self, log: Dict[str, Any], conditions: List[Dict[str, Any]]
    ) -> bool:
        for cond in conditions:
            if cond["type"] == "eq":
                if str(log.get(cond["field"], "")) != cond["value"]:
                    return False
            elif cond["type"] in ("gt", "lt", "gte", "lte"):
                val = log.get(cond["field"])
                if val is None:
                    return False
                try:
                    num_val = float(val)
                    if cond["type"] == "gt" and not num_val > cond["value"]:
                        return False
                    elif cond["type"] == "lt" and not num_val < cond["value"]:
                        return False
                    elif cond["type"] == "gte" and not num_val >= cond["value"]:
                        return False
                    elif cond["type"] == "lte" and not num_val <= cond["value"]:
                        return False
                except (ValueError, TypeError):
                    return False
            elif cond["type"] == "contains":
                log_str = json.dumps(log).lower()
                if cond["value"].lower() not in log_str:
                    return False

        return True

    def check_correlations(self) -> List[SIEMAlert]:
        """Run correlation rules against ingested logs and generate alerts."""
        new_alerts: List[SIEMAlert] = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            matches = self._evaluate_rule(rule)
            if matches:
                alert = SIEMAlert(
                    alert_id=f"alert-{rule.rule_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    title=rule.name,
                    severity=rule.severity,
                    status="new",
                    created_at=datetime.utcnow().isoformat(),
                    description=rule.description,
                    source="siem-simulator",
                    mitre_techniques=[rule.mitre_technique] if rule.mitre_technique else [],
                    related_events=[m.get("id", "") for m in matches],
                    metadata={
                        "rule_id": rule.rule_id,
                        "match_count": len(matches),
                        "matched_logs": matches[:10],
                    },
                )
                new_alerts.append(alert)
                self._alerts.append(alert)

                rule.trigger_count += 1
                rule.last_triggered = datetime.utcnow()

        return new_alerts

    def _evaluate_rule(self, rule: CorrelationRule) -> List[Dict[str, Any]]:
        """Evaluate a correlation rule against logs."""
        conditions = rule.conditions
        match_patterns = conditions.get("match", {})
        group_by = conditions.get("group_by")
        count_threshold = conditions.get("count_threshold", 1)
        time_window = conditions.get("time_window", 0)
        field_threshold = conditions.get("field_threshold", {})

        matching_logs: List[Dict[str, Any]] = []

        for log in self._logs:
            matched = True
            for field, pattern in match_patterns.items():
                val = str(log.get(field, ""))
                if not re.search(pattern, val, re.IGNORECASE):
                    matched = False
                    break

            if matched:
                for field, threshold in field_threshold.items():
                    val = log.get(field)
                    if val is None:
                        matched = False
                        break
                    try:
                        if float(val) < threshold:
                            matched = False
                            break
                    except (ValueError, TypeError):
                        matched = False
                        break

            if matched:
                matching_logs.append(log)

        if time_window > 0:
            cutoff = datetime.utcnow() - timedelta(seconds=time_window)
            matching_logs = [
                log for log in matching_logs
                if self._parse_timestamp(log.get("timestamp", "")) >= cutoff
            ]

        if group_by and count_threshold > 1:
            groups: Dict[str, List[Dict[str, Any]]] = {}
            for log in matching_logs:
                key = str(log.get(group_by, "unknown"))
                groups.setdefault(key, []).append(log)

            triggered: List[Dict[str, Any]] = []
            for key, logs in groups.items():
                if len(logs) >= count_threshold:
                    triggered.extend(logs)
            return triggered

        return matching_logs if matching_logs else []

    def _parse_timestamp(self, ts: str) -> datetime:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.utcnow()

    def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[SIEMAlert]:
        """Get alerts from the simulator and optionally from real SIEM."""
        alerts = list(self._alerts)

        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if status:
            alerts = [a for a in alerts if a.status == status]

        alerts.sort(key=lambda a: a.created_at, reverse=True)
        return alerts[:limit]

    @property
    def log_count(self) -> int:
        return len(self._logs)

    @property
    def alert_count(self) -> int:
        return len(self._alerts)

    def get_stats(self) -> Dict[str, Any]:
        """Get SIEM statistics."""
        severity_counts: Dict[str, int] = {}
        for alert in self._alerts:
            severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

        source_counts: Dict[str, int] = {}
        for log in self._logs:
            src = log.get("source", "unknown")
            source_counts[src] = source_counts.get(src, 0) + 1

        return {
            "total_logs": self.log_count,
            "total_alerts": self.alert_count,
            "active_rules": sum(1 for r in self._rules.values() if r.enabled),
            "alerts_by_severity": severity_counts,
            "logs_by_source": source_counts,
            "connected_to_siem": self.siem_client is not None,
        }

    def clear(self) -> None:
        """Clear all logs and alerts."""
        self._logs.clear()
        self._alerts.clear()
        self._log_index = 0

    def subscribe_to_event_bus(
        self,
        bus: Any,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> None:
        """Subscribe this SIEM to red team attack events on the shared event bus.

        When a red team attack stage event is received, the attack content is
        ingested as a SIEM log and correlation rules are evaluated. Any alerts
        are published as ``BlueTeamAlertEvent`` events on the bus.

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
            if event.event_type != EventType.RED_TEAM_ATTACK_STAGE:
                return

            payload = event.payload
            log_entry = {
                "source": "red_team_simulator",
                "message": payload.get("content", ""),
                "mitre_technique": payload.get("technique_id", ""),
                "stage_id": payload.get("stage_id", ""),
                "target_system": payload.get("target_system", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.ingest_log(log_entry)

            for alert in self.check_correlations():
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
