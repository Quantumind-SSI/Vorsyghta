"""Alert Triage.

Alert prioritization, false positive reduction, and triage automation.
Scores alerts based on severity, confidence, context, and historical data.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from vorsyghta.core.event_types import BusEvent, EventType
from vorsyghta.integrations.siem_client import SIEMAlert

logger = logging.getLogger(__name__)


@dataclass
class TriagedAlert:
    """An alert that has been triaged and scored."""
    alert: SIEMAlert
    priority_score: float
    priority_level: str  # P1, P2, P3, P4
    is_false_positive: bool = False
    fp_reason: Optional[str] = None
    recommended_action: str = ""
    related_alerts: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    triaged_at: Optional[str] = None
    triaged_by: str = "automated"


SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 5,
}

MITRE_HIGH_PRIORITY = {
    "T1003", "T1190", "T1486", "T1567", "T1041",
    "T1078", "T1136", "T1547", "T1059", "T1071",
}

FP_INDICATORS = [
    ("vulnerability scanner", "Known vulnerability scanner activity"),
    ("nessus", "Nessus scan traffic"),
    ("qualys", "Qualys scan traffic"),
    ("rapid7", "Rapid7 scan traffic"),
    ("nuclei", "Nuclei scan - if authorized"),
    ("internal monitoring", "Internal monitoring system"),
    ("health check", "Health check request"),
    ("load balancer", "Load balancer health check"),
    ("backup", "Backup system activity"),
]


class AlertTriage:
    """Alert triage and prioritization engine.

    Provides:
        - Priority scoring based on severity, MITRE, and context
        - False positive detection with known-benign patterns
        - Alert grouping and correlation
        - Recommended actions per priority level

    Example:
        triage = AlertTriage()
        result = triage.triage_alert(alert)
        results = triage.triage_batch(alerts)
    """

    def __init__(self, fp_threshold: float = 0.7):
        self.fp_threshold = fp_threshold
        self._triaged: List[TriagedAlert] = []
        self._fp_history: Dict[str, int] = {}

    def triage_alert(self, alert: SIEMAlert) -> TriagedAlert:
        """Triage a single alert."""
        score = self._calculate_score(alert)
        priority = self._score_to_priority(score)
        is_fp, fp_reason = self._check_false_positive(alert)
        action = self._recommend_action(priority, is_fp, alert)
        related = self._find_related(alert)

        if is_fp:
            score *= 0.1
            priority = self._score_to_priority(score)

        triaged = TriagedAlert(
            alert=alert,
            priority_score=score,
            priority_level=priority,
            is_false_positive=is_fp,
            fp_reason=fp_reason,
            recommended_action=action,
            related_alerts=related,
            triaged_at=datetime.utcnow().isoformat(),
        )

        self._triaged.append(triaged)
        return triaged

    def triage_batch(self, alerts: List[SIEMAlert]) -> List[TriagedAlert]:
        """Triage multiple alerts and sort by priority."""
        results = [self.triage_alert(a) for a in alerts]
        results.sort(key=lambda t: t.priority_score, reverse=True)
        return results

    def _calculate_score(self, alert: SIEMAlert) -> float:
        """Calculate priority score for an alert."""
        score = SEVERITY_WEIGHTS.get(alert.severity, 10)

        if alert.mitre_techniques:
            for tech in alert.mitre_techniques:
                if tech in MITRE_HIGH_PRIORITY:
                    score += 15
                else:
                    score += 5

        if alert.status == "new":
            score += 5

        if alert.related_events and len(alert.related_events) > 3:
            score += 10

        if alert.metadata:
            if alert.metadata.get("rule_id"):
                rule_id = alert.metadata["rule_id"]
                fp_count = self._fp_history.get(rule_id, 0)
                if fp_count > 5:
                    score -= min(fp_count * 2, 20)

        return min(score, 100.0)

    def _score_to_priority(self, score: float) -> str:
        if score >= 70:
            return "P1"
        elif score >= 50:
            return "P2"
        elif score >= 30:
            return "P3"
        else:
            return "P4"

    def _check_false_positive(self, alert: SIEMAlert) -> tuple:
        """Check if an alert is likely a false positive."""
        check_text = f"{alert.title} {alert.description} {alert.metadata}".lower()

        for indicator, reason in FP_INDICATORS:
            if indicator in check_text:
                return True, reason

        if alert.metadata:
            source = str(alert.metadata.get("source_ip", "")).lower()
            known_scanners = {"10.0.0.100", "10.0.0.101", "192.168.1.50"}
            if source in known_scanners:
                return True, "Known scanner IP address"

        return False, None

    def _recommend_action(
        self,
        priority: str,
        is_fp: bool,
        alert: SIEMAlert,
    ) -> str:
        """Generate recommended action for an alert."""
        if is_fp:
            return "Suppress - likely false positive. Consider tuning detection rule."

        actions = {
            "P1": "Immediate response required. Escalate to IR team. Initiate containment.",
            "P2": "High priority investigation. Assign analyst within 15 minutes.",
            "P3": "Standard investigation. Review within 1 hour.",
            "P4": "Low priority. Monitor for pattern escalation.",
        }
        return actions.get(priority, "Review alert.")

    def _find_related(self, alert: SIEMAlert) -> List[str]:
        """Find related alerts in triaged history."""
        related: List[str] = []

        for triaged in self._triaged:
            if triaged.alert.alert_id == alert.alert_id:
                continue

            if alert.mitre_techniques and triaged.alert.mitre_techniques:
                if set(alert.mitre_techniques) & set(triaged.alert.mitre_techniques):
                    related.append(triaged.alert.alert_id)
                    continue

            if alert.metadata and triaged.alert.metadata:
                src1 = alert.metadata.get("source_ip")
                src2 = triaged.alert.metadata.get("source_ip")
                if src1 and src2 and src1 == src2:
                    related.append(triaged.alert.alert_id)

        return related

    def mark_false_positive(self, alert_id: str, reason: str = "") -> bool:
        """Manually mark an alert as false positive."""
        for triaged in self._triaged:
            if triaged.alert.alert_id == alert_id:
                triaged.is_false_positive = True
                triaged.fp_reason = reason or "Manually marked as FP"
                triaged.priority_score *= 0.1
                triaged.priority_level = self._score_to_priority(triaged.priority_score)

                rule_id = triaged.alert.metadata.get("rule_id", "")
                if rule_id:
                    self._fp_history[rule_id] = self._fp_history.get(rule_id, 0) + 1

                return True
        return False

    def get_triaged(
        self,
        priority: Optional[str] = None,
        exclude_fp: bool = True,
        limit: int = 50,
    ) -> List[TriagedAlert]:
        """Get triaged alerts filtered by priority."""
        results = self._triaged

        if exclude_fp:
            results = [t for t in results if not t.is_false_positive]

        if priority:
            results = [t for t in results if t.priority_level == priority]

        results.sort(key=lambda t: t.priority_score, reverse=True)
        return results[:limit]

    def get_stats(self) -> Dict[str, Any]:
        priority_counts: Dict[str, int] = {}
        fp_count = 0

        for t in self._triaged:
            priority_counts[t.priority_level] = priority_counts.get(t.priority_level, 0) + 1
            if t.is_false_positive:
                fp_count += 1

        return {
            "total_triaged": len(self._triaged),
            "by_priority": priority_counts,
            "false_positives": fp_count,
            "fp_rate": (fp_count / len(self._triaged) * 100) if self._triaged else 0,
            "p1_alerts": priority_counts.get("P1", 0),
            "p2_alerts": priority_counts.get("P2", 0),
        }

    def subscribe_to_event_bus(
        self,
        bus: Any,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> None:
        """Subscribe alert triage to blue team alert events on the shared event bus.

        Args:
            bus: The shared :class:`EventBus`.
            tenant_id: Tenant scope for events to process.
            exercise_id: Optional exercise identifier (unused, kept for API symmetry).
        """
        from vorsyghta.core.event_bus import EventBus

        if not isinstance(bus, EventBus):
            raise TypeError("bus must be an EventBus instance")

        def _handler(event: BusEvent) -> None:
            if event.tenant_id != tenant_id:
                return
            if event.event_type != EventType.BLUE_TEAM_ALERT:
                return

            payload = event.payload
            raw_data = payload.get("raw_data", {})
            alert = SIEMAlert(
                alert_id=payload.get("alert_id", ""),
                title=raw_data.get("title", "Blue team alert"),
                severity=payload.get("severity", "medium"),
                status="new",
                created_at=datetime.utcnow().isoformat(),
                description=payload.get("description", ""),
                source=payload.get("source_module", "blue_team"),
                mitre_techniques=[payload.get("technique_id", "")] if payload.get("technique_id") else [],
                related_events=[],
                metadata=raw_data.get("metadata", {}),
            )
            self.triage_alert(alert)

        bus.subscribe(EventType.BLUE_TEAM_ALERT, _handler)
