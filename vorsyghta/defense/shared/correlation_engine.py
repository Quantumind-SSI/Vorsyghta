"""Correlation engine for matching attacks to detections.

Matches red team attack events with blue team detection events
based on MITRE ATT&CK techniques, time windows, and metadata.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from .attack_timeline import AttackTimeline, AttackEvent
from .detection_timeline import DetectionTimeline, DetectionEvent


@dataclass
class CorrelationResult:
    """Result of correlating an attack event with detections."""
    attack_event: AttackEvent
    matched_detections: List[DetectionEvent] = field(default_factory=list)
    detection_latency: Optional[timedelta] = None
    detected: bool = False
    confidence: float = 0.0

    @property
    def technique_id(self) -> str:
        return self.attack_event.technique_id

    @property
    def latency_seconds(self) -> Optional[float]:
        if self.detection_latency:
            return self.detection_latency.total_seconds()
        return None


class CorrelationEngine:
    """Correlates attack events with detection events.

    Uses MITRE ATT&CK technique matching and configurable time windows
    to determine which attacks were detected by the blue team.
    """

    def __init__(self, time_window: int = 300):
        """Initialize the correlation engine.

        Args:
            time_window: Maximum seconds between attack and detection to consider a match
        """
        self.time_window = timedelta(seconds=time_window)

    def correlate(
        self,
        attack_timeline: AttackTimeline,
        detection_timeline: DetectionTimeline,
    ) -> List[CorrelationResult]:
        """Correlate attack and detection timelines.

        Args:
            attack_timeline: Timeline of attack events
            detection_timeline: Timeline of detection events

        Returns:
            List of CorrelationResult for each attack event
        """
        results: List[CorrelationResult] = []

        for attack in attack_timeline.events:
            result = CorrelationResult(attack_event=attack)
            matched: List[DetectionEvent] = []

            for detection in detection_timeline.events:
                if self._is_match(attack, detection):
                    matched.append(detection)

            if matched:
                result.matched_detections = matched
                result.detected = True
                earliest = min(d.timestamp for d in matched)
                result.detection_latency = earliest - attack.timestamp
                result.confidence = sum(d.confidence for d in matched) / len(matched)

            results.append(result)

        return results

    def _is_match(self, attack: AttackEvent, detection: DetectionEvent) -> bool:
        """Check if an attack and detection event correlate."""
        if detection.mitre_technique and attack.technique_id:
            if detection.mitre_technique != attack.technique_id:
                return False
        else:
            return False

        time_diff = detection.timestamp - attack.timestamp
        if time_diff < timedelta(0) or time_diff > self.time_window:
            return False

        return True

    def generate_coverage_report(
        self, results: List[CorrelationResult]
    ) -> Dict[str, any]:
        """Generate a detection coverage report from correlation results.

        Returns:
            Dict with coverage metrics including MTTD, coverage percentage,
            per-technique breakdown, and gaps.
        """
        total = len(results)
        detected = sum(1 for r in results if r.detected)

        latencies = [
            r.latency_seconds for r in results
            if r.detected and r.latency_seconds is not None
        ]
        mttd = sum(latencies) / len(latencies) if latencies else None

        per_technique: Dict[str, Dict[str, any]] = {}
        for r in results:
            tid = r.technique_id
            if tid not in per_technique:
                per_technique[tid] = {"total": 0, "detected": 0, "latencies": []}
            per_technique[tid]["total"] += 1
            if r.detected:
                per_technique[tid]["detected"] += 1
                if r.latency_seconds is not None:
                    per_technique[tid]["latencies"].append(r.latency_seconds)

        gaps = [
            {
                "technique_id": tid,
                "missed_count": d["total"] - d["detected"],
            }
            for tid, d in per_technique.items()
            if d["detected"] < d["total"]
        ]

        return {
            "total_attacks": total,
            "detected_attacks": detected,
            "coverage_percentage": (detected / total * 100) if total > 0 else 0,
            "mttd_seconds": mttd,
            "per_technique": {
                tid: {
                    "total": d["total"],
                    "detected": d["detected"],
                    "coverage": d["detected"] / d["total"] * 100 if d["total"] > 0 else 0,
                    "avg_latency": sum(d["latencies"]) / len(d["latencies"]) if d["latencies"] else None,
                }
                for tid, d in per_technique.items()
            },
            "detection_gaps": gaps,
        }
