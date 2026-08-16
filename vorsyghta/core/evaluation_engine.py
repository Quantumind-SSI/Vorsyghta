"""Build Black Team — evaluation, benchmarking, and reporting.

The Black Team is responsible for non-interfering observation, performance
scoring, and post-exercise reporting. It scores exercises by comparing Red
Team actions against Blue Team detections and the Purple Team AAR.

Owner: DevRel — Developer Relations
Phase 3 — Black Team evaluation engine
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class EvaluationEngine:
    """Score color-team exercises from the Black Team observer perspective."""

    def __init__(self) -> None:
        self._score_weights = {
            "red_team_execution": 0.25,
            "blue_team_detection": 0.35,
            "purple_team_aar": 0.25,
            "operational_security": 0.15,
        }

    def score_exercise(
        self,
        red_team_stages: List[Dict[str, Any]],
        blue_team_alerts: List[Dict[str, Any]],
        aar: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Score a completed exercise.

        Args:
            red_team_stages: Red Team attack stage event dictionaries.
            blue_team_alerts: Blue Team alert event dictionaries.
            aar: Optional Purple Team after-action report dictionary.

        Returns:
            Structured score card with component scores and overall score.
        """
        def _payload(item: Dict[str, Any]) -> Dict[str, Any]:
            return item.get("payload", item)

        red_count = len(red_team_stages)
        alert_count = len(blue_team_alerts)

        detected_alerts = [a for a in blue_team_alerts if _payload(a).get("detected")]
        missed_alerts = [a for a in blue_team_alerts if not _payload(a).get("detected")]
        detection_count = len(detected_alerts)
        miss_count = len(missed_alerts)

        # Red team execution score: more stages = higher execution fidelity
        red_score = min(1.0, red_count / 5.0) if red_count > 0 else 0.0

        # Blue team detection score: detected / total alerts
        detection_score = detection_count / alert_count if alert_count > 0 else 0.0

        # Purple team AAR score: presence of structured findings and recommendations
        aar_score = 0.0
        if aar and isinstance(aar, dict):
            if aar.get("coverage_gaps") or aar.get("key_findings"):
                aar_score += 0.5
            if aar.get("remediation_recommendations") or aar.get("recommendations"):
                aar_score += 0.3
            metrics = aar.get("detection_metrics", aar.get("blue_team_summary", {}))
            if metrics.get("detection_rate_pct") is not None or metrics.get("detection_rate") is not None:
                aar_score += 0.2
            aar_score = min(1.0, aar_score)

        # Operational security: penalty for missed detections
        ops_score = max(0.0, 1.0 - (miss_count / alert_count)) if alert_count > 0 else 1.0

        weights = self._score_weights
        overall = round(
            red_score * weights["red_team_execution"]
            + detection_score * weights["blue_team_detection"]
            + aar_score * weights["purple_team_aar"]
            + ops_score * weights["operational_security"],
            4,
        )

        scorecard = {
            "overall_score": overall,
            "component_scores": {
                "red_team_execution": round(red_score, 4),
                "blue_team_detection": round(detection_score, 4),
                "purple_team_aar": round(aar_score, 4),
                "operational_security": round(ops_score, 4),
            },
            "weights": weights,
            "metrics": {
                "red_team_stages": red_count,
                "blue_team_alerts": alert_count,
                "detected": detection_count,
                "missed": miss_count,
                "detection_rate": round(detection_count / alert_count, 4) if alert_count > 0 else 0.0,
            },
            "rating": self._rating(overall),
            "recommendations": self._recommendations(
                red_score, detection_score, aar_score, ops_score
            ),
        }

        logger.info(
            "Exercise scored: overall=%.4f, red=%.4f, blue=%.4f, purple=%.4f, ops=%.4f",
            overall, red_score, detection_score, aar_score, ops_score,
        )
        return scorecard

    def _rating(self, overall: float) -> str:
        if overall >= 0.9:
            return "A"
        if overall >= 0.8:
            return "B"
        if overall >= 0.7:
            return "C"
        if overall >= 0.6:
            return "D"
        return "F"

    def _recommendations(
        self,
        red_score: float,
        detection_score: float,
        aar_score: float,
        ops_score: float,
    ) -> List[str]:
        recs = []
        if red_score < 0.7:
            recs.append("Expand Red Team attack chain coverage to exercise more MITRE ATT&CK techniques.")
        if detection_score < 0.7:
            recs.append("Improve Blue Team detection coverage and reduce missed alerts.")
        if aar_score < 0.7:
            recs.append("Strengthen Purple Team AAR structure with actionable findings and recommendations.")
        if ops_score < 0.7:
            recs.append("Reduce operational friction and false negatives during exercise execution.")
        if not recs:
            recs.append("Strong performance across all teams; maintain current runbooks and consider advanced scenarios.")
        return recs
