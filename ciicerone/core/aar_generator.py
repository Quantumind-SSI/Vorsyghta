"""After-Action Report (AAR) generator for Ciicerone Purple Team.

The AARGenerator consumes red team attack events and blue team detection
events to produce a structured after-action report with:
- Detection coverage (which attacks were detected vs missed)
- MITRE technique coverage gap analysis
- Prioritized remediation recommendations
- Response time metrics

Owner: Lanre Shittu (@Shizoqua) — ML/AI Lead
Phase 2 — Purple Team AAR
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


class AARGenerator:
    """Generates after-action reports for color-team exercises.

    Args:
        llm_provider: Optional LLM provider for AI-enhanced recommendations.
                      If None, uses rule-based recommendations.
    """

    def __init__(self, llm_provider: Optional[Any] = None) -> None:
        self.llm_provider = llm_provider

    async def generate_aar(
        self,
        exercise_id: str,
        red_team_stages: List[Dict[str, Any]],
        blue_team_alerts: List[Dict[str, Any]],
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """Generate an after-action report.

        Args:
            exercise_id: ID of the exercise
            red_team_stages: List of red team attack stage event dicts
            blue_team_alerts: List of blue team alert event dicts
            tenant_id: Tenant scope

        Returns:
            Structured AAR dictionary
        """
        aar_id = str(uuid4())
        generated_at = datetime.now(timezone.utc).isoformat()

        detection_metrics = self._compute_detection_metrics(red_team_stages, blue_team_alerts)
        coverage_gaps = self._identify_coverage_gaps(red_team_stages, blue_team_alerts)
        remediations = self._generate_remediation_recommendations(coverage_gaps)
        response_times = self._compute_response_times(red_team_stages, blue_team_alerts)

        aar = {
            "aar_id": aar_id,
            "exercise_id": exercise_id,
            "tenant_id": tenant_id,
            "generated_at": generated_at,
            "summary": self._generate_summary(detection_metrics, coverage_gaps),
            "detection_metrics": detection_metrics,
            "coverage_gaps": coverage_gaps,
            "remediation_recommendations": remediations,
            "response_time_metrics": response_times,
            "mitre_coverage": self._compute_mitre_coverage(red_team_stages, blue_team_alerts),
        }

        logger.info(
            "AAR generated: exercise=%s, detection_rate=%.1f%%, gaps=%d, remediations=%d",
            exercise_id,
            detection_metrics.get("detection_rate_pct", 0),
            len(coverage_gaps),
            len(remediations),
        )

        return aar

    def _compute_detection_metrics(
        self,
        red_stages: List[Dict[str, Any]],
        blue_alerts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        total_stages = len(red_stages)
        if total_stages == 0:
            return {"total_attacks": 0, "detected": 0, "missed": 0, "detection_rate_pct": 0.0}

        detected_stage_ids: set = set()
        for alert in blue_alerts:
            payload = alert.get("payload", alert)
            if payload.get("detected", False):
                stage_id = payload.get("stage_id")
                if stage_id:
                    detected_stage_ids.add(stage_id)

        detected = sum(
            1 for s in red_stages
            if (s.get("payload", s)).get("stage_id") in detected_stage_ids
        )
        missed = total_stages - detected

        return {
            "total_attacks": total_stages,
            "detected": detected,
            "missed": missed,
            "detection_rate_pct": round(detected / total_stages * 100, 1),
            "missed_rate_pct": round(missed / total_stages * 100, 1),
            "total_alerts_generated": len(blue_alerts),
        }

    def _identify_coverage_gaps(
        self,
        red_stages: List[Dict[str, Any]],
        blue_alerts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        detected_techniques: set = set()
        for alert in blue_alerts:
            payload = alert.get("payload", alert)
            if payload.get("detected", False):
                tech_id = payload.get("technique_id")
                if tech_id:
                    detected_techniques.add(tech_id)

        gaps = []
        seen_techniques: set = set()
        for stage in red_stages:
            payload = stage.get("payload", stage)
            tech_id = payload.get("technique_id", "T0000")
            if tech_id in seen_techniques:
                continue
            seen_techniques.add(tech_id)

            if tech_id not in detected_techniques:
                gaps.append({
                    "technique_id": tech_id,
                    "tactic": payload.get("tactic", "unknown"),
                    "stage_name": payload.get("stage_name", "unknown"),
                    "severity": "high",
                })

        return gaps

    def _generate_remediation_recommendations(
        self, coverage_gaps: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        technique_controls = {
            "T1566": "Deploy advanced email filtering with sandbox detonation for all attachments.",
            "T1059": "Enable PowerShell script block logging; deploy EDR with command-line monitoring.",
            "T1078": "Enforce MFA on all privileged accounts; implement just-in-time access.",
            "T1003": "Deploy credential guard; restrict LSASS access; monitor for suspicious memory reads.",
            "T1486": "Implement immutable backups; enable ransomware detection in EDR.",
            "T1021": "Restrict lateral movement with network segmentation; monitor RDP/SMB access.",
            "T1190": "Patch all internet-facing systems; deploy WAF with OWASP ruleset.",
            "T1071": "Implement DNS monitoring; deploy SSL inspection at perimeter.",
            "T1027": "Deploy behavior-based AV/EDR; implement AMSI for script scanning.",
            "T1110": "Implement account lockout policies; enable MFA; monitor failed logins.",
        }

        remediations = []
        for i, gap in enumerate(coverage_gaps):
            tech_id = gap["technique_id"]
            recommendation = technique_controls.get(
                tech_id,
                f"Implement detection rules for {tech_id}; review SIEM/IDS/EDR coverage.",
            )
            remediations.append({
                "priority": i + 1,
                "technique_id": tech_id,
                "tactic": gap.get("tactic", "unknown"),
                "finding": f"No detection coverage for {tech_id} ({gap.get('stage_name', 'unknown')})",
                "recommendation": recommendation,
                "effort": "medium",
                "impact": "high",
            })

        return remediations

    def _compute_response_times(
        self,
        red_stages: List[Dict[str, Any]],
        blue_alerts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        response_times_ms = [
            alert.get("payload", alert).get("response_time_ms")
            for alert in blue_alerts
            if alert.get("payload", alert).get("response_time_ms") is not None
        ]

        if not response_times_ms:
            return {"mean_response_time_ms": None, "max_response_time_ms": None, "samples": 0}

        return {
            "mean_response_time_ms": round(sum(response_times_ms) / len(response_times_ms)),
            "max_response_time_ms": max(response_times_ms),
            "min_response_time_ms": min(response_times_ms),
            "samples": len(response_times_ms),
        }

    def _compute_mitre_coverage(
        self,
        red_stages: List[Dict[str, Any]],
        blue_alerts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        attacked: Dict[str, Dict] = {}
        for stage in red_stages:
            payload = stage.get("payload", stage)
            tech_id = payload.get("technique_id", "T0000")
            attacked[tech_id] = {
                "technique_id": tech_id,
                "tactic": payload.get("tactic", "unknown"),
                "detected": False,
            }

        for alert in blue_alerts:
            payload = alert.get("payload", alert)
            if payload.get("detected", False):
                tech_id = payload.get("technique_id")
                if tech_id and tech_id in attacked:
                    attacked[tech_id]["detected"] = True

        return {
            "techniques_attacked": list(attacked.values()),
            "total_techniques": len(attacked),
            "techniques_detected": sum(1 for t in attacked.values() if t["detected"]),
        }

    def _generate_summary(
        self,
        detection_metrics: Dict[str, Any],
        coverage_gaps: List[Dict[str, Any]],
    ) -> str:
        rate = detection_metrics.get("detection_rate_pct", 0)
        total = detection_metrics.get("total_attacks", 0)
        detected = detection_metrics.get("detected", 0)
        missed = detection_metrics.get("missed", 0)

        if total == 0:
            return "No attack stages were simulated in this exercise."

        level = "strong" if rate >= 80 else "moderate" if rate >= 50 else "weak"

        return (
            f"The exercise simulated {total} attack stage(s). "
            f"The blue team detected {detected} ({rate}%), missing {missed}. "
            f"Overall detection posture is {level}. "
            f"There are {len(coverage_gaps)} MITRE technique coverage gap(s) "
            f"requiring remediation."
        )
