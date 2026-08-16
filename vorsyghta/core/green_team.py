"""Green Team — training and awareness engine for Vorsyghta.

The Green Team is responsible for translating Purple Team after-action report
(AAR) findings and Black Team evaluation scores into actionable training
programs. It performs training needs analysis, generates structured training
plans, assesses organizational security awareness, and tracks training
effectiveness over time.

Responsibilities:
- Training needs analysis from AAR coverage gaps and failed detections
- Training module assignment mapped to MITRE ATT&CK technique gaps
- Awareness assessment scoring (0-100) with maturity levels
- Structured training plan generation with timelines and target audiences
- Effectiveness tracking across historical exercise scores
- Event bus integration to auto-generate training recommendations from AARs

Owner: Green Team Lead
Phase 3 — Green Team training & awareness
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from vorsyghta.core.event_bus import EventBus
from vorsyghta.core.event_types import (
    BusEvent,
    EventType,
    GreenTeamTrainingAssignedEvent,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Training module catalog
# ---------------------------------------------------------------------------

#: Mapping of MITRE ATT&CK technique IDs to structured training module
#: definitions. Each module describes the audience, delivery method, and
#: priority that the Green Team uses when building training plans.
TRAINING_MODULE_CATALOG: Dict[str, Dict[str, Any]] = {
    "T1566": {
        "module_id": "GT-PHISH-001",
        "name": "Phishing Recognition and Response",
        "description": (
            "Train staff to recognize phishing lures, report suspicious "
            "emails, and execute the organizational phishing response "
            "playbook."
        ),
        "target_roles": ["all_staff", "soc_analysts", "helpdesk"],
        "duration_hours": 2,
        "delivery_method": "elearning",
        "priority": "high",
    },
    "T1059": {
        "module_id": "GT-PSH-002",
        "name": "PowerShell Security and Monitoring",
        "description": (
            "Covers PowerShell script block logging, constrained language "
            "mode, AMSI integration, and EDR command-line monitoring for "
            "malicious script execution."
        ),
        "target_roles": ["soc_analysts", "system_administrators", "ir_engineers"],
        "duration_hours": 4,
        "delivery_method": "workshop",
        "priority": "high",
    },
    "T1078": {
        "module_id": "GT-IAM-003",
        "name": "Identity and Access Management Best Practices",
        "description": (
            "Enforce MFA, just-in-time access, privileged access management, "
            "and account lifecycle reviews to reduce valid-account abuse."
        ),
        "target_roles": ["system_administrators", "security_engineers", "it_managers"],
        "duration_hours": 3,
        "delivery_method": "workshop",
        "priority": "high",
    },
    "T1003": {
        "module_id": "GT-CRED-004",
        "name": "Credential Protection and LSASS Security",
        "description": (
            "Deploy Credential Guard, restrict LSASS access, detect LSASS "
            "memory reads, and protect the SAM/NTDS credential stores."
        ),
        "target_roles": ["security_engineers", "system_administrators", "ir_engineers"],
        "duration_hours": 4,
        "delivery_method": "workshop",
        "priority": "critical",
    },
    "T1486": {
        "module_id": "GT-RANS-005",
        "name": "Ransomware Prevention and Response",
        "description": (
            "Immutable backup strategy, EDR ransomware detection, isolation "
            "playbooks, and tabletop rehearsal of ransomware incident "
            "response."
        ),
        "target_roles": ["ir_engineers", "soc_analysts", "it_managers", "executives"],
        "duration_hours": 6,
        "delivery_method": "tabletop",
        "priority": "critical",
    },
    "T1021": {
        "module_id": "GT-LAT-006",
        "name": "Lateral Movement Detection and Prevention",
        "description": (
            "Network segmentation, RDP/SMB/WinRM monitoring, east-west "
            "traffic analytics, and honeypot deployment for lateral "
            "movement detection."
        ),
        "target_roles": ["soc_analysts", "network_engineers", "security_engineers"],
        "duration_hours": 4,
        "delivery_method": "workshop",
        "priority": "high",
    },
    "T1190": {
        "module_id": "GT-WEB-007",
        "name": "Web Application Security Fundamentals",
        "description": (
            "OWASP Top 10 awareness, WAF tuning, secure coding practices, "
            "and patch management for internet-facing systems."
        ),
        "target_roles": ["developers", "security_engineers", "devops_engineers"],
        "duration_hours": 5,
        "delivery_method": "elearning",
        "priority": "high",
    },
    "T1110": {
        "module_id": "GT-PWD-008",
        "name": "Password Security and Account Lockout Policies",
        "description": (
            "Password strength standards, account lockout configuration, "
            "MFA enforcement, and monitoring of brute-force login patterns."
        ),
        "target_roles": ["all_staff", "system_administrators", "helpdesk"],
        "duration_hours": 2,
        "delivery_method": "elearning",
        "priority": "medium",
    },
}

#: Fallback training module used when a MITRE technique gap has no dedicated
#: catalog entry. Ensures every identified gap produces a recommendation.
_GENERIC_TRAINING_MODULE: Dict[str, Any] = {
    "module_id": "GT-GEN-000",
    "name": "Threat Detection Fundamentals",
    "description": (
        "General security awareness and detection fundamentals covering "
        "common attacker techniques and organizational reporting procedures."
    ),
    "target_roles": ["soc_analysts", "security_engineers"],
    "duration_hours": 3,
    "delivery_method": "elearning",
    "priority": "medium",
}

#: Awareness maturity levels keyed by score band lower-bound.
_AWARENESS_LEVELS: List[Dict[str, Any]] = [
    {"min": 80, "level": "expert", "description": "Mature, proactive security awareness program."},
    {"min": 60, "level": "proficient", "description": "Solid awareness with room for targeted improvement."},
    {"min": 30, "level": "developing", "description": "Foundational awareness being established; significant gaps remain."},
    {"min": 0, "level": "novice", "description": "Minimal security awareness; organization-wide training required."},
]

#: Weights applied to each component of the awareness score (sum to 1.0).
_AWARENESS_WEIGHTS = {
    "detection_rate": 0.40,
    "response_time": 0.25,
    "coverage_gaps": 0.25,
    "training_history": 0.10,
}

#: Mapping from module priority to a relative scheduling offset (in days)
#: from the training plan start date. Critical modules are scheduled first.
_PRIORITY_SCHEDULE_OFFSET_DAYS = {
    "critical": 0,
    "high": 7,
    "medium": 14,
    "low": 30,
}

#: Numeric weight used when ranking modules for prioritized assignment.
_PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class TrainingAwarenessEngine:
    """Green Team engine for training needs analysis, planning, and awareness.

    The engine consumes Purple Team AAR outputs and Black Team evaluation
    scores to identify coverage gaps, map them to training modules, and
    produce structured, role-targeted training plans. It also assesses the
    organization's security awareness maturity and tracks training
    effectiveness across historical exercise scores.

    Args:
        llm_provider: Optional LLM provider for AI-enhanced training
            recommendations. If ``None``, rule-based recommendations from
            the module catalog are used.
    """

    def __init__(self, llm_provider: Optional[Any] = None) -> None:
        self.llm_provider = llm_provider
        self.module_catalog: Dict[str, Dict[str, Any]] = dict(TRAINING_MODULE_CATALOG)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_training_needs(
        self,
        aar: Dict[str, Any],
        score: Dict[str, Any],
        red_team_stages: List[Dict[str, Any]],
        blue_team_alerts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Analyze AAR coverage gaps and detection failures for training needs.

        Cross-references the Purple Team AAR coverage gaps, the Black Team
        evaluation score, and the raw red/blue team events to produce a
        structured training needs assessment.

        Args:
            aar: Purple Team after-action report dictionary. Expected to
                contain ``coverage_gaps``, ``detection_metrics``, and
                ``mitre_coverage`` keys.
            score: Black Team evaluation scorecard. Expected to contain
                ``overall_score`` and ``component_scores``.
            red_team_stages: Red Team attack stage event dictionaries.
            blue_team_alerts: Blue Team alert event dictionaries.

        Returns:
            Structured training needs assessment dictionary with keys:
            ``needs_id``, ``generated_at``, ``coverage_gaps``,
            ``failed_detections``, ``training_modules``, ``priority_needs``,
            ``score_context``, and ``summary``.
        """
        coverage_gaps = aar.get("coverage_gaps", []) if aar else []
        detection_metrics = aar.get("detection_metrics", {}) if aar else {}
        mitre_coverage = aar.get("mitre_coverage", {}) if aar else {}

        failed_detections = self._identify_failed_detections(
            red_team_stages, blue_team_alerts
        )
        training_modules = self.generate_training_modules(coverage_gaps)
        priority_needs = self._prioritize_needs(
            coverage_gaps, failed_detections, training_modules, score
        )

        overall_score = score.get("overall_score", 0.0) if score else 0.0
        component_scores = score.get("component_scores", {}) if score else {}

        summary = self._build_needs_summary(
            coverage_gaps, failed_detections, training_modules, overall_score
        )

        needs = {
            "needs_id": str(uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "coverage_gaps": coverage_gaps,
            "failed_detections": failed_detections,
            "training_modules": training_modules,
            "priority_needs": priority_needs,
            "score_context": {
                "overall_score": overall_score,
                "component_scores": component_scores,
                "detection_rate_pct": detection_metrics.get("detection_rate_pct", 0.0),
                "mitre_techniques_attacked": mitre_coverage.get("total_techniques", 0),
                "mitre_techniques_detected": mitre_coverage.get("techniques_detected", 0),
            },
            "summary": summary,
        }

        logger.info(
            "Training needs analyzed: gaps=%d, failed_detections=%d, modules=%d, priority_needs=%d",
            len(coverage_gaps),
            len(failed_detections),
            len(training_modules),
            len(priority_needs),
        )
        return needs

    def generate_training_plan(
        self,
        training_needs: Dict[str, Any],
        tenant_id: str,
    ) -> Dict[str, Any]:
        """Create a structured training plan from identified training needs.

        Args:
            training_needs: Output of :meth:`analyze_training_needs`.
            tenant_id: Tenant scope for the training plan.

        Returns:
            Structured training plan dictionary with keys: ``plan_id``,
            ``tenant_id``, ``created_at``, ``modules``, ``timeline``,
            ``target_roles``, ``total_duration_hours``, ``priority_distribution``,
            and ``summary``.
        """
        plan_id = str(uuid4())
        created_at = datetime.now(timezone.utc)
        modules = training_needs.get("training_modules", [])
        priority_needs = training_needs.get("priority_needs", [])

        # Build scheduled module entries with staggered start dates based on priority.
        scheduled_modules: List[Dict[str, Any]] = []
        target_roles: set = set()
        total_duration_hours = 0
        priority_distribution: Dict[str, int] = {}

        # Order modules by priority rank then by module_id for determinism.
        ordered_modules = sorted(
            modules,
            key=lambda m: (
                _PRIORITY_RANK.get(m.get("priority", "medium"), 2),
                m.get("module_id", ""),
            ),
        )

        for module in ordered_modules:
            offset_days = _PRIORITY_SCHEDULE_OFFSET_DAYS.get(
                module.get("priority", "medium"), 14
            )
            start = created_at + timedelta(days=offset_days)
            end = start + timedelta(hours=module.get("duration_hours", 0))

            for role in module.get("target_roles", []):
                target_roles.add(role)

            total_duration_hours += module.get("duration_hours", 0)
            priority = module.get("priority", "medium")
            priority_distribution[priority] = priority_distribution.get(priority, 0) + 1

            scheduled_modules.append({
                "module_id": module.get("module_id"),
                "name": module.get("name"),
                "technique_id": module.get("technique_id"),
                "target_roles": module.get("target_roles", []),
                "delivery_method": module.get("delivery_method"),
                "duration_hours": module.get("duration_hours", 0),
                "priority": priority,
                "start_date": start.isoformat(),
                "end_date": end.isoformat(),
            })

        timeline = self._build_timeline(scheduled_modules)

        summary = (
            f"Training plan {plan_id} for tenant '{tenant_id}' schedules "
            f"{len(scheduled_modules)} module(s) totaling "
            f"{total_duration_hours} hour(s) across "
            f"{len(target_roles)} target role(s)."
        )

        plan = {
            "plan_id": plan_id,
            "tenant_id": tenant_id,
            "created_at": created_at.isoformat(),
            "based_on_needs_id": training_needs.get("needs_id"),
            "modules": scheduled_modules,
            "timeline": timeline,
            "target_roles": sorted(target_roles),
            "total_duration_hours": total_duration_hours,
            "priority_distribution": priority_distribution,
            "priority_needs": priority_needs,
            "summary": summary,
        }

        logger.info(
            "Training plan generated: plan=%s tenant=%s modules=%d duration=%dh",
            plan_id, tenant_id, len(scheduled_modules), total_duration_hours,
        )
        return plan

    def assess_awareness_level(
        self,
        blue_team_alerts: List[Dict[str, Any]],
        red_team_stages: List[Dict[str, Any]],
        coverage_gaps: Optional[List[Dict[str, Any]]] = None,
        training_history: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Assess the organization's security awareness level.

        Computes an awareness score (0-100) from detection rate, response
        time, coverage gaps, and training history, then maps the score to a
        maturity level.

        Args:
            blue_team_alerts: Blue Team alert event dictionaries.
            red_team_stages: Red Team attack stage event dictionaries.
            coverage_gaps: Optional AAR coverage gaps. If omitted, gaps are
                derived from the red/blue events.
            training_history: Optional list of prior training completion
                records, each with a ``completion_pct`` (0-100) field.

        Returns:
            Awareness assessment dictionary with keys: ``assessment_id``,
            ``assessed_at``, ``score``, ``level``, ``level_description``,
            ``components``, and ``recommendations``.
        """
        detection_component = self._score_detection_rate(blue_team_alerts, red_team_stages)
        response_component = self._score_response_time(blue_team_alerts)
        gaps_component = self._score_coverage_gaps(
            coverage_gaps, red_team_stages, blue_team_alerts
        )
        training_component = self._score_training_history(training_history)

        score = round(
            detection_component * _AWARENESS_WEIGHTS["detection_rate"]
            + response_component * _AWARENESS_WEIGHTS["response_time"]
            + gaps_component * _AWARENESS_WEIGHTS["coverage_gaps"]
            + training_component * _AWARENESS_WEIGHTS["training_history"],
            1,
        )
        score = max(0, min(100, score))

        level_info = self._level_for_score(score)
        recommendations = self._awareness_recommendations(score, level_info["level"])

        assessment = {
            "assessment_id": str(uuid4()),
            "assessed_at": datetime.now(timezone.utc).isoformat(),
            "score": score,
            "level": level_info["level"],
            "level_description": level_info["description"],
            "components": {
                "detection_rate": round(detection_component, 1),
                "response_time": round(response_component, 1),
                "coverage_gaps": round(gaps_component, 1),
                "training_history": round(training_component, 1),
            },
            "weights": dict(_AWARENESS_WEIGHTS),
            "recommendations": recommendations,
        }

        logger.info(
            "Awareness assessed: score=%.1f level=%s detection=%.1f response=%.1f gaps=%.1f training=%.1f",
            score,
            level_info["level"],
            detection_component,
            response_component,
            gaps_component,
            training_component,
        )
        return assessment

    def generate_training_modules(
        self, gaps: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Map MITRE technique gaps to specific training modules.

        Args:
            gaps: List of coverage gap dictionaries, each expected to contain
                a ``technique_id``.

        Returns:
            List of training module dictionaries enriched with the
            ``technique_id`` that triggered the recommendation. Unknown
            techniques fall back to the generic fundamentals module.
        """
        modules: List[Dict[str, Any]] = []
        seen_techniques: set = set()

        for gap in gaps:
            tech_id = gap.get("technique_id") or "T0000"
            if tech_id in seen_techniques:
                continue
            seen_techniques.add(tech_id)

            catalog_entry = self.module_catalog.get(tech_id)
            if catalog_entry is None:
                module = dict(_GENERIC_TRAINING_MODULE)
            else:
                module = dict(catalog_entry)

            module["technique_id"] = tech_id
            module["gap_tactic"] = gap.get("tactic", "unknown")
            module["gap_stage_name"] = gap.get("stage_name", "unknown")
            modules.append(module)

        return modules

    def track_training_effectiveness(
        self, historical_scores: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze score trends over time to measure training effectiveness.

        Args:
            historical_scores: Chronologically ordered list of score records.
                Each record may contain ``overall_score`` (0-1 or 0-100),
                ``component_scores``, ``exercise_id``, ``timestamp``, and an
                optional ``training_completed`` flag.

        Returns:
            Effectiveness report dictionary with keys: ``report_id``,
            ``generated_at``, ``sample_count``, ``trend``, ``trend_slope``,
            ``first_score``, ``latest_score``, ``delta``, ``component_trends``,
            ``effectiveness_rating``, and ``recommendations``.
        """
        if not historical_scores:
            return {
                "report_id": str(uuid4()),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "sample_count": 0,
                "trend": "insufficient_data",
                "trend_slope": 0.0,
                "first_score": None,
                "latest_score": None,
                "delta": 0.0,
                "component_trends": {},
                "effectiveness_rating": "unknown",
                "recommendations": [
                    "Collect at least two historical exercise scores to "
                    "measure training effectiveness."
                ],
            }

        normalized = [self._normalize_score_record(s) for s in historical_scores]
        scores = [s["overall_score"] for s in normalized]

        first_score = scores[0]
        latest_score = scores[-1]
        delta = round(latest_score - first_score, 2)
        trend_slope = self._compute_trend_slope(scores)

        if trend_slope > 1.0:
            trend = "improving"
        elif trend_slope < -1.0:
            trend = "declining"
        else:
            trend = "stable"

        component_trends = self._compute_component_trends(normalized)
        effectiveness_rating = self._effectiveness_rating(delta, trend_slope)
        recommendations = self._effectiveness_recommendations(
            trend, delta, trend_slope, component_trends
        )

        report = {
            "report_id": str(uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sample_count": len(historical_scores),
            "trend": trend,
            "trend_slope": round(trend_slope, 3),
            "first_score": round(first_score, 2),
            "latest_score": round(latest_score, 2),
            "delta": delta,
            "component_trends": component_trends,
            "effectiveness_rating": effectiveness_rating,
            "recommendations": recommendations,
        }

        logger.info(
            "Training effectiveness tracked: samples=%d trend=%s delta=%.2f rating=%s",
            len(historical_scores),
            trend,
            delta,
            effectiveness_rating,
        )
        return report

    def subscribe_to_event_bus(
        self,
        bus: EventBus,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> None:
        """Subscribe to PURPLE_TEAM_AAR events to auto-generate training plans.

        When an AAR event is published on the bus for the given tenant, the
        engine analyzes the AAR payload, generates a training plan, and
        publishes ``GreenTeamTrainingAssignedEvent`` events for each
        recommended module.

        Args:
            bus: The shared :class:`EventBus`.
            tenant_id: Tenant scope for events to process.
            exercise_id: Optional exercise identifier to filter on.
        """
        if not isinstance(bus, EventBus):
            raise TypeError("bus must be an EventBus instance")

        async def _handler(event: BusEvent) -> None:
            if event.tenant_id != tenant_id:
                return
            if exercise_id is not None and event.exercise_id != exercise_id:
                return
            if event.event_type != EventType.PURPLE_TEAM_AAR:
                return

            aar_payload = event.payload or {}
            # The AAR event payload may carry the full AAR or a reference.
            aar = aar_payload.get("aar", aar_payload)
            red_stages = aar_payload.get("red_team_stages", [])
            blue_alerts = aar_payload.get("blue_team_alerts", [])
            score = aar_payload.get("score", {})

            try:
                needs = self.analyze_training_needs(
                    aar=aar, score=score,
                    red_team_stages=red_stages,
                    blue_team_alerts=blue_alerts,
                )
                plan = self.generate_training_plan(needs, tenant_id=tenant_id)

                for module in plan.get("modules", []):
                    assignment_id = str(uuid4())
                    based_on_findings = [
                        f"MITRE {module.get('technique_id', 'unknown')} coverage gap",
                    ]
                    await bus.publish(
                        GreenTeamTrainingAssignedEvent(
                            tenant_id=tenant_id,
                            assignment_id=assignment_id,
                            training_module=module.get("name", "unknown"),
                            target_roles=module.get("target_roles", []),
                            priority=module.get("priority", "medium"),
                            based_on_findings=based_on_findings,
                            exercise_id=event.exercise_id,
                        )
                    )

                logger.info(
                    "Green team auto-generated training plan %s from AAR event %s",
                    plan.get("plan_id"),
                    event.event_id,
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "Green team AAR handler failed for event %s: %s",
                    event.event_id,
                    exc,
                    exc_info=True,
                )

        bus.subscribe(EventType.PURPLE_TEAM_AAR, _handler)
        logger.info(
            "Green team subscribed to PURPLE_TEAM_AAR for tenant=%s exercise=%s",
            tenant_id,
            exercise_id,
        )

    # ------------------------------------------------------------------
    # Internal helpers — training needs
    # ------------------------------------------------------------------

    def _identify_failed_detections(
        self,
        red_team_stages: List[Dict[str, Any]],
        blue_team_alerts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Identify red team stages that were not detected by the blue team."""
        detected_stage_ids: set = set()
        for alert in blue_team_alerts:
            payload = alert.get("payload", alert)
            if payload.get("detected", False):
                stage_id = payload.get("stage_id")
                if stage_id:
                    detected_stage_ids.add(stage_id)

        failed: List[Dict[str, Any]] = []
        for stage in red_team_stages:
            payload = stage.get("payload", stage)
            stage_id = payload.get("stage_id")
            if stage_id is None:
                continue
            if stage_id not in detected_stage_ids:
                failed.append({
                    "stage_id": stage_id,
                    "stage_name": payload.get("stage_name", "unknown"),
                    "technique_id": payload.get("technique_id", "T0000"),
                    "tactic": payload.get("tactic", "unknown"),
                })
        return failed

    def _prioritize_needs(
        self,
        coverage_gaps: List[Dict[str, Any]],
        failed_detections: List[Dict[str, Any]],
        training_modules: List[Dict[str, Any]],
        score: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Produce a prioritized list of training needs.

        A need's priority is elevated when the corresponding technique appears
        in both coverage gaps and failed detections, or when the overall
        exercise score is low.
        """
        failed_techniques = {f.get("technique_id") for f in failed_detections}
        overall_score = score.get("overall_score", 1.0) if score else 1.0
        # Normalize: evaluation engine uses 0-1 scores.
        if overall_score and overall_score > 1.0:
            overall_score = overall_score / 100.0

        priority_needs: List[Dict[str, Any]] = []
        for module in training_modules:
            tech_id = module.get("technique_id")
            base_priority = module.get("priority", "medium")

            if tech_id in failed_techniques:
                # Elevate priority when the gap also resulted in a missed detection.
                base_priority = self._elevate_priority(base_priority)

            # Low overall scores elevate all needs by one band.
            if overall_score and overall_score < 0.6:
                base_priority = self._elevate_priority(base_priority)

            priority_needs.append({
                "technique_id": tech_id,
                "module_id": module.get("module_id"),
                "module_name": module.get("name"),
                "priority": base_priority,
                "target_roles": module.get("target_roles", []),
                "delivery_method": module.get("delivery_method"),
                "duration_hours": module.get("duration_hours", 0),
                "reason": self._priority_reason(
                    tech_id, failed_techniques, overall_score
                ),
            })

        priority_needs.sort(
            key=lambda n: (_PRIORITY_RANK.get(n["priority"], 2), n.get("module_id", ""))
        )
        return priority_needs

    @staticmethod
    def _elevate_priority(priority: str) -> str:
        order = ["low", "medium", "high", "critical"]
        try:
            idx = order.index(priority)
        except ValueError:
            return "high"
        return order[min(idx + 1, len(order) - 1)]

    @staticmethod
    def _priority_reason(
        tech_id: Optional[str],
        failed_techniques: set,
        overall_score: float,
    ) -> str:
        reasons: List[str] = []
        if tech_id in failed_techniques:
            reasons.append(
                f"Technique {tech_id} resulted in a missed detection."
            )
        if overall_score and overall_score < 0.6:
            reasons.append("Overall exercise score below 0.6 indicates broad gaps.")
        if not reasons:
            reasons.append(
                f"Technique {tech_id} coverage gap identified in AAR."
            )
        return " ".join(reasons)

    def _build_needs_summary(
        self,
        coverage_gaps: List[Dict[str, Any]],
        failed_detections: List[Dict[str, Any]],
        training_modules: List[Dict[str, Any]],
        overall_score: float,
    ) -> str:
        return (
            f"Training needs assessment identified {len(coverage_gaps)} coverage "
            f"gap(s) and {len(failed_detections)} failed detection(s), mapped to "
            f"{len(training_modules)} training module(s). Overall exercise score "
            f"was {overall_score}."
        )

    # ------------------------------------------------------------------
    # Internal helpers — training plan
    # ------------------------------------------------------------------

    @staticmethod
    def _build_timeline(scheduled_modules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build a high-level timeline summary from scheduled modules."""
        if not scheduled_modules:
            return {
                "start_date": None,
                "end_date": None,
                "span_days": 0,
                "milestones": [],
            }

        start_dates = [m["start_date"] for m in scheduled_modules if m.get("start_date")]
        end_dates = [m["end_date"] for m in scheduled_modules if m.get("end_date")]
        start = min(start_dates) if start_dates else None
        end = max(end_dates) if end_dates else None

        span_days = 0
        if start and end:
            try:
                span_days = (
                    datetime.fromisoformat(end) - datetime.fromisoformat(start)
                ).days
            except (ValueError, TypeError):
                span_days = 0

        milestones = [
            {
                "date": m.get("start_date"),
                "module": m.get("name"),
                "priority": m.get("priority"),
            }
            for m in scheduled_modules
        ]
        return {
            "start_date": start,
            "end_date": end,
            "span_days": span_days,
            "milestones": milestones,
        }

    # ------------------------------------------------------------------
    # Internal helpers — awareness assessment
    # ------------------------------------------------------------------

    @staticmethod
    def _score_detection_rate(
        blue_team_alerts: List[Dict[str, Any]],
        red_team_stages: List[Dict[str, Any]],
    ) -> float:
        """Score the detection rate component (0-100)."""
        total_stages = len(red_team_stages)
        if total_stages == 0:
            return 50.0  # neutral when no attacks were simulated

        detected_stage_ids: set = set()
        for alert in blue_team_alerts:
            payload = alert.get("payload", alert)
            if payload.get("detected", False):
                stage_id = payload.get("stage_id")
                if stage_id:
                    detected_stage_ids.add(stage_id)

        detected = sum(
            1 for s in red_team_stages
            if (s.get("payload", s)).get("stage_id") in detected_stage_ids
        )
        rate = detected / total_stages
        return round(rate * 100, 1)

    @staticmethod
    def _score_response_time(blue_team_alerts: List[Dict[str, Any]]) -> float:
        """Score the response time component (0-100).

        Faster mean response times yield higher scores. The scoring curve
        rewards sub-minute responses and tapers off for multi-minute delays.
        """
        response_times_ms = [
            alert.get("payload", alert).get("response_time_ms")
            for alert in blue_team_alerts
            if alert.get("payload", alert).get("response_time_ms") is not None
        ]
        if not response_times_ms:
            return 50.0  # neutral when no response time data is available

        mean_ms = sum(response_times_ms) / len(response_times_ms)
        mean_seconds = mean_ms / 1000.0

        # Scoring curve: <=30s -> 100, 30s-60s -> 90-100, 60s-300s -> 60-90,
        # 300s-900s -> 30-60, >900s -> approaches 0.
        if mean_seconds <= 30:
            return 100.0
        if mean_seconds <= 60:
            return round(90 + (60 - mean_seconds) / 30 * 10, 1)
        if mean_seconds <= 300:
            return round(60 + (300 - mean_seconds) / 240 * 30, 1)
        if mean_seconds <= 900:
            return round(30 + (900 - mean_seconds) / 600 * 30, 1)
        return max(0.0, round(30 - (mean_seconds - 900) / 100, 1))

    @staticmethod
    def _score_coverage_gaps(
        coverage_gaps: Optional[List[Dict[str, Any]]],
        red_team_stages: List[Dict[str, Any]],
        blue_team_alerts: List[Dict[str, Any]],
    ) -> float:
        """Score the coverage gap component (0-100).

        Fewer gaps relative to the number of techniques attacked yields a
        higher score. 0 gaps -> 100, all techniques missed -> 0.
        """
        if coverage_gaps is None:
            # Derive gaps from red/blue events.
            detected_techniques: set = set()
            for alert in blue_team_alerts:
                payload = alert.get("payload", alert)
                if payload.get("detected", False):
                    tech_id = payload.get("technique_id")
                    if tech_id:
                        detected_techniques.add(tech_id)
            attacked: set = set()
            for stage in red_team_stages:
                payload = stage.get("payload", stage)
                tech_id = payload.get("technique_id")
                if tech_id:
                    attacked.add(tech_id)
            gap_count = len(attacked - detected_techniques)
            total = len(attacked)
        else:
            gap_count = len(coverage_gaps)
            total = len({s.get("payload", s).get("technique_id") for s in red_team_stages})

        if total == 0:
            return 50.0
        gap_ratio = gap_count / total
        return round((1 - gap_ratio) * 100, 1)

    @staticmethod
    def _score_training_history(
        training_history: Optional[List[Dict[str, Any]]],
    ) -> float:
        """Score the training history component (0-100).

        Averages the ``completion_pct`` of prior training records. When no
        history is available, returns a neutral 50.
        """
        if not training_history:
            return 50.0
        completions = [
            record.get("completion_pct", 0)
            for record in training_history
            if record.get("completion_pct") is not None
        ]
        if not completions:
            return 50.0
        return round(sum(completions) / len(completions), 1)

    @staticmethod
    def _level_for_score(score: float) -> Dict[str, Any]:
        for band in _AWARENESS_LEVELS:
            if score >= band["min"]:
                return band
        return _AWARENESS_LEVELS[-1]

    @staticmethod
    def _awareness_recommendations(score: float, level: str) -> List[str]:
        recs: List[str] = []
        if level == "novice":
            recs.append(
                "Launch an organization-wide security awareness program "
                "covering phishing, password hygiene, and reporting procedures."
            )
            recs.append(
                "Prioritize mandatory e-learning for all staff within 30 days."
            )
        elif level == "developing":
            recs.append(
                "Targeted workshops for SOC analysts and system "
                "administrators on the top coverage gaps."
            )
            recs.append(
                "Introduce quarterly phishing simulations to measure "
                "reporting rates."
            )
        elif level == "proficient":
            recs.append(
                "Run advanced tabletop exercises focused on ransomware and "
                "lateral movement response."
            )
            recs.append(
                "Refine detection content for remaining MITRE technique gaps."
            )
        else:  # expert
            recs.append(
                "Maintain the mature awareness program with continuous "
                "improvement and red-team-validated refreshers."
            )
            recs.append(
                "Mentor peer organizations and contribute lessons learned "
                "to the broader security community."
            )
        return recs

    # ------------------------------------------------------------------
    # Internal helpers — effectiveness tracking
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_score_record(record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a score record so overall_score is on a 0-100 scale."""
        overall = record.get("overall_score", 0.0)
        if overall is None:
            overall = 0.0
        # If the score looks like a 0-1 fraction, scale to 0-100.
        if 0 <= overall <= 1.0:
            overall = overall * 100.0

        components = record.get("component_scores", {}) or {}
        normalized_components: Dict[str, float] = {}
        for key, value in components.items():
            if value is None:
                continue
            if 0 <= value <= 1.0:
                normalized_components[key] = value * 100.0
            else:
                normalized_components[key] = float(value)

        return {
            "overall_score": float(overall),
            "component_scores": normalized_components,
            "exercise_id": record.get("exercise_id"),
            "timestamp": record.get("timestamp"),
            "training_completed": record.get("training_completed", False),
        }

    @staticmethod
    def _compute_trend_slope(scores: List[float]) -> float:
        """Compute a simple linear regression slope of scores over samples."""
        n = len(scores)
        if n < 2:
            return 0.0
        xs = list(range(n))
        x_mean = sum(xs) / n
        y_mean = sum(scores) / n
        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, scores))
        denominator = sum((x - x_mean) ** 2 for x in xs)
        if denominator == 0:
            return 0.0
        return numerator / denominator

    @staticmethod
    def _compute_component_trends(
        normalized: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compute per-component first/latest/delta trends."""
        component_keys: set = set()
        for record in normalized:
            component_keys.update(record.get("component_scores", {}).keys())

        trends: Dict[str, Any] = {}
        for key in sorted(component_keys):
            values = [
                r["component_scores"][key]
                for r in normalized
                if key in r.get("component_scores", {})
            ]
            if not values:
                continue
            trends[key] = {
                "first": round(values[0], 2),
                "latest": round(values[-1], 2),
                "delta": round(values[-1] - values[0], 2),
            }
        return trends

    @staticmethod
    def _effectiveness_rating(delta: float, slope: float) -> str:
        if delta >= 10 and slope > 1.0:
            return "highly_effective"
        if delta > 0 and slope > 0:
            return "effective"
        if abs(delta) < 1 and abs(slope) < 0.5:
            return "stable"
        if delta < 0 and slope < 0:
            return "ineffective"
        return "marginal"

    @staticmethod
    def _effectiveness_recommendations(
        trend: str,
        delta: float,
        slope: float,
        component_trends: Dict[str, Any],
    ) -> List[str]:
        recs: List[str] = []
        if trend == "improving":
            recs.append(
                "Training program is showing measurable improvement; "
                "continue current cadence and expand to adjacent techniques."
            )
        elif trend == "declining":
            recs.append(
                "Scores are declining — review training content relevance, "
                "attendance, and reinforcement cadence."
            )
            recs.append(
                "Re-run baseline awareness assessments to identify "
                "knowledge decay."
            )
        else:
            recs.append(
                "Scores are stable; introduce scenario-based simulations "
                "to push beyond the current plateau."
            )

        # Component-specific recommendations.
        for component, info in component_trends.items():
            if info.get("delta", 0) < -5:
                recs.append(
                    f"{component} scores dropped by {abs(info['delta'])} points; "
                    f"schedule a refresher module targeting this area."
                )

        if not recs:
            recs.append("Maintain the current training program and continue monitoring.")
        return recs
