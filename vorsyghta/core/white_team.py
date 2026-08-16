"""White Team — rules of engagement, scope, and risk governance for Vorsyghta.

The White Team represents the defending organization's leadership and exercise
coordination. Unlike the Red, Blue, Purple, and Black teams, the White Team is
responsible for *governing* the exercise itself rather than attacking or
defending. Its duties are:

- **Rules of Engagement (ROE)** — defining and enforcing the constraints that
  bound the red team's actions (e.g. "no DoS attacks", "business hours only").
- **Scope management** — ensuring the red team stays within approved targets
  and systems.
- **Risk management** — monitoring exercise risk in real-time and pausing or
  aborting the exercise when risk exceeds defined thresholds.
- **Exercise coordination** — approving scope, managing timelines, and
  authorizing the exercise to proceed.

The :class:`WhiteTeamCoordinator` exposes both synchronous governance methods
(ROE compliance, risk assessment, scope approval, report generation) and an
async event-bus integration that performs real-time ROE checks as red team
attack stages are published.

Owner: White Team Lead
Phase 4 — White Team governance
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from vorsyghta.core.event_types import (
    BusEvent,
    EventType,
    WhiteTeamROECheckEvent,
    WhiteTeamROEViolationEvent,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique severity weighting
# ---------------------------------------------------------------------------

# Maps MITRE ATT&CK technique IDs to a base severity weight used by the risk
# assessment. Techniques not listed here default to a medium weight.
_TECHNIQUE_SEVERITY: Dict[str, int] = {
    # Initial access / phishing
    "T1566": 60,
    "T1190": 65,
    "T1078": 55,
    # Execution
    "T1059": 50,
    "T1053": 40,
    # Persistence
    "T1543": 70,
    "T1547": 70,
    "T1136": 65,
    # Credential access
    "T1003": 80,
    "T1110": 60,
    # Lateral movement
    "T1021": 70,
    "T1072": 60,
    # Collection / exfiltration
    "T1041": 85,
    "T1048": 80,
    "T1005": 55,
    # Impact
    "T1486": 90,
    "T1498": 95,
    "T1499": 95,
    # Defense evasion
    "T1070": 50,
    "T1027": 45,
}

# Techniques that indicate lateral movement and add to the risk score.
_LATERAL_MOVEMENT_TECHNIQUES = {"T1021", "T1072", "T1020", "T1071", "T1570"}

# Techniques associated with data exfiltration.
_EXFILTRATION_TECHNIQUES = {"T1041", "T1048", "T1041", "T1052", "T1029"}

# Techniques associated with denial-of-service / impact.
_DOS_TECHNIQUES = {"T1498", "T1499", "T1490", "T1485", "T1489"}

# Techniques associated with persistence.
_PERSISTENCE_TECHNIQUES = {"T1543", "T1547", "T1136", "T1053", "T1098"}


@dataclass
class ROERule:
    """A single Rule of Engagement.

    Attributes:
        rule_id: Stable identifier (e.g. ``ROE-001``).
        description: Human-readable description of the rule.
        severity: Severity applied when the rule is violated
            (``critical``, ``high``, ``medium``, ``low``).
        check: Callable that receives a red team stage payload dict and returns
            ``True`` when the stage *complies* with the rule, ``False`` when it
            violates it. The callable may also return a tuple
            ``(passed: bool, details: str)``.
    """

    rule_id: str
    description: str
    severity: str
    check: Callable[[Dict[str, Any]], Any]
    enabled: bool = True


def _payload(item: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the payload from an event dict, or return the dict itself."""
    return item.get("payload", item) if isinstance(item, dict) else item


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """Best-effort parse of a timestamp value into a timezone-aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


class WhiteTeamCoordinator:
    """Coordinates governance for color-team exercises.

    The White Team coordinator owns the Rules of Engagement, performs scope
    approval, assesses real-time exercise risk, and produces governance
    reports. It can also subscribe to the shared event bus to perform ROE
    checks on every red team attack stage as it is published.

    Args:
        approved_systems: Optional initial set of approved target systems.
        business_hours_start: Start of approved business hours (UTC, 24h).
        business_hours_end: End of approved business hours (UTC, 24h).
        approved_executive_roles: Roles that are off-limits for social
            engineering (defaults to common C-suite titles).
        risk_pause_threshold: Risk score at which a pause is recommended.
        risk_abort_threshold: Risk score at which an abort is recommended.
        extra_roe_rules: Additional ROE rules to register on top of the
            built-in defaults.
    """

    def __init__(
        self,
        approved_systems: Optional[List[str]] = None,
        business_hours_start: time = time(9, 0),
        business_hours_end: time = time(17, 0),
        approved_executive_roles: Optional[List[str]] = None,
        risk_pause_threshold: int = 80,
        risk_abort_threshold: int = 95,
        extra_roe_rules: Optional[List[ROERule]] = None,
    ) -> None:
        self.approved_systems: List[str] = list(approved_systems or [])
        self.business_hours_start = business_hours_start
        self.business_hours_end = business_hours_end
        self.approved_executive_roles: List[str] = list(
            approved_executive_roles
            or ["CEO", "CFO", "COO", "CIO", "CISO", "CTO", "CMO", "Board"]
        )
        self.risk_pause_threshold = risk_pause_threshold
        self.risk_abort_threshold = risk_abort_threshold

        self._roe_rules: Dict[str, ROERule] = {}
        for rule in self._default_roe_rules():
            self._roe_rules[rule.rule_id] = rule
        for rule in extra_roe_rules or []:
            self._roe_rules[rule.rule_id] = rule

        # Runtime state populated by the event-bus integration.
        self._observed_stages: List[Dict[str, Any]] = []
        self._observed_violations: List[Dict[str, Any]] = []
        self._latest_risk_score: float = 0.0

    # ------------------------------------------------------------------
    # ROE rule registry
    # ------------------------------------------------------------------

    @property
    def roe_rules(self) -> List[ROERule]:
        """Return the currently registered ROE rules."""
        return list(self._roe_rules.values())

    def add_roe_rule(self, rule: ROERule) -> None:
        """Register or replace an ROE rule."""
        self._roe_rules[rule.rule_id] = rule
        logger.info("ROE rule registered: %s (%s)", rule.rule_id, rule.description)

    def remove_roe_rule(self, rule_id: str) -> bool:
        """Remove an ROE rule by ID. Returns True if a rule was removed."""
        removed = self._roe_rules.pop(rule_id, None)
        if removed is not None:
            logger.info("ROE rule removed: %s", rule_id)
        return removed is not None

    def get_roe_rule(self, rule_id: str) -> Optional[ROERule]:
        """Return an ROE rule by ID, or None."""
        return self._roe_rules.get(rule_id)

    # ------------------------------------------------------------------
    # Default ROE rules
    # ------------------------------------------------------------------

    def _default_roe_rules(self) -> List[ROERule]:
        """Build the built-in ROE rules ROE-001 through ROE-007."""

        def _check_no_dos(stage: Dict[str, Any]) -> Any:
            tech = (stage.get("technique_id") or "").upper()
            if tech in _DOS_TECHNIQUES:
                return False, f"Denial-of-service technique {tech} detected"
            # Also inspect the content for explicit DoS language.
            content = (stage.get("content") or "").lower()
            dos_markers = ("denial of service", "dos attack", "flood", "syn flood")
            if any(marker in content for marker in dos_markers):
                return False, "DoS language detected in stage content"
            return True, "No denial-of-service indicators"

        def _check_exfiltration_limit(stage: Dict[str, Any]) -> Any:
            tech = (stage.get("technique_id") or "").upper()
            if tech in _EXFILTRATION_TECHNIQUES:
                # Look for an explicit bytes_exfiltrated field; default to
                # assuming a violation if the technique is present without a
                # bounded size.
                bytes_exfil = stage.get("bytes_exfiltrated")
                if bytes_exfil is None:
                    return False, (
                        f"Exfiltration technique {tech} used without a "
                        "declared transfer size"
                    )
                try:
                    if float(bytes_exfil) > 1_048_576:  # 1 MB
                        return False, (
                            f"Exfiltration of {bytes_exfil} bytes exceeds "
                            "the 1MB limit"
                        )
                except (TypeError, ValueError):
                    return False, "Unparseable exfiltration size"
            return True, "Exfiltration within approved limits"

        def _check_no_production_attack(stage: Dict[str, Any]) -> Any:
            target = stage.get("target_system")
            if not target:
                return True, "No target system declared"
            # When an approved list is configured, any target outside it is a
            # violation. When no list is configured, we cannot enforce this
            # rule and treat it as passing.
            if not self.approved_systems:
                return True, "No approved-systems list configured"
            if target not in self.approved_systems:
                return False, (
                    f"Target system '{target}' is not in the approved scope"
                )
            # If the target is explicitly marked as production in its name,
            # treat it as a violation.
            if "prod" in str(target).lower():
                return False, f"Production system '{target}' is out of scope"
            return True, f"Target system '{target}' is within approved scope"

        def _check_no_executive_social_engineering(stage: Dict[str, Any]) -> Any:
            content = (stage.get("content") or "")
            stage_name = (stage.get("stage_name") or "")
            haystack = f"{stage_name} {content}".lower()
            for role in self.approved_executive_roles:
                if role.lower() in haystack:
                    # Only flag when the stage looks like social engineering.
                    se_markers = (
                        "phish",
                        "social engineer",
                        "pretext",
                        "impersonat",
                        "spear phish",
                        "vish",
                    )
                    if any(marker in haystack for marker in se_markers):
                        return False, (
                            f"Social engineering targeting {role} is prohibited"
                        )
            return True, "No prohibited executive targeting detected"

        def _check_business_hours(stage: Dict[str, Any]) -> Any:
            ts = _parse_timestamp(stage.get("timestamp"))
            if ts is None:
                # If no timestamp is present we cannot enforce the rule; treat
                # it as a soft pass with a note.
                return True, "No timestamp provided; business-hours check skipped"
            local = ts.astimezone(timezone.utc).time()
            if not (self.business_hours_start <= local <= self.business_hours_end):
                return False, (
                    f"Attack occurred at {local.isoformat()} UTC which is "
                    f"outside business hours "
                    f"({self.business_hours_start}-{self.business_hours_end})"
                )
            return True, "Attack within approved business hours"

        def _check_no_production_persistence(stage: Dict[str, Any]) -> Any:
            tech = (stage.get("technique_id") or "").upper()
            if tech in _PERSISTENCE_TECHNIQUES:
                target = stage.get("target_system") or ""
                if "prod" in str(target).lower() or (
                    self.approved_systems
                    and target in self.approved_systems
                    and any("prod" in s.lower() for s in self.approved_systems)
                ):
                    return False, (
                        f"Persistence technique {tech} deployed on production "
                        f"system '{target}'"
                    )
                # If persistence is used at all and we have an approved list
                # that includes production systems, flag conservatively.
                if not self.approved_systems:
                    return False, (
                        f"Persistence technique {tech} used; production "
                        "status could not be verified"
                    )
            return True, "No prohibited production persistence detected"

        def _check_actions_logged(stage: Dict[str, Any]) -> Any:
            # An action is considered logged when the stage carries either an
            # explicit ``audit_trail``/``logged`` flag or non-empty content
            # that can serve as a log line.
            if stage.get("logged") is True:
                return True, "Stage explicitly marked as logged"
            if stage.get("audit_trail"):
                return True, "Audit trail present for stage"
            content = stage.get("content")
            if content:
                return True, "Stage content serves as audit record"
            return False, "No audit trail or log content found for stage"

        return [
            ROERule(
                rule_id="ROE-001",
                description="No Denial of Service attacks",
                severity="critical",
                check=_check_no_dos,
            ),
            ROERule(
                rule_id="ROE-002",
                description="No data exfiltration beyond 1MB",
                severity="critical",
                check=_check_exfiltration_limit,
            ),
            ROERule(
                rule_id="ROE-003",
                description="No attacks on production systems",
                severity="high",
                check=_check_no_production_attack,
            ),
            ROERule(
                rule_id="ROE-004",
                description="No social engineering of C-suite executives",
                severity="high",
                check=_check_no_executive_social_engineering,
            ),
            ROERule(
                rule_id="ROE-005",
                description="Business hours only",
                severity="medium",
                check=_check_business_hours,
            ),
            ROERule(
                rule_id="ROE-006",
                description="No persistence mechanisms on production",
                severity="high",
                check=_check_no_production_persistence,
            ),
            ROERule(
                rule_id="ROE-007",
                description="All actions must be logged",
                severity="medium",
                check=_check_actions_logged,
            ),
        ]

    # ------------------------------------------------------------------
    # ROE compliance checking
    # ------------------------------------------------------------------

    def check_roe_compliance(
        self, red_team_stages: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Examine red team attack stages against the ROE rules.

        Args:
            red_team_stages: List of red team attack stage event dicts. Each
                item may be a raw payload dict or a wrapped event dict with a
                ``payload`` key.

        Returns:
            A list of violation dicts, each containing:
                - ``rule_id``: The ROE rule that was violated.
                - ``rule_description``: Human-readable rule description.
                - ``severity``: Violation severity.
                - ``stage_id``: The red team stage that triggered it.
                - ``details``: Explanation of why the check failed.
                - ``action_taken``: Recommended action (warn/pause/abort).
        """
        violations: List[Dict[str, Any]] = []

        for stage in red_team_stages:
            payload = _payload(stage)
            stage_id = payload.get("stage_id")
            for rule in self._roe_rules.values():
                if not rule.enabled:
                    continue
                try:
                    result = rule.check(payload)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "ROE rule %s check raised: %s", rule.rule_id, exc
                    )
                    violations.append({
                        "rule_id": rule.rule_id,
                        "rule_description": rule.description,
                        "severity": rule.severity,
                        "stage_id": stage_id,
                        "details": f"ROE check error: {exc}",
                        "action_taken": "warn",
                    })
                    continue

                passed, details = self._normalize_check_result(result)
                if not passed:
                    action = self._action_for_severity(rule.severity)
                    violations.append({
                        "rule_id": rule.rule_id,
                        "rule_description": rule.description,
                        "severity": rule.severity,
                        "stage_id": stage_id,
                        "details": details or "Rule violated",
                        "action_taken": action,
                    })

        logger.info(
            "ROE compliance check complete: %d violation(s) across %d stage(s)",
            len(violations),
            len(red_team_stages),
        )
        return violations

    @staticmethod
    def _normalize_check_result(result: Any) -> tuple:
        """Normalize a check callable return value into (passed, details)."""
        if isinstance(result, tuple):
            if len(result) >= 2:
                return bool(result[0]), str(result[1])
            if len(result) == 1:
                return bool(result[0]), ""
        return bool(result), ""

    @staticmethod
    def _action_for_severity(severity: str) -> str:
        """Map a violation severity to a recommended action."""
        if severity == "critical":
            return "abort"
        if severity == "high":
            return "pause"
        return "warn"

    # ------------------------------------------------------------------
    # Risk assessment
    # ------------------------------------------------------------------

    def assess_risk(
        self,
        red_team_stages: List[Dict[str, Any]],
        blue_team_alerts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compute a real-time risk score for the exercise.

        The risk score is a 0-100 value derived from:

        - **Attack severity** — weighted by MITRE technique.
        - **Detection gaps** — missed detections increase risk.
        - **ROE violations** — critical violations add 25 points each.
        - **Lateral movement indicators** — techniques that indicate lateral
          movement add to the score.

        Args:
            red_team_stages: Red team attack stage event dicts.
            blue_team_alerts: Blue team alert event dicts.

        Returns:
            A risk assessment dict with:
                - ``risk_score``: 0-100 numeric score.
                - ``risk_level``: low / medium / high / critical.
                - ``recommendation``: continue / monitor / pause / abort.
                - ``components``: Breakdown of contributing factors.
                - ``roe_violations``: Count of violations by severity.
                - ``assessed_at``: ISO timestamp of the assessment.
        """
        assessed_at = datetime.now(timezone.utc).isoformat()

        # --- Attack severity component -----------------------------------
        total_stages = len(red_team_stages)
        technique_weights: List[int] = []
        lateral_count = 0
        for stage in red_team_stages:
            payload = _payload(stage)
            tech = (payload.get("technique_id") or "").upper()
            weight = _TECHNIQUE_SEVERITY.get(tech, 45)
            technique_weights.append(weight)
            if tech in _LATERAL_MOVEMENT_TECHNIQUES:
                lateral_count += 1

        if technique_weights:
            avg_severity = sum(technique_weights) / len(technique_weights)
            max_severity = max(technique_weights)
            # Blend average and max so a single catastrophic technique is not
            # drowned out by many low-severity ones.
            attack_severity_score = (avg_severity * 0.6) + (max_severity * 0.4)
        else:
            attack_severity_score = 0.0

        # --- Detection gap component -------------------------------------
        detected_stage_ids: set = set()
        for alert in blue_team_alerts:
            ap = _payload(alert)
            if ap.get("detected", False):
                sid = ap.get("stage_id")
                if sid:
                    detected_stage_ids.add(sid)

        missed = 0
        for stage in red_team_stages:
            payload = _payload(stage)
            sid = payload.get("stage_id")
            if sid is not None and sid not in detected_stage_ids:
                missed += 1

        if total_stages > 0:
            miss_rate = missed / total_stages
        else:
            miss_rate = 0.0
        # Detection gaps can contribute up to 30 points.
        detection_gap_score = miss_rate * 30.0

        # --- ROE violation component -------------------------------------
        roe_violations = self.check_roe_compliance(red_team_stages)
        severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in roe_violations:
            sev = v.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        roe_score = (
            severity_counts["critical"] * 25
            + severity_counts["high"] * 15
            + severity_counts["medium"] * 8
            + severity_counts["low"] * 3
        )

        # --- Lateral movement component ----------------------------------
        lateral_score = min(lateral_count * 5, 15)

        # --- Combine -----------------------------------------------------
        # attack_severity_score is already on a ~0-100 scale; we scale the
        # other components to keep the final score bounded.
        raw = attack_severity_score * 0.5 + detection_gap_score + roe_score + lateral_score
        risk_score = round(min(100.0, max(0.0, raw)), 1)

        risk_level = self._risk_level(risk_score)
        recommendation = self._risk_recommendation(risk_score)

        assessment = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommendation": recommendation,
            "components": {
                "attack_severity": round(attack_severity_score, 1),
                "detection_gap": round(detection_gap_score, 1),
                "roe_violations": roe_score,
                "lateral_movement": lateral_score,
            },
            "roe_violations": severity_counts,
            "total_roe_violations": len(roe_violations),
            "missed_detections": missed,
            "lateral_movement_indicators": lateral_count,
            "total_stages": total_stages,
            "assessed_at": assessed_at,
        }

        self._latest_risk_score = risk_score
        logger.info(
            "Risk assessed: score=%.1f level=%s recommendation=%s "
            "(severity=%.1f, gap=%.1f, roe=%d, lateral=%d)",
            risk_score,
            risk_level,
            recommendation,
            attack_severity_score,
            detection_gap_score,
            roe_score,
            lateral_score,
        )
        return assessment

    def _risk_level(self, score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    def _risk_recommendation(self, score: float) -> str:
        if score >= self.risk_abort_threshold:
            return "abort"
        if score >= self.risk_pause_threshold:
            return "pause"
        if score >= 60:
            return "monitor"
        if score >= 30:
            return "monitor"
        return "continue"

    # ------------------------------------------------------------------
    # Scope approval
    # ------------------------------------------------------------------

    def approve_scope(
        self,
        scenario: Dict[str, Any],
        target_systems: List[str],
    ) -> Dict[str, Any]:
        """Validate that a scenario's targets are within approved scope.

        Args:
            scenario: Scenario definition dict. May contain a ``targets``
                list and/or a ``target_systems`` list.
            target_systems: Explicit list of target systems proposed for the
                exercise.

        Returns:
            A scope approval dict with:
                - ``approved``: Whether the scope is approved.
                - ``approved_targets``: Targets that passed validation.
                - ``out_of_scope_targets``: Targets not in the approved list.
                - ``production_targets``: Targets flagged as production.
                - ``reason``: Human-readable approval/denial reason.
                - ``approved_at``: ISO timestamp.
        """
        approved_at = datetime.now(timezone.utc).isoformat()

        proposed = list(target_systems or [])
        scenario_targets = scenario.get("targets") or scenario.get("target_systems") or []
        proposed.extend(scenario_targets)
        proposed = list(dict.fromkeys(proposed))  # de-duplicate, preserve order

        approved_set = set(self.approved_systems)
        out_of_scope = [t for t in proposed if approved_set and t not in approved_set]
        production_targets = [t for t in proposed if "prod" in str(t).lower()]

        if not self.approved_systems:
            # No approved list configured: approve everything but flag
            # production targets for review.
            approved = len(production_targets) == 0
            reason = (
                "Scope approved (no approved-systems list configured)."
                if approved
                else "Scope denied: production targets require explicit approval."
            )
        elif out_of_scope:
            approved = False
            reason = (
                f"Scope denied: {len(out_of_scope)} target(s) are outside the "
                "approved systems list."
            )
        elif production_targets:
            approved = False
            reason = (
                "Scope denied: production targets require explicit approval."
            )
        else:
            approved = True
            reason = "Scope approved: all targets within approved systems."

        result = {
            "approved": approved,
            "approved_targets": [t for t in proposed if t not in out_of_scope],
            "out_of_scope_targets": out_of_scope,
            "production_targets": production_targets,
            "reason": reason,
            "approved_at": approved_at,
            "scenario_id": scenario.get("scenario_id") or scenario.get("id"),
        }

        logger.info(
            "Scope approval: approved=%s targets=%d out_of_scope=%d production=%d",
            approved,
            len(proposed),
            len(out_of_scope),
            len(production_targets),
        )
        return result

    # ------------------------------------------------------------------
    # Governance report
    # ------------------------------------------------------------------

    def generate_governance_report(
        self,
        exercise_id: str,
        red_team_stages: List[Dict[str, Any]],
        blue_team_alerts: List[Dict[str, Any]],
        roe_violations: Optional[List[Dict[str, Any]]] = None,
        risk_assessment: Optional[Dict[str, Any]] = None,
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """Produce a structured governance report for the exercise.

        Args:
            exercise_id: ID of the exercise.
            red_team_stages: Red team attack stage event dicts.
            blue_team_alerts: Blue team alert event dicts.
            roe_violations: Pre-computed ROE violations. If None, they are
                computed from the red team stages.
            risk_assessment: Pre-computed risk assessment. If None, it is
                computed from the stages and alerts.
            tenant_id: Tenant scope.

        Returns:
            A structured governance report dict with ROE compliance, risk
            summary, scope summary, and recommendations.
        """
        report_id = str(uuid4())
        generated_at = datetime.now(timezone.utc).isoformat()

        if roe_violations is None:
            roe_violations = self.check_roe_compliance(red_team_stages)
        if risk_assessment is None:
            risk_assessment = self.assess_risk(red_team_stages, blue_team_alerts)

        compliance = self._roe_compliance_summary(roe_violations)
        recommendations = self._governance_recommendations(
            roe_violations, risk_assessment
        )

        report = {
            "report_id": report_id,
            "exercise_id": exercise_id,
            "tenant_id": tenant_id,
            "generated_at": generated_at,
            "roe_compliance": compliance,
            "risk_summary": {
                "risk_score": risk_assessment.get("risk_score"),
                "risk_level": risk_assessment.get("risk_level"),
                "recommendation": risk_assessment.get("recommendation"),
                "components": risk_assessment.get("components", {}),
            },
            "scope_summary": {
                "approved_systems": list(self.approved_systems),
                "total_stages": len(red_team_stages),
                "total_alerts": len(blue_team_alerts),
            },
            "violations": roe_violations,
            "recommendations": recommendations,
            "overall_status": self._overall_status(roe_violations, risk_assessment),
        }

        logger.info(
            "Governance report generated: exercise=%s violations=%d risk=%s status=%s",
            exercise_id,
            len(roe_violations),
            risk_assessment.get("risk_level"),
            report["overall_status"],
        )
        return report

    def _roe_compliance_summary(
        self, violations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Summarize ROE compliance across all registered rules."""
        total_rules = len(self._roe_rules)
        violated_rule_ids = {v.get("rule_id") for v in violations}
        compliant_rules = total_rules - len(violated_rule_ids)

        severity_counts: Dict[str, int] = {}
        actions: Dict[str, int] = {}
        for v in violations:
            sev = v.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            action = v.get("action_taken", "warn")
            actions[action] = actions.get(action, 0) + 1

        return {
            "total_rules": total_rules,
            "compliant_rules": compliant_rules,
            "violated_rules": len(violated_rule_ids),
            "total_violations": len(violations),
            "violations_by_severity": severity_counts,
            "actions_recommended": actions,
            "compliance_rate_pct": round(
                (compliant_rules / total_rules * 100) if total_rules else 100.0, 1
            ),
        }

    def _governance_recommendations(
        self,
        violations: List[Dict[str, Any]],
        risk_assessment: Dict[str, Any],
    ) -> List[str]:
        """Generate governance recommendations from violations and risk."""
        recs: List[str] = []
        risk_level = risk_assessment.get("risk_level", "low")
        risk_rec = risk_assessment.get("recommendation", "continue")

        if risk_rec == "abort":
            recs.append(
                "Abort the exercise immediately: risk score exceeds the abort "
                "threshold. Preserve all artifacts for post-exercise review."
            )
        elif risk_rec == "pause":
            recs.append(
                "Pause the exercise: risk score exceeds the pause threshold. "
                "Re-evaluate scope and ROE before resuming."
            )
        elif risk_level == "high":
            recs.append(
                "Increase monitoring cadence: risk level is high. Prepare to "
                "pause if conditions deteriorate."
            )

        critical = [v for v in violations if v.get("severity") == "critical"]
        if critical:
            recs.append(
                f"Address {len(critical)} critical ROE violation(s) before "
                "continuing the exercise."
            )

        production_violations = [
            v for v in violations
            if v.get("rule_id") in ("ROE-003", "ROE-006")
        ]
        if production_violations:
            recs.append(
                "Production systems were targeted in violation of scope. "
                "Review the approved-systems list and red team targeting."
            )

        components = risk_assessment.get("components", {})
        if components.get("detection_gap", 0) >= 20:
            recs.append(
                "Detection gaps are significant. Coordinate with the Blue "
                "Team to improve coverage before the next exercise."
            )
        if components.get("lateral_movement", 0) > 0:
            recs.append(
                "Lateral movement was observed. Validate that segmentation "
                "controls are in scope for the next iteration."
            )

        if not recs:
            recs.append(
                "Exercise is proceeding within governance bounds. Continue "
                "monitoring and document any deviations."
            )
        return recs

    def _overall_status(
        self,
        violations: List[Dict[str, Any]],
        risk_assessment: Dict[str, Any],
    ) -> str:
        """Determine the overall governance status of the exercise."""
        risk_rec = risk_assessment.get("recommendation", "continue")
        if risk_rec == "abort":
            return "aborted"
        if risk_rec == "pause":
            return "paused"
        if any(v.get("severity") == "critical" for v in violations):
            return "at_risk"
        if violations:
            return "warning"
        return "compliant"

    # ------------------------------------------------------------------
    # Event bus integration
    # ------------------------------------------------------------------

    def subscribe_to_event_bus(
        self,
        bus: Any,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> None:
        """Subscribe to red team attack stages for real-time ROE enforcement.

        When a ``RED_TEAM_ATTACK_STAGE`` event is published, the coordinator
        runs every enabled ROE rule against the stage payload. For each rule
        a :class:`WhiteTeamROECheckEvent` is published; for each violation a
        :class:`WhiteTeamROEViolationEvent` is published with the recommended
        action (warn/pause/abort).

        Args:
            bus: The shared :class:`EventBus`.
            tenant_id: Tenant scope for events to process.
            exercise_id: Optional exercise identifier included in published
                events.
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
            stage_id = payload.get("stage_id")
            self._observed_stages.append(payload)

            for rule in self._roe_rules.values():
                if not rule.enabled:
                    continue
                check_id = str(uuid4())
                try:
                    result = rule.check(payload)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "ROE rule %s raised during event handling: %s",
                        rule.rule_id,
                        exc,
                    )
                    await bus.publish(
                        WhiteTeamROECheckEvent(
                            tenant_id=tenant_id,
                            exercise_id=exercise_id,
                            check_id=check_id,
                            rule_id=rule.rule_id,
                            rule_description=rule.description,
                            passed=False,
                            violation_severity=rule.severity,
                            details=f"ROE check error: {exc}",
                        )
                    )
                    continue

                passed, details = self._normalize_check_result(result)

                await bus.publish(
                    WhiteTeamROECheckEvent(
                        tenant_id=tenant_id,
                        exercise_id=exercise_id,
                        check_id=check_id,
                        rule_id=rule.rule_id,
                        rule_description=rule.description,
                        passed=passed,
                        violation_severity=None if passed else rule.severity,
                        details=details or ("Compliant" if passed else "Violated"),
                    )
                )

                if not passed:
                    action = self._action_for_severity(rule.severity)
                    violation_id = str(uuid4())
                    violation = {
                        "violation_id": violation_id,
                        "rule_id": rule.rule_id,
                        "severity": rule.severity,
                        "description": rule.description,
                        "red_team_stage_id": stage_id,
                        "action_taken": action,
                        "details": details or "Rule violated",
                    }
                    self._observed_violations.append(violation)

                    await bus.publish(
                        WhiteTeamROEViolationEvent(
                            tenant_id=tenant_id,
                            exercise_id=exercise_id,
                            violation_id=violation_id,
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            description=details or rule.description,
                            red_team_stage_id=stage_id,
                            action_taken=action,
                        )
                    )

                    logger.warning(
                        "ROE violation: rule=%s stage=%s severity=%s action=%s",
                        rule.rule_id,
                        stage_id,
                        rule.severity,
                        action,
                    )

        bus.subscribe(EventType.RED_TEAM_ATTACK_STAGE, _handler)
        logger.info(
            "White Team subscribed to event bus for tenant %s exercise %s",
            tenant_id,
            exercise_id,
        )

    # ------------------------------------------------------------------
    # Runtime accessors (populated by the event-bus integration)
    # ------------------------------------------------------------------

    @property
    def observed_stages(self) -> List[Dict[str, Any]]:
        """Return red team stages observed via the event bus."""
        return list(self._observed_stages)

    @property
    def observed_violations(self) -> List[Dict[str, Any]]:
        """Return ROE violations observed via the event bus."""
        return list(self._observed_violations)

    @property
    def latest_risk_score(self) -> float:
        """Return the most recently computed risk score."""
        return self._latest_risk_score

    def reset_runtime_state(self) -> None:
        """Clear observed stages, violations, and the latest risk score."""
        self._observed_stages.clear()
        self._observed_violations.clear()
        self._latest_risk_score = 0.0
