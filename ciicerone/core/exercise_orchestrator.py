"""Exercise orchestrator for Ciicerone color-team exercises.

The orchestrator chains: Red Team attack simulation → Blue Team detection
→ Purple Team after-action report → Black Team scoring. It uses the shared
event bus to communicate between teams and produces a structured
ExerciseResult.

Owner: Ajibola Shokunbi (@jiboo2022) — Core Software Lead
Phase 2 — End-to-End Orchestration
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ciicerone.core.event_bus import EventBus
from ciicerone.core.event_types import (
    BusEvent, BlueTeamAlertEvent, EventType, RedTeamAttackStageEvent,
)
from ciicerone.core.audit_logger import AuditCategory, AuditSeverity, get_audit_logger
from ciicerone.core.models import ThreatScenario
from ciicerone.core.simulator import Simulator

logger = logging.getLogger(__name__)


@dataclass
class ExerciseResult:
    """Complete result of a color-team exercise."""

    exercise_id: str
    tenant_id: str
    scenario_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"
    red_team_stages: List[Dict[str, Any]] = field(default_factory=list)
    blue_team_alerts: List[Dict[str, Any]] = field(default_factory=list)
    aar: Optional[Dict[str, Any]] = None
    score: Optional[Dict[str, Any]] = None
    # Extended color teams
    white_team_report: Optional[Dict[str, Any]] = None
    yellow_team_report: Optional[Dict[str, Any]] = None
    green_team_report: Optional[Dict[str, Any]] = None
    orange_team_report: Optional[Dict[str, Any]] = None
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exercise_id": self.exercise_id,
            "tenant_id": self.tenant_id,
            "scenario_name": self.scenario_name,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status,
            "red_team_stages": self.red_team_stages,
            "blue_team_alerts": self.blue_team_alerts,
            "aar": self.aar,
            "score": self.score,
            "white_team_report": self.white_team_report,
            "yellow_team_report": self.yellow_team_report,
            "green_team_report": self.green_team_report,
            "orange_team_report": self.orange_team_report,
            "errors": self.errors,
        }


class ExerciseOrchestrator:
    """Orchestrates full color-team exercises.

    Chains Red Team → Blue Team → Purple Team → Black Team.
    Uses the shared EventBus for inter-team communication.

    Usage::

        orchestrator = ExerciseOrchestrator(tenant_id="bank-abc")
        result = await orchestrator.run_exercise(
            scenario=ThreatScenario(...),
            teams=["red", "blue", "purple", "black"]
        )
    """

    def __init__(
        self,
        tenant_id: str = "default",
        event_bus: Optional[EventBus] = None,
        llm_provider: Optional[Any] = None,
    ):
        self.tenant_id = tenant_id
        self.event_bus = event_bus or EventBus()
        self.llm_provider = llm_provider
        self._active_exercises: Dict[str, ExerciseResult] = {}

        # Subscribe blue team handler to red team attack events
        self.event_bus.subscribe(EventType.RED_TEAM_ATTACK_STAGE, self._blue_team_handler)

    async def run_exercise(
        self,
        scenario: ThreatScenario,
        teams: Optional[List[str]] = None,
        exercise_id: Optional[str] = None,
    ) -> ExerciseResult:
        """Run a full color-team exercise.

        Args:
            scenario: The threat scenario to simulate
            teams: List of teams to activate (default: all)
            exercise_id: Optional ID for the exercise

        Returns:
            ExerciseResult with all team outputs
        """
        teams = teams or ["yellow", "white", "red", "blue", "purple", "black", "green", "orange"]
        exercise_id = exercise_id or str(uuid4())

        result = ExerciseResult(
            exercise_id=exercise_id,
            tenant_id=self.tenant_id,
            scenario_name=scenario.name,
            start_time=datetime.now(timezone.utc),
        )
        self._active_exercises[exercise_id] = result

        audit = get_audit_logger()
        audit.log(
            "exercise.started",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO,
            context={
                "exercise_id": exercise_id,
                "scenario": scenario.name,
                "teams": teams,
                "tenant_id": self.tenant_id,
            },
            description=f"Exercise started: {scenario.name}",
        )

        logger.info(
            "Starting exercise %s: scenario=%s teams=%s",
            exercise_id, scenario.name, teams,
        )

        try:
            # Yellow team provisions infrastructure first
            if "yellow" in teams:
                await self._run_yellow_team(scenario, result)

            # White team approves scope and sets ROE before red team runs
            if "white" in teams:
                await self._run_white_team(scenario, result)

            if "red" in teams:
                await self._run_red_team(scenario, result)

            if "blue" in teams:
                await self._run_blue_team(scenario, result)

            if "purple" in teams:
                await self._run_purple_team(result)

            if "black" in teams:
                await self._run_black_team(result)

            # Green team generates training plans from AAR findings
            if "green" in teams:
                await self._run_green_team(result)

            # Orange team maps findings to compliance frameworks
            if "orange" in teams:
                await self._run_orange_team(result)

            result.status = "completed"
            result.end_time = datetime.now(timezone.utc)

            audit.log(
                "exercise.completed",
                category=AuditCategory.SECURITY,
                severity=AuditSeverity.INFO,
                context={"exercise_id": exercise_id, "status": "completed"},
                description=f"Exercise completed: {scenario.name}",
            )
            logger.info("Exercise %s completed successfully", exercise_id)

        except Exception as exc:
            result.status = "failed"
            result.end_time = datetime.now(timezone.utc)
            result.errors.append(str(exc))
            logger.error("Exercise %s failed: %s", exercise_id, exc, exc_info=True)
            audit.log(
                "exercise.failed",
                category=AuditCategory.SECURITY,
                severity=AuditSeverity.ERROR,
                context={"exercise_id": exercise_id, "error": str(exc)},
            )
        finally:
            self._active_exercises.pop(exercise_id, None)

        return result

    async def _run_red_team(self, scenario: ThreatScenario, result: ExerciseResult) -> None:
        """Run the red team simulation and publish events to the bus."""
        logger.info("Exercise %s: starting red team phase", result.exercise_id)

        sim = Simulator(llm_provider=self.llm_provider)
        sim_result = await sim.execute_simulation(scenario)

        for stage in sim_result.stages:
            # Read technique_id/tactic/stage_name from metadata if not directly on stage
            meta = getattr(stage, "metadata", {}) or {}
            stage_event = RedTeamAttackStageEvent(
                tenant_id=self.tenant_id,
                stage_id=getattr(stage, "stage_id", str(uuid4())),
                stage_name=meta.get("stage_name") or getattr(stage, "stage_name", None) or getattr(stage, "stage_type", "unknown"),
                technique_id=meta.get("technique_id") or getattr(stage, "technique_id", "T0000"),
                tactic=meta.get("tactic") or getattr(stage, "tactic", "unknown"),
                content=getattr(stage, "content", ""),
                exercise_id=result.exercise_id,
                simulation_id=sim_result.result_id,
                llm_info=meta.get("llm_info") or {},
            )
            result.red_team_stages.append(stage_event.to_dict())
            try:
                await self.event_bus.publish(stage_event)
            except Exception as e:
                logger.warning(f"Failed to publish red team stage event: {e}")
                result.errors.append(f"Event publish failed: {e}")

        logger.info(
            "Exercise %s: red team phase complete (%d stages)",
            result.exercise_id, len(result.red_team_stages),
        )

    async def _blue_team_handler(self, event: BusEvent) -> None:
        """Event bus handler: blue team processes red team attack events."""
        exercise_id = event.exercise_id
        if exercise_id is None:
            return
        result = self._active_exercises.get(exercise_id)
        if result is None:
            return

        payload = event.payload
        technique_id = payload.get("technique_id", "T0000")
        detected = self._detect_technique(technique_id)

        alert = BlueTeamAlertEvent(
            tenant_id=self.tenant_id,
            alert_id=str(uuid4()),
            source_module="siem",
            technique_id=technique_id,
            severity="high" if detected else "info",
            description=(
                f"{'Detected' if detected else 'Missed'}: {technique_id} "
                f"in stage '{payload.get('stage_name', '')}'"
            ),
            detected=detected,
            stage_id=payload.get("stage_id"),
            exercise_id=exercise_id,
        )
        result.blue_team_alerts.append(alert.to_dict())
        try:
            await self.event_bus.publish(alert)
        except Exception as e:
            logger.warning(f"Failed to publish blue team alert event: {e}")

    def _detect_technique(self, technique_id: str) -> bool:
        """Deterministic ~70% detection rate based on technique ID hash."""
        import hashlib
        h = int(hashlib.md5(technique_id.encode()).hexdigest()[:4], 16)
        return (h % 10) < 7

    async def _run_blue_team(self, scenario: ThreatScenario, result: ExerciseResult) -> None:
        """Yield to allow pending event bus handlers to complete."""
        logger.info(
            "Exercise %s: blue team phase (%d alerts so far)",
            result.exercise_id, len(result.blue_team_alerts),
        )
        await asyncio.sleep(0)

    async def _run_purple_team(self, result: ExerciseResult) -> None:
        """Generate the after-action report from red + blue team data."""
        logger.info("Exercise %s: generating purple team AAR", result.exercise_id)

        from ciicerone.core.aar_generator import AARGenerator
        generator = AARGenerator(llm_provider=self.llm_provider)
        result.aar = await generator.generate_aar(
            exercise_id=result.exercise_id,
            red_team_stages=result.red_team_stages,
            blue_team_alerts=result.blue_team_alerts,
        )

        logger.info("Exercise %s: AAR generated", result.exercise_id)

    async def _run_black_team(self, result: ExerciseResult) -> None:
        """Score the exercise from the black team observer perspective."""
        logger.info("Exercise %s: running black team scoring", result.exercise_id)

        from ciicerone.core.evaluation_engine import EvaluationEngine
        engine = EvaluationEngine()
        result.score = engine.score_exercise(
            red_team_stages=result.red_team_stages,
            blue_team_alerts=result.blue_team_alerts,
            aar=result.aar,
        )

        logger.info(
            "Exercise %s: black team score = %s",
            result.exercise_id,
            result.score.get("overall_score") if result.score else "N/A",
        )

    def get_active_exercises(self) -> Dict[str, ExerciseResult]:
        """Return currently running exercises."""
        return dict(self._active_exercises)

    # -----------------------------------------------------------------------
    # Extended color teams
    # -----------------------------------------------------------------------

    async def _run_yellow_team(self, scenario: ThreatScenario, result: ExerciseResult) -> None:
        """Provision and validate the exercise infrastructure."""
        logger.info("Exercise %s: starting yellow team phase", result.exercise_id)

        from ciicerone.core.yellow_team import InfrastructureManager
        manager = InfrastructureManager()
        env_report = await manager.provision_environment(
            scenario=scenario,
            tenant_id=self.tenant_id,
        )
        result.yellow_team_report = env_report

        logger.info(
            "Exercise %s: yellow team phase complete (env_id=%s, ready=%s)",
            result.exercise_id,
            env_report.get("env_id"),
            env_report.get("ready"),
        )

    async def _run_white_team(self, scenario: ThreatScenario, result: ExerciseResult) -> None:
        """Set rules of engagement and approve scope before red team runs."""
        logger.info("Exercise %s: starting white team phase", result.exercise_id)

        from ciicerone.core.white_team import WhiteTeamCoordinator
        coordinator = WhiteTeamCoordinator()

        scenario_dict = {
            "name": scenario.name,
            "target_systems": getattr(scenario, "target_systems", []),
        }
        scope_approval = coordinator.approve_scope(
            scenario=scenario_dict,
            target_systems=getattr(scenario, "target_systems", []),
        )

        result.white_team_report = {
            "scope_approval": scope_approval,
            "roe_rules": [
                {"rule_id": r.rule_id, "description": r.description, "severity": r.severity}
                for r in coordinator.roe_rules
            ],
            "risk_pause_threshold": coordinator.risk_pause_threshold,
            "risk_abort_threshold": coordinator.risk_abort_threshold,
        }

        logger.info(
            "Exercise %s: white team phase complete (scope_approved=%s, roe_rules=%d)",
            result.exercise_id,
            scope_approval.get("approved"),
            len(coordinator.roe_rules),
        )

    async def _run_green_team(self, result: ExerciseResult) -> None:
        """Generate training plans from AAR findings."""
        logger.info("Exercise %s: starting green team phase", result.exercise_id)

        from ciicerone.core.green_team import TrainingAwarenessEngine
        engine = TrainingAwarenessEngine(llm_provider=self.llm_provider)

        training_needs = engine.analyze_training_needs(
            aar=result.aar,
            score=result.score,
            red_team_stages=result.red_team_stages,
            blue_team_alerts=result.blue_team_alerts,
        )

        training_plan = engine.generate_training_plan(
            training_needs=training_needs,
            tenant_id=self.tenant_id,
        )

        awareness = engine.assess_awareness_level(
            blue_team_alerts=result.blue_team_alerts,
            red_team_stages=result.red_team_stages,
        )

        result.green_team_report = {
            "training_needs": training_needs,
            "training_plan": training_plan,
            "awareness_assessment": awareness,
        }

        logger.info(
            "Exercise %s: green team phase complete (modules=%d, awareness=%s)",
            result.exercise_id,
            len(training_plan.get("modules", [])),
            awareness.get("level"),
        )

    async def _run_orange_team(self, result: ExerciseResult) -> None:
        """Map findings to compliance frameworks and identify gaps."""
        logger.info("Exercise %s: starting orange team phase", result.exercise_id)

        from ciicerone.core.orange_team import ComplianceGovernanceEngine
        engine = ComplianceGovernanceEngine()

        framework_mapping = engine.map_to_frameworks(
            red_team_stages=result.red_team_stages,
            blue_team_alerts=result.blue_team_alerts,
            aar=result.aar,
        )

        compliance_gaps = engine.analyze_compliance_gaps(framework_mapping)

        compliance_report = engine.generate_compliance_report(
            exercise_id=result.exercise_id,
            framework_mapping=framework_mapping,
            compliance_gaps=compliance_gaps,
        )

        result.orange_team_report = {
            "framework_mapping": framework_mapping,
            "compliance_gaps": compliance_gaps,
            "compliance_report": compliance_report,
        }

        logger.info(
            "Exercise %s: orange team phase complete (frameworks=%d, gaps=%d)",
            result.exercise_id,
            len(framework_mapping),
            len(compliance_gaps),
        )
