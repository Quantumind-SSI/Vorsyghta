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
        teams = teams or ["red", "blue", "purple", "black"]
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
            if "red" in teams:
                await self._run_red_team(scenario, result)

            if "blue" in teams:
                await self._run_blue_team(scenario, result)

            if "purple" in teams:
                await self._run_purple_team(result)

            if "black" in teams:
                await self._run_black_team(result)

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
            )
            result.red_team_stages.append(stage_event.to_dict())
            await self.event_bus.publish(stage_event)

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
        await self.event_bus.publish(alert)

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
