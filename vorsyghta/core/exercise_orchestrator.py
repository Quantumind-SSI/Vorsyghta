"""Exercise orchestrator for Vorsyghta color-team exercises.

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

from vorsyghta.core.event_bus import EventBus
from vorsyghta.core.event_types import (
    BusEvent, BlueTeamAlertEvent, EventType, RedTeamAttackStageEvent,
)
from vorsyghta.core.audit_logger import AuditCategory, AuditSeverity, get_audit_logger
from vorsyghta.core.models import ThreatScenario
from vorsyghta.core.simulator import Simulator

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
        # Event bus: injected or built in-process. Event store attaches lazily
        # (build_event_store is async); run_exercise awaits it once per bus.
        if event_bus is None:
            event_bus = EventBus()
        self.event_bus = event_bus
        self.llm_provider = llm_provider
        self._store_attach_attempted = False
        self._blue_integration: Optional[Any] = None
        self._active_exercises: Dict[str, ExerciseResult] = {}

        # Subscribe blue team handler to red team attack events
        self.event_bus.subscribe(EventType.RED_TEAM_ATTACK_STAGE, self._blue_team_handler)

    async def _ensure_event_store(self) -> None:
        """Attach a durable event store to the bus if it lacks one.

        build_event_store() is async (Postgres store initializes on create),
        so attachment happens on first exercise instead of __init__.
        """
        if self._store_attach_attempted:
            return
        self._store_attach_attempted = True
        if getattr(self.event_bus, "has_event_store", False):
            return
        try:
            from vorsyghta.core.contracts import build_event_store

            store = await build_event_store()
            self.event_bus.attach_event_store(store)
            logger.info("Event bus persistence attached: %s", type(store).__name__)
        except Exception as exc:  # noqa: BLE001 - persistence is best-effort
            logger.warning("Event store attach failed, continuing without persistence: %s", exc)

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
        await self._ensure_event_store()
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

            # White team approves scope and sets ROE before red team runs.
            # Denial aborts the exercise before any attack activity.
            if "white" in teams:
                await self._run_white_team(scenario, result)
                approval = (result.white_team_report or {}).get("scope_approval", {})
                if approval.get("approved") is False:
                    result.status = "aborted"
                    result.end_time = datetime.now(timezone.utc)
                    audit.log(
                        "exercise.aborted",
                        category=AuditCategory.SECURITY,
                        severity=AuditSeverity.WARNING,
                        context={
                            "exercise_id": exercise_id,
                            "reason": approval.get("reason"),
                            "out_of_scope_targets": approval.get("out_of_scope_targets"),
                            "production_targets": approval.get("production_targets"),
                        },
                        description=f"Exercise aborted by white team: {approval.get('reason')}",
                    )
                    logger.warning(
                        "Exercise %s aborted by white team: %s",
                        exercise_id, approval.get("reason"),
                    )
                    return result

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

            # Yellow team tears the environment down after all teams finish
            if "yellow" in teams:
                await self._run_yellow_teardown(result)

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

        # Wire the blue defense modules before the first stage publishes so
        # every stage is evaluated by SIEM/IDS/EDR in the same run.
        if self._blue_integration is None:
            from vorsyghta.defense.blue_team.bus_integration import BlueTeamBusIntegration

            self._blue_integration = BlueTeamBusIntegration(
                bus=self.event_bus,
                tenant_id=self.tenant_id,
                exercise_id=result.exercise_id,
            )

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
        """Event bus handler: blue team evaluates each red team attack stage.

        Detection is delegated to the real blue defense modules (SIEM
        correlation, IDS, EDR) via :class:`BlueTeamBusIntegration` when
        available. Each stage is recorded as an alert with an explicit
        detected flag so downstream scoring/AAR reflect real coverage.
        """
        exercise_id = event.exercise_id
        if exercise_id is None:
            return
        result = self._active_exercises.get(exercise_id)
        if result is None:
            return

        payload = event.payload
        technique_id = payload.get("technique_id", "T0000")
        stage_id = payload.get("stage_id")
        blue = self._blue_integration
        alerts: List[BlueTeamAlertEvent] = []

        # Real detection: run the blue defense modules against the stage.
        module_alerts = self._run_blue_detection(blue, payload) if blue is not None else []

        if module_alerts:
            # Aggregate module detections into a single stage alert so the
            # stage↔alert mapping stays 1:1 for scoring and AAR.
            source_modules = sorted({a.source for a in module_alerts})
            severities = [a.severity for a in module_alerts]
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            top_severity = min(severities, key=lambda s: sev_rank.get(s, 4))
            alerts.append(BlueTeamAlertEvent(
                tenant_id=self.tenant_id,
                alert_id=f"detect-{stage_id or uuid4()}",
                source_module="+".join(source_modules),
                technique_id=module_alerts[0].mitre_techniques[0]
                if module_alerts[0].mitre_techniques else technique_id,
                severity=top_severity,
                description=(
                    f"Detected: {len(module_alerts)} module alert(s) for {technique_id} "
                    f"in stage '{payload.get('stage_name', '')}'"
                ),
                detected=True,
                stage_id=stage_id,
                iocs=payload.get("iocs", []),
                raw_data={
                    "module_alerts": [
                        {"title": a.title, "severity": a.severity, "source": a.source,
                         "description": a.description}
                        for a in module_alerts
                    ],
                },
                exercise_id=exercise_id,
                simulation_id=event.simulation_id,
            ))
        else:
            # Stage not detected by any module: record an explicit miss.
            alerts.append(BlueTeamAlertEvent(
                tenant_id=self.tenant_id,
                alert_id=f"miss-{stage_id or uuid4()}",
                source_module="orchestrator",
                technique_id=technique_id,
                severity="info",
                description=(
                    f"Missed: {technique_id} in stage '{payload.get('stage_name', '')}'"
                ),
                detected=False,
                stage_id=stage_id,
                exercise_id=exercise_id,
                simulation_id=event.simulation_id,
            ))

        for alert in alerts:
            result.blue_team_alerts.append(alert.to_dict())
            try:
                await self.event_bus.publish(alert)
            except Exception as e:
                logger.warning("Failed to publish blue team alert event: %s", e)

    def _run_blue_detection(self, blue: Any, payload: Dict[str, Any]) -> List[Any]:
        """Run blue defense modules against a single red stage payload.

        Returns raw module alerts (SIEMAlert-shaped) for the stage.
        """
        content = payload.get("content", "")
        technique_id = payload.get("technique_id", "")
        stage_id = payload.get("stage_id", "")
        timestamp = datetime.now(timezone.utc).isoformat()
        alerts: List[Any] = []

        try:
            # SIEM: ingest stage as a log entry and run correlation rules.
            from vorsyghta.defense.blue_team.siem_simulator import SIEMSimulator

            siem: SIEMSimulator = blue.siem
            siem.ingest_log({
                "source": "red_team_simulator",
                "message": content,
                "mitre_technique": technique_id,
                "stage_id": stage_id,
                "timestamp": timestamp,
            })
            alerts.extend(siem.check_correlations())
        except Exception as exc:  # noqa: BLE001 - per-module isolation
            logger.debug("SIEM detection failed for stage %s: %s", stage_id, exc)

        try:
            # IDS: inspect a network packet derived from the stage.
            from vorsyghta.defense.blue_team.ids_detector import IDSDetector, NetworkPacket

            ids: IDSDetector = blue.ids
            technique_ports = {
                "T1046": 80, "T1190": 80, "T1110": 22, "T1003": 445,
                "T1059": 443, "T1071": 443, "T1041": 443, "T1048": 53,
                "T1505": 80, "T1136": 445,
            }
            packet = NetworkPacket(
                timestamp=timestamp,
                protocol="tcp",
                source_ip="10.0.0.5",
                source_port=12345,
                dest_ip="10.0.0.10",
                dest_port=technique_ports.get(technique_id, 80),
                payload=content[:1000],
            )
            alerts.extend(ids.inspect_packet(packet))
        except Exception as exc:  # noqa: BLE001 - per-module isolation
            logger.debug("IDS detection failed for stage %s: %s", stage_id, exc)

        try:
            # EDR: process/file/network/registry telemetry from stage content.
            from vorsyghta.defense.blue_team.edr_agent import (
                EDRAgent, FileEvent, ProcessEvent,
            )

            edr: EDRAgent = blue.edr
            process_event = ProcessEvent(
                pid=1,
                process_name="attack.exe",
                command_line=content,
                user="attacker",
                timestamp=timestamp,
            )
            alerts.extend(edr.monitor_process(process_event))

            file_event = FileEvent(
                path=f"/tmp/{stage_id}.dat",
                operation="create",
                process="attack.exe",
                user="attacker",
                timestamp=timestamp,
            )
            alerts.extend(edr.monitor_file(file_event))
        except Exception as exc:  # noqa: BLE001 - per-module isolation
            logger.debug("EDR detection failed for stage %s: %s", stage_id, exc)

        return alerts

    async def _run_blue_team(self, scenario: ThreatScenario, result: ExerciseResult) -> None:
        """Blue team phase: yield to let queued alert handlers complete."""
        logger.info(
            "Exercise %s: blue team phase (%d alerts so far)",
            result.exercise_id, len(result.blue_team_alerts),
        )
        await asyncio.sleep(0)

    async def _run_purple_team(self, result: ExerciseResult) -> None:
        """Generate the after-action report from red + blue team data."""
        logger.info("Exercise %s: generating purple team AAR", result.exercise_id)

        from vorsyghta.core.aar_generator import AARGenerator
        generator = AARGenerator(llm_provider=self.llm_provider)
        result.aar = await generator.generate_aar(
            exercise_id=result.exercise_id,
            red_team_stages=result.red_team_stages,
            blue_team_alerts=result.blue_team_alerts,
        )
        await self._publish_typed(
            EventType.PURPLE_TEAM_AAR,
            payload={
                "aar_id": result.exercise_id,
                "aar": result.aar,
                "red_team_stages": result.red_team_stages,
                "blue_team_alerts": result.blue_team_alerts,
                "score": None,
            },
            exercise_id=result.exercise_id,
        )

        logger.info("Exercise %s: AAR generated", result.exercise_id)

    async def _run_black_team(self, result: ExerciseResult) -> None:
        """Score the exercise from the black team observer perspective."""
        logger.info("Exercise %s: running black team scoring", result.exercise_id)

        from vorsyghta.core.evaluation_engine import EvaluationEngine
        engine = EvaluationEngine()
        result.score = engine.score_exercise(
            red_team_stages=result.red_team_stages,
            blue_team_alerts=result.blue_team_alerts,
            aar=result.aar,
        )
        await self._publish_typed(
            EventType.BLACK_TEAM_SCORE,
            payload={"score": result.score},
            exercise_id=result.exercise_id,
        )

        logger.info(
            "Exercise %s: black team score = %s",
            result.exercise_id,
            result.score.get("overall_score") if result.score else "N/A",
        )

    async def _publish_typed(
        self,
        event_type: EventType,
        payload: Dict[str, Any],
        exercise_id: Optional[str] = None,
    ) -> None:
        """Publish a generic BusEvent of ``event_type`` on the shared bus."""
        try:
            await self.event_bus.publish(BusEvent(
                event_type=event_type,
                tenant_id=self.tenant_id,
                exercise_id=exercise_id,
                payload=payload,
            ))
        except Exception as e:
            logger.warning("Failed to publish %s event: %s", event_type.value, e)

    def get_active_exercises(self) -> Dict[str, ExerciseResult]:
        """Return currently running exercises."""
        return dict(self._active_exercises)

    # -----------------------------------------------------------------------
    # Extended color teams
    # -----------------------------------------------------------------------

    async def _run_yellow_team(self, scenario: ThreatScenario, result: ExerciseResult) -> None:
        """Provision and validate the exercise infrastructure."""
        logger.info("Exercise %s: starting yellow team phase", result.exercise_id)

        from vorsyghta.core.yellow_team import InfrastructureManager
        self._yellow_manager = InfrastructureManager()
        env_report = await self._yellow_manager.provision_environment(
            scenario=scenario,
            tenant_id=self.tenant_id,
            exercise_id=result.exercise_id,
        )
        result.yellow_team_report = env_report

        logger.info(
            "Exercise %s: yellow team phase complete (env_id=%s, ready=%s)",
            result.exercise_id,
            env_report.get("env_id"),
            env_report.get("ready"),
        )
        await self._publish_typed(
            EventType.YELLOW_TEAM_ENV_READY,
            payload={
                "env_id": env_report.get("env_id"),
                "components": env_report.get("components", []),
                "vm_ids": env_report.get("vm_ids", []),
                "network_config": env_report.get("network_config", {}),
                "ready": env_report.get("ready", False),
                "issues": env_report.get("issues", []),
            },
            exercise_id=result.exercise_id,
        )

    async def _run_yellow_teardown(self, result: ExerciseResult) -> None:
        """Tear down the provisioned environment and publish the event."""
        env_report = result.yellow_team_report or {}
        env_id = env_report.get("env_id")
        if not env_id:
            return
        manager = getattr(self, "_yellow_manager", None)
        if manager is None:
            return
        teardown_report = await manager.teardown_environment(env_id)
        await self._publish_typed(
            EventType.YELLOW_TEAM_ENV_TEARDOWN,
            payload={
                "env_id": env_id,
                "status": teardown_report.get("status"),
            },
            exercise_id=result.exercise_id,
        )
        logger.info(
            "Exercise %s: yellow team teardown complete (env_id=%s, status=%s)",
            result.exercise_id, env_id, teardown_report.get("status"),
        )

    async def _run_white_team(self, scenario: ThreatScenario, result: ExerciseResult) -> None:
        """Set rules of engagement and approve scope before red team runs."""
        logger.info("Exercise %s: starting white team phase", result.exercise_id)

        from vorsyghta.core.white_team import WhiteTeamCoordinator
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
        await self._publish_typed(
            EventType.WHITE_TEAM_SCOPE_APPROVAL,
            payload={
                "approved": scope_approval.get("approved"),
                "approved_targets": scope_approval.get("approved_targets", []),
                "out_of_scope_targets": scope_approval.get("out_of_scope_targets", []),
                "production_targets": scope_approval.get("production_targets", []),
                "reason": scope_approval.get("reason"),
            },
            exercise_id=result.exercise_id,
        )

        logger.info(
            "Exercise %s: white team phase complete (scope_approved=%s, roe_rules=%d)",
            result.exercise_id,
            scope_approval.get("approved"),
            len(coordinator.roe_rules),
        )

    async def _run_green_team(self, result: ExerciseResult) -> None:
        """Generate training plans from AAR findings."""
        logger.info("Exercise %s: starting green team phase", result.exercise_id)

        from vorsyghta.core.green_team import TrainingAwarenessEngine
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

        from vorsyghta.core.orange_team import ComplianceGovernanceEngine
        engine = ComplianceGovernanceEngine()

        framework_mapping = engine.map_to_frameworks(
            red_team_stages=result.red_team_stages,
            blue_team_alerts=result.blue_team_alerts,
            aar=result.aar,
        )

        compliance_gaps = engine.analyze_compliance_gaps(framework_mapping)

        compliance_report = await engine.generate_compliance_report(
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
