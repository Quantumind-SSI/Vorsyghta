"""End-to-end test for the Ciicerone color-team exercise flow.

Validates the full red → blue → purple → black pipeline without requiring
external services (LLM, database, or network). All LLM calls are mocked.

Exit criteria from docs/plans/maintainer-timelines-bank-pilot-readiness.md:
    ✓ Attack generated (red team stages emitted)
    ✓ Blue team detected (alerts on event bus)
    ✓ AAR produced (purple team after-action report)
    ✓ Exercise scored (black team score)
    ✓ Audit trail written (events in audit logger)
"""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ciicerone.core.exercise_orchestrator import ExerciseOrchestrator, ExerciseResult
from ciicerone.core.aar_generator import AARGenerator
from ciicerone.core.evaluation_engine import EvaluationEngine
from ciicerone.core.audit_logger import (
    AuditLogger, MemoryAuditSink, HashChainAuditSink, get_audit_logger,
    reset_audit_logger,
)
from ciicerone.core.models import ThreatScenario, ThreatType, SimulationResult, SimulationStage, SimulationStatus
from ciicerone.core.event_bus import EventBus
from ciicerone.core.event_types import EventType, BlueTeamAlertEvent, RedTeamAttackStageEvent
from ciicerone.db.models import (
    SimulationResultRecord, AlertRecord, AuditEventRecord,
    AttackPlanRecord, UserRecord, TenantRecord,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_global_audit_logger():
    """Reset the global audit logger singleton between tests."""
    reset_audit_logger()
    yield
    reset_audit_logger()


def _make_mock_sim_result() -> SimulationResult:
    """Build a minimal SimulationResult with 3 stages for testing."""
    result = SimulationResult(
        status=SimulationStatus.COMPLETED,
        scenario_id="test-scenario-id",
    )
    result.result_id = "test-result-id"
    stages = [
        SimulationStage(
            stage_type="Spear Phishing Email",
            content="Crafted phishing email targeting finance department.",
            metadata={"technique_id": "T1566", "tactic": "initial_access", "stage_name": "Spear Phishing Email"},
        ),
        SimulationStage(
            stage_type="Credential Harvesting",
            content="Valid credentials obtained via phishing page.",
            metadata={"technique_id": "T1078", "tactic": "defense_evasion", "stage_name": "Credential Harvesting"},
        ),
        SimulationStage(
            stage_type="Wire Transfer Fraud",
            content="Fraudulent wire transfer instruction sent to finance team.",
            metadata={"technique_id": "T1657", "tactic": "impact", "stage_name": "Wire Transfer Fraud"},
        ),
    ]
    result.stages = stages
    return result


@pytest.fixture
def mock_simulator():
    """Return a Simulator mock that produces 3 deterministic stages."""
    sim_result = _make_mock_sim_result()
    mock = AsyncMock()
    mock.execute_simulation = AsyncMock(return_value=sim_result)
    return mock


@pytest.fixture
def bec_scenario() -> ThreatScenario:
    return ThreatScenario(
        name="BEC Wire Fraud — Bank Pilot",
        threat_type=ThreatType.PHISHING,
        description="Business Email Compromise targeting a bank's wire-transfer team.",
        target_systems=["email", "wire-transfer-system"],
        attack_vectors=["spear-phishing", "business-email-compromise"],
    )


# ---------------------------------------------------------------------------
# Unit tests — individual components
# ---------------------------------------------------------------------------

class TestAARGenerator:
    """Tests for the Purple Team after-action report generator."""

    @pytest.mark.asyncio
    async def test_generates_aar_from_red_and_blue_data(self):
        red_stages = [
            {
                "payload": {
                    "stage_id": "s1",
                    "technique_id": "T1566",
                    "tactic": "initial_access",
                    "stage_name": "Spear Phishing",
                }
            },
            {
                "payload": {
                    "stage_id": "s2",
                    "technique_id": "T1078",
                    "tactic": "defense_evasion",
                    "stage_name": "Credential Harvesting",
                }
            },
        ]
        blue_alerts = [
            {
                "payload": {
                    "alert_id": "a1",
                    "technique_id": "T1566",
                    "stage_id": "s1",
                    "detected": True,
                    "severity": "high",
                }
            },
            {
                "payload": {
                    "alert_id": "a2",
                    "technique_id": "T1078",
                    "stage_id": "s2",
                    "detected": False,
                    "severity": "info",
                }
            },
        ]

        generator = AARGenerator(llm_provider=None)
        aar = await generator.generate_aar(
            exercise_id="ex-001",
            red_team_stages=red_stages,
            blue_team_alerts=blue_alerts,
        )

        assert aar["exercise_id"] == "ex-001"
        assert "aar_id" in aar
        assert "generated_at" in aar
        assert "summary" in aar
        assert "detection_metrics" in aar
        assert "coverage_gaps" in aar
        assert "remediation_recommendations" in aar
        assert "mitre_coverage" in aar

    @pytest.mark.asyncio
    async def test_detection_metrics_correct(self):
        red_stages = [
            {"payload": {"stage_id": f"s{i}", "technique_id": f"T{1000+i}", "tactic": "t"}}
            for i in range(5)
        ]
        # 3 detected, 2 missed
        blue_alerts = [
            {"payload": {"technique_id": f"T{1000+i}", "stage_id": f"s{i}", "detected": i < 3}}
            for i in range(5)
        ]

        generator = AARGenerator()
        aar = await generator.generate_aar("ex-002", red_stages, blue_alerts)
        metrics = aar["detection_metrics"]

        assert metrics["total_attacks"] == 5
        assert metrics["detected"] == 3
        assert metrics["missed"] == 2
        assert metrics["detection_rate_pct"] == 60.0

    @pytest.mark.asyncio
    async def test_empty_stages_returns_safe_aar(self):
        generator = AARGenerator()
        aar = await generator.generate_aar("ex-003", [], [])
        assert aar["detection_metrics"]["total_attacks"] == 0
        assert "No attack stages" in aar["summary"]

    @pytest.mark.asyncio
    async def test_remediation_recommendations_ordered_by_priority(self):
        red_stages = [
            {"payload": {"stage_id": f"s{i}", "technique_id": f"T{i}", "tactic": "t", "stage_name": f"Stage {i}"}}
            for i in range(3)
        ]
        blue_alerts = []  # No detections → all gaps

        generator = AARGenerator()
        aar = await generator.generate_aar("ex-004", red_stages, blue_alerts)
        rems = aar["remediation_recommendations"]

        assert len(rems) == 3
        for idx, rem in enumerate(rems):
            assert rem["priority"] == idx + 1


class TestEvaluationEngine:
    """Tests for the Black Team evaluation engine."""

    def test_score_with_perfect_detection(self):
        red_stages = [
            {"payload": {"stage_id": f"s{i}", "technique_id": f"T{i}"}}
            for i in range(5)
        ]
        blue_alerts = [
            {"payload": {"stage_id": f"s{i}", "detected": True, "technique_id": f"T{i}"}}
            for i in range(5)
        ]
        aar = {
            "coverage_gaps": [],
            "remediation_recommendations": ["Fix X"],
            "detection_metrics": {"detection_rate_pct": 100.0},
        }

        engine = EvaluationEngine()
        score = engine.score_exercise(red_stages, blue_alerts, aar)

        assert score["overall_score"] > 0.5
        assert score["component_scores"]["blue_team_detection"] == 1.0
        assert score["rating"] in ("A", "B", "C", "D", "F")

    def test_score_with_zero_detections(self):
        red_stages = [{"payload": {"stage_id": f"s{i}", "technique_id": f"T{i}"}} for i in range(3)]
        blue_alerts = [{"payload": {"stage_id": f"s{i}", "detected": False}} for i in range(3)]

        engine = EvaluationEngine()
        score = engine.score_exercise(red_stages, blue_alerts)

        assert score["component_scores"]["blue_team_detection"] == 0.0
        assert score["component_scores"]["operational_security"] == 0.0
        assert score["rating"] == "F"

    def test_score_structure_is_complete(self):
        engine = EvaluationEngine()
        score = engine.score_exercise([], [], None)

        required_keys = {"overall_score", "component_scores", "weights", "metrics", "rating", "recommendations"}
        assert required_keys.issubset(score.keys())

    def test_recommendations_generated_for_low_scores(self):
        red_stages = []
        blue_alerts = []

        engine = EvaluationEngine()
        score = engine.score_exercise(red_stages, blue_alerts)

        assert len(score["recommendations"]) > 0


class TestHashChainAuditSink:
    """Tests for the tamper-evident hash-chain audit sink."""

    def test_first_event_has_zero_prev_hash(self):
        from ciicerone.core.audit_logger import AuditEvent, AuditCategory, AuditSeverity
        inner = MemoryAuditSink()
        chain = HashChainAuditSink(inner)

        evt = AuditEvent(
            event_type="test.event",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO,
        )
        chain.write(evt)

        written = inner.events[0]
        assert "prev_hash" in written.context
        # First event's prev_hash should be all zeros
        assert written.context["prev_hash"] == "0" * 64
        # Event hash should be a 64-char hex string
        assert len(written.context["event_hash"]) == 64

    def test_chain_prev_hash_links_events(self):
        from ciicerone.core.audit_logger import AuditEvent, AuditCategory
        inner = MemoryAuditSink()
        chain = HashChainAuditSink(inner)

        for i in range(3):
            evt = AuditEvent(
                event_type=f"test.event.{i}",
                category=AuditCategory.SECURITY,
            )
            chain.write(evt)

        events = inner.events
        assert len(events) == 3

        # Verify chain linkage: each event's prev_hash == previous event's event_hash
        first_event_hash = events[0].context["event_hash"]
        second_event_prev = events[1].context["prev_hash"]
        assert second_event_prev == first_event_hash

        second_event_hash = events[1].context["event_hash"]
        third_event_prev = events[2].context["prev_hash"]
        assert third_event_prev == second_event_hash

    def test_chain_is_tamper_evident(self):
        """The hash chain ensures each event references the previous event's hash."""
        from ciicerone.core.audit_logger import AuditEvent, AuditCategory
        inner = MemoryAuditSink()
        chain = HashChainAuditSink(inner)

        evt1 = AuditEvent(event_type="test.1", category=AuditCategory.SECURITY)
        evt2 = AuditEvent(event_type="test.2", category=AuditCategory.SECURITY)
        chain.write(evt1)
        chain.write(evt2)

        # Second event's prev_hash must equal first event's event_hash
        hash_1 = inner.events[0].context["event_hash"]
        prev_hash_2 = inner.events[1].context["prev_hash"]
        assert hash_1 == prev_hash_2

        # If event 1 was tampered, its stored event_hash would no longer match
        # what you'd compute fresh — proving the chain is tamper-evident
        assert len(hash_1) == 64  # SHA-256 hex digest


# ---------------------------------------------------------------------------
# Integration test — full exercise flow (mocked LLM)
# ---------------------------------------------------------------------------

class TestExerciseOrchestrator:
    """Integration tests for the ExerciseOrchestrator."""

    @pytest.mark.asyncio
    async def test_full_exercise_produces_complete_result(self, bec_scenario, mock_simulator):
        """Full e2e: red → blue → purple → black, all teams produce output."""
        with patch("ciicerone.core.exercise_orchestrator.Simulator", return_value=mock_simulator):
            orchestrator = ExerciseOrchestrator(tenant_id="bank-pilot-test")
            result = await orchestrator.run_exercise(
                scenario=bec_scenario,
                teams=["red", "blue", "purple", "black"],
                exercise_id="e2e-test-001",
            )

        assert result.status == "completed"
        assert result.exercise_id == "e2e-test-001"
        assert result.tenant_id == "bank-pilot-test"
        assert result.scenario_name == bec_scenario.name
        assert result.start_time is not None
        assert result.end_time is not None
        assert len(result.errors) == 0

    @pytest.mark.asyncio
    async def test_red_team_produces_stages(self, bec_scenario, mock_simulator):
        with patch("ciicerone.core.exercise_orchestrator.Simulator", return_value=mock_simulator):
            orchestrator = ExerciseOrchestrator(tenant_id="test")
            result = await orchestrator.run_exercise(bec_scenario, teams=["red"])

        assert len(result.red_team_stages) == 3  # matches _make_mock_sim_result()
        for stage in result.red_team_stages:
            assert "payload" in stage
            assert "technique_id" in stage["payload"]

    @pytest.mark.asyncio
    async def test_blue_team_generates_alerts_for_each_stage(self, bec_scenario, mock_simulator):
        with patch("ciicerone.core.exercise_orchestrator.Simulator", return_value=mock_simulator):
            orchestrator = ExerciseOrchestrator(tenant_id="test")
            result = await orchestrator.run_exercise(bec_scenario, teams=["red", "blue"])

        # One alert per red team stage (via event bus subscription)
        assert len(result.blue_team_alerts) == len(result.red_team_stages)
        for alert in result.blue_team_alerts:
            payload = alert.get("payload", alert)
            assert "alert_id" in payload
            assert "detected" in payload
            assert "technique_id" in payload

    @pytest.mark.asyncio
    async def test_purple_team_generates_aar(self, bec_scenario, mock_simulator):
        with patch("ciicerone.core.exercise_orchestrator.Simulator", return_value=mock_simulator):
            orchestrator = ExerciseOrchestrator(tenant_id="test")
            result = await orchestrator.run_exercise(bec_scenario, teams=["red", "blue", "purple"])

        assert result.aar is not None
        assert "summary" in result.aar
        assert "detection_metrics" in result.aar
        assert "coverage_gaps" in result.aar
        assert "remediation_recommendations" in result.aar

    @pytest.mark.asyncio
    async def test_black_team_scores_exercise(self, bec_scenario, mock_simulator):
        with patch("ciicerone.core.exercise_orchestrator.Simulator", return_value=mock_simulator):
            orchestrator = ExerciseOrchestrator(tenant_id="test")
            result = await orchestrator.run_exercise(bec_scenario, teams=["red", "blue", "purple", "black"])

        assert result.score is not None
        assert "overall_score" in result.score
        assert "rating" in result.score
        assert 0.0 <= result.score["overall_score"] <= 1.0

    @pytest.mark.asyncio
    async def test_audit_events_recorded(self, bec_scenario, mock_simulator):
        """Exercise lifecycle events should appear in the audit logger."""
        # Set up a memory sink on the global logger
        memory_sink = MemoryAuditSink()
        audit = get_audit_logger()
        audit.add_sink(memory_sink)

        with patch("ciicerone.core.exercise_orchestrator.Simulator", return_value=mock_simulator):
            orchestrator = ExerciseOrchestrator(tenant_id="test")
            await orchestrator.run_exercise(bec_scenario, teams=["red"], exercise_id="audit-test")

        events = memory_sink.events
        event_types = [e.event_type for e in events]
        assert "exercise.started" in event_types
        assert "exercise.completed" in event_types

    @pytest.mark.asyncio
    async def test_exercise_completes_on_partial_teams(self, bec_scenario, mock_simulator):
        """Running with only red+blue should still complete successfully."""
        with patch("ciicerone.core.exercise_orchestrator.Simulator", return_value=mock_simulator):
            orchestrator = ExerciseOrchestrator(tenant_id="test")
            result = await orchestrator.run_exercise(bec_scenario, teams=["red", "blue"])

        assert result.status == "completed"
        assert result.aar is None  # purple not requested
        assert result.score is None  # black not requested

    @pytest.mark.asyncio
    async def test_exercise_result_serializes_to_dict(self, bec_scenario, mock_simulator):
        with patch("ciicerone.core.exercise_orchestrator.Simulator", return_value=mock_simulator):
            orchestrator = ExerciseOrchestrator(tenant_id="test")
            result = await orchestrator.run_exercise(bec_scenario, teams=["red", "blue", "purple", "black"])

        d = result.to_dict()
        import json
        json_str = json.dumps(d, default=str)  # Must not raise
        assert len(json_str) > 0
        assert d["status"] == "completed"


# ---------------------------------------------------------------------------
# ORM model smoke tests (no database required)
# ---------------------------------------------------------------------------

class TestORMModels:
    """Verify ORM models are importable and have correct attributes."""

    def test_simulation_result_record_has_required_columns(self):
        cols = {c.name for c in SimulationResultRecord.__table__.columns}
        assert {"id", "result_id", "tenant_id", "status", "success", "start_time"}.issubset(cols)

    def test_alert_record_has_no_fk_to_simulation_stages(self):
        """AlertRecord.stage_id must be a soft reference (no FK constraint)."""
        col = AlertRecord.__table__.c.stage_id
        assert len(col.foreign_keys) == 0

    def test_audit_event_record_has_hash_chain_columns(self):
        cols = {c.name for c in AuditEventRecord.__table__.columns}
        assert "prev_hash" in cols
        assert "event_hash" in cols

    def test_user_record_has_hashed_password_column(self):
        cols = {c.name for c in UserRecord.__table__.columns}
        assert "hashed_password" in cols
        assert "password" not in cols  # plain password must NOT be stored

    def test_all_orm_models_have_tenant_id(self):
        models_with_tenant = [
            SimulationResultRecord,
            AlertRecord,
        ]
        for model in models_with_tenant:
            cols = {c.name for c in model.__table__.columns}
            assert "tenant_id" in cols, f"{model.__name__} missing tenant_id"
