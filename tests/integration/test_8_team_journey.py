"""Full 8-team journey: red→blue→purple→black→green→orange with yellow
infrastructure and white governance gates, driven through the real
ExerciseOrchestrator with a mocked Simulator (deterministic stages)."""

import pytest

from vorsyghta.core.exercise_orchestrator import ExerciseOrchestrator
from vorsyghta.core.models import SimulationResult, SimulationStage, SimulationStatus, ThreatScenario, ThreatType
from vorsyghta.core.worker.teams import create_all_workers

TEAMS = ["yellow", "white", "red", "blue", "purple", "black", "green", "orange"]


def _sim_result() -> SimulationResult:
    result = SimulationResult(
        status=SimulationStatus.COMPLETED,
        scenario_id="test-scenario-id",
    )
    result.result_id = "test-result-id"
    result.stages = [
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
    ]
    return result


def _scenario() -> ThreatScenario:
    return ThreatScenario(
        name="8-Team Journey",
        threat_type=ThreatType.PHISHING,
        description="Journey across all eight color teams.",
        target_systems=["email"],
        attack_vectors=["spear-phishing"],
    )


async def _run_journey(monkeypatch) -> "ExerciseResult":
    """Run the full 8-team exercise with a deterministic Simulator."""
    from unittest.mock import AsyncMock

    simulator = AsyncMock()
    simulator.execute_simulation = AsyncMock(return_value=_sim_result())
    monkeypatch.setattr(
        "vorsyghta.core.exercise_orchestrator.Simulator",
        lambda llm_provider=None: simulator,
    )

    orchestrator = ExerciseOrchestrator(tenant_id="bank-abc")
    return await orchestrator.run_exercise(
        scenario=_scenario(),
        teams=TEAMS,
        exercise_id="journey-001",
    )


@pytest.mark.asyncio
async def test_worker_factories_cover_all_eight_teams():
    workers = create_all_workers(broker=None)  # construct all 8 without a live Redis
    assert {w.name for w in workers} == set(TEAMS)


@pytest.mark.asyncio
async def test_journey_pipeline_outputs(monkeypatch):
    """Red/blue/purple/black produce stages, alerts, AAR and a score."""
    result = await _run_journey(monkeypatch)

    assert result.status == "completed"
    assert len(result.red_team_stages) == 2
    # Blue evaluated every stage: one alert per stage (detected or miss).
    assert len(result.blue_team_alerts) == len(result.red_team_stages)
    assert result.aar is not None
    assert result.score is not None and "overall_score" in result.score


@pytest.mark.asyncio
async def test_journey_extended_house_reports(monkeypatch):
    """White/yellow/green/orange each report, with the white gate approved."""
    result = await _run_journey(monkeypatch)

    assert result.white_team_report is not None
    assert result.white_team_report["scope_approval"]["approved"] is True
    assert result.yellow_team_report is not None
    assert result.yellow_team_report.get("env_id")
    assert result.green_team_report is not None
    assert result.orange_team_report is not None
    assert result.errors == []
