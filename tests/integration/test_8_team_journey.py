"""Full 8-team journey: red→blue→purple→black→green→orange with yellow
infrastructure and white governance gates, driven through the real
ExerciseOrchestrator with a mocked Simulator (deterministic stages)."""

import pytest

from vorsyghta.core.exercise_orchestrator import ExerciseOrchestrator
from vorsyghta.core.models import SimulationResult, SimulationStage, SimulationStatus, ThreatScenario, ThreatType
from vorsyghta.core.worker.teams import create_all_workers


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


@pytest.mark.asyncio
async def test_full_8_team_exercise(monkeypatch):
    monkeypatch.setattr(
        "vorsyghta.core.exercise_orchestrator.Simulator",
        lambda llm_provider=None: type("M", (), {"execute_simulation": _exec})(),
    )

    async def _exec(self, scenario):
        return _sim_result()

    orchestrator = ExerciseOrchestrator(tenant_id="bank-abc")
    scenario = ThreatScenario(
        name="8-Team Journey",
        threat_type=ThreatType.PHISHING,
        description="Journey across all eight color teams.",
        target_systems=["email"],
        attack_vectors=["spear-phishing"],
    )

    workers = create_all_workers(broker=None)  # construct all 8 without a live Redis
    assert len(workers) == 8
    assert {w.name for w in workers} == {"red", "blue", "purple", "white", "black", "yellow", "green", "orange"}

    result = await orchestrator.run_exercise(
        scenario=scenario,
        teams=["yellow", "white", "red", "blue", "purple", "black", "green", "orange"],
        exercise_id="journey-001",
    )

    assert result.status == "completed"
    assert len(result.red_team_stages) == 2
    # Blue evaluated every stage: one alert per stage (detected or miss).
    assert len(result.blue_team_alerts) == len(result.red_team_stages)
    # Purple AAR and Black score present downstream.
    assert result.aar is not None
    assert result.score is not None and "overall_score" in result.score
    # Extended houses all reported.
    assert result.white_team_report is not None
    assert result.yellow_team_report is not None
    assert result.green_team_report is not None
    assert result.orange_team_report is not None
    assert result.errors == []
