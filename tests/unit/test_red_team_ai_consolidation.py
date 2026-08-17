"""Grounded tests for the consolidated AI-driven red-team engine (PR1).

Two layers, per the project testing principle (unit + REAL-USAGE):

Component tests (planner/orchestrator units, LLM mocked at its boundary):
  1. Planning: the AIAttackPlanner turns an LLM JSON reply into concrete,
     tool-server-executable steps.
  2. Fail-closed planning: an LLM failure raises PlannerUnavailableError so the
     orchestrator can fall back to the deterministic map, never a fabricated plan.
  3. Fallback: create_ai_attack_sequence with no/failed planner falls back to the
     deterministic MITRE path and flags the run degraded.
  4. Adaptation: after a step runs, the planner's refined next command is applied
     to the next step, and a 'stop' decision halts the run.
  5. Safety preserved: a command the AI planner refines into a dangerous form is
     STILL blocked by the fail-closed safety gate before execution.

Real-usage simulation (``TestRealUsageAIPentest``): drives the ACTUAL code path
a real operator runs via ``vorsyghta red-team attack`` — AIAttackPlanner +
AttackOrchestrator against the tool server — with a REAL in-memory SQLite DB
(real ORM rows, real SQL) and a realistic scripted LLM that plans and then adapts
using the real tool output. Only the tool-server HTTP boundary is faked. These
prove the business + algorithmic logic holds end to end, not just in isolation.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from vorsyghta.core.ai_planner import (
    AIAttackPlanner,
    PlannerUnavailableError,
    AdaptDecision,
)


# --------------------------------------------------------------------------- #
# LLM stubs
# --------------------------------------------------------------------------- #
class _StubLLM:
    """LLM provider stub returning a scripted reply (or raising)."""

    def __init__(self, reply: Optional[str] = None, raise_exc: bool = False) -> None:
        self._reply = reply
        self._raise = raise_exc
        self.prompts: List[str] = []

    async def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if self._raise:
            raise RuntimeError("simulated provider failure")
        return self._reply or ""


_PLAN_JSON = """
{
  "name": "Web app assessment",
  "objectives": ["map surface", "find injection"],
  "steps": [
    {"technique_id": "T1595", "technique_name": "Active Scanning",
     "phase": "reconnaissance", "tool": "nmap",
     "command": "nmap -sV -p 1-1000 10.0.100.10",
     "success_indicators": ["open port"]},
    {"technique_id": "T1190", "technique_name": "Exploit Public App",
     "phase": "initial_access", "tool": "nikto",
     "command": "nikto -h 10.0.100.10"}
  ]
}
"""


# --------------------------------------------------------------------------- #
# 1 + 2: Planner
# --------------------------------------------------------------------------- #
class TestPlanner:
    async def test_plans_concrete_steps_from_llm(self) -> None:
        planner = AIAttackPlanner(_StubLLM(reply=_PLAN_JSON))
        draft = await planner.plan_steps(
            target="10.0.100.10", scenario_name="web"
        )
        assert draft.name == "Web app assessment"
        assert len(draft.steps) == 2
        assert draft.steps[0].tool == "nmap"
        assert draft.steps[0].command == "nmap -sV -p 1-1000 10.0.100.10"
        assert draft.steps[1].technique_id == "T1190"

    async def test_malformed_steps_are_dropped(self) -> None:
        # A step missing command/tool must not produce an unrunnable step.
        reply = (
            '{"name":"x","objectives":[],"steps":['
            '{"technique_id":"T1","tool":"nmap","command":"nmap 10.0.100.10"},'
            '{"technique_id":"T2","tool":"","command":""}]}'
        )
        planner = AIAttackPlanner(_StubLLM(reply=reply))
        draft = await planner.plan_steps(target="10.0.100.10", scenario_name="x")
        assert len(draft.steps) == 1

    async def test_llm_failure_raises_planner_unavailable(self) -> None:
        planner = AIAttackPlanner(_StubLLM(raise_exc=True))
        with pytest.raises(PlannerUnavailableError):
            await planner.plan_steps(target="10.0.100.10", scenario_name="x")

    async def test_empty_plan_raises_planner_unavailable(self) -> None:
        planner = AIAttackPlanner(_StubLLM(reply='{"name":"x","steps":[]}'))
        with pytest.raises(PlannerUnavailableError):
            await planner.plan_steps(target="10.0.100.10", scenario_name="x")

    async def test_adapt_stops_and_degrades_on_llm_failure(self) -> None:
        planner = AIAttackPlanner(_StubLLM(raise_exc=True))
        decision = await planner.adapt(
            target="10.0.100.10", technique="T1595", command="nmap 10.0.100.10",
            exit_code=0, output="22/tcp open", next_command="nikto -h 10.0.100.10",
            discovered={},
        )
        assert decision.should_continue is False
        assert decision.degraded is True

    async def test_adapt_refines_next_command(self) -> None:
        reply = (
            '{"continue": true, "findings": ["ssh open"], '
            '"discovered": {"open_ports": [22, 80]}, '
            '"refined_next_command": "nikto -h 10.0.100.10 -p 80"}'
        )
        planner = AIAttackPlanner(_StubLLM(reply=reply))
        decision = await planner.adapt(
            target="10.0.100.10", technique="T1595", command="nmap 10.0.100.10",
            exit_code=0, output="22/tcp open\n80/tcp open",
            next_command="nikto -h 10.0.100.10", discovered={},
        )
        assert decision.should_continue is True
        assert decision.refined_next_command == "nikto -h 10.0.100.10 -p 80"
        assert decision.discovered.get("open_ports") == [22, 80]
        assert "ssh open" in decision.findings

    async def test_adapt_rejects_non_command_refinement(self) -> None:
        # A JSON-blob 'refined command' must be ignored (guarded), not applied.
        reply = '{"continue": true, "refined_next_command": "{not a command}"}'
        planner = AIAttackPlanner(_StubLLM(reply=reply))
        decision = await planner.adapt(
            target="10.0.100.10", technique="T1", command="nmap 10.0.100.10",
            exit_code=0, output="", next_command="nikto -h 10.0.100.10",
            discovered={},
        )
        assert decision.refined_next_command is None


# --------------------------------------------------------------------------- #
# Orchestrator fixtures (mirror the existing test_red_team stubs)
# --------------------------------------------------------------------------- #
class _RecordingClient:
    url = "http://toolserver.test"

    def __init__(self) -> None:
        self.executed_commands: List[str] = []

    async def health_check(self) -> bool:
        return True

    async def execute_and_track(self, command: str, **kwargs: Any) -> Dict[str, Any]:
        self.executed_commands.append(command)
        return {"success": True, "stdout": "22/tcp open ssh", "returncode": 0,
                "duration_seconds": 0.1}


class _FakeSession:
    def __init__(self) -> None:
        self.commits = 0
        self.added: List[Any] = []

    async def commit(self) -> None:
        self.commits += 1

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def execute(self, stmt: Any) -> Any:
        class _R:
            rowcount = 1
        return _R()

    async def refresh(self, obj: Any) -> None:
        pass


class _FakeStep:
    def __init__(self, command: str, tool: str = "nmap") -> None:
        self.step_id = "step_x"
        self.step_name = "s"
        self.step_type = "tool_execution"
        self.command = command
        self.tool_name = tool
        self.mitre_technique_id = "T1595"
        self.attack_phase = "reconnaissance"
        self.target = "10.0.100.10"
        self.step_status = "pending"
        self.error_message = None
        self.start_time = None
        self.end_time = None
        self.success = None
        self.output_summary = None
        self.duration_seconds = None
        self.findings = None


class _SeqStub:
    exercise_id = None
    simulation_id = None
    target_ip = "10.0.100.10"
    target_system = "10.0.100.10"


class _StubPlanner:
    """Planner stub for orchestrator-level adaptation tests."""

    def __init__(self, decision: AdaptDecision) -> None:
        self._decision = decision
        self.adapt_calls = 0

    async def adapt(self, **kwargs: Any) -> AdaptDecision:
        self.adapt_calls += 1
        return self._decision


# --------------------------------------------------------------------------- #
# 3: Fallback when planner is absent/unavailable
# --------------------------------------------------------------------------- #
class TestOrchestratorAIFallback:
    def _orch(self, planner: Any = None) -> Any:
        from vorsyghta.core.attack_orchestrator import AttackOrchestrator
        return AttackOrchestrator(
            tool_server_client=_RecordingClient(),
            tenant_id="t1",
            planner=planner,
        )

    async def test_no_planner_falls_back_and_flags_degraded(self, monkeypatch) -> None:
        orch = self._orch(planner=None)
        captured: Dict[str, Any] = {}

        async def _fake_persist(**kwargs: Any) -> str:
            captured.update(kwargs)
            return "seq_fake"

        monkeypatch.setattr(orch, "_persist_sequence", _fake_persist)
        result = await orch.create_ai_attack_sequence(
            scenario_name="web", target="10.0.100.10",
            mitre_techniques=["T1595", "T1046"],
        )
        assert result["ai_planned"] is False
        assert result["degraded"] is True
        assert result["sequence_id"] == "seq_fake"
        # Fell back to the deterministic map path.
        assert captured["initiated_by_source"] == "orchestrator"

    async def test_planner_failure_falls_back(self, monkeypatch) -> None:
        class _FailPlanner:
            async def plan_steps(self, **kwargs: Any) -> Any:
                raise PlannerUnavailableError("LLM down")

        orch = self._orch(planner=_FailPlanner())

        async def _fake_persist(**kwargs: Any) -> str:
            return "seq_fb"

        monkeypatch.setattr(orch, "_persist_sequence", _fake_persist)
        result = await orch.create_ai_attack_sequence(
            scenario_name="web", target="10.0.100.10",
        )
        assert result["ai_planned"] is False
        assert result["degraded"] is True
        assert "LLM down" in result["degraded_reason"]

    async def test_ai_plan_persists_ai_steps(self, monkeypatch) -> None:
        class _OkPlanner:
            async def plan_steps(self, **kwargs: Any) -> Any:
                from vorsyghta.core.ai_planner import AttackPlanDraft, PlannedStep
                return AttackPlanDraft(
                    name="AI plan",
                    objectives=["o1"],
                    steps=[PlannedStep("T1595", "Scan", "reconnaissance",
                                       "nmap", "nmap -sV 10.0.100.10")],
                )

        orch = self._orch(planner=_OkPlanner())
        captured: Dict[str, Any] = {}

        async def _fake_persist(**kwargs: Any) -> str:
            captured.update(kwargs)
            return "seq_ai"

        monkeypatch.setattr(orch, "_persist_sequence", _fake_persist)
        result = await orch.create_ai_attack_sequence(
            scenario_name="web", target="10.0.100.10",
        )
        assert result["ai_planned"] is True
        assert result["degraded"] is False
        assert captured["initiated_by_source"] == "ai_planner"
        assert captured["steps_data"][0]["command"] == "nmap -sV 10.0.100.10"


# --------------------------------------------------------------------------- #
# 4 + 5: Adaptation applies refinement; safety gate still blocks
# --------------------------------------------------------------------------- #
class TestOrchestratorAdaptation:
    def _orch(self, planner: Any) -> Any:
        from vorsyghta.core.attack_orchestrator import AttackOrchestrator
        return AttackOrchestrator(
            tool_server_client=_RecordingClient(),
            tenant_id="t1",
            planner=planner,
        )

    async def test_refined_command_applied_to_next_step(self) -> None:
        planner = _StubPlanner(AdaptDecision(
            should_continue=True,
            refined_next_command="nikto -h 10.0.100.10 -p 80",
        ))
        orch = self._orch(planner)
        session = _FakeSession()
        seq = _SeqStub()
        executed = _FakeStep("nmap -sV 10.0.100.10")
        executed.output_summary = "80/tcp open http"
        executed.success = True
        next_step = _FakeStep("nikto -h 10.0.100.10", tool="nikto")

        decision = await orch._adapt_after_step(
            session=session, seq=seq, step=executed,
            next_step=next_step, discovered={},
        )
        assert planner.adapt_calls == 1
        assert decision.should_continue is True
        # The refined command was written to the next step (execution re-validates).
        assert next_step.command == "nikto -h 10.0.100.10 -p 80"

    async def test_refined_dangerous_command_still_blocked_by_gate(self) -> None:
        # The planner refines the next command into a dangerous one; the
        # orchestrator persists it, but _run_step's fail-closed safety gate must
        # block it before the tool server sees it. Adaptation cannot bypass safety.
        planner = _StubPlanner(AdaptDecision(
            should_continue=True,
            refined_next_command="rm -rf /",
        ))
        orch = self._orch(planner)
        client = orch.client
        session = _FakeSession()
        seq = _SeqStub()
        executed = _FakeStep("nmap -sV 10.0.100.10")
        executed.output_summary = "ok"
        executed.success = True
        next_step = _FakeStep("nikto -h 10.0.100.10", tool="nikto")

        # Adapt writes the dangerous refinement onto next_step.
        await orch._adapt_after_step(
            session=session, seq=seq, step=executed,
            next_step=next_step, discovered={},
        )
        assert next_step.command == "rm -rf /"

        # Now run the next step: the safety gate must block it, unexecuted.
        outcome = await orch._run_step(
            session=session, seq=seq, step=next_step,
            invoked_by="system", timeout_per_step=5,
        )
        assert outcome["blocked"] == 1
        assert "rm -rf /" not in client.executed_commands
        assert next_step.step_status == "blocked"


# --------------------------------------------------------------------------- #
# REAL-USAGE SIMULATION
#
# Drives the actual AI-driven pentest flow end to end against a REAL in-memory
# SQLite database (real ORM rows, real SQL), a realistic scripted LLM that plans
# then adapts on real tool output, and a fake tool-server client at the sole
# external (HTTP) boundary. This validates the true business + algorithmic
# behaviour a real operator relies on when running `vorsyghta red-team attack`.
# --------------------------------------------------------------------------- #
@pytest.fixture
async def sqlite_db():
    """Provision a real in-memory SQLite DB wired as the global session factory.

    Yields the engine; resets the global engine/factory singletons afterwards so
    tests never leak DB state between each other.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    from vorsyghta.db import base as db_base
    from vorsyghta.db.base import Base
    from vorsyghta.db.session import create_session_factory
    import vorsyghta.db.models.tool_tracking  # noqa: F401 - register tables

    prev_engine = db_base._engine
    prev_factory = db_base._session_factory

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    db_base._engine = engine
    db_base._session_factory = create_session_factory(engine)
    try:
        yield engine
    finally:
        await engine.dispose()
        db_base._engine = prev_engine
        db_base._session_factory = prev_factory


class _ScriptedLLM:
    """A realistic LLM: plans on the first call, then adapts on real output.

    The adaptation reply is derived from what the prompt actually contains (the
    real nmap output), so the test proves the loop feeds real observations back
    to the model rather than using canned state.
    """

    def __init__(self) -> None:
        self.calls = 0

    async def generate(self, prompt: str) -> str:
        self.calls += 1
        if "Produce an ordered attack plan" in prompt:
            return json.dumps({
                "name": "AI web assessment",
                "objectives": ["map the surface", "probe web app"],
                "steps": [
                    {"technique_id": "T1595", "technique_name": "Active Scanning",
                     "phase": "reconnaissance", "tool": "nmap",
                     "command": "nmap -sV -p 1-1000 10.0.100.10",
                     "success_indicators": ["open port"]},
                    {"technique_id": "T1190", "technique_name": "Exploit Public App",
                     "phase": "initial_access", "tool": "nikto",
                     "command": "nikto -h 10.0.100.10"},
                ],
            })
        if "adapting an AUTHORIZED penetration test" in prompt:
            # The model SEES the real nmap output; refine to the discovered port.
            saw_8080 = "8080/tcp open" in prompt
            return json.dumps({
                "continue": True,
                "findings": ["web service on 8080"] if saw_8080 else [],
                "discovered": {"open_ports": [22, 8080]},
                "refined_next_command":
                    "nikto -h 10.0.100.10 -p 8080" if saw_8080 else None,
            })
        return "{}"


class _FakeToolServerClient:
    """Fake tool-server client (the one external HTTP boundary)."""

    url = "http://tool-server:9090"

    def __init__(self) -> None:
        self.executed: List[str] = []

    async def health_check(self) -> bool:
        return True

    async def execute_and_track(self, command: str, **kwargs: Any) -> Dict[str, Any]:
        self.executed.append(command)
        if command.startswith("nmap"):
            stdout = "22/tcp open ssh\n8080/tcp open http-proxy"
        elif command.startswith("nikto"):
            stdout = "+ Server: nginx\n+ OSVDB-3092: /admin/: admin dir found"
        else:
            stdout = ""
        return {"success": True, "stdout": stdout, "returncode": 0,
                "duration_seconds": 0.2}


class _InScope:
    def is_authorized(self, engagement_id: str, target: str):
        return (target == "10.0.100.10", "in scope")


class _Deny:
    def is_authorized(self, engagement_id: str, target: str):
        return (False, "target not in engagement scope")


def _orch(planner_llm: Any, tool: Any, manager: Any):
    from vorsyghta.core.attack_orchestrator import AttackOrchestrator
    return AttackOrchestrator(
        tool_server_client=tool,
        tenant_id="acme",
        planner=AIAttackPlanner(planner_llm) if planner_llm is not None else None,
        engagement_manager=manager,
        engagement_id="ENG-1",
        require_authorization=True,
    )


@pytest.mark.usefixtures("sqlite_db")
class TestRealUsageAIPentest:
    async def test_full_ai_run_plans_persists_executes_and_adapts(self) -> None:
        llm = _ScriptedLLM()
        tool = _FakeToolServerClient()
        orch = _orch(llm, tool, _InScope())

        seq = await orch.create_ai_attack_sequence(
            scenario_name="Web pentest", target="10.0.100.10",
        )
        assert seq["ai_planned"] is True and seq["degraded"] is False
        assert seq["total_steps"] == 2

        result = await orch.execute_sequence(seq["sequence_id"], timeout_per_step=5)

        # AI-driven, and the AI plan's commands ran (not the deterministic map).
        assert result["ai_driven"] is True
        assert result["status"] == "completed"
        assert tool.executed[0] == "nmap -sV -p 1-1000 10.0.100.10"
        # Adaptation refined the nikto command using the REAL discovered port.
        assert tool.executed[1] == "nikto -h 10.0.100.10 -p 8080"
        assert result["findings_count"] >= 1

        # Persistence: read the sequence + steps back from the REAL DB.
        from vorsyghta.db.session import get_session
        from vorsyghta.db.models.tool_tracking import (
            AttackSequenceRecord, AttackSequenceStepRecord,
        )
        from sqlalchemy import select
        async with get_session() as session:
            row = (await session.execute(
                select(AttackSequenceRecord).where(
                    AttackSequenceRecord.sequence_id == seq["sequence_id"]))
            ).scalar_one()
            assert row.sequence_status == "completed"
            assert row.initiated_by_source == "ai_planner"
            steps = (await session.execute(
                select(AttackSequenceStepRecord)
                .where(AttackSequenceStepRecord.sequence_id == seq["sequence_id"])
                .order_by(AttackSequenceStepRecord.step_order))
            ).scalars().all()
            # The persisted 2nd step's command was REWRITTEN by adaptation.
            assert steps[1].command == "nikto -h 10.0.100.10 -p 8080"
            assert steps[0].step_status == "completed"

    async def test_ai_refined_dangerous_command_blocked_end_to_end(self) -> None:
        class _Malicious(_ScriptedLLM):
            async def generate(self, prompt: str) -> str:
                if "Produce an ordered attack plan" in prompt:
                    return json.dumps({"name": "x", "objectives": [], "steps": [
                        {"technique_id": "T1595", "technique_name": "Scan",
                         "phase": "reconnaissance", "tool": "nmap",
                         "command": "nmap -sV 10.0.100.10"},
                        {"technique_id": "T1190", "technique_name": "Web",
                         "phase": "initial_access", "tool": "nikto",
                         "command": "nikto -h 10.0.100.10"},
                    ]})
                if "adapting an AUTHORIZED" in prompt:
                    return json.dumps({"continue": True, "findings": [],
                                       "refined_next_command": "rm -rf /"})
                return "{}"

        tool = _FakeToolServerClient()
        orch = _orch(_Malicious(), tool, _InScope())
        seq = await orch.create_ai_attack_sequence(scenario_name="x", target="10.0.100.10")
        result = await orch.execute_sequence(seq["sequence_id"], timeout_per_step=5)

        # The AI-refined destructive command must never reach the tool server.
        assert "rm -rf /" not in tool.executed
        assert result["blocked_steps"] >= 1

    async def test_out_of_scope_target_refused_before_any_tool_runs(self) -> None:
        tool = _FakeToolServerClient()
        orch = _orch(_ScriptedLLM(), tool, _Deny())
        seq = await orch.create_ai_attack_sequence(scenario_name="x", target="203.0.113.9")
        result = await orch.execute_sequence(seq["sequence_id"], timeout_per_step=5)
        assert result["status"] == "unauthorized"
        assert tool.executed == []

    async def test_llm_down_degrades_to_deterministic_and_still_runs(self) -> None:
        class _Dead:
            async def generate(self, prompt: str) -> str:
                raise RuntimeError("provider timeout")

        tool = _FakeToolServerClient()
        orch = _orch(_Dead(), tool, _InScope())
        seq = await orch.create_ai_attack_sequence(
            scenario_name="x", target="10.0.100.10",
            mitre_techniques=["T1595", "T1046"],
        )
        assert seq["ai_planned"] is False and seq["degraded"] is True
        assert "provider timeout" in seq["degraded_reason"]

        result = await orch.execute_sequence(seq["sequence_id"], timeout_per_step=5)
        assert result["status"] in ("completed", "failed")
        assert len(tool.executed) >= 1

    async def test_cli_operator_flow_end_to_end(self, tmp_path, monkeypatch) -> None:
        """Drive the EXACT function the `red-team attack` CLI command runs.

        This is the real operator entrypoint (_attack_standalone_async): it loads
        a scenario file, builds the planner, constructs the orchestrator, plans,
        executes, adapts, and renders results. We inject the scripted LLM (via
        _build_planner), a fake tool server, and an in-scope engagement at their
        boundaries; everything else is the production code path.
        """
        from vorsyghta.cli import red_team as rt
        import vorsyghta.core.attack_orchestrator as ao

        llm = _ScriptedLLM()
        tool = _FakeToolServerClient()
        real_orch_cls = ao.AttackOrchestrator

        def _factory(**kwargs: Any):
            # Inject the fake tool server + in-scope engagement; keep the rest
            # of the real orchestrator (safety, ROE, persistence, adaptation).
            kwargs["tool_server_client"] = tool
            kwargs["engagement_manager"] = _InScope()
            return real_orch_cls(**kwargs)

        monkeypatch.setattr(rt, "_build_planner", lambda: AIAttackPlanner(llm))
        monkeypatch.setattr(ao, "AttackOrchestrator", _factory)

        scenario_file = tmp_path / "web.yaml"
        scenario_file.write_text(
            json.dumps({"name": "Web pentest",
                        "mitre_techniques": ["T1595", "T1190"]})
        )

        await rt._attack_standalone_async(
            scenario_path=str(scenario_file),
            target="10.0.100.10",
            output=None,
            tenant="acme",
            techniques_override=None,
            timeout=5,
            engagement_id="ENG-1",
            allow_unauthorized=False,
            use_ai=True,
        )

        # The operator's CLI run planned with AI, executed, and adapted the
        # nikto command to the discovered web port — end to end.
        assert tool.executed == [
            "nmap -sV -p 1-1000 10.0.100.10",
            "nikto -h 10.0.100.10 -p 8080",
        ]
