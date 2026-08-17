"""AI attack planner/adaptor for the consolidated red-team engine.

This module is the *brain* half of the consolidated red team. It reuses the
LLM reasoning that already lives on :class:`~vorsyghta.vm.agent.AIAttackAgent`
(planning prompts, fail-closed LLM invocation, JSON extraction) but adapts it to
drive the :class:`~vorsyghta.core.attack_orchestrator.AttackOrchestrator`
execution/persistence spine (tool server, safety gate, ROE gate, DB).

Design (consolidation, not duplication):
  - Planning: :meth:`AIAttackPlanner.plan_steps` calls the LLM to produce an
    ordered list of concrete, tool-server-executable steps for a target. On any
    LLM failure it raises :class:`PlannerUnavailableError` so the caller can fall
    back to the deterministic MITRE map with an honest ``degraded`` flag — never
    a fabricated plan.
  - Adaptation: :meth:`AIAttackPlanner.adapt` feeds a completed step's real
    output back to the LLM and returns a decision (continue?, findings, refined
    next command). Fail-closed: an LLM failure returns a decision that stops the
    run and marks it degraded rather than inventing analysis.

The planner performs NO execution, NO safety decisions, and NO persistence — the
orchestrator owns all of those. It only reasons.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PlannerUnavailableError(RuntimeError):
    """Raised when the LLM planner cannot produce a plan.

    Surfacing this (instead of returning an empty/fabricated plan) lets the
    orchestrator fall back to its deterministic MITRE map and mark the run
    ``degraded`` honestly, per the no-fabrication rule.
    """


# Planning prompt: ask the model for concrete, single-line, tool-server-runnable
# commands against ONE target. Kept deliberately close to the AIAttackAgent
# planning contract so the two share a mental model, but scoped to the tool
# server's allowlisted, non-interactive tools (no metasploit console, no SSH).
PLANNING_PROMPT = """You are an expert penetration tester planning an AUTHORIZED \
security assessment of a single sanctioned target in an isolated lab.

TARGET: {target}
SCENARIO: {scenario_name}
CONTEXT: {context}

Available tools (each command runs non-interactively via a sandbox tool server; \
NO shell pipelines, NO metasploit console, NO SSH):
  nmap, nikto, dirb, gobuster, whatweb, ffuf, nuclei, sqlmap, hydra, curl, \
wget, whois, dig

Produce an ordered attack plan as JSON with this exact shape:
{{
  "name": "short plan name",
  "objectives": ["objective 1", "objective 2"],
  "steps": [
    {{
      "technique_id": "T1595",
      "technique_name": "Active Scanning",
      "phase": "reconnaissance",
      "tool": "nmap",
      "command": "nmap -sV -p 1-1000 {target}",
      "success_indicators": ["open port", "service version"]
    }}
  ]
}}

Rules:
- Every "command" MUST be a single, complete, non-interactive command line that \
targets {target} (or a host/service discovered from it). No placeholders.
- Order steps recon -> discovery -> web/service testing -> exploitation attempts.
- 4 to 8 steps. Use only the tools listed above.
- Return ONLY the JSON object, no prose.
"""

# Adaptation prompt: given the real output of the step just executed, decide
# whether to continue and optionally refine the NEXT command with discovered
# hosts/ports/paths. Mirrors AIAttackAgent's analysis contract.
ADAPT_PROMPT = """You are adapting an AUTHORIZED penetration test based on real \
tool output.

TARGET: {target}
STEP JUST EXECUTED:
  technique: {technique}
  command:   {command}
  exit_code: {exit_code}
OUTPUT (truncated):
{output}

NEXT PLANNED STEP (may be refined):
  command: {next_command}

Discovered so far: {discovered}

Answer as JSON with this exact shape:
{{
  "continue": true,
  "findings": ["notable finding 1"],
  "discovered": {{"open_ports": [80, 443], "paths": ["/admin"], "hosts": []}},
  "refined_next_command": "the next command, with discovered ports/paths \
substituted, or null to keep it unchanged"
}}

Rules:
- "refined_next_command" MUST remain a single non-interactive command targeting \
{target} using only the allowed tools, or null.
- Set "continue" false only if further testing is pointless (target down, or \
objectives met).
- Return ONLY the JSON object.
"""


@dataclass
class PlannedStep:
    """A single AI-planned, tool-server-executable step.

    Mirrors the fields the orchestrator needs to build an
    ``AttackSequenceStepRecord`` — technique metadata plus the exact command.
    """

    technique_id: str
    technique_name: str
    phase: str
    tool: str
    command: str
    success_indicators: List[str] = field(default_factory=list)


@dataclass
class AttackPlanDraft:
    """The AI-produced plan: a name, objectives, and ordered executable steps."""

    name: str
    objectives: List[str]
    steps: List[PlannedStep]


@dataclass
class AdaptDecision:
    """The AI's decision after observing one executed step.

    Attributes:
        should_continue: Whether the orchestrator should run further steps.
        findings: Notable findings extracted by the model from the output.
        discovered: Structured discoveries (ports/paths/hosts) to carry forward.
        refined_next_command: A refined command for the next step, or ``None`` to
            keep the planned command unchanged.
        degraded: True when the decision could not be obtained from the LLM and a
            safe fail-closed default (stop) was returned instead.
    """

    should_continue: bool
    findings: List[str] = field(default_factory=list)
    discovered: Dict[str, Any] = field(default_factory=dict)
    refined_next_command: Optional[str] = None
    degraded: bool = False


class AIAttackPlanner:
    """LLM planner/adaptor that drives the orchestrator's execution spine.

    The planner wraps an LLM provider (or an ``LLMManager`` from which it
    resolves the strict ``pydantic_ai`` provider, matching AIAttackAgent's
    routing) and exposes two operations: :meth:`plan_steps` and :meth:`adapt`.

    It never executes commands, never makes safety/ROE decisions, and never
    touches the database — those belong to the orchestrator.
    """

    def __init__(self, llm_manager: Any):
        """Initialize the planner.

        Args:
            llm_manager: An ``LLMManager`` (exposing ``get_provider``) or a raw
                provider. The strict pydantic-ai provider is preferred when the
                manager exposes one, so red-team reasoning routes through Azure
                gpt-4o in production, identical to AIAttackAgent.
        """
        self.llm = self._resolve_llm(llm_manager)

    @staticmethod
    def _resolve_llm(llm_manager: Any) -> Any:
        """Prefer the strict pydantic-ai provider for red-team reasoning."""
        getter = getattr(llm_manager, "get_provider", None)
        if callable(getter):
            provider = getter("pydantic_ai")
            if provider is not None:
                logger.info("AI planner routed through pydantic-ai (Azure gpt-4o).")
                return provider
        return llm_manager

    async def plan_steps(
        self,
        target: str,
        scenario_name: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AttackPlanDraft:
        """Generate an ordered, executable attack plan for ``target`` via the LLM.

        Args:
            target: The authorised target host/IP/URL.
            scenario_name: Human-readable scenario label for prompt context.
            context: Optional extra context (e.g. known service, tech stack).

        Returns:
            An :class:`AttackPlanDraft` with 4-8 concrete steps.

        Raises:
            PlannerUnavailableError: If the LLM call fails or yields no usable
                steps. The caller must fall back to the deterministic map and
                mark the run degraded rather than proceeding on a fabricated plan.
        """
        assert isinstance(target, str) and target, "target must be a non-empty str"
        prompt = PLANNING_PROMPT.format(
            target=target,
            scenario_name=scenario_name or "General assessment",
            context=json.dumps(context or {}, default=str),
        )
        response = await self._generate(prompt)
        data = self._parse_json(response)
        raw_steps = data.get("steps") if isinstance(data, dict) else None
        if not raw_steps:
            raise PlannerUnavailableError(
                "LLM returned no usable steps for the attack plan"
            )

        steps = self._build_steps(raw_steps)
        if not steps:
            raise PlannerUnavailableError(
                "LLM plan contained no valid tool/command steps"
            )

        return AttackPlanDraft(
            name=str(data.get("name", scenario_name or "AI Attack Plan")),
            objectives=[str(o) for o in (data.get("objectives") or [])],
            steps=steps,
        )

    @staticmethod
    def _build_steps(raw_steps: List[Any]) -> List[PlannedStep]:
        """Convert raw LLM step dicts into validated :class:`PlannedStep` objects.

        Steps missing a concrete tool+command are dropped rather than emitted as
        unrunnable commands (the caller treats an all-empty result as a planning
        failure and falls back to the deterministic map).
        """
        steps: List[PlannedStep] = []
        for raw in raw_steps:
            if not isinstance(raw, dict):
                continue
            command = str(raw.get("command", "")).strip()
            tool = str(raw.get("tool", "")).strip()
            if not command or not tool:
                continue
            steps.append(
                PlannedStep(
                    technique_id=str(raw.get("technique_id", "T0000")),
                    technique_name=str(raw.get("technique_name", "Unknown")),
                    phase=str(raw.get("phase", "reconnaissance")),
                    tool=tool,
                    command=command,
                    success_indicators=[
                        str(s) for s in (raw.get("success_indicators") or [])
                    ],
                )
            )
        return steps

    async def adapt(
        self,
        target: str,
        technique: str,
        command: str,
        exit_code: int,
        output: str,
        next_command: Optional[str],
        discovered: Dict[str, Any],
    ) -> AdaptDecision:
        """Analyse a completed step's output and decide the next action.

        Fail-closed: if the LLM call or parse fails, returns a decision that
        STOPS the run and is flagged ``degraded`` — never a fabricated analysis
        that would let the attack proceed on invented state.

        Args:
            target: The authorised target.
            technique: MITRE technique id of the executed step.
            command: The command that was executed.
            exit_code: Its process exit code.
            output: Its (truncated) stdout.
            next_command: The next planned command, if any.
            discovered: Accumulated structured discoveries so far.

        Returns:
            An :class:`AdaptDecision`.
        """
        prompt = ADAPT_PROMPT.format(
            target=target,
            technique=technique,
            command=command,
            exit_code=exit_code,
            output=(output or "")[:3000],
            next_command=next_command or "(none)",
            discovered=json.dumps(discovered or {}, default=str),
        )
        try:
            response = await self._generate(prompt)
        except PlannerUnavailableError as exc:
            logger.error("Adaptation LLM call failed; stopping (degraded): %s", exc)
            return AdaptDecision(should_continue=False, degraded=True)

        data = self._parse_json(response)
        if not isinstance(data, dict):
            logger.error("Adaptation returned unparseable analysis; stopping (degraded)")
            return AdaptDecision(should_continue=False, degraded=True)

        discovered_val = data.get("discovered")
        return AdaptDecision(
            should_continue=bool(data.get("continue", True)),
            findings=[str(f) for f in (data.get("findings") or [])],
            discovered=discovered_val if isinstance(discovered_val, dict) else {},
            refined_next_command=self._sanitize_refined_command(
                data.get("refined_next_command")
            ),
            degraded=False,
        )

    @staticmethod
    def _sanitize_refined_command(refined: Any) -> Optional[str]:
        """Return a plausible single-line command, or ``None``.

        Guards against the model returning a JSON blob or an oversized value in
        the ``refined_next_command`` slot. This is a shape guard only — the
        command's *safety* is enforced later by the orchestrator's fail-closed
        VMSafetyController, never here.
        """
        if not isinstance(refined, str):
            return None
        clean = refined.strip()
        if clean and len(clean) < 500 and not clean.startswith("{"):
            return clean
        return None

    async def _generate(self, prompt: str) -> str:
        """Invoke the LLM provider, normalising the two provider interfaces.

        Raises:
            PlannerUnavailableError: If no usable generate method exists or the
                provider call fails. Fail-closed so callers never proceed on a
                fabricated empty reply.
        """
        import asyncio

        try:
            if hasattr(self.llm, "generate"):
                if asyncio.iscoroutinefunction(self.llm.generate):
                    return await self.llm.generate(prompt)
                return self.llm.generate(prompt)
            if hasattr(self.llm, "generate_content"):
                result = await self.llm.generate_content(prompt)
                return result.content if hasattr(result, "content") else str(result)
            raise PlannerUnavailableError("LLM provider has no generate method")
        except PlannerUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalise to fail-closed error
            logger.error("Planner LLM generation failed: %s", exc)
            raise PlannerUnavailableError(str(exc)) from exc

    @staticmethod
    def _parse_json(text: str) -> Dict[str, Any]:
        """Parse a JSON object from a model reply that may wrap it in prose/fences."""
        if not text:
            return {}
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            pass
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if fence:
            try:
                parsed = json.loads(fence.group(1))
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                pass
        brace = re.search(r"\{[\s\S]*\}", text)
        if brace:
            try:
                parsed = json.loads(brace.group(0))
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                pass
        return {}
