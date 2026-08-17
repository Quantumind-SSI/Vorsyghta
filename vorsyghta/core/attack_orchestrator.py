"""Attack Orchestrator — integrates the tool server into simulation execution.

This module provides the AttackOrchestrator class which coordinates
real tool execution via the tool server during attack simulations.
It bridges the gap between the LLM-generated attack plans and the
actual security tools running on the sandbox VM.

Flow:
    1. Simulator generates a ThreatScenario with attack stages
    2. AttackOrchestrator converts stages into an AttackSequence
    3. Each stage's tool commands are executed via the ToolServerClient
    4. Results are tracked in the database (tool_usage, attack_sequences)
    5. Findings and IOCs are fed back into the simulation

Owner: Vorsyghta Core Team
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from vorsyghta.core.tool_server_client import ToolServerClient, get_tool_server_client
from vorsyghta.vm.safety import VMSafetyController

logger = logging.getLogger(__name__)


class EngagementNotAuthorizedError(RuntimeError):
    """Raised when an attack sequence is executed without a valid, in-scope,
    active engagement authorising its target.

    Fail-closed rules-of-engagement (ROE) control: no offensive tool runs until
    the target is proven authorised under an approved engagement. The ``reason``
    attribute carries the human-readable policy explanation for the audit trail.
    """

    def __init__(self, target: str, reason: str):
        assert isinstance(target, str), "target must be a str"
        assert isinstance(reason, str) and reason, "reason must be a non-empty str"
        self.target = target
        self.reason = reason
        super().__init__(f"Engagement authorization denied for {target}: {reason}")


# MITRE technique → tool mapping for common attack phases
MITRE_TO_TOOL_MAP: Dict[str, Dict[str, Any]] = {
    # Reconnaissance
    "T1595": {
        "tool": "nmap",
        "command_template": "nmap -sV -p 1-1000 {target}",
        "phase": "reconnaissance",
        "name": "Active Scanning",
    },
    "T1595.001": {
        "tool": "nmap",
        "command_template": "nmap -sn {target}/24",
        "phase": "reconnaissance",
        "name": "Scanning IP Blocks",
    },
    "T1592": {
        "tool": "nmap",
        "command_template": "nmap -O {target}",
        "phase": "reconnaissance",
        "name": "Gather Victim Host Info",
    },
    # Discovery
    "T1046": {
        "tool": "nmap",
        "command_template": "nmap -sV -p 1-1000 {target}",
        "phase": "discovery",
        "name": "Network Service Discovery",
    },
    "T1082": {
        "tool": "nmap",
        "command_template": "nmap -O {target}",
        "phase": "discovery",
        "name": "System Information Discovery",
    },
    "T1083": {
        "tool": "dirb",
        "command_template": "dirb http://{target}/",
        "phase": "discovery",
        "name": "File and Directory Discovery",
    },
    # Web-based
    "T1190": {
        "tool": "nikto",
        "command_template": "nikto -h {target}",
        "phase": "initial_access",
        "name": "Exploit Public-Facing Application",
    },
    "T1504.003": {
        "tool": "sqlmap",
        "command_template": "sqlmap -u http://{target}/ --batch --dbs",
        "phase": "execution",
        "name": "SQL Injection",
    },
    "T1110": {
        "tool": "hydra",
        "command_template": "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-get /",
        "phase": "credential_access",
        "name": "Brute Force",
    },
}


class AttackOrchestrator:
    """Orchestrates real tool execution during attack simulations.

    This class bridges the simulation engine and the tool server,
    converting MITRE ATT&CK techniques into actual tool commands
    and tracking the results.
    """

    def __init__(
        self,
        tool_server_client: Optional[ToolServerClient] = None,
        tenant_id: str = "default",
        safety: Optional[VMSafetyController] = None,
        enforce_safety: bool = True,
        engagement_manager: Optional[Any] = None,
        engagement_id: Optional[str] = None,
        require_authorization: bool = True,
    ):
        """Initialize the orchestrator.

        Args:
            tool_server_client: Tool server client (defaults to the shared one).
            tenant_id: Tenant the orchestrated sequences belong to.
            safety: Command-safety gate. Defaults to a fresh
                :class:`VMSafetyController` (the canonical lab-scope allowlist /
                destructive-command denylist). Reused, not re-implemented.
            enforce_safety: When True (default, production), every command is
                validated fail-closed before it reaches the tool server. Only
                set False in trusted unit tests that assert ungated behaviour.
            engagement_manager: The canonical
                :class:`~vorsyghta.research.engagement.EngagementManager` that
                owns rules-of-engagement / scope / authorization. Reused, not
                re-implemented. If ``None`` a default manager is lazily created
                when authorization is enforced.
            engagement_id: The engagement under which this orchestrator's
                sequences are authorised. Required (fail-closed) when
                ``require_authorization`` is True.
            require_authorization: When True (default, production), every
                sequence target must pass ``EngagementManager.is_authorized``
                before any tool runs. Setting False (explicit opt-out, e.g. an
                internal sanctioned-lab smoke test) skips the ROE gate and is
                logged as a warning so the bypass is never silent.
        """
        self.client = tool_server_client or get_tool_server_client()
        self.tenant_id = tenant_id
        self.safety = safety or VMSafetyController()
        self.enforce_safety = enforce_safety
        self.engagement_manager = engagement_manager
        self.engagement_id = engagement_id
        self.require_authorization = require_authorization

    def _get_engagement_manager(self) -> Any:
        """Return the engagement manager, creating the canonical default once.

        Returns:
            The :class:`EngagementManager` used for ROE authorization.
        """
        if self.engagement_manager is None:
            # Lazy import keeps the offensive core decoupled from the research
            # package until authorization is actually enforced.
            from vorsyghta.research.engagement import EngagementManager

            self.engagement_manager = EngagementManager()
        return self.engagement_manager

    def _authorize_target(self, target: str) -> None:
        """Fail-closed rules-of-engagement gate for a sequence target.

        Enforces that ``target`` is authorised under the configured engagement
        via the canonical :meth:`EngagementManager.is_authorized` before any
        offensive tool is dispatched.

        Args:
            target: The target IP / host / URL the sequence will act against.

        Raises:
            EngagementNotAuthorizedError: If authorization is required and the
                target is not in scope of an active, approved engagement, or no
                engagement was configured.
        """
        if not self.require_authorization:
            logger.warning(
                "ROE authorization BYPASSED for target %s (require_authorization=False)",
                target,
            )
            return

        if not self.engagement_id:
            raise EngagementNotAuthorizedError(
                target,
                "no engagement_id configured; an approved engagement is required "
                "before any attack sequence may run",
            )

        manager = self._get_engagement_manager()
        authorized, reason = manager.is_authorized(self.engagement_id, target)
        if not authorized:
            raise EngagementNotAuthorizedError(target, reason)
        logger.info(
            "ROE authorization granted: engagement=%s target=%s",
            self.engagement_id,
            target,
        )

    async def create_attack_sequence_from_scenario(
        self,
        scenario_name: str,
        target: str,
        mitre_techniques: List[str],
        exercise_id: Optional[str] = None,
        simulation_id: Optional[str] = None,
        initiated_by: str = "system",
    ) -> Dict[str, Any]:
        """Create an attack sequence from a scenario's MITRE techniques.

        This converts MITRE technique IDs into ordered tool execution
        steps, creating a full attack sequence ready for execution.
        """
        from vorsyghta.db.session import get_session
        from vorsyghta.db.models.tool_tracking import (
            AttackSequenceRecord, AttackSequenceStepRecord,
        )

        sequence_id = f"seq_{uuid4().hex[:12]}"
        tactics = set()
        steps_data: List[Dict[str, Any]] = []

        for i, technique_id in enumerate(mitre_techniques):
            mapping = MITRE_TO_TOOL_MAP.get(technique_id)
            if not mapping:
                # Skip techniques without a tool mapping
                steps_data.append({
                    "technique_id": technique_id,
                    "tool": None,
                    "command": None,
                    "phase": "unknown",
                    "name": f"Technique {technique_id}",
                    "skipped": True,
                })
                continue

            command = mapping["command_template"].format(target=target)
            tactics.add(mapping["phase"])
            steps_data.append({
                "technique_id": technique_id,
                "tool": mapping["tool"],
                "command": command,
                "phase": mapping["phase"],
                "name": mapping["name"],
                "skipped": False,
            })

        # Create sequence and steps in DB
        async with get_session() as session:
            seq = AttackSequenceRecord(
                sequence_id=sequence_id,
                tenant_id=self.tenant_id,
                exercise_id=exercise_id,
                simulation_id=simulation_id,
                scenario_name=scenario_name,
                name=f"Attack: {scenario_name}",
                description=f"Automated attack sequence for {scenario_name} targeting {target}",
                target_system=target,
                target_ip=target,
                mitre_tactics=json.dumps(list(tactics)),
                mitre_techniques=json.dumps(mitre_techniques),
                total_steps=len([s for s in steps_data if not s["skipped"]]),
                initiated_by=initiated_by,
                initiated_by_source="orchestrator",
            )
            session.add(seq)

            for i, step_data in enumerate(steps_data):
                step = AttackSequenceStepRecord(
                    step_id=f"step_{uuid4().hex[:12]}",
                    tenant_id=self.tenant_id,
                    sequence_id=sequence_id,
                    step_order=i,
                    step_name=step_data["name"],
                    step_type="tool_execution" if not step_data["skipped"] else "observation",
                    description=f"MITRE {step_data['technique_id']}: {step_data['name']}",
                    mitre_technique_id=step_data["technique_id"],
                    mitre_tactic=step_data["phase"],
                    attack_phase=step_data["phase"],
                    tool_name=step_data["tool"],
                    command=step_data["command"],
                    target=target,
                )
                session.add(step)

            await session.commit()

        return {
            "sequence_id": sequence_id,
            "total_steps": len(steps_data),
            "executable_steps": len([s for s in steps_data if not s["skipped"]]),
            "skipped_steps": len([s for s in steps_data if s["skipped"]]),
            "mitre_techniques": mitre_techniques,
            "target": target,
        }

    async def execute_sequence(
        self,
        sequence_id: str,
        timeout_per_step: int = 300,
        fail_fast: bool = False,
        invoked_by: str = "system",
    ) -> Dict[str, Any]:
        """Execute all pending steps in an attack sequence.

        This is the main execution loop — it iterates through the
        sequence steps, executes each via the tool server, and
        records results.

        Before any tool runs, the sequence target is validated against the
        configured engagement's rules-of-engagement (fail-closed). If the
        target is not authorised the sequence is refused and NO command is
        executed; the returned dict carries ``status='unauthorized'``.
        """
        from vorsyghta.db.session import get_session
        from vorsyghta.db.models.tool_tracking import (
            AttackSequenceRecord, AttackSequenceStepRecord,
        )

        # Check tool server health
        healthy = await self.client.health_check()
        if not healthy:
            return {
                "sequence_id": sequence_id,
                "status": "failed",
                "error": f"Tool server at {self.client.url} is not reachable",
            }

        async with get_session() as session:
            # Get sequence
            seq_result = await session.execute(
                select_stmt(AttackSequenceRecord, sequence_id)
            )
            seq = seq_result.scalar_one_or_none()
            if not seq:
                return {"sequence_id": sequence_id, "error": "Sequence not found"}

            # Rules-of-engagement authorization (fail-closed). This runs BEFORE
            # any step executes, so an out-of-scope or unauthorised target never
            # reaches the tool server.
            try:
                self._authorize_target(seq.target_ip or seq.target_system)
            except EngagementNotAuthorizedError as exc:
                seq.sequence_status = "unauthorized"
                seq.result_summary = f"Blocked by ROE gate: {exc.reason}"
                await session.commit()
                logger.warning(
                    "Attack sequence %s refused: %s", sequence_id, exc.reason
                )
                return {
                    "sequence_id": sequence_id,
                    "status": "unauthorized",
                    "error": str(exc),
                    "reason": exc.reason,
                    "target": seq.target_ip or seq.target_system,
                }

            # Get pending steps
            steps_result = await session.execute(
                select_stmt(AttackSequenceStepRecord, sequence_id, pending_only=True)
            )
            steps = steps_result.scalars().all()

            if not steps:
                return {"sequence_id": sequence_id, "status": "no_pending_steps"}

            # Lifecycle guard (B-3): atomically claim the sequence for execution.
            # Only a runnable sequence (pending/created) may transition to
            # running, and the compare-and-set is done in a single SQL UPDATE so
            # two concurrent executors cannot both claim the same sequence
            # (prevents double tool runs / replay of terminal sequences).
            claimed = await self._claim_sequence_for_run(session, seq)
            if not claimed:
                return {
                    "sequence_id": sequence_id,
                    "status": "not_runnable",
                    "error": (
                        f"Sequence is '{seq.sequence_status}', not runnable "
                        f"(already running or in a terminal state)"
                    ),
                }
            await session.refresh(seq)

            results: List[Dict[str, Any]] = []
            completed = 0
            successful = 0
            failed = 0
            blocked = 0
            all_findings: List[str] = []

            for step in steps:
                outcome = await self._run_step(
                    session=session,
                    seq=seq,
                    step=step,
                    invoked_by=invoked_by,
                    timeout_per_step=timeout_per_step,
                )
                completed += outcome["completed"]
                successful += outcome["successful"]
                failed += outcome["failed"]
                blocked += outcome["blocked"]
                all_findings.extend(outcome["findings"])
                if outcome["result"] is not None:
                    results.append(outcome["result"])
                if fail_fast and outcome["stop"]:
                    break

            await self._finalize_sequence(
                session, seq, completed, successful, failed, blocked, all_findings
            )

            return {
                "sequence_id": sequence_id,
                "status": seq.sequence_status,
                "overall_success": seq.overall_success,
                "total_steps": seq.total_steps,
                "completed_steps": seq.completed_steps,
                "successful_steps": seq.successful_steps,
                "failed_steps": seq.failed_steps,
                "blocked_steps": blocked,
                "total_duration_seconds": seq.total_duration_seconds,
                "findings_count": len(all_findings),
                "step_results": results,
            }

    # A sequence may be claimed for execution only from one of these states.
    _RUNNABLE_STATES = ("pending", "created")

    async def _claim_sequence_for_run(self, session: Any, seq: Any) -> bool:
        """Atomically transition a runnable sequence to ``running``.

        Uses a compare-and-set UPDATE (``SET status='running' WHERE
        sequence_id=? AND tenant_id=? AND status IN runnable``) so that under
        concurrent execution exactly one caller wins the claim. Returns True iff
        this call performed the transition (rowcount == 1).

        Args:
            session: Active async DB session.
            seq: The sequence ORM row (used for id/tenant/start_time).

        Returns:
            True if this caller claimed the sequence; False if it was already
            running or in a terminal state.
        """
        from sqlalchemy import update as _update
        from vorsyghta.db.models.tool_tracking import AttackSequenceRecord

        result = await session.execute(
            _update(AttackSequenceRecord)
            .where(
                AttackSequenceRecord.sequence_id == seq.sequence_id,
                AttackSequenceRecord.tenant_id == self.tenant_id,
                AttackSequenceRecord.sequence_status.in_(self._RUNNABLE_STATES),
            )
            .values(sequence_status="running", start_time=datetime.utcnow())
        )
        await session.commit()
        # rowcount == 1 means this call won the compare-and-set claim.
        return getattr(result, "rowcount", 0) == 1

    async def _finalize_sequence(
        self,
        session: Any,
        seq: Any,
        completed: int,
        successful: int,
        failed: int,
        blocked: int,
        all_findings: List[str],
    ) -> None:
        """Write the aggregate sequence result after all steps have run.

        The three accumulator counters are updated atomically (SET x = x + n) to
        avoid the lost-update race between concurrent/replayed executions of the
        same sequence (B-2); derived fields are computed from this run's local
        tallies and assigned directly. The ORM object is refreshed afterward so
        the caller sees the atomically-updated counter values.
        """
        from sqlalchemy import update as _update
        from vorsyghta.db.models.tool_tracking import AttackSequenceRecord

        end_time = datetime.utcnow()
        seq.end_time = end_time
        if seq.start_time:
            seq.total_duration_seconds = (end_time - seq.start_time).total_seconds()
        clean = failed == 0 and blocked == 0
        seq.overall_success = clean and successful > 0
        seq.sequence_status = "completed" if clean else "failed"
        seq.result_summary = (
            f"{successful}/{completed} steps successful"
            + (f", {blocked} blocked by safety gate" if blocked else "")
        )
        if all_findings:
            seq.key_findings = json.dumps(all_findings[:50])  # cap at 50 findings
        await session.execute(
            _update(AttackSequenceRecord)
            .where(
                AttackSequenceRecord.sequence_id == seq.sequence_id,
                AttackSequenceRecord.tenant_id == self.tenant_id,
            )
            .values(
                completed_steps=AttackSequenceRecord.completed_steps + completed,
                successful_steps=AttackSequenceRecord.successful_steps + successful,
                failed_steps=AttackSequenceRecord.failed_steps + failed,
            )
        )
        await session.commit()
        await session.refresh(seq)

    @staticmethod
    def _step_outcome(
        completed: int = 0,
        successful: int = 0,
        failed: int = 0,
        blocked: int = 0,
        findings: Optional[List[str]] = None,
        result: Optional[Dict[str, Any]] = None,
        stop: bool = False,
    ) -> Dict[str, Any]:
        """Build a normalized per-step outcome tally consumed by the main loop."""
        return {
            "completed": completed,
            "successful": successful,
            "failed": failed,
            "blocked": blocked,
            "findings": findings or [],
            "result": result,
            "stop": stop,
        }

    async def _run_step(
        self,
        session: Any,
        seq: Any,
        step: Any,
        invoked_by: str,
        timeout_per_step: int,
    ) -> Dict[str, Any]:
        """Execute a single sequence step through the fail-closed safety gate.

        Returns a normalized outcome dict (see :meth:`_step_outcome`). Steps that
        are non-executable are skipped; commands rejected by the safety gate are
        recorded as ``blocked`` and NEVER sent to the tool server.
        """
        if step.step_type != "tool_execution" or not step.command:
            step.step_status = "skipped"
            return self._step_outcome(completed=1)

        # Execution-boundary safety gate (fail-closed). Closes the authorization
        # gap where the orchestrator previously trusted caller-supplied DB
        # commands verbatim.
        is_safe, reason = self._authorize_command(step.command)
        if not is_safe:
            return await self._record_blocked_step(session, step, reason)

        return await self._execute_tool_step(
            session, seq, step, invoked_by, timeout_per_step
        )

    async def _record_blocked_step(
        self, session: Any, step: Any, reason: str
    ) -> Dict[str, Any]:
        """Persist a safety-blocked step (not executed) and return its outcome."""
        step.step_status = "blocked"
        step.error_message = f"Blocked by safety gate: {reason}"
        step.end_time = datetime.utcnow()
        await session.commit()
        return self._step_outcome(
            completed=1,
            blocked=1,
            stop=True,
            result={
                "step_id": step.step_id,
                "step_name": step.step_name,
                "tool": step.tool_name,
                "technique": step.mitre_technique_id,
                "success": False,
                "blocked": True,
                "reason": reason,
            },
        )

    async def _execute_tool_step(
        self,
        session: Any,
        seq: Any,
        step: Any,
        invoked_by: str,
        timeout_per_step: int,
    ) -> Dict[str, Any]:
        """Run one authorized command via the tool server and record results."""
        from vorsyghta.db.models.tool_tracking import AttackExecutionRecord

        step.step_status = "running"
        step.start_time = datetime.utcnow()
        await session.commit()

        tool_result = await self.client.execute_and_track(
            command=step.command,
            tool_name=step.tool_name or "unknown",
            tenant_id=self.tenant_id,
            exercise_id=seq.exercise_id,
            simulation_id=seq.simulation_id,
            sequence_step_id=step.step_id,
            invoked_by=invoked_by,
            invocation_source="orchestrator",
            mitre_technique_id=step.mitre_technique_id,
            attack_phase=step.attack_phase,
            target=step.target,
            timeout=timeout_per_step,
        )
        success = bool(tool_result.get("success"))

        step.end_time = datetime.utcnow()
        step.success = success
        step.error_message = tool_result.get("error")
        step.output_summary = (tool_result.get("stdout") or "")[:2000]
        step.duration_seconds = tool_result.get("duration_seconds", 0)

        findings = self._extract_findings(tool_result.get("stdout", ""), step.tool_name)
        if findings:
            step.findings = json.dumps(findings)

        session.add(AttackExecutionRecord(
            execution_id=f"exec_{uuid4().hex[:12]}",
            tenant_id=self.tenant_id,
            step_id=step.step_id,
            executor="tool_server",
            executor_endpoint=self.client.url,
            input_command=step.command,
            raw_output=tool_result.get("stdout"),
            return_code=tool_result.get("returncode", -1),
            exit_status="success" if success else "failure",
            error_details=tool_result.get("error"),
            execution_duration_seconds=tool_result.get("duration_seconds", 0),
            started_at=step.start_time,
            completed_at=step.end_time,
        ))

        step.step_status = "completed" if success else "failed"
        await session.commit()
        return self._step_outcome(
            completed=1,
            successful=1 if success else 0,
            failed=0 if success else 1,
            findings=findings,
            stop=not success,
            result={
                "step_id": step.step_id,
                "step_name": step.step_name,
                "tool": step.tool_name,
                "technique": step.mitre_technique_id,
                "success": success,
                "duration_seconds": tool_result.get("duration_seconds", 0),
                "findings_count": len(findings),
            },
        )

    def _authorize_command(self, command: str) -> tuple[bool, str]:
        """Fail-closed authorization for a single tool command.

        Returns ``(True, "OK")`` only when safety enforcement is enabled and the
        command passes :meth:`VMSafetyController.validate_command`. When
        enforcement is disabled (trusted tests) it returns ``(True, ...)``
        explicitly so the bypass is visible rather than silent.

        Args:
            command: The exact command string that would be sent to the tool
                server.

        Returns:
            Tuple of ``(is_authorized, reason)``.
        """
        assert isinstance(command, str) and command, "command must be a non-empty str"
        if not self.enforce_safety:
            return True, "safety enforcement disabled"
        return self.safety.validate_command(command)

    @staticmethod
    def _parse_nmap(line: str) -> Optional[str]:
        if "/tcp" in line and "open" in line:
            return f"Open port: {line}"
        if "OS details:" in line or "MAC Address:" in line:
            return line
        return None

    @staticmethod
    def _parse_nikto(line: str) -> Optional[str]:
        if line.startswith("+") and any(k in line for k in ("OSVDB", "Server:", "PHP")):
            return line
        return None

    @staticmethod
    def _parse_sqlmap(line: str) -> Optional[str]:
        low = line.lower()
        if "available databases" in low:
            return f"SQLi found: {line}"
        if "is vulnerable" in low:
            return f"Vulnerability: {line}"
        if "sqlmap identified" in low:
            return line
        return None

    @staticmethod
    def _parse_hydra(line: str) -> Optional[str]:
        low = line.lower()
        if "successfully" in low and "password" in low:
            return f"Credential found: {line}"
        return None

    @staticmethod
    def _parse_gobuster(line: str) -> Optional[str]:
        if "Status:" in line and any(c in line for c in ("200", "301", "302")):
            return f"Directory found: {line}"
        return None

    @staticmethod
    def _parse_whatweb(line: str) -> Optional[str]:
        if line and not line.startswith("HTTP"):
            return f"Tech detected: {line[:200]}"
        return None

    @staticmethod
    def _parse_dirb(line: str) -> Optional[str]:
        if "+ " in line and "CODE:" in line:
            return f"Path found: {line}"
        return None

    # Dispatch table: tool name -> per-line parser (Power-of-10 rule 9).
    _TOOL_PARSERS = {
        "nmap": _parse_nmap,
        "nikto": _parse_nikto,
        "sqlmap": _parse_sqlmap,
        "hydra": _parse_hydra,
        "gobuster": _parse_gobuster,
        "whatweb": _parse_whatweb,
        "dirb": _parse_dirb,
    }

    def _extract_findings(self, output: str, tool_name: str) -> List[str]:
        """Extract key findings from tool output via a per-tool parser table.

        Args:
            output: Raw stdout from the security tool.
            tool_name: Tool identifier selecting the parser (e.g. ``nmap``).

        Returns:
            Up to 20 finding strings. Empty if output is empty or the tool is
            unknown.
        """
        if not output:
            return []
        parser = self._TOOL_PARSERS.get(tool_name)
        if parser is None:
            return []
        # A value stored in a class-body dict may be a staticmethod object;
        # unwrap to the underlying callable.
        parse = getattr(parser, "__func__", parser)

        findings: List[str] = []
        for raw in output.split("\n"):
            finding = parse(raw.strip())
            if finding is not None:
                findings.append(finding)
        return findings[:20]  # cap at 20 findings per tool


def select_stmt(model, sequence_id: str, pending_only: bool = False):
    """Build a select statement for sequence-related queries.

    The SQLAlchemy import is performed lazily here so that the offensive core
    (attack planning, execution, and findings extraction) does not require the
    database layer to be installed or imported.
    """
    from sqlalchemy import select as _select

    if model.__name__ == "AttackSequenceRecord":
        return _select(model).where(
            model.sequence_id == sequence_id,
        )
    else:
        query = _select(model).where(model.sequence_id == sequence_id)
        if pending_only:
            query = query.where(model.step_status == "pending")
        return query.order_by(model.step_order)
