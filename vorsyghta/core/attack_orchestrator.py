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

logger = logging.getLogger(__name__)


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
    ):
        self.client = tool_server_client or get_tool_server_client()
        self.tenant_id = tenant_id

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
        """
        from vorsyghta.db.session import get_session
        from vorsyghta.db.models.tool_tracking import (
            AttackSequenceRecord, AttackSequenceStepRecord, AttackExecutionRecord,
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

            # Get pending steps
            steps_result = await session.execute(
                select_stmt(AttackSequenceStepRecord, sequence_id, pending_only=True)
            )
            steps = steps_result.scalars().all()

            if not steps:
                return {"sequence_id": sequence_id, "status": "no_pending_steps"}

            # Update sequence to running
            seq.sequence_status = "running"
            seq.start_time = datetime.utcnow()
            await session.commit()

            results: List[Dict[str, Any]] = []
            completed = 0
            successful = 0
            failed = 0
            all_findings: List[str] = []

            for step in steps:
                if step.step_type != "tool_execution" or not step.command:
                    step.step_status = "skipped"
                    completed += 1
                    continue

                # Execute via tool server
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

                step.end_time = datetime.utcnow()
                step.success = tool_result["success"]
                step.error_message = tool_result.get("error")
                step.output_summary = (tool_result.get("stdout") or "")[:2000]
                step.duration_seconds = tool_result.get("duration_seconds", 0)

                # Extract findings from output
                findings = self._extract_findings(tool_result.get("stdout", ""), step.tool_name)
                if findings:
                    step.findings = json.dumps(findings)
                    all_findings.extend(findings)

                # Create execution record
                execution = AttackExecutionRecord(
                    execution_id=f"exec_{uuid4().hex[:12]}",
                    tenant_id=self.tenant_id,
                    step_id=step.step_id,
                    executor="tool_server",
                    executor_endpoint=self.client.url,
                    input_command=step.command,
                    raw_output=tool_result.get("stdout"),
                    return_code=tool_result.get("returncode", -1),
                    exit_status="success" if tool_result["success"] else "failure",
                    error_details=tool_result.get("error"),
                    execution_duration_seconds=tool_result.get("duration_seconds", 0),
                    started_at=step.start_time,
                    completed_at=step.end_time,
                )
                session.add(execution)

                if tool_result["success"]:
                    step.step_status = "completed"
                    successful += 1
                else:
                    step.step_status = "failed"
                    failed += 1
                    if fail_fast:
                        completed += 1
                        break

                completed += 1
                results.append({
                    "step_id": step.step_id,
                    "step_name": step.step_name,
                    "tool": step.tool_name,
                    "technique": step.mitre_technique_id,
                    "success": tool_result["success"],
                    "duration_seconds": tool_result.get("duration_seconds", 0),
                    "findings_count": len(findings),
                })
                await session.commit()

            # Update sequence
            seq.completed_steps = seq.completed_steps + completed
            seq.successful_steps = seq.successful_steps + successful
            seq.failed_steps = seq.failed_steps + failed
            seq.end_time = datetime.utcnow()
            if seq.start_time:
                seq.total_duration_seconds = (seq.end_time - seq.start_time).total_seconds()
            seq.overall_success = failed == 0 and successful > 0
            seq.sequence_status = "completed" if failed == 0 else "failed"
            seq.result_summary = f"{successful}/{completed} steps successful"
            if all_findings:
                seq.key_findings = json.dumps(all_findings[:50])  # cap at 50 findings
            await session.commit()

            return {
                "sequence_id": sequence_id,
                "status": seq.sequence_status,
                "overall_success": seq.overall_success,
                "total_steps": seq.total_steps,
                "completed_steps": seq.completed_steps,
                "successful_steps": seq.successful_steps,
                "failed_steps": seq.failed_steps,
                "total_duration_seconds": seq.total_duration_seconds,
                "findings_count": len(all_findings),
                "step_results": results,
            }

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
