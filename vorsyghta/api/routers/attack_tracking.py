"""Attack Tracking API Router.

Endpoints for managing attack sequences, tracking tool usage, and
viewing execution results during attack simulations.

Endpoints:
    /api/attack-tracking/sequences           — Create/list attack sequences
    /api/attack-tracking/sequences/{id}      — Get sequence with steps
    /api/attack-tracking/sequences/{id}/steps — Add steps to a sequence
    /api/attack-tracking/sequences/{id}/execute — Execute a sequence via tool server
    /api/attack-tracking/tool-usage          — List tool usage records
    /api/attack-tracking/tool-usage/{id}     — Get specific tool usage
    /api/attack-tracking/tools/available     — List tools available on tool server
    /api/attack-tracking/tools/execute       — Execute a single tool via tool server
    /api/attack-tracking/stats               — Tracking statistics

Owner: Vorsyghta Core Team
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, update

from vorsyghta.security.rbac import CurrentUser, get_current_user, require_analyst
from vorsyghta.core.audit_logger import AuditCategory, AuditSeverity, get_audit_logger
from vorsyghta.core.tool_server_client import get_tool_server_client

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/attack-tracking", tags=["Attack Tracking"])


# =============================================================================
# Request / Response Models
# =============================================================================

class AttackSequenceCreate(BaseModel):
    name: str
    description: Optional[str] = None
    exercise_id: Optional[str] = None
    simulation_id: Optional[str] = None
    scenario_name: Optional[str] = None
    target_system: Optional[str] = None
    target_ip: Optional[str] = None
    target_url: Optional[str] = None
    attacker_vm: Optional[str] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class AttackSequenceStepCreate(BaseModel):
    step_name: str
    step_type: str = "tool_execution"
    description: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    attack_phase: Optional[str] = None
    tool_name: Optional[str] = None
    command: Optional[str] = None
    target: Optional[str] = None
    depends_on_steps: List[str] = Field(default_factory=list)
    condition: Optional[str] = None


class ToolExecuteRequest(BaseModel):
    command: str = Field(..., description="Full command string (e.g., 'nmap -sV 172.17.0.2')")
    tool_name: str = Field(..., description="Tool name (must be in allowlist)")
    timeout: int = Field(300, description="Timeout in seconds")
    exercise_id: Optional[str] = None
    simulation_id: Optional[str] = None
    sequence_step_id: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    attack_phase: Optional[str] = None
    target: Optional[str] = None


class SequenceExecuteRequest(BaseModel):
    """Execute all pending steps in a sequence via the tool server."""
    timeout_per_step: int = Field(300, description="Timeout per step in seconds")
    fail_fast: bool = Field(False, description="Stop on first failure")


# =============================================================================
# Attack Sequence Endpoints
# =============================================================================

@router.post("/sequences", status_code=status.HTTP_201_CREATED)
async def create_sequence(
    request: AttackSequenceCreate,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Create a new attack sequence."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.tool_tracking import AttackSequenceRecord
    import json

    sequence_id = f"seq_{uuid4().hex[:12]}"
    async with get_session() as session:
        record = AttackSequenceRecord(
            sequence_id=sequence_id,
            tenant_id=current_user.tenant_id,
            exercise_id=request.exercise_id,
            simulation_id=request.simulation_id,
            scenario_name=request.scenario_name,
            name=request.name,
            description=request.description,
            target_system=request.target_system,
            target_ip=request.target_ip,
            target_url=request.target_url,
            attacker_vm=request.attacker_vm,
            mitre_tactics=json.dumps(request.mitre_tactics) if request.mitre_tactics else None,
            mitre_techniques=json.dumps(request.mitre_techniques) if request.mitre_techniques else None,
            initiated_by=current_user.user_id,
            initiated_by_source="api",
        )
        session.add(record)
        await session.commit()

        audit = get_audit_logger()
        audit.log(
            "attack_tracking.sequence.created",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO,
            actor={"user_id": current_user.user_id},
            context={"sequence_id": sequence_id, "name": request.name},
            description=f"Attack sequence created: {request.name}",
        )

        return {
            "sequence_id": sequence_id,
            "name": request.name,
            "status": "pending",
            "total_steps": 0,
            "created_at": record.created_at.isoformat() if record.created_at else None,
        }


@router.get("/sequences")
async def list_sequences(
    exercise_id: Optional[str] = None,
    sequence_status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    current_user: CurrentUser = Depends(get_current_user),
):
    """List attack sequences for the current tenant."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.tool_tracking import AttackSequenceRecord

    async with get_session() as session:
        query = select(AttackSequenceRecord).where(
            AttackSequenceRecord.tenant_id == current_user.tenant_id
        )
        if exercise_id:
            query = query.where(AttackSequenceRecord.exercise_id == exercise_id)
        if sequence_status:
            query = query.where(AttackSequenceRecord.sequence_status == sequence_status)
        query = query.offset(skip).limit(limit).order_by(
            AttackSequenceRecord.created_at.desc()
        )
        result = await session.execute(query)
        sequences = result.scalars().all()
        return [
            {
                "sequence_id": s.sequence_id,
                "name": s.name,
                "description": s.description,
                "status": s.sequence_status,
                "total_steps": s.total_steps,
                "completed_steps": s.completed_steps,
                "successful_steps": s.successful_steps,
                "failed_steps": s.failed_steps,
                "overall_success": s.overall_success,
                "target_system": s.target_system,
                "exercise_id": s.exercise_id,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in sequences
        ]


@router.get("/sequences/{sequence_id}")
async def get_sequence(
    sequence_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get a specific attack sequence with all its steps."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.tool_tracking import AttackSequenceRecord, AttackSequenceStepRecord
    import json

    async with get_session() as session:
        result = await session.execute(
            select(AttackSequenceRecord).where(
                AttackSequenceRecord.sequence_id == sequence_id,
                AttackSequenceRecord.tenant_id == current_user.tenant_id,
            )
        )
        seq = result.scalar_one_or_none()
        if not seq:
            raise HTTPException(status_code=404, detail="Attack sequence not found")

        steps_result = await session.execute(
            select(AttackSequenceStepRecord).where(
                AttackSequenceStepRecord.sequence_id == sequence_id
            ).order_by(AttackSequenceStepRecord.step_order)
        )
        steps = steps_result.scalars().all()

        return {
            "sequence_id": seq.sequence_id,
            "name": seq.name,
            "description": seq.description,
            "status": seq.sequence_status,
            "target_system": seq.target_system,
            "target_ip": seq.target_ip,
            "attacker_vm": seq.attacker_vm,
            "mitre_tactics": json.loads(seq.mitre_tactics) if seq.mitre_tactics else [],
            "mitre_techniques": json.loads(seq.mitre_techniques) if seq.mitre_techniques else [],
            "total_steps": seq.total_steps,
            "completed_steps": seq.completed_steps,
            "successful_steps": seq.successful_steps,
            "failed_steps": seq.failed_steps,
            "overall_success": seq.overall_success,
            "result_summary": seq.result_summary,
            "start_time": seq.start_time.isoformat() if seq.start_time else None,
            "end_time": seq.end_time.isoformat() if seq.end_time else None,
            "total_duration_seconds": seq.total_duration_seconds,
            "steps": [
                {
                    "step_id": st.step_id,
                    "step_order": st.step_order,
                    "step_name": st.step_name,
                    "step_type": st.step_type,
                    "step_status": st.step_status,
                    "success": st.success,
                    "tool_name": st.tool_name,
                    "command": st.command,
                    "target": st.target,
                    "mitre_technique_id": st.mitre_technique_id,
                    "mitre_tactic": st.mitre_tactic,
                    "attack_phase": st.attack_phase,
                    "description": st.description,
                    "output_summary": st.output_summary,
                    "error_message": st.error_message,
                    "duration_seconds": st.duration_seconds,
                    "depends_on_steps": json.loads(st.depends_on_steps) if st.depends_on_steps else [],
                }
                for st in steps
            ],
        }


@router.post("/sequences/{sequence_id}/steps", status_code=status.HTTP_201_CREATED)
async def add_step_to_sequence(
    sequence_id: str,
    request: AttackSequenceStepCreate,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Add a step to an existing attack sequence."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.tool_tracking import AttackSequenceRecord, AttackSequenceStepRecord
    import json

    step_id = f"step_{uuid4().hex[:12]}"
    async with get_session() as session:
        # Verify sequence exists
        seq_result = await session.execute(
            select(AttackSequenceRecord).where(
                AttackSequenceRecord.sequence_id == sequence_id,
                AttackSequenceRecord.tenant_id == current_user.tenant_id,
            )
        )
        seq = seq_result.scalar_one_or_none()
        if not seq:
            raise HTTPException(status_code=404, detail="Attack sequence not found")

        # Determine step order
        step_order = seq.total_steps

        step = AttackSequenceStepRecord(
            step_id=step_id,
            tenant_id=current_user.tenant_id,
            sequence_id=sequence_id,
            step_order=step_order,
            step_name=request.step_name,
            step_type=request.step_type,
            description=request.description,
            mitre_technique_id=request.mitre_technique_id,
            mitre_tactic=request.mitre_tactic,
            attack_phase=request.attack_phase,
            tool_name=request.tool_name,
            command=request.command,
            target=request.target,
            depends_on_steps=json.dumps(request.depends_on_steps) if request.depends_on_steps else None,
            condition=request.condition,
        )
        session.add(step)

        # Update sequence total_steps atomically (SET x = x + 1) to avoid the
        # lost-update race between concurrent step-adds (B-2). A Python
        # read-modify-write on seq.total_steps could clobber a concurrent add.
        await session.execute(
            update(AttackSequenceRecord)
            .where(
                AttackSequenceRecord.sequence_id == sequence_id,
                AttackSequenceRecord.tenant_id == current_user.tenant_id,
            )
            .values(total_steps=AttackSequenceRecord.total_steps + 1)
        )
        await session.commit()

        return {
            "step_id": step_id,
            "sequence_id": sequence_id,
            "step_order": step_order,
            "step_name": request.step_name,
            "step_status": "pending",
        }


@router.post("/sequences/{sequence_id}/execute")
async def execute_sequence(
    sequence_id: str,
    request: SequenceExecuteRequest,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Execute all pending steps in an attack sequence via the tool server.

    This iterates through the sequence steps in order, executes each
    tool_execution step via the tool server, records the results,
    and updates the sequence status.
    """
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.tool_tracking import (
        AttackSequenceRecord, AttackSequenceStepRecord, AttackExecutionRecord,
    )
    import json

    async with get_session() as session:
        # Get sequence
        seq_result = await session.execute(
            select(AttackSequenceRecord).where(
                AttackSequenceRecord.sequence_id == sequence_id,
                AttackSequenceRecord.tenant_id == current_user.tenant_id,
            )
        )
        seq = seq_result.scalar_one_or_none()
        if not seq:
            raise HTTPException(status_code=404, detail="Attack sequence not found")

        # Get pending steps
        steps_result = await session.execute(
            select(AttackSequenceStepRecord).where(
                AttackSequenceStepRecord.sequence_id == sequence_id,
                AttackSequenceStepRecord.step_status == "pending",
            ).order_by(AttackSequenceStepRecord.step_order)
        )
        steps = steps_result.scalars().all()

        if not steps:
            return {"sequence_id": sequence_id, "message": "No pending steps to execute"}

        # Lifecycle guard (B-3): atomically claim the sequence. Only a runnable
        # (pending/created) sequence may transition to running, via a single
        # compare-and-set UPDATE so concurrent executes cannot both claim it
        # (prevents double tool runs and replay of terminal sequences).
        claim = await session.execute(
            update(AttackSequenceRecord)
            .where(
                AttackSequenceRecord.sequence_id == sequence_id,
                AttackSequenceRecord.tenant_id == current_user.tenant_id,
                AttackSequenceRecord.sequence_status.in_(("pending", "created")),
            )
            .values(sequence_status="running", start_time=datetime.utcnow())
        )
        await session.commit()
        if getattr(claim, "rowcount", 0) != 1:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Sequence is '{seq.sequence_status}', not runnable "
                    f"(already running or in a terminal state)"
                ),
            )
        await session.refresh(seq)

        # Get tool server client
        client = get_tool_server_client()

        # Check tool server health
        healthy = await client.health_check()
        if not healthy:
            seq.sequence_status = "failed"
            seq.result_summary = "Tool server unreachable"
            seq.end_time = datetime.utcnow()
            await session.commit()
            raise HTTPException(
                status_code=503,
                detail="Tool server is not reachable. Check VORSYGHTA_TOOL_SERVER_URL.",
            )

        results: List[Dict[str, Any]] = []
        completed = 0
        successful = 0
        failed = 0

        for step in steps:
            # Skip non-tool steps
            if step.step_type != "tool_execution" or not step.command:
                step.step_status = "skipped"
                completed += 1
                continue

            # Execute via tool server
            step.step_status = "running"
            step.start_time = datetime.utcnow()
            await session.commit()

            tool_result = await client.execute_and_track(
                command=step.command,
                tool_name=step.tool_name or "unknown",
                tenant_id=current_user.tenant_id,
                exercise_id=seq.exercise_id,
                simulation_id=seq.simulation_id,
                sequence_step_id=step.step_id,
                invoked_by=current_user.user_id,
                invocation_source="sequence_orchestrator",
                mitre_technique_id=step.mitre_technique_id,
                attack_phase=step.attack_phase,
                target=step.target,
                timeout=request.timeout_per_step,
            )

            step.end_time = datetime.utcnow()
            step.success = tool_result["success"]
            step.error_message = tool_result.get("error")
            step.output_summary = (tool_result.get("stdout") or "")[:2000]
            step.duration_seconds = tool_result.get("duration_seconds", 0)

            # Create execution record
            execution = AttackExecutionRecord(
                execution_id=f"exec_{uuid4().hex[:12]}",
                tenant_id=current_user.tenant_id,
                step_id=step.step_id,
                executor="tool_server",
                executor_endpoint=client.url,
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
                if request.fail_fast:
                    completed += 1
                    break

            completed += 1
            results.append({
                "step_id": step.step_id,
                "step_name": step.step_name,
                "tool": step.tool_name,
                "success": tool_result["success"],
                "duration_seconds": tool_result.get("duration_seconds", 0),
                "usage_id": tool_result.get("usage_id"),
            })
            await session.commit()

        # Update sequence. The three accumulator counters are updated atomically
        # (SET x = x + n) to avoid the lost-update race between concurrent
        # executes of the same sequence (B-2); the derived fields below are
        # computed from THIS run's local tallies and are safe to assign.
        end_time = datetime.utcnow()
        seq.end_time = end_time
        if seq.start_time:
            seq.total_duration_seconds = (end_time - seq.start_time).total_seconds()
        seq.overall_success = failed == 0 and successful > 0
        seq.sequence_status = "completed" if failed == 0 else "failed"
        seq.result_summary = f"{successful}/{completed} steps successful"
        await session.execute(
            update(AttackSequenceRecord)
            .where(
                AttackSequenceRecord.sequence_id == sequence_id,
                AttackSequenceRecord.tenant_id == current_user.tenant_id,
            )
            .values(
                completed_steps=AttackSequenceRecord.completed_steps + completed,
                successful_steps=AttackSequenceRecord.successful_steps + successful,
                failed_steps=AttackSequenceRecord.failed_steps + failed,
            )
        )
        await session.commit()
        await session.refresh(seq)

        audit = get_audit_logger()
        audit.log(
            "attack_tracking.sequence.executed",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO,
            actor={"user_id": current_user.user_id},
            context={"sequence_id": sequence_id, "successful": successful, "failed": failed},
            description=f"Attack sequence executed: {successful} successful, {failed} failed",
        )

        return {
            "sequence_id": sequence_id,
            "status": seq.sequence_status,
            "overall_success": seq.overall_success,
            "total_steps": seq.total_steps,
            "completed_steps": seq.completed_steps,
            "successful_steps": seq.successful_steps,
            "failed_steps": seq.failed_steps,
            "total_duration_seconds": seq.total_duration_seconds,
            "step_results": results,
        }


# =============================================================================
# Tool Usage Endpoints
# =============================================================================

@router.get("/tool-usage")
async def list_tool_usage(
    exercise_id: Optional[str] = None,
    simulation_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    success: Optional[bool] = None,
    skip: int = 0,
    limit: int = 100,
    current_user: CurrentUser = Depends(get_current_user),
):
    """List tool usage records."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.tool_tracking import ToolUsageRecord

    async with get_session() as session:
        query = select(ToolUsageRecord).where(
            ToolUsageRecord.tenant_id == current_user.tenant_id
        )
        if exercise_id:
            query = query.where(ToolUsageRecord.exercise_id == exercise_id)
        if simulation_id:
            query = query.where(ToolUsageRecord.simulation_id == simulation_id)
        if tool_name:
            query = query.where(ToolUsageRecord.tool_name == tool_name)
        if success is not None:
            query = query.where(ToolUsageRecord.success == success)
        query = query.offset(skip).limit(limit).order_by(
            ToolUsageRecord.started_at.desc()
        )
        result = await session.execute(query)
        records = result.scalars().all()
        return [
            {
                "usage_id": r.usage_id,
                "tool_name": r.tool_name,
                "command": r.command,
                "target": r.target,
                "success": r.success,
                "return_code": r.return_code,
                "duration_seconds": r.duration_seconds,
                "timed_out": r.timed_out,
                "mitre_technique_id": r.mitre_technique_id,
                "attack_phase": r.attack_phase,
                "invoked_by": r.invoked_by,
                "invocation_source": r.invocation_source,
                "exercise_id": r.exercise_id,
                "simulation_id": r.simulation_id,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            }
            for r in records
        ]


@router.get("/tool-usage/{usage_id}")
async def get_tool_usage(
    usage_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get a specific tool usage record with full output."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.tool_tracking import ToolUsageRecord

    async with get_session() as session:
        result = await session.execute(
            select(ToolUsageRecord).where(
                ToolUsageRecord.usage_id == usage_id,
                ToolUsageRecord.tenant_id == current_user.tenant_id,
            )
        )
        record = result.scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="Tool usage record not found")

        return {
            "usage_id": record.usage_id,
            "tool_name": record.tool_name,
            "command": record.command,
            "target": record.target,
            "success": record.success,
            "return_code": record.return_code,
            "stdout": record.stdout,
            "stderr": record.stderr,
            "error_message": record.error_message,
            "duration_seconds": record.duration_seconds,
            "timeout_seconds": record.timeout_seconds,
            "timed_out": record.timed_out,
            "mitre_technique_id": record.mitre_technique_id,
            "attack_phase": record.attack_phase,
            "invoked_by": record.invoked_by,
            "invocation_source": record.invocation_source,
            "tool_server_url": record.tool_server_url,
            "output_size_bytes": record.output_size_bytes,
            "exercise_id": record.exercise_id,
            "simulation_id": record.simulation_id,
            "sequence_step_id": record.sequence_step_id,
            "started_at": record.started_at.isoformat() if record.started_at else None,
            "completed_at": record.completed_at.isoformat() if record.completed_at else None,
        }


# =============================================================================
# Tool Server Direct Endpoints
# =============================================================================

@router.get("/tools/available")
async def list_available_tools(
    current_user: CurrentUser = Depends(get_current_user),
):
    """List tools available on the tool server."""
    client = get_tool_server_client()
    healthy = await client.health_check()
    if not healthy:
        raise HTTPException(status_code=503, detail="Tool server is not reachable")
    tools = await client.list_tools()
    return {"tool_server_url": client.url, "healthy": healthy, "tools": tools}


@router.post("/tools/execute")
async def execute_tool(
    request: ToolExecuteRequest,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Execute a single tool via the tool server.

    This executes a command directly (not as part of a sequence) and
    tracks the usage in the database.
    """
    client = get_tool_server_client()

    # Check health
    healthy = await client.health_check()
    if not healthy:
        raise HTTPException(
            status_code=503,
            detail=f"Tool server at {client.url} is not reachable",
        )

    result = await client.execute_and_track(
        command=request.command,
        tool_name=request.tool_name,
        tenant_id=current_user.tenant_id,
        exercise_id=request.exercise_id,
        simulation_id=request.simulation_id,
        sequence_step_id=request.sequence_step_id,
        invoked_by=current_user.user_id,
        invocation_source="api",
        mitre_technique_id=request.mitre_technique_id,
        attack_phase=request.attack_phase,
        target=request.target,
        timeout=request.timeout,
    )

    audit = get_audit_logger()
    audit.log(
        "attack_tracking.tool.executed",
        category=AuditCategory.SECURITY,
        severity=AuditSeverity.INFO if result["success"] else AuditSeverity.WARNING,
        actor={"user_id": current_user.user_id},
        context={
            "tool": request.tool_name,
            "command": request.command[:200],
            "usage_id": result.get("usage_id"),
        },
        description=f"Tool executed: {request.tool_name} (success={result['success']})",
    )

    return result


# =============================================================================
# Statistics
# =============================================================================

@router.get("/stats")
async def tracking_stats(
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get attack tracking statistics for the current tenant."""
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.tool_tracking import (
        ToolUsageRecord, AttackSequenceRecord, AttackSequenceStepRecord,
    )

    stats: Dict[str, Any] = {}
    async with get_session() as session:
        # Total sequences
        total_seq = await session.execute(
            select(func.count(AttackSequenceRecord.id)).where(
                AttackSequenceRecord.tenant_id == current_user.tenant_id
            )
        )
        stats["total_sequences"] = total_seq.scalar_one()

        # Sequences by status
        for st in ["pending", "running", "completed", "failed", "aborted"]:
            count = await session.execute(
                select(func.count(AttackSequenceRecord.id)).where(
                    AttackSequenceRecord.tenant_id == current_user.tenant_id,
                    AttackSequenceRecord.sequence_status == st,
                )
            )
            stats[f"sequences_{st}"] = count.scalar_one()

        # Total tool usage
        total_tools = await session.execute(
            select(func.count(ToolUsageRecord.id)).where(
                ToolUsageRecord.tenant_id == current_user.tenant_id
            )
        )
        stats["total_tool_usage"] = total_tools.scalar_one()

        # Successful tool usage
        successful_tools = await session.execute(
            select(func.count(ToolUsageRecord.id)).where(
                ToolUsageRecord.tenant_id == current_user.tenant_id,
                ToolUsageRecord.success == True,  # noqa: E712
            )
        )
        stats["successful_tool_usage"] = successful_tools.scalar_one()

        # Tool usage by tool name
        tool_counts = await session.execute(
            select(
                ToolUsageRecord.tool_name,
                func.count(ToolUsageRecord.id).label("count"),
                func.sum(ToolUsageRecord.success.cast(__import__('sqlalchemy').Integer)).label("successes"),
            ).where(
                ToolUsageRecord.tenant_id == current_user.tenant_id
            ).group_by(ToolUsageRecord.tool_name)
        )
        stats["tools_by_name"] = [
            {"tool": row.tool_name, "count": row.count, "successes": row.successes or 0}
            for row in tool_counts
        ]

        # Total steps
        total_steps = await session.execute(
            select(func.count(AttackSequenceStepRecord.id)).where(
                AttackSequenceStepRecord.tenant_id == current_user.tenant_id
            )
        )
        stats["total_steps"] = total_steps.scalar_one()

    return stats
