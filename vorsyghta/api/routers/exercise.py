"""Exercise orchestration API router for Vorsyghta.

Exposes the full color-team exercise pipeline through the API:
    POST /api/exercises/run  — run red→blue→purple→black end-to-end
    GET  /api/exercises/{id} — retrieve exercise result
    GET  /api/exercises      — list active exercises
    POST /api/exercises/{id}/aar — regenerate AAR for an exercise

This router wires together:
    - ExerciseOrchestrator (red→blue→purple→black chain)
    - AARGenerator (purple team after-action report)
    - EvaluationEngine (black team scoring)
    - EventBus (inter-team communication)
    - AuditLogger (tamper-evident audit trail)

Owner: Ajibola Shokunbi (@jiboo2022) — Core Software Lead
Phase 2 — End-to-End Orchestration (P0-1, P1-1)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from vorsyghta.core.models import ThreatScenario, ThreatType
from vorsyghta.core.exercise_orchestrator import ExerciseOrchestrator, ExerciseResult
from vorsyghta.core.event_bus import EventBus
from vorsyghta.core.audit_logger import (
    AuditCategory,
    AuditSeverity,
    get_audit_logger,
)
from vorsyghta.security.rbac import CurrentUser, require_analyst
from vorsyghta.llm.manager import LLMManager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/exercises", tags=["Exercise Orchestration"])

# =============================================================================
# Module-level state
# =============================================================================

_event_bus = EventBus()
_orchestrators: Dict[str, ExerciseOrchestrator] = {}
_completed_exercises: Dict[str, ExerciseResult] = {}


def get_event_bus() -> EventBus:
    """Return the shared exercise event bus for this API process.

    The API lifespan attaches the durable event store here at startup, so
    orchestrators created later inherit persistence via this bus instead of
    performing their own lazy attach on first exercise run.
    """
    return _event_bus


def _get_orchestrator(tenant_id: str, llm: Optional[LLMManager] = None) -> ExerciseOrchestrator:
    """Get or create an orchestrator for a tenant."""
    key = f"{tenant_id}:{id(llm)}"
    if key not in _orchestrators:
        _orchestrators[key] = ExerciseOrchestrator(
            tenant_id=tenant_id,
            event_bus=_event_bus,
            llm_provider=llm,
        )
    return _orchestrators[key]


# =============================================================================
# Request / Response models
# =============================================================================

class ExerciseRunRequest(BaseModel):
    """Request to run a full color-team exercise."""
    scenario_name: str = Field(..., description="Name of the threat scenario")
    threat_type: ThreatType = Field(ThreatType.CUSTOM, description="Type of threat")
    description: str = Field("", description="Scenario description")
    severity: str = Field("medium", description="Severity (low, medium, high, critical)")
    target_systems: List[str] = Field(default_factory=list)
    attack_vectors: List[str] = Field(default_factory=list)
    teams: List[str] = Field(
        default_factory=lambda: ["red", "blue", "purple", "black"],
        description="Teams to activate",
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExerciseRunResponse(BaseModel):
    """Response from running an exercise."""
    exercise_id: str
    status: str
    scenario_name: str
    tenant_id: str
    start_time: str
    end_time: Optional[str] = None
    red_team_stages: List[Dict[str, Any]] = Field(default_factory=list)
    blue_team_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    aar: Optional[Dict[str, Any]] = None
    score: Optional[Dict[str, Any]] = None
    errors: List[str] = Field(default_factory=list)
    tokens_used: int = 0
    is_real_ai: bool = False


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/run", response_model=ExerciseRunResponse, status_code=status.HTTP_200_OK)
async def run_exercise(
    request: ExerciseRunRequest,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Run a full color-team exercise end-to-end.

    Chains: Red Team attack simulation → Blue Team detection →
    Purple Team after-action report → Black Team scoring.

    The exercise uses the LLM manager to generate realistic attack
    content, runs deterministic blue team detection, produces a
    structured AAR with remediation recommendations, and scores
    the overall exercise.
    """
    exercise_id = str(uuid4())

    # Build the scenario
    scenario = ThreatScenario(
        name=request.scenario_name,
        threat_type=request.threat_type,
        description=request.description,
        severity=request.severity,
        target_systems=request.target_systems,
        attack_vectors=request.attack_vectors,
        metadata=request.metadata,
    )

    # Get LLM manager (optional — orchestrator works without it)
    llm = None
    try:
        from vorsyghta.api.main import get_llm_manager
        llm = get_llm_manager()
    except Exception:
        pass

    # Get orchestrator and run
    orch = _get_orchestrator(current_user.tenant_id, llm)

    # Audit: exercise initiated
    audit = get_audit_logger()
    audit.log(
        "exercise.api.run.initiated",
        category=AuditCategory.SECURITY,
        severity=AuditSeverity.INFO,
        actor={"user_id": current_user.user_id, "role": current_user.role.value},
        context={
            "exercise_id": exercise_id,
            "scenario": request.scenario_name,
            "teams": request.teams,
            "tenant_id": current_user.tenant_id,
        },
        description=f"Exercise initiated via API: {request.scenario_name}",
    )

    try:
        result = await orch.run_exercise(
            scenario=scenario,
            teams=request.teams,
            exercise_id=exercise_id,
        )

        # Store completed exercise
        _completed_exercises[exercise_id] = result

        # Aggregate LLM token usage across all red-team stages
        total_tokens = 0
        used_real_ai = False
        for stage_dict in result.red_team_stages:
            payload = stage_dict.get("payload", {}) if isinstance(stage_dict, dict) else {}
            llm_info = payload.get("llm_info") or stage_dict.get("llm_info") or {}
            if isinstance(llm_info, dict):
                total_tokens += llm_info.get("tokens_used", 0) or llm_info.get("total_tokens", 0)
                if llm_info.get("is_real_ai"):
                    used_real_ai = True

        return ExerciseRunResponse(
            exercise_id=result.exercise_id,
            status=result.status,
            scenario_name=result.scenario_name,
            tenant_id=result.tenant_id,
            start_time=result.start_time.isoformat(),
            end_time=result.end_time.isoformat() if result.end_time else None,
            red_team_stages=result.red_team_stages,
            blue_team_alerts=result.blue_team_alerts,
            aar=result.aar,
            score=result.score,
            errors=result.errors,
            tokens_used=total_tokens,
            is_real_ai=used_real_ai,
        )
    except Exception as e:
        logger.error(f"Exercise failed: {e}", exc_info=True)
        audit.log(
            "exercise.api.run.failed",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.ERROR,
            actor={"user_id": current_user.user_id},
            context={"exercise_id": exercise_id, "error": str(e)},
            description=f"Exercise failed: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Exercise failed: {e}",
        )


@router.get("/{exercise_id}", response_model=ExerciseRunResponse)
async def get_exercise(
    exercise_id: str,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Retrieve a completed exercise by ID."""
    result = _completed_exercises.get(exercise_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Exercise {exercise_id} not found",
        )
    # Aggregate LLM token usage across all red-team stages
    total_tokens = 0
    used_real_ai = False
    for stage_dict in result.red_team_stages:
        payload = stage_dict.get("payload", {}) if isinstance(stage_dict, dict) else {}
        llm_info = payload.get("llm_info") or stage_dict.get("llm_info") or {}
        if isinstance(llm_info, dict):
            total_tokens += llm_info.get("tokens_used", 0) or llm_info.get("total_tokens", 0)
            if llm_info.get("is_real_ai"):
                used_real_ai = True
    return ExerciseRunResponse(
        exercise_id=result.exercise_id,
        status=result.status,
        scenario_name=result.scenario_name,
        tenant_id=result.tenant_id,
        start_time=result.start_time.isoformat(),
        end_time=result.end_time.isoformat() if result.end_time else None,
        red_team_stages=result.red_team_stages,
        blue_team_alerts=result.blue_team_alerts,
        aar=result.aar,
        score=result.score,
        errors=result.errors,
        tokens_used=total_tokens,
        is_real_ai=used_real_ai,
    )


@router.get("/")
async def list_exercises(
    current_user: CurrentUser = Depends(require_analyst),
):
    """List all completed exercises for the current tenant."""
    tenant_exercises = [
        {
            "exercise_id": r.exercise_id,
            "scenario_name": r.scenario_name,
            "status": r.status,
            "start_time": r.start_time.isoformat(),
            "end_time": r.end_time.isoformat() if r.end_time else None,
            "red_team_stages": len(r.red_team_stages),
            "blue_team_alerts": len(r.blue_team_alerts),
            "has_aar": r.aar is not None,
            "has_score": r.score is not None,
        }
        for r in _completed_exercises.values()
        if r.tenant_id == current_user.tenant_id
    ]
    return {
        "total": len(tenant_exercises),
        "exercises": tenant_exercises,
    }


@router.post("/{exercise_id}/aar")
async def regenerate_aar(
    exercise_id: str,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Regenerate the after-action report for a completed exercise.

    This is useful when the AAR was not generated during the initial
    run (e.g., the purple team was not included in the teams list)
    or when you want to re-generate it with updated data.
    """
    result = _completed_exercises.get(exercise_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Exercise {exercise_id} not found",
        )

    from vorsyghta.core.aar_generator import AARGenerator

    # Get LLM manager for AI-enhanced recommendations
    llm = None
    try:
        from vorsyghta.api.main import get_llm_manager
        llm = get_llm_manager()
    except Exception:
        pass

    generator = AARGenerator(llm_provider=llm)
    result.aar = await generator.generate_aar(
        exercise_id=result.exercise_id,
        red_team_stages=result.red_team_stages,
        blue_team_alerts=result.blue_team_alerts,
        tenant_id=result.tenant_id,
    )

    # Audit
    audit = get_audit_logger()
    audit.log(
        "exercise.aar.regenerated",
        category=AuditCategory.SECURITY,
        severity=AuditSeverity.INFO,
        actor={"user_id": current_user.user_id},
        context={"exercise_id": exercise_id},
        description=f"AAR regenerated for exercise {exercise_id}",
    )

    return {
        "exercise_id": exercise_id,
        "aar": result.aar,
    }


@router.get("/{exercise_id}/score")
async def get_exercise_score(
    exercise_id: str,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Get the Black Team evaluation score for a completed exercise."""
    result = _completed_exercises.get(exercise_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Exercise {exercise_id} not found",
        )

    if result.score is None:
        # Generate score if not present
        from vorsyghta.core.evaluation_engine import EvaluationEngine
        engine = EvaluationEngine()
        result.score = engine.score_exercise(
            red_team_stages=result.red_team_stages,
            blue_team_alerts=result.blue_team_alerts,
            aar=result.aar,
        )

    return {
        "exercise_id": exercise_id,
        "score": result.score,
    }
