"""FastAPI application for Vorsyghta API.

This module provides the main FastAPI application with core endpoints
for threat simulation, scenario management, and system health checks.
"""

import logging
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from vorsyghta.core.models import ThreatScenario, SimulationResult, ThreatType
from vorsyghta.core.simulator import Simulator
from vorsyghta.llm.manager import LLMManager
from vorsyghta.core.audit_logger import get_audit_logger, AuditCategory, AuditSeverity

# Import API routers
from vorsyghta.api.routers import (
    manuals_router,
    knowledge_router,
    feedback_router,
    auth_router,
    threat_hunting_router,
    exercise_router,
    templates_router,
    threat_intel_router,
    attack_tracking_router,
    engagement_router,
    disclosure_router,
    secrets_router,
    sso_router,
    integrations_router,
)

# Import security dependencies
from vorsyghta.security.rbac import get_current_user, require_analyst, CurrentUser

# Import audit middleware
from vorsyghta.api.middleware import AuditMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global instances
simulator: Optional[Simulator] = None
llm_manager: Optional[LLMManager] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global simulator, llm_manager

    # Startup
    logger.info("Starting Vorsyghta API...")
    try:
        # Initialize audit logger (hash-chain in production)
        audit = get_audit_logger()
        audit.info(
            "api.startup",
            category=AuditCategory.SYSTEM,
            context={"environment": os.getenv("ENVIRONMENT", "development")},
            description="Vorsyghta API starting up",
        )

        # Initialize database — create tables if they don't exist
        await _init_database()

        llm_manager = LLMManager()
        simulator = Simulator(llm_provider=llm_manager)
        logger.info("Vorsyghta API started successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Vorsyghta API: {str(e)}")
        # Don't raise — allow API to start even if DB is unavailable
        # (endpoints that need DB will fail gracefully)

    yield

    # Shutdown
    logger.info("Shutting down Vorsyghta API...")
    audit = get_audit_logger()
    audit.info(
        "api.shutdown",
        category=AuditCategory.SYSTEM,
        description="Vorsyghta API shutting down",
    )
    audit.flush()

    # Dispose DB engine
    try:
        from vorsyghta.db.base import dispose_engine
        await dispose_engine()
    except Exception as e:
        logger.warning(f"Failed to dispose DB engine: {e}")


async def _init_database() -> None:
    """Initialize the database by creating all ORM tables if they don't exist.

    This is a lightweight alternative to Alembic migrations for the pilot.
    In production, use Alembic migrations instead.
    """
    try:
        import vorsyghta.db.models  # noqa: F401 — register all models
        from vorsyghta.db.base import Base, get_engine
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialized — all ORM tables created")
    except Exception as e:
        logger.warning(f"Database initialization skipped (DB may be unavailable): {e}")


# Create FastAPI app
app = FastAPI(
    title="Vorsyghta API",
    version="0.1.0",
    description="Advanced AI-powered threat simulation and analysis platform",
    lifespan=lifespan
)

# Add CORS middleware - Production should configure ALLOWED_ORIGINS env var
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add audit middleware — tamper-evident logging of every API request
app.add_middleware(AuditMiddleware)

# Include API routers
app.include_router(manuals_router, prefix="/api")
app.include_router(knowledge_router, prefix="/api")
app.include_router(feedback_router, prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(threat_hunting_router, prefix="/api")
app.include_router(exercise_router, prefix="/api")
app.include_router(templates_router, prefix="/api")
app.include_router(threat_intel_router, prefix="/api")
app.include_router(attack_tracking_router, prefix="/api")
app.include_router(engagement_router, prefix="/api")
app.include_router(disclosure_router, prefix="/api")
app.include_router(secrets_router, prefix="/api")
app.include_router(sso_router, prefix="/api")
app.include_router(integrations_router, prefix="/api")


# Pydantic models for API
class ScenarioRequest(BaseModel):
    """Request model for creating threat scenarios."""
    name: str = Field(..., description="Name of the threat scenario")
    threat_type: ThreatType = Field(..., description="Type of threat")
    description: str = Field("", description="Detailed description of the scenario")
    severity: str = Field("medium", description="Severity level (low, medium, high, critical)")
    target_systems: List[str] = Field(default_factory=list, description="Target systems")
    attack_vectors: List[str] = Field(default_factory=list, description="Attack vectors")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ScenarioResponse(BaseModel):
    """Response model for threat scenarios."""
    scenario_id: str
    name: str
    threat_type: ThreatType
    description: str
    severity: str
    target_systems: List[str]
    attack_vectors: List[str]
    created_at: datetime
    metadata: Dict[str, Any]


class SimulationRequest(BaseModel):
    """Request model for simulation execution."""
    scenario_id: str = Field(..., description="ID of the scenario to simulate")
    max_stages: Optional[int] = Field(10, description="Maximum number of simulation stages")


class HealthResponse(BaseModel):
    """Response model for health checks."""
    status: str
    timestamp: datetime
    version: str
    components: Dict[str, str]


# Dependencies
def get_simulator() -> Simulator:
    """Get the threat simulator instance."""
    if simulator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat simulator not initialized"
        )
    return simulator


def get_llm_manager() -> LLMManager:
    """Get the LLM manager instance."""
    if llm_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM manager not initialized"
        )
    return llm_manager


# Health check endpoints
@app.get("/", response_model=Dict[str, str])
async def read_root():
    """Root endpoint."""
    return {
        "message": "Vorsyghta API",
        "version": "0.1.0",
        "status": "operational"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    try:
        # Check component health
        components = {
            "api": "healthy",
            "simulator": "healthy" if simulator else "unavailable",
            "llm_manager": "healthy" if llm_manager else "unavailable"
        }

        # Check DB health
        try:
            from vorsyghta.db.health import check_database_health
            db_health = await check_database_health()
            components["database"] = "healthy" if db_health.healthy else "unavailable"
        except Exception:
            components["database"] = "unavailable"

        # Check audit logger
        try:
            audit = get_audit_logger()
            components["audit"] = "healthy" if audit.sinks else "unavailable"
        except Exception:
            components["audit"] = "unavailable"

        # Overall status
        overall_status = "healthy" if all(
            status == "healthy" for status in components.values()
        ) else "degraded"

        return HealthResponse(
            status=overall_status,
            timestamp=datetime.utcnow(),
            version="0.1.0",
            components=components
        )

    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Health check failed"
        )


@app.get("/audit/events")
async def get_audit_events(
    limit: int = 100,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Retrieve recent audit events (tamper-evident hash-chained log).

    Returns events from the in-memory audit sink. In production, events
    are also written to stdout/file with SHA-256 hash-chain integrity.
    """
    from vorsyghta.core.audit_logger import MemoryAuditSink, get_audit_logger
    audit = get_audit_logger()
    events = []
    for sink in audit.sinks:
        # Unwrap HashChainAuditSink if present
        inner = getattr(sink, "_inner", sink)
        if isinstance(inner, MemoryAuditSink):
            events = inner.events[-limit:]
            break
        if isinstance(sink, MemoryAuditSink):
            events = sink.events[-limit:]
            break
    return {
        "total": len(events),
        "events": [e.to_dict() for e in events],
    }


# Scenario management endpoints
@app.post("/scenarios", response_model=ScenarioResponse, status_code=status.HTTP_201_CREATED)
async def create_scenario(request: ScenarioRequest):
    """Create a new threat scenario."""
    try:
        scenario = ThreatScenario(
            name=request.name,
            threat_type=request.threat_type,
            description=request.description,
            severity=request.severity,
            target_systems=request.target_systems,
            attack_vectors=request.attack_vectors,
            metadata=request.metadata
        )

        return ScenarioResponse(
            scenario_id=scenario.scenario_id,
            name=scenario.name,
            threat_type=scenario.threat_type,
            description=scenario.description,
            severity=scenario.severity,
            target_systems=scenario.target_systems,
            attack_vectors=scenario.attack_vectors,
            created_at=scenario.created_at,
            metadata=scenario.metadata
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to create scenario: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create scenario"
        )


# Simulation endpoints
@app.post("/simulations", status_code=status.HTTP_202_ACCEPTED)
async def run_simulation(
    request: SimulationRequest,
    sim: Simulator = Depends(get_simulator),
    current_user: CurrentUser = Depends(require_analyst)
):
    """Execute a threat simulation."""
    try:
        # Create basic scenario (storage integration pending)
        scenario = ThreatScenario(
            name=f"Scenario_{request.scenario_id}",
            threat_type=ThreatType.CUSTOM,
            description="API-initiated simulation scenario"
        )

        # Execute simulation
        result = await sim.execute_simulation(scenario)

        return {
            "message": "Simulation executed successfully",
            "result_id": result.result_id,
            "status": result.status,
            "stages_completed": len(result.stages),
            "success_rate": result.success_rate,
            "duration_seconds": result.total_duration_seconds
        }

    except Exception as e:
        logger.error(f"Simulation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Simulation failed: {str(e)}"
        )


@app.get("/simulations/active")
async def get_active_simulations(
    sim: Simulator = Depends(get_simulator),
    current_user: CurrentUser = Depends(require_analyst)
):
    """Get currently active simulations."""
    try:
        active = sim.get_active_simulations()
        return {
            "active_simulations": len(active),
            "simulations": [
                {
                    "result_id": result_id,
                    "status": result.status,
                    "scenario_id": result.scenario_id,
                    "stages_completed": len(result.stages),
                    "start_time": result.start_time.isoformat()
                }
                for result_id, result in active.items()
            ]
        }
    except Exception as e:
        logger.error(f"Failed to get active simulations: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get active simulations"
        )


# LLM endpoints
class ContentGenerationRequest(BaseModel):
    """Request model for direct content generation."""
    prompt: str = Field(..., description="The prompt for content generation")
    scenario_type: str = Field("custom", description="Type of scenario")
    max_tokens: int = Field(1000, description="Maximum tokens to generate")
    temperature: float = Field(0.7, description="Generation temperature")
    provider: Optional[str] = Field(None, description="Specific LLM provider to use")


class ContentGenerationResponse(BaseModel):
    """Response model for content generation."""
    content: str
    provider_used: str
    tokens_used: int
    generation_time_seconds: float
    safety_score: float
    metadata: Dict[str, Any]


@app.post("/llm/generate", response_model=ContentGenerationResponse)
async def generate_content(
    request: ContentGenerationRequest,
    llm: LLMManager = Depends(get_llm_manager),
    current_user: CurrentUser = Depends(get_current_user)
):
    """Generate content directly using LLM providers."""
    try:
        start_time = datetime.utcnow()

        # Generate content using the LLM manager
        response = await llm.generate_content(
            prompt=request.prompt,
            scenario_type=request.scenario_type,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            provider_name=request.provider
        )

        end_time = datetime.utcnow()
        generation_time = (end_time - start_time).total_seconds()

        # Extract token usage — LLMResponse stores tokens in metadata or as
        # dynamic attribute depending on the provider
        meta = getattr(response, 'metadata', {}) or {}
        tokens_used = (
            getattr(response, 'tokens_used', None)
            or meta.get('total_tokens')
            or (meta.get('prompt_tokens', 0) + meta.get('completion_tokens', 0))
            or 0
        )

        return ContentGenerationResponse(
            content=response.content,
            provider_used=response.provider,
            tokens_used=tokens_used,
            generation_time_seconds=generation_time,
            safety_score=getattr(response, 'safety_score', 1.0),
            metadata=meta,
        )

    except Exception as e:
        logger.error(f"Content generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Content generation failed: {str(e)}"
        )


@app.get("/llm/providers")
async def list_providers(
    llm: LLMManager = Depends(get_llm_manager),
    current_user: CurrentUser = Depends(get_current_user)
):
    """List available LLM providers."""
    try:
        providers = llm.get_available_providers()
        default = None
        if hasattr(llm, 'provider') and llm.provider:
            default = getattr(llm.provider, 'name', type(llm.provider).__name__)
        return {
            "providers": providers,
            "default_provider": default,
            "total_providers": len(providers)
        }
    except Exception as e:
        logger.error(f"Failed to list providers: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list providers"
        )


@app.get("/llm/status")
async def llm_status(llm: LLMManager = Depends(get_llm_manager)):
    """Get LLM provider status."""
    try:
        providers = llm.get_available_providers()
        default = None
        if hasattr(llm, 'provider') and llm.provider:
            default = getattr(llm.provider, 'name', type(llm.provider).__name__)
        return {
            "llm_manager": "operational" if providers else "no_providers",
            "available_providers": providers,
            "default_provider": default,
            "status": "ready" if providers else "no_providers_configured"
        }
    except Exception as e:
        logger.error(f"Failed to get LLM status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get LLM status"
        )


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler."""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
