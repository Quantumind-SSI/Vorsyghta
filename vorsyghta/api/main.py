"""FastAPI application for Vorsyghta API.

This module provides the main FastAPI application with core endpoints
for threat simulation, scenario management, and system health checks.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

from anyio import to_thread
from fastapi import FastAPI, HTTPException, Depends, Response, status
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from redis.exceptions import RedisError

from vorsyghta.core.models import ThreatScenario, SimulationResult, ThreatType
from vorsyghta.core.simulator import Simulator
from vorsyghta.core.event_types import EventType
from vorsyghta.llm.manager import LLMManager
from vorsyghta.core.audit_logger import get_audit_logger, AuditCategory, AuditSeverity, MemoryAuditSink
from vorsyghta.core.redis_client import get_redis_client
from vorsyghta.db.health import check_database_health
from vorsyghta.integrations.stripe_billing import (
    StripeBillingConfigurationError,
    StripeBillingSettings,
    billing_required_from_env,
)

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
    billing_router,
)

# Import security dependencies
from vorsyghta.security.rbac import (
    CurrentUser,
    get_current_user,
    require_analyst,
    validate_authentication_configuration,
)
from vorsyghta.api.routers.billing import require_entitled_user

# Import audit middleware
from vorsyghta.api.middleware import AuditMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

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

        llm_manager = LLMManager()
        simulator = Simulator(llm_provider=llm_manager)
        logger.info("Vorsyghta API started successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Vorsyghta API: {str(e)}")
        # Don't raise — allow API to start even if DB is unavailable
        # (endpoints that need DB will fail gracefully)

    # Eagerly construct the DB engine/session factory so bad configuration
    # fails at boot, not on the first request. Non-fatal — /ready reports
    # database health and endpoints degrade gracefully.
    try:
        from vorsyghta.db.base import initialize_engine

        initialize_engine()
        logger.info("Database engine initialized at startup")
    except Exception as e:
        logger.warning(f"Database engine init deferred (first access will retry): {e}")

    # Attach a durable event store to the shared exercise event bus so events
    # persist for all API activity from startup, not only from the first
    # exercise run. Best-effort: on failure the bus continues unpersisted and
    # ExerciseOrchestrator._ensure_event_store remains the fallback.
    try:
        from vorsyghta.api.routers.exercise import get_event_bus
        from vorsyghta.core.contracts import build_event_store

        bus = get_event_bus()
        if not bus.has_event_store:
            store = await build_event_store()
            bus.attach_event_store(store)
            logger.info("Event store attached to API event bus: %s", type(store).__name__)
    except Exception as e:
        logger.warning(f"Event store attach skipped, continuing without persistence: {e}")

    # Redis Streams fan-out: publish every bus event to its stream topic and
    # run supervised team workers that consume from the stream. Best-effort:
    # when Redis is unavailable the API keeps serving without fan-out.
    _stream_tasks: list = []
    _unsubscribe_streams = None
    try:
        from vorsyghta.core.broker.redis_broker import RedisStreamsBroker
        from vorsyghta.api.routers.exercise import get_event_bus
        from vorsyghta.core.worker.base import run_all
        from vorsyghta.core.worker.teams import create_all_workers
        from vorsyghta.core.worker.observability import DLQ

        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            broker = RedisStreamsBroker(redis_url)
            dlq = DLQ(broker)
            workers = create_all_workers(broker)
            _stream_tasks = await run_all(broker, workers, dlq=dlq)
            if app is not None:
                app.state.streams_broker = broker

            async def _publish_to_stream(event) -> None:
                # Workers subscribe to topics named EventType.<X>.value; the
                # broker serializes BusEvent natively. Fan-out is
                # fire-and-forget: durability is the event store's job.
                try:
                    await broker.publish(event.event_type.value, event)
                except Exception as exc:  # noqa: BLE001 - fan-out is best-effort
                    logger.warning(
                        "Stream fan-out failed for %s: %s", event.event_type.value, exc
                    )

            bus = get_event_bus()
            bus.subscribe_many(list(EventType), _publish_to_stream)

            def _unsubscribe_streams_fn() -> None:
                for et in EventType:
                    bus.unsubscribe(et, _publish_to_stream)

            _unsubscribe_streams = _unsubscribe_streams_fn
            logger.info(
                "Redis Streams fan-out attached to event bus (%d workers)",
                len(_stream_tasks),
            )
        else:
            logger.info("REDIS_URL not set; stream fan-out disabled for this process")
    except Exception as e:
        logger.warning(f"Stream fan-out setup skipped: {e}")

    yield

    # Shutdown: stop stream workers and close the broker before the rest.
    if _unsubscribe_streams is not None:
        try:
            _unsubscribe_streams()
        except Exception as e:
            logger.warning(f"Stream fan-out unsubscribe failed: {e}")
    if _stream_tasks:
        from vorsyghta.core.worker.base import stop_all

        await stop_all(_stream_tasks)
    _broker_to_close = getattr(app.state, "streams_broker", None) if app is not None else None
    if _broker_to_close is not None:
        try:
            await _broker_to_close.aclose()
        except Exception as e:
            logger.warning(f"Streams broker close failed: {e}")


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


# Create FastAPI app
app = FastAPI(
    title="Vorsyghta API",
    version="0.1.0",
    description="Advanced AI-powered threat simulation and analysis platform",
    lifespan=lifespan,
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
_ENTITLED = [Depends(require_entitled_user)]
app.include_router(auth_router, prefix="/api")
app.include_router(templates_router, prefix="/api", dependencies=_ENTITLED)
app.include_router(threat_intel_router, prefix="/api", dependencies=_ENTITLED)
app.include_router(attack_tracking_router, prefix="/api", dependencies=_ENTITLED)
app.include_router(billing_router, prefix="/api")

try:
    _SAAS_MODE = billing_required_from_env()
except StripeBillingConfigurationError as exc:
    # A typo in ENVIRONMENT (or related billing env) must not silently hide the
    # ten self-hosted routers — surface the misconfiguration loudly.
    logger.error(
        "Billing/deployment configuration invalid (%s); running in SaaS mode "
        "with self-hosted routers disabled. Fix ENVIRONMENT / VORSYGHTA_BILLING_REQUIRED.",
        exc,
    )
    _SAAS_MODE = True

if not _SAAS_MODE:
    app.include_router(manuals_router, prefix="/api", dependencies=_ENTITLED)
    app.include_router(knowledge_router, prefix="/api", dependencies=_ENTITLED)
    app.include_router(feedback_router, prefix="/api", dependencies=_ENTITLED)
    app.include_router(threat_hunting_router, prefix="/api", dependencies=_ENTITLED)
    app.include_router(exercise_router, prefix="/api", dependencies=_ENTITLED)
    app.include_router(engagement_router, prefix="/api", dependencies=_ENTITLED)
    app.include_router(disclosure_router, prefix="/api", dependencies=_ENTITLED)
    app.include_router(secrets_router, prefix="/api", dependencies=_ENTITLED)
    app.include_router(sso_router, prefix="/api")
    app.include_router(integrations_router, prefix="/api", dependencies=_ENTITLED)


def require_self_hosted_surface() -> None:
    """Hide legacy process-global operations from billing-required SaaS."""
    try:
        if billing_required_from_env():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    except StripeBillingConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Deployment mode is not configured",
        ) from exc


_EXTENDED_SURFACE = [Depends(require_entitled_user), Depends(require_self_hosted_surface)]
_SAAS_HIDDEN_OPENAPI_PATHS = {
    "/audit/events",
    "/scenarios",
    "/simulations",
    "/simulations/active",
    "/llm/generate",
    "/llm/providers",
    "/llm/status",
    "/api/attack-tracking/sequences/{sequence_id}/execute",
    "/api/attack-tracking/tools/execute",
}
_openapi_billing_required: bool | None = None


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


class ReadinessResponse(BaseModel):
    """Deployment readiness based on required infrastructure and configuration."""

    status: str
    timestamp: datetime
    checks: Dict[str, str]


def _billing_configuration_status() -> str:
    """Return a non-secret readiness state for optional or required billing."""
    try:
        if not billing_required_from_env():
            return "not_required"
        StripeBillingSettings.from_env()
    except StripeBillingConfigurationError:
        return "invalid"
    return "configured"


def _authentication_configuration_status() -> str:
    """Return whether JWT signing and lifetime settings are usable."""
    try:
        validate_authentication_configuration()
    except HTTPException:
        return "invalid"
    return "configured"


async def _redis_readiness_status() -> str:
    """Verify the shared rate-limit store without blocking the event loop."""
    client = await to_thread.run_sync(get_redis_client)
    if client is None:
        return "unavailable"
    try:
        healthy = await to_thread.run_sync(client.ping)
    except RedisError:
        return "unavailable"
    return "ready" if healthy else "unavailable"


# Dependencies
def get_simulator() -> Simulator:
    """Get the threat simulator instance."""
    if simulator is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Threat simulator not initialized")
    return simulator


def get_llm_manager() -> LLMManager:
    """Get the LLM manager instance."""
    if llm_manager is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="LLM manager not initialized")
    return llm_manager


# Health check endpoints
@app.get("/", response_model=Dict[str, str])
async def read_root():
    """Root endpoint."""
    return {"message": "Vorsyghta API", "version": "0.1.0", "status": "operational"}


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    try:
        # Check component health
        components = {
            "api": "healthy",
            "simulator": "healthy" if simulator else "unavailable",
            "llm_manager": "healthy" if llm_manager else "unavailable",
        }

        # Check DB health
        try:
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
        overall_status = "healthy" if all(status == "healthy" for status in components.values()) else "degraded"

        return HealthResponse(
            status=overall_status,
            timestamp=datetime.now(timezone.utc),
            version="0.1.0",
            components=components,
        )

    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Health check failed")


@app.get("/ready", response_model=ReadinessResponse)
async def readiness_check(response: Response) -> ReadinessResponse:
    """Return 200 only when the migrated database and required billing config are ready."""
    database = await check_database_health()
    billing = _billing_configuration_status()
    authentication = _authentication_configuration_status()
    redis = await _redis_readiness_status()
    ready = (
        database.healthy
        and billing != "invalid"
        and authentication == "configured"
        and redis == "ready"
    )
    response.status_code = status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(
        status="ready" if ready else "not_ready",
        timestamp=datetime.now(timezone.utc),
        checks={
            "database": "ready" if database.healthy else "unavailable",
            "billing": billing,
            "authentication": authentication,
            "redis": redis,
        },
    )


@app.get("/audit/events", dependencies=_EXTENDED_SURFACE)
async def get_audit_events(
    limit: int = 100,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Retrieve recent audit events (tamper-evident hash-chained log).

    Returns events from the in-memory audit sink. In production, events
    are also written to stdout/file with SHA-256 hash-chain integrity.
    """

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
@app.post(
    "/scenarios",
    response_model=ScenarioResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=_EXTENDED_SURFACE,
)
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
            metadata=request.metadata,
        )

        return ScenarioResponse(
            scenario_id=scenario.scenario_id,
            name=scenario.name,
            threat_type=ThreatType(scenario.threat_type),
            description=scenario.description,
            severity=scenario.severity,
            target_systems=scenario.target_systems,
            attack_vectors=scenario.attack_vectors,
            created_at=scenario.created_at,
            metadata=scenario.metadata,
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create scenario: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create scenario")


# Simulation endpoints
@app.post("/simulations", status_code=status.HTTP_202_ACCEPTED, dependencies=_EXTENDED_SURFACE)
async def run_simulation(
    request: SimulationRequest,
    sim: Simulator = Depends(get_simulator),
    current_user: CurrentUser = Depends(require_analyst),
):
    """Execute a threat simulation."""
    try:
        # Create basic scenario (storage integration pending)
        scenario = ThreatScenario(
            name=f"Scenario_{request.scenario_id}",
            threat_type=ThreatType.CUSTOM,
            description="API-initiated simulation scenario",
        )

        # Execute simulation
        result = await sim.execute_simulation(scenario)

        return {
            "message": "Simulation executed successfully",
            "result_id": result.result_id,
            "status": result.status,
            "stages_completed": len(result.stages),
            "success_rate": result.success_rate,
            "duration_seconds": result.total_duration_seconds,
        }

    except Exception as e:
        logger.error(f"Simulation failed: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Simulation failed: {str(e)}")


@app.get("/simulations/active", dependencies=_EXTENDED_SURFACE)
async def get_active_simulations(
    sim: Simulator = Depends(get_simulator), current_user: CurrentUser = Depends(require_analyst)
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
                    "start_time": result.start_time.isoformat(),
                }
                for result_id, result in active.items()
            ],
        }
    except Exception as e:
        logger.error(f"Failed to get active simulations: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get active simulations"
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


@app.post("/llm/generate", response_model=ContentGenerationResponse, dependencies=_EXTENDED_SURFACE)
async def generate_content(
    request: ContentGenerationRequest,
    llm: LLMManager = Depends(get_llm_manager),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Generate content directly using LLM providers."""
    try:
        start_time = datetime.now(timezone.utc)

        # Generate content using the LLM manager
        response = await llm.generate_content(
            prompt=request.prompt,
            scenario_type=request.scenario_type,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            provider_name=request.provider,
        )

        end_time = datetime.now(timezone.utc)
        generation_time = (end_time - start_time).total_seconds()

        # Extract token usage — LLMResponse stores tokens in metadata or as
        # dynamic attribute depending on the provider
        meta = getattr(response, "metadata", {}) or {}
        tokens_used = (
            getattr(response, "tokens_used", None)
            or meta.get("total_tokens")
            or (meta.get("prompt_tokens", 0) + meta.get("completion_tokens", 0))
            or 0
        )

        return ContentGenerationResponse(
            content=response.content,
            provider_used=response.provider,
            tokens_used=tokens_used,
            generation_time_seconds=generation_time,
            safety_score=getattr(response, "safety_score", 1.0),
            metadata=meta,
        )

    except Exception as e:
        logger.error(f"Content generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Content generation failed: {str(e)}"
        )


@app.get("/llm/providers", dependencies=_EXTENDED_SURFACE)
async def list_providers(
    llm: LLMManager = Depends(get_llm_manager), current_user: CurrentUser = Depends(get_current_user)
):
    """List available LLM providers."""
    try:
        providers = llm.get_available_providers()
        default = None
        if hasattr(llm, "provider") and llm.provider:
            default = getattr(llm.provider, "name", type(llm.provider).__name__)
        return {"providers": providers, "default_provider": default, "total_providers": len(providers)}
    except Exception as e:
        logger.error(f"Failed to list providers: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list providers")


@app.get("/llm/status", dependencies=_EXTENDED_SURFACE)
async def llm_status(llm: LLMManager = Depends(get_llm_manager)):
    """Get LLM provider status."""
    try:
        providers = llm.get_available_providers()
        default = None
        if hasattr(llm, "provider") and llm.provider:
            default = getattr(llm.provider, "name", type(llm.provider).__name__)
        return {
            "llm_manager": "operational" if providers else "no_providers",
            "available_providers": providers,
            "default_provider": default,
            "status": "ready" if providers else "no_providers_configured",
        }
    except Exception as e:
        logger.error(f"Failed to get LLM status: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get LLM status")


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


def _custom_openapi():
    """Hide direct execution contracts from billing-required SaaS schemas."""
    global _openapi_billing_required
    try:
        billing_required = billing_required_from_env()
    except StripeBillingConfigurationError:
        billing_required = True
    if app.openapi_schema is not None and _openapi_billing_required == billing_required:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    if billing_required:
        for path in _SAAS_HIDDEN_OPENAPI_PATHS:
            schema.get("paths", {}).pop(path, None)
    app.openapi_schema = schema
    _openapi_billing_required = billing_required
    return schema


setattr(app, "openapi", _custom_openapi)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
