"""Enterprise integrations API router for Ciicerone.

Exposes the existing enterprise platform integrations (Microsoft 365,
Proofpoint, KnowBe4, Slack) through the REST API:

    GET  /api/integrations                                — list integrations + status
    GET  /api/integrations/available                       — list available platforms
    POST /api/integrations/test                            — test connectivity for all platforms
    POST /api/integrations/{platform}/authenticate         — authenticate with a platform
    POST /api/integrations/{platform}/deploy               — deploy content through a platform
    GET  /api/integrations/{platform}/metrics/{campaign_id} — get campaign metrics

This router wires together:
    - PlatformIntegrationManager (manages all platform integrations)
    - Microsoft365Integration / ProofpointIntegration / KnowBe4Integration / SlackIntegration
    - AuditLogger (tamper-evident audit trail)
    - RBAC dependencies (require_analyst)

Owner: Ajibola Shokunbi (@jiboo2022) — Core Software Lead
Phase 2 — Enterprise Integrations
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ciicerone.core.audit_logger import (
    AuditCategory,
    AuditSeverity,
    get_audit_logger,
)
from ciicerone.security.rbac import CurrentUser, require_analyst

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/integrations", tags=["Enterprise Integrations"])

# =============================================================================
# Module-level state
# =============================================================================

# Cached PlatformIntegrationManager instances keyed by tenant_id
_managers: Dict[str, "PlatformIntegrationManager"] = {}

# Supported platform identifiers
SUPPORTED_PLATFORMS = ["microsoft365", "proofpoint", "knowbe4", "slack"]


def _load_platform_config() -> Dict[str, Any]:
    """Load platform configuration from environment variables.

    Each platform is only included when its required credentials are
    present in the environment. Returns a dict keyed by platform name
    suitable for passing to ``PlatformIntegrationManager``.
    """
    config: Dict[str, Any] = {}

    # Microsoft 365 — OAuth2 client credentials
    m365_tenant = os.getenv("M365_TENANT_ID")
    m365_client = os.getenv("M365_CLIENT_ID")
    m365_secret = os.getenv("M365_CLIENT_SECRET")
    if m365_tenant and m365_client and m365_secret:
        config["microsoft365"] = {
            "tenant_id": m365_tenant,
            "client_id": m365_client,
            "client_secret": m365_secret,
        }

    # Proofpoint — API key
    proofpoint_key = os.getenv("PROOFPOINT_API_KEY")
    if proofpoint_key:
        config["proofpoint"] = {
            "api_key": proofpoint_key,
            "base_url": os.getenv(
                "PROOFPOINT_BASE_URL", "https://tap-api-v2.proofpoint.com"
            ),
        }

    # KnowBe4 — API key
    knowbe4_key = os.getenv("KNOWBE4_API_KEY")
    if knowbe4_key:
        config["knowbe4"] = {
            "api_key": knowbe4_key,
            "base_url": os.getenv("KNOWBE4_BASE_URL", "https://us.api.knowbe4.com"),
        }

    # Slack — bot token
    slack_token = os.getenv("SLACK_BOT_TOKEN")
    if slack_token:
        config["slack"] = {"bot_token": slack_token}

    return config


def _get_manager(tenant_id: str) -> "PlatformIntegrationManager":
    """Get or create a PlatformIntegrationManager for a tenant.

    Configuration is loaded from environment variables. The manager is
    cached per tenant so that authentication state is preserved across
    requests within the same process.
    """
    from ciicerone.deployment.integrations import PlatformIntegrationManager

    if tenant_id not in _managers:
        config = _load_platform_config()
        _managers[tenant_id] = PlatformIntegrationManager(config)
    return _managers[tenant_id]


def _get_integration(platform: str, tenant_id: str):
    """Resolve a single integration instance for a platform.

    Raises HTTPException 404 if the platform is not supported or not
    configured.
    """
    manager = _get_manager(tenant_id)
    if platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Platform '{platform}' is not supported. "
                f"Supported platforms: {', '.join(SUPPORTED_PLATFORMS)}"
            ),
        )
    if platform not in manager.integrations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Platform '{platform}' is not configured. "
                f"Set the required environment variables to enable it."
            ),
        )
    return manager.integrations[platform]


# =============================================================================
# Request / Response models
# =============================================================================

class IntegrationStatus(BaseModel):
    """Status of a single integration platform."""

    platform: str = Field(..., description="Platform identifier")
    configured: bool = Field(..., description="Whether the platform is configured")
    authenticated: bool = Field(
        False, description="Whether the platform is currently authenticated"
    )


class IntegrationListResponse(BaseModel):
    """Response listing all integrations and their status."""

    total: int = Field(0, description="Total number of supported platforms")
    integrations: List[IntegrationStatus] = Field(default_factory=list)
    configured: List[str] = Field(
        default_factory=list, description="Platforms with credentials configured"
    )


class AvailablePlatformsResponse(BaseModel):
    """Response listing available (configured) platforms."""

    platforms: List[str] = Field(default_factory=list)
    supported: List[str] = Field(default_factory=list)


class AuthenticateResponse(BaseModel):
    """Response from authenticating with a platform."""

    platform: str
    authenticated: bool
    message: str = ""


class DeployTarget(BaseModel):
    """A single deployment target."""

    email: Optional[str] = None
    name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    user_id: Optional[str] = None
    phone: Optional[str] = None


class DeployRequest(BaseModel):
    """Request to deploy content through a platform."""

    content: Dict[str, Any] = Field(
        ..., description="Content to deploy (subject, body_html, sender_email, etc.)"
    )
    targets: List[DeployTarget] = Field(
        ..., description="List of target recipients"
    )


class DeployResponse(BaseModel):
    """Response from a deployment operation."""

    deployment_id: str
    channel: str
    status: str
    targets_attempted: int = 0
    targets_successful: int = 0
    targets_failed: int = 0
    deployment_start: str
    deployment_duration_seconds: float = 0.0
    tracking_ids: List[str] = Field(default_factory=list)
    deployment_details: Dict[str, Any] = Field(default_factory=dict)


class CampaignMetricsResponse(BaseModel):
    """Response containing campaign metrics from a platform."""

    campaign_id: str
    platform: str
    emails_sent: int = 0
    emails_delivered: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    attachments_downloaded: int = 0
    credentials_submitted: int = 0
    verification_attempts: int = 0
    training_effectiveness_score: float = 0.0
    security_awareness_improvement: float = 0.0


class ConnectivityTestResponse(BaseModel):
    """Response from testing connectivity for all platforms."""

    results: Dict[str, Any] = Field(default_factory=dict)
    healthy: List[str] = Field(default_factory=list)
    failed: List[str] = Field(default_factory=list)


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/available", response_model=AvailablePlatformsResponse)
async def list_available_platforms(
    current_user: CurrentUser = Depends(require_analyst),
):
    """List available (configured) and supported platforms."""
    manager = _get_manager(current_user.tenant_id)
    return AvailablePlatformsResponse(
        platforms=manager.get_available_platforms(),
        supported=SUPPORTED_PLATFORMS,
    )


@router.get("/", response_model=IntegrationListResponse)
async def list_integrations(
    current_user: CurrentUser = Depends(require_analyst),
):
    """List all integrations and their status."""
    manager = _get_manager(current_user.tenant_id)

    integrations: List[IntegrationStatus] = []
    for platform in SUPPORTED_PLATFORMS:
        configured = platform in manager.integrations
        authenticated = False
        if configured:
            integration = manager.integrations[platform]
            authenticated = getattr(integration, "_authenticated", False)
        integrations.append(
            IntegrationStatus(
                platform=platform,
                configured=configured,
                authenticated=authenticated,
            )
        )

    configured_platforms = manager.get_available_platforms()
    return IntegrationListResponse(
        total=len(SUPPORTED_PLATFORMS),
        integrations=integrations,
        configured=configured_platforms,
    )


@router.post("/test", response_model=ConnectivityTestResponse)
async def test_all_platforms(
    current_user: CurrentUser = Depends(require_analyst),
):
    """Test connectivity for all configured platforms."""
    manager = _get_manager(current_user.tenant_id)

    audit = get_audit_logger()
    audit.log(
        "integrations.test_all.initiated",
        category=AuditCategory.SECURITY,
        severity=AuditSeverity.INFO,
        actor={"user_id": current_user.user_id, "role": current_user.role.value},
        context={"tenant_id": current_user.tenant_id},
        description="Connectivity test initiated for all platforms",
    )

    results: Dict[str, Any] = {}
    healthy: List[str] = []
    failed: List[str] = []

    for platform in manager.get_available_platforms():
        try:
            result = await manager.test_platform_connectivity(platform)
            results[platform] = result
            if result.get("status") == "healthy":
                healthy.append(platform)
            else:
                failed.append(platform)
        except Exception as e:
            logger.error(f"Connectivity test failed for {platform}: {e}", exc_info=True)
            results[platform] = {
                "platform": platform,
                "authentication": False,
                "error": str(e),
                "status": "error",
            }
            failed.append(platform)

    audit.log(
        "integrations.test_all.completed",
        category=AuditCategory.SECURITY,
        severity=AuditSeverity.INFO,
        actor={"user_id": current_user.user_id},
        context={
            "tenant_id": current_user.tenant_id,
            "healthy": healthy,
            "failed": failed,
        },
        description="Connectivity test completed for all platforms",
    )

    return ConnectivityTestResponse(results=results, healthy=healthy, failed=failed)


@router.post("/{platform}/authenticate", response_model=AuthenticateResponse)
async def authenticate_platform(
    platform: str,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Authenticate with a specific platform."""
    integration = _get_integration(platform, current_user.tenant_id)

    audit = get_audit_logger()
    audit.log(
        "integrations.authenticate.initiated",
        category=AuditCategory.SECURITY,
        severity=AuditSeverity.INFO,
        actor={"user_id": current_user.user_id, "role": current_user.role.value},
        context={"platform": platform, "tenant_id": current_user.tenant_id},
        description=f"Authentication initiated for platform {platform}",
    )

    try:
        success = await integration.authenticate()
        audit.log(
            "integrations.authenticate.completed",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO if success else AuditSeverity.WARNING,
            actor={"user_id": current_user.user_id},
            context={"platform": platform, "success": success},
            description=f"Authentication {'succeeded' if success else 'failed'} for {platform}",
        )
        return AuthenticateResponse(
            platform=platform,
            authenticated=success,
            message="Authentication successful" if success else "Authentication failed",
        )
    except Exception as e:
        logger.error(f"Authentication failed for {platform}: {e}", exc_info=True)
        audit.log(
            "integrations.authenticate.failed",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.ERROR,
            actor={"user_id": current_user.user_id},
            context={"platform": platform, "error": str(e)},
            description=f"Authentication error for {platform}: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed for platform '{platform}': {e}",
        )


@router.post("/{platform}/deploy", response_model=DeployResponse)
async def deploy_content(
    platform: str,
    request: DeployRequest,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Deploy content through a specific platform."""
    integration = _get_integration(platform, current_user.tenant_id)

    audit = get_audit_logger()
    audit.log(
        "integrations.deploy.initiated",
        category=AuditCategory.SECURITY,
        severity=AuditSeverity.INFO,
        actor={"user_id": current_user.user_id, "role": current_user.role.value},
        context={
            "platform": platform,
            "tenant_id": current_user.tenant_id,
            "targets": len(request.targets),
        },
        description=f"Deployment initiated via {platform} to {len(request.targets)} targets",
    )

    try:
        # Ensure authentication before deploying
        if not getattr(integration, "_authenticated", False):
            await integration.authenticate()

        targets = [t.dict(exclude_none=True) for t in request.targets]
        result = await integration.deploy_content(request.content, targets)

        audit.log(
            "integrations.deploy.completed",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.INFO,
            actor={"user_id": current_user.user_id},
            context={
                "platform": platform,
                "deployment_id": result.deployment_id,
                "targets_successful": result.targets_successful,
                "targets_failed": result.targets_failed,
            },
            description=f"Deployment {result.deployment_id} completed via {platform}",
        )

        return DeployResponse(
            deployment_id=result.deployment_id,
            channel=result.channel.value if hasattr(result.channel, "value") else str(result.channel),
            status=result.status.value if hasattr(result.status, "value") else str(result.status),
            targets_attempted=result.targets_attempted,
            targets_successful=result.targets_successful,
            targets_failed=result.targets_failed,
            deployment_start=result.deployment_start.isoformat(),
            deployment_duration_seconds=result.deployment_duration_seconds,
            tracking_ids=result.tracking_ids,
            deployment_details=result.deployment_details,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Deployment failed via {platform}: {e}", exc_info=True)
        audit.log(
            "integrations.deploy.failed",
            category=AuditCategory.SECURITY,
            severity=AuditSeverity.ERROR,
            actor={"user_id": current_user.user_id},
            context={"platform": platform, "error": str(e)},
            description=f"Deployment failed via {platform}: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Deployment failed via '{platform}': {e}",
        )


@router.get(
    "/{platform}/metrics/{campaign_id}",
    response_model=CampaignMetricsResponse,
)
async def get_campaign_metrics(
    platform: str,
    campaign_id: str,
    current_user: CurrentUser = Depends(require_analyst),
):
    """Get campaign metrics from a specific platform."""
    integration = _get_integration(platform, current_user.tenant_id)

    audit = get_audit_logger()
    audit.log(
        "integrations.metrics.requested",
        category=AuditCategory.SECURITY,
        severity=AuditSeverity.INFO,
        actor={"user_id": current_user.user_id, "role": current_user.role.value},
        context={
            "platform": platform,
            "campaign_id": campaign_id,
            "tenant_id": current_user.tenant_id,
        },
        description=f"Metrics requested for campaign {campaign_id} from {platform}",
    )

    try:
        # Ensure authentication before requesting metrics
        if not getattr(integration, "_authenticated", False):
            await integration.authenticate()

        metrics = await integration.get_campaign_metrics(campaign_id)

        return CampaignMetricsResponse(
            campaign_id=metrics.campaign_id,
            platform=platform,
            emails_sent=metrics.emails_sent,
            emails_delivered=metrics.emails_delivered,
            emails_opened=metrics.emails_opened,
            links_clicked=metrics.links_clicked,
            attachments_downloaded=metrics.attachments_downloaded,
            credentials_submitted=metrics.credentials_submitted,
            verification_attempts=metrics.verification_attempts,
            training_effectiveness_score=metrics.training_effectiveness_score,
            security_awareness_improvement=metrics.security_awareness_improvement,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get metrics from {platform}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get metrics from '{platform}': {e}",
        )
