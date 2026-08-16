"""API Routers for Vorsyghta."""

from .manuals import router as manuals_router
from .knowledge import router as knowledge_router
from .feedback import router as feedback_router
from .auth import router as auth_router
from .threat_hunting import router as threat_hunting_router
from .exercise import router as exercise_router
from .templates import router as templates_router
from .threat_intel import router as threat_intel_router
from .attack_tracking import router as attack_tracking_router
from .engagement import router as engagement_router
from .disclosure import router as disclosure_router
from .secrets import router as secrets_router
from .sso import router as sso_router
from .integrations import router as integrations_router

__all__ = [
    "manuals_router",
    "knowledge_router",
    "feedback_router",
    "auth_router",
    "threat_hunting_router",
    "exercise_router",
    "templates_router",
    "threat_intel_router",
    "attack_tracking_router",
    "engagement_router",
    "disclosure_router",
    "secrets_router",
    "sso_router",
    "integrations_router",
]
