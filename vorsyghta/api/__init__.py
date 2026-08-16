"""REST API for Vorsyghta.

Provides FastAPI-based REST endpoints for threat simulation,
scenario management, and system integration.
"""

from vorsyghta.api.main import app

__all__ = [
    "app",
]
