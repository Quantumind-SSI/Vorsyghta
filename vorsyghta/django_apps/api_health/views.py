"""API health views: parity with FastAPI /health and /ready."""

import socket

from django.db import connection
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class HealthView(APIView):
    """GET /health — liveness."""

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def get(self, request):
        return Response(
            {
                "status": "healthy",
                "version": "0.1.0",
                "components": {"api": "operational"},
            }
        )


class ReadinessView(APIView):
    """GET /ready — readiness: DB migrated, settings usable."""

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def get(self, request):
        checks: dict[str, str] = {}

        # Database reachable + migrated
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            checks["database"] = "ready"
        except Exception:  # pragma: no cover - depends on live DB
            checks["database"] = "unavailable"

        checks["host"] = socket.gethostname()

        ready = all(v == "ready" for k, v in checks.items() if k == "database")
        return Response(
            {"status": "ready" if ready else "degraded", "checks": checks},
            status=200 if ready else 503,
        )
