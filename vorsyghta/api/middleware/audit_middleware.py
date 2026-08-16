"""Audit logging middleware for the Vorsyghta API.

Logs every API request as a tamper-evident audit event via the global
:class:`AuditLogger` singleton.  In production the logger wraps sinks
with :class:`HashChainAuditSink`, producing a SHA-256 hash chain that
makes any tampering with audit records detectable.

Owner: Jeremiah Okino (@okino007) — Compliance Lead
Phase 1 — Tamper-evident audit trail (P0-5)
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Callable, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from vorsyghta.core.audit_logger import (
    AuditCategory,
    AuditSeverity,
    get_audit_logger,
)

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware that emits an audit event for every HTTP request.

    Each event records:
    - HTTP method and path
    - Status code of the response
    - Response latency in milliseconds
    - Authenticated user (from JWT ``sub`` claim, if available)
    - Tenant ID (from JWT, if available)
    - Correlation ID (generated per request)
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        # Skip health checks to avoid noise
        path = request.url.path
        if path in ("/health", "/", "/docs", "/openapi.json", "/redoc"):
            return await call_next(request)

        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        start = time.perf_counter()

        # Extract user info from the Authorization header if present
        actor = self._extract_actor(request)

        try:
            response = await call_next(request)
            latency_ms = round((time.perf_counter() - start) * 1000, 2)

            severity = AuditSeverity.INFO
            if response.status_code >= 500:
                severity = AuditSeverity.ERROR
            elif response.status_code >= 400:
                severity = AuditSeverity.WARNING

            audit = get_audit_logger()
            audit.log(
                f"api.request.{request.method.lower()}.{response.status_code}",
                category=AuditCategory.API,
                severity=severity,
                actor=actor,
                target={"path": path, "method": request.method},
                context={
                    "status_code": response.status_code,
                    "latency_ms": latency_ms,
                    "client_ip": request.client.host if request.client else None,
                    "user_agent": request.headers.get("user-agent", ""),
                },
                correlation_id=correlation_id,
                description=f"{request.method} {path} → {response.status_code} ({latency_ms}ms)",
            )

            # Add correlation ID to response headers
            response.headers["X-Correlation-ID"] = correlation_id
            return response

        except Exception as exc:
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
            audit = get_audit_logger()
            audit.log(
                f"api.request.{request.method.lower()}.exception",
                category=AuditCategory.API,
                severity=AuditSeverity.CRITICAL,
                actor=actor,
                target={"path": path, "method": request.method},
                context={
                    "latency_ms": latency_ms,
                    "client_ip": request.client.host if request.client else None,
                    "error": str(exc),
                },
                correlation_id=correlation_id,
                description=f"{request.method} {path} → exception: {exc}",
            )
            raise

    def _extract_actor(self, request: Request) -> dict:
        """Extract user identity from the Authorization header.

        We decode the JWT without verifying the signature here (the
        RBAC dependency does the real verification).  This is purely
        for audit attribution — if the token is invalid we log
        ``actor={"authenticated": False}``.
        """
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"authenticated": False}

        token = auth_header[7:]
        try:
            from jose import jwt as jose_jwt
            # Decode without verification — just for audit attribution
            payload = jose_jwt.get_unverified_claims(token)
            return {
                "authenticated": True,
                "user_id": payload.get("sub"),
                "tenant_id": payload.get("tenant_id"),
                "role": payload.get("role"),
            }
        except Exception:
            return {"authenticated": False, "token_present": True}
