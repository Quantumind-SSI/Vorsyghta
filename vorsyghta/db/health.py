"""Database health check for Vorsyghta.

Provides a single :func:`check_database_health` function that pings the
database and returns a structured result.  This should be called at
application startup to fail fast with a helpful error if PostgreSQL is
unreachable or the schema is not migrated.

Owner: Ajibola Shokunbi (@jiboo2022) — Core Software Lead
Phase 1 of the persistence layer fix.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)


@dataclass
class DatabaseHealth:
    """Result of a database health check."""

    healthy: bool
    message: str
    detail: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "healthy": self.healthy,
            "message": self.message,
            "detail": self.detail,
        }


async def check_database_health(engine: Optional[AsyncEngine] = None) -> DatabaseHealth:
    """Check that the database is reachable and the schema is initialised.

    Args:
        engine: Optional engine to check.  If ``None``, the module-level
            singleton from :func:`vorsyghta.db.base.get_engine` is used.

    Returns:
        :class:`DatabaseHealth` with ``healthy=True`` if the connection
        succeeded and the ``audit.events`` table exists.
    """
    if engine is None:
        from vorsyghta.db.base import get_engine
        engine = get_engine()

    # 1. Basic connectivity
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        msg = "Cannot connect to PostgreSQL"
        detail = (
            f"{type(exc).__name__}: {exc}\n"
            "Ensure PostgreSQL is running and DATABASE_URL is set correctly.\n"
            "  Example: postgresql://user:password@localhost:5432/vorsyghta\n"
            "  Run migrations: alembic upgrade head"
        )
        logger.error("Database health check failed: %s", detail)
        return DatabaseHealth(healthy=False, message=msg, detail=detail)

    # 2. Schema check — verify audit.events table exists (created by migration 001)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT EXISTS ("
                    "  SELECT FROM information_schema.tables "
                    "  WHERE table_schema = 'audit' AND table_name = 'events'"
                    ")"
                )
            )
            events_table_exists = result.scalar() or False
    except Exception as exc:
        msg = "Database reachable but schema query failed"
        detail = f"{type(exc).__name__}: {exc}"
        logger.error(msg + ": %s", detail)
        return DatabaseHealth(healthy=False, message=msg, detail=detail)

    if not events_table_exists:
        msg = "Database reachable but migrations not applied"
        detail = (
            "The audit.events table does not exist.\n"
            "Run: alembic upgrade head"
        )
        logger.warning(msg)
        return DatabaseHealth(healthy=False, message=msg, detail=detail)

    logger.info("Database health check passed")
    return DatabaseHealth(healthy=True, message="Database is healthy")
