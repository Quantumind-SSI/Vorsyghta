"""Database persistence layer for Vorsyghta.

This package provides the SQLAlchemy ORM foundation that all domain
models inherit from, async session management, and a database health
check.

Phase 1 deliverables (this package):
    - :class:`Base` — declarative base for all ORM models
    - :func:`create_engine` — async engine factory with connection pooling
    - :func:`get_engine` — singleton engine accessor
    - :func:`get_session` — async session context manager
    - :func:`get_session_dep` — FastAPI dependency for sessions
    - :func:`check_database_health` — startup health check
    - :func:`dispose_engine` — clean shutdown of the engine pool

Phase 2 (domain models) will add submodules under ``vorsyghta.db.models``
that define the actual ORM tables.

Owner: Ajibola Shokunbi (@jiboo2022) — Core Software Lead
Phase 1 of the persistence layer fix (see docs/plans/persistence-layer-maintainer-assignment.md).
"""

from vorsyghta.db.base import (
    Base,
    create_engine,
    get_engine,
    get_session_factory,
    dispose_engine,
)
from vorsyghta.db.session import (
    DatabaseConfig,
    create_session_factory,
    get_session,
    get_session_dep,
)
from vorsyghta.db.health import (
    DatabaseHealth,
    check_database_health,
)

__all__ = [
    # Base
    "Base",
    "create_engine",
    "get_engine",
    "get_session_factory",
    "dispose_engine",
    # Session
    "DatabaseConfig",
    "create_session_factory",
    "get_session",
    "get_session_dep",
    # Health
    "DatabaseHealth",
    "check_database_health",
]
