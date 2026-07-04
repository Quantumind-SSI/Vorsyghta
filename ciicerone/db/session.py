"""Async session management for Ciicerone.

Provides:
- :func:`create_session_factory` — build an ``async_sessionmaker`` bound to an engine
- :func:`get_session` — async context manager for acquiring a session
- :class:`DatabaseConfig` — typed configuration for the persistence layer

Usage::

    from ciicerone.db.session import get_session

    async with get_session() as session:
        result = await session.execute(select(SimulationResultRecord))
        records = result.scalars().all()

Owner: Ajibola Shokunbi (@jiboo2022) — Core Software Lead
Phase 1 of the persistence layer fix.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class DatabaseConfig:
    """Typed configuration for the database persistence layer.

    Values default from environment variables (see :mod:`ciicerone.db.base`)
    but can be explicitly overridden for testing or specialised deployments.
    """

    url: str = ""
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30  # seconds
    pool_recycle: int = 3600  # seconds
    echo: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def resolved_url(self) -> str:
        """Return the URL, falling back to ``DATABASE_URL`` env then default."""
        import os
        if self.url:
            return self.url
        return os.getenv("DATABASE_URL", "postgresql://localhost/ciicerone")


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

def create_session_factory(
    engine: AsyncEngine,
    *,
    expire_on_commit: bool = False,
    class_: type = AsyncSession,
) -> async_sessionmaker:
    """Create an async session factory bound to *engine*.

    Args:
        engine: An :class:`AsyncEngine` (from :func:`ciicerone.db.base.create_engine`).
        expire_on_commit: If ``False`` (default), objects remain accessible
            after ``commit()`` without re-fetching.  This is the common
            choice for async sessions.
        class_: Session class to use (subclass :class:`AsyncSession` to
            customise).

    Returns:
        An :class:`async_sessionmaker` callable.
    """
    factory = async_sessionmaker(
        bind=engine,
        class_=class_,
        expire_on_commit=expire_on_commit,
        autoflush=False,
        autocommit=False,
    )
    logger.debug("Session factory created (expire_on_commit=%s)", expire_on_commit)
    return factory


# ---------------------------------------------------------------------------
# Session acquisition
# ---------------------------------------------------------------------------

@asynccontextmanager
async def get_session(
    engine: Optional[AsyncEngine] = None,
    *,
    factory: Optional[async_sessionmaker] = None,
) -> AsyncIterator[AsyncSession]:
    """Acquire an async DB session as a context manager.

    Usage::

        async with get_session() as session:
            ...

    The session is automatically rolled back if an exception propagates
    out of the ``with`` block, and closed in all cases.

    Args:
        engine: Optional engine.  If *factory* is not given and *engine*
            is, a temporary factory is created.  If both are ``None`` the
            module-level singleton factory is used (see
            :func:`ciicerone.db.base.get_session_factory`).
        factory: Optional pre-built session factory.  Takes precedence
            over *engine*.
    """
    if factory is None:
        if engine is not None:
            factory = create_session_factory(engine)
        else:
            from ciicerone.db.base import get_session_factory
            factory = get_session_factory()

    session: AsyncSession = factory()
    try:
        yield session
    except Exception:
        await session.rollback()
        logger.warning("Session rolled back due to exception")
        raise
    finally:
        await session.close()


async def get_session_dep() -> AsyncIterator[AsyncSession]:
    """FastAPI-style dependency that yields an async session.

    Usage in a router::

        from ciicerone.db.session import get_session_dep

        @router.get("/items")
        async def list_items(session: AsyncSession = Depends(get_session_dep)):
            ...

    The session is closed automatically when the response is finished.
    """
    from ciicerone.db.base import get_session_factory

    factory = get_session_factory()
    async with factory() as session:
        yield session
