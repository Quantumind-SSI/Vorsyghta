"""Event store port and non-Postgres implementations.

Defines :class:`EventStorePort` — the structural contract every event store
satisfies — and two concrete stores (:class:`InMemoryEventStore`,
:class:`SqliteEventStore`) that honour the *same* optimistic-concurrency
semantics as :class:`vorsyghta.core.postgres_event_store.PostgresEventStore`:

    A new aggregate has version 0. Appending an event requires
    ``event.version == current_aggregate_version + 1``; otherwise a
    :class:`ConcurrencyError` is raised. Events are returned ordered by version.

:func:`build_event_store` selects a store from configuration: PostgreSQL when a
``postgresql`` ``DATABASE_URL`` is present, SQLite for a file/``sqlite`` URL, and
an in-memory store otherwise (tests / ephemeral demos).

Owner: Vorsyghta Core — see docs/architecture/TEAM_ARCHITECTURE.md
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from uuid import UUID

from vorsyghta.core.event_sourcing import ConcurrencyError, Event

try:  # aiosqlite is already a project dependency (see pyproject aiosqlite>=0.19.0)
    import aiosqlite

    _AIOSQLITE_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when dependency missing
    _AIOSQLITE_AVAILABLE = False


@runtime_checkable
class EventStorePort(Protocol):
    """Structural contract for an append-only, replayable event store.

    Any object providing these two coroutines satisfies the port. This is the
    single seam the :class:`vorsyghta.core.event_bus.EventBus` and the teams
    depend on, decoupling them from the concrete storage backend.
    """

    async def append(self, event: Event) -> int:
        """Append ``event`` and return its assigned sequence number.

        Preconditions:
            ``event.version == current_aggregate_version + 1``.
        Raises:
            ConcurrencyError: if the version precondition is violated.
        """
        ...

    async def get_events(
        self,
        aggregate_id: UUID,
        from_version: int = 0,
        to_version: Optional[int] = None,
    ) -> List[Event]:
        """Return events for ``aggregate_id`` ordered by ascending version."""
        ...


class InMemoryEventStore:
    """Non-durable event store backed by a per-aggregate list.

    Suitable for unit tests and single-process demos. Not shared across
    processes and lost on restart — never select this in production.

    Complexity: ``append`` O(1) amortised; ``get_events`` O(k) for k matching
    events (already version-ordered by construction).
    """

    def __init__(self) -> None:
        self._events: Dict[UUID, List[Event]] = {}
        self._sequence: int = 0
        self._lock = asyncio.Lock()

    async def append(self, event: Event) -> int:
        assert event.version >= 1, "event.version must be >= 1"
        async with self._lock:
            history = self._events.setdefault(event.aggregate_id, [])
            current_version = history[-1].version if history else 0
            expected = event.version - 1
            if current_version != expected:
                raise ConcurrencyError(event.aggregate_id, expected, current_version)
            self._sequence += 1
            stored = _with_sequence(event, self._sequence)
            history.append(stored)
            return self._sequence

    async def get_events(
        self,
        aggregate_id: UUID,
        from_version: int = 0,
        to_version: Optional[int] = None,
    ) -> List[Event]:
        history = self._events.get(aggregate_id, [])
        result = [
            e
            for e in history
            if e.version >= from_version
            and (to_version is None or e.version <= to_version)
        ]
        return result


class SqliteEventStore:
    """Durable single-node event store backed by aiosqlite.

    Honours the same optimistic-concurrency contract as the Postgres store. A
    unique index on ``(aggregate_id, version)`` enforces the invariant at the
    storage layer in addition to the read-check, so concurrent writers cannot
    both commit the same version.

    Use :meth:`create` for connection setup and schema initialisation.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
        sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id        TEXT NOT NULL UNIQUE,
        aggregate_id    TEXT NOT NULL,
        aggregate_type  TEXT NOT NULL,
        version         INTEGER NOT NULL,
        event_type      TEXT NOT NULL,
        event_data      TEXT NOT NULL,
        metadata        TEXT NOT NULL,
        timestamp       TEXT NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS ux_events_aggregate_version
        ON events (aggregate_id, version);
    """

    def __init__(self, connection: "aiosqlite.Connection") -> None:
        self._conn = connection
        self._lock = asyncio.Lock()

    @classmethod
    async def create(cls, database_path: str) -> "SqliteEventStore":
        """Open ``database_path`` (creating parent dirs) and initialise schema."""
        if not _AIOSQLITE_AVAILABLE:  # pragma: no cover
            raise ImportError("aiosqlite is required for SqliteEventStore")
        if database_path not in (":memory:", ""):
            parent = os.path.dirname(os.path.abspath(database_path))
            os.makedirs(parent, exist_ok=True)
        conn = await aiosqlite.connect(database_path)
        await conn.executescript(cls._SCHEMA)
        await conn.commit()
        return cls(conn)

    async def append(self, event: Event) -> int:
        assert event.version >= 1, "event.version must be >= 1"
        async with self._lock:
            async with self._conn.execute(
                "SELECT COALESCE(MAX(version), 0) FROM events WHERE aggregate_id = ?",
                (str(event.aggregate_id),),
            ) as cur:
                row = await cur.fetchone()
            current_version = int(row[0]) if row else 0
            expected = event.version - 1
            if current_version != expected:
                raise ConcurrencyError(event.aggregate_id, expected, current_version)
            cursor = await self._conn.execute(
                """
                INSERT INTO events (
                    event_id, aggregate_id, aggregate_type, version,
                    event_type, event_data, metadata, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(event.event_id),
                    str(event.aggregate_id),
                    event.aggregate_type.value,
                    event.version,
                    event.event_type,
                    json.dumps(event.event_data),
                    json.dumps(event.metadata),
                    event.timestamp.isoformat(),
                ),
            )
            await self._conn.commit()
            return int(cursor.lastrowid)

    async def get_events(
        self,
        aggregate_id: UUID,
        from_version: int = 0,
        to_version: Optional[int] = None,
    ) -> List[Event]:
        if to_version is None:
            query = (
                "SELECT event_id, aggregate_id, aggregate_type, version, "
                "event_type, event_data, metadata, sequence_number, timestamp "
                "FROM events WHERE aggregate_id = ? AND version >= ? "
                "ORDER BY version ASC"
            )
            params: tuple = (str(aggregate_id), from_version)
        else:
            query = (
                "SELECT event_id, aggregate_id, aggregate_type, version, "
                "event_type, event_data, metadata, sequence_number, timestamp "
                "FROM events WHERE aggregate_id = ? AND version >= ? AND version <= ? "
                "ORDER BY version ASC"
            )
            params = (str(aggregate_id), from_version, to_version)
        async with self._conn.execute(query, params) as cur:
            rows = await cur.fetchall()
        return [_row_to_event(row) for row in rows]

    async def close(self) -> None:
        """Close the underlying connection."""
        await self._conn.close()


def _with_sequence(event: Event, sequence_number: int) -> Event:
    """Return a copy of ``event`` with ``sequence_number`` populated."""
    from dataclasses import replace

    return replace(event, sequence_number=sequence_number)


def _row_to_event(row: Any) -> Event:
    """Reconstruct an :class:`Event` from a SQLite row tuple."""
    from vorsyghta.core.event_sourcing import AggregateType

    return Event(
        event_id=UUID(row[0]),
        aggregate_id=UUID(row[1]),
        aggregate_type=AggregateType(row[2]),
        event_type=row[4],
        event_data=json.loads(row[5]),
        metadata=json.loads(row[6]),
        sequence_number=int(row[7]),
        timestamp=datetime.fromisoformat(row[8]),
        version=int(row[3]),
    )


async def build_event_store(
    database_url: Optional[str] = None,
) -> EventStorePort:
    """Select and construct an event store from configuration.

    Selection rules (in order):
        1. ``postgresql://`` / ``postgres://`` / SQLAlchemy-style
           ``postgresql+<driver>://`` URL                -> PostgresEventStore.
        2. ``sqlite:///path`` URL or a filesystem path -> SqliteEventStore.
        3. Otherwise (no URL / ``:memory:``)           -> InMemoryEventStore.

    Args:
        database_url: Explicit URL; falls back to the ``DATABASE_URL`` env var.

    Returns:
        A ready-to-use object satisfying :class:`EventStorePort`.
    """
    url = database_url if database_url is not None else os.getenv("DATABASE_URL")

    if url and url.startswith(("postgresql://", "postgres://", "postgresql+")):
        from vorsyghta.core.postgres_event_store import PostgresEventStore

        # Normalize SQLAlchemy-style DSNs (e.g. postgresql+asyncpg://) to the
        # plain scheme asyncpg expects. create() initializes the schema itself.
        scheme, _, rest = url.partition("://")
        if "+" in scheme:
            url = scheme.split("+", 1)[0] + "://" + rest
        return await PostgresEventStore.create(url)

    if url and url.startswith("sqlite:///"):
        return await SqliteEventStore.create(url[len("sqlite:///"):])

    if url and url not in (":memory:",) and not url.endswith("://"):
        # Treat a bare filesystem path as a SQLite database location.
        return await SqliteEventStore.create(url)

    return InMemoryEventStore()
