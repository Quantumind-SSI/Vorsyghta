"""Shared typed contracts that connect Vorsyghta's teams.

This package defines the seams every team and every event store implements, so
that the color/functional teams communicate through one typed contract rather
than ad-hoc dictionaries.

Exports:
    EventStorePort:        Protocol every event store satisfies (append/get_events).
    InMemoryEventStore:    Non-durable store for tests and single-process demos.
    SqliteEventStore:      Durable single-node store (aiosqlite).
    build_event_store:     Config-driven factory (Postgres in prod, else SQLite/memory).
    BusEventToEventAdapter: Converts a BusEvent into the frozen event-sourcing Event
                            with monotonic per-aggregate versioning.

Owner: Vorsyghta Core — see docs/architecture/TEAM_ARCHITECTURE.md
"""
from __future__ import annotations

from vorsyghta.core.contracts.event_store_port import (
    EventStorePort,
    InMemoryEventStore,
    SqliteEventStore,
    build_event_store,
)
from vorsyghta.core.contracts.bus_event_adapter import BusEventToEventAdapter

__all__ = [
    "EventStorePort",
    "InMemoryEventStore",
    "SqliteEventStore",
    "build_event_store",
    "BusEventToEventAdapter",
]
