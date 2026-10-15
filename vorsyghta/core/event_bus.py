"""Shared async event bus for Vorsyghta color-team communication.

The event bus provides an in-process async pub/sub channel used by the exercise
orchestrator to route events between color teams (Red, Blue, Purple, White,
Black). All events are persisted to the event store for audit trail.

Owner: Ajibola Shokunbi (@jiboo2022) — Core Software Lead
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from vorsyghta.core.event_types import BusEvent, EventType

logger = logging.getLogger(__name__)

EventHandler = Callable[[BusEvent], Any]


class EventBus:
    """In-process async pub/sub event bus with optional persistence.

    The bus is designed to be created once per application and shared across
    all color teams. Handlers can be coroutines or regular functions. Events are
    delivered to handlers concurrently using asyncio.gather.

    Attributes:
        _handlers: Mapping from event type to list of subscribed handlers.
        _event_store: Optional event store for audit persistence.
    """

    def __init__(self, event_store: Optional[Any] = None):
        self._handlers: Dict[EventType, List[EventHandler]] = {
            event_type: [] for event_type in EventType
        }
        self._event_store: Optional[Any] = event_store
        self._lock = asyncio.Lock()
        self._adapter = None
        if event_store is not None:
            from vorsyghta.core.contracts import BusEventToEventAdapter
            self._adapter = BusEventToEventAdapter()
        else:
            logger.warning("EventBus created without event_store – persistence disabled for production")

    @property
    def has_event_store(self) -> bool:
        """Whether an event store is attached for persistence."""
        return self._event_store is not None

    def attach_event_store(self, event_store: Any) -> None:
        """Attach (or replace) the event store used for persistence.

        Enables async construction paths: build the bus synchronously, then
        attach a store awaited in async context (e.g. ``run_exercise``).
        """
        self._event_store = event_store
        from vorsyghta.core.contracts import BusEventToEventAdapter
        self._adapter = BusEventToEventAdapter()

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Register a handler for a specific event type.

        Args:
            event_type: The event type to subscribe to.
            handler: Callable or coroutine that receives a :class:`BusEvent`.
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
        logger.debug("Subscribed handler to %s", event_type.value)

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Remove a handler from an event type.

        Args:
            event_type: The event type to unsubscribe from.
            handler: The handler to remove.
        """
        if event_type in self._handlers and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
            logger.debug("Unsubscribed handler from %s", event_type.value)

    def subscribe_many(
        self, event_types: List[EventType], handler: EventHandler
    ) -> None:
        """Register a handler for multiple event types."""
        for event_type in event_types:
            self.subscribe(event_type, handler)

    async def publish(self, event: BusEvent) -> None:
        """Publish an event to all subscribers and optionally persist it.

        Args:
            event: The event to publish.
        """
        logger.debug(
            "Publishing %s for tenant %s", event.event_type.value, event.tenant_id
        )

        # Persist to event store if available
        if self._event_store is not None:
            try:
                await self._persist_event(event)
            except Exception as exc:
                logger.warning("Failed to persist event %s: %s", event.event_id, exc)

        handlers = list(self._handlers.get(event.event_type, []))
        if not handlers:
            return

        # Deliver to handlers concurrently
        results = await asyncio.gather(
            *[self._invoke_handler(handler, event) for handler in handlers],
            return_exceptions=True,
        )

        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(
                    "Event handler %s for %s failed: %s",
                    handlers[idx].__name__,
                    event.event_type.value,
                    result,
                )

    async def _invoke_handler(self, handler: EventHandler, event: BusEvent) -> None:
        """Invoke a single handler, supporting both sync and async handlers."""
        result = handler(event)
        if asyncio.iscoroutine(result):
            await result

    async def _persist_event(self, event: BusEvent) -> None:
        """Persist the event to the configured event store."""
        if self._event_store is None:
            return
        append = getattr(self._event_store, "append", None)
        if append is None:
            return
        if self._adapter:
            # Adapt BusEvent to Event with versioning
            adapted = self._adapter.adapt(event, getattr(event, "aggregate_id", None))
            await append(adapted)
        else:
            # Fallback for legacy stores expecting dict
            await append(event.to_dict())

    def get_subscriber_count(self, event_type: EventType) -> int:
        """Return the number of subscribers for an event type."""
        return len(self._handlers.get(event_type, []))
