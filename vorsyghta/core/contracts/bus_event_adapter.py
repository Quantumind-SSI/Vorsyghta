"""BusEvent → EventSourcing Event adapter.

Converts a BusEvent (pub/sub wire format) into the frozen EventSourcing Event
with monotonic per-aggregate versioning for the EventStorePort.
"""
from __future__ import annotations
from typing import Optional
from uuid import uuid4, UUID
from vorsyghta.core.event_types import BusEvent
from vorsyghta.core.event_sourcing import Event, AggregateType


class BusEventToEventAdapter:
    """Adapter that maps BusEvent to Event with aggregate versioning."""

    def __init__(self) -> None:
        self._aggregate_versions: dict[UUID | str, int] = {}

    def adapt(self, bus_event: BusEvent, aggregate_id: Optional[str] = None) -> Event:
        agg_id_raw = aggregate_id or getattr(bus_event, "exercise_id", None) or str(uuid4())
        try:
            agg_id: UUID | str = UUID(str(agg_id_raw))
        except Exception:
            agg_id = agg_id_raw  # type: ignore

        current_version = self._aggregate_versions.get(agg_id, 0)
        next_version = current_version + 1
        self._aggregate_versions[agg_id] = next_version

        data = bus_event.to_dict() if hasattr(bus_event, "to_dict") else dict(bus_event.__dict__)

        return Event(
            event_id=UUID(str(uuid4())),
            aggregate_id=agg_id,
            aggregate_type=AggregateType.SIMULATION,
            event_type=bus_event.event_type.value
            if hasattr(bus_event.event_type, "value")
            else str(bus_event.event_type),
            event_data=data,
            metadata={"tenant_id": getattr(bus_event, "tenant_id", None)},
            sequence_number=0,
            timestamp=bus_event.timestamp,
            version=next_version,
        )
