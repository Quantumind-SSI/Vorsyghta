"""Integration tests: adapter contract (BusEvent → event-sourcing Event with
per-aggregate versioning, as consumed by the event store)."""


from vorsyghta.core.contracts import BusEventToEventAdapter
from vorsyghta.core.event_types import BusEvent, EventType


def _bus_event() -> BusEvent:
    return BusEvent(
        event_type=EventType.RED_TEAM_ATTACK_STAGE,
        tenant_id="tenant-a",
        exercise_id="agg-1",
        payload={"stage_id": "s1"},
    )


def test_bus_event_maps_to_store_event():
    adapter = BusEventToEventAdapter()
    ev = adapter.adapt(_bus_event(), "agg-1")
    assert str(ev.aggregate_id) == "agg-1"
    assert ev.event_type == "red_team.attack_stage"
    assert ev.version == 1
    assert ev.event_data["payload"]["stage_id"] == "s1"


def test_same_aggregate_versions_increment():
    adapter = BusEventToEventAdapter()
    bus_event = _bus_event()
    first = adapter.adapt(bus_event, "agg-1")
    second = adapter.adapt(bus_event, "agg-1")
    assert second.version == first.version + 1


def test_non_uuid_aggregate_is_kept_verbatim():
    adapter = BusEventToEventAdapter()
    ev = adapter.adapt(_bus_event(), "not-a-uuid")
    assert str(ev.aggregate_id) == "not-a-uuid"
