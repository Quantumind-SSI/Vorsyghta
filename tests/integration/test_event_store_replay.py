from vorsyghta.core.contracts import BusEventToEventAdapter
from vorsyghta.core.event_types import BusEvent, EventType


def test_adapter():
    """BusEvent adapts to a versioned event-sourcing Event for the store."""
    adapter = BusEventToEventAdapter()
    bus_event = BusEvent(
        event_type=EventType.RED_TEAM_ATTACK_STAGE,
        tenant_id="tenant-a",
        exercise_id="agg-1",
        payload={"stage_id": "s1"},
    )
    ev = adapter.adapt(bus_event, "agg-1")
    assert str(ev.aggregate_id) == "agg-1"
    assert ev.event_type == "red_team.attack_stage"
    assert ev.version == 1
    assert ev.event_data["payload"]["stage_id"] == "s1"

    # Second event on the same aggregate increments the version.
    ev2 = adapter.adapt(bus_event, "agg-1")
    assert ev2.version == 2
