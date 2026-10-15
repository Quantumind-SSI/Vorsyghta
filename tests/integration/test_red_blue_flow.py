import pytest

from vorsyghta.core.broker.redis_broker import decode_event, encode_event
from vorsyghta.core.event_types import BusEvent, EventType


def test_encode_decode_roundtrip():
    """A typed BusEvent survives serialization with tenant/exercise intact."""
    event = BusEvent(
        event_type=EventType.RED_TEAM_ATTACK_STAGE,
        tenant_id="tenant-a",
        exercise_id="ex-1",
        payload={"stage_id": "s1", "technique_id": "T1566"},
    )

    raw = encode_event(event)
    decoded = decode_event(raw)

    assert decoded.tenant_id == "tenant-a"
    assert decoded.exercise_id == "ex-1"
    assert decoded.payload["technique_id"] == "T1566"
    assert decoded.event_type == EventType.RED_TEAM_ATTACK_STAGE
