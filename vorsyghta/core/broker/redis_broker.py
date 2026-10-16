from __future__ import annotations

import json
import logging
import os
from typing import Any, AsyncIterator

import redis.asyncio as aioredis

from vorsyghta.core.broker.contracts import EventBroker
from vorsyghta.core.event_types import BusEvent

logger = logging.getLogger(__name__)


def encode_event(event: BusEvent) -> str:
    """Serialize a BusEvent to a JSON string safe for Redis stream fields."""
    if hasattr(event, "to_dict"):
        data = event.to_dict()
    else:
        data = dict(event.__dict__)
    return json.dumps(data, default=str)


def decode_event(raw: str) -> BusEvent:
    """Reconstruct a BusEvent from its JSON payload."""
    data: dict[str, Any] = json.loads(raw)
    if "tenant_id" in data:
        try:
            return BusEvent.from_dict(data)
        except (ValueError, TypeError, KeyError):
            # Tolerate event_type values outside the EventType enum
            # (legacy producers): fall through to the raw constructor.
            pass
    return BusEvent(**data)  # type: ignore[arg-type]


class RedisStreamsBroker:
    def __init__(self, url: str | None = None):
        self.url = url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.client = None

    async def _get(self):
        if self.client is None:
            self.client = aioredis.from_url(self.url, decode_responses=True)
        return self.client

    async def publish(self, topic: str, event: BusEvent, key: str | None = None) -> str:
        client = await self._get()
        msg_id = await client.xadd(topic, {"payload": encode_event(event)}, id=key or "*")
        return msg_id

    async def stream(self, topic: str, consumer_group: str, consumer: str) -> AsyncIterator[BusEvent]:
        client = await self._get()
        try:
            await client.xgroup_create(topic, consumer_group, id="0", mkstream=True)
        except aioredis.ResponseError as exc:
            # BUSYGROUP = group already exists, which is the idempotent case.
            if "BUSYGROUP" not in str(exc):
                raise
        while True:
            msgs = await client.xreadgroup(consumer_group, consumer, {topic: ">"}, count=10, block=5000)
            if not msgs:
                continue
            for _, entries in msgs:
                for msg_id, data in entries:
                    try:
                        yield decode_event(data["payload"])
                    except Exception as exc:  # noqa: BLE001 - poison message
                        logger.error("Unparsable event %s on %s: %s", msg_id, topic, exc)
                    await client.xack(topic, consumer_group, msg_id)
