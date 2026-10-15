from __future__ import annotations
from typing import Callable
from vorsyghta.core.broker.redis_broker import RedisStreamsBroker
from vorsyghta.core.event_types import BusEvent

class TeamWorker:
    def __init__(self, name: str, topics: list[str], broker: RedisStreamsBroker, handler: Callable[[BusEvent], None]):
        self.name = name
        self.topics = topics
        self.broker = broker
        self.handler = handler

    async def run(self, consumer_group: str = "vorsyghta", consumer: str | None = None):
        import asyncio
        consumer_name = consumer or self.name
        tasks = []
        for topic in self.topics:
            tasks.append(asyncio.create_task(self._consume(topic, consumer_group, consumer_name)))
        await asyncio.gather(*tasks)

    async def _consume(self, topic: str, group: str, consumer: str):
        async for event in self.broker.stream(topic, group, consumer):
            try:
                await self.handler(event)
            except Exception:
                # DLQ handling placeholder
                pass
