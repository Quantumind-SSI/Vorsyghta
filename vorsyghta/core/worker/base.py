from __future__ import annotations
import asyncio
import logging
from typing import Callable

from vorsyghta.core.broker.redis_broker import RedisStreamsBroker
from vorsyghta.core.event_types import BusEvent

logger = logging.getLogger(__name__)


class TeamWorker:
    def __init__(
        self,
        name: str,
        topics: list[str],
        broker: RedisStreamsBroker,
        handler: Callable[[BusEvent], None],
        dlq=None,
    ):
        self.name = name
        self.topics = topics
        self.broker = broker
        self.handler = handler
        self.dlq = dlq

    async def run(self, consumer_group: str = "vorsyghta", consumer: str | None = None):
        consumer_name = consumer or self.name
        tasks = []
        for topic in self.topics:
            tasks.append(asyncio.create_task(self._consume(topic, consumer_group, consumer_name)))
        await asyncio.gather(*tasks)

    async def _consume(self, topic: str, group: str, consumer: str):
        async for event in self.broker.stream(topic, group, consumer):
            try:
                await self.handler(event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Failed events must not be lost: forward to the DLQ stream.
                if self.dlq is not None:
                    try:
                        await self.dlq.send(topic, event, f"{type(exc).__name__}: {exc}")
                    except Exception:
                        logger.exception("DLQ publish failed for topic %s", topic)
                else:
                    logger.exception("Handler failed on topic %s and no DLQ configured", topic)


async def _supervise(worker: TeamWorker, restart_backoff: float = 1.0) -> None:
    """Restart a crashed worker.run() forever, backing off between attempts."""
    while True:
        try:
            await worker.run()
            # run() returning means the stream ended; treat as clean exit and
            # stop supervising.
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Worker %s crashed (%s); restarting in %.2fs", worker.name, exc, restart_backoff)
            await asyncio.sleep(restart_backoff)


async def run_all(broker: RedisStreamsBroker, workers: list[TeamWorker], dlq=None) -> list[asyncio.Task]:
    """Start every worker under supervision and return the supervisor tasks."""
    tasks: list[asyncio.Task] = []
    for worker in workers:
        if dlq is not None and worker.dlq is None:
            worker.dlq = dlq
        tasks.append(asyncio.create_task(_supervise(worker)))
    return tasks


async def stop_all(tasks: list[asyncio.Task]) -> None:
    """Cancel and await every task; swallow cancellation."""
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
