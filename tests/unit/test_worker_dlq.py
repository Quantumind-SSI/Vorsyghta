"""Regression tests: TeamWorker handler failures route to the DLQ.

Prior behavior: handler exceptions were silently swallowed (``except: pass``),
losing events. The worker now forwards failed events to the DLQ, and the
supervisor restarts crashed workers.
"""

import asyncio

import pytest

from vorsyghta.core.event_types import BusEvent, EventType
from vorsyghta.core.worker.base import TeamWorker, _supervise, run_all, stop_all
from vorsyghta.core.worker.observability import DLQ


class FakeBroker:
    """Minimal async broker: yields queued events from stream()."""

    def __init__(self, events=None):
        self.events = list(events or [])
        self.published = []
        self.closed = False

    async def stream(self, topic, group, consumer):
        while self.events:
            yield self.events.pop(0)

    async def publish(self, topic, event, key=None):
        self.published.append((topic, event))
        return f"fake-{len(self.published)}"

    async def aclose(self):
        self.closed = True


def _event():
    return BusEvent(event_type=EventType.RED_TEAM_ATTACK_STAGE, tenant_id="t")


@pytest.mark.asyncio
async def test_handler_failure_goes_to_dlq():
    broker = FakeBroker([_event()])
    dlq = DLQ(FakeBroker())
    calls = []

    async def handler(event):
        calls.append(event)
        raise RuntimeError("boom")

    worker = TeamWorker("red", ["red_team.attack_stage"], broker, handler, dlq=dlq)
    task = asyncio.create_task(worker._consume("red_team.attack_stage", "g", "c"))
    await asyncio.wait_for(task, timeout=2)

    assert len(calls) == 1, "handler ran"
    assert dlq.broker.published, "failed event published to DLQ"
    assert dlq.broker.published[0][0] == "dlq.red_team.attack_stage"


@pytest.mark.asyncio
async def test_handler_success_no_dlq():
    broker = FakeBroker([_event()])
    dlq = DLQ(FakeBroker())

    async def handler(event):
        return None

    worker = TeamWorker("red", ["red_team.attack_stage"], broker, handler, dlq=dlq)
    await asyncio.wait_for(
        asyncio.create_task(worker._consume("red_team.attack_stage", "g", "c")),
        timeout=2,
    )
    assert not dlq.broker.published, "no DLQ publish on success"


@pytest.mark.asyncio
async def test_supervisor_restarts_crashed_worker():
    broker = FakeBroker()
    crashes = []

    async def handler(event):
        crashes.append(1)
        raise RuntimeError("worker crash")

    worker = TeamWorker("red", ["red_team.attack_stage"], broker, handler)
    # run() will crash immediately because broker.stream is an empty generator
    # returning — no; simulate a crash by making run raise.
    async def crash_run(consumer_group="v", consumer=None):
        crashes.append(1)
        raise RuntimeError("crash")

    worker.run = crash_run
    task = asyncio.create_task(_supervise(worker, restart_backoff=0.01))
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(crashes) >= 2, "supervisor restarted the crashed worker"


@pytest.mark.asyncio
async def test_stop_all_cancels_tasks():
    async def forever():
        while True:
            await asyncio.sleep(1)

    tasks = [asyncio.create_task(forever()) for _ in range(3)]
    await stop_all(tasks)
    assert all(t.cancelled() for t in tasks)
