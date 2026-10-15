import asyncio

import pytest

from vorsyghta.llm.dispatcher import LLMQueue


@pytest.mark.asyncio
async def test_llm_priority():
    """White-team jobs dequeue before black-team jobs under concurrency."""
    q = LLMQueue()
    order: list[str] = []
    done = asyncio.Event()

    async def job(name: str) -> None:
        order.append(name)
        if len(order) >= 2:
            done.set()

    # Enqueue out of priority order: black first, then white.
    await q.submit("black", job("black"))
    await q.submit("white", job("white"))

    runner = asyncio.create_task(q.start())
    try:
        await asyncio.wait_for(done.wait(), timeout=5)
    finally:
        q.stop()
        runner.cancel()

    # White (priority 0) must run before black (priority 7).
    assert order[0] == "white"
    assert order[1] == "black"
    assert q.PRIORITY["white"] < q.PRIORITY["black"]
