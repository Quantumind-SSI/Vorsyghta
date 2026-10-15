import pytest
from vorsyghta.core.worker.observability import DLQ

@pytest.mark.asyncio
async def test_dlq_send():
    class FakeBroker:
        published = []
        async def publish(self, topic, event):
            self.published.append((topic, event))
    dlq = DLQ(FakeBroker())
    await dlq.send("test.topic", object(), "error")
    assert len(dlq.broker.published) == 1
