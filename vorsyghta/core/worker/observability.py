import logging
logger = logging.getLogger(__name__)

class DLQ:
    def __init__(self, broker):
        self.broker = broker
    async def send(self, topic, event, reason):
        logger.error("DLQ %s %s", topic, reason)
        await self.broker.publish(f"dlq.{topic}", event)
