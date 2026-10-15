from __future__ import annotations
import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass

@dataclass
class LLMJob:
    priority: int
    team: str
    coro: asyncio.coroutines

class LLMQueue:
    PRIORITY = {"white":0,"blue":1,"red":2,"purple":3,"green":4,"orange":5,"yellow":6,"black":7}
    def __init__(self):
        self.queues = {p: deque() for p in range(8)}
        self.sem = asyncio.Semaphore(5)
        self._running = False

    async def submit(self, team: str, coro):
        prio = self.PRIORITY.get(team, 7)
        self.queues[prio].append(LLMJob(prio, team, coro))

    async def start(self):
        self._running = True
        while self._running:
            for prio in range(8):
                while self.queues[prio]:
                    job = self.queues[prio].popleft()
                    async with self.sem:
                        asyncio.create_task(job.coro)
            await asyncio.sleep(0.05)

    def stop(self):
        self._running = False
