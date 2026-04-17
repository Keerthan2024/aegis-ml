import asyncio
from typing import List

from backend.core.schemas import UnifiedEvent
from backend.core.config import QUEUE_MAX_SIZE, BATCH_SIZE


class AsyncEventQueue:
    """
    An asynchronous queue for incoming events that provides backpressure 
    by dropping the oldest events when full, and supports batch extraction.
    """

    def __init__(self):
        self.queue = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
        self.total_received = 0
        self.total_dropped = 0

    async def push(self, event: UnifiedEvent) -> bool:
        """
        Push event onto the queue. 
        Drops the oldest event if the queue is full (backpressure).
        """
        try:
            self.queue.put_nowait(event)
            self.total_received += 1
            return True
        except asyncio.QueueFull:
            # Drop the oldest to make room
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(event)
                self.total_dropped += 1
                self.total_received += 1
                return True
            except Exception:
                return False

    async def consume_batch(self) -> List[UnifiedEvent]:
        """
        Pull up to BATCH_SIZE events. 
        Waits a maximum of 0.1s for the first event.
        """
        batch = []
        try:
            first = await asyncio.wait_for(self.queue.get(), timeout=0.1)
            batch.append(first)
        except asyncio.TimeoutError:
            return []
        
        # Drain remaining without waiting
        for _ in range(BATCH_SIZE - 1):
            try:
                batch.append(self.queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        
        return batch

    @property
    def size(self) -> int:
        return self.queue.qsize()

    @property
    def stats(self) -> dict:
        return {
            "received": self.total_received,
            "dropped": self.total_dropped,
            "current_size": self.size,
            "drop_rate": self.total_dropped / max(self.total_received, 1)
        }
