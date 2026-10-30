"""Failed-attempt rate limiting, in memory and per process (put proxy-level limits in front too).

Memory is bounded without ever resetting the whole table: entries whose failures all fell out of the window are dropped first,
then, only if the table is still over `max_clients`, the least recently touched clients are evicted one by one. An attacker who
churns addresses therefore cannot wipe the counters of clients that are being limited.
"""
import threading
import time
from collections import OrderedDict


class FailureLimiter:
    def __init__(self, window: float = 60.0, limit: int = 10, max_clients: int = 10_000):
        self.window, self.limit, self.max_clients = window, limit, max_clients
        self._failures: OrderedDict[str, list[float]] = OrderedDict()      # ordered by last failure, oldest first
        self._lock = threading.Lock()

    def limited(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            times = self._failures.get(client)
            if not times:
                return False
            recent = [t for t in times if now - t < self.window]
            if recent:
                self._failures[client] = recent
            else:
                del self._failures[client]
            return len(recent) >= self.limit

    def _evict(self, now: float) -> None:
        while self._failures:                                                # expired entries sit at the front: drop those first
            oldest = next(iter(self._failures))
            if now - self._failures[oldest][-1] < self.window:
                break
            del self._failures[oldest]
        while len(self._failures) > self.max_clients:                        # still over: least recently failed goes first
            self._failures.popitem(last=False)

    def record(self, client: str) -> None:
        now = time.monotonic()
        with self._lock:
            times = [t for t in self._failures.pop(client, []) if now - t < self.window]
            times.append(now)
            self._failures[client] = times                                   # re-inserted at the end: most recent
            if len(self._failures) > self.max_clients:
                self._evict(now)

    def forgive(self, client: str) -> None:
        """Take back this client's most recent recorded failure (an attempt that succeeded, or was never judged). Forgetting a
        client with no failures is a no-op; a client left with none is removed from the table."""
        with self._lock:
            times = self._failures.get(client)
            if not times:
                return
            times.pop()
            if not times:
                del self._failures[client]

    def clear(self) -> None:
        with self._lock:
            self._failures.clear()
