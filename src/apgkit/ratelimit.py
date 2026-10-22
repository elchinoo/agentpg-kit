"""Failed-attempt rate limiting, in memory and per process (put proxy-level limits in front too)."""
import threading
import time


class FailureLimiter:
    def __init__(self, window: float = 60.0, limit: int = 10, max_clients: int = 10_000):
        self.window, self.limit, self.max_clients = window, limit, max_clients
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def limited(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            recent = [t for t in self._failures.get(client, []) if now - t < self.window]
            self._failures[client] = recent
            return len(recent) >= self.limit

    def record(self, client: str) -> None:
        with self._lock:
            self._failures.setdefault(client, []).append(time.monotonic())
            if len(self._failures) > self.max_clients:      # bound memory under address churn
                self._failures.clear()

    def clear(self) -> None:
        with self._lock:
            self._failures.clear()
