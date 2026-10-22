"""Postgres connections. The database may be scaled to zero (AgentPG), so connecting retries with backoff.

`Database` holds the URL source and an optional pool for hot paths. The pgvector adapter is registered when the extension
exists, and quietly skipped before the first migration has created it.
"""
import sys
import threading
import time
from collections.abc import Callable

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .config import database_url


def _register_vector(conn: psycopg.Connection) -> None:
    try:
        from pgvector.psycopg import register_vector
        register_vector(conn)
    except psycopg.ProgrammingError:       # the extension does not exist yet: the migration creates it
        conn.rollback()


class Database:
    def __init__(self, url: Callable[[], str] = database_url, *, vector: bool = False, pool_max: int = 20):
        self._url, self.vector, self.pool_max = url, vector, pool_max
        self._pool: ConnectionPool | None = None
        self._lock = threading.Lock()

    def connect(self, retries: int = 5, delay: float = 1.0) -> psycopg.Connection:
        last: Exception | None = None
        for attempt in range(retries):
            try:
                conn = psycopg.connect(self._url(), row_factory=dict_row, connect_timeout=10)
                if self.vector:
                    _register_vector(conn)
                return conn
            except psycopg.OperationalError as exc:       # cold start / waking database
                last = exc
                if retries > 1:                           # say what is happening (the message holds no password)
                    print(f"database not reachable (attempt {attempt + 1}/{retries}): {str(exc).strip().splitlines()[0][:200]}",
                          file=sys.stderr, flush=True)
                time.sleep(delay * (2**attempt))
        raise RuntimeError(f"database unavailable after {retries} attempts: {last}")

    def pool(self) -> ConnectionPool:
        with self._lock:
            if self._pool is None:
                def configure(conn):
                    if self.vector:
                        _register_vector(conn)
                    conn.commit()
                self._pool = ConnectionPool(self._url(), min_size=2, max_size=self.pool_max, open=False, timeout=5,
                                            kwargs={"row_factory": dict_row, "connect_timeout": 10}, configure=configure)
                self._pool.open(wait=True, timeout=30)
            return self._pool

    def close_pool(self) -> None:
        with self._lock:
            if self._pool is not None:
                self._pool.close()
                self._pool = None
