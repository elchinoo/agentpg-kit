"""Prometheus metrics with the family names every app exposes, so one PagerLens agent preset reads them all:
http_requests_total, http_request_duration_seconds, db_up, app_info and process_*."""
import logging
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.process_collector import ProcessCollector

log = logging.getLogger("apgkit.metrics")


def add_insights_collector(registry: CollectorRegistry, connect: Callable[[], AbstractContextManager], app: str, *, top: int = 5,
                           min_calls: int = 5, ttl: float = 30.0) -> None:
    """Optional: export query insights (see `apgkit.insights`) as small-cardinality gauges so PagerLens can alert on slow-query
    regressions. `connect` returns a connection usable in a `with` block (e.g. `db.connect`). At scrape time (cached for `ttl` seconds,
    so frequent scrapes do not hit the database):

    - `db_insights_available{app}`: 1 when a statistics source could be read, else 0 (the other gauges are then absent)
    - `db_insights_top_query_mean_seconds{app,queryid}`: mean execution time of the `top` slowest statements with >= `min_calls` calls
    - `db_insights_statement_calls{app}`: calls across the statements seen (a gauge: statistics buckets roll off)
    - `db_insights_tuner_recommendations{app}`: number of edb_pg_tuner recommendations (absent when edb_pg_tuner is unavailable)

    A scrape never fails: any error means `db_insights_available 0`."""
    from . import insights
    lock, cache = threading.Lock(), {"at": 0.0, "families": []}

    def build() -> list:
        out = []
        with connect() as conn:
            tq = insights.top_queries(conn, "mean", 100)
            tn = insights.tuner(conn)
        g = GaugeMetricFamily("db_insights_available", "1 when query statistics could be read", labels=["app"])
        g.add_metric([app], 1 if tq["available"] else 0)
        out.append(g)
        if tq["available"]:
            qs = tq["queries"]
            slow = GaugeMetricFamily("db_insights_top_query_mean_seconds", "Mean execution time of the slowest statements",
                                     labels=["app", "queryid"])
            for q in [q for q in qs if q["calls"] >= min_calls and q["mean_ms"] is not None][:top]:
                slow.add_metric([app, q["queryid"]], q["mean_ms"] / 1000)
            calls = GaugeMetricFamily("db_insights_statement_calls", "Statement calls across the statistics window", labels=["app"])
            calls.add_metric([app], sum(q["calls"] for q in qs))
            out += [slow, calls]
        if tn["available"]:
            t = GaugeMetricFamily("db_insights_tuner_recommendations", "edb_pg_tuner recommendations", labels=["app"])
            t.add_metric([app], len(tn["recommendations"]))
            out.append(t)
        return out

    class _Collector:
        def collect(self):
            with lock:
                if time.monotonic() - cache["at"] >= ttl:
                    try:
                        cache["families"] = build()
                    except Exception as exc:  # noqa: BLE001
                        log.warning("insights collector failed: %s", exc)
                        g = GaugeMetricFamily("db_insights_available", "1 when query statistics could be read", labels=["app"])
                        g.add_metric([app], 0)
                        cache["families"] = [g]
                    cache["at"] = time.monotonic()
                families = list(cache["families"])
            yield from families

    registry.register(_Collector())


class Metrics:
    def __init__(self, app: str, version: str):
        self.app = app
        self.registry = CollectorRegistry()
        ProcessCollector(registry=self.registry)
        self.requests = Counter("http_requests_total", "HTTP requests handled", ["app", "method", "route", "status"], registry=self.registry)
        self.latency = Histogram("http_request_duration_seconds", "HTTP request latency", ["app", "route"], registry=self.registry,
                                 buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.18, 0.25, 0.5, 1, 2.5, 5, 10))
        info = Gauge("app_info", "Build information", ["app", "version"], registry=self.registry)
        info.labels(app, version).set(1)

    def observe(self, method: str, route: str, status: int, started: float) -> None:
        self.requests.labels(self.app, method, route, str(status)).inc()
        self.latency.labels(self.app, route).observe(time.perf_counter() - started)

    def add_db_collector(self, probe: Callable[[], dict[str, float]]) -> None:
        """`probe` runs at scrape time and returns {metric_name: value}; it must return at least db_up.
        If it raises, db_up is 0: a scrape never fails because the database is down, that is the signal."""
        app = self.app

        class _Collector:
            def collect(self):
                try:
                    values = probe()
                except Exception:  # noqa: BLE001
                    values = {"db_up": 0}
                for name, value in values.items():
                    g = GaugeMetricFamily(name, name.replace("_", " "), labels=["app"])
                    g.add_metric([app], value)
                    yield g

        self.registry.register(_Collector())

    def add_insights_collector(self, connect: Callable[[], AbstractContextManager], **kw) -> None:
        add_insights_collector(self.registry, connect, self.app, **kw)

    def render(self) -> tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST
