"""Prometheus metrics with the family names every app exposes, so one PagerLens agent preset reads them all:
http_requests_total, http_request_duration_seconds, db_up, app_info and process_*."""
import time
from collections.abc import Callable

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

    def render(self) -> tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST
