"""Config, ids, passwords, rate limiting, the URL guard, metrics and the security middleware (no database)."""
import socket

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apgkit import config, ids, passwords
from apgkit.guard import SecurityGuard
from apgkit.metrics import Metrics
from apgkit.netguard import NetGuard, UnsafeURL
from apgkit.ratelimit import FailureLimiter


def test_read_secret_prefers_env_then_file(tmp_path, monkeypatch):
    f = tmp_path / "k"
    f.write_text("from-file\nsecond line\n")
    monkeypatch.delenv("APG_SECRET", raising=False)
    monkeypatch.setenv("APG_SECRET_FILE", str(f))
    assert config.read_secret("APG_SECRET") == "from-file"
    monkeypatch.setenv("APG_SECRET", "from-env")
    assert config.read_secret("APG_SECRET") == "from-env"
    monkeypatch.delenv("APG_SECRET")
    monkeypatch.setenv("APG_SECRET_FILE", str(tmp_path / "missing"))
    assert config.read_secret("APG_SECRET") == ""
    assert config.read_secret("APG_NOPE", "") == ""


def test_database_url_order(monkeypatch):
    for n in config.DATABASE_ENV_NAMES:
        monkeypatch.delenv(n, raising=False)
    assert config.database_url() == ""
    monkeypatch.setenv("PSQL_CONNECTION_STRING", "c")
    monkeypatch.setenv("DB_EXTERNAL_DSN", "b")
    assert config.database_url() == "b"
    monkeypatch.setenv("DATABASE_URL", "a")
    assert config.database_url() == "a"


def test_ids_and_hashes():
    a, b = ids.new_id("x_", 10), ids.new_id("x_", 10)
    assert a != b and a.startswith("x_") and len(a) == 12
    assert ids.sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert ids.hmac_hex("k", "m") == ids.hmac_hex(b"k", "m") and len(ids.hmac_hex("k", "m")) == 64


def test_password_roundtrip_and_strength():
    h = passwords.hash_password("correct horse battery")
    assert h.startswith("scrypt$") and "correct" not in h
    assert passwords.verify_password("correct horse battery", h)
    assert not passwords.verify_password("wrong horse battery", h)
    assert not passwords.verify_password("x", "garbage") and not passwords.verify_password("x", "md5$1$2$3$4$5")
    for bad in ("short", "x" * 257):
        with pytest.raises(ValueError):
            passwords.check_strength(bad)


def test_failure_limiter_window_and_bound():
    lim = FailureLimiter(window=60, limit=3)
    for _ in range(3):
        assert not lim.limited("a")
        lim.record("a")
    assert lim.limited("a") and not lim.limited("b")
    lim.clear()
    assert not lim.limited("a")
    small = FailureLimiter(max_clients=2)
    for c in "abc":
        small.record(c)
    assert len(small._failures) <= 2   # bounded under address churn


@pytest.fixture
def resolve(monkeypatch):
    def fake(addr):
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 443))])
    return fake


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.1.2.3", "192.168.0.9", "100.64.0.5", "169.254.169.254"])
def test_netguard_refuses_private_by_default(resolve, addr, monkeypatch):
    monkeypatch.delenv("APG_ALLOW_PRIVATE", raising=False)
    resolve(addr)
    with pytest.raises(UnsafeURL):
        NetGuard("APG_ALLOW_PRIVATE").check("https://example.org")


def test_netguard_allows_a_public_https_host_and_normalises(resolve):
    resolve("93.184.216.34")
    assert NetGuard("APG_ALLOW_PRIVATE").check("https://example.org/v1/") == "https://example.org/v1"


def test_netguard_private_opt_in_never_covers_link_local(resolve, monkeypatch):
    monkeypatch.setenv("APG_ALLOW_PRIVATE", "true")
    resolve("127.0.0.1")
    assert NetGuard("APG_ALLOW_PRIVATE").check("http://localhost:8080") == "http://localhost:8080"
    resolve("169.254.169.254")
    with pytest.raises(UnsafeURL, match="link-local"):
        NetGuard("APG_ALLOW_PRIVATE").check("http://metadata.internal")


@pytest.mark.parametrize("url", ["", "ftp://x.org", "https://u:p@x.org", "https://x.org/?a=1", "https://x.org/#f", "http://x.org", "x" * 400])
def test_netguard_shape_rules(resolve, url):
    resolve("93.184.216.34")
    with pytest.raises(UnsafeURL):
        NetGuard("APG_ALLOW_PRIVATE").check(url)


def make_app(calls):
    app = FastAPI()

    @app.get("/api/x")
    def get_x():
        return {"ok": True}

    @app.post("/api/x")
    def post_x():
        return {"ok": True}

    @app.get("/metrics")
    def metrics():
        return {}

    app.add_middleware(SecurityGuard, csrf_header="X-Test-CSRF", max_body=100,
                       observe=lambda m, r, s, t: calls.append((m, r, s)))
    return TestClient(app)


def test_guard_headers_csrf_body_cap_and_metrics():
    calls = []
    c = make_app(calls)
    r = c.get("/api/x")
    assert r.status_code == 200
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in r.headers["content-security-policy"] and r.headers["cache-control"] == "no-store"
    assert c.post("/api/x").status_code == 403                                           # a browser write without the header
    assert c.post("/api/x", headers={"X-Test-CSRF": "1"}).status_code == 200
    assert c.post("/api/x", headers={"Authorization": "Bearer t"}).status_code == 200    # API calls are exempt
    big = c.post("/api/x", headers={"X-Test-CSRF": "1"}, content=b"x" * 500)
    assert big.status_code == 413 and "x-frame-options" in big.headers
    c.get("/metrics")
    assert ("GET", "/api/x", 200) in calls and ("POST", "other", 403) in calls and ("POST", "other", 413) in calls
    assert not any(route == "/metrics" for _, route, _ in calls)                          # scrapes are not counted


def test_metrics_family_names_and_db_collector():
    m = Metrics("demo", "1.2.3")
    m.observe("GET", "/x", 200, 0.0)
    m.add_db_collector(lambda: {"db_up": 1, "demo_things": 7})
    text = m.render()[0].decode()
    for needle in ('http_requests_total{app="demo",method="GET",route="/x",status="200"} 1.0', 'app_info{app="demo",version="1.2.3"} 1.0',
                   'db_up{app="demo"} 1.0', 'demo_things{app="demo"} 7.0', "http_request_duration_seconds_bucket"):
        assert needle in text, needle

    def boom():
        raise RuntimeError("database down")
    n = Metrics("demo", "1")
    n.add_db_collector(boom)
    assert 'db_up{app="demo"} 0.0' in n.render()[0].decode()    # a scrape never fails because the database is down
