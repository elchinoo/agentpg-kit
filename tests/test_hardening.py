"""Hardening: NetGuard (IPv6 forms, pinning), limiter eviction, client address, anonymous and static-key modes."""
import ipaddress
import logging
import socket

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from apgkit import config
from apgkit.auth import Authenticator
from apgkit.auth.local import LocalAuth
from apgkit.auth.principal import AppAuth
from apgkit.guard import SecurityGuard
from apgkit.llm import LLMClient, LLMError
from apgkit.netguard import NetGuard, UnsafeURL, classify
from apgkit.ratelimit import FailureLimiter
from apgkit.web import client_ip, resolve_client

PUBLIC4 = "93.184.216.34"
APP = AppAuth("demo", "demo-client", role_permissions={"admin": frozenset({"*"})}, scope_permissions={"read": frozenset({"things:read"})})


def one(addr):
    return lambda *a, **k: [(socket.AF_INET6 if ":" in addr else socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 443))]


# ---- NetGuard: address classes ------------------------------------------------------------------------------------------
REVIEW_ADDRESSES = ["64:ff9b::a00:1", "64:ff9b::7f00:1", "::10.0.0.1", "fec0::1", "192.0.0.9"]


@pytest.mark.parametrize("addr", REVIEW_ADDRESSES)
def test_netguard_refuses_the_addresses_python_calls_global(addr, monkeypatch):
    monkeypatch.delenv("APG_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", one(addr))
    with pytest.raises(UnsafeURL):
        NetGuard("APG_ALLOW_PRIVATE").check("https://example.org")


PRIVATE_FORMS = [
    # embedded IPv4 in every wrapper
    "64:ff9b::a00:1", "64:ff9b::c0a8:1", "64:ff9b::ac10:1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::6440:1",
    "64:ff9b:1::a00:1", "64:ff9b:1:ffff::1", "::10.0.0.1", "::7f00:1", "::192.168.0.1", "::8.8.8.8",
    "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:192.168.1.1", "::ffff:100.64.0.1",
    "2002:0a00:0001::1", "2002:7f00:0001::1", "2002:c0a8:0101::1", "2002:a9fe:a9fe::1",
    "2001:0:a00:1::1", "2001:0:5efe:1::f5ff:fffe",      # Teredo with a private server / private client (0a00:0001 ^ ffff = f5ff:fffe)
    # other non-public IPv6
    "fec0::1", "fec0:0:0:1::5", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1", "::1", "::", "100::1", "2001:db8::1", "3fff::1",
    # IPv4
    "0.0.0.0", "10.0.0.1", "127.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.0.1", "100.64.0.1", "100.127.255.255", "198.18.0.1",
    "198.19.255.255", "192.0.0.9", "192.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
    "169.254.169.254",
]
PUBLIC_FORMS = [PUBLIC4, "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888", "64:ff9b::808:808", "::ffff:8.8.8.8", "2002:0808:0808::1",
                "2001:0:808:808::f7f7:f7f7"]


@pytest.mark.parametrize("addr", PRIVATE_FORMS)
def test_classify_blocks_every_non_public_form(addr):
    assert classify(ipaddress.ip_address(addr)) in {"private", "link-local"}, addr


@pytest.mark.parametrize("addr", PUBLIC_FORMS)
def test_classify_keeps_public_addresses_usable(addr):
    assert classify(ipaddress.ip_address(addr)) is None, addr


@pytest.mark.parametrize("addr", ["169.254.169.254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "fe80::1"])
def test_link_local_forms_are_never_allowed_even_with_the_private_opt_in(addr, monkeypatch):
    monkeypatch.setenv("APG_ALLOW_PRIVATE", "true")
    monkeypatch.setattr(socket, "getaddrinfo", one(addr))
    with pytest.raises(UnsafeURL, match="link-local"):
        NetGuard("APG_ALLOW_PRIVATE").check("https://metadata.example")


def test_a_mixed_dns_answer_with_one_bad_address_is_refused(monkeypatch):
    monkeypatch.delenv("APG_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a_, 443)) for a_ in (PUBLIC4, "10.0.0.1")])
    with pytest.raises(UnsafeURL):
        NetGuard("APG_ALLOW_PRIVATE").resolve("https://example.org")


# ---- NetGuard: pinning ----------------------------------------------------------------------------------------------------
def test_resolve_pins_the_validated_ip_and_keeps_host_and_sni(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", one(PUBLIC4))
    r = NetGuard("APG_ALLOW_PRIVATE").resolve("https://api.example.org:8443/v1/")
    url, headers, ext = r.request_args("/chat/completions")
    assert r.ip == PUBLIC4 and url == f"https://{PUBLIC4}:8443/v1/chat/completions"
    assert headers == {"Host": "api.example.org:8443"} and ext == {"sni_hostname": "api.example.org"}
    monkeypatch.setattr(socket, "getaddrinfo", one("2606:4700:4700::1111"))
    url, headers, _ = NetGuard("APG_ALLOW_PRIVATE").resolve("https://api.example.org").request_args("/x")
    assert url == "https://[2606:4700:4700::1111]:443/x" and headers == {"Host": "api.example.org"}


def test_llm_client_connects_to_the_pinned_address_and_resolves_only_once(monkeypatch):
    calls = []

    def fake(*a, **k):
        calls.append(a[0])
        return one(PUBLIC4 if len(calls) == 1 else "127.0.0.1")()      # a rebinding DNS: the second answer would be loopback

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    seen = []

    def handler(request: httpx.Request):
        seen.append((str(request.url), request.headers["host"], request.extensions.get("sni_hostname")))
        return httpx.Response(200, json={"ok": 1})

    client = LLMClient(NetGuard("APG_ALLOW_PRIVATE"), http_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    resp = client.post_json("https://api.example.org/v1", "/chat/completions", "k", {}, trusted=False)
    assert resp.status_code == 200 and calls == ["api.example.org"]
    assert seen == [(f"https://{PUBLIC4}/v1/chat/completions", "api.example.org", "api.example.org")]


def test_a_redirect_is_refused_and_never_followed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", one(PUBLIC4))
    seen = []

    def handler(request: httpx.Request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    client = LLMClient(NetGuard("APG_ALLOW_PRIVATE"), http_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False))
    with pytest.raises(LLMError, match="redirected"):
        client.post_json("https://api.example.org/v1", "/x", "k", {}, trusted=False)
    assert len(seen) == 1


def test_a_rebinding_host_that_turns_private_is_refused_on_the_next_call(monkeypatch):
    monkeypatch.delenv("APG_ALLOW_PRIVATE", raising=False)
    guard = NetGuard("APG_ALLOW_PRIVATE")
    monkeypatch.setattr(socket, "getaddrinfo", one(PUBLIC4))
    guard.resolve("https://api.example.org")
    monkeypatch.setattr(socket, "getaddrinfo", one("64:ff9b::a00:1"))
    with pytest.raises(UnsafeURL):
        guard.resolve("https://api.example.org")


# ---- limiter ------------------------------------------------------------------------------------------------------------------
def test_limiter_eviction_drops_only_the_oldest_and_keeps_active_limits():
    lim = FailureLimiter(window=60, limit=3, max_clients=100)
    for _ in range(3):
        lim.record("victim")
    assert lim.limited("victim")
    for i in range(5_000):                                  # address churn from an attacker
        lim.record(f"spray-{i}")
    assert len(lim._failures) <= 100
    # the sprayed entries are as recent as the victim's, so eviction is by age: the oldest spray entries go first, then the
    # victim's, which is the documented bound. Without churn beyond the cap the limit must survive:
    lim2 = FailureLimiter(window=60, limit=3, max_clients=100)
    for _ in range(3):
        lim2.record("victim")
    for i in range(99):
        lim2.record(f"c{i}")
    assert lim2.limited("victim") and len(lim2._failures) == 100
    lim2.record("one-more")                                 # one over the cap evicts exactly one entry, the oldest, not all
    assert len(lim2._failures) == 100 and "victim" not in lim2._failures and "c98" in lim2._failures


def test_limiter_touch_refreshes_age_and_expired_entries_go_first(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("apgkit.ratelimit.time.monotonic", lambda: now[0])
    lim = FailureLimiter(window=60, limit=2, max_clients=3)
    lim.record("old")
    now[0] += 61                                            # "old" expires
    for c in ("a", "b"):
        lim.record(c)
    lim.record("a")                                         # a is now the most recent
    lim.record("c")                                         # over the cap: expired "old" is dropped, nobody else
    assert set(lim._failures) == {"a", "b", "c"}
    lim.record("d")                                         # nothing expired: the least recently failed (b) goes
    assert set(lim._failures) == {"a", "c", "d"}
    assert lim.limited("a")
    assert not lim.limited("never-seen") and "never-seen" not in lim._failures    # lookups do not grow the table


# ---- client address -----------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("peer,xff,hops,want", [
    ("10.0.0.5", ["203.0.113.7"], 1, "203.0.113.7"),
    ("10.0.0.5", ["1.2.3.4, 203.0.113.7"], 1, "203.0.113.7"),                  # a spoofed leading entry is ignored
    ("10.0.0.5", ["1.2.3.4", "9.9.9.9, 203.0.113.7"], 1, "203.0.113.7"),       # several header lines
    ("10.0.0.5", ["198.51.100.1, 203.0.113.7, 10.1.1.1"], 2, "203.0.113.7"),
    ("10.0.0.5", ["203.0.113.7"], 0, "10.0.0.5"),                              # 0: the socket peer, header ignored
    ("10.0.0.5", [], 1, "10.0.0.5"),                                           # not through the proxy
    ("10.0.0.5", ["203.0.113.7"], 2, "10.0.0.5"),                              # fewer entries than hops
    ("10.0.0.5", ["not-an-ip"], 1, "10.0.0.5"),
    ("10.0.0.5", ["[2001:db8::1]:443"], 1, "2001:db8::1"),
    ("10.0.0.5", ["203.0.113.7:5555"], 1, "203.0.113.7"),
    (None, [], 1, "unknown"),
])
def test_resolve_client(peer, xff, hops, want):
    assert resolve_client(peer, xff, hops) == want


def test_client_ip_and_authenticator_use_the_right_most_entry(monkeypatch):
    app = FastAPI()
    seen = {}

    @app.get("/who")
    def who(request: Request):
        seen["state"] = request.state.client_ip
        return {"ip": client_ip(request), "ip0": client_ip(request, 0)}

    app.add_middleware(SecurityGuard, csrf_header="X-C")
    c = TestClient(app, client=("10.0.0.5", 5000))
    r = c.get("/who", headers={"X-Forwarded-For": "6.6.6.6, 203.0.113.7"}).json()
    assert r == {"ip": "203.0.113.7", "ip0": "10.0.0.5"} and seen["state"] == "203.0.113.7"
    app2 = FastAPI()
    app2.add_middleware(SecurityGuard, csrf_header="X-C", trusted_hops=0)

    @app2.get("/s")
    def s(request: Request):
        return {"ip": request.state.client_ip}

    assert TestClient(app2, client=("10.0.0.5", 1)).get("/s", headers={"X-Forwarded-For": "6.6.6.6"}).json() == {"ip": "10.0.0.5"}


def test_trusted_hops_env(monkeypatch):
    monkeypatch.delenv("DEMO_TRUSTED_HOPS", raising=False)
    assert config.trusted_hops("demo") == 1
    for raw, want in (("0", 0), ("2", 2), ("-3", 0), ("x", 1), (" 3 ", 3)):
        monkeypatch.setenv("DEMO_TRUSTED_HOPS", raw)
        assert config.trusted_hops("demo") == want


def test_authenticator_limits_per_forwarded_client_not_per_proxy(monkeypatch):
    monkeypatch.delenv("DEMO_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_API_KEY_FILE", "/nonexistent")
    auth = Authenticator(APP, LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes=set()), None,
                         cookie_name="s", trusted_hops=1)
    app = FastAPI()

    @app.get("/x")
    def x(p=Depends(auth.require("things:read"))):
        return {}

    c = TestClient(app, client=("10.0.0.5", 1))
    h = lambda ip, spoof="1.1.1.1": {"Authorization": "Bearer bad", "X-Forwarded-For": f"{spoof}, {ip}"}  # noqa: E731
    codes = [c.get("/x", headers=h("203.0.113.7", spoof=f"9.9.9.{i}")).status_code for i in range(12)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]       # rotating the spoofed entry does not reset the count
    assert c.get("/x", headers=h("203.0.113.8")).status_code == 401    # another real client is not locked out


# ---- anonymous and static key modes ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("host,override,want", [
    ("127.0.0.1", False, True), ("localhost", False, True), ("::1", False, True), ("[::1]", False, True),
    ("0.0.0.0", False, False), ("::", False, False), ("10.1.2.3", False, False), ("", False, False), ("example.org", False, False),
    ("0.0.0.0", True, True), ("", True, True),
])
def test_anonymous_flag_is_refused_unless_loopback_or_overridden(host, override, want, monkeypatch):
    monkeypatch.setenv("DEMO_ALLOW_ANONYMOUS", "1")
    monkeypatch.delenv("DEMO_ALLOW_ANONYMOUS_PUBLIC", raising=False)
    if override:
        monkeypatch.setenv("DEMO_ALLOW_ANONYMOUS_PUBLIC", "1")
    assert config.anonymous_allowed("demo", host=host) is want
    auth = Authenticator(APP, LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes=set()), None, cookie_name="s",
                         allow_anonymous=lambda: config.env_bool("DEMO_ALLOW_ANONYMOUS"), bind_host=host)
    assert auth.anonymous_allowed() is want


def test_anonymous_off_when_flag_unset_even_on_loopback(monkeypatch):
    monkeypatch.delenv("DEMO_ALLOW_ANONYMOUS", raising=False)
    assert config.anonymous_allowed("demo", host="127.0.0.1") is False
    auth = Authenticator(APP, LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes=set()), None, cookie_name="s", bind_host="127.0.0.1")
    assert auth.anonymous_allowed() is False


def test_refused_anonymous_gives_no_access_and_logs_loudly(monkeypatch, caplog):
    monkeypatch.delenv("DEMO_ALLOW_ANONYMOUS_PUBLIC", raising=False)
    monkeypatch.delenv("DEMO_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_API_KEY_FILE", "/nonexistent")
    auth = Authenticator(APP, LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes=set()), None, cookie_name="s",
                         allow_anonymous=True, bind_host="0.0.0.0")  # noqa: S104
    app = FastAPI()

    @app.get("/x")
    def x(p=Depends(auth.require("things:read"))):
        return {"kind": p.kind}

    with caplog.at_level(logging.WARNING, logger="apgkit.auth"):
        assert TestClient(app).get("/x").status_code == 401
    assert any("REFUSED" in r.getMessage() and "ALLOW_ANONYMOUS_PUBLIC" in r.getMessage() for r in caplog.records)


def test_static_key_needs_32_characters_and_warns_at_startup(monkeypatch, caplog):
    good, short = "k" * 32, "k" * 31
    monkeypatch.setenv("DEMO_API_KEY", good)
    with caplog.at_level(logging.WARNING, logger="apgkit.auth"):
        auth = Authenticator(APP, LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes=set()), None, cookie_name="s")
    assert any("static wildcard API key" in r.getMessage() and r.levelno == logging.WARNING for r in caplog.records)
    assert auth.resolve_bearer(good).kind == "static"
    caplog.clear()
    monkeypatch.setenv("DEMO_API_KEY", short)
    with caplog.at_level(logging.WARNING, logger="apgkit.auth"):
        auth = Authenticator(APP, LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes=set()), None, cookie_name="s")
    assert any("REFUSED" in r.getMessage() and "32" in r.getMessage() for r in caplog.records)
    assert auth.resolve_bearer(short) is None                                     # a short key never authenticates
    monkeypatch.delenv("DEMO_API_KEY")
    monkeypatch.setenv("DEMO_API_KEY_FILE", "/nonexistent")
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="apgkit.auth"):
        Authenticator(APP, LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes=set()), None, cookie_name="s")
    assert not caplog.records                                                      # no key, no noise
