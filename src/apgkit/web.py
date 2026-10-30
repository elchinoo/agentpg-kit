"""Small helpers every FastAPI app in the fleet needs."""
import ipaddress
import os

from fastapi import Request


def is_https(request: Request) -> bool:
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https"


def public_url(request: Request, env: str | None = None) -> str:
    """The URL this app is reached at: the configured one (`env`), else the request's own address. AgentPG terminates TLS in
    front of the sandbox, so the forwarded protocol is honoured."""
    if env and os.environ.get(env):
        return os.environ[env].rstrip("/")
    proto = "https" if is_https(request) else request.url.scheme
    return f"{proto}://{request.headers.get('host') or request.url.netloc}"


def mount_kit_static(app) -> None:
    """Serve the shared UI kit (base.css, ui.js, api.js, session.js, logos) under /kit/."""
    from pathlib import Path

    from fastapi.staticfiles import StaticFiles
    app.mount("/kit", StaticFiles(directory=Path(__file__).resolve().parent / "static"), name="kit")


UNKNOWN_CLIENT = "unknown"


def _parse_ip(value: str) -> str | None:
    value = value.strip().strip('"')
    if value.startswith("[") and "]" in value:                 # [2001:db8::1]:443
        value = value[1 : value.index("]")]
    elif value.count(":") == 1 and "." in value:               # 203.0.113.9:51234
        value = value.split(":")[0]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def resolve_client(peer: str | None, forwarded_for: list[str], trusted_hops: int = 1) -> str:
    """The client address, taking the `trusted_hops`-th entry of X-Forwarded-For counting from the RIGHT (each of the operator's
    proxies appends the address it received the connection from, so anything to the left is client-supplied and ignored).
    `trusted_hops` = 0 ignores the header and uses the socket peer. With fewer entries than hops, or an unparsable entry, the socket
    peer is used (the request did not come through the expected proxies)."""
    direct = _parse_ip(peer or "") if peer else None
    if trusted_hops <= 0:
        return direct or UNKNOWN_CLIENT
    chain = [p for part in forwarded_for for p in part.split(",") if p.strip()]
    if len(chain) < trusted_hops:
        return direct or UNKNOWN_CLIENT
    return _parse_ip(chain[-trusted_hops]) or direct or UNKNOWN_CLIENT


def client_ip(request: Request, trusted_hops: int = 1) -> str:
    """The caller's address for rate limiting and logs. Use `config.trusted_hops("<PREFIX>")` for the operator's setting.

    Behind AgentPG's single proxy the default of 1 is right. The app must only be reachable through that proxy: a client that can
    connect directly could put anything in the last X-Forwarded-For entry. Run uvicorn with `proxy_headers=True` and
    `forwarded_allow_ips` limited to the proxy's address (never "*"), see GUIDE 7.12.
    """
    peer = request.client.host if request.client else None
    return resolve_client(peer, request.headers.getlist("x-forwarded-for"), trusted_hops)
