"""Security middleware (pure ASGI): response headers, request-body cap, CSRF header for browser writes, request metrics.

* Every response gets nosniff, frame denial, no-referrer, no-store and a strict Content-Security-Policy.
* Bodies over `max_body` bytes are refused with 413 on the guarded prefixes.
* The caller's address is worked out once (`web.resolve_client`: the Nth X-Forwarded-For entry from the right, `trusted_hops`,
  default 1; 0 = socket peer) and left in `request.state.client_ip` for handlers and limiters.
* Browser writes (cookie-authenticated) on `csrf_prefixes` must carry a custom header, which cross-site pages cannot set;
  requests that carry an Authorization header are API calls and exempt.
"""
import json
import time
from collections.abc import Callable

from .web import resolve_client

DEFAULT_CSP = (b"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
               b"base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class _TooLarge(Exception):
    pass


class SecurityGuard:
    def __init__(self, app, *, csrf_header: str, csrf_prefixes: tuple[str, ...] = ("/api/",), body_prefixes: tuple[str, ...] = ("/api/",),
                 max_body: int = 64 * 1024, csp: bytes = DEFAULT_CSP, observe: Callable[[str, str, int, float], None] | None = None,
                 skip_metrics_for: str = "/metrics", trusted_hops: int = 1):
        self.app, self.csrf_header, self.csrf_prefixes = app, csrf_header.lower(), csrf_prefixes
        self.body_prefixes, self.max_body, self.csp, self.observe, self.skip = body_prefixes, max_body, csp, observe, skip_metrics_for
        self.trusted_hops = trusted_hops

    def _headers(self) -> list[tuple[bytes, bytes]]:
        return [(b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"), (b"referrer-policy", b"no-referrer"),
                (b"content-security-policy", self.csp)]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        path, method = scope["path"], scope["method"]
        forwarded = [v.decode() for k, v in scope["headers"] if k.lower() == b"x-forwarded-for"]
        scope.setdefault("state", {})["client_ip"] = resolve_client((scope.get("client") or (None,))[0], forwarded, self.trusted_hops)
        started = time.perf_counter()
        status = {"code": 500}

        async def reject(code: int, detail: str):
            body = json.dumps({"detail": detail}).encode()
            await send({"type": "http.response.start", "status": code, "headers": [
                (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"cache-control", b"no-store")] + self._headers()})
            await send({"type": "http.response.body", "body": body})
            status["code"] = code

        length = headers.get("content-length", "")
        if path.startswith(self.body_prefixes) and length.isdigit() and int(length) > self.max_body:
            await reject(413, "request body too large")
        elif (path.startswith(self.csrf_prefixes) and method not in {"GET", "HEAD", "OPTIONS"}
              and not headers.get("authorization") and not headers.get(self.csrf_header)):
            await reject(403, "missing CSRF header")
        else:
            begun = {"v": False}
            counted = {"n": 0}
            capped = path.startswith(self.body_prefixes)

            async def limited_receive():
                msg = await receive()
                if capped and msg["type"] == "http.request":       # chunked bodies have no Content-Length to check up front
                    counted["n"] += len(msg.get("body", b""))
                    if counted["n"] > self.max_body:
                        raise _TooLarge
                return msg

            async def wrapped(msg):
                if msg["type"] == "http.response.start":
                    begun["v"] = True
                    status["code"] = msg["status"]
                    have = {h[0].lower() for h in msg["headers"]}
                    msg["headers"] = list(msg["headers"]) + [h for h in self._headers() if h[0] not in have]
                    if b"cache-control" not in have:
                        msg["headers"].append((b"cache-control", b"no-store"))
                await send(msg)
            try:
                await self.app(scope, limited_receive, wrapped)
            except _TooLarge:
                if begun["v"]:
                    raise
                await reject(413, "request body too large")
        if self.observe:
            route = getattr(scope.get("route"), "path", None) or ("/mcp" if path.startswith("/mcp") else "other")
            if route != self.skip:
                self.observe(method, route, status["code"], started)
