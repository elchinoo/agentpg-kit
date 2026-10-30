"""One front door for every credential an app accepts.

Order for a bearer token: the static key, app-registered prefixes (merchant keys...), local API tokens, then federated JWTs.
Without a bearer token, the browser session cookie. The result is a Principal with permissions; `require("x:y")` is the
FastAPI dependency that routes use, and the same call works whether the app runs standalone or federated.
"""
import hmac
import logging
import threading
import time
from collections.abc import Callable

import psycopg
from fastapi import HTTPException, Request

from .. import config
from ..db import Database
from ..ratelimit import FailureLimiter
from ..web import client_ip
from .local import LocalAuth
from .oidc import TokenError, TokenVerifier, principal_from_claims
from .principal import WILDCARD, AppAuth, Principal

log = logging.getLogger("apgkit.auth")


class Authenticator:
    def __init__(self, app: AppAuth, local: LocalAuth, db: Database, *, cookie_name: str, verifier: TokenVerifier | None = None,
                 limiter: FailureLimiter | None = None, allow_anonymous: bool | Callable[[], bool] = False,
                 bearer_resolvers: dict[str, Callable[[str], Principal | None]] | None = None,
                 static_tokens: list[tuple[Callable[[], str], Principal]] | None = None, token_cache_seconds: float = 0.0,
                 trusted_hops: int | None = None, bind_host: str | None = None):
        """`static_tokens`: extra fixed bearer credentials, each a (getter, principal) pair, e.g. a scrape-only metrics token read from the
        environment. `token_cache_seconds` > 0 caches successful local-token lookups (saves a database round trip per request on hot
        paths); a revoked token then works for up to that long on other processes, and `forget_tokens()` clears this process at once.

        `allow_anonymous` (every request becomes a wildcard principal) is only honoured when the server binds to loopback
        (`bind_host`, default from `<PREFIX>_HOST` or `HOST`; unknown counts as public) or `<PREFIX>_ALLOW_ANONYMOUS_PUBLIC=1` is set.
        A static `<PREFIX>_API_KEY` is wildcard access: it needs >= 32 characters (a shorter key is never accepted) and a loud
        warning is logged at startup. `trusted_hops` (default `<PREFIX>_TRUSTED_HOPS`, else 1) feeds `client()`."""
        self.app, self.local, self.db, self.cookie_name, self.verifier = app, local, db, cookie_name, verifier
        self.limiter = limiter or FailureLimiter()
        self._anon = allow_anonymous
        self.bearer_resolvers = bearer_resolvers or {}
        self.static_tokens = static_tokens or []
        self.token_cache_seconds = token_cache_seconds
        self._token_cache: dict[str, tuple[Principal, float]] = {}
        self._cache_lock = threading.Lock()
        prefix = local.env_prefix
        self.trusted_hops = config.trusted_hops(prefix) if trusted_hops is None else trusted_hops
        self.bind_host = config.bind_host(prefix) if bind_host is None else bind_host
        self._anon_warned = False
        self._check_static_key()

    def _check_static_key(self) -> None:
        key = self.local.static_key()
        if not key:
            return
        problem = config.static_key_problem(key)
        if problem:
            log.error("%s_API_KEY is configured but REFUSED: %s. Generate one with `openssl rand -base64 36`.", self.local.env_prefix, problem)
        else:
            log.warning("SECURITY: a static wildcard API key (%s_API_KEY) is enabled; it grants full access, never expires and cannot be "
                        "scoped. Prefer scoped API tokens and remove it when not needed.", self.local.env_prefix)

    def anonymous_allowed(self) -> bool:
        if not (self._anon() if callable(self._anon) else self._anon):
            return False
        prefix = self.local.env_prefix
        if config.is_loopback_host(self.bind_host) or config.env_bool(f"{prefix}_ALLOW_ANONYMOUS_PUBLIC"):
            if not self._anon_warned and not config.is_loopback_host(self.bind_host):
                log.warning("SECURITY: %s_ALLOW_ANONYMOUS is honoured on a non-loopback address because %s_ALLOW_ANONYMOUS_PUBLIC is set; "
                            "everyone who can reach this server has full access.", prefix, prefix)
                self._anon_warned = True
            return True
        if not self._anon_warned:
            log.error("SECURITY: %s_ALLOW_ANONYMOUS is set but REFUSED: the server does not bind to loopback (bind address %r). Bind to "
                      "127.0.0.1 or set %s_ALLOW_ANONYMOUS_PUBLIC=1 to accept the exposure.", prefix, self.bind_host or "unknown", prefix)
            self._anon_warned = True
        return False

    def forget_tokens(self) -> None:
        with self._cache_lock:
            self._token_cache.clear()

    def client(self, request: Request) -> str:
        """The caller's address (see `web.client_ip`): the `trusted_hops`-th X-Forwarded-For entry from the right."""
        return client_ip(request, self.trusted_hops)

    @staticmethod
    def bearer(request: Request) -> str | None:
        header = request.headers.get("authorization", "")
        return header[7:].strip() if header[:7].lower() == "bearer " else None

    @staticmethod
    def db_unavailable() -> HTTPException:
        return HTTPException(503, "database unavailable; it may be waking up, retry in a few seconds")

    def authenticate(self, request: Request, *, allow_cookie: bool = True) -> Principal | None:
        """The caller's Principal, or None if no credential was presented. Raises 401 / 429 / 503 for bad credentials."""
        if self.anonymous_allowed():
            return Principal("anonymous", "anonymous", frozenset({WILDCARD}), name="anonymous")
        client = self.client(request)
        if self.limiter.limited(client):
            raise HTTPException(429, "too many failed attempts; wait a minute")
        raw = self.bearer(request)
        if raw is not None:
            p = self.resolve_bearer(raw)
            if p is None:
                self.limiter.record(client)
                raise HTTPException(401, "invalid credentials")
            return p
        cookie = request.cookies.get(self.cookie_name) if allow_cookie else None
        if cookie:
            try:
                with self.db.connect(retries=1) as conn:
                    return self.local.session_principal(conn, cookie)
            except (psycopg.Error, RuntimeError) as exc:
                raise self.db_unavailable() from exc
        return None

    _bearer = property(lambda self: self.resolve_bearer)          # the old private name

    def resolve_bearer(self, raw: str) -> Principal | None:
        """The Principal for a bearer credential, or None. Does NOT consult or update the failed-attempt limiter: an app that runs its own
        (for example behind a proxy where every caller shares one address) can use this directly."""
        if self.local.static_key_matches(raw) and config.static_key_problem(raw) is None:
            return Principal("static", "static-key", frozenset({WILDCARD}), name="api key")
        for getter, principal in self.static_tokens:
            fixed = getter()
            if fixed and hmac.compare_digest(raw.encode(), fixed.encode()):
                return principal
        for prefix, resolve in self.bearer_resolvers.items():
            if raw.startswith(prefix):
                try:
                    return resolve(raw)
                except (psycopg.Error, RuntimeError) as exc:
                    raise self.db_unavailable() from exc
        if raw.startswith(self.local.token_prefix):
            if self.token_cache_seconds:
                with self._cache_lock:
                    hit = self._token_cache.get(raw)
                if hit and time.monotonic() - hit[1] < self.token_cache_seconds:
                    return hit[0]
            try:
                with self.db.connect(retries=1) as conn:
                    p = self.local.token_principal(conn, raw)
            except (psycopg.Error, RuntimeError) as exc:
                raise self.db_unavailable() from exc
            if self.token_cache_seconds:
                with self._cache_lock:
                    if len(self._token_cache) > 10_000:
                        self._token_cache.clear()
                    if p:
                        self._token_cache[raw] = (p, time.monotonic())
                    else:
                        self._token_cache.pop(raw, None)
            return p
        if self.verifier is not None and raw.count(".") == 2:
            try:
                return principal_from_claims(self.app, self.verifier.verify(raw))
            except TokenError:
                return None
            except Exception:  # noqa: BLE001 - the identity provider being unreachable must read as "not authenticated", not a 500
                return None
        return None

    def require(self, permission: str, *, allow_cookie: bool = True):
        """FastAPI dependency: the caller must hold `permission` (`*` holders pass everything)."""

        def dep(request: Request) -> Principal:
            p = self.authenticate(request, allow_cookie=allow_cookie)
            if p is None:
                raise HTTPException(401, "authentication required")
            if not p.can(permission):
                raise HTTPException(403, f"this credential cannot do that (it lacks '{permission}')")
            return p

        return dep
