"""One front door for every credential an app accepts.

Order for a bearer token: the static key, app-registered prefixes (merchant keys...), local API tokens, then federated JWTs.
Without a bearer token, the browser session cookie. The result is a Principal with permissions; `require("x:y")` is the
FastAPI dependency that routes use, and the same call works whether the app runs standalone or federated.
"""
from collections.abc import Callable

import psycopg
from fastapi import HTTPException, Request

from ..db import Database
from ..ratelimit import FailureLimiter
from .local import LocalAuth
from .oidc import TokenError, TokenVerifier, principal_from_claims
from .principal import WILDCARD, AppAuth, Principal


class Authenticator:
    def __init__(self, app: AppAuth, local: LocalAuth, db: Database, *, cookie_name: str, verifier: TokenVerifier | None = None,
                 limiter: FailureLimiter | None = None, allow_anonymous: bool | Callable[[], bool] = False,
                 bearer_resolvers: dict[str, Callable[[str], Principal | None]] | None = None):
        self.app, self.local, self.db, self.cookie_name, self.verifier = app, local, db, cookie_name, verifier
        self.limiter = limiter or FailureLimiter()
        self._anon = allow_anonymous
        self.bearer_resolvers = bearer_resolvers or {}

    @staticmethod
    def client(request: Request) -> str:
        return request.client.host if request.client else "?"

    @staticmethod
    def bearer(request: Request) -> str | None:
        header = request.headers.get("authorization", "")
        return header[7:].strip() if header[:7].lower() == "bearer " else None

    @staticmethod
    def db_unavailable() -> HTTPException:
        return HTTPException(503, "database unavailable; it may be waking up, retry in a few seconds")

    def authenticate(self, request: Request, *, allow_cookie: bool = True) -> Principal | None:
        """The caller's Principal, or None if no credential was presented. Raises 401 / 429 / 503 for bad credentials."""
        if self._anon() if callable(self._anon) else self._anon:
            return Principal("anonymous", "anonymous", frozenset({WILDCARD}), name="anonymous")
        client = self.client(request)
        if self.limiter.limited(client):
            raise HTTPException(429, "too many failed attempts; wait a minute")
        raw = self.bearer(request)
        if raw is not None:
            p = self._bearer(raw)
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

    def _bearer(self, raw: str) -> Principal | None:
        if self.local.static_key_matches(raw):
            return Principal("static", "static-key", frozenset({WILDCARD}), name="api key")
        for prefix, resolve in self.bearer_resolvers.items():
            if raw.startswith(prefix):
                try:
                    return resolve(raw)
                except (psycopg.Error, RuntimeError) as exc:
                    raise self.db_unavailable() from exc
        if raw.startswith(self.local.token_prefix):
            try:
                with self.db.connect(retries=1) as conn:
                    return self.local.token_principal(conn, raw)
            except (psycopg.Error, RuntimeError) as exc:
                raise self.db_unavailable() from exc
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
