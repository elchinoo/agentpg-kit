"""Federated authentication, resource-server side: verify access tokens issued by the ecosystem identity provider.

Tokens are JWTs signed with an asymmetric key (RS256, ES256 or EdDSA; `none` and HMAC algorithms are refused, which also
closes the key-confusion attack). The public keys come from the provider's JWKS and are cached; an unknown `kid` triggers one
refresh (rate limited) so key rotation needs no restart. Checked: signature, issuer, audience, expiry and not-before.
"""
import os
import threading
import time
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from .principal import AppAuth, Principal

ALGORITHMS = ["RS256", "ES256", "EdDSA"]
# How long a fetched JWKS is trusted. A signing key the provider removes (an emergency rotation) is refused once this has passed, so it is
# short by default and capped: a larger value passed in is lowered to MAX_JWKS_TTL. If the provider cannot be reached when the cache
# expires, the old keys are still used, but only for MAX_STALE seconds after the last successful fetch, then verification fails closed.
DEFAULT_JWKS_TTL = 300.0
MAX_JWKS_TTL = 3600.0
MAX_STALE = 3600.0


def jwks_ttl_from_env(prefix: str) -> float | None:
    """`<PREFIX>_OIDC_JWKS_TTL` in seconds (1 to MAX_JWKS_TTL); unset or invalid means the default."""
    try:
        v = float(os.environ.get(f"{prefix.upper()}_OIDC_JWKS_TTL", ""))
    except ValueError:
        return None
    return min(v, MAX_JWKS_TTL) if v >= 1 else None


class TokenError(Exception):
    """The token is not acceptable. The message says why, in words safe to log (it never contains the token)."""


def _client_factory() -> httpx.Client:
    return httpx.Client(timeout=10, follow_redirects=False)


def check_issuer_url(issuer: str) -> str:
    u = urlsplit(issuer)
    local = (u.hostname or "") in {"localhost", "127.0.0.1", "::1"} or (u.hostname or "").endswith(".localhost")
    if u.scheme not in {"http", "https"} or not u.hostname or u.username or u.query or u.fragment:
        raise ValueError("the issuer must be an http(s) URL without credentials, query or fragment")
    if u.scheme == "http" and not local:
        raise ValueError("the issuer must use https (plain http is only accepted for localhost)")
    return issuer.rstrip("/")


def discover(issuer: str, http: Callable[[], httpx.Client] = _client_factory) -> dict:
    """The provider's OpenID configuration. The `issuer` it reports must equal the one we were configured with."""
    issuer = check_issuer_url(issuer)
    with http() as c:
        r = c.get(f"{issuer}/.well-known/openid-configuration")
    if r.status_code != 200:
        raise TokenError(f"the identity provider's discovery document answered HTTP {r.status_code}")
    doc = r.json()
    if doc.get("issuer", "").rstrip("/") != issuer:
        raise TokenError("the discovery document names a different issuer than the one configured")
    return doc


class TokenVerifier:
    def __init__(self, issuer: str, audience: str, *, jwks_url: str | None = None, http: Callable[[], httpx.Client] = _client_factory,
                 leeway: int = 30, ttl: float | None = None, min_refresh: float = 15.0, max_stale: float = MAX_STALE):
        self.issuer, self.audience = check_issuer_url(issuer), audience
        self._jwks_url, self._http, self.leeway, self.min_refresh, self.max_stale = jwks_url, http, leeway, min_refresh, max_stale
        self.ttl = DEFAULT_JWKS_TTL if ttl is None else max(0.0, min(float(ttl), MAX_JWKS_TTL))
        self._keys = None
        self._fetched = 0.0
        self._lock = threading.Lock()

    def _jwks_endpoint(self) -> str:
        if not self._jwks_url:
            self._jwks_url = discover(self.issuer, self._http)["jwks_uri"]
        return self._jwks_url

    def _load(self, force: bool = False):
        with self._lock:
            now = time.monotonic()
            fresh = self._keys is not None and now - self._fetched < self.ttl
            if fresh and not force:
                return self._keys
            if force and self._keys is not None and now - self._fetched < self.min_refresh:
                return self._keys                       # refreshed a moment ago: do not hammer the provider
            with self._http() as c:
                r = c.get(self._jwks_endpoint())
            if r.status_code != 200:
                if self._keys is not None and now - self._fetched < self.max_stale:
                    return self._keys                   # keep serving with the keys we have, for a bounded time
                raise TokenError(f"cannot fetch the signing keys (HTTP {r.status_code})")
            self._keys = KeySet.import_key_set(r.json())
            self._fetched = now
            return self._keys

    def verify(self, token: str) -> dict:
        if token.count(".") != 2:
            raise TokenError("not a JWT")
        registry = JWTClaimsRegistry(leeway=self.leeway, iss={"essential": True, "value": self.issuer},
                                     aud={"essential": True, "value": self.audience}, exp={"essential": True}, sub={"essential": True})
        for attempt in (0, 1):
            keys = self._load(force=bool(attempt))
            try:
                decoded = jwt.decode(token, keys, algorithms=ALGORITHMS)
                registry.validate(decoded.claims)
                return dict(decoded.claims)
            except JoseError as exc:
                if attempt == 0 and type(exc).__name__ in {"MissingKeyError", "InvalidKeyIdError", "ValueError"} or "kid" in str(exc).lower():
                    continue                            # maybe the provider rotated its keys: refresh once and retry
                raise TokenError(f"invalid token: {type(exc).__name__}") from exc
            except (ValueError, TypeError, KeyError) as exc:
                raise TokenError("malformed token") from exc
        raise TokenError("invalid token")


def principal_from_claims(app: AppAuth, claims: dict) -> Principal:
    """Turn verified claims into a Principal: roles of THIS app and the granted scopes become permissions."""
    roles = frozenset(r for r in claims.get("roles", []) if isinstance(r, str) and app.role_name(r) is not None)
    scopes = frozenset(str(claims.get("scope", "")).split())
    kind = "service" if claims.get("sub_type") == "service" else "user"
    return Principal(kind, str(claims["sub"]), app.permissions_for(roles=roles, scopes=scopes), roles=roles, scopes=scopes,
                     name=str(claims.get("name") or claims.get("client_name") or ""), email=str(claims.get("email") or ""), source="oidc",
                     extra={"jti": claims.get("jti"), "azp": claims.get("azp")})


class TokenSource:
    """Service-to-service: obtain (and cache) an access token for this app with the client_credentials grant."""

    def __init__(self, issuer: str, client_id: str, client_secret: Callable[[], str], *, scope: str = "", audience: str | None = None,
                 http: Callable[[], httpx.Client] = _client_factory):
        self.issuer, self.client_id, self._secret, self.scope, self.audience, self._http = check_issuer_url(issuer), client_id, client_secret, scope, audience, http
        self._token: tuple[str, float] | None = None
        self._endpoint: str | None = None
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            if self._token and self._token[1] - time.monotonic() > 30:
                return self._token[0]
            if self._endpoint is None:
                self._endpoint = discover(self.issuer, self._http)["token_endpoint"]
            data = {"grant_type": "client_credentials"}
            if self.scope:
                data["scope"] = self.scope
            if self.audience:
                data["audience"] = self.audience
            with self._http() as c:
                r = c.post(self._endpoint, data=data, auth=(self.client_id, self._secret()))
            if r.status_code != 200:
                raise TokenError(f"the identity provider refused the service credentials (HTTP {r.status_code})")
            doc = r.json()
            self._token = (doc["access_token"], time.monotonic() + float(doc.get("expires_in", 300)))
            return self._token[0]

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token()}"}
