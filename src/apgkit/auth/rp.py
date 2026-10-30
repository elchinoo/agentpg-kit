"""Federated authentication, browser side: sign users in with the ecosystem identity provider (authorization code + PKCE).

`begin` stores a one-time state (with the PKCE verifier and a nonce) and returns the provider's authorization URL; `finish`
checks the state, exchanges the code, verifies the ID token (signature, issuer, audience, nonce) and returns its claims.
The app then starts its own server-side session from them. Roles and name come from the verified ID token only.
"""
import base64
import hashlib
import hmac
import secrets
from collections.abc import Callable
from urllib.parse import urlencode

import httpx

from .oidc import TokenError, TokenVerifier, _client_factory, check_issuer_url, discover

STATE_TTL_MINUTES = 10
SCOPES = "openid profile email roles"


def safe_return_to(value: str | None) -> str:
    """Only same-site paths: never an absolute URL or a protocol-relative one (open redirect)."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value and len(value) <= 300:
        return value
    return "/"


class RelyingParty:
    def __init__(self, issuer: str, client_id: str, client_secret: Callable[[], str] | None = None, *,
                 http: Callable[[], httpx.Client] = _client_factory, scopes: str = SCOPES):
        self.issuer, self.client_id, self._secret, self._http, self.scopes = check_issuer_url(issuer), client_id, client_secret, http, scopes
        self._conf: dict | None = None
        self._id_verifier = TokenVerifier(self.issuer, client_id, http=http)

    def conf(self) -> dict:
        if self._conf is None:
            self._conf = discover(self.issuer, self._http)
            self._id_verifier._jwks_url = self._conf["jwks_uri"]
        return self._conf

    def begin(self, conn, redirect_uri: str, return_to: str | None = None, *, provider_hint: str | None = None) -> str:
        state, verifier, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(48), secrets.token_urlsafe(16)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        conn.execute("DELETE FROM oidc_login WHERE created_at < now() - %s * interval '1 minute'", (STATE_TTL_MINUTES,))
        conn.execute("INSERT INTO oidc_login (state, verifier, nonce, return_to) VALUES (%s,%s,%s,%s)",
                     (state, verifier, nonce, safe_return_to(return_to)))
        conn.commit()
        params = {"response_type": "code", "client_id": self.client_id, "redirect_uri": redirect_uri, "scope": self.scopes,
                  "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
        if provider_hint:
            params["idp"] = provider_hint
        return f"{self.conf()['authorization_endpoint']}?{urlencode(params)}"

    def finish(self, conn, redirect_uri: str, code: str, state: str) -> tuple[dict, str, str]:
        """Returns (id_token claims, return_to, raw id_token). Raises TokenError for anything wrong."""
        row = conn.execute("DELETE FROM oidc_login WHERE state=%s AND created_at > now() - %s * interval '1 minute' "
                           "RETURNING verifier, nonce, return_to", (state, STATE_TTL_MINUTES)).fetchone()
        conn.commit()
        if not row:
            raise TokenError("the login attempt is unknown or expired; start again")
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "code_verifier": row["verifier"]}
        auth = None
        secret = self._secret() if self._secret else ""
        if secret:
            auth = (self.client_id, secret)
        else:
            data["client_id"] = self.client_id
        with self._http() as c:
            r = c.post(self.conf()["token_endpoint"], data=data, auth=auth)
        if r.status_code != 200:
            raise TokenError(f"the identity provider refused the login (HTTP {r.status_code})")
        doc = r.json()
        id_token = doc.get("id_token")
        if not id_token:
            raise TokenError("the identity provider returned no ID token")
        claims = self._id_verifier.verify(id_token)
        if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"].encode(), str(row["nonce"]).encode()):
            raise TokenError("the ID token does not belong to this login attempt")
        return claims, row["return_to"], id_token

    def logout_url(self, id_token_hint: str | None, post_logout_redirect: str) -> str | None:
        end = self.conf().get("end_session_endpoint")
        if not end:
            return None
        params = {"post_logout_redirect_uri": post_logout_redirect, "client_id": self.client_id}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        return f"{end}?{urlencode(params)}"
