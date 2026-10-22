"""Federated authentication: token verification, the service token source and the relying-party login flow."""
import base64
import hashlib
import hmac
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey

from apgkit.auth import AppAuth, Authenticator, LocalAuth, TokenError, TokenSource, TokenVerifier
from apgkit.auth.oidc import check_issuer_url, discover, principal_from_claims
from apgkit.auth.rp import RelyingParty, safe_return_to

ISS, AUD = "https://id.example.org", "demo-client"
APP = AppAuth("demo", AUD, role_permissions={"admin": frozenset({"*"}), "viewer": frozenset({"things:read"})},
              scope_permissions={"demo.write": frozenset({"things:write"}), "read": frozenset({"things:read"})})


def mint_key(kid="k1"):
    return RSAKey.generate_key(2048, {"kid": kid, "use": "sig", "alg": "RS256"})


class Provider:
    """A fake identity provider answering discovery, JWKS and the token endpoint through an httpx transport."""

    def __init__(self):
        self.key = mint_key()
        self.jwks_calls = 0
        self.token_requests = []
        self.next_id_token = None
        self.status = 200

    def keyset(self):
        return {"keys": [self.key.as_dict(private=False)]}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISS, "jwks_uri": f"{ISS}/jwks", "authorization_endpoint": f"{ISS}/authorize",
                                             "token_endpoint": f"{ISS}/token", "end_session_endpoint": f"{ISS}/logout"})
        if path == "/jwks":
            self.jwks_calls += 1
            return httpx.Response(200, json=self.keyset())
        if path == "/token":
            self.token_requests.append(request)
            if self.status != 200:
                return httpx.Response(self.status, json={"error": "invalid_grant"})
            body = parse_qs(request.content.decode())
            if body["grant_type"] == ["client_credentials"]:
                return httpx.Response(200, json={"access_token": self.sign(sub="svc", sub_type="service"), "expires_in": 3600, "token_type": "Bearer"})
            return httpx.Response(200, json={"access_token": "opaque", "id_token": self.next_id_token, "token_type": "Bearer"})
        return httpx.Response(404)

    def http(self):
        return lambda: httpx.Client(transport=httpx.MockTransport(self.handler), follow_redirects=False)

    def sign(self, key=None, header=None, **claims):
        base = {"iss": ISS, "aud": AUD, "sub": "usr_1", "exp": int(time.time()) + 600, "iat": int(time.time())}
        base.update(claims)
        return jwt.encode({"alg": "RS256", "kid": (key or self.key).kid, **(header or {})}, base, key or self.key)


@pytest.fixture
def idp():
    return Provider()


def verifier(idp, **kw):
    return TokenVerifier(ISS, AUD, http=idp.http(), **kw)


def test_a_valid_token_verifies(idp):
    claims = verifier(idp).verify(idp.sign(roles=["demo:viewer"], scope="demo.write"))
    assert claims["sub"] == "usr_1" and claims["roles"] == ["demo:viewer"]


def test_audience_list_containing_ours_is_accepted(idp):
    assert verifier(idp).verify(idp.sign(aud=["other", AUD]))["sub"] == "usr_1"


@pytest.mark.parametrize("claims", [
    {"exp": int(time.time()) - 3600}, {"nbf": int(time.time()) + 3600}, {"aud": "someone-else"}, {"iss": "https://evil.example.org"}])
def test_bad_claims_are_refused(idp, claims):
    with pytest.raises(TokenError):
        verifier(idp).verify(idp.sign(**claims))


def test_missing_required_claims_are_refused(idp):
    for drop in ("exp", "sub", "aud", "iss"):
        base = {"iss": ISS, "aud": AUD, "sub": "u", "exp": int(time.time()) + 60}
        base.pop(drop)
        with pytest.raises(TokenError):
            verifier(idp).verify(jwt.encode({"alg": "RS256", "kid": "k1"}, base, idp.key))


def test_a_token_signed_by_another_key_is_refused(idp):
    other = mint_key("k1")                      # same kid, different key: the signature cannot match
    with pytest.raises(TokenError):
        verifier(idp).verify(idp.sign(key=other))


def test_hmac_key_confusion_and_alg_none_are_refused(idp):
    # the classic attack: sign with HMAC using the PUBLIC key as the secret (the library itself refuses to build this key,
    # so forge the token by hand and check that our verifier refuses it too)
    pub = idp.key.as_pem(private=False)
    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=")  # noqa: E731
    signing_input = b64(b'{"alg":"HS256","typ":"JWT","kid":"k1"}') + b"." + b64(json.dumps(
        {"iss": ISS, "aud": AUD, "sub": "u", "exp": int(time.time()) + 60}).encode())
    forged = (signing_input + b"." + b64(hmac.new(pub, signing_input, hashlib.sha256).digest())).decode()
    with pytest.raises(TokenError):
        verifier(idp).verify(forged)
    none = (base64.urlsafe_b64encode(b'{"alg":"none","kid":"k1"}').rstrip(b"=") + b"." +
            base64.urlsafe_b64encode(json.dumps({"iss": ISS, "aud": AUD, "sub": "u", "exp": int(time.time()) + 60}).encode()).rstrip(b"=") + b".").decode()
    with pytest.raises(TokenError):
        verifier(idp).verify(none)
    for junk in ("not a jwt", "a.b.c", ""):
        with pytest.raises(TokenError):
            verifier(idp).verify(junk)


def test_key_rotation_refreshes_once_then_works(idp):
    v = verifier(idp, min_refresh=0.0)
    v.verify(idp.sign())
    idp.key = mint_key("k2")                    # the provider rotates
    assert v.verify(idp.sign())["sub"] == "usr_1"
    assert idp.jwks_calls == 2


def test_unknown_kid_refreshes_are_rate_limited(idp):
    v = verifier(idp, min_refresh=3600)
    v.verify(idp.sign())
    for _ in range(5):
        with pytest.raises(TokenError):
            v.verify(idp.sign(key=mint_key("rogue")))
    assert idp.jwks_calls == 1                  # an attacker cannot make us hammer the provider


def test_discovery_must_report_the_configured_issuer(idp):
    assert discover(ISS, idp.http())["jwks_uri"] == f"{ISS}/jwks"
    with pytest.raises(TokenError):
        discover("https://other.example.org", idp.http())


def test_issuer_url_rules():
    assert check_issuer_url("https://id.example.org/") == "https://id.example.org"
    assert check_issuer_url("http://localhost:9000") == "http://localhost:9000"
    for bad in ("http://id.example.org", "ftp://x", "https://u:p@x.org", "https://x.org/?q=1", "nonsense"):
        with pytest.raises(ValueError):
            check_issuer_url(bad)


def test_principal_from_claims_keeps_only_this_apps_roles():
    p = principal_from_claims(APP, {"sub": "usr_1", "roles": ["demo:viewer", "other:admin", "demo:ghost"], "scope": "openid demo.write",
                                    "name": "Ada", "email": "ada@example.org"})
    assert p.kind == "user" and p.source == "oidc" and p.name == "Ada"
    assert p.roles == frozenset({"demo:viewer", "demo:ghost"})          # another app's admin role does not leak in
    assert p.can("things:read") and p.can("things:write") and not p.can("things:delete")
    s = principal_from_claims(APP, {"sub": "svc", "sub_type": "service", "scope": "demo.write"})
    assert s.kind == "service" and s.can("things:write") and not s.can("things:read")
    admin = principal_from_claims(APP, {"sub": "a", "roles": ["demo:admin"]})
    assert admin.can("anything")


def test_token_source_caches_until_near_expiry(idp):
    src = TokenSource(ISS, "svc", lambda: "s3cret", scope="demo.write", http=idp.http())
    t1, t2 = src.token(), src.token()
    assert t1 == t2 and len(idp.token_requests) == 1
    req = idp.token_requests[0]
    assert req.headers["authorization"].startswith("Basic ")            # client_secret_basic
    assert parse_qs(req.content.decode())["scope"] == ["demo.write"]
    assert src.headers() == {"Authorization": f"Bearer {t1}"}
    idp.status = 401
    cold = TokenSource(ISS, "svc", lambda: "bad", http=idp.http())
    with pytest.raises(TokenError):
        cold.token()


def test_safe_return_to_blocks_open_redirects():
    assert safe_return_to("/requests?x=1") == "/requests"[:0] + "/requests?x=1"
    for bad in (None, "", "https://evil.example", "//evil.example", "/\\evil", "javascript:alert(1)", "/" + "a" * 400):
        assert safe_return_to(bad) == "/"


# ---- relying party (needs the database for the one-time login state) ----------------------------------------------
from conftest import needs_db  # noqa: E402


@needs_db
def test_login_flow_pkce_state_nonce_and_single_use(db):
    from apgkit.auth.schema import SQL
    with db.connect() as c:
        c.execute(SQL)
        c.commit()
    idp = Provider()
    rp = RelyingParty(ISS, AUD, lambda: "s3cret", http=idp.http())
    with db.connect() as c:
        url = rp.begin(c, "https://app.example.org/auth/callback", "/requests")
        q = parse_qs(urlsplit(url).query)
        assert url.startswith(f"{ISS}/authorize?") and q["code_challenge_method"] == ["S256"] and q["scope"][0].startswith("openid")
        state, nonce, challenge = q["state"][0], q["nonce"][0], q["code_challenge"][0]
        idp.next_id_token = idp.sign(aud=AUD, nonce=nonce, roles=["demo:admin"], name="Ada")
        claims, back, raw = rp.finish(c, "https://app.example.org/auth/callback", "the-code", state)
        assert claims["name"] == "Ada" and back == "/requests" and raw == idp.next_id_token
        sent = parse_qs(idp.token_requests[-1].content.decode())
        verifier = sent["code_verifier"][0]
        assert base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode() == challenge   # PKCE ties them
        assert sent["redirect_uri"] == ["https://app.example.org/auth/callback"]
        with pytest.raises(TokenError):                                                     # the state is single-use
            rp.finish(c, "https://app.example.org/auth/callback", "the-code", state)
        with pytest.raises(TokenError):
            rp.finish(c, "https://app.example.org/auth/callback", "code", "unknown-state")
        # a stolen/misdirected ID token with the wrong nonce
        url = rp.begin(c, "https://app.example.org/auth/callback")
        st = parse_qs(urlsplit(url).query)["state"][0]
        idp.next_id_token = idp.sign(aud=AUD, nonce="not-the-nonce")
        with pytest.raises(TokenError, match="does not belong"):
            rp.finish(c, "https://app.example.org/auth/callback", "code", st)
        # an expired attempt
        url = rp.begin(c, "https://app.example.org/auth/callback")
        st = parse_qs(urlsplit(url).query)["state"][0]
        c.execute("UPDATE oidc_login SET created_at = now() - interval '1 hour'")
        c.commit()
        with pytest.raises(TokenError, match="expired"):
            rp.finish(c, "https://app.example.org/auth/callback", "code", st)
        # the provider refusing the code
        url = rp.begin(c, "https://app.example.org/auth/callback")
        st = parse_qs(urlsplit(url).query)["state"][0]
        idp.status = 400
        with pytest.raises(TokenError, match="refused"):
            rp.finish(c, "https://app.example.org/auth/callback", "code", st)


@needs_db
def test_public_client_sends_client_id_instead_of_a_secret(db):
    from apgkit.auth.schema import SQL
    with db.connect() as c:
        c.execute(SQL)
        c.commit()
    idp = Provider()
    rp = RelyingParty(ISS, AUD, None, http=idp.http())
    with db.connect() as c:
        q = parse_qs(urlsplit(rp.begin(c, "https://a.example.org/cb")).query)
        idp.next_id_token = idp.sign(nonce=q["nonce"][0])
        rp.finish(c, "https://a.example.org/cb", "code", q["state"][0])
    req = idp.token_requests[-1]
    assert "authorization" not in req.headers and parse_qs(req.content.decode())["client_id"] == [AUD]
    assert rp.logout_url("hint", "https://a.example.org/").startswith(f"{ISS}/logout?")


# ---- the authenticator: every credential kind through one dependency ---------------------------------------------------
@needs_db
def test_authenticator_accepts_every_credential_kind(db, tmp_path, monkeypatch):
    from apgkit.auth.schema import SQL
    monkeypatch.delenv("DEMO_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_API_KEY", "static-key-value")
    with db.connect() as c:
        c.execute(SQL)
        c.commit()
    local = LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes={"read"})
    idp = Provider()
    auth = Authenticator(APP, local, db, cookie_name="demo_session", verifier=verifier(idp),
                         bearer_resolvers={"mk_": lambda raw: None})
    app = FastAPI()

    @app.get("/read")
    def read(p=Depends(auth.require("things:read"))):
        return {"who": p.subject, "kind": p.kind, "source": p.source}

    @app.get("/write")
    def write(p=Depends(auth.require("things:write"))):
        return {"who": p.subject}

    c = TestClient(app)
    H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    assert c.get("/read").status_code == 401                                              # nothing presented
    assert c.get("/read", headers=H("static-key-value")).json()["kind"] == "static"
    assert c.get("/write", headers=H("static-key-value")).status_code == 200              # the static key is full access
    jwt_viewer = idp.sign(roles=["demo:viewer"])
    r = c.get("/read", headers=H(jwt_viewer))
    assert r.status_code == 200 and r.json() == {"who": "usr_1", "kind": "user", "source": "oidc"}
    assert c.get("/write", headers=H(jwt_viewer)).status_code == 403                        # authenticated, not authorised
    assert c.get("/write", headers=H(idp.sign(sub="svc", sub_type="service", scope="demo.write"))).status_code == 200
    assert c.get("/read", headers=H(idp.sign(aud="another-app"))).status_code == 401        # a token for a different app
    with db.connect() as conn:
        _, tok = local.create_token(conn, "ci", "read")
        raw = local.create_session(conn)
    assert c.get("/read", headers=H(tok)).json()["source"] == "local"                       # local token, same dependency
    c.cookies.set("demo_session", raw)
    assert c.get("/write").status_code == 200                                               # local admin session
    c.cookies.clear()
    assert c.get("/read", headers=H("garbage")).status_code == 401 and c.get("/read", headers=H("mk_nope")).status_code == 401


@needs_db
def test_authenticator_rate_limits_bad_credentials_and_anonymous_opt_in(db, monkeypatch):
    from apgkit.auth.schema import SQL
    monkeypatch.delenv("DEMO_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_API_KEY_FILE", "/nonexistent")
    with db.connect() as c:
        c.execute(SQL)
        c.commit()
    local = LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes={"read"})
    auth = Authenticator(APP, local, db, cookie_name="s")
    app = FastAPI()

    @app.get("/x")
    def x(p=Depends(auth.require("things:read"))):
        return {"ok": True}

    c = TestClient(app)
    codes = [c.get("/x", headers={"Authorization": "Bearer bad"}).status_code for _ in range(12)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]
    anon = Authenticator(APP, local, db, cookie_name="s", allow_anonymous=True)
    app2 = FastAPI()

    @app2.get("/x")
    def y(p=Depends(anon.require("things:read"))):
        return {"kind": p.kind}

    assert TestClient(app2).get("/x").json() == {"kind": "anonymous"}
