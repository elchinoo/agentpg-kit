"""The OIDC client secret is read at use time: with sealed boot it does not exist until unseal."""
import base64
import os
import subprocess
import sys
import textwrap
from urllib.parse import parse_qs

import pytest
from test_oidc import AUD, ISS, Provider

from apgkit import sealed as sl
from apgkit.auth import ClientSecretUnavailable, RelyingParty, from_env
from apgkit.auth.rp import _binding

PASS = "correct-horse-battery-staple-9"
SECRET = "idp-client-secret-xyz"
REDIRECT = "https://app.example.org/auth/callback"


@pytest.fixture(autouse=True)
def _reset():
    yield
    sl.set_active(None)


class FakeConn:
    """Just enough of a connection for RelyingParty.finish: one pending login."""
    def __init__(self, state="st", nonce="nn"):
        self.row = {"verifier": "v" * 50, "nonce": nonce, "return_to": "/", "binding_hash": _binding(state, nonce)}
        self.state, self.deleted = state, 0

    def execute(self, sql, params=()):
        self.deleted += 1
        return self

    def fetchone(self):
        return self.row

    def commit(self):
        pass


def _wire(rp, idp):
    rp._http = rp._id_verifier._http = idp.http()


def _finish(rp, idp):
    conn = FakeConn()
    idp.next_id_token = idp.sign(aud=AUD, nonce="nn", roles=["demo:admin"])
    return rp.finish(conn, REDIRECT, "code", conn.state, _binding(conn.state, "nn"))


def _auth_header(idp):
    h = idp.token_requests[-1].headers.get("authorization", "")
    return base64.b64decode(h.split()[1]).decode() if h.startswith("Basic ") else None


def _sealed_env(monkeypatch):
    monkeypatch.setenv("SF_OIDC_ISSUER", ISS)
    for k in ("SF_OIDC_CLIENT_SECRET", "SF_OIDC_CLIENT_SECRET_FILE", "SF_OIDC_PUBLIC_CLIENT"):
        monkeypatch.delenv(k, raising=False)


def test_sealed_boot_uses_confidential_client_only_after_unseal(monkeypatch):
    _sealed_env(monkeypatch)
    s = sl.Sealed(sl.seal({"SF_OIDC_CLIENT_SECRET": SECRET}, PASS))
    sl.set_active(s)
    idp = Provider()
    fed = from_env("SF", AUD)                       # built while sealed: the secret is unreadable now
    _wire(fed.rp, idp)
    with pytest.raises(ClientSecretUnavailable):
        _finish(fed.rp, idp)
    assert idp.token_requests == []                    # nothing was sent, in particular no public-client request
    s.unseal_with(sl.Protected(PASS))
    claims, _, _ = _finish(fed.rp, idp)
    assert claims["sub"] == "usr_1"
    assert _auth_header(idp) == f"{AUD}:{SECRET}"
    assert "client_id" not in parse_qs(idp.token_requests[-1].content.decode())
    s.seal_again()                                     # a re-seal is honoured: the secret is not cached
    with pytest.raises(ClientSecretUnavailable):
        _finish(fed.rp, idp)
    assert len(idp.token_requests) == 1


def test_sealed_public_client_only_when_declared(monkeypatch):
    _sealed_env(monkeypatch)
    monkeypatch.setenv("SF_OIDC_PUBLIC_CLIENT", "true")
    sl.set_active(sl.Sealed(sl.seal({"x": "y"}, PASS)))
    idp = Provider()
    fed = from_env("SF", AUD)
    _wire(fed.rp, idp)
    _finish(fed.rp, idp)
    assert _auth_header(idp) is None and "client_id" in parse_qs(idp.token_requests[-1].content.decode())


def test_unsealed_deployment_unchanged(monkeypatch):
    _sealed_env(monkeypatch)
    idp = Provider()
    fed = from_env("SF", AUD)                       # no sealing, no secret: public client, as before
    _wire(fed.rp, idp)
    _finish(fed.rp, idp)
    assert _auth_header(idp) is None
    monkeypatch.setenv("SF_OIDC_CLIENT_SECRET", SECRET)   # set after construction: read at use time
    _finish(fed.rp, idp)
    assert _auth_header(idp).endswith(f":{SECRET}")


def test_sealing_enabled_and_open_without_secret_is_public_like_unsealed(monkeypatch):
    _sealed_env(monkeypatch)
    s = sl.Sealed(sl.seal({"other": "v"}, PASS))
    sl.set_active(s)
    s.unseal_with(sl.Protected(PASS))
    idp = Provider()
    rp = RelyingParty(ISS, AUD, lambda: "", http=idp.http())
    _finish(rp, idp)
    assert _auth_header(idp) is None


def test_fresh_interpreter_sealed_boot(tmp_path):
    """The ShopFront pattern: the module builds its relying party at import, long before the operator unseals."""
    blob = sl.seal({"SF_OIDC_CLIENT_SECRET": SECRET}, PASS)
    script = textwrap.dedent("""
        import os, sys
        from apgkit import sealed as sl
        from apgkit.auth import ClientSecretUnavailable, from_env
        s = sl.Sealed.from_env()
        sl.set_active(s)
        fed = from_env("SF", "shop")                    # import-time construction, sealed
        try:
            fed.rp._client_auth()
            print("BEFORE:no-error")
        except ClientSecretUnavailable:
            print("BEFORE:closed")
        s.unseal_with(sl.Protected(os.environ["PP"]))
        auth, extra = fed.rp._client_auth()
        print("AFTER:" + ("confidential" if auth and auth[1] == os.environ["EXPECT"] and not extra else "public"))
    """)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SF_", "APGKIT_"))}
    env.update(APGKIT_SEALED=blob, SF_OIDC_ISSUER=ISS, PP=PASS, EXPECT=SECRET)
    out = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-500:]
    assert "BEFORE:closed" in out.stdout and "AFTER:confidential" in out.stdout
    assert SECRET not in out.stdout + out.stderr
