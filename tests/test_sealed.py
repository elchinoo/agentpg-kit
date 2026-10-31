import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apgkit import config
from apgkit import sealed as sl

PASS = "correct-horse-battery-staple-9"


@pytest.fixture(autouse=True)
def _reset():
    yield
    sl.set_active(None)


def test_protected_roundtrip_and_never_leaks():
    p = sl.Protected("postgres://u:s3cret@h/db")
    assert "s3cret" not in repr(p) and "s3cret" not in str(p)
    with p.reveal() as buf:
        assert bytes(buf) == b"postgres://u:s3cret@h/db"
    assert p.reveal_str().endswith("/db") and p.matches("postgres://u:s3cret@h/db") and not p.matches("x")
    with pytest.raises(TypeError):
        import pickle
        pickle.dumps(p)
    assert p != sl.Protected("postgres://u:s3cret@h/db")             # identity, never a value comparison


def test_protected_pages_never_hold_the_value_and_remask_changes_them():
    p = sl.Protected(b"A" * 40)
    assert b"A" * 8 not in p._masked.read() and b"A" * 8 not in p._pad.read()
    before = (p._masked.read(), p._pad.read())
    p.remask()
    assert (p._masked.read(), p._pad.read()) != before
    with p.reveal() as buf:
        assert bytes(buf) == b"A" * 40
    p.wipe()
    with pytest.raises(sl.SealError):
        with p.reveal():
            pass


def test_reveal_buffer_is_zeroed():
    p = sl.Protected("hunter2hunter2")
    with p.reveal() as buf:
        held = buf
    assert set(held) == {0}


def test_seal_open_and_failures():
    blob = sl.seal({"DATABASE_URL": "postgres://x", "K": "v"}, PASS)
    assert "postgres" not in blob and blob.startswith(sl.SEAL_PREFIX)
    assert sl.open_blob(blob, PASS) == {"DATABASE_URL": "postgres://x", "K": "v"}
    with pytest.raises(sl.SealError):
        sl.open_blob(blob, PASS + "x")
    with pytest.raises(sl.SealError):
        sl.open_blob(blob[:-4] + "AAAA", PASS)
    assert sl.seal({"a": "b"}, PASS) != sl.seal({"a": "b"}, PASS)          # fresh salt and nonce
    with pytest.raises(sl.SealError):
        sl.seal({"a": "b"}, "short")
    assert sl.open_blob(sl.reseal(blob, PASS, PASS + "2"), PASS + "2")["K"] == "v"


def test_generated_passphrase_is_accepted():
    g = sl.generate_passphrase()
    sl.check_passphrase(g)
    assert g != sl.generate_passphrase()


def _app(blob, ready):
    s = sl.Sealed(blob)
    s.on_unsealed(lambda sealed, pw: ready.append(sealed.get("DATABASE_URL")))
    app = FastAPI()

    @app.get("/data")
    def data():
        return {"ok": True}

    @app.get("/healthz")
    def health():
        return {"ok": True}

    sl.install(app, s, trusted_hops=0, harden=False)
    return s, TestClient(app)


def unseal(client, passphrase):
    key = client.get("/_seal/key").json()["public_key"]
    return client.post("/_seal/unseal", json=sl.make_envelope(key, passphrase))


def test_sealed_app_serves_nothing_until_unsealed_then_exposes_secrets_to_config():
    ready = []
    s, c = _app(sl.seal({"DATABASE_URL": "postgres://sealed/db", "OIDC_CLIENT_SECRET": "cs"}, PASS), ready)
    assert c.get("/data").status_code == 503 and c.get("/healthz").status_code == 200
    assert c.get("/_seal/status").json() == {"state": "sealed"}
    assert config.database_url() != "postgres://sealed/db"
    assert unseal(c, PASS).json() == {"state": "unsealed"}
    assert ready == ["postgres://sealed/db"]
    assert c.get("/data").status_code == 200
    assert config.database_url() == "postgres://sealed/db" and config.read_secret("OIDC_CLIENT_SECRET") == "cs"
    assert c.get("/_seal/key").status_code == 409


def test_wrong_passphrase_stays_sealed_and_is_limited():
    s, c = _app(sl.seal({"DATABASE_URL": "x"}, PASS), [])
    for _ in range(5):
        assert unseal(c, "wrong-wrong-wrong-wrong-1").status_code == 401
    assert unseal(c, PASS).status_code == 429
    assert not s.unsealed


def test_callback_failure_reseals():
    s = sl.Sealed(sl.seal({"DATABASE_URL": "x"}, PASS))

    def boom(sealed, pw):
        raise RuntimeError("db down")
    s.on_unsealed(boom)
    app = FastAPI()
    sl.install(app, s, trusted_hops=0, harden=False)
    c = TestClient(app)
    assert unseal(c, PASS).status_code == 503
    assert not s.unsealed and s.names() == []


def test_envelope_is_ciphertext_bound_to_the_ephemeral_key_and_expires(monkeypatch):
    s = sl.Sealed(sl.seal({"a": "b"}, PASS))
    env = sl.make_envelope(s.public_key(), PASS)
    assert PASS not in json.dumps(env)
    other = sl.Sealed(sl.seal({"a": "b"}, PASS))
    other.public_key()
    with pytest.raises(sl.SealError):
        other.unseal(env)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 3600)
    with pytest.raises(sl.SealError):
        s.unseal(env)


def test_seal_again_forgets_everything():
    s = sl.Sealed(sl.seal({"a": "b"}, PASS))
    s.unseal_with(sl.Protected(PASS))
    assert s.get("a") == "b"
    s.seal_again()
    assert s.state == "sealed" and s.get("a") is None


def test_disabled_never_runs_callbacks_and_runs_the_lifespan_as_before():
    import contextlib
    ran, life = [], []
    s = sl.Sealed(None)
    s.on_unsealed(lambda *_: ran.append(1))

    @contextlib.asynccontextmanager
    async def inner(app):
        life.append("start")
        yield
        life.append("stop")
    app = FastAPI(lifespan=s.deferred(inner))
    with TestClient(app):
        assert life == ["start"]
    assert ran == [] and s.unsealed and s.state == "disabled" and life == ["start", "stop"]


def test_deferred_lifespan_starts_only_after_unseal():
    import contextlib
    life = []

    @contextlib.asynccontextmanager
    async def inner(app):
        life.append("start")
        yield
        life.append("stop")
    s = sl.Sealed(sl.seal({"a": "b"}, PASS))
    app = FastAPI(lifespan=s.deferred(inner))
    sl.install(app, s, trusted_hops=0, harden=False)
    with TestClient(app) as c:
        assert life == []
        assert unseal(c, PASS).status_code == 200
        for _ in range(50):
            if life:
                break
            time.sleep(0.1)
        assert life == ["start"]
    assert life == ["start", "stop"]


def test_harden_process_reports():
    assert "core_dumps_off" in sl.harden_process()


def test_vault_unlock_sealed_and_platform_key_ignored(monkeypatch):
    import os

    from apgkit.vault import Vault
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("needs TEST_DATABASE_URL")
    from apgkit import settings_store  # noqa: F401
    s = sl.Sealed(sl.seal({"a": "b"}, PASS))
    sl.set_active(s)
    monkeypatch.setenv("T_ENCRYPTION_KEY", "z" * 64)
    v = Vault("T")
    assert v._env_secret() == ""                       # a platform key in the environment is not used while sealing is on
    assert v._dk is None


@pytest.mark.skipif(not __import__("os").environ.get("TEST_DATABASE_URL"), reason="needs TEST_DATABASE_URL")
def test_sealed_vault_creates_then_opens_with_passphrase_only(db, monkeypatch):
    from apgkit.auth.schema import SQL as AUTH_SQL
    from apgkit.vault import Vault, VaultLocked, sealed_unlocker
    monkeypatch.setenv("T_ENCRYPTION_KEY", "z" * 64)
    s = sl.Sealed(sl.seal({"a": "b"}, PASS))
    sl.set_active(s)
    with db.connect() as c:
        c.execute(AUTH_SQL)
        c.commit()
    v = Vault("T")
    assert v._env_secret() == "" and v._dk is None
    cb = sealed_unlocker(v, db.connect)
    cb(s, sl.Protected(PASS))
    assert v.is_unlocked()
    token = v.encrypt("hello", context="x")
    # the vault is stored under the passphrase alone: a platform key never wrapped it
    v2 = Vault("T")
    with db.connect() as c:
        with pytest.raises(VaultLocked):
            v2.unlock_sealed(c, sl.Protected("a-different-passphrase-of-length"))
        assert v2.unlock_sealed(c, sl.Protected(PASS)) == "unlocked"
        assert v2.status(c)["auto_unlock"] is False
    assert v2.decrypt(token, context="x") == "hello"
