"""Vault v2 envelope (AES-256-GCM, key id, HKDF subkeys, AAD context), platform-wrap KDF choice, scrypt concurrency cap and
login attempt counting."""
import base64
import hashlib
import secrets
import threading
import time

import pytest
from conftest import needs_db
from cryptography.fernet import Fernet
from fastapi import HTTPException

from apgkit import migrate, passwords, settings_store
from apgkit.auth.local import LocalAuth
from apgkit.auth.principal import AppAuth
from apgkit.auth.schema import SQL as AUTH_SQL
from apgkit.ratelimit import FailureLimiter
from apgkit.vault import KDF_HKDF, KDF_LEGACY, Vault, VaultError, _b64, _kdf, is_high_entropy

PW = "a long enough password"
RANDOM_ENV = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")      # what our tooling generates
HUMAN_ENV = "platform-managed-secret-value"


def unlocked_vault(key: bytes | None = None) -> Vault:
    v = Vault("demo")
    v._data_key = key or secrets.token_bytes(32)
    return v


def legacy(v: Vault, text: str) -> str:
    return Fernet(base64.urlsafe_b64encode(v._data_key)).encrypt(text.encode()).decode()


# ---- envelope (no database) -----------------------------------------------------------------------------------------
def test_v2_round_trip_and_format():
    v = unlocked_vault()
    t = v.encrypt("sk-secret", "provider.api_key_enc:7")
    version, kid, blob = t.split("$")
    assert version == "v2" and len(kid) == 12 and "sk-secret" not in t
    assert len(base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))) == 12 + len(b"sk-secret") + 16     # nonce + ct + GCM tag
    assert v.decrypt(t, "provider.api_key_enc:7") == "sk-secret"
    assert v.encrypt("sk-secret", "provider.api_key_enc:7") != t                                           # random nonce
    assert unlocked_vault(v._data_key).decrypt(t, "provider.api_key_enc:7") == "sk-secret"                  # same key, same key id
    assert Vault.is_legacy(legacy(v, "x")) and not Vault.is_legacy(t)


def test_context_mismatch_fails_closed():
    v = unlocked_vault()
    t = v.encrypt("secret", "provider.api_key_enc:1")
    for wrong in ("provider.api_key_enc:2", "provider.webhook_secret_enc:1", ""):
        with pytest.raises(VaultError):
            v.decrypt(t, wrong)
    with pytest.raises(VaultError):
        v.decrypt(v.encrypt("secret"), "provider.api_key_enc:1")        # empty-context ciphertext does not open under a context


def test_no_context_still_works_and_other_key_or_tampering_fails():
    v = unlocked_vault()
    t = v.encrypt("plain")
    assert v.decrypt(t) == "plain"
    with pytest.raises(VaultError):
        unlocked_vault().decrypt(t)                                       # a different data key (different key id)
    kid, blob = t.split("$")[1:]
    tampered = f"v2${kid}${blob[:-2]}{'A' if blob[-2] != 'A' else 'B'}{blob[-1]}"
    with pytest.raises(VaultError):
        v.decrypt(tampered)
    with pytest.raises(VaultError):
        v.decrypt("v2$nokey$AAAA")


def test_subkeys_differ_per_purpose():
    v = unlocked_vault()
    a, b = v.derive_key("hmac-a"), v.derive_key("hmac-b")
    assert a != b and len(a) == 32 and a != v._data_key
    from apgkit.vault import _INFO_SECRET, _INFO_WRAP, _hkdf
    assert _hkdf(v._data_key, _INFO_SECRET) != _hkdf(v._data_key, _INFO_WRAP) and _hkdf(v._data_key, _INFO_SECRET) not in (a, b)


def test_legacy_fernet_still_decrypts_and_reencrypt_legacy_upgrades():
    v = unlocked_vault()
    old = legacy(v, "old secret")
    assert v.decrypt(old) == "old secret" and v.decrypt(old, "any:context") == "old secret"      # legacy tokens carry no context
    new = v.reencrypt_legacy(old, "provider.api_key_enc:3")
    assert new.startswith("v2$") and v.decrypt(new, "provider.api_key_enc:3") == "old secret"
    assert v.reencrypt_legacy(new, "provider.api_key_enc:3") == new                             # idempotent on v2


def test_is_high_entropy_rule():
    assert is_high_entropy(RANDOM_ENV)
    assert is_high_entropy(base64.b64encode(secrets.token_bytes(32)).decode())               # standard base64 with padding and +/
    assert is_high_entropy(secrets.token_hex(32))
    assert not is_high_entropy(HUMAN_ENV)
    assert not is_high_entropy("correct-horse-battery-staple-correct-horse")                  # long but a phrase
    assert not is_high_entropy(base64.urlsafe_b64encode(secrets.token_bytes(24)).decode())     # 24 bytes: below 32
    assert not is_high_entropy("A" * 60)


# ---- database: wraps, rotation ----------------------------------------------------------------------------------------
@pytest.fixture
def setup(db, tmp_path, monkeypatch):
    migrate.run(db, tmp_path)
    monkeypatch.delenv("DEMO_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY_FILE", str(tmp_path / "none"))
    with db.connect() as c:
        c.execute("CREATE TABLE vals (id int PRIMARY KEY, enc text)")
        c.commit()
    return db


def _state(c):
    return {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM app_setting WHERE key LIKE 'vault_%'").fetchall()}


@needs_db
def test_rotate_data_key_upgrades_legacy_tokens_with_registered_context(setup):
    v = Vault("demo")
    v.register_store("vals.enc", "SELECT id, enc AS value FROM vals", "UPDATE vals SET enc = %(value)s WHERE id = %(id)s",
                     context="vals.enc:{id}")
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        c.execute("INSERT INTO vals VALUES (1, %s), (2, %s), (3, %s)",
                  (legacy(v, "one"), v.encrypt("two", "vals.enc:2"), legacy(v, "three")))
        c.commit()
        assert v.rotate_data_key(c, password=PW) == {"vals.enc": 3}
        rows = c.execute("SELECT id, enc FROM vals ORDER BY id").fetchall()
        assert all(r["enc"].startswith("v2$") for r in rows)
        assert [v.decrypt(r["enc"], f"vals.enc:{r['id']}") for r in rows] == ["one", "two", "three"]
        with pytest.raises(VaultError):                                  # now bound to its row
            v.decrypt(rows[0]["enc"], "vals.enc:2")
        assert all(s.startswith("v2$wrap$") for k, s in _state(c).items() if k.startswith("vault_wrap_"))


@needs_db
def test_rotate_data_key_callback_with_reencrypt_legacy(setup):
    v = Vault("demo")
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        c.execute("INSERT INTO vals VALUES (1, %s), (2, %s)", (legacy(v, "a"), v.encrypt("b", "vals:2")))
        c.commit()

        def cb(old_decrypt, new_encrypt):
            for r in c.execute("SELECT id, enc FROM vals").fetchall():
                tok = v.reencrypt_legacy(r["enc"], f"vals:{r['id']}", old_decrypt=old_decrypt, new_encrypt=new_encrypt)
                c.execute("UPDATE vals SET enc=%s WHERE id=%s", (tok, r["id"]))

        v.rotate_data_key(c, cb, password=PW)
        rows = c.execute("SELECT id, enc FROM vals ORDER BY id").fetchall()
        assert [v.decrypt(r["enc"], f"vals:{r['id']}") for r in rows] == ["a", "b"] and all(r["enc"].startswith("v2$") for r in rows)


@needs_db
def test_platform_wrap_kdf_selection(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", RANDOM_ENV)
    v = Vault("demo")
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        s = _state(c)
        assert s["vault_kdf_env"] == KDF_HKDF and s["vault_kdf_pw"] == "scrypt$17$8$1"
        assert s["vault_wrap_env"].startswith("v2$wrap$")
        tok = v.encrypt("x", "ctx")
        v2 = Vault("demo")
        assert v2.try_unlock_with_platform_secret(c) and v2.decrypt(tok, "ctx") == "x"
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", HUMAN_ENV)               # a human-chosen secret keeps scrypt
    with setup.connect() as c:
        v2.rotate_platform_secret(c, HUMAN_ENV)
        c.commit()
        assert _state(c)["vault_kdf_env"] == "scrypt$17$8$1"
        assert Vault("demo").try_unlock_with_platform_secret(c)


@needs_db
def test_hkdf_unlock_runs_no_scrypt(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", RANDOM_ENV)
    with setup.connect() as c:
        Vault("demo").initialize(c, PW)
        c.commit()
        calls = []
        real = passwords.scrypt
        monkeypatch.setattr(passwords, "scrypt", lambda *a, **k: calls.append(1) or real(*a, **k))
        assert Vault("demo").try_unlock_with_platform_secret(c)
        assert calls == []


@needs_db
def test_legacy_wraps_still_open_and_are_upgraded_to_hkdf_and_v2(setup, monkeypatch):
    """A wrap written by the previous kit (Fernet under scrypt, with and without a stored KDF) opens with a random platform secret
    and is rewritten as HKDF + v2."""
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", RANDOM_ENV)
    v = Vault("demo")
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        key = v._data_key
        tok = legacy(v, "kept")
        for sk, wk, kk, secret in (("vault_salt", "vault_wrap_pw", "vault_kdf_pw", PW),
                                   ("vault_env_salt", "vault_wrap_env", "vault_kdf_env", RANDOM_ENV)):
            salt = secrets.token_bytes(16)
            settings_store.put(c, sk, _b64(salt))
            settings_store.put(c, wk, _kdf(secret, salt, KDF_LEGACY).encrypt(key).decode())
            settings_store.put(c, kk, "scrypt$15$8$1")
        c.commit()
        v2 = Vault("demo")
        assert v2.try_unlock_with_platform_secret(c) and v2.decrypt(tok) == "kept"
        s = _state(c)
        assert s["vault_kdf_env"] == KDF_HKDF and s["vault_wrap_env"].startswith("v2$wrap$")
        assert s["vault_wrap_pw"].startswith("g")                          # password wrap untouched until the password is presented
        v3 = Vault("demo")
        assert v3.unlock_with_password(c, PW)
        c.commit()
        assert _state(c)["vault_wrap_pw"].startswith("v2$wrap$") and Vault("demo").unlock_with_password(c, PW)


@needs_db
def test_wrap_is_bound_to_its_slot(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", RANDOM_ENV)
    with setup.connect() as c:
        Vault("demo").initialize(c, PW)
        c.commit()
        s = _state(c)
        # the env wrap's blob moved into the password slot never opens, even under the right KDF inputs
        settings_store.put(c, "vault_wrap_pw", s["vault_wrap_env"])
        c.commit()
        assert not Vault("demo").unlock_with_password(c, PW)


# ---- scrypt concurrency cap ---------------------------------------------------------------------------------------------
def test_scrypt_concurrency_cap(monkeypatch):
    live, peak, lock = 0, 0, threading.Lock()

    def slow(secret, salt, n, r, p, maxmem, dklen):
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        time.sleep(0.15)
        with lock:
            live -= 1
        return b"\0" * dklen

    monkeypatch.setattr(hashlib, "scrypt", slow)
    monkeypatch.setattr(passwords, "_WAIT_SECONDS", 0.05)
    passwords.set_concurrency(2)
    results = []
    barrier = threading.Barrier(8)

    def go():
        barrier.wait()
        try:
            passwords._derive("pw", b"s" * 16, 2**10, 8, 1)
            results.append("ok")
        except passwords.ScryptBusy as exc:
            assert exc.status_code == 503 and exc.headers["Retry-After"]
            results.append("busy")

    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert peak == 2 and results.count("ok") == 2 and results.count("busy") == 6
    assert passwords._derive("pw", b"s" * 16, 2**10, 8, 1)                  # slots were released
    passwords.set_concurrency(None)


def test_concurrency_env_var(monkeypatch):
    monkeypatch.setenv("APGKIT_SCRYPT_CONCURRENCY", "5")
    passwords.set_concurrency(None)
    assert passwords._gate._value == 5
    monkeypatch.setenv("APGKIT_SCRYPT_CONCURRENCY", "junk")
    passwords.set_concurrency(None)
    assert passwords._gate._value == 2
    monkeypatch.delenv("APGKIT_SCRYPT_CONCURRENCY")
    passwords.set_concurrency(None)


# ---- login: counting before hashing, one derivation ---------------------------------------------------------------------
APP = AppAuth("t", "t", {}, {"read": frozenset({"x:read"})})
FAST = (10, 8, 1)


@pytest.fixture
def local(setup, monkeypatch):
    monkeypatch.setattr(passwords, "_N", 2**10)                              # keep the tests quick; the cap and counts are what matter
    monkeypatch.setattr("apgkit.vault.KDF_CURRENT", FAST)
    with setup.connect() as c:
        c.execute(AUTH_SQL)
        c.commit()
    vault = Vault("demo")
    la = LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes={"read"}, vault=vault)
    with setup.connect() as c:
        la.set_admin_password(c, PW)
    return setup, la, vault


def _count_scrypt(monkeypatch):
    calls = []
    real = passwords.scrypt
    monkeypatch.setattr(passwords, "scrypt", lambda *a, **k: calls.append(1) or real(*a, **k))
    return calls


@needs_db
def test_one_scrypt_per_login_with_vault_and_platform_wrap(local, monkeypatch):
    db, la, vault = local
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", RANDOM_ENV)
    with db.connect() as c:
        vault._wrap(c, RANDOM_ENV, "vault_env_salt", "vault_wrap_env", "vault_kdf_env", vault._data_key)
        c.commit()
        v2 = Vault("demo")
        la.vault = v2
        assert v2.try_unlock_with_platform_secret(c)
        calls = _count_scrypt(monkeypatch)
        assert la.login_password(c, PW) and len(calls) == 1
        calls.clear()
        assert not la.login_password(c, "wrong password!") and len(calls) == 1
        calls.clear()
        la.vault = Vault("demo")                                              # fresh process: locked, wrap not yet proven
        assert la.login_password(c, PW) and len(calls) == 1 and la.vault.is_unlocked()


@needs_db
def test_one_scrypt_per_login_without_vault(setup, monkeypatch):
    monkeypatch.setattr(passwords, "_N", 2**10)
    with setup.connect() as c:
        c.execute(AUTH_SQL)
        c.commit()
        la = LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes={"read"})
        la.set_admin_password(c, PW)
        calls = _count_scrypt(monkeypatch)
        assert la.login_password(c, PW) and len(calls) == 1
        calls.clear()
        assert not la.login_password(c, "wrong password!") and len(calls) == 1


@needs_db
def test_burst_of_failures_is_counted_before_hashing(local, monkeypatch):
    db, la, _ = local
    limiter = FailureLimiter(limit=3)
    calls = _count_scrypt(monkeypatch)
    outcomes, barrier = [], threading.Barrier(12)

    def attempt():
        with db.connect() as c:
            barrier.wait()
            try:
                outcomes.append("ok" if la.login_password(c, "wrong password!", client="1.2.3.4", limiter=limiter) else "bad")
            except HTTPException as exc:
                outcomes.append(exc.status_code)

    threads = [threading.Thread(target=attempt) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert outcomes.count("bad") == 3 and outcomes.count(429) == 9           # only `limit` attempts ever reach the hash
    assert len(calls) == 3
    with db.connect() as c:
        with pytest.raises(HTTPException) as e:
            la.login_password(c, PW, client="1.2.3.4", limiter=limiter)       # even the right password waits while limited
        assert e.value.status_code == 429
        assert la.login_password(c, PW, client="5.6.7.8", limiter=limiter)    # another client is unaffected


@needs_db
def test_successful_login_is_forgiven_and_busy_returns_the_slot(local, monkeypatch):
    db, la, _ = local
    limiter = FailureLimiter(limit=2)
    with db.connect() as c:
        for _ in range(5):
            assert la.login_password(c, PW, client="c", limiter=limiter)       # successes never lock the admin out
        assert not limiter.limited("c")
        monkeypatch.setattr(passwords, "_WAIT_SECONDS", 0.01)
        passwords.set_concurrency(1)
        passwords._get_gate().acquire()                                       # every slot taken
        for _ in range(4):
            with pytest.raises(passwords.ScryptBusy):
                la.login_password(c, PW, client="c", limiter=limiter)
        assert not limiter.limited("c")                                       # no password was judged: nothing counted
        passwords.set_concurrency(None)
