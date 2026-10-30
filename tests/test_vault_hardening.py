"""Vault hardening: data-key rotation, platform-secret rotation, KDF parameters, admin-password-only mode."""
import pytest
from conftest import needs_db

from apgkit import migrate, passwords, settings_store
from apgkit.vault import KDF_CURRENT, KDF_LEGACY, Vault, VaultError, VaultLocked, _b64, _kdf

pytestmark = needs_db
PW = "a long enough password"
ENV = "platform-managed-secret-value"


@pytest.fixture
def setup(db, tmp_path, monkeypatch):
    migrate.run(db, tmp_path)
    monkeypatch.delenv("DEMO_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY_FILE", str(tmp_path / "none"))
    with db.connect() as c:
        c.execute("CREATE TABLE vals (id int PRIMARY KEY, enc text, other text)")
        c.commit()
    return db


def _fill(v, c, n=3):
    for i in range(n):
        c.execute("INSERT INTO vals VALUES (%s, %s, %s)", (i, v.encrypt(f"secret-{i}"), v.encrypt(f"other-{i}")))
    c.commit()


def _register(v):
    v.register_store("vals.enc", "SELECT id, enc AS value FROM vals", "UPDATE vals SET enc = %(value)s WHERE id = %(id)s")
    v.register_store("vals.other", "SELECT id, other AS value FROM vals", "UPDATE vals SET other = %(value)s WHERE id = %(id)s")


def _rows(db):
    with db.connect() as c:
        return c.execute("SELECT id, enc, other FROM vals ORDER BY id").fetchall()


def _state(c):
    return {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM app_setting WHERE key LIKE 'vault_%'").fetchall()}


def test_rotate_data_key_registered_stores(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
    v = Vault("demo")
    _register(v)
    assert set(v.stores()) == {"vals.enc", "vals.other"}
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        _fill(v, c)
        before_state, before_rows = _state(c), _rows(setup)
        c.rollback()                                                  # rotate_data_key needs an idle connection
        old_cipher = before_rows[0]["enc"]
        counts = v.rotate_data_key(c, password=PW)
        assert counts == {"vals.enc": 3, "vals.other": 3}
        after_rows = _rows(setup)
        assert [r["enc"] for r in after_rows] != [r["enc"] for r in before_rows]
        assert [v.decrypt(r["enc"]) for r in after_rows] == ["secret-0", "secret-1", "secret-2"]
        with pytest.raises(VaultError):
            v.decrypt(old_cipher)                                   # the old ciphertext no longer opens
        assert _state(c) != before_state
        # a restarted process opens the new key by either wrap
        for how in ("env", "pw"):
            v2 = Vault("demo")
            assert (v2.try_unlock_with_platform_secret(c) if how == "env" else v2.unlock_with_password(c, PW))
            assert v2.decrypt(after_rows[1]["enc"]) == "secret-1"
        # a copy of the pre-rotation wraps plus the old secrets recovers the OLD key only: it does not open new data
        c.execute("DELETE FROM app_setting WHERE key LIKE 'vault_%'")
        for k, val in before_state.items():
            settings_store.put(c, k, val)
        c.commit()
        old = Vault("demo")
        assert old.unlock_with_password(c, PW)
        with pytest.raises(VaultError):
            old.decrypt(after_rows[0]["enc"])


def test_rotate_data_key_callback_and_failure_midway_keeps_old_key(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
    v = Vault("demo")
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        _fill(v, c)
        before_state, before_rows = _state(c), _rows(setup)
        c.rollback()                                                  # rotate_data_key needs an idle connection

        def boom(old_decrypt, new_encrypt):
            for r in c.execute("SELECT id, enc FROM vals ORDER BY id").fetchall():
                c.execute("UPDATE vals SET enc=%s WHERE id=%s", (new_encrypt(old_decrypt(r["enc"])), r["id"]))
                if r["id"] == 1:
                    raise RuntimeError("crash midway")

        with pytest.raises(RuntimeError):
            v.rotate_data_key(c, boom, password=PW)
        c.rollback()
        assert _rows(setup) == before_rows and _state(c) == before_state     # nothing changed anywhere
        assert v.is_unlocked() and v.decrypt(before_rows[0]["enc"]) == "secret-0"   # the old key is intact in memory too

        def good(old_decrypt, new_encrypt):
            for r in c.execute("SELECT id, enc FROM vals").fetchall():
                c.execute("UPDATE vals SET enc=%s WHERE id=%s", (new_encrypt(old_decrypt(r["enc"])), r["id"]))

        c.rollback()
        v.register_store("vals.other", "SELECT id, other AS value FROM vals", "UPDATE vals SET other = %(value)s WHERE id = %(id)s")
        v.rotate_data_key(c, good, password=PW)                                # registered store + callback together
        rows = _rows(setup)
        assert [v.decrypt(r["enc"]) for r in rows] == ["secret-0", "secret-1", "secret-2"]
        assert [v.decrypt(r["other"]) for r in rows] == ["other-0", "other-1", "other-2"]


def test_rotate_data_key_failure_while_wrapping_rolls_back_rows(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
    v = Vault("demo")
    _register(v)
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        _fill(v, c)
        before_state, before_rows = _state(c), _rows(setup)
        c.rollback()                                                  # rotate_data_key needs an idle connection
        real = v._wrap
        calls = []

        def flaky(conn, secret, *a):
            calls.append(secret)
            if secret == ENV:                      # the password wrap was written, the platform wrap fails
                raise RuntimeError("disk full")
            return real(conn, secret, *a)

        monkeypatch.setattr(v, "_wrap", flaky)
        with pytest.raises(RuntimeError):
            v.rotate_data_key(c, password=PW)
        assert calls == [PW, ENV]
        assert _rows(setup) == before_rows and _state(c) == before_state
        assert v.decrypt(before_rows[2]["enc"]) == "secret-2"


def test_rotate_data_key_preconditions(setup, monkeypatch):
    v = Vault("demo")
    with setup.connect() as c:
        with pytest.raises(VaultLocked):
            v.rotate_data_key(c, lambda d, e: None, password=PW)
        v.initialize(c, PW)
        c.commit()
        with pytest.raises(VaultError, match="password is required"):
            v.rotate_data_key(c, lambda d, e: None)
        with pytest.raises(VaultError, match="incorrect") as ei:
            v.rotate_data_key(c, lambda d, e: None, password="wrong password!!!")
        assert "wrong password" not in str(ei.value)
        with pytest.raises(VaultError, match="nothing to re-encrypt"):
            v.rotate_data_key(c, password=PW)
        c.execute("SELECT 1")
        with pytest.raises(VaultError, match="no open transaction"):
            v.rotate_data_key(c, lambda d, e: None, password=PW)


def test_rotate_data_key_without_platform_secret_drops_stale_env_wrap(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
    v = Vault("demo")
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        monkeypatch.delenv("DEMO_ENCRYPTION_KEY")
        v.rotate_data_key(c, lambda d, e: None, password=PW)
        s = _state(c)
        assert "vault_wrap_env" not in s and "vault_wrap_pw" in s     # the old-key wrap is gone


def test_rotate_data_key_sso_only_vault(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
    v = Vault("demo")
    with setup.connect() as c:
        assert v.initialize_with_platform_secret(c)
        c.commit()
        tok = v.encrypt("x")
        v.rotate_data_key(c, lambda d, e: None)                       # no password wrap: no password needed
        with pytest.raises(VaultError):
            v.decrypt(tok)
        v2 = Vault("demo")
        assert v2.try_unlock_with_platform_secret(c)


def test_rotate_platform_secret(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
    v = Vault("demo")
    with setup.connect() as c:
        with pytest.raises(VaultLocked):
            v.rotate_platform_secret(c, "x")
        v.initialize(c, PW)
        c.commit()
        tok = v.encrypt("keep")
        v.rotate_platform_secret(c, "the-new-platform-secret")
        c.commit()
        monkeypatch.setenv("DEMO_ENCRYPTION_KEY", "the-new-platform-secret")
        v2 = Vault("demo")
        assert v2.try_unlock_with_platform_secret(c) and v2.decrypt(tok) == "keep"
        monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
        v3 = Vault("demo")
        assert not v3.try_unlock_with_platform_secret(c)              # the old secret no longer opens it


def test_new_wraps_use_current_kdf_and_legacy_wraps_are_upgraded(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
    v = Vault("demo")
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        assert KDF_CURRENT == (17, 8, 1)
        assert _state(c)["vault_kdf_pw"] == _state(c)["vault_kdf_env"] == "scrypt$17$8$1"
        tok = v.encrypt("hello")
        # rewrite both wraps the way the previous kit version did: N=2^15 and no stored parameters
        key = v._data_key
        for sk, wk, kk, secret in (("vault_salt", "vault_wrap_pw", "vault_kdf_pw", PW),
                                   ("vault_env_salt", "vault_wrap_env", "vault_kdf_env", ENV)):
            import secrets
            salt = secrets.token_bytes(16)
            settings_store.put(c, sk, _b64(salt))
            settings_store.put(c, wk, _kdf(secret, salt, KDF_LEGACY).encrypt(key).decode())
            c.execute("DELETE FROM app_setting WHERE key=%s", (kk,))
        c.commit()
        # platform-secret unlock at start upgrades the platform wrap only
        v2 = Vault("demo")
        assert v2.try_unlock_with_platform_secret(c) and v2.decrypt(tok) == "hello"
        s = _state(c)
        assert s["vault_kdf_env"] == "scrypt$17$8$1" and "vault_kdf_pw" not in s
        # password sign-in upgrades the password wrap
        v3 = Vault("demo")
        assert v3.unlock_with_password(c, PW)
        c.commit()
        assert _state(c)["vault_kdf_pw"] == "scrypt$17$8$1"
        v4 = Vault("demo")
        assert v4.unlock_with_password(c, PW) and v4.decrypt(tok) == "hello"


def test_damaged_or_excessive_kdf_parameters_fail_closed(setup, monkeypatch):
    v = Vault("demo")
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        for bad in ("scrypt$40$8$1", "scrypt$17$8$99", "scrypt$17$64$1", "argon$1$2$3", "garbage"):
            settings_store.put(c, "vault_kdf_pw", bad)
            v.lock()
            assert not v.unlock_with_password(c, PW) and not v.is_unlocked()


def test_admin_password_only_mode(setup, monkeypatch):
    """No <APP>_ENCRYPTION_KEY: the vault is wrapped under the password alone and stays locked after a restart."""
    v = Vault("demo")
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        tok = v.encrypt("sk-provider")
        s = _state(c)
        assert "vault_wrap_env" not in s and "vault_env_salt" not in s       # nothing the platform holds opens it
        v2 = Vault("demo")                                                   # a restart
        assert not v2.try_unlock_with_platform_secret(c) and not v2.is_unlocked()
        st = v2.status(c)
        assert st == {"initialized": True, "unlocked": False, "auto_unlock": False, "reason": "no_platform_key"}
        assert not v2.initialize_with_platform_secret(c)                     # SSO-only bootstrap is impossible here
        with pytest.raises(VaultLocked):
            v2.decrypt(tok)
        assert v2.unlock_with_password(c, PW) and v2.decrypt(tok) == "sk-provider"
        # the env key being set later (an attacker's or an operator's) does not matter until a human unlocks: then it is added
        monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
        v3 = Vault("demo")
        assert not v3.try_unlock_with_platform_secret(c)


def test_drop_platform_wrap_switches_to_password_only(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
    v = Vault("demo")
    with setup.connect() as c:
        v.initialize(c, PW)
        c.commit()
        v.drop_platform_wrap(c)
        c.commit()
        assert "vault_wrap_env" not in _state(c)
        # ... but a later password unlock re-adds it while the env key is still configured: unset it first
        monkeypatch.delenv("DEMO_ENCRYPTION_KEY")
        v2 = Vault("demo")
        assert not v2.try_unlock_with_platform_secret(c) and v2.unlock_with_password(c, PW)
        c.commit()
        assert "vault_wrap_env" not in _state(c)


def test_drop_platform_wrap_refuses_when_it_is_the_only_wrap(setup, monkeypatch):
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", ENV)
    v = Vault("demo")
    with setup.connect() as c:
        assert v.initialize_with_platform_secret(c)
        with pytest.raises(VaultError):
            v.drop_platform_wrap(c)


def test_password_hash_parameters_and_rehash():
    h = passwords.hash_password("correct horse battery")
    assert h.startswith("scrypt$131072$8$1$") and not passwords.needs_rehash(h)
    import base64
    import hashlib
    salt = b"0123456789abcdef"
    raw = hashlib.scrypt(b"correct horse battery", salt=salt, n=2**15, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=32)
    legacy = f"scrypt$32768$8$1${base64.b64encode(salt).decode()}${base64.b64encode(raw).decode()}"
    assert passwords.verify_password("correct horse battery", legacy) and passwords.needs_rehash(legacy)
    assert not passwords.verify_password("x", "scrypt$1099511627776$8$1$AAAA$AAAA")        # absurd cost is refused, not computed
    assert passwords.needs_rehash("garbage")


def test_login_rehashes_legacy_admin_hash(setup, tmp_path, monkeypatch):
    from test_db_blocks import local
    la = local(setup, tmp_path, monkeypatch)
    import base64
    import hashlib
    salt = b"0123456789abcdef"
    raw = hashlib.scrypt(b"correct horse battery", salt=salt, n=2**15, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=32)
    legacy = f"scrypt$32768$8$1${base64.b64encode(salt).decode()}${base64.b64encode(raw).decode()}"
    with setup.connect() as c:
        settings_store.put(c, "admin_password_hash", legacy)
        c.commit()
        assert la.login_password(c, "correct horse battery")
        assert not passwords.needs_rehash(settings_store.get(c, "admin_password_hash"))
        assert la.login_password(c, "correct horse battery")


def test_vault_errors_do_not_contain_secrets(setup):
    v = Vault("demo")
    with setup.connect() as c:
        v.initialize(c, PW)
        with pytest.raises(VaultError) as ei:
            v.decrypt("gAAAA-secret-looking-token")
        assert "secret-looking" not in str(ei.value) and ei.value.__cause__ is not None
        assert PW not in repr(v.status(c))
