"""Database-backed blocks: migrations, the vault and local authentication."""
import pytest
from conftest import needs_db

from apgkit import migrate, settings_store
from apgkit.auth import AppAuth, LocalAuth
from apgkit.auth.schema import SQL as AUTH_SQL
from apgkit.db import Database
from apgkit.vault import Vault, VaultError, VaultLocked

pytestmark = needs_db


def test_migrations_apply_once_in_order_with_replacements(db, tmp_path):
    (tmp_path / "002_b.sql").write_text("INSERT INTO t VALUES ({{N}});")
    (tmp_path / "001_a.sql").write_text("CREATE TABLE t (n int);")
    assert migrate.run(db, tmp_path, replacements={"{{N}}": "7"}) == ["001_a.sql", "002_b.sql"]
    assert migrate.run(db, tmp_path, replacements={"{{N}}": "7"}) == []
    with db.connect() as c:
        assert c.execute("SELECT n FROM t").fetchone()["n"] == 7
        assert c.execute("SELECT count(*) AS n FROM app_setting").fetchone()["n"] == 0     # the shared table exists
    with pytest.raises(ValueError):
        migrate.run(db, tmp_path, extensions=("bad name;drop",))


def test_two_apps_in_one_database_keep_separate_migration_tables(db, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    (a / "001.sql").write_text("CREATE TABLE ta (x int);")
    (b / "001.sql").write_text("CREATE TABLE tb (x int);")
    assert migrate.run(db, a, table="a_migrations") == ["001.sql"]
    assert migrate.run(db, b, table="b_migrations") == ["001.sql"]


def test_vault_lifecycle(db, tmp_path, monkeypatch):
    migrate.run(db, tmp_path)
    monkeypatch.delenv("DEMO_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY_FILE", str(tmp_path / "none"))
    v = Vault("demo")
    with db.connect() as c:
        assert not v.is_initialized(c) and not v.is_unlocked()
        with pytest.raises(VaultLocked):
            v.encrypt("x")
        v.initialize(c, "a long enough password")
        c.commit()
        token = v.encrypt("sk-secret")
        assert "sk-secret" not in token and v.decrypt(token) == "sk-secret"
        v.lock()
        with pytest.raises(VaultLocked):
            v.decrypt(token)
        assert not v.unlock_with_password(c, "wrong password!!")
        assert v.unlock_with_password(c, "a long enough password") and v.decrypt(token) == "sk-secret"
        v.change_password(c, "another long password")
        c.commit()
        v.lock()
        assert not v.unlock_with_password(c, "a long enough password")
        assert v.unlock_with_password(c, "another long password") and v.decrypt(token) == "sk-secret"
        with pytest.raises(VaultError):
            v.decrypt("not-a-token")
        assert settings_store.get(c, "vault_wrap_pw")          # the storage keys the apps used before the kit


def test_vault_platform_secret_unlocks_after_restart(db, tmp_path, monkeypatch):
    migrate.run(db, tmp_path)
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", "platform-managed-secret-value")
    v = Vault("demo")
    with db.connect() as c:
        v.initialize(c, "a long enough password")
        c.commit()
        assert v.status(c)["auto_unlock"]
        token = v.encrypt("hello")
        v.lock()
        assert v.try_unlock_with_platform_secret(c) and v.decrypt(token) == "hello"
        monkeypatch.setenv("DEMO_ENCRYPTION_KEY", "a-different-secret")
        v.lock()
        assert not v.try_unlock_with_platform_secret(c)


def _vault_state(c):
    return settings_store.get(c, "vault_wrap_env"), settings_store.get(c, "vault_env_salt")


def test_vault_first_wrap_and_status_reason(db, tmp_path, monkeypatch):
    migrate.run(db, tmp_path)
    monkeypatch.delenv("DEMO_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY_FILE", str(tmp_path / "none"))
    v = Vault("demo")
    with db.connect() as c:
        assert v.status(c)["reason"] == "not_initialized"
        v.initialize(c, "a long enough password")
        c.commit()
        assert _vault_state(c) == (None, None) and v.status(c)["reason"] is None
        token = v.encrypt("hello")
        v.lock()
        assert v.status(c)["reason"] == "no_platform_key" and not v.status(c)["auto_unlock"]
        monkeypatch.setenv("DEMO_ENCRYPTION_KEY", "first-platform-key-value")
        assert v.status(c)["reason"] == "no_platform_wrap"
        assert not v.try_unlock_with_platform_secret(c) and not v.is_unlocked()
        assert v.unlock_with_password(c, "a long enough password")      # first wrap
        c.commit()
        assert all(_vault_state(c)) and v.status(c)["auto_unlock"]
        v.lock()
        assert v.try_unlock_with_platform_secret(c) and v.decrypt(token) == "hello"


def test_vault_rotated_platform_key_is_rewrapped_by_password_unlock(db, tmp_path, monkeypatch):
    migrate.run(db, tmp_path)
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", "old-platform-key-value")
    v = Vault("demo")
    with db.connect() as c:
        v.initialize(c, "a long enough password")
        c.commit()
        token = v.encrypt("hello")
        old_wrap = _vault_state(c)
        v.lock()
        monkeypatch.setenv("DEMO_ENCRYPTION_KEY", "new-platform-key-value")
        v = Vault("demo")                                            # a restarted process with the new key
        assert not v.try_unlock_with_platform_secret(c) and not v.is_unlocked()
        st = v.status(c)
        assert st["reason"] == "platform_key_mismatch" and st["auto_unlock"] and not st["unlocked"]
        with pytest.raises(VaultLocked):
            v.decrypt(token)
        assert v.unlock_with_password(c, "a long enough password")
        c.commit()
        assert _vault_state(c) != old_wrap and v.status(c)["auto_unlock"]
        v = Vault("demo")                                            # restart again: auto-unlock now works
        assert v.try_unlock_with_platform_secret(c) and v.decrypt(token) == "hello"
        assert v.status(c)["reason"] is None


def test_vault_auto_unlock_with_wrong_or_damaged_wrap_fails_closed(db, tmp_path, monkeypatch):
    migrate.run(db, tmp_path)
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY", "platform-managed-secret-value")
    v = Vault("demo")
    with db.connect() as c:
        v.initialize(c, "a long enough password")
        c.commit()
        wrap = _vault_state(c)
        v.lock()
        monkeypatch.setenv("DEMO_ENCRYPTION_KEY", "some-other-key-entirely")
        assert not v.try_unlock_with_platform_secret(c) and not v.is_unlocked()
        assert v.status(c)["reason"] == "platform_key_mismatch"
        assert _vault_state(c) == wrap                               # nothing was weakened or overwritten
        monkeypatch.setenv("DEMO_ENCRYPTION_KEY", "platform-managed-secret-value")
        settings_store.put(c, "vault_env_salt", "!!not base64!!")    # a damaged wrap must not raise
        v2 = Vault("demo")
        assert not v2.try_unlock_with_platform_secret(c) and not v2.is_unlocked()
        assert v2.unlock_with_password(c, "a long enough password")  # and the password path heals it
        c.commit()
        v2.lock()
        assert v2.try_unlock_with_platform_secret(c)


APP = AppAuth("demo", "demo-client", role_permissions={"admin": frozenset({"*"}), "viewer": frozenset({"things:read"})},
              scope_permissions={"read": frozenset({"things:read"}), "full": frozenset({"*"})})


def local(db, tmp_path, monkeypatch, vault=None) -> LocalAuth:
    monkeypatch.delenv("DEMO_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_API_KEY_FILE", str(tmp_path / "nokey"))
    with db.connect() as c:
        c.execute(AUTH_SQL)
        c.commit()
    return LocalAuth(APP, env_prefix="DEMO", token_prefix="dm_", token_scopes={"read", "full"}, vault=vault)


def test_setup_flow_and_password_login(db, tmp_path, monkeypatch):
    a = local(db, tmp_path, monkeypatch, Vault("demo"))
    with db.connect() as c:
        assert a.needs_setup(c) and not a.admin_configured(c)
        with pytest.raises(PermissionError):
            a.complete_setup(c, "AAAA-BBBB-CCCC", "a long enough password")
        a.complete_setup(c, a.setup_code().lower(), "a long enough password")      # the code is case-insensitive
        assert not a.needs_setup(c) and a.vault.is_unlocked()
        with pytest.raises(PermissionError):
            a.complete_setup(c, a.setup_code(), "another long password")
        assert a.login_password(c, "a long enough password") and not a.login_password(c, "nope nope nope nope")
        with pytest.raises(ValueError):
            a.set_admin_password(c, "short")
        a.change_password(c, "a long enough password", "a brand new password")
        assert a.login_password(c, "a brand new password")
        with pytest.raises(PermissionError):
            a.change_password(c, "wrong wrong wrong", "x" * 20)


def test_static_key_disables_the_setup_flow(db, tmp_path, monkeypatch):
    a = local(db, tmp_path, monkeypatch)
    monkeypatch.setenv("DEMO_API_KEY", "static-key-value")
    with db.connect() as c:
        assert not a.needs_setup(c) and a.static_key_configured()
    assert a.static_key_matches("static-key-value") and not a.static_key_matches("static-key-valuf")


def test_sessions_local_admin_and_federated_user(db, tmp_path, monkeypatch):
    a = local(db, tmp_path, monkeypatch)
    with db.connect() as c:
        raw = a.create_session(c)
        p = a.session_principal(c, raw)
        assert p.kind == "session" and p.can("anything:at-all") and p.source == "local"
        fed = a.create_session(c, subject="usr_1", name="Ada", email="ada@example.com", roles=["demo:viewer", "other:admin"], source="oidc",
                               id_token_hint="hint")
        q = a.session_principal(c, fed)
        assert q.can("things:read") and not q.can("things:write") and q.name == "Ada" and q.source == "oidc"
        assert q.roles == frozenset({"demo:viewer", "other:admin"})
        row = a.delete_session(c, fed)
        assert row["id_token_hint"] == "hint" and a.session_principal(c, fed) is None
        assert a.session_principal(c, None) is None and a.session_principal(c, "bogus") is None
        c.execute("UPDATE web_session SET expires_at = now() - interval '1 minute'")
        c.commit()
        assert a.session_principal(c, raw) is None


def test_tokens_scope_hashing_and_revocation(db, tmp_path, monkeypatch):
    a = local(db, tmp_path, monkeypatch)
    with db.connect() as c:
        with pytest.raises(ValueError):
            a.create_token(c, "x", "admin")
        tid, raw = a.create_token(c, "ci", "read")
        stored = c.execute("SELECT token_hash FROM api_token WHERE id=%s", (tid,)).fetchone()["token_hash"]
        assert raw.startswith("dm_") and raw not in stored
        p = a.token_principal(c, raw)
        assert p.can("things:read") and not p.can("things:write") and p.name == "ci" and p.scopes == frozenset({"read"})
        assert a.token_principal(c, "dm_wrong") is None and a.token_principal(c, "other_prefix") is None
        assert a.revoke_token(c, tid) and not a.revoke_token(c, tid) and a.token_principal(c, raw) is None
        assert a.list_tokens(c)[0]["revoked_at"] is not None


def test_reset_admin_runs_the_app_hook_and_ends_sessions(db, tmp_path, monkeypatch):
    seen = []
    a = local(db, tmp_path, monkeypatch, Vault("demo"))
    a.on_reset = lambda conn: seen.append(1)
    with db.connect() as c:
        a.set_admin_password(c, "a long enough password")
        raw = a.create_session(c)
        a.reset_admin(c)
        assert seen and a.needs_setup(c) and a.session_principal(c, raw) is None and not a.vault.is_initialized(c)


def test_auth_schema_upgrades_a_pre_kit_session_table(db):
    with db.connect() as c:
        c.execute("CREATE TABLE web_session (token_hash text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL)")
        c.execute("INSERT INTO web_session (token_hash, expires_at) VALUES ('h', now() + interval '1 hour')")
        c.execute(AUTH_SQL)
        c.execute(AUTH_SQL)                                    # idempotent
        row = c.execute("SELECT subject, source, roles FROM web_session").fetchone()
        assert row == {"subject": "local-admin", "source": "local", "roles": []}


def test_vault_can_start_from_the_platform_secret_alone(db, tmp_path, monkeypatch):
    migrate.run(db, tmp_path)
    monkeypatch.delenv("DEMO_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("DEMO_ENCRYPTION_KEY_FILE", str(tmp_path / "none"))
    v = Vault("demo")
    with db.connect() as c:
        assert not v.initialize_with_platform_secret(c)                       # no platform secret: nothing happens
        monkeypatch.setenv("DEMO_ENCRYPTION_KEY", "platform-managed-secret-value")
        assert v.initialize_with_platform_secret(c) and v.is_initialized(c) and v.is_unlocked()
        c.commit()
        token = v.encrypt("sk-secret")
        assert not v.initialize_with_platform_secret(c)                       # already initialised
        v.lock()
        assert not v.unlock_with_password(c, "any password at all")           # there is no password wrap
        assert v.try_unlock_with_platform_secret(c) and v.decrypt(token) == "sk-secret"
        v.change_password(c, "a password added later")                        # a local admin can still be added afterwards
        c.commit()
        v.lock()
        assert v.unlock_with_password(c, "a password added later") and v.decrypt(token) == "sk-secret"


# ---- v0.2 ----------------------------------------------------------------------------------------------------
@needs_db
def test_a_non_waiting_pool_opens_without_blocking(db):
    import time

    lazy = Database(pool_wait=False)
    t = time.monotonic()
    pool = lazy.pool()
    assert time.monotonic() - t < 5
    with pool.connection() as conn:
        assert conn.execute("SELECT 1 AS one").fetchone()["one"] == 1
    lazy.close_pool()


@needs_db
def test_authenticator_static_tokens_cache_and_public_resolver(db):
    import hmac  # noqa: F401

    from apgkit.auth import AppAuth, Authenticator, LocalAuth, Principal
    from apgkit.auth.schema import SQL

    with db.connect() as c:
        c.execute("CREATE TABLE IF NOT EXISTS app_setting (key text PRIMARY KEY, value text NOT NULL)")
        c.execute(SQL)
        c.commit()
    app = AppAuth("t", "t", {}, {"read": frozenset({"x:read"})})
    local = LocalAuth(app, env_prefix="KITT", token_prefix="kt_", token_scopes={"read"})
    metrics_p = Principal("static", "metrics-token", frozenset({"metrics:scrape"}))
    auth = Authenticator(app, local, db, cookie_name="c", static_tokens=[(lambda: "scrape-secret", metrics_p), (lambda: "", metrics_p)],
                         token_cache_seconds=60)
    assert auth.resolve_bearer("scrape-secret") == metrics_p and auth.resolve_bearer("nope") is None and auth.resolve_bearer("") is None
    with db.connect() as c:
        tid, raw = local.create_token(c, "ro", "read")
    p = auth.resolve_bearer(raw)
    assert p and p.can("x:read")
    with db.connect() as c:
        local.revoke_token(c, tid)
    assert auth.resolve_bearer(raw) is not None                    # cached for this process
    auth.forget_tokens()
    assert auth.resolve_bearer(raw) is None
