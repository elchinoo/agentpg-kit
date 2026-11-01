"""Row MACs: a database write without the data key cannot plant or edit a session, a token or a password wrap."""
import pytest
from conftest import needs_db

from apgkit import passwords
from apgkit.auth.local import LocalAuth
from apgkit.auth.principal import AppAuth
from apgkit.auth.schema import SQL as AUTH_SQL
from apgkit.ids import sha256
from apgkit.vault import Vault, VaultLocked

APP = AppAuth("t", "t", {}, {"read": frozenset({"x:read"}), "write": frozenset({"x:write"})})
PW = "a-long-admin-password-1"


@pytest.fixture
def local(db, monkeypatch):
    monkeypatch.setattr(passwords, "_N", 2**10)
    monkeypatch.setattr("apgkit.vault.KDF_CURRENT", (10, 8, 1))
    with db.connect() as c:
        c.execute(AUTH_SQL)
        c.commit()
    vault = Vault("rm")
    la = LocalAuth(APP, env_prefix="RM", token_prefix="rm_", token_scopes={"read", "write"}, vault=vault)
    with db.connect() as c:
        la.set_admin_password(c, PW)
    assert vault.is_unlocked()
    return db, la, vault


def test_row_mac_basics():
    v = Vault("x")
    with pytest.raises(VaultLocked):
        v.row_mac("t", "a")
    v._data_key = b"k" * 32
    m = v.row_mac("t", "a", "b")
    assert v.check_row_mac("t", m, "a", "b") and not v.check_row_mac("t", m, "a", "c") and not v.check_row_mac("u", m, "a", "b")
    assert v.row_mac("t", "ab", "") != v.row_mac("t", "a", "b")              # length-prefixed fields do not collide
    assert not v.check_row_mac("t", None, "a") and not v.check_row_mac("t", "", "a")


@needs_db
def test_genuine_session_and_token_work(local):
    db, la, _ = local
    with db.connect() as c:
        raw = la.create_session(c, subject="u1", name="N", email="e@x", roles=["a"], source="oidc")
        assert la.session_principal(c, raw).subject == "u1"
        tid, tok = la.create_token(c, "ci", "read")
        assert la.token_principal(c, tok).scopes == frozenset({"read"})
        assert la.revoke_token(c, tid) and la.token_principal(c, tok) is None


@needs_db
def test_planted_session_rows_are_refused(local):
    db, la, _ = local
    with db.connect() as c:
        # an attacker with database write access inserts a local-admin session, with and without a made-up MAC
        for mac in (None, "AAAA"):
            c.execute("INSERT INTO web_session (token_hash, expires_at, subject, source, mac) VALUES (%s, now() + interval '1 hour', 'local-admin', 'local', %s)",
                      (sha256("planted" + str(mac)), mac))
        c.commit()
        assert la.session_principal(c, "planted" + "None") is None
        assert la.session_principal(c, "planted" + "AAAA") is None


@needs_db
def test_edited_session_and_token_rows_are_refused(local):
    db, la, _ = local
    with db.connect() as c:
        raw = la.create_session(c, subject="u1", roles=["viewer"], source="oidc")
        c.execute("UPDATE web_session SET roles='[\"admin\"]' WHERE token_hash=%s", (sha256(raw),))
        c.execute("UPDATE web_session SET source='local' WHERE token_hash=%s", (sha256(raw),))
        c.commit()
        assert la.session_principal(c, raw) is None
        _, tok = la.create_token(c, "ci", "read")
        c.execute("UPDATE api_token SET scope='write' WHERE token_hash=%s", (sha256(tok),))
        c.commit()
        assert la.token_principal(c, tok) is None


@needs_db
def test_extended_expiry_and_planted_token_are_refused(local):
    db, la, _ = local
    with db.connect() as c:
        raw = la.create_session(c)
        c.execute("UPDATE web_session SET expires_at = expires_at + interval '30 days' WHERE token_hash=%s", (sha256(raw),))
        c.execute("INSERT INTO api_token (name, token_hash, prefix, scope) VALUES ('x', %s, 'rm_aaaaa', 'write')", (sha256("rm_planted"),))
        c.commit()
        assert la.session_principal(c, raw) is None
        assert la.token_principal(c, "rm_planted") is None


@needs_db
def test_undoing_a_revocation_with_the_stored_mac_fails(local):
    db, la, _ = local
    with db.connect() as c:
        tid, tok = la.create_token(c, "ci", "read")
        la.revoke_token(c, tid)
        c.execute("UPDATE api_token SET revoked_at = NULL WHERE id=%s", (tid,))
        c.commit()
        assert la.token_principal(c, tok) is None


@needs_db
def test_planted_password_wrap_does_not_replace_the_key_in_memory(local):
    db, la, vault = local
    with db.connect() as c:
        # the attacker builds a vault of their own, wrapped under a password they know, and swaps the stored rows in
        other = Vault("rm")
        rows = {k: c.execute("SELECT value FROM app_setting WHERE key=%s", (k,)).fetchone() for k in ("vault_salt", "vault_wrap_pw", "vault_kdf_pw")}
        c.execute("DELETE FROM app_setting WHERE key LIKE 'vault_%'")
        other.initialize(c, "attacker-password-123456")
        c.commit()
        assert vault.is_unlocked()
        key_before = vault._data_key
        assert la.login_password(c, "attacker-password-123456") is False
        assert vault._data_key == key_before                                   # the planted wrap never replaced the key in memory
        assert all(rows.values())


@needs_db
def test_adopt_rows_signs_legacy_rows(local):
    db, la, _ = local
    with db.connect() as c:
        c.execute("INSERT INTO api_token (name, token_hash, prefix, scope) VALUES ('old', %s, 'rm_old__', 'read')", (sha256("rm_old"),))
        c.commit()
        assert la.token_principal(c, "rm_old") is None
        assert la.adopt_rows(c)["tokens"] == 1
        assert la.token_principal(c, "rm_old").scopes == frozenset({"read"})
