"""Standalone authentication: the app's own admin password, browser sessions, API tokens and an optional static key.

* First run: a one-time *setup code* is printed to the server log (readable only by whoever operates the server). Presenting it
  in the browser lets the first person set the admin password (scrypt, never stored in the clear).
* Browser: password login creates a server-side session; the browser holds an HttpOnly cookie. Only the cookie's SHA-256 is stored.
* Clients: API tokens created in the UI, shown once, revocable, each with a scope the app maps to permissions.
* Optional static key (`<PREFIX>_API_KEY`, env or file): a full-access credential for automation.
Federated mode (see oidc.py / rp.py) sits beside this; an app can run either or both.
"""
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from .. import passwords
from .. import settings_store as store
from ..config import read_secret
from ..ids import sha256
from ..vault import Vault
from .principal import WILDCARD, AppAuth, Principal

_K_ADMIN = "admin_password_hash"
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no look-alike characters  # pragma: allowlist secret
SESSION_HOURS = 12


class LocalAuth:
    def __init__(self, app: AppAuth, *, env_prefix: str, token_prefix: str, token_scopes: set[str], vault: Vault | None = None,
                 on_reset=None):
        self.app, self.env_prefix, self.token_prefix = app, env_prefix.upper(), token_prefix
        self.token_scopes, self.vault, self.on_reset = token_scopes, vault, on_reset
        self._setup_code: str | None = None

    # ---- setup and password -------------------------------------------------------------------------------
    def setup_code(self) -> str:
        if self._setup_code is None:
            raw = "".join(secrets.choice(_ALPHABET) for _ in range(12))
            self._setup_code = f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"
        return self._setup_code

    def static_key(self) -> str:
        return read_secret(f"{self.env_prefix}_API_KEY", f"/etc/{self.env_prefix.lower()}/api_key")

    def static_key_configured(self) -> bool:
        return bool(self.static_key())

    def static_key_matches(self, raw: str) -> bool:
        key = self.static_key()
        return bool(key) and hmac.compare_digest(raw.encode(), key.encode())

    def admin_configured(self, conn) -> bool:
        return store.get(conn, _K_ADMIN) is not None

    def needs_setup(self, conn) -> bool:
        return not self.admin_configured(conn) and not self.static_key_configured()

    def complete_setup(self, conn, code: str, password: str) -> None:
        if self.admin_configured(conn):
            raise PermissionError("setup is already complete")
        if not hmac.compare_digest(code.strip().upper().encode(), self.setup_code().encode()):
            raise PermissionError("invalid setup code")
        self.set_admin_password(conn, password)
        self._setup_code = None

    def set_admin_password(self, conn, password: str) -> None:
        """Create or replace the admin password (hash); keep the vault, if the app has one, initialised and unlocked."""
        passwords.check_strength(password)
        store.put(conn, _K_ADMIN, passwords.hash_password(password))
        if self.vault:
            if self.vault.is_initialized(conn):
                self.vault.change_password(conn, password)
            else:
                self.vault.initialize(conn, password)
        conn.commit()

    def login_password(self, conn, password: str) -> bool:
        stored = store.get(conn, _K_ADMIN)
        if stored is None or not passwords.verify_password(password, stored):
            return False
        if passwords.needs_rehash(stored):                # hashed with weaker parameters: upgrade it now that the password is in hand
            store.put(conn, _K_ADMIN, passwords.hash_password(password))
        if self.vault:
            self.vault.unlock_with_password(conn, password)
        conn.commit()
        return True

    def change_password(self, conn, current: str, new: str) -> None:
        stored = store.get(conn, _K_ADMIN)
        if stored is None or not passwords.verify_password(current, stored):
            raise PermissionError("current password is incorrect")
        if self.vault and not self.vault.is_unlocked():
            self.vault.unlock_with_password(conn, current)
        self.set_admin_password(conn, new)

    def reset_admin(self, conn) -> None:
        """Operator recovery: forget the admin password (and the vault); the app's hook clears whatever it encrypted."""
        store.delete(conn, _K_ADMIN)
        if self.vault:
            self.vault.reset(conn)
        if self.on_reset:
            self.on_reset(conn)
        conn.execute("DELETE FROM web_session")
        conn.commit()

    # ---- sessions -------------------------------------------------------------------------------------------
    def create_session(self, conn, *, subject: str = "local-admin", name: str = "", email: str = "", roles=(), source: str = "local",
                       id_token_hint: str | None = None) -> str:
        from psycopg.types.json import Jsonb
        raw = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        conn.execute("DELETE FROM web_session WHERE expires_at < %s", (now,))
        conn.execute("INSERT INTO web_session (token_hash, expires_at, subject, name, email, roles, source, id_token_hint) "
                     "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                     (sha256(raw), now + timedelta(hours=SESSION_HOURS), subject, name[:120], email[:254], Jsonb(list(roles)), source, id_token_hint))
        conn.commit()
        return raw

    def session_principal(self, conn, raw: str | None) -> Principal | None:
        if not raw:
            return None
        row = conn.execute("SELECT subject, name, email, roles, source FROM web_session WHERE token_hash=%s AND expires_at > now()",
                           (sha256(raw),)).fetchone()
        if not row:
            return None
        if row["source"] == "local":                      # the local admin is the whole app's operator
            return Principal("session", row["subject"], frozenset({WILDCARD}), name=row["name"] or "admin", source="local")
        roles = frozenset(row["roles"])
        return Principal("session", row["subject"], self.app.permissions_for(roles=roles), roles=roles, name=row["name"],
                         email=row["email"], source=row["source"])

    def delete_session(self, conn, raw: str | None) -> dict | None:
        """End a session; returns its stored id_token_hint (for RP-initiated logout) if any."""
        if not raw:
            return None
        row = conn.execute("DELETE FROM web_session WHERE token_hash=%s RETURNING source, id_token_hint", (sha256(raw),)).fetchone()
        conn.commit()
        return row

    # ---- API tokens -----------------------------------------------------------------------------------------
    def create_token(self, conn, name: str, scope: str) -> tuple[int, str]:
        if scope not in self.token_scopes:
            raise ValueError(f"scope must be one of: {', '.join(sorted(self.token_scopes))}")
        raw = self.token_prefix + secrets.token_urlsafe(32)
        row = conn.execute("INSERT INTO api_token (name, token_hash, prefix, scope) VALUES (%s,%s,%s,%s) RETURNING id",
                           (name, sha256(raw), raw[:8], scope)).fetchone()
        conn.commit()
        return row["id"], raw

    def list_tokens(self, conn) -> list[dict]:
        return conn.execute("SELECT id, name, prefix, scope, created_at, last_used_at, revoked_at FROM api_token ORDER BY id DESC").fetchall()

    def revoke_token(self, conn, token_id: int) -> bool:
        row = conn.execute("UPDATE api_token SET revoked_at = now() WHERE id=%s AND revoked_at IS NULL RETURNING id", (token_id,)).fetchone()
        conn.commit()
        return row is not None

    def token_principal(self, conn, raw: str) -> Principal | None:
        if not raw.startswith(self.token_prefix):
            return None
        row = conn.execute("UPDATE api_token SET last_used_at = now() WHERE token_hash=%s AND revoked_at IS NULL RETURNING id, scope, name",
                           (sha256(raw),)).fetchone()
        conn.commit()
        if not row:
            return None
        scopes = frozenset({row["scope"]})
        return Principal("token", f"token:{row['id']}", self.app.permissions_for(scopes=scopes), scopes=scopes, name=row["name"],
                         ident=row["id"], source="local")
