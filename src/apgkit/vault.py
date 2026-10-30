"""Envelope encryption for secrets stored in the database (provider keys, webhook secrets...).

A random 32-byte *data key* encrypts every stored secret (Fernet: AES-128-CBC + HMAC-SHA256). The data key is never stored
in the clear. It is stored *wrapped* (encrypted) under a key derived from the admin password with scrypt, and optionally
under a key derived from a platform-managed secret (`<PREFIX>_ENCRYPTION_KEY` or `/etc/<prefix>/encryption_key`).

Each wrap stores its own KDF parameters (`vault_kdf_pw`, `vault_kdf_env`: `scrypt$<log2 N>$<r>$<p>`). A wrap with no stored
parameters is a legacy wrap (N=2^15). New wraps use the current parameters (OWASP's first scrypt choice: N=2^17, r=8, p=1);
a legacy wrap is upgraded the next time its secret is presented (password sign-in, or the platform-secret unlock at start).

Consequences, by design: the database alone is useless to an attacker; after a restart the vault is LOCKED until the admin
signs in (or the platform secret unlocks it at startup); the unwrapped key lives only in this process's memory.
The storage keys and key-derivation parameters are the ones the apps used before the kit, so existing vaults keep working.
"""
import base64
import hashlib
import hmac
import secrets
import threading
from collections.abc import Callable

import psycopg
from cryptography.fernet import Fernet, InvalidToken

from . import settings_store as store
from .config import read_secret

_K_SALT, _K_PW, _K_ENV_SALT, _K_ENV = "vault_salt", "vault_wrap_pw", "vault_env_salt", "vault_wrap_env"
_K_KDF_PW, _K_KDF_ENV = "vault_kdf_pw", "vault_kdf_env"

# (log2 N, r, p). scrypt memory is 128 * N * r bytes: 128 MiB for the current parameters. MAXMEM leaves headroom for it and is
# the same for every derivation, so a wrap can always be opened with the parameters it was written with.
KDF_CURRENT = (17, 8, 1)
KDF_LEGACY = (15, 8, 1)                    # wraps written before parameters were stored
_MAXMEM = 256 * 1024 * 1024
_MAX_COST = 2**20                          # cap on N * r accepted from storage (= 128 MiB): a damaged row cannot demand more
_MAX_P = 16


class VaultError(RuntimeError):
    """A failure whose message is safe to show to users."""


class VaultLocked(VaultError):
    pass


def _kdf(secret: str, salt: bytes, params: tuple[int, int, int] = KDF_CURRENT) -> Fernet:
    log_n, r, p = params
    raw = hashlib.scrypt(secret.encode(), salt=salt, n=2**log_n, r=r, p=p, maxmem=_MAXMEM, dklen=32)
    return Fernet(base64.urlsafe_b64encode(raw))


def _format_params(params: tuple[int, int, int]) -> str:
    return "scrypt${}${}${}".format(*params)


def _parse_params(text: str | None) -> tuple[int, int, int] | None:
    """The stored parameters; KDF_LEGACY when none are stored; None when they are damaged or out of bounds."""
    if text is None:
        return KDF_LEGACY
    try:
        scheme, log_n, r, p = text.split("$")
        log_n, r, p = int(log_n), int(r), int(p)
    except ValueError:
        return None
    if scheme != "scrypt" or not (10 <= log_n <= 20 and 1 <= r <= 16 and 1 <= p <= _MAX_P) or (2**log_n) * r > _MAX_COST:
        return None
    return log_n, r, p


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _decrypt_with(fernet: Fernet, token: str) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise VaultError("A stored secret could not be decrypted. Re-enter it.") from exc


class Vault:
    def __init__(self, env_prefix: str):
        self.env_prefix = env_prefix.upper()
        self._lock = threading.Lock()
        self._data_key: bytes | None = None
        self._env_ok: bool | None = None     # did the current platform secret open the stored wrap? None = not tried yet
        self._rot = threading.RLock()        # held while the data key is replaced: encrypt/decrypt wait for it
        self._stores: dict[str, tuple[str, str]] = {}

    def _env_secret(self) -> str:
        return read_secret(f"{self.env_prefix}_ENCRYPTION_KEY", f"/etc/{self.env_prefix.lower()}/encryption_key")

    def _wrap(self, conn, secret: str, salt_key: str, wrap_key: str, kdf_key: str, data_key: bytes) -> None:
        """Write salt, parameters and wrap together (one transaction or savepoint: never a mix of old and new)."""
        salt = secrets.token_bytes(16)
        wrapped = _kdf(secret, salt, KDF_CURRENT).encrypt(data_key).decode()
        with conn.transaction():
            store.put(conn, salt_key, _b64(salt))
            store.put(conn, kdf_key, _format_params(KDF_CURRENT))
            store.put(conn, wrap_key, wrapped)

    def _unwrap(self, conn, secret: str, salt_key: str, wrap_key: str, kdf_key: str) -> bytes | None:
        salt, wrapped = store.get(conn, salt_key), store.get(conn, wrap_key)
        params = _parse_params(store.get(conn, kdf_key))
        if not salt or not wrapped or params is None:
            return None
        try:
            return _kdf(secret, base64.b64decode(salt), params).decrypt(wrapped.encode())
        except (InvalidToken, ValueError):      # wrong secret, or a damaged wrap: fail closed
            return None

    def _is_current(self, conn, kdf_key: str) -> bool:
        return _parse_params(store.get(conn, kdf_key)) == KDF_CURRENT

    def is_initialized(self, conn) -> bool:
        return store.get(conn, _K_PW) is not None or store.get(conn, _K_ENV) is not None

    def is_unlocked(self) -> bool:
        return self._data_key is not None

    def lock(self) -> None:
        with self._lock:
            self._data_key = None

    def status(self, conn) -> dict:
        """`auto_unlock` is True when a platform secret is set and a wrap for it is stored (the platform is expected to open the vault; when it cannot, `reason` is `platform_key_mismatch`). `reason` says why a
        locked vault is locked (None when unlocked): `not_initialized`, `no_platform_key`, `no_platform_wrap` or
        `platform_key_mismatch` (the key changed: unlock once with the admin password to re-wrap)."""
        env, wrapped = bool(self._env_secret()), store.get(conn, _K_ENV) is not None
        reason = None
        if not self.is_unlocked():
            reason = ("not_initialized" if not self.is_initialized(conn) else "no_platform_key" if not env
                      else "no_platform_wrap" if not wrapped else "platform_key_mismatch" if self._env_ok is False
                      else "locked")
        return {"initialized": self.is_initialized(conn), "unlocked": self.is_unlocked(),
                "auto_unlock": env and wrapped, "reason": reason}

    def initialize(self, conn, password: str) -> None:
        """Create the data key, wrapped under the password (and the platform secret, if configured). Unlocks."""
        data_key = secrets.token_bytes(32)
        self._wrap(conn, password, _K_SALT, _K_PW, _K_KDF_PW, data_key)
        env = self._env_secret()
        if env:
            self._wrap(conn, env, _K_ENV_SALT, _K_ENV, _K_KDF_ENV, data_key)
            self._env_ok = True
        with self._lock:
            self._data_key = data_key

    def initialize_with_platform_secret(self, conn) -> bool:
        """For deployments with no local admin password (single sign-on only): create the data key wrapped under the platform
        secret alone. Returns False if there is no platform secret or the vault already exists. Unlocks."""
        env = self._env_secret()
        if not env or self.is_initialized(conn):
            return False
        data_key = secrets.token_bytes(32)
        self._wrap(conn, env, _K_ENV_SALT, _K_ENV, _K_KDF_ENV, data_key)
        with self._lock:
            self._data_key = data_key
        self._env_ok = True
        return True

    def unlock_with_password(self, conn, password: str) -> bool:
        key = self._unwrap(conn, password, _K_SALT, _K_PW, _K_KDF_PW)
        if key is None:
            return False
        with self._lock:
            self._data_key = key
        if not self._is_current(conn, _K_KDF_PW):          # a wrap with older parameters: upgrade it now that the password is in hand
            try:
                self._wrap(conn, password, _K_SALT, _K_PW, _K_KDF_PW, key)
            except Exception:                              # the old wrap still works; try again at the next sign-in
                pass
        self._sync_platform_wrap(conn, key)
        return True

    def _sync_platform_wrap(self, conn, key: bytes) -> None:
        """Keep the platform-secret wrap current: add it if missing, replace it if the secret changed (the caller has proven
        it holds the data key by unlocking with the password). Never raises: the password unlock has already succeeded."""
        env = self._env_secret()
        if not env:
            return
        try:
            current = self._unwrap(conn, env, _K_ENV_SALT, _K_ENV, _K_KDF_ENV)
            if current is None or not hmac.compare_digest(current, key) or not self._is_current(conn, _K_KDF_ENV):
                self._wrap(conn, env, _K_ENV_SALT, _K_ENV, _K_KDF_ENV, key)
            self._env_ok = True
        except Exception:                                  # a failed re-wrap leaves the old wrap; the password still works
            self._env_ok = False

    def try_unlock_with_platform_secret(self, conn) -> bool:
        env = self._env_secret()
        if not env:
            return False
        key = self._unwrap(conn, env, _K_ENV_SALT, _K_ENV, _K_KDF_ENV)
        self._env_ok = key is not None
        if key is None:
            return False                                   # fail closed: stay locked, status() says why
        with self._lock:
            self._data_key = key
        if not self._is_current(conn, _K_KDF_ENV):         # upgrade a legacy wrap (the secret is in hand); best effort, committed here
            try:
                self._wrap(conn, env, _K_ENV_SALT, _K_ENV, _K_KDF_ENV, key)
                conn.commit()
            except Exception:
                conn.rollback()
        return True

    def change_password(self, conn, new_password: str) -> None:
        """Re-wrap the data key under a new password. Requires the vault to be unlocked."""
        if self._data_key is None:
            raise VaultLocked("unlock the vault first")
        self._wrap(conn, new_password, _K_SALT, _K_PW, _K_KDF_PW, self._data_key)

    def reset(self, conn) -> None:
        """Forget the data key and all wraps. Anything encrypted with it becomes unreadable (callers must delete it)."""
        self.lock()
        store.delete(conn, _K_SALT, _K_PW, _K_ENV_SALT, _K_ENV, _K_KDF_PW, _K_KDF_ENV)

    def _fernet(self) -> Fernet:
        if self._data_key is None:
            raise VaultLocked("Stored secrets are locked. Sign in with your admin password to unlock them.")
        return Fernet(base64.urlsafe_b64encode(self._data_key))

    def encrypt(self, plaintext: str) -> str:
        with self._rot:
            return self._fernet().encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        with self._rot:
            return _decrypt_with(self._fernet(), token)

    # ---- rotation -----------------------------------------------------------------------------------------------
    def drop_platform_wrap(self, conn) -> None:
        """Delete the platform-secret wrap: the vault then needs the admin password after every restart (see
        docs/GUIDE.md, "Admin-password-only mode"). Refuses when there is no password wrap (that would lose the vault)."""
        if store.get(conn, _K_PW) is None:
            raise VaultError("there is no admin-password wrap: dropping the platform wrap would make the vault unrecoverable")
        with conn.transaction():
            store.delete(conn, _K_ENV_SALT, _K_ENV, _K_KDF_ENV)
        self._env_ok = None

    def rotate_platform_secret(self, conn, new_secret: str) -> None:
        """Re-wrap the SAME data key under `new_secret` (the new value of `<PREFIX>_ENCRYPTION_KEY`). Requires the vault unlocked.

        NOT sufficient after the old platform secret or a database copy has been exposed: whoever holds a copy of the old wrap row
        and the old secret still recovers the data key, hence every ciphertext copied at that time. Use `rotate_data_key` for that.
        Set the new secret in the platform's environment as well, or the next restart finds a wrap it cannot open."""
        if self._data_key is None:
            raise VaultLocked("unlock the vault first")
        if not new_secret:
            raise VaultError("the new platform secret is empty")
        self._wrap(conn, new_secret, _K_ENV_SALT, _K_ENV, _K_KDF_ENV, self._data_key)
        self._env_ok = None

    def register_store(self, name: str, select_sql: str, update_sql: str) -> None:
        """Declare a place where this vault's ciphertexts are stored, so `rotate_data_key` can re-encrypt it.

        `select_sql` returns one row per ciphertext, with the ciphertext in a column named `value` and whatever other columns
        identify the row (for example `SELECT id, api_key_enc AS value FROM provider WHERE api_key_enc IS NOT NULL`).
        `update_sql` writes it back, using named parameters: `%(value)s` for the new ciphertext and `%(<column>)s` for each other
        selected column (for example `UPDATE provider SET api_key_enc = %(value)s WHERE id = %(id)s`).
        Rows whose `value` is NULL or empty are skipped. Registering the same name again replaces it."""
        self._stores[name] = (select_sql, update_sql)

    def stores(self) -> dict[str, dict[str, str]]:
        """The registered stores: name -> {"select": ..., "update": ...} (what the vault encrypts, for audits and tests)."""
        return {n: {"select": s, "update": u} for n, (s, u) in self._stores.items()}

    def _reencrypt_registered(self, conn, old_decrypt: Callable[[str], str], new_encrypt: Callable[[str], str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for name, (select_sql, update_sql) in self._stores.items():
            n = 0
            for row in conn.execute(select_sql).fetchall():
                if not row["value"]:
                    continue
                conn.execute(update_sql, {**row, "value": new_encrypt(old_decrypt(row["value"]))})
                n += 1
            counts[name] = n
        return counts

    def rotate_data_key(self, conn, reencrypt: Callable[[Callable[[str], str], Callable[[str], str]], object] | None = None, *,
                        password: str | None = None) -> dict[str, int]:
        """Replace the data key. Requires the vault unlocked. Returns the rows re-encrypted per registered store.

        `reencrypt(old_decrypt, new_encrypt)` is called once, on `conn`, inside the rotation's transaction, and must re-encrypt EVERY
        stored ciphertext (read with `old_decrypt`, write `new_encrypt(plaintext)`), using `conn` for its writes. When it is None
        the stores declared with `register_store` are re-encrypted. If both exist (register_store AND a callback) the registered
        stores run first, then the callback. A value that cannot be decrypted aborts the rotation (decide in the callback: skip or null it).

        Transaction boundary: the re-encrypted rows, the new password wrap and the new platform wrap are written in ONE transaction
        that this method commits. A crash, an exception or a lost connection before the commit leaves the old key, the old rows and
        the old wraps untouched; after the commit everything is new. The in-memory key is replaced only after the commit. `conn` must
        be idle (no open transaction: commit or roll back first), because the commit is what makes the rotation atomic.
        If the commit's outcome is unknown (connection lost at commit) the vault locks itself; unlock again to get the key that won.

        `password` is the admin password: required when a password wrap exists, because the wrap is rewritten (it is checked first).
        The platform wrap is rewritten under the current `<PREFIX>_ENCRYPTION_KEY` when one is set; if none is set, a stored
        platform wrap is deleted (it would still open the OLD key). Other processes of the same app keep the old key in memory
        and fail to decrypt until they are restarted or unlocked again: restart them, and stop writers during the rotation
        (`LOCK TABLE ... IN SHARE ROW EXCLUSIVE MODE` inside the callback for the tables it rewrites).
        Old database backups still decrypt with the old key: after exposure they stay exposed; only the secrets themselves can be re-issued."""
        if self._data_key is None:
            raise VaultLocked("unlock the vault first")
        if conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
            raise VaultError("rotate_data_key needs a connection with no open transaction (commit or roll back first)")
        if reencrypt is None and not self._stores:
            raise VaultError("nothing to re-encrypt: pass a callback or register stores")
        with self._rot:
            old_key = self._data_key
            try:
                has_pw = store.get(conn, _K_PW) is not None
                if has_pw:
                    if password is None:
                        raise VaultError("the admin password is required to rotate the data key")
                    current = self._unwrap(conn, password, _K_SALT, _K_PW, _K_KDF_PW)
                    if current is None or not hmac.compare_digest(current, old_key):
                        raise VaultError("the admin password is incorrect")
                elif not self._env_secret():
                    raise VaultError("no wrap would exist for the new key (no admin password wrap and no platform secret)")
            finally:
                conn.rollback()                  # the checks above only read; end that transaction so the rotation's own commits for real
            new_key = secrets.token_bytes(32)
            old_f, new_f = Fernet(base64.urlsafe_b64encode(old_key)), Fernet(base64.urlsafe_b64encode(new_key))
            old_decrypt = lambda t: _decrypt_with(old_f, t)                                # noqa: E731
            new_encrypt = lambda t: new_f.encrypt(t.encode()).decode()                     # noqa: E731
            env = self._env_secret()
            try:
                with conn.transaction():
                    counts = self._reencrypt_registered(conn, old_decrypt, new_encrypt) if self._stores else {}
                    if reencrypt is not None:
                        reencrypt(old_decrypt, new_encrypt)
                    if has_pw:
                        self._wrap(conn, password, _K_SALT, _K_PW, _K_KDF_PW, new_key)
                    if env:
                        self._wrap(conn, env, _K_ENV_SALT, _K_ENV, _K_KDF_ENV, new_key)
                    else:
                        store.delete(conn, _K_ENV_SALT, _K_ENV, _K_KDF_ENV)
            except psycopg.OperationalError:
                with self._lock:
                    self._data_key = None                  # outcome unknown: fail closed, unlock reads whichever key is stored
                raise
            with self._lock:
                self._data_key = new_key
            self._env_ok = True if env else None
            return counts
