"""Envelope encryption for secrets stored in the database (provider keys, webhook secrets...).

A random 32-byte *data key* encrypts every stored secret. The data key is never stored in the clear. It is stored *wrapped*
(encrypted) under a key derived from the admin password with scrypt, and optionally under a key derived from a platform-managed
secret (`<PREFIX>_ENCRYPTION_KEY` or `/etc/<prefix>/encryption_key`).

Ciphertext format (new ciphertexts): `v2$<key id>$<base64url(nonce + AES-256-GCM ciphertext)>`. The AES key is an HKDF-SHA256
subkey of the data key (info `apgkit/vault/secret`), the key id is a short non-secret fingerprint (HKDF info `apgkit/vault/kid`),
and the associated data binds the ciphertext to the key id and to a caller-supplied *context* string, so a ciphertext copied to
another row or column does not decrypt. Wraps use a separate subkey (info `apgkit/vault/wrap`) and are bound to their slot.
Legacy Fernet tokens (AES-128-CBC + HMAC, no context) are still read and upgraded by `rotate_data_key` / `reencrypt_legacy`.

Platform-secret wraps use HKDF-SHA256 when the secret is long and random (`is_high_entropy`), scrypt otherwise (human passwords).

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
import re
import secrets
import threading
from collections.abc import Callable

import psycopg
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import passwords
from . import settings_store as store
from .config import read_secret

_K_SALT, _K_PW, _K_ENV_SALT, _K_ENV = "vault_salt", "vault_wrap_pw", "vault_env_salt", "vault_wrap_env"
_K_KDF_PW, _K_KDF_ENV = "vault_kdf_pw", "vault_kdf_env"

# (log2 N, r, p). scrypt memory is 128 * N * r bytes: 128 MiB for the current parameters. MAXMEM leaves headroom for it and is
# the same for every derivation, so a wrap can always be opened with the parameters it was written with.
KDF_CURRENT = (17, 8, 1)
KDF_LEGACY = (15, 8, 1)                    # wraps written before parameters were stored
_MAX_COST = 2**20                          # cap on N * r accepted from storage (= 128 MiB): a damaged row cannot demand more
_MAX_P = 16
KDF_HKDF = "hkdf$sha256"                   # stored in vault_kdf_env for a platform secret that is long and random

V2 = "v2"
_INFO_SECRET, _INFO_WRAP, _INFO_KID, _INFO_KEK = (b"apgkit/vault/secret", b"apgkit/vault/wrap", b"apgkit/vault/kid", b"apgkit/vault/kek")
_INFO_APP = b"apgkit/vault/app/"


class VaultError(RuntimeError):
    """A failure whose message is safe to show to users."""


class VaultLocked(VaultError):
    pass


def _kdf(secret: str, salt: bytes, params: tuple[int, int, int] = KDF_CURRENT) -> Fernet:
    """The legacy construction (scrypt output used directly as a Fernet key); kept to read wraps written before v2."""
    log_n, r, p = params
    raw = passwords.scrypt(secret.encode(), salt=salt, n=2**log_n, r=r, p=p)
    return Fernet(base64.urlsafe_b64encode(raw))


def _format_params(params: tuple[int, int, int]) -> str:
    return "scrypt${}${}${}".format(*params)


def _parse_params(text: str | None) -> tuple[int, int, int] | None:
    """The stored scrypt parameters; KDF_LEGACY when none are stored; None when they are damaged, out of bounds or not scrypt."""
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


_URLSAFE_RE = re.compile(r"[A-Za-z0-9_-]{43,}={0,2}")


def is_high_entropy(secret: str) -> bool:
    """True when `secret` looks like a machine-generated key, for which a slow KDF adds nothing. A secret that decodes (base64,
    url-safe base64 or hex) must give at least 32 bytes with at least 16 distinct byte values (32 random bytes have about 28; a
    repeated or low-variety passphrase fails). A secret that does not decode keeps the length rule (at least 43 url-safe
    characters, which carry 256 bits) and needs at least 16 distinct characters. Anything else is a human password: scrypt."""
    try:
        raw = bytes.fromhex(secret)                    # hex first: its characters are also valid base64, which would decode to noise
    except ValueError:
        pass
    else:
        return len(raw) >= 32 and len(set(raw)) >= 16
    for decode in (lambda t: base64.b64decode(t, validate=True), lambda t: base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))):
        try:
            raw = decode(secret)
        except ValueError:
            continue
        return len(raw) >= 32 and len(set(raw)) >= 16
    return bool(_URLSAFE_RE.fullmatch(secret)) and len(set(secret)) >= 16


def _hkdf(key: bytes, info: bytes, salt: bytes | None = None, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(key)


def _kek(secret: str, salt: bytes, kdf: str | None) -> bytes:
    """Key-encryption key from a secret under the named KDF (scrypt parameters or `hkdf$sha256`)."""
    if kdf == KDF_HKDF:
        return _hkdf(secret.encode(), _INFO_KEK, salt)
    params = _parse_params(kdf)
    if params is None:
        raise ValueError("bad kdf")
    log_n, r, p = params
    return passwords.scrypt(secret.encode(), salt=salt, n=2**log_n, r=r, p=p)


def _wrap_aad(slot: str) -> bytes:
    return b"apgkit/vault/wrap-v2\x00" + slot.encode()


def _key_id(data_key: bytes) -> str:
    return _hkdf(data_key, _INFO_KID, length=6).hex()


def _aad(kid: str, context: str) -> bytes:
    return b"apgkit/vault/v2\x00" + kid.encode() + b"\x00" + context.encode()


def _seal(data_key: bytes, plaintext: str, context: str = "") -> str:
    kid, nonce = _key_id(data_key), secrets.token_bytes(12)
    ct = AESGCM(_hkdf(data_key, _INFO_SECRET)).encrypt(nonce, plaintext.encode(), _aad(kid, context))
    return f"{V2}${kid}${base64.urlsafe_b64encode(nonce + ct).decode().rstrip('=')}"


def _open(data_key: bytes, token: str, context: str = "") -> str:
    """Decrypt a v2 token (bound to `context`) or a legacy Fernet token (context is not part of those)."""
    try:
        if token.startswith(V2 + "$"):
            _v, kid, blob = token.split("$")
            if kid != _key_id(data_key):
                raise VaultError("A stored secret was encrypted under a different key. Re-enter it.")
            raw = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
            return AESGCM(_hkdf(data_key, _INFO_SECRET)).decrypt(raw[:12], raw[12:], _aad(kid, context)).decode()
        return Fernet(base64.urlsafe_b64encode(data_key)).decrypt(token.encode()).decode()
    except (InvalidToken, InvalidTag, ValueError, UnicodeError) as exc:
        raise VaultError("A stored secret could not be decrypted. Re-enter it.") from exc


def is_legacy_token(token: str) -> bool:
    """True for a token in the legacy (Fernet) format."""
    return not token.startswith(V2 + "$")


def _wrap_key_bytes(kek: bytes) -> bytes:
    return _hkdf(kek, _INFO_WRAP)


def _seal_wrap(kek: bytes, data_key: bytes, slot: str) -> str:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_wrap_key_bytes(kek)).encrypt(nonce, data_key, _wrap_aad(slot))
    return f"{V2}$wrap${base64.urlsafe_b64encode(nonce + ct).decode().rstrip('=')}"


def _open_wrap(kek: bytes, wrapped: str, slot: str) -> bytes:
    """The data key from a wrap: v2 (AES-256-GCM, slot-bound) or legacy Fernet under the scrypt output. Raises on any failure."""
    if wrapped.startswith(V2 + "$"):
        blob = wrapped.split("$")[2]
        raw = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
        try:
            return AESGCM(_wrap_key_bytes(kek)).decrypt(raw[:12], raw[12:], _wrap_aad(slot))
        except InvalidTag as exc:
            raise ValueError("wrap does not open") from exc
    try:
        return Fernet(base64.urlsafe_b64encode(kek)).decrypt(wrapped.encode())
    except InvalidToken as exc:
        raise ValueError("wrap does not open") from exc


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class Vault:
    def __init__(self, env_prefix: str):
        self.env_prefix = env_prefix.upper()
        self._lock = threading.Lock()
        self._data_key: bytes | None = None
        self._env_proved: bytes | None = None   # digest of the platform secret that opened (or wrote) the stored wrap in this process
        self._env_ok: bool | None = None     # did the current platform secret open the stored wrap? None = not tried yet
        self._rot = threading.RLock()        # held while the data key is replaced: encrypt/decrypt wait for it
        self._stores: dict[str, tuple[str, str]] = {}

    def _mark_env(self, env: str | None) -> None:
        self._env_ok = True if env else None
        self._env_proved = hashlib.sha256(env.encode()).digest() if env else None

    def _env_secret(self) -> str:
        return read_secret(f"{self.env_prefix}_ENCRYPTION_KEY", f"/etc/{self.env_prefix.lower()}/encryption_key")

    def _env_kdf(self, secret: str) -> str:
        """The KDF for a platform-secret wrap: HKDF for a long random secret, scrypt for anything a human might have typed."""
        return KDF_HKDF if is_high_entropy(secret) else _format_params(KDF_CURRENT)

    def _wrap(self, conn, secret: str, salt_key: str, wrap_key: str, kdf_key: str, data_key: bytes) -> None:
        """Write salt, KDF name and wrap together (one transaction or savepoint: never a mix of old and new)."""
        salt = secrets.token_bytes(16)
        kdf = self._env_kdf(secret) if kdf_key == _K_KDF_ENV else _format_params(KDF_CURRENT)
        wrapped = _seal_wrap(_kek(secret, salt, kdf), data_key, wrap_key)
        with conn.transaction():
            store.put(conn, salt_key, _b64(salt))
            store.put(conn, kdf_key, kdf)
            store.put(conn, wrap_key, wrapped)

    def _unwrap(self, conn, secret: str, salt_key: str, wrap_key: str, kdf_key: str) -> bytes | None:
        salt, wrapped, kdf = store.get(conn, salt_key), store.get(conn, wrap_key), store.get(conn, kdf_key)
        if not salt or not wrapped:
            return None
        if kdf is None:
            kdf = _format_params(KDF_LEGACY)                     # no stored name: a wrap written before parameters were stored
        elif kdf != KDF_HKDF and _parse_params(kdf) is None:
            return None
        try:
            return _open_wrap(_kek(secret, base64.b64decode(salt), kdf), wrapped, wrap_key)
        except (ValueError, TypeError):      # wrong secret, or a damaged wrap: fail closed
            return None

    def _is_current(self, conn, kdf_key: str, secret: str | None = None) -> bool:
        """True when the stored wrap already has the KDF this secret would get now and the v2 wrap format."""
        want = self._env_kdf(secret) if kdf_key == _K_KDF_ENV and secret else _format_params(KDF_CURRENT)
        wrap_key = _K_ENV if kdf_key == _K_KDF_ENV else _K_PW
        return store.get(conn, kdf_key) == want and (store.get(conn, wrap_key) or "").startswith(V2 + "$")

    def has_password_wrap(self, conn) -> bool:
        return store.get(conn, _K_PW) is not None

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
            self._mark_env(env)
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
        self._mark_env(env)
        return True

    def unlock_with_password(self, conn, password: str) -> bool:
        key = self._unwrap(conn, password, _K_SALT, _K_PW, _K_KDF_PW)
        if key is None:
            return False
        with self._lock:
            self._data_key = key
        if not self._is_current(conn, _K_KDF_PW):          # a wrap with older parameters or the legacy format: upgrade it now that the password is in hand
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
            if self._env_proved == hashlib.sha256(env.encode()).digest() and self._is_current(conn, _K_KDF_ENV, env):
                return                       # this process already opened the stored wrap with this secret: no derivation needed
            current = self._unwrap(conn, env, _K_ENV_SALT, _K_ENV, _K_KDF_ENV)
            if current is None or not hmac.compare_digest(current, key) or not self._is_current(conn, _K_KDF_ENV, env):
                self._wrap(conn, env, _K_ENV_SALT, _K_ENV, _K_KDF_ENV, key)
            self._mark_env(env)
        except Exception:                                  # a failed re-wrap leaves the old wrap; the password still works
            self._env_ok, self._env_proved = False, None

    def try_unlock_with_platform_secret(self, conn) -> bool:
        env = self._env_secret()
        if not env:
            return False
        key = self._unwrap(conn, env, _K_ENV_SALT, _K_ENV, _K_KDF_ENV)
        self._env_ok = key is not None
        self._env_proved = hashlib.sha256(env.encode()).digest() if key is not None else None
        if key is None:
            return False                                   # fail closed: stay locked, status() says why
        with self._lock:
            self._data_key = key
        if not self._is_current(conn, _K_KDF_ENV, env):    # upgrade a legacy wrap (older parameters, scrypt for a random key, Fernet format) (the secret is in hand); best effort, committed here
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

    def _key(self) -> bytes:
        if self._data_key is None:
            raise VaultLocked("Stored secrets are locked. Sign in with your admin password to unlock them.")
        return self._data_key

    def encrypt(self, plaintext: str, context: str = "") -> str:
        """Encrypt under the data key (AES-256-GCM, `v2$...`). `context` is a stable string the app chooses for where the value
        lives (for example `provider.api_key_enc:<id>`): decrypt must be given the same string, so a ciphertext copied to another
        row or column does not open. An empty context still works but binds nothing: use a context for every new call site."""
        with self._rot:
            return _seal(self._key(), plaintext, context)

    def decrypt(self, token: str, context: str = "") -> str:
        """Decrypt a v2 token (the context must match) or a legacy Fernet token (which never carried a context)."""
        with self._rot:
            return _open(self._key(), token, context)

    @staticmethod
    def is_legacy(token: str) -> bool:
        return is_legacy_token(token)

    def reencrypt_legacy(self, token: str, context: str = "", *, old_decrypt: Callable[..., str] | None = None,
                         new_encrypt: Callable[..., str] | None = None) -> str:
        """Return `token` as a v2 token bound to `context`.

        Alone (no functions): a legacy token is decrypted and re-encrypted under the current key; a v2 token is returned unchanged
        (so it can be run over every row to migrate, repeatedly). Inside a `rotate_data_key` callback pass the callback's
        `old_decrypt` and `new_encrypt`: the token is then ALWAYS decrypted with the old key and encrypted with the new one,
        whatever its format, which is what the rotation needs:
            vault.rotate_data_key(conn, lambda od, ne: [... vault.reencrypt_legacy(t, ctx, old_decrypt=od, new_encrypt=ne) ...])"""
        if old_decrypt is not None and new_encrypt is not None:
            return new_encrypt(old_decrypt(token, context), context)
        if not is_legacy_token(token):
            return token
        return self.encrypt(self.decrypt(token), context)

    def derive_key(self, purpose: str, length: int = 32) -> bytes:
        """A subkey of the data key for the app's own non-encryption uses (for example an HMAC key), separate per `purpose`
        (HKDF-SHA256, info `apgkit/vault/app/<purpose>`). Raises VaultLocked when locked. Changes when the data key is rotated."""
        if not purpose:
            raise ValueError("purpose is required")
        return _hkdf(self._key(), _INFO_APP + purpose.encode(), length=length)

    # ---- rotation -----------------------------------------------------------------------------------------------
    def drop_platform_wrap(self, conn) -> None:
        """Delete the platform-secret wrap: the vault then needs the admin password after every restart (see
        docs/GUIDE.md, "Admin-password-only mode"). Refuses when there is no password wrap (that would lose the vault)."""
        if store.get(conn, _K_PW) is None:
            raise VaultError("there is no admin-password wrap: dropping the platform wrap would make the vault unrecoverable")
        with conn.transaction():
            store.delete(conn, _K_ENV_SALT, _K_ENV, _K_KDF_ENV)
        self._mark_env(None)

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
        self._mark_env(None)

    def register_store(self, name: str, select_sql: str, update_sql: str, context: str | None = None) -> None:
        """Declare a place where this vault's ciphertexts are stored, so `rotate_data_key` can re-encrypt it.

        `select_sql` returns one row per ciphertext, with the ciphertext in a column named `value` and whatever other columns
        identify the row (for example `SELECT id, api_key_enc AS value FROM provider WHERE api_key_enc IS NOT NULL`).
        `update_sql` writes it back, using named parameters: `%(value)s` for the new ciphertext and `%(<column>)s` for each other
        selected column (for example `UPDATE provider SET api_key_enc = %(value)s WHERE id = %(id)s`).
        Rows whose `value` is NULL or empty are skipped. Registering the same name again replaces it.
        `context` is the string the app passes to encrypt/decrypt for this column, as a `str.format` template over the selected
        columns (for example `"provider.api_key_enc:{id}"`); rotation re-encrypts each value bound to its own row's context.
        Leave it None when the app encrypts with an empty context."""
        self._stores[name] = (select_sql, update_sql, context)

    def stores(self) -> dict[str, dict[str, str]]:
        """The registered stores: name -> {"select": ..., "update": ...} (what the vault encrypts, for audits and tests)."""
        return {n: {"select": s, "update": u, "context": c or ""} for n, (s, u, c) in self._stores.items()}

    def _reencrypt_registered(self, conn, old_decrypt: Callable[..., str], new_encrypt: Callable[..., str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for name, (select_sql, update_sql, template) in self._stores.items():
            n = 0
            for row in conn.execute(select_sql).fetchall():
                if not row["value"]:
                    continue
                ctx = template.format(**row) if template else ""
                conn.execute(update_sql, {**row, "value": new_encrypt(old_decrypt(row["value"], ctx), ctx)})
                n += 1
            counts[name] = n
        return counts

    def rotate_data_key(self, conn, reencrypt: Callable[[Callable[..., str], Callable[..., str]], object] | None = None, *,
                        password: str | None = None) -> dict[str, int]:
        """Replace the data key. Requires the vault unlocked. Returns the rows re-encrypted per registered store.

        `reencrypt(old_decrypt, new_encrypt)` is called once (`old_decrypt(token, context="")` opens a v2 or legacy token under the OLD
        key; `new_encrypt(plaintext, context="")` writes a v2 token under the NEW key, so rotation upgrades every legacy Fernet token;
        see `reencrypt_legacy`), on `conn`, inside the rotation's transaction, and must re-encrypt EVERY
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
            old_decrypt = lambda t, context="": _open(old_key, t, context)                 # noqa: E731
            new_encrypt = lambda t, context="": _seal(new_key, t, context)                 # noqa: E731
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
            self._mark_env(env)
            return counts
