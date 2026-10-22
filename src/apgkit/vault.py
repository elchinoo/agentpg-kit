"""Envelope encryption for secrets stored in the database (provider keys, webhook secrets...).

A random 32-byte *data key* encrypts every stored secret (Fernet: AES-128-CBC + HMAC-SHA256). The data key is never stored
in the clear. It is stored *wrapped* (encrypted) under a key derived from the admin password with scrypt, and optionally
under a key derived from a platform-managed secret (`<PREFIX>_ENCRYPTION_KEY` or `/etc/<prefix>/encryption_key`).

Consequences, by design: the database alone is useless to an attacker; after a restart the vault is LOCKED until the admin
signs in (or the platform secret unlocks it at startup); the unwrapped key lives only in this process's memory.
The storage keys and key-derivation parameters are the ones the apps used before the kit, so existing vaults keep working.
"""
import base64
import hashlib
import secrets
import threading

from cryptography.fernet import Fernet, InvalidToken

from . import settings_store as store
from .config import read_secret

_K_SALT, _K_PW, _K_ENV_SALT, _K_ENV = "vault_salt", "vault_wrap_pw", "vault_env_salt", "vault_wrap_env"


class VaultError(RuntimeError):
    """A failure whose message is safe to show to users."""


class VaultLocked(VaultError):
    pass


def _kdf(secret: str, salt: bytes) -> Fernet:
    raw = hashlib.scrypt(secret.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=32)
    return Fernet(base64.urlsafe_b64encode(raw))


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class Vault:
    def __init__(self, env_prefix: str):
        self.env_prefix = env_prefix.upper()
        self._lock = threading.Lock()
        self._data_key: bytes | None = None

    def _env_secret(self) -> str:
        return read_secret(f"{self.env_prefix}_ENCRYPTION_KEY", f"/etc/{self.env_prefix.lower()}/encryption_key")

    def _wrap(self, conn, secret: str, salt_key: str, wrap_key: str, data_key: bytes) -> None:
        salt = secrets.token_bytes(16)
        store.put(conn, salt_key, _b64(salt))
        store.put(conn, wrap_key, _kdf(secret, salt).encrypt(data_key).decode())

    def _unwrap(self, conn, secret: str, salt_key: str, wrap_key: str) -> bytes | None:
        salt, wrapped = store.get(conn, salt_key), store.get(conn, wrap_key)
        if not salt or not wrapped:
            return None
        try:
            return _kdf(secret, base64.b64decode(salt)).decrypt(wrapped.encode())
        except InvalidToken:
            return None

    def is_initialized(self, conn) -> bool:
        return store.get(conn, _K_PW) is not None or store.get(conn, _K_ENV) is not None

    def is_unlocked(self) -> bool:
        return self._data_key is not None

    def lock(self) -> None:
        with self._lock:
            self._data_key = None

    def status(self, conn) -> dict:
        return {"initialized": self.is_initialized(conn), "unlocked": self.is_unlocked(),
                "auto_unlock": bool(self._env_secret()) and store.get(conn, _K_ENV) is not None}

    def initialize(self, conn, password: str) -> None:
        """Create the data key, wrapped under the password (and the platform secret, if configured). Unlocks."""
        data_key = secrets.token_bytes(32)
        self._wrap(conn, password, _K_SALT, _K_PW, data_key)
        env = self._env_secret()
        if env:
            self._wrap(conn, env, _K_ENV_SALT, _K_ENV, data_key)
        with self._lock:
            self._data_key = data_key

    def initialize_with_platform_secret(self, conn) -> bool:
        """For deployments with no local admin password (single sign-on only): create the data key wrapped under the platform
        secret alone. Returns False if there is no platform secret or the vault already exists. Unlocks."""
        env = self._env_secret()
        if not env or self.is_initialized(conn):
            return False
        data_key = secrets.token_bytes(32)
        self._wrap(conn, env, _K_ENV_SALT, _K_ENV, data_key)
        with self._lock:
            self._data_key = data_key
        return True

    def unlock_with_password(self, conn, password: str) -> bool:
        key = self._unwrap(conn, password, _K_SALT, _K_PW)
        if key is None:
            return False
        with self._lock:
            self._data_key = key
        env = self._env_secret()
        if env and store.get(conn, _K_ENV) is None:      # a platform secret was added later: wrap it for auto-unlock
            self._wrap(conn, env, _K_ENV_SALT, _K_ENV, key)
        return True

    def try_unlock_with_platform_secret(self, conn) -> bool:
        env = self._env_secret()
        if not env:
            return False
        key = self._unwrap(conn, env, _K_ENV_SALT, _K_ENV)
        if key is None:
            return False
        with self._lock:
            self._data_key = key
        return True

    def change_password(self, conn, new_password: str) -> None:
        """Re-wrap the data key under a new password. Requires the vault to be unlocked."""
        if self._data_key is None:
            raise VaultLocked("unlock the vault first")
        self._wrap(conn, new_password, _K_SALT, _K_PW, self._data_key)

    def reset(self, conn) -> None:
        """Forget the data key and all wraps. Anything encrypted with it becomes unreadable (callers must delete it)."""
        self.lock()
        store.delete(conn, _K_SALT, _K_PW, _K_ENV_SALT, _K_ENV)

    def _fernet(self) -> Fernet:
        if self._data_key is None:
            raise VaultLocked("Stored secrets are locked. Sign in with your admin password to unlock them.")
        return Fernet(base64.urlsafe_b64encode(self._data_key))

    def encrypt(self, plaintext: str) -> str:
        return self._fernet().encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet().decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise VaultError("A stored secret could not be decrypted. Re-enter it.") from exc
