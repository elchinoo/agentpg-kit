"""Sealed boot: an app that starts with no secret in its environment, its config files or its image.

The platform holds everything an app is given at start (environment, mounted files, the database it provisions). Anything
readable there is readable by whoever breaches the platform. So the app is deployed with one *sealed blob*: every secret it
needs (database URL, client secrets, API keys...) encrypted with AES-256-GCM under a key derived (scrypt) from an operator
passphrase that is never stored on the platform. The blob is ciphertext: it may sit in the environment or a config file.

Lifecycle: the app starts SEALED and serves nothing but `/_seal/*` and the health check. The operator sends the passphrase
(`ecoctl unseal`), encrypted to an ephemeral X25519 key that exists only in this process, so the platform's TLS-terminating
proxy and its logs see ciphertext. The app opens the blob, keeps the secrets in `Protected` memory, runs the callbacks registered
with `on_unsealed` (connect to the database, unlock the vault, migrate) and starts serving. A restart seals it again.

What this does and does not do. It removes secrets from every place a platform breach reads *at rest* and *in transit*
(environment, files, repository, image, logs, backups, the proxy). It does not stop an attacker who can read this process's
memory while it is unsealed; `Protected` and `harden_process` make that harder (no core dumps, no ptrace by other users, locked
pages, secrets never held as long-lived strings, masked at rest and re-masked) but a root attacker on the host can still win.
A passphrase typed into a compromised proxy that actively impersonates the app (rather than only observing) is also not
prevented: compare `fingerprint` out of band when that matters.
"""
import base64
import ctypes
import ctypes.util
import hmac
import json
import mmap
import os
import secrets
import sys
import threading
import time
import weakref
from collections.abc import Callable
from contextlib import contextmanager

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from . import passwords

SEAL_PREFIX = "apgkit-seal1"
_AAD = b"apgkit/seal/1"
_INFO_UNSEAL = b"apgkit/unseal/1"
_KDF = (17, 8, 1)
MIN_PASSPHRASE = 20
ENVELOPE_MAX_AGE = 120.0
_B64 = lambda b: base64.urlsafe_b64encode(b).decode()  # noqa: E731
_UNB64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731


class SealError(RuntimeError):
    """A failure whose message is safe to show to the caller (it never says which part was wrong)."""


# --- memory protection -----------------------------------------------------------------------------------------------

_libc = None
try:
    _libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
except OSError:                                              # pragma: no cover
    pass


def harden_process() -> dict:
    """Best-effort process hardening; call once at start. Returns what took effect so the app can log it (never raises).

    core dumps off (RLIMIT_CORE 0), the process made non-dumpable (Linux PR_SET_DUMPABLE: other users, including same-uid debuggers,
    cannot ptrace it or read /proc/<pid>/mem) and no privilege gain (PR_SET_NO_NEW_PRIVS); on macOS ptrace(PT_DENY_ATTACH)."""
    report: dict[str, bool] = {}
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        report["core_dumps_off"] = True
    except (ImportError, ValueError, OSError):
        report["core_dumps_off"] = False
    if _libc is not None and sys.platform.startswith("linux"):
        report["non_dumpable"] = _libc.prctl(4, 0, 0, 0, 0) == 0            # PR_SET_DUMPABLE
        report["no_new_privs"] = _libc.prctl(38, 1, 0, 0, 0) == 0           # PR_SET_NO_NEW_PRIVS
    elif _libc is not None and sys.platform == "darwin":
        report["ptrace_denied"] = _libc.ptrace(31, 0, 0, 0) == 0            # PT_DENY_ATTACH
    return report


class _Region:
    """An anonymous page-aligned mapping, locked in RAM (no swap) and excluded from core dumps where the platform allows."""

    def __init__(self, size: int):
        self.size = size
        self.map = mmap.mmap(-1, max(size, 1))
        self.locked = False
        buf = ctypes.c_char.from_buffer(self.map)
        self._addr = ctypes.addressof(buf)
        del buf                                              # an exported buffer would block close()
        if _libc is not None:
            self.locked = _libc.mlock(ctypes.c_void_p(self._addr), ctypes.c_size_t(max(size, 1))) == 0
        if hasattr(mmap, "MADV_DONTDUMP"):
            try:
                self.map.madvise(mmap.MADV_DONTDUMP)
            except OSError:                                  # pragma: no cover
                pass

    def read(self) -> bytes:
        return self.map[: self.size]

    def write(self, data: bytes) -> None:
        self.map[: self.size] = data

    def wipe(self) -> None:
        try:
            ctypes.memset(self._addr, 0, max(self.size, 1))
            if self.locked and _libc is not None:
                _libc.munlock(ctypes.c_void_p(self._addr), ctypes.c_size_t(max(self.size, 1)))
            self.map.close()
        except (ValueError, BufferError):                    # already closed
            pass


_live: "weakref.WeakSet[Protected]" = weakref.WeakSet()
_remask_thread: threading.Thread | None = None
_remask_lock = threading.Lock()


def _remask_loop() -> None:
    while True:
        try:
            interval = max(1.0, float(os.environ.get("APGKIT_REMASK_SECONDS", "15")))
        except ValueError:
            interval = 15.0
        time.sleep(interval)
        for item in list(_live):
            item.remask()


def _ensure_remasker() -> None:
    global _remask_thread
    with _remask_lock:
        if _remask_thread is None:
            _remask_thread = threading.Thread(target=_remask_loop, name="apgkit-remask", daemon=True)
            _remask_thread.start()


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big") if a else b""


class Protected:
    """A secret kept obfuscated in memory: stored as `value XOR pad` in one locked page and `pad` in another, with the pad replaced
    by a fresh random one every few seconds (`APGKIT_REMASK_SECONDS`, default 15). No page holds the value, so `strings`, a stale
    swap page, a partial memory disclosure or a core taken between two re-masks does not show it. It does not stop a debugger on
    the live process: that attacker can read both pages. The value is revealed only inside `with p.reveal() as buf:`, as a bytearray
    that is zeroed on exit. Never printed, pickled, compared with == or turned into a str by accident."""

    def __init__(self, value: "bytes | bytearray | str"):
        data = value.encode() if isinstance(value, str) else bytes(value)
        self._lock = threading.Lock()
        self._n = len(data)
        self._pad, self._masked = _Region(self._n), _Region(self._n)
        pad = os.urandom(self._n)
        self._pad.write(pad)
        self._masked.write(_xor(data, pad))
        self._open = True
        _live.add(self)
        _ensure_remasker()

    def __len__(self) -> int:
        return self._n

    def __repr__(self) -> str:
        return "<Protected ***>"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("a Protected secret cannot be pickled")

    # `==` is identity (never a value comparison); compare a candidate with `matches`, in constant time

    def remask(self) -> None:
        with self._lock:
            if not self._open:
                return
            new_pad = os.urandom(self._n)
            delta = _xor(self._pad.read(), new_pad)          # old pad XOR new pad: random-looking, never the value
            self._masked.write(_xor(self._masked.read(), delta))
            self._pad.write(new_pad)

    @contextmanager
    def reveal(self):
        with self._lock:
            if not self._open:
                raise SealError("secret was wiped")
            pad, masked = self._pad.read(), self._masked.read()
            buf = bytearray(a ^ b for a, b in zip(pad, masked))
        try:
            yield buf
        finally:
            for i in range(len(buf)):
                buf[i] = 0

    def reveal_str(self) -> str:
        """The value as a str, for APIs that only take one (a database URL). The str is immutable and cannot be wiped: keep it for
        the shortest time and never store it."""
        with self.reveal() as buf:
            return buf.decode()

    def matches(self, candidate: "bytes | str") -> bool:
        cand = candidate.encode() if isinstance(candidate, str) else candidate
        with self.reveal() as buf:
            return hmac.compare_digest(bytes(buf), cand)

    def wipe(self) -> None:
        with self._lock:
            self._open = False
            self._pad.wipe()
            self._masked.wipe()


# --- the sealed blob -------------------------------------------------------------------------------------------------

def generate_passphrase() -> str:
    """A random passphrase with about 124 bits of entropy (five groups of five characters from a 32-letter alphabet), for operators who do not have a manager that makes one."""
    alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(5))


def check_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE:
        raise SealError(f"the passphrase must be at least {MIN_PASSPHRASE} characters (use `ecoctl seal --generate` for a random one)")
    if len(set(passphrase)) < 8:
        raise SealError("the passphrase is too repetitive")


def _key(passphrase: str, salt: bytes) -> bytes:
    log_n, r, p = _KDF
    return passwords.scrypt(passphrase.encode(), salt=salt, n=2**log_n, r=r, p=p)


def seal(secrets_map: dict[str, str], passphrase: str) -> str:
    """Encrypt `secrets_map` (name -> value, e.g. `DATABASE_URL`, `OIDC_CLIENT_SECRET`) under the passphrase. The result is safe to store."""
    check_passphrase(passphrase)
    if not secrets_map or not all(isinstance(k, str) and isinstance(v, str) and k for k, v in secrets_map.items()):
        raise SealError("secrets must be a non-empty mapping of names to text values")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    body = json.dumps({"v": 1, "secrets": secrets_map}, separators=(",", ":")).encode()
    ct = AESGCM(_key(passphrase, salt)).encrypt(nonce, body, _AAD)
    return f"{SEAL_PREFIX}${_B64(salt)}${_B64(nonce + ct)}"


def open_blob(blob: str, passphrase: str) -> dict[str, str]:
    """The plaintext secrets. Raises SealError for a wrong passphrase or a damaged blob, without saying which."""
    try:
        prefix, salt, rest = blob.strip().split("$")
        if prefix != SEAL_PREFIX:
            raise ValueError
        raw = _UNB64(rest)
        body = AESGCM(_key(passphrase, _UNB64(salt))).decrypt(raw[:12], raw[12:], _AAD)
        data = json.loads(body)
        return dict(data["secrets"])
    except passwords.ScryptBusy:
        raise
    except (ValueError, TypeError, KeyError, InvalidTag):
        raise SealError("wrong passphrase, or the sealed blob is damaged") from None


def reseal(blob: str, old: str, new: str) -> str:
    return seal(open_blob(blob, old), new)


# --- the unseal channel: passphrase encrypted to an ephemeral key ----------------------------------------------------

def _envelope_key(shared: bytes, server_pub: bytes, client_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=server_pub + client_pub, info=_INFO_UNSEAL).derive(shared)


def make_envelope(server_public_key: str, passphrase: str) -> dict:
    """Client side (ecoctl): encrypt the passphrase to the app's ephemeral key. Only that process can open it."""
    server_pub = _UNB64(server_public_key)
    eph = X25519PrivateKey.generate()
    client_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = _envelope_key(eph.exchange(X25519PublicKey.from_public_bytes(server_pub)), server_pub, client_pub)
    nonce = secrets.token_bytes(12)
    body = json.dumps({"passphrase": passphrase, "ts": time.time()}).encode()
    return {"epk": _B64(client_pub), "ct": _B64(nonce + AESGCM(key).encrypt(nonce, body, _INFO_UNSEAL))}


def fingerprint(public_key: str) -> str:
    """Short human-comparable digest of the app's ephemeral key."""
    h = hashes.Hash(hashes.SHA256())
    h.update(_UNB64(public_key))
    d = h.finalize().hex()
    return "-".join(d[i : i + 4] for i in range(0, 16, 4))


Callback = Callable[["Sealed", Protected], None]


class Sealed:
    """The in-process state: SEALED until the passphrase opens the blob, then UNSEALED. With no blob configured, `enabled` is False
    and the app runs as before (development, tests, deployments that do not use sealing)."""

    def __init__(self, blob: str | None = None):
        self.blob = (blob or "").strip() or None
        self._secrets: dict[str, Protected] = {}
        self._callbacks: list[Callback] = []
        self._lock = threading.RLock()
        self._unsealed = False
        self._priv: Protected | None = None
        self._pub: str | None = None
        self._ran_ready = False
        self._event = threading.Event()

    @classmethod
    def from_env(cls) -> "Sealed":
        """`APGKIT_SEALED` holds the blob, or `APGKIT_SEALED_FILE` names a file with it (both are ciphertext)."""
        blob = os.environ.get("APGKIT_SEALED", "")
        path = os.environ.get("APGKIT_SEALED_FILE", "")
        if not blob and path:
            try:
                with open(path) as fh:
                    blob = fh.read()
            except OSError as exc:
                print(f"WARNING: cannot read APGKIT_SEALED_FILE {path}: {exc.strerror}", file=sys.stderr)
        return cls(blob)

    @property
    def enabled(self) -> bool:
        return self.blob is not None

    @property
    def unsealed(self) -> bool:
        return (not self.enabled) or self._unsealed

    @property
    def state(self) -> str:
        return "disabled" if not self.enabled else "unsealed" if self._unsealed else "sealed"

    def names(self) -> list[str]:
        return sorted(self._secrets)

    def get(self, name: str) -> str | None:
        item = self._secrets.get(name)
        return item.reveal_str() if item is not None else None

    def protected(self, name: str) -> Protected | None:
        return self._secrets.get(name)

    def on_unsealed(self, callback: Callback) -> None:
        """Run `callback(sealed, passphrase)` when the blob is opened, before the app starts serving (for work that needs the secrets or
        the passphrase: unlock the vault). The passphrase is a `Protected`; use it and let it go. A callback that raises seals the app
        again. When sealing is not enabled the callbacks never run: the app keeps its ordinary start-up."""
        with self._lock:
            self._callbacks.append(callback)

    # the ephemeral key the operator encrypts the passphrase to
    def public_key(self) -> str:
        with self._lock:
            if self._pub is None:
                priv = X25519PrivateKey.generate()
                self._priv = Protected(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
                self._pub = _B64(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
            return self._pub

    def _open_envelope(self, envelope: dict) -> Protected:
        if self._priv is None:
            raise SealError("request the key first")
        try:
            client_pub = _UNB64(str(envelope["epk"]))
            raw = _UNB64(str(envelope["ct"]))
            server_pub = _UNB64(self._pub or "")
            with self._priv.reveal() as buf:
                shared = X25519PrivateKey.from_private_bytes(bytes(buf)).exchange(X25519PublicKey.from_public_bytes(client_pub))
            body = json.loads(AESGCM(_envelope_key(shared, server_pub, client_pub)).decrypt(raw[:12], raw[12:], _INFO_UNSEAL))
            if abs(time.time() - float(body["ts"])) > ENVELOPE_MAX_AGE:
                raise ValueError("stale")
            return Protected(str(body["passphrase"]))
        except (KeyError, ValueError, TypeError, InvalidTag):
            raise SealError("the unseal request could not be opened") from None

    def unseal(self, envelope: dict) -> None:
        self.unseal_with(self._open_envelope(envelope))

    def unseal_with(self, passphrase: Protected) -> None:
        """Open the blob with the passphrase and run the callbacks. The passphrase is wiped afterwards."""
        if not self.enabled:
            raise SealError("sealing is not enabled")
        with self._lock:
            if self._unsealed:
                passphrase.wipe()
                return
            try:
                with passphrase.reveal() as buf:
                    plain = open_blob(self.blob or "", buf.decode())
                self._secrets = {k: Protected(v) for k, v in plain.items()}
                del plain
                self._unsealed = True
                for cb in list(self._callbacks):
                    cb(self, passphrase)
                self._ran_ready = True
                self._event.set()
            except BaseException:                           # fail closed: a callback that cannot finish leaves the app sealed
                self._reseal()
                raise
            finally:
                passphrase.wipe()
            if self._priv is not None:
                self._priv.wipe()
                self._priv, self._pub = None, None

    def wait_unsealed(self, timeout: float | None = None) -> bool:
        """Block until the app is unsealed (True at once when sealing is not enabled)."""
        return True if not self.enabled else self._event.wait(timeout)

    def deferred(self, lifespan):
        """Wrap an ASGI lifespan so its start-up (migrations, background loops that use the database) runs only once the app is
        unsealed. Sealing off: the lifespan runs as it always did. Sealed: the app serves the unseal routes at once, and the wrapped
        lifespan starts after the operator unseals it and stops at shutdown."""
        import asyncio
        import contextlib

        @contextlib.asynccontextmanager
        async def wrapper(app):
            if not self.enabled:
                async with lifespan(app):
                    yield
                return
            stop = asyncio.Event()

            async def run():
                while not await asyncio.to_thread(self.wait_unsealed, 1.0):
                    if stop.is_set():
                        return
                async with lifespan(app):
                    await stop.wait()

            task = asyncio.create_task(run())
            try:
                yield
            finally:
                stop.set()
                await asyncio.gather(task, return_exceptions=True)
        return wrapper

    def _reseal(self) -> None:
        self._event.clear()
        self._unsealed = False
        for item in self._secrets.values():
            item.wipe()
        self._secrets = {}

    def seal_again(self) -> None:
        """Forget every secret (an operator's panic button, or a detected anomaly). The app answers 503 until it is unsealed again."""
        with self._lock:
            self._reseal()
            self._ran_ready = False


# --- process-wide instance, used by config.read_secret / config.database_url ------------------------------------------

_active: Sealed | None = None


def set_active(sealed: Sealed | None) -> None:
    global _active
    _active = sealed


def active() -> Sealed | None:
    return _active


def sealed_secret(name: str) -> str | None:
    """The unsealed value of `name`, if sealing is on and open and the blob holds it."""
    s = _active
    return s.get(name) if (s is not None and s.enabled and s.unsealed) else None


# --- web layer -------------------------------------------------------------------------------------------------------

_OPEN_PATHS = ("/_seal/", "/healthz", "/health", "/livez")


class SealGate:
    """ASGI middleware: while sealed, answer 503 to everything except the unseal routes and the health checks."""

    def __init__(self, app, sealed: Sealed):
        self.app, self.sealed = app, sealed

    async def __call__(self, scope, receive, send):
        if self.sealed.unsealed or scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if any(path == p.rstrip("/") or path.startswith(p) for p in _OPEN_PATHS):
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            return await send({"type": "websocket.close", "code": 1013})
        body = b'{"detail":"sealed: an operator must unseal this app","unseal":"/_seal/status"}'
        await send({"type": "http.response.start", "status": 503,
                    "headers": [(b"content-type", b"application/json"), (b"retry-after", b"30"), (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": body})


def install(app, sealed: Sealed, *, trusted_hops: int | None = None, harden: bool = True) -> Sealed:
    """Wire sealing into a FastAPI app: make `sealed` the active instance, harden the process, add the gate and the routes
    `GET /_seal/status`, `GET /_seal/key`, `POST /_seal/unseal`. Call before the app serves its first request."""
    from fastapi import HTTPException, Request

    from .config import trusted_hops as _hops
    from .ratelimit import FailureLimiter
    from .web import client_ip

    set_active(sealed)
    if not sealed.enabled:
        return sealed
    if harden:
        report = harden_process()
        print("sealed boot: process hardening " + ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in report.items()), file=sys.stderr, flush=True)
    hops = _hops("APGKIT") if trusted_hops is None else trusted_hops
    per_client, overall = FailureLimiter(window=60, limit=5), FailureLimiter(window=60, limit=30)

    @app.get("/_seal/status", include_in_schema=False)
    def seal_status():
        return {"state": sealed.state}

    @app.get("/_seal/key", include_in_schema=False)
    def seal_key():
        if sealed.unsealed:
            raise HTTPException(409, "already unsealed")
        key = sealed.public_key()
        return {"public_key": key, "fingerprint": fingerprint(key)}

    @app.post("/_seal/unseal", include_in_schema=False)
    def seal_unseal(request: Request, envelope: dict):
        if sealed.unsealed:
            raise HTTPException(409, "already unsealed")
        who = client_ip(request, hops)
        if per_client.limited(who) or overall.limited("*"):
            raise HTTPException(429, "too many failed attempts; wait a minute", headers={"Retry-After": "60"})
        per_client.record(who)
        overall.record("*")                                  # counted before the scrypt work, so a burst cannot out-run the limit
        try:
            sealed.unseal(envelope)
        except SealError as exc:
            raise HTTPException(401, str(exc)) from None
        except passwords.ScryptBusy:
            per_client.forgive(who)
            overall.forgive("*")
            raise
        except Exception as exc:                             # the blob opened but start-up could not finish: say so, stay sealed
            per_client.forgive(who)
            overall.forgive("*")
            raise HTTPException(503, f"the passphrase is right but the app could not start: {type(exc).__name__}") from None
        per_client.forgive(who)
        overall.forgive("*")
        return {"state": sealed.state}

    app.add_middleware(SealGate, sealed=sealed)
    return sealed
