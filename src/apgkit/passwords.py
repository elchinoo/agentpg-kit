"""Password hashing with scrypt from the standard library (memory-hard, salted, constant-time compare).

Every scrypt derivation in the kit (password hashes and vault key wraps) goes through `scrypt()` below, which holds a
process-wide slot while it runs: at most `APGKIT_SCRYPT_CONCURRENCY` (default 2) derivations at once, so a burst of
unauthenticated logins cannot allocate 128 MiB per request thread. A caller that cannot get a slot within a short wait gets
`ScryptBusy`, an HTTP 503 with `Retry-After`, instead of queueing without bound.
"""
import base64
import hashlib
import hmac
import os
import secrets
import threading
from contextlib import contextmanager

from fastapi import HTTPException

MIN_LENGTH = 12
_N, _R, _P = 2**17, 8, 1          # OWASP's first scrypt choice (128 MiB); each hash stores its own parameters
_MAXMEM = 256 * 1024 * 1024
_MAX_COST = 2**20                  # cap on n * r accepted from storage


class ScryptBusy(HTTPException):
    """Every scrypt slot is taken: answer 503 now (the client retries) rather than queue. Raised as an HTTPException, so a route
    that does not catch it still answers 503 with `Retry-After`."""

    def __init__(self):
        super().__init__(503, "the server is busy verifying passwords; retry in a moment", headers={"Retry-After": "1"})


_WAIT_SECONDS = 0.5                # how long a caller waits for a slot before ScryptBusy
_gate_lock = threading.Lock()
_gate: threading.BoundedSemaphore | None = None


def _concurrency_from_env() -> int:
    try:
        return max(1, int(os.environ.get("APGKIT_SCRYPT_CONCURRENCY", "2")))
    except ValueError:
        return 2


def set_concurrency(limit: int | None = None) -> None:
    """Set the process-wide cap (None: read `APGKIT_SCRYPT_CONCURRENCY` again). Call at start-up, before any derivation runs."""
    global _gate
    with _gate_lock:
        _gate = threading.BoundedSemaphore(max(1, limit) if limit else _concurrency_from_env())


def _get_gate() -> threading.BoundedSemaphore:
    if _gate is None:
        set_concurrency()
    return _gate  # type: ignore[return-value]


@contextmanager
def scrypt_slot():
    gate = _get_gate()
    if not gate.acquire(timeout=_WAIT_SECONDS):
        raise ScryptBusy()
    try:
        yield
    finally:
        gate.release()


def scrypt(secret: bytes, *, salt: bytes, n: int, r: int, p: int, dklen: int = 32) -> bytes:
    """hashlib.scrypt under the process-wide concurrency cap (raises ScryptBusy when saturated)."""
    with scrypt_slot():
        return hashlib.scrypt(secret, salt=salt, n=n, r=r, p=p, maxmem=_MAXMEM, dklen=dklen)


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return scrypt(password.encode(), salt=salt, n=n, r=r, p=p)


def check_strength(password: str) -> None:
    if len(password) < MIN_LENGTH:
        raise ValueError(f"password must be at least {MIN_LENGTH} characters")
    if len(password) > 256:
        raise ValueError("password must be at most 256 characters")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _derive(password, salt, _N, _R, _P)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${_N}${_R}${_P}${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        if not (2 <= int(n) and int(n) & (int(n) - 1) == 0 and 1 <= int(r) <= 16 and 1 <= int(p) <= 16) or int(n) * int(r) > _MAX_COST:
            return False
        actual = _derive(password, base64.b64decode(salt), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def needs_rehash(stored: str) -> bool:
    """True when `stored` was made with weaker parameters than the current ones (rehash it after a successful sign-in)."""
    try:
        scheme, n, r, p, _salt, _digest = stored.split("$")
        return scheme != "scrypt" or (int(n), int(r), int(p)) != (_N, _R, _P)
    except ValueError:
        return True
