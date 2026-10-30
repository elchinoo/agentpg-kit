"""Password hashing with scrypt from the standard library (memory-hard, salted, constant-time compare)."""
import base64
import hashlib
import hmac
import secrets

MIN_LENGTH = 12
_N, _R, _P = 2**17, 8, 1          # OWASP's first scrypt choice (128 MiB); each hash stores its own parameters
_MAXMEM = 256 * 1024 * 1024
_MAX_COST = 2**20                  # cap on n * r accepted from storage


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=_MAXMEM, dklen=32)


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
