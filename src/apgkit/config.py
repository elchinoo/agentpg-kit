"""Configuration helpers shared by every app."""
import os
import sys

DATABASE_ENV_NAMES = ("DATABASE_URL", "DB_EXTERNAL_DSN", "PSQL_CONNECTION_STRING")


def read_secret(env: str, default_file: str = "") -> str:
    """A secret from the environment variable, else the first line of the file named by <ENV>_FILE (or `default_file`).

    Platforms that can only mount files (or that should not put secrets in the environment) can still supply it.
    """
    value = os.environ.get(env, "")
    if value:
        return value
    path = os.environ.get(f"{env}_FILE", default_file)
    if not path:
        return ""
    try:
        with open(path) as fh:
            return fh.readline().strip()
    except FileNotFoundError:
        return ""
    except OSError as exc:  # exists but unreadable, e.g. a root-only file and a non-root container user
        print(f"WARNING: cannot read {env} file {path}: {exc.strerror}", file=sys.stderr)
        return ""


def database_url() -> str:
    """First match wins. An empty DSN makes libpq fall back to PGHOST, PGUSER, PGPASSWORD, PGDATABASE, which linked
    AgentPG sandboxes also provide."""
    for name in DATABASE_ENV_NAMES:
        if os.environ.get(name):
            return os.environ[name]
    return ""


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


MIN_STATIC_KEY_LENGTH = 32


def trusted_hops(prefix: str, default: int = 1) -> int:
    """`<PREFIX>_TRUSTED_HOPS`: how many of the operator's own proxies sit in front of the app (AgentPG: one). 0 = use the socket peer."""
    raw = os.environ.get(f"{prefix.upper()}_TRUSTED_HOPS", "").strip()
    try:
        return max(0, int(raw)) if raw else default
    except ValueError:
        print(f"WARNING: {prefix.upper()}_TRUSTED_HOPS={raw!r} is not an integer; using {default}", file=sys.stderr)
        return default


def is_loopback_host(host: str | None) -> bool:
    """True for a bind address that only local processes can reach. Anything unknown or empty (or 0.0.0.0, ::) is not loopback."""
    import ipaddress
    host = (host or "").strip().strip("[]")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def bind_host(prefix: str) -> str:
    """The address the server binds to, from `<PREFIX>_HOST`, else `HOST`; empty when not stated (treated as public)."""
    return os.environ.get(f"{prefix.upper()}_HOST") or os.environ.get("HOST") or ""


def anonymous_allowed(prefix: str, host: str | None = None, flag_env: str | None = None) -> bool:
    """Whether `<PREFIX>_ALLOW_ANONYMOUS` is honoured. The flag grants every request full access, so it is refused unless the server
    binds to loopback or `<PREFIX>_ALLOW_ANONYMOUS_PUBLIC=1` says the operator accepts exposing an unauthenticated app."""
    prefix = prefix.upper()
    if not env_bool(flag_env or f"{prefix}_ALLOW_ANONYMOUS"):
        return False
    if is_loopback_host(host if host is not None else bind_host(prefix)):
        return True
    if env_bool(f"{prefix}_ALLOW_ANONYMOUS_PUBLIC"):
        return True
    return False


def static_key_problem(key: str) -> str | None:
    return None if len(key) >= MIN_STATIC_KEY_LENGTH else f"static API keys must be at least {MIN_STATIC_KEY_LENGTH} characters"
