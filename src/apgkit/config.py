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
