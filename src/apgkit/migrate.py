"""A tiny plain-SQL migration runner (just Postgres: no ORM, no proprietary tooling).

Every app keeps numbered `.sql` files in its own `migrations/` directory. `bootstrap` creates the tables every app shares.
"""
from pathlib import Path

from .db import Database

SHARED_SQL = """
CREATE TABLE IF NOT EXISTS app_setting (key text PRIMARY KEY, value text NOT NULL);
"""


def run(db: Database, directory: Path, *, extensions: tuple[str, ...] = (), replacements: dict[str, str] | None = None,
        table: str = "schema_migrations") -> list[str]:
    """Apply the migrations in `directory` that have not run yet, in name order. Returns the names applied."""
    applied: list[str] = []
    with db.connect() as conn:
        for ext in extensions:
            if not ext.replace("_", "").isalnum():
                raise ValueError(f"bad extension name {ext!r}")
            conn.execute(f"CREATE EXTENSION IF NOT EXISTS {ext}")
        conn.execute(SHARED_SQL)
        conn.execute(f"CREATE TABLE IF NOT EXISTS {table} (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
        done = {r["name"] for r in conn.execute(f"SELECT name FROM {table}")}
        for path in sorted(directory.glob("*.sql")):
            if path.name in done:
                continue
            sql = path.read_text()
            for k, v in (replacements or {}).items():
                sql = sql.replace(k, v)
            conn.execute(sql)
            conn.execute(f"INSERT INTO {table} (name) VALUES (%s)", (path.name,))
            applied.append(path.name)
        conn.commit()
    return applied
