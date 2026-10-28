"""Database-enforced column masking for the read-only role, without superuser extensions (no data_redaction).

AgentPG instances have the group role `a1p_readonly` (SELECT on public tables by default privilege); direct DB users created with
`agentpg db-users create --permission read` and the restricted MCP server's read-only user are members of it. `mask_view` takes the
base table away from that role and grants it a security_barrier view of masked columns instead, so the database itself enforces what
those users see (they get "permission denied" on the base table; writes are refused anyway).

Facts and gotchas (verified on an AgentPG instance):
- Only the table OWNER can REVOKE/GRANT. A non-owner REVOKE only raises a warning and changes nothing, so the result is checked with
  `has_table_privilege` and reported (`base_denied`); it is never assumed.
- Default privileges re-grant SELECT to the role on NEW tables: call `mask_view` after the tables exist and again on every migrate
  (it is idempotent). `migrate.run(..., after_migrate=[...])` does exactly that.
- Each statement runs in its own autocommit step: a multi-statement call rolls back as a whole on any error.
- The view runs with its owner's rights (that is what lets the role read through it); `security_barrier` stops a role's own functions
  from seeing unmasked rows through pushed-down predicates. A view column rule that is "pass" shows the value as is.
- Grants made AFTER startup reopen tables: `agentpg db-users create` and the default privileges give the role SELECT on base tables
  again at any time, not only on new ones. A one-off call at migrate time is therefore not enough: run `reassert_forever` (below).
- Where the role does not exist (plain Postgres in dev/CI) masking is skipped and logged, never an error.
"""
from __future__ import annotations

import asyncio
import logging
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractContextManager
from typing import Any

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

log = logging.getLogger("apgkit.masking")

READONLY_ROLE = "a1p_readonly"
# column rules; {c} is the quoted column. Anything else in the `columns` mapping is used as a raw SQL expression (developer-written,
# never user input).
RULES = {
    "pass": "{c}",
    "email": "regexp_replace({c}::text, '^.*@', '***@')",
    "last4": "'**** ' || right({c}::text, 4)",
    "initial": "left({c}::text, 1) || '***'",
    "hash": "left(encode(sha256(convert_to({c}::text, 'UTF8')), 'hex'), 12)",
    "redact": "'[redacted]'::text",
}
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def _qualified(name: str, default_schema: str | None = None) -> tuple[str, str]:
    parts = name.split(".")
    if len(parts) == 1:
        schema, rel = default_schema or "public", parts[0]
    elif len(parts) == 2:
        schema, rel = parts
    else:
        raise ValueError(f"bad relation name {name!r}")
    if not _IDENT.match(schema) or not _IDENT.match(rel):
        raise ValueError(f"bad relation name {name!r}")
    return schema, rel


def _ident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"bad identifier {name!r}")
    return name


class _Autocommit:
    """Run a block with autocommit on (each statement its own transaction), after committing whatever the caller had open."""
    def __init__(self, conn: psycopg.Connection):
        self.conn = conn

    def __enter__(self):
        self.conn.commit()
        self.prev = self.conn.autocommit
        self.conn.autocommit = True
        return self.conn

    def __exit__(self, *exc):
        self.conn.autocommit = self.prev


def _q(conn: psycopg.Connection, query: Any, params: tuple = ()) -> list[dict[str, Any]]:
    """Rows as dicts whatever row factory the caller's connection uses."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(query, params)
        return cur.fetchall() if cur.description else []


def _fq(schema: str, rel: str) -> str:
    return f'"{schema}"."{rel}"'          # both parts are validated identifiers


def _role_exists(conn: psycopg.Connection, role: str) -> bool:
    return bool(_q(conn, "SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)))


def _can_select(conn: psycopg.Connection, role: str, schema: str, rel: str) -> bool:
    return bool(_q(conn, "SELECT has_table_privilege(%s, %s::regclass, 'SELECT') AS ok", (role, _fq(schema, rel)))[0]["ok"])


def _expr(conn: psycopg.Connection, schema: str, table: str, column: str, rule: str) -> sql.Composable:
    col = sql.Identifier(column)
    if rule == "null":
        rows = _q(conn, "SELECT format_type(a.atttypid, a.atttypmod) AS t FROM pg_attribute a "
                        "WHERE a.attrelid = %s::regclass AND a.attname = %s AND a.attnum > 0 AND NOT a.attisdropped",
                  (_fq(schema, table), column))
        if not rows:
            raise ValueError(f"column {column!r} not found in {schema}.{table}")
        return sql.SQL("NULL::") + sql.SQL(rows[0]["t"])
    if rule in RULES:
        return sql.SQL(RULES[rule]).format(c=col)
    return sql.SQL(rule)


def mask_view(conn: psycopg.Connection, table: str, view: str, columns: Mapping[str, str], readonly_role: str = READONLY_ROLE) -> dict[str, Any]:
    """Create or replace `view` (security_barrier) exposing only `columns` ({column: rule}) of `table` masked, REVOKE the base table
    from `readonly_role`, GRANT it the view and USAGE on the schema. Rules: pass, email, last4, initial, hash, redact, null, or a raw
    SQL expression. Idempotent; skips (returns applied False) if the role does not exist. Returns
    {"applied", "reason", "base_denied", "view_readable"}; `base_denied` False means the REVOKE did not take (not the table owner,
    or PUBLIC can read it): treat as not masked."""
    schema, rel = _qualified(table)
    vschema, vrel = _qualified(view, schema)
    _ident(readonly_role)
    if not columns:
        raise ValueError("columns must not be empty")
    with _Autocommit(conn):
        if not _role_exists(conn, readonly_role):
            log.info("masking %s skipped: role %s does not exist", table, readonly_role)
            return {"applied": False, "reason": f"role {readonly_role} does not exist", "base_denied": False, "view_readable": False}
        select = sql.SQL(", ").join(
            sql.SQL("{} AS {}").format(_expr(conn, schema, rel, c, str(rule)), sql.Identifier(c)) for c, rule in columns.items())
        base, vname = sql.Identifier(schema, rel), sql.Identifier(vschema, vrel)
        body = sql.SQL("SELECT {} FROM {}").format(select, base)
        role = sql.Identifier(readonly_role)
        try:
            conn.execute(sql.SQL("CREATE OR REPLACE VIEW {} WITH (security_barrier = true) AS ").format(vname) + body)
        except psycopg.errors.InvalidTableDefinition:       # the column set or types changed: replace cannot do that
            conn.execute(sql.SQL("DROP VIEW {}").format(vname))
            conn.execute(sql.SQL("CREATE VIEW {} WITH (security_barrier = true) AS ").format(vname) + body)
        conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), role))
        if vschema != schema:
            conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(vschema), role))
        conn.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(vname, role))
        conn.execute(sql.SQL("REVOKE SELECT ON {} FROM {}").format(base, role))      # a non-owner only gets a warning: verified below
        denied, readable = not _can_select(conn, readonly_role, schema, rel), _can_select(conn, readonly_role, vschema, vrel)
    if not denied:
        log.warning("masking %s: %s can still read the base table (not the owner, or PUBLIC has SELECT)", table, readonly_role)
    return {"applied": denied and readable, "reason": "" if denied else "base table still readable by the role", "base_denied": denied,
            "view_readable": readable}


def unmask(conn: psycopg.Connection, table: str, view: str, readonly_role: str = READONLY_ROLE) -> dict[str, Any]:
    """Undo `mask_view`: drop the view and give the role SELECT on the base table back. Skips if the role does not exist."""
    schema, rel = _qualified(table)
    vschema, vrel = _qualified(view, schema)
    _ident(readonly_role)
    with _Autocommit(conn):
        if not _role_exists(conn, readonly_role):
            return {"applied": False, "reason": f"role {readonly_role} does not exist"}
        conn.execute(sql.SQL("DROP VIEW IF EXISTS {}").format(sql.Identifier(vschema, vrel)))
        conn.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(sql.Identifier(schema, rel), sql.Identifier(readonly_role)))
    return {"applied": True, "reason": ""}


def describe(conn: psycopg.Connection, table: str, view: str, readonly_role: str = READONLY_ROLE, sample: int = 0) -> dict[str, Any]:
    """What the read-only role can see: {"role_exists", "base_readable", "view_exists", "view_readable", "columns": [...],
    "sample": [rows as the role sees them] }. `sample` > 0 fetches that many rows by SET LOCAL ROLE inside a rolled-back transaction
    (works when the connected user may SET ROLE to the group role; otherwise "sample_error" says why)."""
    schema, rel = _qualified(table)
    vschema, vrel = _qualified(view, schema)
    _ident(readonly_role)
    conn.commit()
    out: dict[str, Any] = {"role_exists": _role_exists(conn, readonly_role), "base_readable": False, "view_exists": False,
                           "view_readable": False, "columns": []}
    if not out["role_exists"]:
        return out
    vname = sql.Identifier(vschema, vrel)
    out["base_readable"] = _can_select(conn, readonly_role, schema, rel)
    out["view_exists"] = _q(conn, "SELECT to_regclass(%s) IS NOT NULL AS ok", (_fq(vschema, vrel),))[0]["ok"]
    if out["view_exists"]:
        out["view_readable"] = _can_select(conn, readonly_role, vschema, vrel)
        out["columns"] = [r["attname"] for r in _q(
            conn, "SELECT attname FROM pg_attribute WHERE attrelid = %s::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum",
            (_fq(vschema, vrel),))]
        if sample > 0:
            try:
                with conn.transaction(force_rollback=True):
                    conn.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(readonly_role)))
                    out["sample"] = _q(conn, sql.SQL("SELECT * FROM {} LIMIT {}").format(vname, sql.Literal(int(sample))))
            except psycopg.Error as exc:
                out["sample_error"] = str(exc).strip().splitlines()[0]
    conn.commit()
    return out


def _existing(conn: psycopg.Connection, tables: Iterable[str]) -> tuple[list[tuple[str, str, str]], list[str]]:
    found, missing = [], []
    for t in tables:
        schema, rel = _qualified(t)
        if _q(conn, "SELECT to_regclass(%s) IS NOT NULL AS ok", (_fq(schema, rel),))[0]["ok"]:
            found.append((t, schema, rel))
        else:
            missing.append(t)
    return found, missing


def deny_tables(conn: psycopg.Connection, tables: Iterable[str], readonly_role: str = READONLY_ROLE) -> dict[str, Any]:
    """REVOKE SELECT on each base table from `readonly_role`, with no view (for tables the role must not see at all). Idempotent; one
    statement per table in autocommit; tables that do not exist are skipped. Skips (applied False) if the role does not exist.
    Returns the shape of `mask_view` plus `tables` ({name: denied}) and `skipped` (missing tables): `base_denied` is True only if the
    role can read none of the existing tables afterwards (checked with has_table_privilege; a non-owner REVOKE changes nothing)."""
    _ident(readonly_role)
    tables = list(tables)
    with _Autocommit(conn):
        if not _role_exists(conn, readonly_role):
            log.info("deny_tables skipped: role %s does not exist", readonly_role)
            return {"applied": False, "reason": f"role {readonly_role} does not exist", "base_denied": False, "view_readable": False,
                    "tables": {}, "skipped": []}
        found, missing = _existing(conn, tables)
        for _, schema, rel in found:
            conn.execute(sql.SQL("REVOKE SELECT ON {} FROM {}").format(sql.Identifier(schema, rel), sql.Identifier(readonly_role)))
        result = {t: not _can_select(conn, readonly_role, schema, rel) for t, schema, rel in found}
    denied = all(result.values())
    if not denied:
        log.warning("deny_tables: %s can still read %s (not the owner, or PUBLIC has SELECT)", readonly_role,
                    ", ".join(t for t, ok in result.items() if not ok))
    return {"applied": denied, "reason": "" if denied else "some tables still readable by the role", "base_denied": denied,
            "view_readable": False, "tables": result, "skipped": missing}


def drift(conn: psycopg.Connection, tables: Iterable[str], readonly_role: str = READONLY_ROLE) -> list[str]:
    """Which of `tables` (that exist) the role can SELECT right now although they should be denied. [] if the role is missing."""
    _ident(readonly_role)
    conn.commit()
    if not _role_exists(conn, readonly_role):
        return []
    found, _ = _existing(conn, tables)
    out = [t for t, schema, rel in found if _can_select(conn, readonly_role, schema, rel)]
    conn.commit()
    return out


_STATE: dict[str, dict[str, Any]] = {}
_STATE_LOCK = threading.Lock()


def status(name: str = "masking") -> dict[str, Any]:
    """What the re-assert loop `name` last did: {"last_ok": ISO UTC time or None, "drift": tables found open before the last
    apply (None until the first tick), "ok": last tick succeeded}. Use it in a readiness/status route."""
    with _STATE_LOCK:
        st = dict(_STATE.get(name, {}))
    ts = st.get("last_ok")
    return {"last_ok": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else None, "drift": st.get("drift"),
            "ok": bool(st.get("ok", False))}


def _metrics_for(metrics: Any, name: str) -> tuple[Any, Any, Any]:
    from prometheus_client import Counter, Gauge
    cache = metrics.__dict__.setdefault("_masking_metrics", {})
    if name not in cache:
        reg = metrics.registry
        suffix = "" if name == "masking" else f"_{re.sub(r'[^a-z0-9_]', '_', name.lower())}"
        cache[name] = (Gauge(f"masking_last_ok_timestamp{suffix}", "Unix time of the last successful masking re-assert", registry=reg),
                       Counter(f"masking_reapplied_total{suffix}", "Masking re-asserts that ran successfully", registry=reg),
                       Gauge(f"masking_drift_tables{suffix}", "Tables the read-only role could read before the last re-assert", registry=reg))
    return cache[name]


def reassert_tick(connect: Callable[[], AbstractContextManager], apply: Callable[[psycopg.Connection], Any], *, name: str = "masking",
                  deny: Iterable[str] = (), readonly_role: str = READONLY_ROLE, metrics: Any = None,
                  clock: Callable[[], float] = time.time) -> bool:
    """One re-assert (blocking): count drift for `deny`, run `apply(conn)` on its own connection, record state and metrics. Never raises."""
    deny = list(deny)
    try:
        with connect() as conn:
            opened = drift(conn, deny, readonly_role) if deny else []
            apply(conn)
            try:
                conn.commit()
            except psycopg.Error:
                pass
    except Exception as exc:   # noqa: BLE001 - a background loop must survive anything
        with _STATE_LOCK:
            _STATE.setdefault(name, {})["ok"] = False
        log.warning("%s re-assert failed: %s", name, str(exc).strip().splitlines()[0][:200] if str(exc).strip() else type(exc).__name__)
        return False
    now = clock()
    with _STATE_LOCK:
        _STATE[name] = {"last_ok": now, "drift": len(opened), "ok": True}
    if opened:
        log.warning("%s: %d table(s) were readable by %s and have been re-secured: %s", name, len(opened), readonly_role, ", ".join(opened))
    if metrics is not None:
        try:
            last, total, dr = _metrics_for(metrics, name)
            last.set(now)
            total.inc()
            dr.set(len(opened))
        except Exception:   # noqa: BLE001
            log.warning("%s: could not update metrics", name)
    return True


async def reassert_forever(connect: Callable[[], AbstractContextManager], apply: Callable[[psycopg.Connection], Any], every: float = 300,
                           *, name: str = "masking", deny: Iterable[str] = (), readonly_role: str = READONLY_ROLE, metrics: Any = None,
                           sleep: Callable[[float], Any] = asyncio.sleep, clock: Callable[[], float] = time.time) -> None:
    """Run the app's idempotent `apply(conn)` (its `mask_view`/`deny_tables` calls) now and then every `every` seconds on its own
    connection in a worker thread, until cancelled. Never raises (failures log one warning line and the loop goes on). `deny` lists
    base tables that must stay closed: each tick first counts how many the role could read (`masking_drift_tables` gauge, `drift` in
    `status(name)`). Pass the kit's `Metrics` as `metrics` for `masking_last_ok_timestamp`, `masking_reapplied_total` and
    `masking_drift_tables`. `sleep`/`clock` are injectable for tests."""
    every = max(1.0, float(every))
    while True:
        await asyncio.to_thread(reassert_tick, connect, apply, name=name, deny=deny, readonly_role=readonly_role, metrics=metrics, clock=clock)
        await sleep(every)
