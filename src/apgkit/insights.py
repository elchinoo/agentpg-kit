"""Query insights from the EDB extensions that ship on AgentPG, read-only and degrading gracefully.

Sources (each optional): `edb_stat_monitor` (bucketed statement statistics), `pg_stat_statements` (fallback), `edb_pg_tuner`
(settings recommendations) and `query_advisor` (qualifier statistics: which columns are filtered on, how many rows the filter threw away).
Every function takes a psycopg connection and returns a JSON-ready dict. A missing extension, a missing privilege, a timeout or any
database error gives `{"available": False, "reason": "..."}`; nothing here raises for a database reason (only a bad `order` argument
raises ValueError, because that is a programming error). Each probe runs in its own savepoint with a short `statement_timeout`, so a
failure cannot poison the caller's transaction.

Privacy: query text is whatever the views hold (both statistics extensions store the normalised text with `$n` placeholders, not the
bound values), is whitespace-collapsed and cut to `QUERY_CHARS`. Never returned: `query_plan`, `client_ip`, user names, comments.
"""
from __future__ import annotations

import datetime as dt
import decimal
import logging
import re
from typing import Any

import psycopg
from psycopg.rows import dict_row

log = logging.getLogger("apgkit.insights")

QUERY_CHARS = 300
TIMEOUT = "5s"
ORDERS = {"total": "total_ms", "mean": "mean_ms", "calls": "calls"}
# the queries these probes run themselves must not top their own list
_SELF = ("edb_stat_monitor", "pg_stat_statements", "edb_pg_tuner", "query_advisor")


def _unavailable(reason: str) -> dict[str, Any]:
    return {"available": False, "reason": reason}


def _plain(v: Any) -> Any:
    if isinstance(v, decimal.Decimal):
        return float(v)
    if isinstance(v, dt.datetime | dt.date):
        return v.isoformat()
    return v


def _run(conn: psycopg.Connection, sql: str, params: tuple | dict = ()) -> list[dict[str, Any]]:
    """Run one read-only statement in a savepoint with a timeout; rows as plain dicts (never poisons the caller's transaction)."""
    with conn.transaction():
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SET LOCAL statement_timeout = '{TIMEOUT}'")
            cur.execute(sql, params)
            return [{k: _plain(v) for k, v in row.items()} for row in cur.fetchall()]


def _why(exc: Exception) -> str:
    if isinstance(exc, psycopg.errors.InsufficientPrivilege):
        return "permission denied for this database role"
    if isinstance(exc, psycopg.errors.QueryCanceled):
        return "timed out"
    msg = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
    return msg[:200]


def _clean(sql: str | None) -> str:
    text = re.sub(r"\s+", " ", sql or "").strip()
    return text if len(text) <= QUERY_CHARS else text[: QUERY_CHARS - 1] + "…"


def _exists(conn: psycopg.Connection, relation: str) -> bool:
    return bool(_run(conn, "SELECT to_regclass(%s) IS NOT NULL AS ok", (relation,))[0]["ok"])


def sources(conn: psycopg.Connection) -> dict[str, dict[str, Any]]:
    """Which insight sources exist and can be read: {name: {"available": bool, "version"?: str, "reason"?: str}}."""
    probes = {
        "edb_stat_monitor": "SELECT 1 FROM edb_stat_monitor LIMIT 1",
        "pg_stat_statements": "SELECT 1 FROM pg_stat_statements LIMIT 1",
        "edb_pg_tuner": "SELECT 1 FROM edb_pg_tuner_recommendations() LIMIT 1",
        "query_advisor": "SELECT 1 FROM query_advisor_qualstats LIMIT 1",
    }
    out: dict[str, dict[str, Any]] = {}
    try:
        versions = {r["extname"]: r["extversion"] for r in _run(conn, "SELECT extname, extversion FROM pg_extension")}
    except psycopg.Error as exc:
        return {name: _unavailable(_why(exc)) for name in probes}
    for name, probe in probes.items():
        try:
            _run(conn, probe)
        except psycopg.errors.UndefinedTable:
            out[name] = _unavailable("not installed on this database")
        except psycopg.errors.UndefinedFunction:
            out[name] = _unavailable("not installed on this database")
        except psycopg.Error as exc:
            out[name] = _unavailable(_why(exc))
        else:
            out[name] = {"available": True, **({"version": versions[name]} if name in versions else {})}
    return out


_ESM = """
SELECT queryid::text AS queryid, min(query) AS query, sum(calls)::bigint AS calls, sum(total_exec_time) AS total_ms,
       sum(total_exec_time) / NULLIF(sum(calls), 0) AS mean_ms, max(max_exec_time) AS max_ms, sum(rows)::bigint AS rows,
       min(bucket_start_time) AS since
  FROM edb_stat_monitor
 WHERE datname = current_database() AND COALESCE(elevel, 0) = 0 AND queryid IS NOT NULL
   AND query !~* %(selfpat)s
 GROUP BY queryid HAVING sum(calls) > 0
 ORDER BY {order} DESC NULLS LAST, queryid LIMIT %(limit)s
"""
_PGSS = """
SELECT queryid::text AS queryid, query, calls::bigint AS calls, total_exec_time AS total_ms, mean_exec_time AS mean_ms,
       max_exec_time AS max_ms, rows::bigint AS rows, NULL::timestamptz AS since
  FROM pg_stat_statements
 WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) AND queryid IS NOT NULL AND calls > 0
   AND query !~* %(selfpat)s
 ORDER BY {order} DESC NULLS LAST, queryid LIMIT %(limit)s
"""


def top_queries(conn: psycopg.Connection, order: str = "total", limit: int = 20) -> dict[str, Any]:
    """Top statements of the current database by `order` ('total' time, 'mean' time, 'calls'). edb_stat_monitor buckets are
    aggregated by queryid; pg_stat_statements is the fallback. Times are milliseconds."""
    if order not in ORDERS:
        raise ValueError(f"order must be one of {sorted(ORDERS)}")
    limit = max(1, min(int(limit), 100))
    params = {"limit": limit, "selfpat": "|".join(_SELF)}
    reasons = []
    for source, sql in (("edb_stat_monitor", _ESM), ("pg_stat_statements", _PGSS)):
        try:
            rows = _run(conn, sql.format(order=ORDERS[order]), params)
        except (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn):
            reasons.append(f"{source}: not installed on this database")
        except psycopg.Error as exc:
            reasons.append(f"{source}: {_why(exc)}")
        else:
            for r in rows:
                r["query"] = _clean(r["query"])
            hidden = sum(1 for r in rows if r["query"] == "<insufficient privilege>")
            return {"available": True, "source": source, "order": order, "queries": rows, "text_hidden": hidden,
                    "since": min((r["since"] for r in rows if r["since"]), default=None)}
    return _unavailable("; ".join(reasons))


_SETTING = re.compile(r"^\s*([\w.]+)\s*=\s*'?(.*?)'?\s*$")


def tuner(conn: psycopg.Connection) -> dict[str, Any]:
    """edb_pg_tuner recommendations: {"recommendations": [{"setting", "value", "raw"}], "global_stats": {...} | None}."""
    try:
        raw = [next(iter(r.values())) for r in _run(conn, "SELECT * FROM edb_pg_tuner_recommendations()")]
    except psycopg.errors.UndefinedFunction:
        return _unavailable("edb_pg_tuner is not installed on this database")
    except psycopg.Error as exc:
        return _unavailable(_why(exc))
    recs = []
    for line in raw:
        m = _SETTING.match(str(line))
        recs.append({"setting": m.group(1), "value": m.group(2), "raw": str(line)} if m else {"setting": "", "value": "", "raw": str(line)})
    try:
        stats = (_run(conn, "SELECT * FROM edb_pg_tuner_global_stats()") or [None])[0]
    except psycopg.Error:
        stats = None
    return {"available": True, "recommendations": recs, "global_stats": stats}


_OPS = ("=", "<", ">", "<=", ">=", "~~", "~~*")
# pg_attribute keeps a dropped column as "........pg.dropped.N........"; it must never reach the UI
_DROPPED = r"^\.*pg\.dropped\.\d+\.*$"
_ADV_BASE = """
WITH agg AS (
SELECT n.nspname::text AS schema, q.lrelid::regclass::text AS "table", a.attname::text AS "column", o.oprname::text AS operator,
       sum(q.occurrences)::bigint AS occurrences, sum(q.execution_count)::bigint AS executions, sum(q.nbfiltered)::bigint AS rows_filtered,
       EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = q.lrelid AND i.indisvalid AND i.indpred IS NULL
                  AND i.indkey[0] = q.lattnum) AS indexed
  FROM query_advisor_qualstats q
  JOIN pg_class c ON c.oid = q.lrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = q.lrelid AND a.attnum = q.lattnum
  JOIN pg_operator o ON o.oid = q.opno
 WHERE q.rrelid IS NULL AND q.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
   AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_%%'
   AND a.attnum > 0 AND NOT a.attisdropped AND a.attname <> '' AND a.attname::text !~ %(dropped)s
   AND o.oprname::text = ANY(%(ops)s)
 GROUP BY q.lrelid, q.lattnum, 1, 2, 3, 4 HAVING sum(q.execution_count) > 0 AND sum(q.nbfiltered) > 0
)
"""
_ADV = _ADV_BASE + """SELECT schema, "table", "column", operator, occurrences, executions, rows_filtered FROM agg WHERE NOT indexed
 ORDER BY rows_filtered DESC, 2, 3 LIMIT %(limit)s"""
_ADV_COUNT = _ADV_BASE + "SELECT count(*)::bigint AS n FROM agg WHERE indexed"


def advisor(conn: psycopg.Connection, limit: int = 20) -> dict[str, Any]:
    """query_advisor's qualifier statistics in readable form (read from the base view `query_advisor_qualstats`, resolved to
    table/column/operator names here: the `_pretty` and `_all` views are not granted to the AgentPG login role). `rows_filtered` is the number of rows the qualifier read and then threw
    away: the benefit an index on that column could remove. It is a hint from observed workload, not a measured speed-up.

    Left out: dropped columns, operators a btree cannot serve, and columns that already lead a valid, non-partial index (primary key and
    unique indexes included). The number hidden for the last reason is `summary["already_indexed"]`."""
    params = {"limit": max(1, min(int(limit), 100)), "dropped": _DROPPED, "ops": list(_OPS)}
    try:
        rows = _run(conn, _ADV, params)
        hidden = _run(conn, _ADV_COUNT, params)[0]["n"]
    except (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedFunction):
        return _unavailable("query_advisor is not installed on this database")
    except psycopg.Error as exc:
        return _unavailable(_why(exc))
    for r in rows:
        r["filtered_per_execution"] = round(r["rows_filtered"] / r["executions"], 2)
        r["suggestion"] = f'Consider an index on {r["table"]} ({r["column"]})'
    return {"available": True, "suggestions": rows, "summary": {"already_indexed": int(hidden)}}


def insights_payload(conn: psycopg.Connection, order: str = "total", limit: int = 20) -> dict[str, Any]:
    """Everything the UI needs for `GET /api/insights`; each part degrades on its own."""
    def safe(fn, *a):
        try:
            return fn(conn, *a)
        except ValueError:
            raise
        except Exception as exc:   # noqa: BLE001 - a broken probe is a state to show, never a 500
            log.warning("insights %s failed: %s", fn.__name__, exc)
            return _unavailable(f"{fn.__name__} failed")
    return {"sources": safe(sources), "top_queries": safe(top_queries, order, limit), "tuner": safe(tuner), "advisor": safe(advisor, limit)}
