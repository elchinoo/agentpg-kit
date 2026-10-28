"""Query insights: fakes with the real column names stand in for edb_stat_monitor, query_advisor and edb_pg_tuner (those extensions
exist only on AgentPG); everything must degrade to {"available": False} when absent or unreadable."""
import psycopg
import pytest
from conftest import TEST_URL, needs_db
from psycopg.conninfo import make_conninfo

from apgkit import insights
from apgkit.metrics import Metrics

pytestmark = needs_db

FAKE_ESM = """
CREATE TABLE edb_stat_monitor (bucket int, bucket_start_time timestamptz, datname name, queryid bigint, query text, elevel int,
  calls bigint, total_exec_time float8, min_exec_time float8, max_exec_time float8, mean_exec_time float8, rows bigint,
  query_plan text, client_ip inet, username name);
INSERT INTO edb_stat_monitor (bucket, bucket_start_time, datname, queryid, query, elevel, calls, total_exec_time, max_exec_time, mean_exec_time, rows, query_plan, client_ip, username) VALUES
 (0, '2026-10-28 10:00+00', current_database(), 111, E'SELECT *\\n  FROM orders WHERE id = $1', 0, 10, 100, 30, 10, 10, 'Seq Scan secret-plan', '10.1.2.3', 'alice'),
 (1, '2026-10-28 10:05+00', current_database(), 111, E'SELECT *\\n  FROM orders WHERE id = $1', 0, 30, 500, 90, 16.6, 30, 'p', '10.1.2.3', 'alice'),
 (0, '2026-10-28 10:00+00', current_database(), 222, 'UPDATE stock SET n = $1', 0, 1000, 200, 2, 0.2, 1000, 'p', NULL, 'bob'),
 (0, '2026-10-28 10:00+00', current_database(), 333, 'SELECT pg_sleep($1)', 0, 2, 4000, 2500, 2000, 2, 'p', NULL, 'bob'),
 (0, '2026-10-28 10:00+00', current_database(), 444, 'SELECT boom', 21, 5, 0, 0, 0, 0, 'p', NULL, 'bob'),
 (0, '2026-10-28 10:00+00', 'other_db', 555, 'SELECT elsewhere', 0, 9999, 99999, 9, 9, 1, 'p', NULL, 'bob'),
 (0, '2026-10-28 10:00+00', current_database(), 666, 'SELECT * FROM edb_stat_monitor', 0, 9999, 99999, 9, 9, 1, 'p', NULL, 'bob');
"""
FAKE_ADVISOR = """
CREATE TABLE orders (id int, customer int);
CREATE TABLE stock (id int);
CREATE TABLE query_advisor_qualstats (userid oid, dbid oid, lrelid oid, lattnum smallint, opno oid, rrelid oid, rattnum smallint,
  occurrences bigint, execution_count bigint, nbfiltered bigint, queryid bigint);
INSERT INTO query_advisor_qualstats SELECT 10, d.oid, 'orders'::regclass, 1, '=(int4,int4)'::regoperator, NULL, NULL, v.o, v.e, v.f, 1
  FROM pg_database d, (VALUES (2, 40, 4000), (1, 10, 1000)) v(o, e, f) WHERE d.datname = current_database();
INSERT INTO query_advisor_qualstats SELECT 10, d.oid, 'orders'::regclass, 2, '=(int4,int4)'::regoperator, 'stock'::regclass, 1, 1, 10, 5000, 2
  FROM pg_database d WHERE d.datname = current_database();                       -- a join: left out
INSERT INTO query_advisor_qualstats SELECT 10, d.oid, 'stock'::regclass, 1, '<>(int4,int4)'::regoperator, NULL, NULL, 1, 5, 50, 3
  FROM pg_database d WHERE d.datname = current_database();
INSERT INTO query_advisor_qualstats SELECT 10, d.oid, 'pg_class'::regclass, 1, '=(oid,oid)'::regoperator, NULL, NULL, 1, 1, 99999, 4
  FROM pg_database d WHERE d.datname = current_database();                       -- catalog: left out
INSERT INTO query_advisor_qualstats SELECT 10, d.oid, 'orders'::regclass, 1, '=(int4,int4)'::regoperator, NULL, NULL, 1, 0, 0, 5
  FROM pg_database d WHERE d.datname = current_database();                       -- never executed: left out of the sums
"""
FAKE_TUNER = """
CREATE FUNCTION edb_pg_tuner_recommendations() RETURNS SETOF text LANGUAGE sql AS
 $$ VALUES ('shared_buffers = ''186 MB'''), ('effective_cache_size = ''460 MB'''), ('odd line') $$;
CREATE FUNCTION edb_pg_tuner_global_stats(OUT collected timestamptz, OUT db_size bigint) LANGUAGE sql AS
 $$ SELECT '2026-10-28 10:00+00'::timestamptz, 418444::bigint $$;
"""


def _conn(db, ddl=""):
    c = db.connect()
    if ddl:
        c.execute(ddl)
        c.commit()
    return c


def test_nothing_installed_degrades_everywhere(db):
    with _conn(db) as c:
        s = insights.sources(c)
        assert set(s) == {"edb_stat_monitor", "pg_stat_statements", "edb_pg_tuner", "query_advisor"}
        assert all(not v["available"] and v["reason"] for k, v in s.items() if k != "pg_stat_statements")
        for part in (insights.top_queries(c), insights.tuner(c), insights.advisor(c)):
            assert part["available"] is False and part["reason"]
        p = insights.insights_payload(c)
        assert set(p) == {"sources", "top_queries", "tuner", "advisor"} and p["tuner"]["available"] is False
        c.execute("SELECT 1")                         # the connection is still usable: no aborted transaction left behind


def test_top_queries_aggregate_buckets_and_hide_internals(db):
    with _conn(db, FAKE_ESM) as c:
        r = insights.top_queries(c, "total")
        assert r["available"] and r["source"] == "edb_stat_monitor" and r["since"].startswith("2026-10-28")
        ids = [q["queryid"] for q in r["queries"]]
        assert ids == ["333", "111", "222"]           # other db, error rows and the probe's own statements are excluded
        q111 = r["queries"][1]
        assert q111["calls"] == 40 and q111["total_ms"] == 600 and q111["mean_ms"] == 15 and q111["max_ms"] == 90
        assert q111["query"] == "SELECT * FROM orders WHERE id = $1"        # whitespace collapsed
        assert [q["queryid"] for q in insights.top_queries(c, "mean")["queries"]] == ["333", "111", "222"]
        assert [q["queryid"] for q in insights.top_queries(c, "calls")["queries"]] == ["222", "111", "333"]
        assert len(insights.top_queries(c, "total", 1)["queries"]) == 1
        flat = repr(r)
        assert "secret-plan" not in flat and "10.1.2.3" not in flat and "alice" not in flat
        with pytest.raises(ValueError):
            insights.top_queries(c, "bogus; drop table x")


def test_long_query_text_is_truncated(db):
    with _conn(db, FAKE_ESM) as c:
        c.execute("UPDATE edb_stat_monitor SET query = 'SELECT ' || repeat('x', 2000) WHERE queryid = 222")
        c.commit()
        q = next(q for q in insights.top_queries(c)["queries"] if q["queryid"] == "222")
        assert len(q["query"]) == insights.QUERY_CHARS and q["query"].endswith("…")


def test_tuner_and_advisor(db):
    with _conn(db, FAKE_TUNER + FAKE_ADVISOR) as c:
        t = insights.tuner(c)
        assert t["available"]
        assert t["recommendations"][0] == {"setting": "shared_buffers", "value": "186 MB", "raw": "shared_buffers = '186 MB'"}
        assert t["recommendations"][2]["setting"] == "" and t["recommendations"][2]["raw"] == "odd line"
        import datetime as dt
        assert dt.datetime.fromisoformat(t["global_stats"]["collected"]) == dt.datetime(2026, 10, 28, 10, tzinfo=dt.UTC)
        assert t["global_stats"]["db_size"] == 418444
        a = insights.advisor(c)
        rows = {(r["table"], r["column"]): r for r in a["suggestions"]}
        assert set(rows) == {("orders", "id"), ("stock", "id")}          # joins, never-executed and catalog rows are left out
        o = rows[("orders", "id")]
        assert (o["executions"], o["rows_filtered"], o["filtered_per_execution"]) == (50, 5000, 100.0)
        assert o["suggestion"] == "Consider an index on orders (id)"
        assert rows[("stock", "id")]["suggestion"] == ""                 # '<>' cannot use a btree index
        assert a["suggestions"][0]["table"] == "orders"                  # biggest benefit first


def test_unreadable_source_is_reported_not_raised(db):
    login = "kit_insights_login"
    with _conn(db, FAKE_ESM + FAKE_TUNER) as c:
        c.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{login}') THEN CREATE ROLE {login} LOGIN PASSWORD 'ro-pw-test'; END IF; END $$")
        c.execute(f"GRANT USAGE ON SCHEMA public TO {login}")
        c.execute(f"REVOKE ALL ON edb_stat_monitor FROM PUBLIC, {login}")
        c.execute("REVOKE ALL ON FUNCTION edb_pg_tuner_recommendations() FROM PUBLIC")
        c.commit()
    with psycopg.connect(make_conninfo(TEST_URL, user=login, password="ro-pw-test"), row_factory=psycopg.rows.dict_row) as lc:
        s = insights.sources(lc)
        assert s["edb_stat_monitor"] == {"available": False, "reason": "permission denied for this database role"}
        assert insights.top_queries(lc)["available"] is False
        assert insights.tuner(lc)["available"] is False
        lc.execute("SELECT 1")


def test_pg_stat_statements_fallback_when_it_exists(db):
    with _conn(db) as c:
        if not insights.sources(c)["pg_stat_statements"]["available"]:
            pytest.skip("pg_stat_statements is not loaded on the test database")
        c.execute("SELECT 41 + 1 AS apgkit_probe")
        r = insights.top_queries(c, "calls")
        assert r["available"] and r["source"] == "pg_stat_statements"


def test_metrics_collector(db):
    with _conn(db, FAKE_ESM + FAKE_TUNER) as c:
        c.execute("INSERT INTO edb_stat_monitor (bucket, bucket_start_time, datname, queryid, query, elevel, calls, total_exec_time, max_exec_time, mean_exec_time, rows) "
                  "VALUES (0, now(), current_database(), 777, 'SELECT few', 0, 2, 9000, 5000, 4500, 2)")   # slow but under min_calls
        c.commit()
    m = Metrics("demo", "1.0")
    m.add_insights_collector(db.connect, top=2, min_calls=5, ttl=0)
    body = m.render()[0].decode()
    assert 'db_insights_available{app="demo"} 1.0' in body
    assert 'db_insights_top_query_mean_seconds{app="demo",queryid="111"} 0.015' in body
    assert 'db_insights_top_query_mean_seconds{app="demo",queryid="222"} 0.0002' in body
    assert 'queryid="333"' not in body and 'queryid="777"' not in body     # 333 has 2 calls: below min_calls
    assert 'db_insights_statement_calls{app="demo"} 1044.0' in body
    assert 'db_insights_tuner_recommendations{app="demo"} 3.0' in body


def test_metrics_collector_never_fails_a_scrape(db):
    m = Metrics("demo", "1.0")
    m.add_insights_collector(db.connect, ttl=0)           # nothing installed
    assert 'db_insights_available{app="demo"} 0.0' in m.render()[0].decode()
    m2 = Metrics("demo", "1.0")

    def broken():
        raise RuntimeError("db down")
    m2.add_insights_collector(broken, ttl=0)
    body = m2.render()[0].decode()
    assert 'db_insights_available{app="demo"} 0.0' in body and "db_insights_top_query" not in body
