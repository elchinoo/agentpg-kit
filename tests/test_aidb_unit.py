"""AIDB layer tests that need no AIDB: pure helpers, backend selection, and behaviour on plain Postgres (TEST_DATABASE_URL)."""
import logging

import pytest
from conftest import TEST_URL, needs_db

from apgkit import aidb, retrieval


def test_check_name_rejects_injection_and_odd_names():
    assert aidb.check_name("docs_v2") == "docs_v2"
    for bad in ("", "Docs", "a-b", "a b", "x;drop table y", "1abc", "a" * 64, 'a"b', None):
        with pytest.raises(ValueError):
            aidb.check_name(bad)


def test_version_tuple_and_status_at_least():
    assert aidb.version_tuple("7.9.0") == (7, 9, 0)
    st = aidb.Status(True, version="7.9.0")
    assert st.at_least("7.7") and st.at_least("7.9.0") and not st.at_least("8.0")
    assert not aidb.Status(False).at_least("1")


def test_rrf_prefers_keys_that_rank_well_in_both_lists():
    s = aidb.rrf([["a", "b", "c"], ["b", "a", "d"]])
    assert s["a"] == s["b"] > s["c"] and s["c"] == s["d"] or s["a"] > s["c"]
    assert max(s, key=s.get) in {"a", "b"}
    assert aidb.rrf([]) == {}


def test_scrub_removes_the_secret_from_errors():
    assert aidb._scrub("bad key sk-123 here", "sk-123") == "bad key [redacted] here"
    assert aidb._scrub("nothing", "") == "nothing"


def test_span_attributes_are_flattened():
    payload = {"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "purpose_decision", "attributes": [
        {"key": "aidb.agent.decision.denial_reason", "value": {"stringValue": "engine_privilege_denied"}},
        {"key": "n", "value": {"intValue": "3"}}]}]}]}]}
    a = aidb._span_attrs(payload)
    assert a["_name"] == "purpose_decision" and a["aidb.agent.decision.denial_reason"] == "engine_privilege_denied" and a["n"] == "3"
    assert aidb._span_attrs({}) == {}


def test_purpose_role_name_is_prefixed_and_bounded():
    assert aidb.purpose_role_name("support") == "aidb_p_support"
    assert len(aidb.purpose_role_name("a" * 50)) <= 63
    with pytest.raises(ValueError):
        aidb.purpose_role_name("x; DROP ROLE y")


def test_requested_backend(monkeypatch, caplog):
    monkeypatch.delenv("T_RETRIEVAL_BACKEND", raising=False)
    assert retrieval.requested_backend("T") == "app"
    monkeypatch.setenv("T_RETRIEVAL_BACKEND", " AIDB ")
    assert retrieval.requested_backend("T") == "aidb"
    monkeypatch.setenv("T_RETRIEVAL_BACKEND", "solr")
    with caplog.at_level(logging.ERROR, logger="apgkit.retrieval"):
        assert retrieval.requested_backend("T") == "app"
    assert "solr" in caplog.text


class _Conn:
    closed = False

    def close(self):
        self.closed = True


def test_select_default_is_app_and_never_connects(monkeypatch):
    monkeypatch.delenv("T_RETRIEVAL_BACKEND", raising=False)
    app = retrieval.AppRetrieval("docs", key_column="id", text_column="body")

    def boom():
        raise AssertionError("must not connect when the app backend is requested")
    assert retrieval.select("T", app=app, aidb=retrieval.AidbRetrieval("public.pipeline_x"), connect=boom) is app


def test_select_falls_back_loudly_when_aidb_is_unavailable(monkeypatch, caplog):
    monkeypatch.setenv("T_RETRIEVAL_BACKEND", "aidb")
    app = retrieval.AppRetrieval("docs", key_column="id", text_column="body")
    kb = retrieval.AidbRetrieval("public.pipeline_x")
    conn = _Conn()
    monkeypatch.setattr(retrieval, "_detect", lambda c: aidb.Status(False, reason="the aidb extension is not installed on this server"))
    with caplog.at_level(logging.ERROR, logger="apgkit.retrieval"):
        assert retrieval.select("T", app=app, aidb=kb, connect=lambda: conn) is app
    assert conn.closed
    assert "RETRIEVAL BACKEND FALLBACK" in caplog.text and "not installed" in caplog.text

    caplog.clear()
    monkeypatch.setattr(retrieval, "_detect", lambda c: aidb.Status(True, version="7.9.0"))
    monkeypatch.setattr(retrieval, "_kb_exists", lambda c, name: False)
    with caplog.at_level(logging.ERROR, logger="apgkit.retrieval"):
        assert retrieval.select("T", app=app, aidb=kb, connect=lambda: _Conn()) is app
    assert "does not exist" in caplog.text

    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="apgkit.retrieval"):
        assert retrieval.select("T", app=app, aidb=None, connect=lambda: _Conn()) is app      # app configured no KB
        assert retrieval.select("T", app=app, aidb=kb, connect=lambda: (_ for _ in ()).throw(RuntimeError("db down"))) is app
    assert "db down" in caplog.text


def test_select_returns_aidb_when_usable(monkeypatch):
    monkeypatch.setenv("T_RETRIEVAL_BACKEND", "aidb")
    app = retrieval.AppRetrieval("docs", key_column="id", text_column="body")
    kb = retrieval.AidbRetrieval("public.pipeline_x")
    monkeypatch.setattr(retrieval, "_detect", lambda c: aidb.Status(True, version="7.9.0"))
    monkeypatch.setattr(retrieval, "_kb_exists", lambda c, name: True)
    assert retrieval.select("T", app=app, aidb=kb, connect=lambda: _Conn()) is kb


def test_hit_shape_is_the_same_for_both_backends():
    fields = ("key", "text", "score", "distance", "backend")
    assert tuple(retrieval.Hit.__dataclass_fields__) == fields


def test_app_retrieval_validates_distance():
    with pytest.raises(ValueError):
        retrieval.AppRetrieval("docs", key_column="id", text_column="body", distance="manhattan")


@needs_db
def test_detect_on_plain_postgres_reports_unavailable_and_keeps_the_connection_usable(db):
    import psycopg
    with psycopg.connect(TEST_URL) as conn:
        st = aidb.detect(conn)
        assert not st.available and not st.installed and "aidb" in st.reason
        assert conn.execute("SELECT 1").fetchone()[0] == 1               # not in an aborted transaction
        with pytest.raises(aidb.AidbUnavailable):
            aidb.require(conn)
        assert aidb.status(conn)["aidb"]["available"] is False
        assert set(aidb.status(conn)) == {"aidb", "problems"}


@needs_db
def test_app_backend_keyword_search_and_filters_on_plain_postgres(db):
    with db.connect() as c:
        c.execute("CREATE TABLE docs (id int PRIMARY KEY, body text, category text)")
        c.cursor().executemany("INSERT INTO docs VALUES (%s, %s, %s)", [
            (1, "Connection pooling with pgbouncer reduces connection overhead", "ops"),
            (2, "Chocolate cake recipe with cocoa and butter", "food"),
            (3, "Backup and restore with pg_basebackup", "ops"),
            (4, "Pooling resources for a big dinner party", "food")])
        c.commit()
        app = retrieval.AppRetrieval("docs", key_column="id", text_column="body")
        hits = app.retrieve(c, "how do I pool connections", k=3)
        assert hits[0].key == "1" and hits[0].backend == "app" and hits[0].distance is None and hits[0].text.startswith("Connection")
        ops = app.retrieve(c, "pooling", k=5, filters={"category": "ops"})
        assert [h.key for h in ops] == ["1"]
        both = app.retrieve(c, "pooling", k=5, filters={"category": ["ops", "food"]})
        assert {h.key for h in both} == {"1", "4"}
        assert app.retrieve(c, "xyzzy", k=3) == []
        with pytest.raises(ValueError):
            app.retrieve(c, "x", k=0)


@needs_db
def test_app_backend_vector_leg_hybrid_and_embedder_failure(db):
    with db.connect() as c:
        c.execute("CREATE EXTENSION IF NOT EXISTS vector")
        c.execute("CREATE TABLE docs (id int PRIMARY KEY, body text, emb vector(3))")
        c.cursor().executemany("INSERT INTO docs VALUES (%s, %s, %s::vector)", [
            (1, "alpha pooling", "[1,0,0]"), (2, "beta cake", "[0,1,0]"), (3, "gamma backup", "[0,0,1]")])
        c.commit()
        vecs = {"near alpha": [0.9, 0.1, 0.0], "cake": [0.0, 1.0, 0.0]}
        app = retrieval.AppRetrieval("docs", key_column="id", text_column="body", embedding_column="emb",
                                     embedder=lambda q: vecs.get(q, [0.3, 0.3, 0.3]))
        v = app.retrieve(c, "near alpha", k=2)
        assert v[0].key == "1" and v[0].distance is not None and v[0].score > v[1].score
        h = app.retrieve(c, "cake", k=3, hybrid=True)
        assert h[0].key == "2" and h[0].distance is not None            # in both legs: fused first, carries the distance

        def down(q):
            raise RuntimeError("embedding service down")
        degraded = retrieval.AppRetrieval("docs", key_column="id", text_column="body", embedding_column="emb", embedder=down)
        assert [x.key for x in degraded.retrieve(c, "pooling", k=2)] == ["1"]    # keyword leg answers alone
        assert c.execute("SELECT 1 AS one").fetchone()["one"] == 1
