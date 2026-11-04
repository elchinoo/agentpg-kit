"""One retrieval interface, two backends, one setting.

    retriever = retrieval.select("TRUSTDESK", app=AppRetrieval(...), aidb=AidbRetrieval("public.pipeline_policy"), connect=db.connect)
    hits = retriever.retrieve(conn, "how do we rotate keys?", k=5, filters={"tenant": "acme"})

Both backends return `list[Hit]` with the same fields, so an app swaps backends by changing what it constructs, not what it reads.

- `app`: pgvector similarity and/or PostgreSQL full-text search over the app's own table (what the fleet's apps do today). The kit
  did not contain this code before; this is the generic form of it. Bring an `embedder` (text -> list[float]) for the vector leg;
  without one, or when it fails, the keyword leg answers alone.
- `aidb`: an AIDB knowledge base (see `apgkit.aidb`): the database embeds the table (Live pipeline) and answers the query.

`<PREFIX>_RETRIEVAL_BACKEND=app|aidb` (default `app`) picks one. Asking for `aidb` where it is unavailable (plain Postgres, no grant,
no such knowledge base) falls back to `app` and logs an ERROR naming the reason; apps stay up.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import psycopg
from psycopg import sql

from . import aidb

log = logging.getLogger("apgkit.retrieval")
BACKENDS = ("app", "aidb")


@dataclass(frozen=True)
class Hit:
    key: str                      # the source row's key, as text (same for both backends)
    text: str | None              # the source text
    score: float                  # higher is better; comparable within one backend and one call, not across backends
    distance: float | None = None  # vector distance when the vector leg matched, else None
    backend: str = ""


class Retrieval(Protocol):
    name: str

    def retrieve(self, conn: psycopg.Connection, query: str, k: int = 5, *, filters: Mapping[str, Any] | None = None,
                 hybrid: bool = False) -> list[Hit]: ...


_OPS = {"cosine": "<=>", "l2": "<->", "ip": "<#>"}


def _vector_literal(vec) -> str:
    return "[" + ",".join(repr(float(x)) for x in vec) + "]"


class AppRetrieval:
    """Retrieval over an app table with pgvector and/or full-text search.

    `table` (optionally `schema.table`), `key_column` and `text_column` name the source rows; `embedding_column` plus `embedder` turn
    on the vector leg (`distance`: cosine, l2 or ip, matching the column's index). `filters` ({column: value | [values] | None}) apply
    to both legs. `hybrid=True` fuses both legs with reciprocal-rank fusion; without it the vector leg is used when available,
    else the keyword leg. The keyword leg ORs the query's terms (stemmed with `fts_config`), ranked by ts_rank_cd."""
    name = "app"

    def __init__(self, table: str, *, key_column: str, text_column: str, embedding_column: str = "",
                 embedder: Callable[[str], list[float]] | None = None, distance: str = "cosine", fts_config: str = "english"):
        if distance not in _OPS:
            raise ValueError(f"distance must be one of {sorted(_OPS)}")
        self.schema, _, self.table = table.rpartition(".")
        self.schema = self.schema or "public"
        self.key_column, self.text_column, self.embedding_column = key_column, text_column, embedding_column
        self.embedder, self.distance, self.fts_config = embedder, distance, fts_config

    def _from(self) -> sql.Composed:
        return sql.SQL("{}.{} src").format(sql.Identifier(self.schema), sql.Identifier(self.table))

    def _vector_leg(self, conn, query, n, filters) -> list[Hit]:
        where, params = aidb._where(filters, "src")
        emb = sql.Identifier("src", self.embedding_column)
        vec = _vector_literal(self.embedder(query))                    # type: ignore[misc]
        op = sql.SQL(_OPS[self.distance])
        q = sql.SQL("SELECT src.{k}::text AS key, src.{t} AS text, {e} {op} %s::vector AS distance FROM {f} "
                    "WHERE {e} IS NOT NULL AND {w} ORDER BY {e} {op} %s::vector LIMIT %s").format(
            k=sql.Identifier(self.key_column), t=sql.Identifier(self.text_column), e=emb, op=op, f=self._from(), w=where)
        with conn.transaction():
            aidb._one(conn, "SELECT set_config('hnsw.iterative_scan', 'relaxed_order', true)")
            rows = aidb._rows(conn, q, (vec, *params, vec, n))
        return [Hit(r["key"], r["text"], 1.0 / (1.0 + float(r["distance"])), float(r["distance"]), self.name) for r in rows]

    def _keyword_leg(self, conn, query, n, filters) -> list[Hit]:
        where, params = aidb._where(filters, "src")
        t = sql.Identifier("src", self.text_column)
        q = sql.SQL("SELECT src.{k}::text AS key, src.{tc} AS text, ts_rank_cd(to_tsvector(%s::regconfig, {t}), q.tq) AS rank "
                    "FROM {f}, (SELECT replace(plainto_tsquery(%s::regconfig, %s)::text, '&', '|')::tsquery AS tq) q "
                    "WHERE to_tsvector(%s::regconfig, {t}) @@ q.tq AND {w} ORDER BY rank DESC LIMIT %s").format(
            k=sql.Identifier(self.key_column), tc=sql.Identifier(self.text_column), t=t, f=self._from(), w=where)
        # the filter parameters sit in the WHERE clause, after the four regconfig/query parameters that precede it
        rows = aidb._rows(conn, q, (self.fts_config, self.fts_config, query, self.fts_config, *params, n))
        return [Hit(r["key"], r["text"], float(r["rank"]), None, self.name) for r in rows]

    def retrieve(self, conn, query, k=5, *, filters=None, hybrid=False) -> list[Hit]:
        if k < 1:
            raise ValueError("k must be positive")
        vector: list[Hit] = []
        use_vector = bool(self.embedder and self.embedding_column)
        if use_vector:
            try:
                vector = self._vector_leg(conn, query, k * 5 if hybrid else k, filters)
            except Exception as exc:                                    # embedder down, bad column, ...: keyword leg answers
                log.warning("app retrieval: vector leg failed (%s); using keyword search", str(exc).splitlines()[0][:200])
                if isinstance(exc, psycopg.Error):
                    conn.rollback()
                use_vector = False
        if use_vector and not hybrid:
            return vector[:k]
        keyword = self._keyword_leg(conn, query, k * 5 if hybrid else k, filters)
        if not use_vector or not hybrid:
            return keyword[:k]
        fused = aidb.rrf([[h.key for h in vector], [h.key for h in keyword]])
        by_key = {h.key: h for h in keyword}
        by_key.update({h.key: h for h in vector})                     # the vector hit carries the distance
        return [Hit(h.key, h.text, fused[h.key], h.distance, self.name)
                for h in sorted(by_key.values(), key=lambda h: -fused[h.key])][:k]


class AidbRetrieval:
    """Retrieval from an AIDB knowledge base, identified as `schema.table` (for example `public.pipeline_policy`; the identifier
    `aidb.ensure_pipeline` returns). `rerank_model` names a registered reranking model to reorder candidates."""
    name = "aidb"

    def __init__(self, kb: str, *, rerank_model: str = "", fts_config: str = "english"):
        self.kb, self.rerank_model, self.fts_config = kb, rerank_model, fts_config

    def retrieve(self, conn, query, k=5, *, filters=None, hybrid=False) -> list[Hit]:
        rows = aidb.retrieve(conn, self.kb, query, k, filters=filters, hybrid=hybrid, fts_config=self.fts_config,
                             rerank_model=self.rerank_model)
        return [Hit(r["key"], r["text"], float(r["score"]), r["distance"], self.name) for r in rows]


def requested_backend(prefix: str) -> str:
    """The value of `<PREFIX>_RETRIEVAL_BACKEND`, defaulting to `app`; an unknown value is logged and treated as `app`."""
    var = f"{prefix}_RETRIEVAL_BACKEND"
    raw = (os.environ.get(var) or "app").strip().lower()
    if raw not in BACKENDS:
        log.error("%s=%r is not one of %s; using the app backend", var, raw, "|".join(BACKENDS))
        return "app"
    return raw


def select(prefix: str, *, app: Retrieval, aidb: AidbRetrieval | None = None,
           connect: Callable[[], psycopg.Connection] | None = None) -> Retrieval:
    """Pick the backend named by `<PREFIX>_RETRIEVAL_BACKEND` (default `app`). For `aidb`, checks through `connect` that AIDB is
    usable and the knowledge base exists; otherwise logs an ERROR with the reason and returns `app`. Call it at start-up (after
    the pipeline was ensured), not per request."""
    want = requested_backend(prefix)
    if want == "app":
        return app
    reason = ""
    if aidb is None:
        reason = "the app configured no AIDB knowledge base"
    elif connect is None:
        reason = "no connection factory was given to check AIDB"
    else:
        try:
            conn = connect()
            try:
                st = _detect(conn)
                if not st.available:
                    reason = st.reason
                elif not _kb_exists(conn, aidb.kb):
                    reason = f"knowledge base {aidb.kb!r} does not exist (run the pipeline setup)"
            finally:
                conn.close()
        except Exception as exc:
            reason = f"could not check AIDB: {str(exc).splitlines()[0][:200]}"
    if reason:
        log.error("RETRIEVAL BACKEND FALLBACK: %s_RETRIEVAL_BACKEND=aidb but %s; using the app backend", prefix, reason)
        return app
    log.info("%s retrieval backend: aidb (%s)", prefix, aidb.kb)
    return aidb


# indirection so the argument named `aidb` in select() does not shadow the module
_detect = aidb.detect
_kb_exists = aidb.kb_exists
