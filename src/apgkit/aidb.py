"""EDB AI Accelerator (AIDB) helpers: detect it, register models, keep knowledge bases live over an app table, retrieve, confine agents
with purposes, register SQL tools, run agents, and report health. Everything degrades cleanly on plain Postgres.

Conventions
- Every helper takes a psycopg connection (the kit's `Database.connect()`; dict rows or tuple rows both work).
- `ensure_*` helpers are idempotent: they read the catalog first, change only what differs and return what they did
  (`"created"`, `"updated"` or `"unchanged"`). They commit at the end (`commit=False` leaves that to the caller).
  A definition that differs in a way AIDB cannot update in place raises `AidbConflict` unless `replace=True`.
- All SQL is parameterised or built with `psycopg.sql` identifiers; no value is formatted into a statement. Secrets are read
  with `config.read_secret`, sent as bind parameters and never logged (errors are scrubbed of the value).
- Authority-bearing definitions (models, credentials' host restriction, pipelines, purposes with their role's grants, SQL tools,
  agents) can be sealed with a MAC under the vault's data key (`vault=`), and `verify(conn, vault)` reports any definition changed
  by a database write that did not go through the code path. This detects; it does not prevent (see GUIDE "AIDB layer").

Verified against AIDB 7.9.0 (Docker image aidb-postgres:17). Catalog views used: aidb.knowledge_bases, aidb.pipelines,
aidb.pipeline_metrics, aidb.models, aidb.credentials, aidb.agents, aidb.purpose_registry, aidb.sql_tool_registry, aidb.tools,
aidb_otel.traces.
"""
from __future__ import annotations

import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from .config import read_secret

LOCAL_EMBEDDING_MODEL = "bge-small-en-v1.5-f16"      # pre-registered by AIDB, 384 dimensions, no key
DISTANCE_OPERATORS = {"Cosine": "<=>", "L2": "<->", "InnerProduct": "<#>", "L1": "<+>"}
_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_CONFIG_HELPERS = {"embeddings_config", "completions_config", "openai_responses_config", "anthropic_messages_config",
                   "gemini_config", "nim_clip_config", "nim_ocr_config", "nim_reranking_config", "openrouter_chat_config",
                   "openrouter_embeddings_config"}


class AidbError(RuntimeError):
    pass


class AidbUnavailable(AidbError):
    """AIDB is not installed, or this role may not use it."""


class AidbConflict(AidbError):
    """An existing object differs from the requested definition and cannot be changed in place."""


class AidbTampered(AidbError):
    """A sealed definition no longer matches its MAC."""


def check_name(name: str, what: str = "name") -> str:
    """Names used for AIDB objects and roles: lower-case letters, digits, underscore; at most 63 bytes."""
    if not isinstance(name, str) or not _NAME.match(name):
        raise ValueError(f"bad {what} {name!r}: use lower-case letters, digits and underscores, starting with a letter or _")
    return name


def _rows(conn: psycopg.Connection, query, params=None) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(query, params)
        if cur.description is None:
            return []
        cols = [d.name for d in cur.description]
        return [r if isinstance(r, dict) else dict(zip(cols, r)) for r in cur.fetchall()]


def _one(conn: psycopg.Connection, query, params=None) -> dict[str, Any] | None:
    rows = _rows(conn, query, params)
    return rows[0] if rows else None


def _call(conn: psycopg.Connection, query, params=None, *, secret: str = "") -> list[dict[str, Any]]:
    """Run a statement, turning a database error into AidbError (privilege errors get a hint) and scrubbing `secret` from it."""
    try:
        return _rows(conn, query, params)
    except psycopg.errors.InsufficientPrivilege as exc:
        conn.rollback()
        raise AidbError(f"permission denied: {_scrub(str(exc), secret)} (grant aidb_users, or aidb_governance for purposes and "
                        "decision records, or CREATEROLE for purpose roles)") from None
    except psycopg.Error as exc:
        conn.rollback()
        raise AidbError(_scrub(str(exc).strip(), secret)) from None


def _scrub(text: str, secret: str) -> str:
    return text.replace(secret, "[redacted]") if secret else text


def _qual(name: str, default_schema: str = "public") -> tuple[str, str]:
    schema, _, table = name.rpartition(".")
    return (schema or default_schema), table


def _ident(schema: str, table: str) -> sql.Composed:
    return sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(table))


def _log(msg: str) -> None:
    print(f"apgkit.aidb: {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Status:
    available: bool                    # installed and this role may call it
    installed: bool = False            # the extension exists in this database
    installable: bool = False          # the server offers it (CREATE EXTENSION would work for a privileged role)
    version: str = ""
    pgvector: str = ""
    can_use: bool = False              # USAGE on schema aidb and EXECUTE on retrieve_text
    can_govern: bool = False           # member of aidb_governance (purposes, decision records)
    can_read_telemetry: bool = False   # SELECT on aidb_otel.traces
    can_create_roles: bool = False     # CREATEROLE or superuser (purpose roles)
    otel_client: str = ""              # aidb.otel_client as seen by this session ('database' records decisions)
    reason: str = ""                   # why unavailable, in words

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def at_least(self, version: str) -> bool:
        return version_tuple(self.version) >= version_tuple(version)


def version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v)[:3])


def detect(conn: psycopg.Connection) -> Status:
    """Is AIDB here, which version, and what may the connected role do? Never raises for a missing extension or a missing
    privilege (a plain Postgres answers `available=False` with a reason); the connection stays usable."""
    try:
        with conn.transaction():
            ext = _one(conn, "SELECT (SELECT extversion FROM pg_extension WHERE extname = 'aidb') AS version, "
                             "EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'aidb') AS installable, "
                             "(SELECT extversion FROM pg_extension WHERE extname = 'vector') AS vector, "
                             "(SELECT rolcreaterole OR rolsuper FROM pg_roles WHERE rolname = current_user) AS roles") or {}
            if not ext.get("version"):
                why = ("the aidb extension is available but not created in this database (CREATE EXTENSION aidb)"
                       if ext.get("installable") else "the aidb extension is not installed on this server")
                return Status(False, installable=bool(ext.get("installable")), pgvector=ext.get("vector") or "", reason=why)
            priv = _one(conn, """
                SELECT has_schema_privilege(current_user, 'aidb', 'USAGE')
                       AND has_function_privilege(current_user, 'aidb.retrieve_text(text, text, integer, boolean)', 'EXECUTE') AS can_use,
                       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aidb_governance')
                            THEN pg_has_role(current_user, 'aidb_governance', 'USAGE') ELSE false END AS can_govern,
                       CASE WHEN EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'aidb_otel')
                                 AND has_schema_privilege(current_user, 'aidb_otel', 'USAGE')
                            THEN COALESCE(has_table_privilege(current_user, to_regclass('aidb_otel.traces'), 'SELECT'), false)
                            ELSE false END AS can_read_telemetry,
                       current_setting('aidb.otel_client', true) AS otel
            """) or {}
    except psycopg.Error as exc:
        return Status(False, reason=f"could not inspect the database: {str(exc).strip().splitlines()[0][:200]}")
    can_use = bool(priv.get("can_use"))
    return Status(available=can_use, installed=True, installable=True, version=ext["version"], pgvector=ext.get("vector") or "",
                  can_use=can_use, can_govern=bool(priv.get("can_govern")), can_read_telemetry=bool(priv.get("can_read_telemetry")),
                  can_create_roles=bool(ext.get("roles")), otel_client=priv.get("otel") or "",
                  reason="" if can_use else "aidb is installed but this role lacks USAGE on schema aidb / EXECUTE on its functions "
                                            "(ask for `GRANT aidb_users TO <role>`)")


def require(conn: psycopg.Connection, *, min_version: str = "") -> Status:
    st = detect(conn)
    if not st.available:
        raise AidbUnavailable(st.reason)
    if min_version and not st.at_least(min_version):
        raise AidbUnavailable(f"AIDB {st.version} is older than the required {min_version}")
    return st


# ---------------------------------------------------------------------------------------------------------------------
# Sealing: a MAC over each authority-bearing definition (see module docstring)
# ---------------------------------------------------------------------------------------------------------------------
SEAL_SQL = """
CREATE TABLE IF NOT EXISTS apgkit_aidb_seal (
  kind text NOT NULL, name text NOT NULL, mac text NOT NULL, sealed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, name));
"""
SEAL_TABLE = "apgkit_aidb_seal"
SEAL_KINDS = ("model", "credential", "pipeline", "purpose", "sql_tool", "agent")


def _jsonable(v: Any) -> Any:
    return v if v is None or isinstance(v, (str, int, float, bool, list, dict)) else str(v)


def definition(conn: psycopg.Connection, kind: str, name: str) -> list[str] | None:
    """The canonical fields of one object as the catalog holds them now (None when it does not exist)."""
    import json
    if kind == "model":
        r = _one(conn, "SELECT provider, options::text AS options, credential FROM aidb.models WHERE name = %s", (name,))
        return None if r is None else ["model", name, r["provider"], r["options"], r["credential"]]
    if kind == "credential":
        r = _one(conn, "SELECT endpoint, shared FROM aidb.credentials WHERE name = %s", (name,))
        return None if r is None else ["credential", name, r["endpoint"], str(r["shared"])]
    if kind == "pipeline":
        r = _one(conn, "SELECT source_schema, source, source_key_column, source_data_column, steps::text AS steps, "
                       "destination_schema, destination FROM aidb.pipelines WHERE name = %s", (name,))
        return None if r is None else ["pipeline", name, *(str(r[k]) for k in
                ("source_schema", "source", "source_key_column", "source_data_column", "steps", "destination_schema", "destination"))]
    if kind == "purpose":
        r = _one(conn, "SELECT role, deleted_at IS NOT NULL AS retired FROM aidb.purpose_registry WHERE name = %s", (name,))
        if r is None:
            return None
        return ["purpose", name, r["role"], str(r["retired"]), json.dumps(role_grants(conn, r["role"]), sort_keys=True)]
    if kind == "sql_tool":
        r = _one(conn, "SELECT description, query_text, read_only, "
                       "(SELECT COALESCE(jsonb_agg(to_jsonb(p)), '[]'::jsonb)::text FROM unnest(params) p) AS params "
                       "FROM aidb.sql_tool_registry WHERE name = %s", (name,))
        return None if r is None else ["sql_tool", name, r["description"], r["query_text"], str(r["read_only"]), r["params"]]
    if kind == "agent":
        r = _one(conn, "SELECT instructions, model, tools, delegates, purpose, output_type::text AS output_type, input_token_budget, "
                       "output_token_budget, max_iterations, timeout_seconds, budget_strategy::text AS budget, plugins "
                       "FROM aidb.agents WHERE name = %s", (name,))
        return None if r is None else ["agent", name, *(json.dumps(_jsonable(r[k])) for k in
                ("instructions", "model", "tools", "delegates", "purpose", "output_type", "input_token_budget", "output_token_budget",
                 "max_iterations", "timeout_seconds", "budget", "plugins"))]
    raise ValueError(f"unknown kind {kind!r}")


def _seal_table(conn: psycopg.Connection) -> None:
    conn.execute(SEAL_SQL)


def seal(conn: psycopg.Connection, vault, kind: str, name: str) -> bool:
    """Record the MAC of the object's current definition. Returns False when the object does not exist."""
    fields = definition(conn, kind, name)
    if fields is None:
        return False
    _seal_table(conn)
    conn.execute("INSERT INTO apgkit_aidb_seal (kind, name, mac) VALUES (%s, %s, %s) "
                 "ON CONFLICT (kind, name) DO UPDATE SET mac = EXCLUDED.mac, sealed_at = now()",
                 (kind, name, vault.row_mac(SEAL_TABLE, *fields)))
    return True


def unseal(conn: psycopg.Connection, kind: str, name: str) -> None:
    _seal_table(conn)
    conn.execute("DELETE FROM apgkit_aidb_seal WHERE kind = %s AND name = %s", (kind, name))


def _guard(conn: psycopg.Connection, vault, kind: str, name: str, reseal: bool) -> None:
    """Before changing an existing sealed object: refuse when it no longer matches its seal (someone edited it)."""
    if vault is None or reseal:
        return
    _seal_table(conn)
    row = _one(conn, "SELECT mac FROM apgkit_aidb_seal WHERE kind = %s AND name = %s", (kind, name))
    fields = definition(conn, kind, name)
    if row is not None and fields is not None and not vault.check_row_mac(SEAL_TABLE, row["mac"], *fields):
        raise AidbTampered(f"{kind} {name!r} was changed outside the app (its seal does not match); inspect it, then call again "
                           "with reseal=True to accept the current state")


def _finish(conn: psycopg.Connection, vault, kind: str, name: str, commit: bool) -> None:
    if vault is not None:
        seal(conn, vault, kind, name)
    if commit:
        conn.commit()


@dataclass
class Drift:
    kind: str
    name: str
    problem: str            # modified | missing | unsealed


def verify(conn: psycopg.Connection, vault, *, strict: bool = True, ignore: Sequence[tuple[str, str]] = ()) -> list[Drift]:
    """Compare every sealed definition with the catalog. `strict` also reports agents, purposes and SQL tools that carry no seal
    (planted objects, or a deleted seal row). Empty list = nothing changed behind the app's back. Raises VaultLocked if the vault is locked."""
    _seal_table(conn)
    out: list[Drift] = []
    seen: set[tuple[str, str]] = set()
    for row in _rows(conn, "SELECT kind, name, mac FROM apgkit_aidb_seal ORDER BY kind, name"):
        key = (row["kind"], row["name"])
        seen.add(key)
        if key in ignore or row["kind"] not in SEAL_KINDS:
            continue
        fields = definition(conn, row["kind"], row["name"])
        if fields is None:
            out.append(Drift(*key, "missing"))
        elif not vault.check_row_mac(SEAL_TABLE, row["mac"], *fields):
            out.append(Drift(*key, "modified"))
    if strict:
        for kind, query in (("agent", "SELECT name FROM aidb.agents"), ("purpose", "SELECT name FROM aidb.purpose_registry WHERE deleted_at IS NULL"),
                            ("sql_tool", "SELECT name FROM aidb.sql_tool_registry")):
            for r in _rows(conn, query):
                if (kind, r["name"]) not in seen and (kind, r["name"]) not in ignore:
                    out.append(Drift(kind, r["name"], "unsealed"))
    conn.commit()
    return out


# ---------------------------------------------------------------------------------------------------------------------
# Credentials and models
# ---------------------------------------------------------------------------------------------------------------------
def ensure_credential(conn: psycopg.Connection, name: str, *, endpoint: str, secret_env: str = "", secret: str = "",
                      secret_key: str = "api_key", rotate: bool = False, share: bool = False, vault=None, reseal: bool = False,
                      commit: bool = True) -> str:
    """A named AIDB credential holding one secret, limited to `endpoint` (an AIDB endpoint pattern such as `gw.example.com`).
    The secret is `secret`, else `read_secret(secret_env)`; it travels as a bind parameter and is never logged. AIDB cannot return a
    stored secret, so an existing credential keeps its secret unless `rotate=True` (or it has none)."""
    check_name(name, "credential name")
    value = secret or (read_secret(secret_env) if secret_env else "")
    cur = _one(conn, "SELECT endpoint, shared, has_secret FROM aidb.credentials WHERE name = %s", (name,))
    if cur is None:
        if not value:
            raise AidbError(f"credential {name!r}: no secret (set {secret_env or 'the secret'} or pass secret=)")
        _call(conn, "SELECT aidb.create_credential(name => %s, credentials => %s, endpoint => %s, share => %s)",
              (name, Jsonb({secret_key: value}), endpoint, share), secret=value)
        _finish(conn, vault, "credential", name, commit)
        return "created"
    _guard(conn, vault, "credential", name, reseal)
    sets: list[str] = []
    args: dict[str, Any] = {}
    if cur["endpoint"] != endpoint:
        sets.append("endpoint")
        args["endpoint"] = endpoint
    if bool(cur["shared"]) != share:
        sets.append("share")
        args["share"] = share
    if value and (rotate or not cur["has_secret"]):
        sets.append("credentials")
        args["credentials"] = Jsonb({secret_key: value})
    if sets:
        q = sql.SQL("SELECT aidb.update_credential(name => %s, {})").format(
            sql.SQL(", ").join(sql.SQL("{} => %s").format(sql.Identifier(k)) for k in args))
        _call(conn, q, (name, *args.values()), secret=value)
    _finish(conn, vault, "credential", name, commit)
    return "updated" if sets else "unchanged"


def _model_config(conn: psycopg.Connection, helper: str, config: Mapping[str, Any]) -> dict[str, Any]:
    if helper not in _CONFIG_HELPERS:
        raise ValueError(f"unsupported config helper {helper!r}")
    args = {k: v for k, v in config.items() if v is not None}
    q = sql.SQL("SELECT aidb.{}({}) AS cfg").format(sql.Identifier(helper), sql.SQL(", ").join(
        sql.SQL("{} => %s").format(sql.Identifier(check_name(k, "config key"))) for k in args))
    row = _one(conn, q, tuple(args.values()))
    import json
    cfg = row["cfg"] if row else {}
    return cfg if isinstance(cfg, dict) else json.loads(cfg)


def _stored_config(options: Sequence[str] | None) -> dict[str, Any]:
    import json
    for item in options or ():
        if item.startswith("config="):
            try:
                return json.loads(item[len("config="):])
            except ValueError:
                return {}
    return {}


def ensure_model(conn: psycopg.Connection, name: str, provider: str, *, config_helper: str = "", config: Mapping[str, Any] | None = None,
                 credential: str = "", replace: bool = False, validate: bool | None = None, vault=None,
                 reseal: bool = False, commit: bool = True) -> str:
    """Register a model. `config_helper` names the `aidb.*_config` function (for example `embeddings_config`) and `config` its named
    arguments; with no helper, `config` is stored as given (local providers take plain JSON, for example `llamacpp_reranking`). An existing model with a different provider, config or credential raises `AidbConflict` (AIDB has no update_model);
    `replace=True` deletes and recreates it (this fails while a pipeline still uses it)."""
    check_name(name.replace("-", "_").replace(".", "_"), "model name")
    cfg = _model_config(conn, config_helper, config or {}) if config_helper else dict(config or {})
    cur = _one(conn, "SELECT provider, options, credential FROM aidb.models WHERE name = %s", (name,))
    if cur is not None:
        _guard(conn, vault, "model", name, reseal)
        stored = _stored_config(cur["options"])
        same = (cur["provider"] == provider and all(stored.get(k) == v for k, v in cfg.items())
                and (not credential or cur["credential"] == credential))
        if same:
            _finish(conn, vault, "model", name, commit)
            return "unchanged"
        if not replace:
            raise AidbConflict(f"model {name!r} exists with a different definition; pass replace=True to recreate it")
        _call(conn, "SELECT aidb.delete_model(%s)", (name,))
    args: list[Any] = [name, provider]
    q = "SELECT aidb.create_model(name => %s, provider => %s"
    if cfg:
        q += ", config => %s"
        args.append(Jsonb(cfg))
    if credential:
        q += ", credential => %s"
        args.append(credential)
    if validate is not None:                       # AIDB calls the endpoint at creation unless told not to
        q += ", validate => %s"
        args.append(validate)
    _call(conn, q + ")", tuple(args))
    _finish(conn, vault, "model", name, commit)
    return "updated" if cur is not None else "created"


def ensure_gateway_model(conn: psycopg.Connection, name: str, *, kind: str, model: str, base_url: str,
                         credential: str = "llm_gateway", secret_env: str = "LLM_API_KEY", rotate: bool = False,
                         extra: Mapping[str, Any] | None = None, validate: bool | None = None, vault=None, reseal: bool = False,
                         commit: bool = True) -> dict[str, str]:
    """Register an OpenAI-compatible model that points at the ecosystem's llm-gateway (`base_url` is the gateway's `/v1` URL; the key
    is `read_secret(secret_env)` stored in an AIDB credential limited to the gateway's host). `kind` is `embeddings` or `chat`.
    Chat models use the `openai_completions` provider: AIDB then simulates tool calling in the prompt text (the gateway does not
    serve the Responses API). `validate=True/False` tells AIDB whether to call the endpoint while registering (default: AIDB's own
    choice, which does call it). AIDB refuses plain http egress unless the server sets `aidb.allow_insecure_egress` (loopback and
    private targets only), so a gateway URL must be https in production. Returns the actions taken: {"credential": ..., "model": ...}."""
    if kind not in ("embeddings", "chat"):
        raise ValueError("kind must be 'embeddings' or 'chat'")
    base = base_url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise ValueError("base_url must be an http(s) URL")
    provider, helper, path = (("openai_embeddings", "embeddings_config", "/embeddings") if kind == "embeddings"
                              else ("openai_completions", "completions_config", "/chat/completions"))
    url = base + path
    host = _one(conn, "SELECT aidb.endpoint_host(%s, %s) AS h", (provider, url))["h"]
    cred = ensure_credential(conn, credential, endpoint=host, secret_env=secret_env, rotate=rotate, share=False,
                             vault=vault, reseal=reseal, commit=False)
    mdl = ensure_model(conn, name, provider, config_helper=helper, config={"model": model, "url": url, **(extra or {})},
                       credential=credential, validate=validate, vault=vault, reseal=reseal, commit=False)
    if commit:
        conn.commit()
    return {"credential": cred, "model": mdl}


# ---------------------------------------------------------------------------------------------------------------------
# Pipelines and knowledge bases
# ---------------------------------------------------------------------------------------------------------------------
@dataclass
class PipelineInfo:
    action: str                 # created | updated | unchanged
    pipeline: str
    kb: str                     # the knowledge base identifier to retrieve from (schema.table), not the deprecated pipeline name
    backfilled: bool = False


def kb_for_pipeline(conn: psycopg.Connection, pipeline: str) -> str | None:
    r = _one(conn, "SELECT name FROM aidb.knowledge_bases WHERE %s = ANY (pipeline_names) ORDER BY id LIMIT 1", (pipeline,))
    return r["name"] if r else None


def ensure_pipeline(conn: psycopg.Connection, name: str, *, source: str, key_column: str, text_column: str,
                    model: str = LOCAL_EMBEDDING_MODEL, distance: str = "Cosine", live: bool = True, backfill: bool = True,
                    chunk: Mapping[str, int | str] | None = None, replace: bool = False, vault=None, reseal: bool = False,
                    commit: bool = True) -> PipelineInfo:
    """A pipeline that embeds `source.text_column` (keyed by `key_column`) into a knowledge base, in `Live` mode so new and changed
    rows are embedded by the database with no app code. Existing rows are embedded once (`backfill`). `chunk` (for example
    `{"desired_length": 500, "overlap_length": 50}`) adds a ChunkText step first. Repeating the call changes nothing; a different
    source, columns, model, distance or chunking raises `AidbConflict` unless `replace=True` (which deletes the knowledge base
    and rebuilds it)."""
    check_name(name, "pipeline name")
    if distance not in DISTANCE_OPERATORS:
        raise ValueError(f"distance must be one of {sorted(DISTANCE_OPERATORS)}")
    schema, table = _qual(source)
    ops = (["ChunkText"] if chunk else []) + ["KnowledgeBase"]
    cur = _one(conn, "SELECT source_schema, source, source_key_column, source_data_column, steps, auto_processing::text AS mode "
                     "FROM aidb.pipelines WHERE name = %s", (name,))
    action, backfilled = "unchanged", False
    if cur is not None:
        _guard(conn, vault, "pipeline", name, reseal)
        kb = kb_for_pipeline(conn, name)
        kbrow = _one(conn, "SELECT model_name, distance_operator::text AS dist FROM aidb.knowledge_bases WHERE name = %s", (kb,)) or {}
        steps = cur["steps"] if isinstance(cur["steps"], list) else []
        kb_step = next((s for s in steps if s.get("operation") == "KnowledgeBase"), {})
        same = ((cur["source_schema"], cur["source"], cur["source_key_column"], cur["source_data_column"]) == (schema, table, key_column, text_column)
                and [s.get("operation") for s in steps] == ops and kbrow.get("model_name") == model and kbrow.get("dist") == distance
                and kb_step.get("options", {}).get("model", model) == model)
        if same and chunk:
            c = next((s for s in steps if s.get("operation") == "ChunkText"), {}).get("options", {})
            same = all(c.get(k) == v for k, v in chunk.items())
        if not same:
            if not replace:
                raise AidbConflict(f"pipeline {name!r} exists with a different definition; pass replace=True to rebuild it")
            _call(conn, "SELECT aidb.delete_knowledge_base(%s)", (kb,)) if kb else _call(conn, "SELECT aidb.delete_pipeline(%s)", (name,))
            cur = None
            action = "updated"
    if cur is None:
        args: list[Any] = [name, f"{schema}.{table}", key_column, text_column, "Live" if live else "Disabled", model, distance]
        q = ("SELECT aidb.create_pipeline(name => %s, source => %s, source_key_column => %s, source_data_column => %s, "
             "auto_processing => %s::aidb.pipelineautoprocessingmode, ")
        kb_cfg = "aidb.knowledge_base_config(model => %s, data_format => 'Text', distance_operator => %s::aidb.distanceoperator)"
        if chunk:
            cfg_args = ", ".join(f"{check_name(k, 'chunk option')} => %s" for k in chunk)
            q += f"step_1 => 'ChunkText', step_1_options => aidb.chunk_text_config({cfg_args}), step_2 => 'KnowledgeBase', step_2_options => {kb_cfg})"
            args[5:5] = list(chunk.values())
        else:
            q += f"step_1 => 'KnowledgeBase', step_1_options => {kb_cfg})"
        _call(conn, q, tuple(args))
        action = action if action == "updated" else "created"
        if backfill:
            _call(conn, "SELECT aidb.run_pipeline(%s)", (name,))
            backfilled = True
    else:
        if live and cur["mode"] != "Live":
            _call(conn, "SELECT aidb.update_pipeline(name => %s, auto_processing => 'Live')", (name,))
            action = "updated"
        if backfill and _unprocessed(conn, name) > 0:
            _call(conn, "SELECT aidb.run_pipeline(%s)", (name,))
            backfilled = True
    kb = kb_for_pipeline(conn, name)
    if kb is None:
        raise AidbError(f"pipeline {name!r} has no knowledge base")
    _finish(conn, vault, "pipeline", name, commit)
    return PipelineInfo(action, name, kb, backfilled)


def _unprocessed(conn: psycopg.Connection, pipeline: str) -> int:
    r = _one(conn, 'SELECT "table: unprocessed rows" AS n FROM aidb.pipeline_metrics WHERE pipeline = %s', (pipeline,))
    return int(r["n"] or 0) if r else 0


def refresh_pipeline(conn: psycopg.Connection, name: str, *, commit: bool = True) -> dict[str, Any]:
    """Process every row not yet embedded (what Live mode does continuously) and return the pipeline's status."""
    _call(conn, "SELECT aidb.run_pipeline(%s)", (name,))
    if commit:
        conn.commit()
    return pipeline_status(conn, name)[0]


def drop_pipeline(conn: psycopg.Connection, name: str, *, commit: bool = True) -> None:
    kb = kb_for_pipeline(conn, name)
    _call(conn, "SELECT aidb.delete_knowledge_base(%s)", (kb,)) if kb else _call(conn, "SELECT aidb.delete_pipeline(%s)", (name,))
    unseal(conn, "pipeline", name)
    if commit:
        conn.commit()


def pipeline_status(conn: psycopg.Connection, name: str | None = None) -> list[dict[str, Any]]:
    """Per pipeline: mode, rows waiting (`lag`), source and destination counts, AIDB's status, error counts, last run."""
    rows = _rows(conn, """
        SELECT pipeline AS name, "auto processing" AS mode, COALESCE("table: unprocessed rows", 0) AS lag,
               "count(source records)" AS source_rows, "count(destination records)" AS embedded_rows, "Status" AS status,
               COALESCE("count(record errors)", 0) AS record_errors, COALESCE("count(blocking errors)", 0) AS blocking_errors,
               "last run completed" AS last_run
        FROM aidb.pipeline_metrics WHERE (%s::text IS NULL OR pipeline = %s) ORDER BY pipeline""", (name, name))
    for r in rows:
        r["kb"] = kb_for_pipeline(conn, r["name"])
    return rows


# ---------------------------------------------------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------------------------------------------------
@dataclass
class KbInfo:
    name: str
    vector_schema: str
    vector_table: str
    key_column: str
    data_column: str
    operator: str
    source_schema: str = ""
    source_table: str = ""
    source_key: str = ""
    source_text: str = ""


def kb_info(conn: psycopg.Connection, kb: str) -> KbInfo | None:
    r = _one(conn, "SELECT name, vector_schema, vector_table, vector_key_column, vector_data_column, distance_operator::text AS dist, "
                   "pipeline_names FROM aidb.knowledge_bases WHERE name = %s", (kb,))
    if r is None:
        return None
    info = KbInfo(r["name"], r["vector_schema"], r["vector_table"], r["vector_key_column"], r["vector_data_column"],
                  DISTANCE_OPERATORS.get(r["dist"], "<=>"))
    p = _one(conn, "SELECT source_schema, source, source_key_column, source_data_column FROM aidb.pipelines WHERE name = %s",
             ((r["pipeline_names"] or [""])[0],))
    if p:
        info.source_schema, info.source_table, info.source_key, info.source_text = (
            p["source_schema"], p["source"], p["source_key_column"], p["source_data_column"])
    return info


def kb_exists(conn: psycopg.Connection, kb: str) -> bool:
    return kb_info(conn, kb) is not None


def _where(filters: Mapping[str, Any] | None, alias: str) -> tuple[sql.Composable, list[Any]]:
    parts: list[sql.Composable] = []
    params: list[Any] = []
    for col, val in (filters or {}).items():
        if isinstance(val, (list, tuple, set, frozenset)):
            parts.append(sql.SQL("{}.{} = ANY (%s)").format(sql.Identifier(alias), sql.Identifier(col)))
            params.append(list(val))
        elif val is None:
            parts.append(sql.SQL("{}.{} IS NULL").format(sql.Identifier(alias), sql.Identifier(col)))
        else:
            parts.append(sql.SQL("{}.{} = %s").format(sql.Identifier(alias), sql.Identifier(col)))
            params.append(val)
    return (sql.SQL(" AND ").join(parts) if parts else sql.SQL("true")), params


def rrf(lists: Sequence[Sequence[str]], k: int = 60) -> dict[str, float]:
    """Reciprocal Rank Fusion over ranked key lists (best first)."""
    score: dict[str, float] = {}
    for keys in lists:
        for rank, key in enumerate(keys, start=1):
            score[key] = score.get(key, 0.0) + 1.0 / (k + rank)
    return score


def retrieve(conn: psycopg.Connection, kb: str, query: str, k: int = 5, *, filters: Mapping[str, Any] | None = None,
             hybrid: bool = False, fts_config: str = "english", rerank_model: str = "", deduplicate: bool = True) -> list[dict[str, Any]]:
    """Top-`k` source rows for `query` from the knowledge base `kb` (the identifier `schema.table`, for example
    `public.pipeline_docs`, never the pipeline name: that lookup is deprecated). Returns dicts with key (str), text, distance
    (vector distance, None for a keyword-only hit) and score (higher is better; reciprocal-rank fusion when hybrid).

    - plain: `aidb.retrieve_text`.
    - `filters` ({source column: value | list of values | None}): the knowledge base's vector table joined to the source table with
      the filter applied at the vector query level (pgvector iterative scans), per AIDB's hybrid-search guide.
    - `hybrid=True`: vector results fused (RRF) with PostgreSQL full-text search over the source text column.
    - `rerank_model`: a registered reranking model; candidates (3x k) are reordered with `aidb.rerank_text`.
    Not available for volume-sourced knowledge bases (no source table) except the plain form."""
    if k < 1:
        raise ValueError("k must be positive")
    pool = k * 3 if rerank_model else k
    if not filters and not hybrid:
        rows = _rows(conn, "SELECT key, value, distance FROM aidb.retrieve_text(%s, %s, %s, deduplicate => %s)",
                     (kb, query, pool, deduplicate))
        hits = [{"key": str(r["key"]), "text": r["value"], "distance": r["distance"], "score": 1.0 / (1.0 + float(r["distance"]))}
                for r in rows]
    else:
        info = kb_info(conn, kb)
        if info is None:
            raise AidbError(f"unknown knowledge base {kb!r}")
        if not info.source_table:
            raise AidbError(f"knowledge base {kb!r} has no source table: filters and hybrid search need one")
        hits = _filtered(conn, info, query, pool, filters, hybrid, fts_config)
    if rerank_model and hits:
        hits = _rerank(conn, rerank_model, query, hits)
    return hits[:k]


def _filtered(conn: psycopg.Connection, info: KbInfo, query: str, k: int, filters, hybrid: bool, fts_config: str) -> list[dict[str, Any]]:
    where, fparams = _where(filters, "src")
    src, vec = _ident(info.source_schema, info.source_table), _ident(info.vector_schema, info.vector_table)
    skey, stext = sql.Identifier(info.source_key), sql.Identifier(info.source_text)
    vkey, vdata = sql.Identifier(info.key_column), sql.Identifier(info.data_column)
    op = sql.SQL(info.operator)                      # from a fixed map, never user input
    semantic = sql.SQL("""
        WITH q AS MATERIALIZED (SELECT aidb.kb_query_encode(%s, %s)::vector AS v)
        SELECT kb.{vkey}::text AS key, src.{stext} AS text, kb.{vdata} {op} (SELECT v FROM q) AS distance
        FROM {vec} kb JOIN {src} src ON src.{skey}::text = kb.{vkey}::text
        WHERE {where}
        ORDER BY kb.{vdata} {op} (SELECT v FROM q)
        LIMIT %s""").format(vkey=vkey, stext=stext, vdata=vdata, op=op, vec=vec, src=src, skey=skey, where=where)
    with conn.transaction():
        _one(conn, "SELECT set_config('hnsw.iterative_scan', 'relaxed_order', true)")
        rows = _rows(conn, semantic, (info.name, query, *fparams, k * 5))
    best: dict[str, dict[str, Any]] = {}
    for r in rows:                                    # several chunks of one row: keep the closest
        if r["key"] not in best:
            best[r["key"]] = {"key": r["key"], "text": r["text"], "distance": float(r["distance"]), "score": 0.0}
    ranked = list(best.values())
    if hybrid:
        kw = _rows(conn, sql.SQL("""
            SELECT src.{skey}::text AS key, src.{stext} AS text
            FROM {src} src, (SELECT replace(plainto_tsquery(%s::regconfig, %s)::text, '&', '|')::tsquery AS tq) q
            WHERE to_tsvector(%s::regconfig, src.{stext}) @@ q.tq AND {where}
            ORDER BY ts_rank_cd(to_tsvector(%s::regconfig, src.{stext}), q.tq) DESC
            LIMIT %s""").format(skey=skey, stext=stext, src=src, where=where),
                   (fts_config, query, fts_config, *fparams, fts_config, k * 5))
        texts = {h["key"]: h for h in ranked}
        for r in kw:
            texts.setdefault(r["key"], {"key": r["key"], "text": r["text"], "distance": None, "score": 0.0})
        fused = rrf([[h["key"] for h in ranked], [r["key"] for r in kw]])
        out = sorted(texts.values(), key=lambda h: -fused[h["key"]])
        for h in out:
            h["score"] = fused[h["key"]]
        return out[:k]
    for h in ranked:
        h["score"] = 1.0 / (1.0 + h["distance"])
    return ranked[:k]


def _rerank(conn: psycopg.Connection, model: str, query: str, hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reorder `hits` by `aidb.rerank_text` (it returns each input with its position in `id` and a raw logit in `logit_score`)."""
    rows = _call(conn, "SELECT logit_score, id FROM aidb.rerank_text(%s, %s, %s::text[])", (model, query, [h["text"] or "" for h in hits]))
    if len(rows) != len(hits):
        raise AidbError(f"rerank_text returned {len(rows)} scores for {len(hits)} candidates")
    return [{**hits[r["id"]], "score": float(r["logit_score"])} for r in sorted(rows, key=lambda r: -float(r["logit_score"]))]


# ---------------------------------------------------------------------------------------------------------------------
# Governance: purposes and least-privilege roles
# ---------------------------------------------------------------------------------------------------------------------
def purpose_role_name(purpose: str) -> str:
    return f"aidb_p_{check_name(purpose, 'purpose')}"[:63]


def role_grants(conn: psycopg.Connection, role: str) -> list[list[str]]:
    """The relation privileges granted directly to `role`, sorted: [[schema, relation, privilege], ...]."""
    rows = _rows(conn, """
        SELECT n.nspname AS s, c.relname AS r, a.privilege_type AS p
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, LATERAL aclexplode(c.relacl) a
        WHERE a.grantee = (SELECT oid FROM pg_roles WHERE rolname = %s) AND c.relkind IN ('r', 'v', 'm', 'p', 'f')
        ORDER BY 1, 2, 3""", (role,))
    return [[r["s"], r["r"], r["p"]] for r in rows]


def ensure_purpose(conn: psycopg.Connection, purpose: str, *, read: Sequence[str] = (), write: Sequence[str] = (),
                   role: str = "", description: str = "", members: Sequence[str] | None = None, native_tools: Sequence[str] = (),
                   vault=None, reseal: bool = False, commit: bool = True) -> dict[str, Any]:
    """A purpose backed by its own NOLOGIN role that holds exactly the listed grants: SELECT on `read` relations, SELECT/INSERT/UPDATE
    on `write` relations (tables and views, `schema.name` or `name` in public), nothing else. Grants no longer listed are revoked,
    so repeating the call converges on the list. `members` (default: the connected role) are granted the role, because AIDB requires
    the caller of `agent_converse` to be a member of the purpose's role. `native_tools` adds USAGE on schema aidb and EXECUTE on
    those native tools plus the aidb_otel grants the doc requires (custom SQL tools need none). Registering the purpose needs
    `aidb_governance`; creating the role needs CREATEROLE. Returns {"role", "purpose", "changed": [...]}."""
    role = role or purpose_role_name(purpose)
    check_name(role, "role name")
    check_name(purpose, "purpose")
    changed: list[str] = []
    _guard(conn, vault, "purpose", purpose, reseal)
    if not _one(conn, "SELECT 1 AS x FROM pg_roles WHERE rolname = %s", (role,)):
        _call(conn, sql.SQL("CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS").format(sql.Identifier(role)))
        changed.append(f"role {role} created")
    desired: set[tuple[str, str, str]] = set()
    for rel in read:
        s, t = _qual(rel)
        desired.add((s, t, "SELECT"))
    for rel in write:
        s, t = _qual(rel)
        desired.update({(s, t, "SELECT"), (s, t, "INSERT"), (s, t, "UPDATE")})
    current = {tuple(g) for g in role_grants(conn, role) if g[0] != "aidb"}
    for s, t, p in sorted(current - desired):
        _call(conn, sql.SQL("REVOKE {} ON {} FROM {}").format(sql.SQL(p), _ident(s, t), sql.Identifier(role)))
        changed.append(f"revoked {p} on {s}.{t}")
    for s, t, p in sorted(desired - current):
        _call(conn, sql.SQL("GRANT {} ON {} TO {}").format(sql.SQL(p), _ident(s, t), sql.Identifier(role)))
        changed.append(f"granted {p} on {s}.{t}")
    for s in sorted({s for s, _, _ in desired}):
        if not _one(conn, "SELECT has_schema_privilege(%s, %s, 'USAGE') AS ok", (role, s))["ok"]:
            _call(conn, sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(s), sql.Identifier(role)))
            changed.append(f"granted USAGE on schema {s}")
    if native_tools:
        changed += _grant_native(conn, role, native_tools)
    who = [_one(conn, "SELECT current_user AS u")["u"]] if members is None else list(members)
    for m in who:
        if not _one(conn, "SELECT pg_has_role(%s, %s, 'MEMBER') AS ok", (m, role))["ok"]:
            _call(conn, sql.SQL("GRANT {} TO {}").format(sql.Identifier(role), sql.Identifier(m)))
            changed.append(f"granted {role} to {m}")
    reg = _one(conn, "SELECT role, description, deleted_at IS NOT NULL AS retired FROM aidb.purpose_registry WHERE name = %s", (purpose,))
    if reg is None or reg["retired"]:
        _call(conn, "SELECT aidb.create_purpose(%s, %s, %s)", (purpose, role, description or None))
        changed.append(f"purpose {purpose} registered")
    elif reg["role"] != role or (description and reg["description"] != description):
        _call(conn, "SELECT aidb.update_purpose(name => %s, role => %s, description => %s)", (purpose, role, description or None))
        changed.append(f"purpose {purpose} updated")
    _finish(conn, vault, "purpose", purpose, commit)
    return {"role": role, "purpose": purpose, "changed": changed}


def _grant_native(conn: psycopg.Connection, role: str, tools: Sequence[str]) -> list[str]:
    done: list[str] = []
    r = sql.Identifier(role)
    _call(conn, sql.SQL("GRANT USAGE ON SCHEMA aidb TO {}").format(r))
    _call(conn, sql.SQL("GRANT USAGE ON SCHEMA aidb_otel TO {}").format(r))
    for fn in _rows(conn, "SELECT p.oid::regprocedure::text AS sig FROM pg_proc p WHERE p.pronamespace = 'aidb_otel'::regnamespace "
                          "AND p.proname IN ('store_metrics', 'store_logs', 'store_traces')"):
        _call(conn, sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(sql.SQL(fn["sig"]), r))
    for tool in tools:
        check_name(tool, "tool name")
        sigs = _rows(conn, "SELECT p.oid::regprocedure::text AS sig FROM pg_proc p WHERE p.pronamespace = 'aidb'::regnamespace AND p.proname = %s", (tool,))
        if not sigs:
            raise AidbError(f"no native tool function aidb.{tool}")
        for fn in sigs:
            _call(conn, sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(sql.SQL(fn["sig"]), r))
        done.append(f"granted EXECUTE on aidb.{tool}")
    return done


def retire_purpose(conn: psycopg.Connection, purpose: str, *, commit: bool = True) -> None:
    _call(conn, "SELECT aidb.delete_purpose(%s)", (purpose,))
    if commit:
        conn.commit()


def enable_telemetry(conn: psycopg.Connection, *, persist: bool = True) -> None:
    """Record decisions in aidb_otel.traces (`aidb.otel_client = 'database'`). The exporter is chosen at the first aidb call of a
    backend, so `persist` sets it on the database (new sessions) and this session gets it too, which only helps if no aidb call ran yet.
    Needs to be the database owner for `persist`."""
    if persist:
        _call(conn, sql.SQL("ALTER DATABASE {} SET aidb.otel_client = 'database'").format(
            sql.Identifier(_one(conn, "SELECT current_database() AS d")["d"])))
    _one(conn, "SELECT set_config('aidb.otel_client', 'database', false)")
    conn.commit()


def _span_attrs(payload: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for rs in payload.get("resourceSpans") or []:
        for ss in rs.get("scopeSpans") or []:
            for span in ss.get("spans") or []:
                out["_name"] = span.get("name")
                for a in span.get("attributes") or []:
                    v = a.get("value") or {}
                    out[a.get("key")] = next(iter(v.values()), None) if v else None
    return out


def decisions(conn: psycopg.Connection, *, status: str = "denied", since: str = "24 hours", limit: int = 50) -> list[dict[str, Any]]:
    """Purpose decisions recorded by AIDB (needs `aidb.otel_client = 'database'` when they happened, and SELECT on aidb_otel.traces:
    the aidb_governance role). Newest first. Fields: recorded_at, decision_id, status, agent, principal, role, reason, sql, relations."""
    if status not in ("denied", "allowed"):
        raise ValueError("status must be 'denied' or 'allowed'")
    rows = _rows(conn, "SELECT recorded_at, decision_id, decision_status, agent_name, principal, payload_json FROM aidb_otel.traces "
                       "WHERE decision_status = %s AND source = 'internal' AND recorded_at > now() - %s::interval "
                       "ORDER BY id DESC LIMIT %s", (status, since, limit))
    out = []
    for r in rows:
        a = _span_attrs(r["payload_json"] or {})
        out.append({"recorded_at": r["recorded_at"], "decision_id": r["decision_id"], "status": r["decision_status"],
                    "agent": r["agent_name"], "principal": r["principal"] or a.get("aidb.agent.decision.principal"),
                    "role": a.get("aidb.agent.decision.agent_role"), "reason": a.get("aidb.agent.decision.denial_reason"),
                    "sql": a.get("db.query.text"), "attributes": a})
    return out


# ---------------------------------------------------------------------------------------------------------------------
# Custom SQL tools and agents
# ---------------------------------------------------------------------------------------------------------------------
def ensure_sql_tool(conn: psycopg.Connection, name: str, *, description: str, sql_statement: str,
                    params: Mapping[str, tuple[str, str]] | None = None, read_only: bool = True, replace: bool = True,
                    vault=None, reseal: bool = False, commit: bool = True) -> str:
    """Register a parameterised SQL tool. `sql_statement` uses `${name}` placeholders AIDB binds as real parameters; `params` maps a
    placeholder name to (SQL type, description). Read-only is enforced by AIDB at registration. A tool whose definition differs is
    deleted and recreated (`replace=False` raises `AidbConflict` instead); AIDB refuses the delete while it cannot."""
    check_name(name, "tool name")
    params = params or {}
    for p in params:
        check_name(p, "parameter name")
    want = [[p, t, d] for p, (t, d) in params.items()]
    cur = _one(conn, "SELECT description, query_text, read_only, (SELECT COALESCE(jsonb_agg(jsonb_build_array(x.name, x.type::text, x.description)), '[]'::jsonb) "
                     "FROM unnest(params) x) AS params FROM aidb.sql_tool_registry WHERE name = %s", (name,))
    stripped = sql_statement.strip().rstrip(";").rstrip()
    if cur is not None:
        _guard(conn, vault, "sql_tool", name, reseal)
        have = [list(p) for p in (cur["params"] or [])]
        if cur["description"] == description and cur["query_text"] == stripped and bool(cur["read_only"]) == read_only \
                and [[p[0], str(p[1]).upper(), p[2]] for p in have] == [[p[0], p[1].upper(), p[2]] for p in want]:
            _finish(conn, vault, "sql_tool", name, commit)
            return "unchanged"
        if not replace:
            raise AidbConflict(f"sql tool {name!r} exists with a different definition")
        _call(conn, "SELECT aidb.delete_tool(%s)", (name,))
    pieces = [sql.SQL("aidb.tool_param(%s, %s, %s)")] * len(want)
    pq = sql.SQL("aidb.tool_params({})").format(sql.SQL(", ").join(pieces)) if want else sql.SQL("aidb.tool_params()")
    q = sql.SQL("SELECT aidb.create_sql_tool(name => %s, description => %s, sql_statement => %s, params => {}, read_only => %s)").format(pq)
    _call(conn, q, (name, description, sql_statement, *[x for w in want for x in w], read_only))
    _finish(conn, vault, "sql_tool", name, commit)
    return "updated" if cur is not None else "created"


_AGENT_COLS = {"instructions": "instructions", "model": "model", "tools": "tools", "delegates": "delegates", "purpose": "purpose",
               "max_iterations": "max_iterations", "timeout": "timeout", "input_token_budget": "input_token_budget",
               "output_token_budget": "output_token_budget"}


def ensure_agent(conn: psycopg.Connection, name: str, *, instructions: str, model: str, tools: Sequence[str] = (),
                 delegates: Sequence[str] = (), purpose: str | None = None, max_iterations: int | None = None,
                 timeout: int | None = 120, input_token_budget: int | None = None, output_token_budget: int | None = None,
                 vault=None, reseal: bool = False, commit: bool = True) -> str:
    """Create or update an agent (`aidb.create_agent` / `update_agent`). The purpose confines its tools to a role (see
    `ensure_purpose`); an agent with no purpose runs its tools as whoever calls it, so give every agent one. `timeout` is the
    per-call wall clock in seconds AIDB enforces. A purpose cannot be cleared on an existing agent (`AidbConflict`)."""
    check_name(name, "agent name")
    want: dict[str, Any] = {"instructions": instructions, "model": model, "tools": list(tools), "delegates": list(delegates),
                            "purpose": purpose, "max_iterations": max_iterations, "timeout": timeout,
                            "input_token_budget": input_token_budget, "output_token_budget": output_token_budget}
    cur = _one(conn, "SELECT instructions, model, COALESCE(tools, '{}') AS tools, COALESCE(delegates, '{}') AS delegates, purpose, "
                     "max_iterations, timeout_seconds AS timeout, input_token_budget, output_token_budget FROM aidb.agents WHERE name = %s", (name,))
    if cur is None:
        args = {k: v for k, v in want.items() if v not in (None, [])}
        q = sql.SQL("SELECT * FROM aidb.create_agent(name => %s, {})").format(
            sql.SQL(", ").join(sql.SQL("{} => %s").format(sql.Identifier(k)) for k in args))
        rows = _call(conn, q, (name, *args.values()))
        if rows and rows[0].get("error"):
            raise AidbError(f"create_agent {name!r}: {rows[0]['error']}")
        _finish(conn, vault, "agent", name, commit)
        return "created"
    _guard(conn, vault, "agent", name, reseal)
    if cur["purpose"] and purpose is None:
        raise AidbConflict(f"agent {name!r} has purpose {cur['purpose']!r}; AIDB cannot clear it (delete the agent first)")
    diff = {k: v for k, v in want.items() if v is not None and (list(cur[_AGENT_COLS[k]] or []) if isinstance(v, list) else cur[_AGENT_COLS[k]]) != v}
    if diff:
        q = sql.SQL("SELECT * FROM aidb.update_agent(name => %s, {})").format(
            sql.SQL(", ").join(sql.SQL("{} => %s").format(sql.Identifier(k)) for k in diff))
        rows = _call(conn, q, (name, *diff.values()))
        if rows and rows[0].get("error"):
            raise AidbError(f"update_agent {name!r}: {rows[0]['error']}")
    _finish(conn, vault, "agent", name, commit)
    return "updated" if diff else "unchanged"


@dataclass
class AgentReply:
    message: str | None
    conversation_id: str | None
    error: str | None = None
    timed_out: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.error and self.message is not None


def converse(conn: psycopg.Connection, agent: str, prompt: str, *, conversation_id: str | None = None, read_only: bool | None = None,
             timeout: float = 120.0, debug: bool = False) -> AgentReply:
    """Ask an agent (`aidb.agent_converse`). `timeout` bounds the whole call with statement_timeout (the agent's own `timeout` is
    checked by AIDB between steps); on expiry the transaction is rolled back and the reply has `timed_out=True`. AIDB reports an
    agent-logic failure in the `error` column and a governance refusal inside the tool response, not here: read `decisions()` for
    denials. Commits on success so the conversation persists."""
    try:
        with conn.transaction():
            _one(conn, "SELECT set_config('statement_timeout', %s, true)", (str(int(timeout * 1000)),))
            row = _one(conn, "SELECT message, conversation_id, error FROM aidb.agent_converse(agent_name => %s, prompt => %s, "
                             "conversation_id => %s, read_only => %s, debug => %s)", (agent, prompt, conversation_id, read_only, debug))
    except psycopg.errors.QueryCanceled:
        return AgentReply(None, conversation_id, f"timed out after {timeout:g}s", timed_out=True)
    except psycopg.Error as exc:
        conn.rollback()
        return AgentReply(None, conversation_id, str(exc).strip())
    conn.commit()
    row = row or {}
    return AgentReply(row.get("message"), row.get("conversation_id"), row.get("error") or None)


# ---------------------------------------------------------------------------------------------------------------------
# Status / health
# ---------------------------------------------------------------------------------------------------------------------
def status(conn: psycopg.Connection, *, window: str = "24 hours") -> dict[str, Any]:
    """One JSON-able report: detection, pipelines with lag, knowledge-base row counts, models, agents, purposes, denials in `window`,
    and a list of `problems`. Sections the role cannot read come back as {"unavailable": reason}; plain Postgres gives
    {"aidb": {"available": false, ...}} and nothing else."""
    st = detect(conn)
    report: dict[str, Any] = {"aidb": st.as_dict(), "problems": []}
    if not st.available:
        return report

    def section(key: str, fn):
        try:
            with conn.transaction():
                report[key] = fn()
        except psycopg.Error as exc:
            report[key] = {"unavailable": str(exc).strip().splitlines()[0][:200]}

    def kbs():
        return _rows(conn, "SELECT s.name, s.pipelines, s.embeddings, s.status, k.model_name AS model "
                           "FROM aidb.knowledge_base_stats s LEFT JOIN aidb.knowledge_bases k USING (name) ORDER BY s.name")

    section("pipelines", lambda: pipeline_status(conn))
    section("knowledge_bases", kbs)
    section("models", lambda: _rows(conn, "SELECT name, provider, credential FROM aidb.models ORDER BY name"))
    section("agents", lambda: _rows(conn, "SELECT name, model, purpose, tools FROM aidb.agents ORDER BY name"))
    section("purposes", lambda: _rows(conn, "SELECT name, role, deleted_at IS NOT NULL AS retired FROM aidb.purpose_registry ORDER BY name"))
    report["telemetry"] = {"otel_client": st.otel_client}
    if st.can_read_telemetry:
        section("denials", lambda: {"window": window, "count": _one(conn, "SELECT count(*) AS n FROM aidb_otel.traces WHERE decision_status = 'denied' "
                                    "AND source = 'internal' AND recorded_at > now() - %s::interval", (window,))["n"],
                                    "recent": [{k: d[k] for k in ("recorded_at", "agent", "principal", "role", "reason", "decision_id")}
                                               for d in decisions(conn, since=window, limit=10)]})
    else:
        report["denials"] = {"unavailable": "this role cannot read aidb_otel.traces (needs aidb_governance or an explicit grant)"}
    pipes = report.get("pipelines")
    if isinstance(pipes, list):
        for p in pipes:
            if p["blocking_errors"] or p["record_errors"]:
                report["problems"].append(f"pipeline {p['name']}: {p['record_errors']} record errors, {p['blocking_errors']} blocking")
            if p["lag"]:
                report["problems"].append(f"pipeline {p['name']}: {p['lag']} rows not yet embedded")
            if p["mode"] != "Live":
                report["problems"].append(f"pipeline {p['name']}: auto processing is {p['mode']}, not Live")
    if st.otel_client != "database":
        report["problems"].append("aidb.otel_client is not 'database': purpose decisions are not recorded")
    return report
