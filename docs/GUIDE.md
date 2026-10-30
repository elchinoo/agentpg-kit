# agentpg-kit guide

Version described: **0.4.0** (`apgkit.__version__` is the single source; `pyproject.toml` reads it). Everything below was checked against the
source in `src/apgkit`, the tests in `tests/`, and the way the other projects of the ecosystem use the kit. Where a statement could
not be verified it is listed under [Known limitations](#13-known-limitations-and-things-not-verified).

Contents: [1 Purpose](#1-purpose-and-audience) | [2 Ecosystem](#2-how-the-kit-fits-the-ecosystem) | [3 Architecture](#3-architecture) |
[4 Install](#4-install) | [5 Configuration](#5-configuration-reference) | [6 First run](#6-first-run-walkthrough-build-a-small-app) |
[7 Blocks](#7-using-the-blocks) | [8 Roles and permissions](#8-roles-scopes-and-permissions) | [9 Security](#9-security-notes) |
[10 Operations](#10-operations) | [11 Testing](#11-testing-and-development) | [12 AIDB and AgentPG](#12-aidb-and-agentpg-integration) |
[13 Limitations](#13-known-limitations-and-things-not-verified)

---

## 1. Purpose and audience

`agentpg-kit` (import name `apgkit`) is a small Python library of the parts every app in the AgentPG showcase ecosystem needs and
should not rewrite: reading configuration and secrets, connecting to a Postgres that may be asleep, plain-SQL migrations, an
encrypted secrets vault, password hashing, an SSRF guard, an OpenAI-compatible client, a security middleware, Prometheus metric
names, one authentication front door (local admin, API tokens, static key, federated OIDC), and a shared browser UI (CSS and
plain JavaScript modules served under `/kit/`).

It is a **library, not a service**: nothing in this repository listens on a port. An app imports it and mounts its static files.

Who it is for:

- Developers building a new app on AgentPG (FastAPI + psycopg 3 + Postgres, optionally pgvector) who want sign-in, a vault and
  a consistent UI on day one. Section 6 builds one in about ten minutes.
- Maintainers of the existing fleet apps (identity, llm-gateway, TrustDesk, PagerLens, CityPulse, CityPulse Simulator, PayBroker,
  ShopFront), where a fix here is a fix everywhere after each app moves to the new release tag.
- Security reviewers: the security-critical code of every app (password hashing, vault, SSRF guard, token verification, CSRF/CSP
  middleware) lives here once. See [SECURITY.md](../SECURITY.md).

What it is not: an ORM, a web framework, an MCP server framework (see limitations), or a vector/retrieval layer.

## 2. How the kit fits the ecosystem

The ecosystem (manifest: `ecosystem/ecosystem.yaml`) is a fleet of apps, each on its own AgentPG sandbox with its own database,
deployed by `ecoctl`. The kit is the one dependency they share.

```mermaid
flowchart LR
  kit["agentpg-kit (apgkit)<br/>library, pinned by tag"]
  subgraph apps["Apps built on the kit"]
    idp["identity<br/>OIDC provider"]
    gw["llm-gateway"]
    td["TrustDesk"]
    pl["PagerLens"]
    cp["CityPulse"]
    sim["CityPulse Simulator"]
    pb["PayBroker"]
    sf["ShopFront"]
  end
  eco["ecoctl<br/>provisions and deploys"]
  kit -. "pip install (Dockerfile: tag v0.2.5)" .-> apps
  eco -- "creates sandboxes, sets OIDC_* and ENCRYPTION_KEY env" --> apps
  eco -- "registers clients, roles, scopes" --> idp
  apps -- "browser login (PKCE) and JWKS verification" --> idp
  cp -- "client_credentials: pagerlens.ingest" --> pl
  sim -- "client_credentials: citypulse.ingest, trustdesk.requests.write, pagerlens.ingest, llmgw.use" --> cp
  td & pl & pb & sf -- "LLM_BASE_URL + lg_ key, OpenAI-compatible" --> gw
```

Facts behind the diagram, each checked:

- **Delivery.** Every app lists `agentpg-kit>=0.2.5` in its `pyproject.toml` and its `Dockerfile` installs
  `agentpg-kit @ https://github.com/elchinoo/agentpg-kit/archive/refs/tags/v0.2.5.tar.gz` before the app. Local development uses an
  editable path (`uv pip install -e ../agentpg-kit`, set in each app's `pyproject.toml`). A release is a git tag; there is no
  package index upload in this repository.
- **ecoctl does not install or configure the kit.** It sets the environment the kit reads: `<PREFIX>_OIDC_ISSUER`,
  `<PREFIX>_OIDC_CLIENT_ID` and `<PREFIX>_OIDC_CLIENT_SECRET` (from `ecosystem/src/ecoctl/plan.py`), plus the names listed under
  `generate:` in the manifest, for example `TRUSTDESK_ENCRYPTION_KEY` (read by `apgkit.vault.Vault`). For apps with `calls:` it also
  sets `<PREFIX>_SERVICE_CLIENT_ID` and `<PREFIX>_SERVICE_CLIENT_SECRET`; the kit does not read those names itself, the app passes
  them to `TokenSource` (CityPulse, Simulator do this).
- **Per-app prefix.** `Vault("TRUSTDESK")`, `from_env("TRUSTDESK", ...)` and `LocalAuth(env_prefix="TRUSTDESK")` derive their variable
  names from one prefix, which must equal the manifest's `env_prefix` (default: the app key upper-cased).

How each project interacts with the kit:

| Project | Kit blocks it imports (from its `src`) | Kit-related auth and configuration |
|---|---|---|
| **identity** (own OIDC provider) | `config`, `db`, `ids`, `vault`, `ratelimit`, `netguard`, `guard`, `web`, `auth.schema`, `auth.rp`, `auth.oidc`, `auth` | Issues the tokens the kit verifies (RS256/ES256/EdDSA, JWKS, PKCE). Uses `RelyingParty` for upstream sign-in with Google (`identity/src/identity/federation.py`). Needs `IDENTITY_PUBLIC_URL` so the issuer is stable (ecoctl refuses to continue if the reported issuer differs from the URL it reached). |
| **llm-gateway** | `auth`, `vault`, `llm`, `db`, `config`, `web`, `ratelimit`, `netguard`, `ids`, `guard`, `auth.schema`, `auth.rp` | `from_env("LLMGW", ...)`; vault holds provider keys; its own `lg_` client keys are what other apps send as `LLM_API_KEY`. Scopes it exposes: `llmgw.use`, `llmgw.read`, `llmgw.metrics`. |
| **TrustDesk** | `config`, `auth`, `vault`, `netguard`, `llm`, `settings_store`, `passwords`, `ids`, `guard`, `web`, `db`, `auth.schema`, `auth.rp` | Roles `admin`, `approver`, `viewer`; scopes exposed `trustdesk.requests.write`, `trustdesk.kb.read`, `trustdesk.metrics`; LLM calls go through the gateway (`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_CHAT_MODEL`, `EMBEDDING_MODEL`, `EMBEDDING_DIM`, set by ecoctl). Has its own MCP server (`mcp_server.py`, not from the kit) behind an `McpGuard` that calls `auth.authenticate(request, allow_cookie=False)` and requires the permission `mcp:use`. |
| **PagerLens** | same set as TrustDesk, plus `TokenSource` in its agent | Roles `admin`, `responder`, `viewer`; scopes `pagerlens.ingest`, `pagerlens.read`, `pagerlens.metrics`. Reads the metric family names the kit's `Metrics` class defines. |
| **CityPulse** | `config`, `auth`, `ids`, `guard`, `web`, `db`, `settings_store`, `auth.schema`, `auth.rp`, `TokenSource` (reporter) | Calls PagerLens with scope `pagerlens.ingest` using `CITYPULSE_SERVICE_CLIENT_ID/_SECRET`. Exposes `citypulse.ingest`, `citypulse.read`, `citypulse.metrics`. |
| **CityPulse Simulator** | `config`, `auth`, `vault`, `ids`, `guard`, `web`, `db`, `auth.schema`, `auth.rp`, `TokenSource` | One `TokenSource` per target, scope per call (`citypulse.ingest`, `trustdesk.requests.write`, `pagerlens.ingest`, `llmgw.use`), secret `CPSIM_SERVICE_CLIENT_SECRET`. |
| **PayBroker** | `auth`, `vault`, `netguard`, `llm`, `passwords`, `settings_store`, `ids`, `guard`, `web`, `db`, `config`, `auth.schema`, `auth.rp` | Roles `admin`, `risk_manager`, `analyst`, `operator`, `viewer`; uses `Authenticator(bearer_resolvers=...)` style hooks for merchant keys (the `Authenticator` supports them). Scopes `paybroker.read`, `paybroker.metrics`, `paybroker.admin`. |
| **ShopFront** | `auth`, `web`, `llm`, `vault`, `netguard`, `settings_store`, `guard`, `db`, `config`, `auth.schema`, `auth.rp` | Roles `admin`, `staff`, `viewer`; scopes `shopfront.api`, `shopfront.read`, `shopfront.metrics`, `shopfront.admin`; `SHOPFRONT_PUBLIC_URL` goes to `web.public_url`. |
| **ecoctl** | none (it is not a Python consumer of the kit) | Sets the environment variables the kit reads, creates the identity clients whose ids the kit uses as audience, and runs the LLM gateway wiring. |

The import lists come from a search of each project's `src/` for `from apgkit...`; the roles and scopes come from
`ecosystem/ecosystem.yaml`. PayBroker's use of `bearer_resolvers` for merchant keys is stated from the `Authenticator` docstring
("app-registered prefixes (merchant keys...)"), not from reading PayBroker's code.

Credentials flow, end to end, for the common cases:

1. **Person in a browser.** App page -> `GET /auth/login` (app route that calls `RelyingParty.begin`) -> identity (authorization code
   + PKCE, scopes `openid profile email roles`) -> `GET /auth/callback` (app route calling `RelyingParty.finish`, which verifies the
   ID token and nonce) -> the app starts a server-side session with the roles from the verified ID token. Roles named
   `<app>:<role>` map to permissions; roles of other apps are ignored.
2. **Service to service.** Caller builds `TokenSource(issuer, client_id, secret_getter, scope="callee.scope")`, which fetches a
   `client_credentials` token (cached until 30 s before expiry) and sends `Authorization: Bearer`. The callee's `Authenticator`
   verifies the JWT locally against the provider's JWKS and maps `scope` to permissions.
3. **Local credentials** (no identity provider): admin password session cookie, API tokens created in the app (`<prefix>_...`), or
   one static key from the environment.

## 3. Architecture

```mermaid
flowchart TB
  browser["Browser<br/>/kit/base.css, ui.js, api.js, session.js"]
  client["API client<br/>Bearer token or JWT"]
  subgraph app["Your FastAPI app"]
    guard["SecurityGuard<br/>headers, CSP, body cap, CSRF header, metrics"]
    authn["Authenticator.require('x:y')"]
    routes["your routes"]
    local["LocalAuth<br/>setup code, password, sessions, tokens"]
    tv["TokenVerifier (JWKS cache)"]
    rp["RelyingParty / TokenSource"]
    vault["Vault<br/>data key in memory only"]
    llm["LLMClient + NetGuard"]
    dbm["Database, migrate, settings_store"]
  end
  pg[("Postgres<br/>app tables, app_setting, web_session,<br/>api_token, oidc_login")]
  idp["identity (OIDC)"]
  prov["Model provider or llm-gateway"]
  browser --> guard
  client --> guard
  guard --> authn --> routes
  authn --> local
  authn --> tv
  tv -- "GET jwks_uri" --> idp
  rp -- "authorize, token" --> idp
  routes --> vault
  routes --> llm -- "POST /chat/completions" --> prov
  local --> dbm
  vault --> dbm
  routes --> dbm --> pg
```

Module map (every file in `src/apgkit`):

| Module | Role |
|---|---|
| `config.py` | `read_secret(env, default_file)`, `database_url()`, `env_bool()` |
| `db.py` | `Database`: `connect()` with retry/backoff, optional `ConnectionPool` (`pool()`, `close_pool()`), pgvector adapter registration |
| `migrate.py` | `run(db, dir, extensions=, replacements=, table=)`; `SHARED_SQL` creates `app_setting` |
| `settings_store.py` | `get`, `put`, `delete` on `app_setting(key, value)` |
| `passwords.py` | scrypt hashing (`hash_password`, `verify_password`, `check_strength`, `MIN_LENGTH=12`) |
| `vault.py` | `Vault`: envelope encryption (Fernet) with the data key wrapped under the admin password and/or a platform secret |
| `ratelimit.py` | `FailureLimiter` (in memory, per process) |
| `netguard.py` | `NetGuard.check(url)`; `UnsafeURL` |
| `llm.py` | `LLMClient`, `ChatConfig`, `LLMError` family, `answer_text`, `empty_answer_error`, `redact` |
| `guard.py` | `SecurityGuard` pure-ASGI middleware |
| `metrics.py` | `Metrics`: shared metric names and a database-probe collector |
| `web.py` | `is_https`, `public_url`, `mount_kit_static` |
| `ids.py` | `new_id`, `sha256`, `hmac_hex` |
| `auth/principal.py` | `AppAuth`, `Principal`, `WILDCARD` |
| `auth/local.py` | `LocalAuth` |
| `auth/oidc.py` | `TokenVerifier`, `TokenSource`, `discover`, `principal_from_claims`, `TokenError` |
| `auth/rp.py` | `RelyingParty`, `safe_return_to` |
| `auth/authenticator.py` | `Authenticator` |
| `auth/env.py` | `from_env(prefix, default_client_id)` -> `Federation` |
| `auth/schema.py` | `SQL`: idempotent DDL for `web_session`, `api_token`, `oidc_login` (and `app_setting`) |
| `static/` | `base.css`, `ui.js`, `api.js`, `session.js`, `logo.svg`, `favicon.svg` |

Design choices worth knowing:

- **State lives in Postgres.** Sessions, API tokens (hashes), OIDC login state, the vault's wrapped keys and the admin password
  hash are all rows. An app can restart or run several replicas and keep its sessions.
- **Fail closed.** With no admin password and no static key, `LocalAuth.needs_setup()` is true and the app should offer setup, not
  access. Anonymous access exists only if the app passes `allow_anonymous` (CityPulse reads `CITYPULSE_ALLOW_ANONYMOUS`).
- **Database may be asleep.** `Database.connect()` retries `OperationalError` with doubling delays (1 s, 2 s, 4 s...) and says why on
  stderr. `Database(pool_wait=False)` opens the pool without blocking so the process starts and a request during wake-up fails fast.
- **No secrets in the browser.** `api.js` keeps no credentials; the session is an `HttpOnly` cookie that the app sets.

## 4. Install

Requirements: Python 3.11 or newer (`requires-python`), Postgres 14+ in practice (no minimum is declared; CI uses
`pgvector/pgvector:pg17`). Runtime dependencies (from `pyproject.toml`): `fastapi`, `httpx`, `psycopg[binary,pool]`, `pgvector`,
`cryptography`, `prometheus-client`, `authlib`, `joserfc`. Optional: extra `dev` installs `pytest`, `ruff`, `uvicorn`.

### 4.1 As a dependency of an app

```bash
# a pinned release (what the fleet's Dockerfiles do)
pip install "agentpg-kit @ https://github.com/elchinoo/agentpg-kit/archive/refs/tags/v0.2.5.tar.gz"

# local development: this repository next to the app
uv pip install -e ../agentpg-kit
```

In the app's `pyproject.toml`, declare `agentpg-kit>=0.2.5` and, for local work, a path source (the fleet uses
`agentpg-kit = { path = "../agentpg-kit", editable = true }` under `[tool.uv.sources]`).

### 4.2 Working on the kit itself, with a throwaway Postgres

Two ways to get a disposable database; the tests drop the `public` schema of whatever `TEST_DATABASE_URL` points at, so never
point it at data you care about.

Docker (what CI uses; not run while writing this guide, the Docker daemon was not running on the machine used):

```bash
docker run --rm -d --name apgkit-pg -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:55432:5432 pgvector/pgvector:pg17
export TEST_DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:55432/postgres
```

Local Postgres binaries (run and verified with Postgres 17.5). **Create the cluster with UTF-8 encoding**: a cluster created with
the default C locale got `SQL_ASCII`, and then `text` columns came back as `bytes` and 12 tests failed (see troubleshooting):

```bash
make test-db     # does the following; override folder and port with APGKIT_PG=... APGKIT_PORT=...
# initdb -D /tmp/apgkit-pg -U postgres -E UTF8 --auth=trust
# pg_ctl -D /tmp/apgkit-pg -o "-p 55432 -c listen_addresses=127.0.0.1 -c unix_socket_directories=''" -l /tmp/apgkit-pg.log start
# createdb -h 127.0.0.1 -p 55432 -U postgres kit_test
export TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:55432/kit_test
```

If the database is not UTF8, `pytest` now stops at start with one message naming the problem instead of failing tests one by one.

Then, in this repository:

```bash
uv venv && uv pip install -e ".[dev]"
make lint        # .venv/bin/ruff check src tests
make test        # .venv/bin/pytest -q   (needs TEST_DATABASE_URL, and node for the UI scripts)
```

Result on the guide's author's machine against Postgres 17.5 (UTF-8) with node 22: `71 passed`, `ruff: All checks passed`.

### 4.3 Docker compose and ecoctl

The kit has **no** `Dockerfile` or compose file of its own (it is a library). The apps that use it do:

- **docker compose.** Each app ships a compose file for local development, for example CityPulse's: a `postgres:17` service
  bound to `127.0.0.1`, an `api` service built from the app's Dockerfile, `DATABASE_URL` pointing at the `db` service, and the
  first-run setup code printed to `docker compose logs api`. Copy that shape for your app. (Read, not executed here.)
- **The app image installs the kit from the release tag** (`ARG KIT_URL=.../tags/v0.2.5.tar.gz`; `RUN pip install "agentpg-kit @ ${KIT_URL}"`),
  then installs the app. Upgrading the kit in a fleet app means changing that tag, rebuilding the image and redeploying.
- **Deploying via ecoctl.** `ecoctl` deploys apps, not the kit. After your app has an image and an entry in
  `ecosystem/ecosystem.yaml` (roles, `exposes`, `calls`, `generate: [<PREFIX>_ENCRYPTION_KEY]`), `ecoctl plan` shows the commands and
  `ecoctl apply --execute` creates the database and sandbox, registers the app in identity, and passes the `<PREFIX>_OIDC_*`
  variables the kit's `from_env` reads. Details: `ecosystem/README.md` and `ecosystem/docs/DEPLOY.md`.

## 5. Configuration reference

The kit has no global settings object. Each block reads the variables below; variable names containing `<PREFIX>` use the prefix
you pass to the constructor (upper-cased where noted). Boolean variables count `1`, `true`, `yes`, `on` (any case) as true; anything
else, including empty, as false (`env_bool`).

### 5.1 Database (`apgkit.config.database_url`, `apgkit.db`)

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | unset | Postgres DSN. First non-empty of the three names wins, in this order. |
| `DB_EXTERNAL_DSN` | unset | The DSN name AgentPG may set for a linked sandbox. |
| `PSQL_CONNECTION_STRING` | unset | Third accepted name. |
| `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, ... | unset | When none of the three DSN variables is set, the DSN is empty and libpq falls back to these (linked AgentPG sandboxes provide them). |

Constructor settings of `Database(url=database_url, *, vector=False, pool_max=20, pool_wait=True)`: `connect(retries=5, delay=1.0)`
uses `connect_timeout=10` and `dict_row`; the pool has `min_size=2`, `max_size=pool_max`, checkout `timeout=5` s and opens with a 30 s
wait unless `pool_wait=False`.

### 5.2 Secrets (`apgkit.config.read_secret`)

Any secret read through `read_secret(ENV)` comes from `ENV`, or else the **first line** of the file named by `ENV_FILE`, or else a
built-in default path (only some secrets have one). A missing file gives an empty string; an unreadable file prints a warning to
stderr and gives an empty string.

| Variable | Default file | Read by | Meaning |
|---|---|---|---|
| `<PREFIX>_ENCRYPTION_KEY` (+ `_FILE`) | `/etc/<prefix>/encryption_key` (prefix lower-cased) | `Vault` | The platform secret that wraps the vault data key so the vault unlocks at start without the admin password. Empty: the vault needs the admin password after every restart. |
| `<PREFIX>_API_KEY` (+ `_FILE`) | `/etc/<prefix>/api_key` | `LocalAuth.static_key` | A full-access static credential for automation. Presence also disables the first-run setup flow (`needs_setup` is false) and makes `static_key_configured()` true. |
| `<PREFIX>_OIDC_CLIENT_SECRET` (+ `_FILE`) | none | `from_env` | The app's confidential-client secret at the identity provider. Empty at start means a **public client** (PKCE only, `client_id` sent in the token request). |

### 5.3 Federation (`apgkit.auth.from_env(prefix, default_client_id)`)

| Variable | Default | Meaning |
|---|---|---|
| `<PREFIX>_OIDC_ISSUER` | unset | The identity provider's issuer URL. **Unset turns federation off**: `Federation.enabled` is false, `verifier` and `rp` are `None`, `local_login` is true. Must be https (http only for `localhost`, `127.0.0.1`, `::1`, `*.localhost`), no credentials, query or fragment, otherwise `ValueError` at start. |
| `<PREFIX>_OIDC_JWKS_TTL` | `300` | Seconds the verifier trusts a fetched JWKS (1 to 3600; larger values are lowered to 3600). A signing key the identity provider removes (an emergency rotation) is refused once this has passed; an unknown `kid` also triggers one rate-limited refresh. If the provider is unreachable at refresh time the cached keys are used for at most one more hour, then verification fails closed. |
| `<PREFIX>_OIDC_CLIENT_ID` | the app name passed as `default_client_id` | This app's client id; also the **audience** `TokenVerifier` requires. |
| `<PREFIX>_OIDC_CLIENT_SECRET` | empty | See 5.2. |
| `<PREFIX>_LOCAL_LOGIN` | `true` | Whether the local admin password remains a login when federation is on. The kit only reports the flag in `Federation.local_login`; **the app must enforce it** (CityPulse's `/api/login` returns 403 when federation is on and this is false). |

### 5.4 Variables chosen by the app, passed to kit constructors

| Where | Example name used by fleet apps | Meaning |
|---|---|---|
| `NetGuard("X_ALLOW_PRIVATE_URLS")` | `TRUSTDESK_ALLOW_PRIVATE_LLM_URLS`, `PAYBROKER_ALLOW_PRIVATE_URLS`, `LLMGW_ALLOW_PRIVATE_URLS` ... | If true, loopback/private targets are allowed (for a local model server). Link-local (cloud metadata) is **always** refused. |
| `public_url(request, "X_PUBLIC_URL")` | `TRUSTDESK_PUBLIC_URL`, `SHOPFRONT_PUBLIC_URL`, `IDENTITY_PUBLIC_URL` | The externally visible base URL; when unset the request's scheme and `Host` header are used (and `X-Forwarded-Proto: https` is honoured). Used to build the OIDC `redirect_uri` (`<url>/auth/callback`). |
| `Authenticator(allow_anonymous=...)` | `CITYPULSE_ALLOW_ANONYMOUS` | If it returns true every request is `Principal("anonymous")` with `*`. Off unless the app wires it. |
| `LocalAuth(env_prefix=, token_prefix=, token_scopes=)` | `CITYPULSE`, `cp_`, `{read, ingest, metrics, full}` | Prefix of env names, prefix of generated API tokens (also how `Authenticator` recognises them), and the scopes a token may have. |

### 5.5 LLM variables (set by ecoctl for apps with `llm: true`; read by the app, passed to the kit)

`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_CHAT_MODEL`, `EMBEDDING_MODEL`, `EMBEDDING_DIM` are conventions of the fleet apps (for example
`trustdesk/src/trustdesk/config.py` reads `LLM_BASE_URL` and `LLM_API_KEY`). The kit itself reads none of them: an app builds a
`ChatConfig(base_url, model, label, trusted=True, key_plain=...)` from them. `trusted=True` skips the SSRF check and must be used
only for operator-set configuration, never for URLs a user typed.

### 5.6 Tests and the shared UI

| Name | Meaning |
|---|---|
| `TEST_DATABASE_URL` | Throwaway database for `pytest`. Unset: the database tests are skipped. The `db` fixture sets `DATABASE_URL` from it and **drops and recreates the `public` schema**. |
| `<html data-csrf="X-App-CSRF">` | The CSRF header name `api.js` sends on non-GET requests (fallback `X-CSRF`). It must equal the `csrf_header` given to `SecurityGuard` (header names are case-insensitive). |

### 5.7 Fixed constants (not configurable without code changes)

Password length 12 to 256; scrypt `N=2^15, r=8, p=1`; session lifetime 12 h (`SESSION_HOURS`); OIDC login state valid 10 min;
`FailureLimiter` default 10 failures per 60 s per client address; `SecurityGuard` default body cap 64 KiB on `/api/` and CSRF checks
on `/api/`; `LLMClient` timeout 60 s, 3 retries (so up to 4 attempts) on HTTP 408, 409, 429, 500, 502, 503, 504, backoff
`min(2^attempt, 8)` s, response cap 8 MiB; JWKS cache 600 s with one forced refresh at most every 15 s; token clock leeway 30 s;
`TokenSource` renews 30 s before expiry; discovery and JWKS calls time out at 10 s.

## 6. First-run walkthrough: build a small app

This builds **Notes**, a tiny app (list, add, delete notes; some notes private and encrypted) with first-run setup, login,
API tokens, a vault and the shared UI. Its source is in [`docs/examples/notes`](examples/notes) (eight files). Everything in this
section was run on 2026-10-27 against a throwaway Postgres 17.5 and checked in a browser. Port and database names are examples.

### 6.1 Prepare

```bash
cp -R agentpg-kit/docs/examples/notes ./notes && cd notes
uv venv && source .venv/bin/activate
uv pip install -e ../agentpg-kit -e .          # or the release tag URL from section 4.1, then: uv pip install -e .
export DATABASE_URL=postgresql://postgres@127.0.0.1:55432/notes     # database must exist, UTF-8
PORT=8790 notes                                  # console script defined in pyproject.toml
```

Expected log: uvicorn start-up, then

```
=== Notes first-run setup ===
Setup code: XXXX-XXXX-XXXX
```

The server migrated the database on start (`notes_migrations` table plus the kit's `app_setting`, `web_session`, `api_token`,
`oidc_login`).

### 6.2 What the example contains

| File | What it shows |
|---|---|
| `src/notes/core.py` | `AppAuth` with roles `admin`, `editor`, `viewer` and scopes `read`, `full`, `notes.read`; `Database`, `Metrics` (with a `db_up` probe), `Vault("NOTES")`, `from_env("NOTES", "notes")`, `LocalAuth(..., vault=vault, on_reset=...)`, `Authenticator` |
| `src/notes/migrations/001_notes.sql` | one app table; `migrate.run` applies `*.sql` in name order, once each |
| `src/notes/app.py` | lifespan (migrate, try platform-secret unlock, print setup code), `SecurityGuard`, `/healthz`, `/readyz`, `/metrics`, `/api/session`, `/api/setup`, `/api/login`, `/api/logout`, `/api/vault/unlock`, notes CRUD, `/api/tokens` |
| `src/notes/static/index.html`, `app.js` | the shared UI: `base.css`, `bootSession`, `renderSetup`, `renderLogin`, `renderVaultBanner`, `confirmDialog`, `toast`, `field`, `fill`, `loading`, `errorState` |

The kit supplies the mechanics but **not the HTTP routes**: `/api/session`, `/api/setup`, `/api/login`, `/api/logout` and
`/api/vault/unlock` are written by the app (about 60 lines here), because their exact shape differs per app. The shared
`session.js` expects these endpoints and fields (see 7.9).

### 6.3 Walk through it in the browser

1. Open `http://127.0.0.1:8790/`. You see "Set up Notes". Enter the setup code from the log and an admin password of at least 12
   characters twice, then "Create admin password". A toast says you are signed in and the notes screen shows "No notes yet."
2. Add a note ("First", "hello"). Add another with "Private (encrypted in the vault)" ticked. Both appear; the private one has a badge.
3. In `psql`, `SELECT title, body, private FROM note;`: the private body is a `gAAAAA...` Fernet token, not your text.
4. Click Delete on a note: the shared confirmation dialog appears; Delete removes it.
5. Stop the server and start it again **without** `NOTES_ENCRYPTION_KEY`. Reload: a banner "Provider keys are locked." appears and
   the private note's text shows "locked". Type the admin password in the banner and Unlock: the text returns without a page
   reload (the `apg-unlocked` event reloads the list).
6. Stop, then start with `NOTES_ENCRYPTION_KEY=<any long random string>`, reload, unlock once with the password (this wraps the
   data key under the platform secret too), stop and start again: the vault is now unlocked at start (`"auto_unlock": true` in
   `/api/session`), no banner.

### 6.4 Walk through it with curl (API and tokens)

Browser-style writes need the CSRF header (any non-empty value of the header named in `data-csrf`). Bearer calls do not.

```bash
B=localhost:8790; H=(-H 'X-Notes-CSRF: 1' -H 'Content-Type: application/json')
curl -s -c jar "${H[@]}" -X POST $B/api/setup -d '{"code":"XXXX-XXXX-XXXX","password":"correct horse battery"}'   # {"ok":true}, sets cookie
curl -s -b jar "${H[@]}" -X POST $B/api/notes -d '{"title":"First","body":"hello"}'                                # {"id":1}
curl -s -b jar "${H[@]}" -X POST "$B/api/tokens?name=ci&scope=read"                                               # token shown once
curl -s -H "Authorization: Bearer nt_..." $B/api/notes                                                            # allowed: notes:read
curl -s -H "Authorization: Bearer nt_..." -H 'Content-Type: application/json' -X POST $B/api/notes -d '{"title":"x"}'
# {"detail":"this credential cannot do that (it lacks 'notes:write')"}   (403)
curl -s -b jar -X POST $B/api/notes -d '{}'                                                                       # {"detail": "missing CSRF header"} (403)
```

Observed during verification: a short password returns 422 `password must be at least 12 characters`; a bad bearer returns 401
`invalid credentials`; a locked vault makes writing a private note fail with `Stored secrets are locked...`.

### 6.5 Turn on single sign-on (not exercised here)

The example already builds `fed = from_env("NOTES", "notes")` and passes `fed.verifier` to `Authenticator`, so **service tokens from
identity work as soon as `NOTES_OIDC_ISSUER` is set** (client id `notes` = audience). Browser SSO additionally needs two routes, `/auth/login`
and `/auth/callback`, that call `fed.rp.begin(...)` and `fed.rp.finish(...)` and then `local.create_session(conn, subject=..., roles=...,
source="oidc", id_token_hint=...)`. Copy them from `CityPulse/src/citypulse/api.py` (`sso_login`, `sso_callback`); the example omits
them to stay short, and its `/api/session` reports `"sso": null`. The kit side of that flow is covered by `tests/test_oidc.py`.

## 7. Using the blocks

### 7.1 `config`, `ids`, `web`

- `read_secret("X")`, `database_url()`, `env_bool("X", default)` as in section 5.
- `ids.new_id(prefix="", n=12)` random lowercase alphanumeric id; `ids.sha256(str)` hex digest; `ids.hmac_hex(key, message)`.
- `web.is_https(request)`; `web.public_url(request, env_name)`; `web.mount_kit_static(app)` mounts `src/apgkit/static` at `/kit`.

### 7.2 Database, migrations, settings

```python
from pathlib import Path
from apgkit import migrate, settings_store
from apgkit.db import Database

db = Database(vector=True, pool_max=10, pool_wait=False)
migrate.run(db, Path("migrations"), extensions=("vector", "pg_trgm"), table="myapp_migrations",
            replacements={"__DIM__": "1536"})
with db.connect() as conn:                      # dict rows; leaving `with` commits on success, rolls back on error, and closes the connection
    settings_store.put(conn, "theme", "dark"); conn.commit()
pool = db.pool()                                # hot paths: ConnectionPool; use `with pool.connection() as conn:`
```

- `migrate.run` creates the named extensions (`CREATE EXTENSION IF NOT EXISTS`, names must be alphanumeric/underscore), creates
  `app_setting`, creates its own bookkeeping table (**one per app**, so two apps can share a database, tested), then runs each
  unseen `*.sql` in sorted name order in one transaction, with `replacements` applied as plain string substitution. It returns the
  names applied. It does **not** take a lock: two replicas starting together can race, so serialise with an advisory lock the way
  CityPulse does (`pg_advisory_lock`).
- Run `apgkit.auth.schema.SQL` **after** your own migrations (CityPulse does): it is idempotent and upgrades a `web_session` table
  created before the kit existed (adds `subject`, `name`, `email`, `roles`, `source`, `id_token_hint`).
- `Database(vector=True)` registers the pgvector adapter on each connection; before the `vector` extension exists the registration is
  skipped quietly, so it is safe to call before the first migration.

### 7.3 Passwords, vault

- `hash_password(pw)` returns `scrypt$N$r$p$salt$digest`; `verify_password(pw, stored)` is constant-time and returns False for any
  malformed or unknown-scheme string; `check_strength` raises `ValueError`.
- `Vault(prefix)`: `initialize(conn, password)`, `initialize_with_platform_secret(conn)` (for SSO-only apps with no admin password;
  False if there is no platform secret or the vault exists), `unlock_with_password`, `try_unlock_with_platform_secret`, `lock`,
  `change_password`, `reset`, `status(conn)` (`initialized`, `unlocked`, `auto_unlock`, `reason`), `encrypt`, `decrypt`. A locked vault raises
  `VaultLocked`; an undecryptable token raises `VaultError` ("Re-enter it"). Both messages are safe to show users.
- `LocalAuth(vault=...)` wires the vault to the admin password: `set_admin_password` initialises or re-wraps it, `login_password`
  unlocks it, `change_password` re-wraps it, `reset_admin` resets it and calls your `on_reset(conn)` hook to delete whatever was
  encrypted (it would be unreadable).

#### 7.3.1 Rotating the data key, and the other vault operations (since 0.4.0)

**Why re-wrapping is not enough.** `change_password`, `rotate_platform_secret` and changing `<PREFIX>_ENCRYPTION_KEY` re-wrap the
SAME 32-byte data key. Anyone who copied the database (and so the old wrap rows) and who holds the old password or platform
secret still recovers that key, and with it every ciphertext copied at the same time. Only `rotate_data_key` replaces the key.

`Vault.rotate_data_key(conn, reencrypt=None, *, password=None) -> dict[str, int]`:

1. requires the vault unlocked and `conn` idle (no open transaction); `password` is required when a password wrap exists (it is
   verified first) because that wrap is rewritten;
2. generates a new data key (`secrets.token_bytes(32)`);
3. inside ONE transaction on `conn`: re-encrypts the registered stores (below) and calls `reencrypt(old_decrypt, new_encrypt)` for
   anything else, then rewrites the password wrap and (when `<PREFIX>_ENCRYPTION_KEY` is set) the platform wrap with the new key; if
   no platform secret is set, a stored platform wrap is deleted because it would still open the old key;
4. commits, and only then switches the in-memory key.

Crash safety: before the commit nothing is visible. An exception (including one raised by your callback), a crash or a lost
connection leaves the old key, the old ciphertexts and the old wraps exactly as they were (tested, including a failure while
writing the platform wrap). After the commit all of them are new. If the connection dies during the commit itself the outcome is
unknown, so the vault locks itself; unlock again and you get whichever key won. A value that cannot be decrypted aborts the
rotation; decide in your callback whether to skip or null it.

Operational rules: stop writers of vault-encrypted columns during the call (use `LOCK TABLE ... IN SHARE ROW EXCLUSIVE MODE` in
the callback); other processes of the same app keep the old key in memory and cannot decrypt until restarted or unlocked again, so
restart them right after; old backups keep decrypting with the old key, so after an exposure you must also re-issue the secrets
themselves at their source.

Stores registry: `vault.register_store(name, select_sql, update_sql)` declares where an app keeps ciphertexts. `select_sql` returns
one row per ciphertext, the ciphertext in a column named `value` plus any columns that identify the row; `update_sql` uses named
parameters, `%(value)s` and one `%(<column>)s` per identifying column. Example:

```python
vault.register_store("provider.api_key",
    "SELECT id, api_key_enc AS value FROM provider WHERE api_key_enc IS NOT NULL",
    "UPDATE provider SET api_key_enc = %(value)s WHERE id = %(id)s")
...
with db.connect() as conn:            # idle connection
    counts = vault.rotate_data_key(conn, password=admin_password)    # {"provider.api_key": 3}
```

`vault.stores()` lists what is registered (useful in a test that fails when a new encrypted column is not registered).

Other operations: `rotate_platform_secret(conn, new_secret)` (unlocked; also set the new value in the platform's environment);
`drop_platform_wrap(conn)` (switch to admin-password-only mode; refuses when it is the only wrap).

**KDF parameters.** Each wrap stores its parameters next to its salt (`vault_kdf_pw`, `vault_kdf_env`, `scrypt$17$8$1`). New wraps
use N=2^17, r=8, p=1 (128 MiB, about 0.3 s); `maxmem` is 256 MiB for every derivation. Wraps without stored parameters are legacy
(N=2^15) and still open. Migration happens on use: a password sign-in upgrades the password wrap, the platform-secret unlock at
start upgrades the platform wrap (that one commits on the connection it is given). A kit older than 0.4.0 cannot open an upgraded
wrap: roll back only before the first unlock, or unlock once after rolling back with a restore of the settings rows.

#### 7.3.2 Admin-password-only mode (stronger, optional; not the default)

Do not set `<PREFIX>_ENCRYPTION_KEY` (nor `_FILE`, nor `/etc/<prefix>/encryption_key`). `initialize(conn, password)` then wraps the
data key under the admin password alone, and no platform wrap exists (tested: `test_admin_password_only_mode`). To move an existing
app: unset the variable first (otherwise a password unlock re-adds the platform wrap), then `drop_platform_wrap(conn)`, and if the
old platform secret may be exposed, run `rotate_data_key` as well.

What you gain: the database plus the environment no longer open the vault; the attacker needs the admin password (guessed offline
at the scrypt cost above) or a running unlocked process. What you lose:

- **No unattended restarts.** After any restart, recreate or crash the vault is locked (`status(conn)["reason"] == "no_platform_key"`)
  until a human signs in with the admin password. Everything that needs a stored secret answers `VaultLocked` meanwhile: outbound
  calls with stored provider keys, webhook delivery and workers, and, for an identity provider, token signing for the whole fleet.
- **No SSO-only deployments.** `initialize_with_platform_secret` returns False; the vault needs a local admin password.
- The admin password becomes a high-value secret (it also opens the vault); losing it loses the vault (`reset_admin`).
- While unlocked, the data key is in process memory: a shell inside the running process still gets it.

The default (platform secret set) is unchanged.

### 7.4 Authentication

`AppAuth(name, audience, role_permissions, scope_permissions)` declares the model; `Principal.can("x:y")` is the only check code
makes. `Authenticator.require("x:y")` is the FastAPI dependency: 401 `authentication required` without a credential, 403
`this credential cannot do that (it lacks 'x:y')` without the permission, 429 after too many bad credentials, 503 when the
database is unreachable.

Bearer resolution order (`resolve_bearer`): static key, `static_tokens` (extra fixed credentials, for example a scrape-only metrics
token), `bearer_resolvers` by prefix (for example merchant keys), local API tokens (by `token_prefix`), then a JWT (three
dot-separated parts) verified with `TokenVerifier`. Without a bearer header, the session cookie is used (disable with
`require(..., allow_cookie=False)`, how TrustDesk's MCP guard refuses browser cookies). `token_cache_seconds > 0` caches
successful local-token lookups; `forget_tokens()` clears this process.

`TokenVerifier(issuer, audience)`: only RS256, ES256 and EdDSA; requires `iss`, `aud`, `exp`, `sub`; 30 s leeway; unknown `kid`
triggers one rate-limited JWKS refresh. `principal_from_claims` keeps only roles of this app and the space-separated `scope` claim,
and sets `kind` to `service` when `sub_type == "service"`.

`RelyingParty(issuer, client_id, secret_getter)`: `begin(conn, redirect_uri, return_to, provider_hint=)` stores state, PKCE verifier
and nonce in `oidc_login` and returns the authorize URL; `finish(conn, redirect_uri, code, state)` consumes the state once, exchanges
the code, verifies the ID token and nonce and returns `(claims, return_to, id_token)`; `logout_url(id_token_hint, post_logout_redirect)`
builds the end-session URL if the provider advertises one. `safe_return_to` accepts only same-site paths.

### 7.5 `SecurityGuard`

```python
app.add_middleware(SecurityGuard, csrf_header="X-Myapp-CSRF", csrf_prefixes=("/api/",), body_prefixes=("/api/",),
                   max_body=64 * 1024, observe=metrics.observe)
```

Adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a strict CSP (`default-src 'none';
script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`)
and `Cache-Control: no-store` (unless set) to every response. 413 for bodies over `max_body` (checked by `Content-Length` and, for
chunked bodies, while streaming). 403 `missing CSRF header` for a non-GET/HEAD/OPTIONS request under a CSRF prefix that has neither an
`Authorization` header nor the CSRF header. Because of the CSP, apps cannot use inline scripts or styles.

### 7.6 `Metrics`

`Metrics(app, version)` exposes `http_requests_total{app,method,route,status}`, `http_request_duration_seconds{app,route}`,
`app_info{app,version}` and `process_*`. `add_db_collector(probe)` registers gauges from the dict the probe returns at scrape time
(it must include `db_up`; if the probe raises, `db_up` is 0 and the scrape still succeeds). `render()` returns `(body, content_type)`.
The guard labels requests by the matched route path, `/mcp` for MCP paths, else `other` (so rejected requests, such as a missing CSRF
header, appear under `route="other"`). `/metrics` itself is not counted.

### 7.7 `NetGuard` and `LLMClient`

`NetGuard(env_name).check(url)` returns the URL without a trailing slash or raises `UnsafeURL` for: empty or over 300 characters,
non-http(s), embedded credentials, query or fragment, unresolvable host, link-local addresses (always), private/loopback addresses
unless the env flag is true, plain http to anything that is not a local server.

`LLMClient(guard, vault=None)`: `chat(cfg, messages, max_tokens=700, temperature=0.1)` posts to `<base_url>/chat/completions`, reads
the answer in bounded chunks, never follows redirects, retries transient errors, redacts the key from every error it raises, and
returns `{"text": ..., "usage": ...}`. `post_json(base_url, path, api_key, body, trusted=...)` is the general call (apps use it for
embeddings; the kit has no embeddings helper). Errors: `LLMError`, `LLMTimeout`, `LLMUnreachable`. An empty answer raises an
`LLMError` that names `finish_reason`, completion tokens and, when present, that the model produced only reasoning. `answer_text(data)` and
`empty_answer_error(data, max_tokens)` give apps the same text for their own calls.

### 7.8 `FailureLimiter`

`limited(client)`, `record(client)`, `clear()`. Memory is bounded (`max_clients`, default 10 000; cleared when exceeded).

### 7.9 The shared UI (`/kit/...`)

Include `/kit/base.css` and load your module script; set `<html data-csrf="X-App-CSRF">`; keep elements with ids `toast`
(`popover="manual"`), `auth-card` and (if you use the vault banner) `vault-banner`. Text is always set with `textContent`; a test fails if
shared JS uses `innerHTML` and similar, or native `confirm`, `alert`, `prompt`.

| Module | Exports |
|---|---|
| `ui.js` | `$`, `h(tag, props, ...kids)`, `fill`, `toast(msg, bad)`, `confirmDialog(message, {title, confirmLabel, cancelLabel, danger, typeToConfirm})` -> `Promise<boolean>`, `promptDialog(message, {title, label, defaultValue, placeholder, confirmLabel, cancelLabel, inputType, min, max, required, validate, multiline})` -> `Promise<string\|null>`, `scrollRegion`, `copy`, `fmtDate`, `fmtDateTime`, `fmtDay`, `money`, `setBusy`, `field`, `loading`, `errorState`, `badge`, `dialogClose`, plus `STATUS`, `ADVICE`, `COMPLIANCE` badge maps (TrustDesk vocabulary) |
| `api.js` | `api(path, {method, json, body, headers})` and `ApiError`. Adds the CSRF header on non-GET, throws readable errors, fires `apg-auth-lost` on a 401 (except under `/api/login`, `/api/setup`, `/login`) and `apg-vault-locked` on a 423 |
| `insights.js` | `initInsights(root, api)`, `topQueriesBlock`, `tunerBlock`, `advisorBlock`; see 7.10 for the `GET /api/insights` contract |
| `session.js` | `state`, `can(permission)`, `refreshSession()`, `bootSession(container, {text, onReady})`, `renderSetup(onDone, product)`, `renderLogin(onDone, notice, product)`, `renderVaultBanner()`; fires `apg-unlocked` after a successful unlock |

Server contract that `session.js` relies on: `GET /api/session` returns `{state, user: {permissions: [...]}, vault: {initialized, unlocked},
password_login, key_login, sso: {login_url, issuer} | null}`; `POST /api/setup {code, password}`; `POST /api/login {password}` or
`{api_key}` (401 for a mismatch); `POST /api/vault/unlock {password}` (403 for a wrong password). `can()` only hides what the server
would refuse; the server enforces.

`base.css` defines design tokens (`--bg`, `--surface`, `--brand`, ... with a dark scheme), layout (`.top`, `.tabs`, `main`, `.card`, `.row`,
`.grid2/3`), forms (`.field`, `.hint`, `.check`), buttons (`primary`, `secondary`, `ghost`, `danger`, `danger-solid`, `small`), tables
(`.card.flush`, `.num`, `td.actions`), badges (`ok`, `alt`, `bad`, `warn`, `plain`), `.banner`, `.toast`, `.loading`, `.error-state`,
`.scroll`, `.sr-only` and the confirm dialog. Tests check badge contrast (WCAG AA) in light and dark and accessible names.

### 7.10 Query insights (`apgkit.insights`, `static/insights.js`, `metrics.add_insights_collector`)

Shows what EDB's extensions on AgentPG know about the workload. Everything is read-only and degrades: a missing extension, a missing
privilege, a timeout or a database error gives `{"available": false, "reason": "..."}` for that part, never an exception or a 500
(each probe runs in a savepoint with `statement_timeout = 5s`). Only a bad `order` argument raises `ValueError`.

```python
from apgkit import insights
with db.connect() as conn:
    insights.sources(conn)                      # {"edb_stat_monitor": {"available": True, "version": "2.1"}, "query_advisor": {"available": False, "reason": "permission denied for this database role"}, ...}
    insights.top_queries(conn, order="mean", limit=20)   # order: "total" | "mean" | "calls"; times in ms
    insights.tuner(conn)                        # {"available", "recommendations": [{"setting", "value", "raw"}], "global_stats": {...} | None}
    insights.advisor(conn, limit=20)            # {"available", "suggestions": [{"schema","table","column","operator","occurrences","executions","rows_filtered","filtered_per_execution","suggestion"}], "summary": {"already_indexed": N}}
    insights.insights_payload(conn, order="total", limit=20)   # {"sources","top_queries","tuner","advisor"}
```

- `top_queries` aggregates `edb_stat_monitor` buckets by `queryid` (calls and times summed, mean = total/calls, max of max) for the
  current database, leaving out error rows (`elevel <> 0`) and the probes' own statements; if `edb_stat_monitor` is absent it uses
  `pg_stat_statements`. Result: `{"available", "source", "order", "queries": [{"queryid" (string), "query", "calls", "total_ms",
  "mean_ms", "max_ms", "rows", "since"}], "since", "text_hidden"}`. Text is whitespace-collapsed and cut at 300 characters. Both
  extensions store the normalised statement (`$1`, `$2`), not the bound values; `query_plan`, `client_ip`, user names and comments are
  never returned. `text_hidden` counts rows whose text the database replaced with `<insufficient privilege>` (a role without
  `pg_read_all_stats` sees other users' statements that way; seen on an AgentPG instance).
- `advisor` reads the base view `query_advisor_qualstats` and resolves table, column and operator itself, because on AgentPG the
  login role is granted `query_advisor_qualstats` and `query_advisor_workload_queries()` but gets "permission denied" on
  `query_advisor_qualstats_pretty` and `query_advisor_qualstats_all`. Joins and catalog tables are left out. The "benefit" is
  `rows_filtered` (rows the condition read and then threw away) and `filtered_per_execution`: an observed hint that an index on that
  column could help, not a measured speed-up. `suggestion` is text only (`Consider an index on t (c)`, equality and range operators
  only); nothing is executed. Since 0.3.1 the SQL leaves out, before the limit applies: dropped columns (`attisdropped`, the
  `........pg.dropped.N........` placeholder, empty names), operators a btree cannot serve (so every row has a non-empty
  `suggestion`), and columns that are the *leading* key column of a valid, non-partial index on that table (primary keys and unique
  indexes included; invalid indexes, partial indexes, expression indexes and second-or-later columns do not count). The number of
  groups hidden because of an existing index is `summary.already_indexed` (absent when the part is unavailable; older payloads
  without it still render), and the UI says "N suggestions hidden: column already indexed.". The checks are plain catalog reads
  (`pg_index`) under the same read-only savepoint and 5 s `statement_timeout`. The platform's own `agentpg recommend all <instance>` builds fuller index/statistics recommendations from the same data.
- `tuner` returns the lines of `edb_pg_tuner_recommendations()` (such as `shared_buffers = '186 MB'`) parsed into setting and value
  (a line that does not parse keeps `raw` with an empty setting) plus the one-row `edb_pg_tuner_global_stats()` as a dict.

**Route contract the app provides** (the module does no auth of its own):

```python
@app.get("/api/insights")
def insights_route(request: Request, order: str = "total", limit: int = 20):
    auth.require(request, "settings:manage")         # or the app's admin permission
    order = order if order in ("total", "mean", "calls") else "total"
    with db.connect() as conn:
        return insights.insights_payload(conn, order, limit)
```

Statement text can reveal table names and the shape of the workload: keep it behind an admin permission, as above.

**UI**: `import { initInsights } from "/kit/insights.js"; initInsights(document.getElementById("main"), api)`. It calls
`GET /api/insights?limit=50` once (Refresh calls it again) and renders a sortable (click a column header; `aria-sort` is set), filterable
(press Enter in the filter box) top-queries table, the tuner recommendations and the advisor suggestions, each in a named scroll
region with a screen-reader caption. A source that is not available shows "Not available on this database." with the server's reason. When statement texts come back as
`<insufficient privilege>` it says that the database role needs `pg_read_all_stats` to show them.
It exports `topQueriesBlock`, `tunerBlock`, `advisorBlock` for apps that want their own layout. Uses only existing tokens, `.sr-only`
and `scrollRegion`; no inline style or script. Tested in node with a fake DOM (`tests/ui/insights.mjs`).

**Metrics**: `Metrics.add_insights_collector(db.connect, top=5, min_calls=5, ttl=30)` (or the module function
`add_insights_collector(registry, connect, app, ...)`) exports, cached for `ttl` seconds so scrapes do not hit the database:
`db_insights_available{app}` (1 if query statistics could be read), `db_insights_top_query_mean_seconds{app,queryid}` (the `top`
slowest statements with at least `min_calls` calls; at most 5 series, though the queryids that appear change over time),
`db_insights_statement_calls{app}` (a gauge: statistics buckets roll off) and `db_insights_tuner_recommendations{app}` (absent if the
tuner is unavailable). A scrape never fails; an error means `db_insights_available 0`. PagerLens alerts on a rising
`db_insights_top_query_mean_seconds` per queryid.

**What exists on an AgentPG instance** (Postgres 18, role without superuser, probed on a throwaway instance):

| Works | Not usable by the login role (needs superuser) |
|---|---|
| `pg_stat_statements` (installed), `edb_stat_monitor` 2.1 (bucketed statistics), `edb_pg_tuner` 1.3.1, `query_advisor` 1.2 (base view and workload function; `_pretty`/`_all` denied), `sql_profiler` (only `sp_profiler_version()` visible), `postgis`, `unaccent`, `citext`, `fuzzystrmatch`, `tcn`, `btree_gin/gist`, `cube`, `tsm_system_rows/time` | `system_stats` (permission denied), `data_redaction`, `pg_prewarm`, `pgstattuple`, `pgrowlocks`, `password_profile`, `sslinfo`, `earthdistance`, `pg_surgery` |

### 7.11 Column masking for the read-only role (`apgkit.masking`)

`data_redaction` needs superuser, but AgentPG gives the same outcome with plain grants. Every instance has the group roles
`a1p_readonly` (SELECT on public tables through default privileges) and `a1p_readwrite`. Direct DB users made with
`agentpg db-users create --permission read` are members of `a1p_readonly`, and AgentPG's restricted MCP server (`agentpg mcp serve
--config` with `access_mode: restricted` and `read_only_url`) runs its queries as that read-only user. Taking the base table away from
the group role and granting it a masking view instead is enforced by the database, whichever client connects. Proven on an instance:
after the change the read-only user got `permission denied for table t` on the base table, masked rows from the view, and writes were refused.

```python
from apgkit import masking, migrate

hook = lambda conn: masking.mask_view(conn, "customer", "customer_masked", {
    "id": "pass", "name": "initial", "email": "email", "card_last4": "last4", "ssn": "redact", "tag": "hash",
    "domain": "split_part(email, '@', 2)"})            # a raw SQL expression is allowed (developer-written, never user input)
migrate.run(db, Path("migrations"), after_migrate=[hook])   # hooks run on EVERY call, after the migrations commit
```

- `mask_view(conn, table, view, columns, readonly_role="a1p_readonly")` creates or replaces `view` WITH `security_barrier`, selecting
  only the listed columns, then `GRANT USAGE ON SCHEMA`, `GRANT SELECT ON view`, `REVOKE SELECT ON table FROM readonly_role`. Rules:
  `pass` (as is), `email` (`***@domain`), `last4` (`**** 1234`), `initial` (`A***`), `hash` (first 12 hex of SHA-256), `redact`
  (`[redacted]`), `null` (NULL of the column's type), or any other string as a raw SQL expression. Columns not listed are not exposed.
  Returns `{"applied", "reason", "base_denied", "view_readable"}`. Names are validated identifiers (`table` may be `schema.table`).
- Idempotent (safe on every migrate). If the role does not exist (plain Postgres in dev or CI) it logs and returns `applied: False`.
- Each statement runs in its own autocommit step (the open transaction is committed first, autocommit restored afterwards): a
  multi-statement call rolls back wholly on any error. If the column set or types changed it drops and recreates the view.
- `masking.describe(conn, table, view, role, sample=0)` reports `role_exists`, `base_readable`, `view_exists`, `view_readable`,
  `columns`, and with `sample=n` the rows as the role sees them (via `SET LOCAL ROLE` in a rolled-back transaction; needs the connected
  user to be allowed to `SET ROLE`, else `sample_error`). `masking.unmask(...)` drops the view and gives SELECT on the table back.
- `migrate.run(after_migrate=[...])` is new in 0.3.0: callables taking the connection, run in order on every call, with no transaction open.

- `masking.deny_tables(conn, tables, readonly_role="a1p_readonly")` is the revoke-only variant (no view) for tables the role must not
  see at all. One `REVOKE` per table, autocommit, idempotent, missing tables skipped. Returns the `mask_view` shape plus
  `tables` (`{name: denied}`) and `skipped`. `masking.drift(conn, tables, role)` lists the tables the role can read right now.

**Failure mode: grants after startup reopen tables.** `mask_view` and `deny_tables` are a snapshot. `agentpg db-users create` (and
AgentPG's default privileges) grant `a1p_readonly` SELECT on base tables again at any time, including tables already masked, so
after `ecoctl mcp users` the role could read raw PII from the base table (the view still masks, but the base is open) until the
next app restart ran the migrate hook. Verified live on TrustDesk. Re-assert periodically:

```python
from apgkit import masking
def apply(conn):                                  # the app's idempotent masking, the same calls as the migrate hook
    masking.mask_view(conn, "employee", "employee_masked", {...})
    masking.deny_tables(conn, ["audit_log"])
# in the lifespan (below): task = asyncio.create_task(masking.reassert_forever(db.connect, apply, 300, deny=["employee", "audit_log"], metrics=metrics))
```

- `masking.reassert_forever(connect, apply, every=300, *, name="masking", deny=(), readonly_role="a1p_readonly", metrics=None, sleep=asyncio.sleep, clock=time.time)`
  is a coroutine: it ticks at once and then every `every` seconds (minimum 1) until cancelled. Each tick runs in a worker thread
  (`asyncio.to_thread`) on its own connection from `connect` (e.g. `db.connect`), so a slow database never blocks the event loop.
  It never raises: a failure logs one warning line and the loop goes on. `deny` is the list of base tables that must stay closed: before
  applying, the tick counts how many the role could read (drift) and logs a warning naming them. `masking.reassert_tick(...)` is one
  blocking tick (returns bool) for tests or a scheduler.
- Metrics (pass the kit's `Metrics` as `metrics`): gauge `masking_last_ok_timestamp`, counter `masking_reapplied_total`, gauge
  `masking_drift_tables` (tables open before the last re-assert; alert on `> 0` and on a stale timestamp). A non-default `name` adds
  the suffix `_<name>` to the three metrics.
- `masking.status(name="masking")` returns `{"last_ok": ISO time | None, "drift": int | None, "ok": bool}` for a readiness or status route.
- Recommended `every`: 300 s. The window in which a new grant is readable is at most one interval; shorter intervals only add catalog reads.
  The loop narrows the window, it does not close it: a grant made just after a tick stays open until the next one.

Limitations and gotchas:

- **Only the table owner can revoke or grant.** A non-owner `REVOKE` only raises a warning and changes nothing, so `mask_view`
  checks `has_table_privilege` afterwards and reports `base_denied: False` (and logs a warning) instead of pretending. Run it as the role that owns the tables.
- **Default privileges re-grant SELECT to `a1p_readonly` on every NEW table.** Mask after the tables exist and again at every migrate
  (the hook does this); a table created later without a mask is readable by the read-only role. Grants made later reopen tables too:
  see the re-assert loop above.
- It protects the `a1p_readonly` path only: the app's own (owner) connection, `a1p_readwrite` members and the platform's owner role see raw data. `PUBLIC` grants would defeat it (reported as `base_denied: False`).
- Hash masking is a short unsalted digest: it hides the value from casual reading, it does not stop a guess-and-compare of low-entropy values.
- A view column with the `pass` rule or a raw expression is exactly as safe as the expression; review them.

## 8. Roles, scopes and permissions

The kit has no fixed roles. Each app declares its own; the kit supplies the machinery.

| Concept | Who holds it | Where it comes from | Mapped by |
|---|---|---|---|
| Permission, for example `requests:decide` | nobody directly | declared and checked in app code via `principal.can()` | n/a |
| Role, for example `trustdesk:approver` | people | the `roles` claim of the ID token or access token, set by identity groups (ecoctl creates groups such as `ecosystem-admins` with role grants) | `AppAuth.role_permissions`; the `<app>:` namespace must equal `AppAuth.name`; a bare role name is accepted as this app's |
| Scope, for example `pagerlens.ingest` | services, local API tokens, the static key | `scope` claim of a `client_credentials` token; `api_token.scope` | `AppAuth.scope_permissions` |
| `*` | local admin session, static key, `full` token (if the app maps it), `admin` role (if the app maps it) | n/a | wildcard passes every `can()` |

Principal kinds: `session`, `token`, `static`, `service`, `user`, `merchant`, `anonymous` (the `kind` field is free text; the kit
sets `session`, `token`, `static`, `service`, `user`, `anonymous`).

Rules that are easy to get wrong, all verified in code or tests:

- A **local** browser session (`source == "local"`) is the whole app's operator and holds `*`, whatever roles an app defines.
- A **federated** session gets permissions only from the roles stored on the session; the app should refuse login when
  `AppAuth.permissions_for(roles=...)` is empty (CityPulse returns "your account has no role in CityPulse").
- Roles of other apps in the same token are ignored.
- A token with no mapped scope has no permissions (an unknown scope maps to the empty set).

Example roles of the fleet apps are in the table in section 2 (from `ecosystem.yaml`); the permission-level mapping of each app is in
that app's `core.py`.

## 9. Security notes

- **Passwords**: scrypt (N=2^17, r=8, p=1, 16-byte salt: OWASP's first scrypt choice in its Password Storage Cheat Sheet), stored as one string with its parameters; 12 to 256 characters. Hashes made with older parameters still verify and are upgraded at the next successful sign-in (`LocalAuth.login_password`); parameters read from storage are bounded so a damaged row cannot demand unbounded memory.
- **Sessions, tokens, keys**: only SHA-256 hashes of session cookies and API tokens are stored; tokens are shown once at creation
  and are revocable; static key compared with `hmac.compare_digest`.
- **Comparisons and logs**: static keys, setup codes, password digests, vault key checks and the OIDC nonce use `hmac.compare_digest`; secrets never appear in log lines or exception messages (the LLM client redacts its key from provider errors; vault errors carry fixed text).
- **Setup code**: 12 characters from an alphabet without look-alikes, held in process memory, printed to the server log. Whoever
  can read the log can create the admin password; completion is refused once an admin exists. It **changes on every restart**
  until setup completes.
- **Vault**: a random 32-byte data key encrypts secrets with Fernet (AES-128-CBC + HMAC-SHA256). The data key is stored only wrapped
  (under a scrypt-derived key from the admin password, and/or from the platform secret; each wrap records its own scrypt parameters, N=2^17 for new wraps, and a legacy N=2^15 wrap is upgraded the next time its secret is presented). The unwrapped key exists only in process
  memory. A database dump alone cannot decrypt; **a dump plus the admin password, or plus the platform secret, can.**
- **Token verification**: algorithm allow-list (`none` and HMAC refused, closing key confusion), mandatory issuer, audience, expiry,
  subject; JWKS from the discovered `jwks_uri`; the discovery document's `issuer` must equal the configured one.
- **Login flow**: PKCE (S256), single-use state and nonce in the database, 10 minute expiry, `return_to` limited to same-site paths.
- **Outbound calls**: `NetGuard` on every non-trusted call, redirects never followed, responses bounded, API key redacted from errors.
  The identity discovery, JWKS and token calls also never follow redirects.
- **Browser**: strict CSP, `no-store`, frame denial, CSRF header on cookie-authenticated writes. Cookies are set by the **app**; the
  fleet apps use `HttpOnly`, `SameSite` (`strict` for local login, `lax` for SSO callback) and `Secure` when the request is https.
- **Limits stated in SECURITY.md**: rate limiting is per process (and keyed by `request.client.host`, so behind a proxy run uvicorn with
  `proxy_headers=True` and a correct `forwarded_allow_ips`, as the fleet apps do); `NetGuard` resolves the host once for the check and
  once for the request.
- **Reporting**: GitHub private vulnerability reporting (see `SECURITY.md`).

## 10. Operations

### 10.1 Health and metrics

The kit defines no routes. By convention the fleet apps expose `GET /healthz` (process up, version), `GET /readyz` (runs `SELECT 1`;
503 `waking-database` while the database wakes) and `GET /metrics` (requires a `metrics:scrape` permission in CityPulse). The Notes
example does the same; `/metrics` there requires `*`. Shared metric names: `http_requests_total`, `http_request_duration_seconds`,
`db_up`, `app_info`, `process_*`, which is what lets one PagerLens agent preset read every app.

### 10.2 Backup and restore

All state is in the app's Postgres database, so `pg_dump` of that database is the backup. Back up **separately**: the platform secret
(`<PREFIX>_ENCRYPTION_KEY`) if you rely on it, because without it and without the admin password the vault cannot be opened; the
static key and OIDC client secret (ecoctl keeps generated ones in `.ecosystem/state.json`). After a restore, start the app: it
migrates, tries the platform secret, and otherwise shows the vault banner for the admin to unlock.

### 10.3 Rotation, verified

| What | How | Verified |
|---|---|---|
| Admin password | `LocalAuth.change_password(conn, current, new)` (apps expose it; CityPulse also deletes all `web_session` rows afterwards). The vault data key is **re-wrapped**, not changed, so stored secrets stay readable. | yes: old password refused, new accepted, old ciphertext still decrypts |
| Platform secret (`<PREFIX>_ENCRYPTION_KEY`) | `Vault.rotate_platform_secret(conn, new_secret)` while unlocked (re-wrap only: NOT sufficient after exposure, see 7.3.1), or set the new value and restart. Auto-unlock with the old wrap now fails closed: the vault stays locked, `try_unlock_with_platform_secret` returns False and `Vault.status(conn)` keeps `"auto_unlock": true` (a platform key and a wrap exist, so apps report a vault that should open but cannot, for example `/readyz` 503) and reports `"reason": "platform_key_mismatch"` (other reasons: `not_initialized`, `no_platform_key`, `no_platform_wrap`, `locked`). The admin then unlocks with the password (`unlock_with_password`, which `LocalAuth.login_password` calls); the kit notices that the platform wrap is missing or does not open with the current key and **re-wraps the data key under the new secret automatically**. The next restart auto-unlocks. A wrong or damaged wrap never raises and never overwrites anything until a password unlock succeeds. No manual SQL is needed. | yes (tests `test_vault_*` in `tests/test_db_blocks.py`) |
| Vault data key | `Vault.rotate_data_key(conn, reencrypt=None, password=...)`: new random key, every stored secret re-encrypted and both wraps rewritten in ONE transaction (section 7.3.1). Re-wrapping alone (platform secret, admin password) does not change the data key. `Vault.reset(conn)` forgets the key and every wrap: everything encrypted becomes unreadable and the app must delete it (the `on_reset` hook). | yes (tests in `tests/test_vault_hardening.py`) |
| Local API token | create a new token, switch clients, `LocalAuth.revoke_token(conn, id)`. With `token_cache_seconds > 0`, other processes honour a revoked token for up to that long; call `forget_tokens()`. | yes (test) |
| Static key | change the env value or file, restart. | by reading code |
| Identity signing keys | handled by identity; consumers re-fetch JWKS on an unknown `kid` (once per 15 s) with no restart. | yes (test) |
| OIDC client secret | rotate at identity (ecoctl `--rotate`), update `<PREFIX>_OIDC_CLIENT_SECRET`, restart. | by reading code |
| Forgot the admin password | operator recovery `LocalAuth.reset_admin(conn)` (apps expose it as a CLI, for example `citypulse reset-admin`): deletes the hash, resets the vault, runs `on_reset`, deletes all sessions; restart prints a new setup code. | yes (test) |

### 10.4 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| stderr: `database not reachable (attempt n/5): ...` then `RuntimeError: database unavailable after 5 attempts` | Wrong DSN, database down, or scaled-to-zero and still waking. Seen when `DATABASE_URL` was not exported and libpq fell back to the default socket. | Check the three DSN variables and `PG*`; wait and retry; on AgentPG resume the sandbox/instance. |
| `AttributeError: 'bytes' object has no attribute 'encode'` in the vault, or `DuplicateTable` in tests | The database has `SQL_ASCII` encoding, so `text` comes back as `bytes`. | Create the database with `UTF8` (`initdb -E UTF8`, or `CREATE DATABASE ... ENCODING 'UTF8' TEMPLATE template0`). |
| 403 `missing CSRF header` | A cookie-authenticated (or unauthenticated) non-GET under a CSRF prefix without the header | Send the header named in `data-csrf` / `csrf_header`; API clients should use `Authorization: Bearer`. |
| 401 `authentication required` | No credential | Sign in, or send a token. |
| 403 `this credential cannot do that (it lacks 'x:y')` | Role/scope not mapped to that permission | Fix the mapping in `AppAuth` or the token's scope. |
| 401 `invalid credentials`, then 429 `too many failed attempts; wait a minute` | 10 bad bearers from one address within 60 s | Wait; fix the credential; check the real client address behind a proxy. |
| 413 `request body too large` | Over `max_body` (default 64 KiB) | Raise `max_body` for that app deliberately (CityPulse sets 2 MiB). |
| 503 `database unavailable; it may be waking up, retry in a few seconds` | Authenticator could not reach Postgres | Retry; check the database. |
| Vault banner "locked" after every restart | No platform secret wrapped | Set `<PREFIX>_ENCRYPTION_KEY`, unlock once with the password, restart. |
| `Stored secrets are locked. Sign in with your admin password to unlock them.` | Vault locked (`VaultLocked`) | Unlock with the admin password. |
| `A stored secret could not be decrypted. Re-enter it.` | The ciphertext was made with a different data key (for example after `reset`) | Re-enter the secret. |
| `the login attempt is unknown or expired; start again` | Login state older than 10 min, already used, or removed | Start the login again. |
| `the discovery document names a different issuer than the one configured` or `the issuer must use https` | Issuer URL differs from what identity reports (for example identity reached over another host name) | Set identity's public URL and use that exact string for `<PREFIX>_OIDC_ISSUER`. |
| `provider URL rejected: that address is private or local; set X=true ...` | `NetGuard` refused a private target | Use a public https URL, or set the app's allow-private variable for a local model server. |
| `the model used all N completion tokens before answering (...)` / `the model produced only reasoning` | A thinking model spent its budget on reasoning | Raise `max_tokens` or use a non-thinking model. |
| LLM call count higher than expected on the gateway | `LLMClient` retries each transient failure up to 3 times | Account for up to 4 gateway requests per failed call (this was the cause of one earlier budget burn, per `ecosystem/docs/01`). |
| No setup code in the log | An admin password or static key already exists, federation is on, or the database was asleep at start | Reset with the app's reset command, or request `/api/session` once (apps print the code on the first request that finds setup required). |

## 11. Testing and development

```bash
export TEST_DATABASE_URL=postgresql://...      # throwaway database; tests drop its public schema
.venv/bin/pytest -q
.venv/bin/ruff check src tests                 # line length 110; rules E, F, I, B, UP (B008, B905, E501 ignored)
```

| File | Covers |
|---|---|
| `tests/test_basics.py` | `read_secret`, `database_url` order, ids, password hashing, `FailureLimiter`, `NetGuard` (private, link-local, shape rules), `SecurityGuard` headers/CSRF/body caps (also chunked), `Metrics`, `LLMClient` bounded reads and typed errors, empty-answer messages |
| `tests/test_db_blocks.py` | migrations (once, ordered, replacements, per-app tables), vault lifecycle and platform-secret unlock, setup flow, static key, sessions, token scope/hash/revocation, reset hook, upgrade of a pre-kit `web_session`, non-waiting pool, `Authenticator` static tokens, cache and public resolver |
| `tests/test_insights.py` | insights with fakes shaped like `edb_stat_monitor`, `query_advisor_qualstats` and `edb_pg_tuner` (aggregation, filtering, truncation, no plan/IP/user leak, parsing, advisor dropped-column and already-indexed suppression against a real `pg_index`), nothing installed, unreadable source via a real unprivileged role, metrics collector; `pg_stat_statements` only if loaded (else skipped) |
| `tests/test_masking.py` | real roles `a1p_readonly` and a login member: base table denied, masked view allowed, writes refused, idempotent re-run, view column changes, after-migrate hook re-masks, missing role skipped, non-owner reported, `describe`/`unmask`, input validation |
| `tests/test_oidc.py` | `TokenVerifier` (valid, audience list, bad claims, wrong key, `alg=none` and HMAC confusion, key rotation, refresh rate limit, discovery issuer check), `principal_from_claims`, `TokenSource` caching, `safe_return_to`, full PKCE login flow including single-use state, public client, `Authenticator` with every credential kind, rate limiting |
| `tests/test_ui.py` | runs each `tests/ui/*.mjs` under node (skipped without node); asserts no `innerHTML`-style APIs and no native dialogs in shared JS; asserts every kit-rendered control has an accessible name |
| `tests/ui/*.mjs` | fake-DOM scripts: confirm/prompt dialogs, dialog inside another modal, loading/error states, login card, contrast of badge tokens (WCAG AA), `scrollRegion` |

CI (`.github/workflows/test.yml`): Ubuntu, Python 3.12, a `pgvector/pgvector:pg17` service, `pip install -e ".[dev]"`, ruff, pytest.

Release routine (from the repository history and the fleet's Dockerfiles): bump `__version__` in
`src/apgkit/__init__.py` (the single source; `pyproject.toml` reads it), add a README changelog entry, tag `vX.Y.Z`; then each app moves
its `KIT_URL` and `>=` pin. The documented order is kit, identity, gateway, apps.

Adding to the shared UI: no `innerHTML`, no native dialogs, give every control a name, run the node scripts.

## 12. AIDB and AgentPG integration

**What the kit does today for AgentPG** (all in code):

- DSN handling matches what AgentPG sandboxes provide: `DATABASE_URL`, `DB_EXTERNAL_DSN`, `PSQL_CONNECTION_STRING`, and libpq's `PG*`
  fallback (`config.database_url`).
- **Scale-to-zero tolerance**: `Database.connect` retries with backoff; `Database(pool_wait=False)` plus `Authenticator.db_unavailable()` turn a
  waking database into a quick 503 with a clear message; `api.js` turns 502/503/504 into "The server is unavailable. It may be
  paused or waking up"; the setup screen's hint names `agentpg sandbox logs <sandbox-id>`.
- **TLS in front of the sandbox**: `web.is_https` and `public_url` honour `X-Forwarded-Proto`.
- **pgvector**: `Database(vector=True)` registers the adapter; `migrate.run(extensions=("vector",))` creates the extension (the apps use
  `vector` and `pg_trgm`). The kit contains no embedding, chunking or retrieval code.
- **LLM access through the gateway**: `LLMClient` speaks the OpenAI-compatible `/chat/completions` surface, which is what the
  ecosystem's llm-gateway serves; apps send the gateway's `lg_` key as `LLM_API_KEY`.

**AIDB**: nothing in this repository references AIDB (a search of `src`, `tests` and the README finds no occurrence). The design in
`ecosystem/docs/03-aidb-integration.md` (a design, not an implementation, written 2026-10-25) proposes for the kit: **a retrieval backend
interface with two implementations, `app` (the apps' current code) and `aidb`, chosen with one setting**, so every app stays runnable
on plain Postgres and the before/after comparison is a toggle. It is listed as step 5 of that plan, to be extracted after the
TrustDesk migration. That document also records, as of 2026-10-25, that AIDB 7.8.0 installs on an AgentPG instance but the instance's login
role lacks the `aidb_users` grant, which blocks any use until the platform changes it. Treat all of this as **planned, not built**.

## 13. Known limitations and things not verified

Limitations of the kit (verified in code):

- **No MCP helper.** The kit contains no MCP code (the only occurrence of "mcp" is a metrics route label in `guard.py`), and
  there is no `mcp` extra (removed in 0.2.6; it only pulled the SDK and an old description claimed a helper). TrustDesk implements
  `mcp_server.py` itself and guards `/mcp` with its own `McpGuard` middleware (`auth.authenticate(request, allow_cookie=False)`,
  then permission `mcp:use`). `pip install "agentpg-kit[mcp]"` still works but pip warns that the extra does not exist.
- **No HTTP routes** for setup, login, logout, vault unlock, SSO or tokens; the app writes them (the example shows a minimum).
- **No multi-replica safety for migrations or the setup code.** Migrations are unlocked (use an advisory lock). The setup code is per
  process: with several replicas the code printed by the replica that did not serve your request is wrong.
- **Rate limiting is per process** and keyed by remote address.
- **No vault data-key rotation.** Platform-secret rotation needs no helper: unlock once with the admin password (see 10.3).
- **`vault.py` shares `app_setting` keys** `vault_salt`, `vault_wrap_pw`, `vault_env_salt`, `vault_wrap_env` and `settings_store` keys
  `admin_password_hash`; do not reuse those names.
- **Shared UI is partly product-flavoured**: the vault banner text says "Provider keys are locked ... (external embeddings and Ask are
  paused)" and `ui.js` carries `STATUS`/`ADVICE`/`COMPLIANCE` maps from TrustDesk; the layout assumes the element ids listed in 7.9.
- **Insights and masking are only proven against fakes and a plain Postgres in tests**: the AgentPG-specific parts (real `edb_stat_monitor` rows, the
  real `a1p_readonly` default privileges) were checked by read-only probes and one throwaway instance, not by the test suite.
- **`edb_pg_tuner_global_stats()` and `edb_pg_tuner_query_stats()`** have no declared column names; the kit returns the former as
  the dict the cursor describes and does not wrap the latter. `query_advisor_index_recommendations()` is not used (its columns are undeclared too).
- **Kit `Federation.local_login` is advisory**; the app must enforce it.
- **`LLMClient` has chat only**; its retries multiply load on a metered gateway.
- Fleet apps pin `>=0.2.5` but only the Dockerfile tag pins an exact version.

Not verified while writing this guide:

- Docker commands in 4.2 (the daemon was not running); the compose description in 4.3 was read from CityPulse's file, not executed.
- `ecoctl` behaviour was read from its README, manifest and `plan.py`, not run (the task forbade deployments); no live service was called.
- Single sign-on with a real identity provider (only the kit's own tests with a fake provider).
- Per-app role-to-permission mappings other than CityPulse's and TrustDesk's were not read; roles and scopes in the tables come
  from `ecosystem.yaml`.
- PayBroker's use of `bearer_resolvers` (inferred from the `Authenticator` docstring).
- Python versions other than 3.12 (the kit's own venv) and 3.13 (the Notes example's venv); Postgres versions other than 17.
