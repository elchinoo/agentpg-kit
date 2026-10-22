# agentpg-kit

The small, reusable blocks that every app in the AgentPG ecosystem is built from, so an app is its own logic and not a copy
of the same vault, auth and middleware again. Import name: `apgkit`.

| Block | What it gives you |
|---|---|
| `apgkit.config` | `read_secret` (env, or a file named by `<ENV>_FILE`), `database_url` (the three DSN variables AgentPG may set), `env_bool` |
| `apgkit.db`, `apgkit.migrate`, `apgkit.settings_store` | Postgres connections that retry while a scaled-to-zero database wakes, an optional pool, the pgvector adapter, a plain-SQL migration runner (each app its own migration table), a key/value settings table |
| `apgkit.passwords`, `apgkit.vault`, `apgkit.ratelimit` | scrypt password hashing; envelope encryption for stored secrets (data key wrapped under the admin password and/or a platform secret; can start from the platform secret alone for SSO-only deployments); failed-attempt limiter |
| `apgkit.netguard`, `apgkit.llm` | SSRF guard for URLs the server will call; an OpenAI-compatible client that guards, retries, never follows redirects, bounds responses and redacts keys |
| `apgkit.guard`, `apgkit.metrics`, `apgkit.web` | one security middleware (headers, CSP, body cap, CSRF header for browser writes, request metrics); the metric names every app shares; URL helpers |
| `apgkit.auth` | `AppAuth` (an app's roles, scopes and permissions), `Principal`, `LocalAuth` (admin password, sessions, API tokens, static key), `TokenVerifier` and `RelyingParty` (federated login), `TokenSource` (service tokens), `Authenticator` (one `require("x:y")` that accepts all of it), `from_env` (turn federation on with `<APP>_OIDC_*` variables) |
| `apgkit.static` (served at `/kit/`) | the shared UI: `base.css`, `ui.js`, `api.js`, `session.js`, logos |

## Authentication and authorization model

An app declares **permissions** (`requests:decide`) and maps **roles** (given to people by the identity provider, namespaced
`<app>:<role>` in tokens) and **scopes** (given to services, local API tokens and the static key) onto them. Code only asks
`principal.can("requests:decide")`. The same `require(...)` works standalone (local admin password) and federated (tokens from
the ecosystem [identity](https://github.com/elchinoo/identity) provider, verified locally against its JWKS).

Verification is strict: RS256/ES256/EdDSA only (`none` and HMAC refused, which also closes key confusion), issuer, audience,
expiry and not-before checked, unknown `kid` triggers one rate-limited JWKS refresh, roles of other apps are ignored.

```python
from apgkit.auth import AppAuth, Authenticator, LocalAuth, from_env
from apgkit.db import Database
from apgkit.vault import Vault

db, vault = Database(), Vault("MYAPP")
fed = from_env("MYAPP", "myapp")                      # MYAPP_OIDC_ISSUER / _CLIENT_ID / _CLIENT_SECRET
app_auth = AppAuth("myapp", fed.client_id, role_permissions={"admin": frozenset({"*"})}, scope_permissions={"read": frozenset({"things:read"})})
local = LocalAuth(app_auth, env_prefix="MYAPP", token_prefix="ma_", token_scopes={"read", "full"}, vault=vault)
auth = Authenticator(app_auth, local, db, cookie_name="ma_session", verifier=fed.verifier)

@app.get("/things", dependencies=[Depends(auth.require("things:read"))])
def things(): ...
```

## Install

Apps pin a release: `pip install "agentpg-kit @ https://github.com/elchinoo/agentpg-kit/archive/refs/tags/v0.2.0.tar.gz"`.
For local development put this repository next to the app and use `uv pip install -e ../agentpg-kit`.

## Tests

```bash
export TEST_DATABASE_URL=postgresql://...      # a throwaway database; the database tests drop its public schema
pytest -q
```
