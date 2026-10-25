# agentpg-kit

The small, reusable blocks that every app in the AgentPG ecosystem is built from, so an app is its own logic and not a copy
of the same vault, auth and middleware again. Import name: `apgkit`.

| Block | What it gives you |
|---|---|
| `apgkit.config` | `read_secret` (env, or a file named by `<ENV>_FILE`), `database_url` (the three DSN variables AgentPG may set), `env_bool` |
| `apgkit.db`, `apgkit.migrate`, `apgkit.settings_store` | Postgres connections that retry while a scaled-to-zero database wakes, an optional pool, the pgvector adapter, a plain-SQL migration runner (each app its own migration table), a key/value settings table |
| `apgkit.passwords`, `apgkit.vault`, `apgkit.ratelimit` | scrypt password hashing; envelope encryption for stored secrets (data key wrapped under the admin password and/or a platform secret; can start from the platform secret alone for SSO-only deployments); failed-attempt limiter |
| `apgkit.netguard`, `apgkit.llm` | SSRF guard for URLs the server will call; an OpenAI-compatible client that guards, retries, never follows redirects, bounds responses and redacts keys; an empty chat answer raises an `LLMError` that says why (`finish_reason`, completion tokens, a thinking model that spent its budget on reasoning) and `answer_text` / `empty_answer_error` give apps the same text |
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

## Shared UI states

Every app shell should show something while data is on its way and something actionable when it fails. All of it is plain
DOM with `textContent` (strict CSP: no inline script or style):

```js
import { loading, errorState } from "/kit/ui.js";
import { bootSession } from "/kit/session.js";

loading(main, "Loading requests\u2026");               // spinner + status text (CSS class .loading)
errorState(main, "Could not load.", () => load());     // message + "Try again" button (CSS class .error-state)

const session = await bootSession(main);               // loading state, then error + retry if /api/session fails; null on error
```

`bootSession(container, { text, onReady })` is the session bootstrap: call it instead of `refreshSession()` at start-up so
the content area is never blank after single sign-on. The vault unlock banner is built once and only shown or hidden, so a
refresh never clears what is typed into it. Do the same in apps: update changed nodes, never rebuild one that holds input.

### Confirmations: `confirmDialog`

Never call `window.confirm()`, `alert()` or `prompt()`: native dialogs cannot be styled and freeze automated browser tests
(a kit test fails if shared JS uses them). Use the shared modal, and `toast()` for plain messages:

```js
import { confirmDialog, toast } from "/kit/ui.js";

if (!(await confirmDialog("Delete this request?", { title: "Delete request", confirmLabel: "Delete", danger: true }))) return;
const ok = await confirmDialog("This erases every stored secret.", { danger: true, typeToConfirm: "ERASE", confirmLabel: "Erase vault" });
```

`confirmDialog(message, { title, confirmLabel, cancelLabel, danger, typeToConfirm })` returns `Promise<boolean>`. It renders
`role="alertdialog"` with `aria-modal`, `aria-labelledby` and `aria-describedby`; focus moves in (to the input, else the safe
button) and is trapped with Tab; Escape and a backdrop click cancel; Enter confirms unless a `typeToConfirm` phrase is required
and not yet typed; focus returns to the opener; the page behind does not scroll (`body.modal-open`). With `typeToConfirm` the
confirm button stays disabled until that exact phrase is typed. The dialog lives under `<body>`, so re-rendering the app
never clears the typed phrase. Calls made while one is open queue. Message text is set with `textContent` only.

## Install

Apps pin a release: `pip install "agentpg-kit @ https://github.com/elchinoo/agentpg-kit/archive/refs/tags/v0.2.0.tar.gz"`.
For local development put this repository next to the app and use `uv pip install -e ../agentpg-kit`.

## Tests

```bash
export TEST_DATABASE_URL=postgresql://...      # a throwaway database; the database tests drop its public schema
pytest -q
```

## Changelog

### 0.2.4
- New: `confirmDialog()` in `ui.js` (+ `.confirm-*`, `button.danger-solid` styles): accessible promise-based replacement for `window.confirm()`, with optional type-to-confirm phrase. Reuses the existing `toast()` for messages.
- Tests: confirm dialog fake-DOM test; a check that shared JS never calls `confirm`/`alert`/`prompt`.

### 0.2.3
- Fix: the vault unlock banner no longer loses typed text or focus when the session is refreshed.
- New: `loading()` and `errorState()` (with retry) in `ui.js`, `.loading` / `.error-state` styles, and `bootSession()` in `session.js` so the content area is never blank while the session loads.
- Tests: node fake-DOM tests under `tests/ui`, run by pytest.
