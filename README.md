# agentpg-kit

The small, reusable blocks that every app in the AgentPG ecosystem is built from, so an app is its own logic and not a copy
of the same vault, auth and middleware again. Import name: `apgkit`.

**Documentation:** [docs/GUIDE.md](docs/GUIDE.md) (purpose, ecosystem, architecture, install, configuration, first-run walkthrough, operations) and [docs/VIDEO-SCRIPT.md](docs/VIDEO-SCRIPT.md) (tutorial: build a new app in 10 minutes). The runnable tutorial app is in [docs/examples/notes](docs/examples/notes).

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

### Confirmations and prompts: `confirmDialog`, `promptDialog`

Never call `window.confirm()`, `alert()` or `window.prompt()`: native dialogs cannot be styled and freeze automated browser tests
(a kit test fails if shared JS uses them). Use the shared modal, and `toast()` for plain messages:

```js
import { confirmDialog, toast } from "/kit/ui.js";

if (!(await confirmDialog("Delete this request?", { title: "Delete request", confirmLabel: "Delete", danger: true }))) return;
const ok = await confirmDialog("This erases every stored secret.", { danger: true, typeToConfirm: "ERASE", confirmLabel: "Erase vault" });
```

`confirmDialog(message, { title, confirmLabel, cancelLabel, danger, typeToConfirm })` returns `Promise<boolean>`. It renders
a native `<dialog role="alertdialog">` opened with `showModal()` (with `aria-modal`, `aria-labelledby`, `aria-describedby`); focus moves in (to the input, else the safe
button) and is trapped with Tab; Escape and a backdrop click cancel; Enter confirms unless a `typeToConfirm` phrase is required
and not yet typed; focus returns to the opener; the page behind does not scroll (`body.modal-open`). With `typeToConfirm` the
confirm button stays disabled until that exact phrase is typed. The dialog lives under `<body>`, so re-rendering the app
never clears the typed phrase. Because it is a modal `<dialog>` itself, it also works above an app's own `showModal()` window
(the app window becomes inert while it is up, and works again afterwards); browsers without `showModal()` get the `open`
attribute and a fixed overlay (`.confirm-fallback`). Calls made while one is open queue. Message text is set with `textContent` only.

```js
import { promptDialog } from "/kit/ui.js";

const reason = await promptDialog("Shown to analysts.", { title: "Chargeback", label: "Reason", required: true });   // string | null
const mins = await promptDialog("Keep the old key working for how many minutes?", { inputType: "number", min: 0, max: 1440, defaultValue: "10", required: true });
const pw = await promptDialog("New password for alice", { inputType: "password", validate: (v) => (v.length < 12 ? "Use at least 12 characters." : null) });
if (pw === null) return;   // cancelled
```

`promptDialog(message, { title, label, defaultValue, placeholder, confirmLabel, cancelLabel, inputType, min, max, required, validate, multiline })`
returns `Promise<string | null>`: the entered text as typed (numbers too, as a string), `null` on cancel, Escape or a backdrop click.
It is the same modal (same ARIA, focus trap, queueing, restore). Enter submits a single-line input; in `multiline` (a textarea)
Enter adds a line and Ctrl/Cmd+Enter submits. The confirm button stays disabled while the value is invalid: blank when
`required`, outside `min`/`max` or not a number for `inputType: "number"`, or when `validate(value)` returns a message, which is
shown inline (`role="alert"`). `inputType: "password"` renders a password field with `autocomplete="new-password"`; the value is
only ever returned to the caller, never logged or written into the page text.

## Accessibility helpers

```js
import { scrollRegion } from "/kit/ui.js";
scrollRegion(tableWrapper, "Recent payments");   // adds .scroll, tabindex="0", role="region", aria-label
```

- `.scroll` (CSS) sets `overflow: auto` and a focus ring. Give every container that can scroll (a wide table wrapper, a `<pre>`)
  `scrollRegion(el, label)` so keyboard users can reach it (axe: `scrollable-region-focusable`). Existing `.card.flush` wrappers
  that scroll: wrap with `scrollRegion(card, "...")`.
- `.sr-only` hides text visually but keeps it for screen readers. Never ship an empty header cell: write
  `<th><span class="sr-only">Actions</span></th>` (`h("th", {}, h("span", { class: "sr-only" }, "Actions"))`) for action columns and
  the heatmap corner cell (axe: `empty-table-header`).
- Controls need a name: use `field(label, input)` (a real `<label>`), or `aria-label` on a `<select>`/`<input>` that has no
  visible label, e.g. `h("select", { "aria-label": `App for group ${name}` })` (axe: `select-name`).
- Status badges (`.badge`, `.ok`, `.alt`, `.bad`, `.warn`, `.plain`) and status text meet WCAG AA (4.5:1) in light and dark; a test
  (`tests/ui/contrast.mjs`) checks every pair. Apps defining their own badge colours should use `--ok`, `--alt`, `--err`, `--warn`
  on `--surface`/`--bg`, which are AA-safe, instead of raw `--brand-2`.

## Install

Apps pin a release: `pip install "agentpg-kit @ https://github.com/elchinoo/agentpg-kit/archive/refs/tags/v0.2.0.tar.gz"`.
For local development put this repository next to the app and use `uv pip install -e ../agentpg-kit`.

## Tests

```bash
export TEST_DATABASE_URL=postgresql://...      # a throwaway database; the database tests drop its public schema
pytest -q
```

## Changelog

### 0.3.0
- New: `apgkit.insights` (query insights from `edb_stat_monitor`, `pg_stat_statements`, `edb_pg_tuner`, `query_advisor`; every source degrades to `{"available": false, "reason"}`), `metrics.add_insights_collector` (small-cardinality gauges), shared `static/insights.js` (`initInsights(root, api)`) and `apgkit.masking` (database-enforced masking views for the AgentPG read-only role `a1p_readonly`).
- New: `migrate.run(..., after_migrate=[hook, ...])`, hooks run on every call after the migrations commit (backward compatible; default empty).
- Docs: GUIDE sections 7.10 and 7.11 with the verified facts and limitations.

### 0.2.5
- Fix: `confirmDialog()`/`promptDialog()` could not be clicked or typed into while an app had a modal `<dialog>` open via `showModal()` (PayBroker merchant window, ShopFront order window): the old `popover="manual"` overlay was inert there. The shared modal is now a native `<dialog role="alertdialog">` opened with `showModal()`, which stacks above an earlier modal dialog. Same API and behaviour (focus trap/restore, Escape and backdrop cancel, typeToConfirm, validation, queueing, scroll lock); fallback for browsers without `showModal()`. CSS: `.confirm-overlay` is replaced by `dialog.confirm-dialog` and its `::backdrop`; apps styling `.confirm-overlay` must update.
- Accessibility: `.badge.ok` and `.badge.alt` text colours now reach 4.5:1 in light and dark (new `--alt` token, darker light `--ok`); the vault unlock input has an `aria-label`.
- New: `scrollRegion(el, label)` in `ui.js` and the `.scroll` class (keyboard-reachable scrolling regions); `.sr-only` for visually hidden text (non-empty action column headers). Apps adopt them as described under "Accessibility helpers".
- Tests: modal-in-modal regression (`confirm_in_modal.mjs`, fails on 0.2.4), native cancel and fallback cases, contrast test of the badge/status tokens, `scrollRegion` test, accessible-name check.

### 0.2.4
- New: `confirmDialog()` in `ui.js` (+ `.confirm-*`, `button.danger-solid` styles): accessible promise-based replacement for `window.confirm()`, with optional type-to-confirm phrase. Reuses the existing `toast()` for messages.
- New: `promptDialog()` in `ui.js`: replacement for `window.prompt()` on the same modal (text, password or number input, required, `validate()` with an inline error, multiline). Resolves a string, or `null` on cancel.
- Tests: confirm and prompt dialog fake-DOM test; a check that shared JS never calls `confirm`/`alert`/`prompt`.

### 0.2.3
- Fix: the vault unlock banner no longer loses typed text or focus when the session is refreshed.
- New: `loading()` and `errorState()` (with retry) in `ui.js`, `.loading` / `.error-state` styles, and `bootSession()` in `session.js` so the content area is never blank while the session loads.
- Tests: node fake-DOM tests under `tests/ui`, run by pytest.
