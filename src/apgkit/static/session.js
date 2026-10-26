import { api } from "/kit/api.js";
import { $, h, toast, loading, errorState } from "/kit/ui.js";

export const state = { session: null, accounts: null };

// Does the signed-in person hold this permission? (The server enforces it; this only hides what would be refused.)
export function can(permission) {
  const perms = state.session?.user?.permissions || [];
  return perms.includes("*") || perms.includes(permission);
}

export async function refreshSession() {
  state.session = await api("/api/session");
  return state.session;
}

// Load the session with a visible state in `container` (the app's content area): "Loading..." while the request is
// in flight (after single sign-on this can take seconds), an error with a retry button if it fails. Resolves to the
// session, or null after an error. The caller renders its own content afterwards, replacing the loading state.
export async function bootSession(container, { text = "Loading\u2026", onReady } = {}) {
  loading(container, text);
  let session;
  try {
    session = await refreshSession();
  } catch (ex) {
    errorState(container, ex.message || "Could not load the session.", () => bootSession(container, { text, onReady }));
    return null;
  }
  if (onReady) await onReady(session);
  return session;
}

// ---- first-run setup ----------------------------------------------------------------------------
export function renderSetup(onDone, product = "this app") {
  const box = $("auth-card");
  const code = h("input", { id: "setup-code", autocomplete: "off", spellcheck: "false", placeholder: "XXXX-XXXX-XXXX", required: true });
  const pw = h("input", { id: "setup-pw", type: "password", autocomplete: "new-password", minlength: "12", required: true });
  const pw2 = h("input", { id: "setup-pw2", type: "password", autocomplete: "new-password", minlength: "12", required: true });
  const err = h("p", { class: "error", role: "alert" });
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      if (pw.value !== pw2.value) { err.textContent = "The passwords do not match."; return; }
      try {
        await api("/api/setup", { method: "POST", json: { code: code.value, password: pw.value } });
        pw.value = pw2.value = "";
        toast("Admin password set. You are signed in.");
        onDone();
      } catch (ex) { err.textContent = ex.message; }
    },
  },
  h("label", { for: "setup-code" }, "Setup code"),
  code,
  h("p", { class: "hint" }, "Printed in the server log when the server started. On AgentPG: agentpg sandbox logs <sandbox-id>"),
  h("label", { for: "setup-pw" }, "Choose an admin password (12+ characters)"),
  pw,
  h("label", { for: "setup-pw2" }, "Repeat the password"),
  pw2,
  h("button", { class: "primary", type: "submit" }, "Create admin password"),
  err);
  box.replaceChildren(
    h("img", { class: "hero-logo", src: "/kit/logo.svg", alt: "", width: "72", height: "72" }),
    h("h1", {}, `Set up ${product}`),
    h("p", { class: "muted" }, "Nobody has an account yet. Prove you operate this server with the one-time code from its log, then pick a password. It is stored only as a salted hash."),
    form);
  box.hidden = false;
  code.focus();
}

// ---- login --------------------------------------------------------------------------------------
export function renderLogin(onDone, notice = "", product = "this app") {
  const box = $("auth-card");
  const s = state.session || {};
  const pw = h("input", { id: "login-pw", type: "password", autocomplete: "current-password", required: true });
  const err = h("p", { class: "error", role: "alert" }, notice);
  const send = async (json) => {
    err.textContent = "";
    try {
      await api("/api/login", { method: "POST", json });
      onDone();
    } catch (ex) { err.textContent = ex.status === 401 ? "That did not match." : ex.message; }
  };
  const children = [
    h("img", { class: "hero-logo", src: "/kit/logo.svg", alt: "", width: "72", height: "72" }),
    h("h1", {}, `Sign in to ${product}`),
  ];
  const ssoError = new URLSearchParams(location.search).get("sso_error");
  if (s.sso) {
    children.push(ssoError ? h("p", { class: "error", role: "alert" }, ssoError) : null,
      h("a", { class: "button primary sso", href: `${s.sso.login_url}?next=${encodeURIComponent("/" + location.hash)}` }, "Sign in with single sign-on"),
      h("p", { class: "hint" }, `Your organisation's identity provider (${new URL(s.sso.issuer).host}) signs you in.`));
  }
  if (s.password_login) {
    if (s.sso) children.push(h("details", { class: "alt-login" }, h("summary", {}, "Administrator password")));
    children.push(h("form", { onsubmit: (e) => { e.preventDefault(); const v = pw.value; pw.value = ""; send({ password: v }); } },
      h("label", { for: "login-pw" }, "Admin password"), pw,
      h("button", { class: "primary", type: "submit" }, "Sign in"), err));
  }
  if (s.key_login) {
    const key = h("input", { id: "login-key", type: "password", autocomplete: "off" });
    children.push(h("details", { class: "alt-login" }, h("summary", {}, "Use the server's API key instead"),
      h("form", { onsubmit: (e) => { e.preventDefault(); const v = key.value; key.value = ""; send({ api_key: v }); } },
        h("label", { for: "login-key" }, "API key"), key,
        h("button", { class: "secondary", type: "submit" }, "Sign in with key"))));
    if (!s.password_login) children.push(err);
  }
  box.replaceChildren(...children.filter((c) => c != null && c !== false));   // replaceChildren would print null as the text "null"
  box.hidden = false;
  (s.password_login ? pw : $("login-key"))?.focus();
}

// ---- vault unlock banner ------------------------------------------------------------------------
// Built once and then only shown or hidden: the page refreshes the session on a timer, and rebuilding the form
// would wipe a password the person is half way through typing and drop the focus. The input is never replaced.
export function renderVaultBanner() {
  const b = $("vault-banner");
  const v = state.session?.vault;
  if (!v || !v.initialized || v.unlocked) { b.hidden = true; return; }
  if (!b.dataset.built) {
    const pw = h("input", { id: "unlock-pw", type: "password", autocomplete: "current-password", placeholder: "Admin password", "aria-label": "Admin password", required: true });
    const err = h("span", { class: "error" });
    b.replaceChildren(
      h("strong", {}, "Provider keys are locked."),
      " The server restarted, so stored keys can't be used (external embeddings and Ask are paused) until you unlock them.",
      h("form", {
        class: "inline",
        onsubmit: async (e) => {
          e.preventDefault();
          err.textContent = "";
          try {
            await api("/api/vault/unlock", { method: "POST", json: { password: pw.value } });
            pw.value = "";
            await refreshSession();
            renderVaultBanner();
            toast("Unlocked");
            window.dispatchEvent(new CustomEvent("apg-unlocked"));
          } catch (ex) { err.textContent = ex.status === 403 ? "Wrong password." : ex.message; }
        },
      }, pw, h("button", { class: "primary small", type: "submit" }, "Unlock"), err));
    b.dataset.built = "1";
  }
  b.hidden = false;
}
