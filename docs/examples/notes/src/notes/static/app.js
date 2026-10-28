import { api } from "/kit/api.js";
import { bootSession, can, renderLogin, renderSetup, renderVaultBanner } from "/kit/session.js";
import { $, confirmDialog, errorState, field, fill, fmtDateTime, h, loading, toast } from "/kit/ui.js";

async function boot() {
  $("view").hidden = true;
  $("signout").hidden = true;
  $("auth-card").hidden = false;
  await bootSession($("auth-card"), {
    text: "Connecting to Notes…",
    onReady: (s) => {
      if (s.state === "setup_required") renderSetup(boot, "Notes");
      else if (s.state === "logged_out") renderLogin(boot, "", "Notes");
      else showApp();
    },
  });
}

async function showApp() {
  $("auth-card").hidden = true;
  $("view").hidden = false;
  $("signout").hidden = false;
  renderVaultBanner();
  await load();
}

async function load() {
  const view = $("view");
  if (!view.firstChild) loading(view, "Loading notes…");
  let notes;
  try { notes = await api("/api/notes"); } catch (ex) { errorState(view, ex.message, load); return; }
  const title = h("input", { id: "n-title", maxlength: "120", required: true });
  const body = h("textarea", { id: "n-body", rows: "3", maxlength: "5000" });
  const priv = h("input", { id: "n-private", type: "checkbox" });
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api("/api/notes", { method: "POST", json: { title: title.value, body: body.value, private: priv.checked } });
        toast("Note saved");
        load();
      } catch (ex) { toast(ex.message, true); }
    },
  }, field("Title", title), field("Text", body), h("label", {}, priv, " Private (encrypted in the vault)"),
  h("button", { class: "primary", type: "submit" }, "Add note"));
  const rows = notes.map((n) => h("tr", {},
    h("td", { class: "title" }, n.title, " ", n.private ? h("span", { class: "badge alt" }, "private") : null),
    h("td", {}, n.body === null ? h("span", { class: "muted" }, "locked") : n.body),
    h("td", {}, n.author),
    h("td", {}, fmtDateTime(n.created_at)),
    h("td", { class: "actions" }, can("notes:write") ? h("button", { class: "danger small", type: "button", onclick: async () => {
      if (!(await confirmDialog(`Delete "${n.title}"?`, { title: "Delete note", confirmLabel: "Delete", danger: true }))) return;
      await api(`/api/notes/${n.id}`, { method: "DELETE" });
      load();
    } }, "Delete") : null)));
  fill(view,
    h("h1", {}, "Notes"),
    can("notes:write") ? h("div", { class: "card" }, form) : null,
    h("div", { class: "card flush" }, notes.length
      ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Title"), h("th", {}, "Text"), h("th", {}, "Author"), h("th", {}, "Created"),
        h("th", {}, h("span", { class: "sr-only" }, "Actions")))), h("tbody", {}, rows))
      : h("p", { class: "empty" }, "No notes yet.")));
}

window.addEventListener("apg-auth-lost", boot);
window.addEventListener("apg-unlocked", load);
window.addEventListener("apg-vault-locked", () => { api("/api/session").then(() => boot()); });
$("signout").addEventListener("click", async () => { await api("/api/logout", { method: "POST" }); boot(); });
boot();
