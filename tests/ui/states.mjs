// Regression: the unlock input keeps its text and focus across refreshes; the loading and error states render. Run: node tests/ui/states.mjs
import { pathToFileURL } from "node:url";
import { register } from "node:module";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const root = new URL("../../src/apgkit/static/", import.meta.url).pathname;
const loader = join(mkdtempSync(join(tmpdir(), "kit-")), "loader.mjs");
writeFileSync(loader, `export async function resolve(s,c,n){ if(s.startsWith("/kit/")) return {url:${JSON.stringify(pathToFileURL(root).href)}+s.slice(5),shortCircuit:true}; return n(s,c);}`);
register(pathToFileURL(loader));

let active = null;
class El {
  constructor(t) { this.tag = t; this.children = []; this.attrs = {}; this.dataset = {}; this.listeners = {}; this.value = ""; this.hidden = false; this.textContent = ""; this.className = ""; }
  get nodeType() { return 1; }
  append(...k) { this.children.push(...k); }
  setAttribute(k, v) { this.attrs[k] = v; }
  addEventListener(t, f) { this.listeners[t] = f; }
  focus() { active = this; }
  contains(n) { return n === this || this.children.some((c) => c.contains && c.contains(n)); }
  replaceChildren(...k) {   // like a browser: a focused node that leaves the tree loses focus
    this.children = k.map((x) => (x == null || x === false ? { nodeType: 3, data: String(x) } : x));
    if (active && !document.body.contains(active)) active = null;
  }
  find(pred) { if (pred(this)) return this; for (const c of this.children) { const f = c.find && c.find(pred); if (f) return f; } return null; }
  text() { return this.textContent + this.children.map((c) => (c.text ? c.text() : c.data ?? "")).join(" "); }
}
const els = {};
const body = new El("body");
for (const id of ["vault-banner", "main"]) { els[id] = new El("div"); body.append(els[id]); }
globalThis.document = { body, documentElement: { dataset: {} }, getElementById: (id) => els[id], createElement: (t) => new El(t), createTextNode: (d) => ({ nodeType: 3, data: d, text: () => String(d) }) };
Object.defineProperty(document, "activeElement", { get: () => active });
globalThis.window = { dispatchEvent() {}, addEventListener() {} };
globalThis.location = { search: "", hash: "" };
const { renderVaultBanner, bootSession, state } = await import("/kit/session.js");
const { loading, errorState } = await import("/kit/ui.js");

let bad = 0;
const check = (ok, msg) => { if (!ok) { console.error("FAIL:", msg); bad++; } };

// 1. typed text and focus survive repeated refreshes
state.session = { vault: { initialized: true, unlocked: false } };
renderVaultBanner();
const input = () => els["vault-banner"].find((e) => e.attrs.id === "unlock-pw");
const first = input();
check(first && !els["vault-banner"].hidden, "banner shows the unlock input when locked");
first.focus(); first.value = "half-typed-secret";
for (let i = 0; i < 3; i++) { state.session = { vault: { initialized: true, unlocked: false } }; renderVaultBanner(); }
check(input() === first, "the same input node is kept");
check(input().value === "half-typed-secret", "typed text survives refresh");
check(document.activeElement === first, "focus survives refresh");
state.session = { vault: { initialized: true, unlocked: true } }; renderVaultBanner();
check(els["vault-banner"].hidden, "banner hides once unlocked");

// 2. loading state
loading(els.main, "Loading requests");
let st = els.main.find((e) => e.attrs.role === "status");
check(st && st.text().includes("Loading requests"), "loading state renders its text with role=status");
check(els.main.find((e) => e.className === "spinner"), "loading state has a spinner");

// 3. error state with retry; bootSession shows loading, then error, then recovers on retry
let calls = 0;
globalThis.fetch = async () => {
  calls++;
  if (calls === 1) return { ok: false, status: 500, headers: { get: () => "application/json" }, json: async () => ({ detail: "boom" }), text: async () => "boom" };
  return { ok: true, status: 200, headers: { get: () => "application/json" }, json: async () => ({ user: { permissions: [] } }), text: async () => "{}" };
};
const pending = bootSession(els.main, { text: "Signing you in" });
check(els.main.find((e) => e.attrs.role === "status")?.text().includes("Signing you in"), "bootSession shows loading while the request runs");
const r = await pending;
const retry = els.main.find((e) => e.tag === "button");
check(r === null && els.main.find((e) => e.attrs.role === "alert") && retry && retry.text().includes("Try again"), "failed bootstrap renders an error with a retry button");
retry.listeners.click();
await new Promise((res) => setTimeout(res, 10));
check(calls === 2 && state.session?.user, "retry loads the session again");
errorState(els.main, "plain");
check(!els.main.find((e) => e.tag === "button"), "error state without a callback has no button");

console.log(bad ? "FAILED" : "ok: unlock input keeps text and focus; loading and error states render");
process.exit(bad ? 1 : 0);
