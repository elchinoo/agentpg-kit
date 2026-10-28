// insights.js: renders every source, an honest "not available" state per source, sorts, filters, and retries after an error. Run: node tests/ui/insights.mjs
import { pathToFileURL } from "node:url";
import { register } from "node:module";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const root = new URL("../../src/apgkit/static/", import.meta.url).pathname;
const loader = join(mkdtempSync(join(tmpdir(), "kit-")), "loader.mjs");
writeFileSync(loader, `export async function resolve(s,c,n){ if(s.startsWith("/kit/")) return {url:${JSON.stringify(pathToFileURL(root).href)}+s.slice(5),shortCircuit:true}; return n(s,c);}`);
register(pathToFileURL(loader));

class El {
  constructor(t) { this.tag = t; this.children = []; this.attrs = {}; this.dataset = {}; this.listeners = {}; this.value = ""; this.hidden = false; this.textContent = ""; this.className = ""; this.id = ""; this.classList = { add: (c) => { this.className += ` ${c}`; } }; }
  get nodeType() { return 1; }
  append(...k) { this.children.push(...k); }
  setAttribute(k, v) { this.attrs[k] = v; if (k === "id") this.id = v; }
  addEventListener(t, f) { this.listeners[t] = f; }
  focus() { globalThis.__focus = this; }
  replaceChildren(...k) { this.children = k.map((x) => (x == null || x === false ? { nodeType: 3, data: String(x) } : x)); }
  findAll(pred, out = []) { if (pred(this)) out.push(this); for (const c of this.children) c.findAll && c.findAll(pred, out); return out; }
  find(pred) { return this.findAll(pred)[0] || null; }
  text() { return this.textContent + this.children.map((c) => (c.text ? c.text() : c.data ?? "")).join(" "); }
}
const body = new El("body");
globalThis.document = { body, documentElement: { dataset: {} }, getElementById: (id) => body.find((e) => e.id === id), createElement: (t) => new El(t), createTextNode: (d) => ({ nodeType: 3, data: d, text: () => String(d) }) };
globalThis.window = { dispatchEvent() {}, addEventListener() {} };
const { initInsights } = await import("/kit/insights.js");

let bad = 0;
const check = (ok, msg) => { if (!ok) { console.error("FAIL:", msg); bad++; } };
const q = (id, query, calls, total) => ({ queryid: id, query, calls, total_ms: total, mean_ms: total / calls, max_ms: total, rows: calls });
const full = {
  sources: {},
  top_queries: { available: true, source: "edb_stat_monitor", since: null, queries: [q("1", "SELECT * FROM a WHERE id = $1", 10, 50), q("2", "UPDATE b SET x = $1", 100, 20), q("3", "SELECT count(*) FROM c", 5, 900)] },
  tuner: { available: true, recommendations: [{ setting: "shared_buffers", value: "186 MB", raw: "shared_buffers = '186 MB'" }] },
  advisor: { available: true, suggestions: [{ table: "public.a", column: "id", operator: "=", occurrences: 3, executions: 10, rows_filtered: 900, filtered_per_execution: 90, suggestion: "Consider an index on public.a (id)" }] },
};
const none = { available: false, reason: "not installed on this database" };
let payload = full, calls = 0;
const api = async () => { calls++; if (payload instanceof Error) throw payload; return payload; };

const main = new El("div"); body.append(main);
await initInsights(main, api);
const firstCol = () => main.findAll((e) => e.tag === "td" && e.className === "insights-sql").map((e) => e.text().trim());
check(!main.text().includes("pg_read_all_stats"), "no hidden-text note when all texts are visible");
check(!main.text().includes("already indexed"), "no already-indexed line when nothing was hidden");
check(main.text().includes("Tuning recommendations") && main.text().includes("shared_buffers") && main.text().includes("Consider an index on public.a (id)"), "all three sources render");
check(firstCol()[0].includes("count(*)"), "default sort is total time, descending");
const header = (label) => main.find((e) => e.tag === "button" && e.text().startsWith(label));
header("Calls").listeners.click();
check(firstCol()[0].includes("UPDATE b"), "sorting by calls descending puts the most called first");
header("Calls").listeners.click();
check(firstCol()[0].includes("count(*)") && main.find((e) => e.tag === "th" && e.attrs["aria-sort"] === "ascending"), "second click flips to ascending and sets aria-sort");
const input = main.find((e) => e.tag === "input");
check(input.attrs["aria-label"] === "Filter statements", "filter input has an accessible name");
input.listeners.change({ target: { value: "update" } });
check(firstCol().length === 1 && firstCol()[0].includes("UPDATE"), "filter narrows the table");
check(globalThis.__focus && globalThis.__focus.id === "insights-filter", "filter input is focused again after re-render");
check(main.findAll((e) => e.attrs.role === "region" && e.attrs["aria-label"]).length >= 3, "tables are in named scroll regions");

payload = { ...full, top_queries: { ...full.top_queries, text_hidden: 2 } };
await main.find((e) => e.tag === "button" && e.text() === "Refresh").listeners.click();
await new Promise((r) => setTimeout(r, 5));
check(main.text().includes("2 statement texts are hidden because the database role needs pg_read_all_stats"), "hidden statement texts are explained");

// advisor: the hidden-by-index line and no empty-suggestion rows
payload = { ...full, advisor: { available: true, summary: { already_indexed: 3 }, suggestions: [full.advisor.suggestions[0], { ...full.advisor.suggestions[0], column: "zzz", suggestion: "" }] } };
await main.find((e) => e.tag === "button" && e.text() === "Refresh").listeners.click();
await new Promise((r) => setTimeout(r, 5));
check(main.text().includes("3 suggestions hidden: column already indexed."), "already-indexed count is shown");
check(!main.text().includes("zzz"), "a row with an empty suggestion is not rendered");
payload = { ...full, advisor: { available: true, summary: { already_indexed: 1 }, suggestions: [] } };
await main.find((e) => e.tag === "button" && e.text() === "Refresh").listeners.click();
await new Promise((r) => setTimeout(r, 5));
check(main.text().includes("1 suggestion hidden: column already indexed.") && main.text().includes("No unindexed filtered columns"), "all suggestions hidden: line plus empty message");
payload = { ...full, advisor: { available: true, suggestions: full.advisor.suggestions } };   // old payload without summary still renders
await main.find((e) => e.tag === "button" && e.text() === "Refresh").listeners.click();
await new Promise((r) => setTimeout(r, 5));
check(main.text().includes("Consider an index on public.a (id)") && !main.text().includes("already indexed"), "payload without summary is backwards compatible");

// every source missing: an honest state per source, no tables, the reason is shown
payload = { sources: {}, top_queries: none, tuner: { available: false, reason: "permission denied for this database role" }, advisor: none };
await main.find((e) => e.tag === "button" && e.text() === "Refresh").listeners.click();
await new Promise((r) => setTimeout(r, 5));
check(main.findAll((e) => e.className.includes("insights-na")).length === 3, "three 'not available' states");
check(main.text().includes("permission denied for this database role") && !main.find((e) => e.tag === "table"), "reason shown, no table");

// an error shows a retry that recovers
payload = new Error("boom");
await main.find((e) => e.tag === "button" && e.text() === "Refresh").listeners.click();
await new Promise((r) => setTimeout(r, 5));
const retry = main.find((e) => e.tag === "button" && e.text().includes("Try again"));
check(main.find((e) => e.attrs.role === "alert") && retry, "error state with retry");
payload = full;
retry.listeners.click();
await new Promise((r) => setTimeout(r, 5));
check(main.text().includes("Top queries") && calls === 8, "retry loads again");

console.log(bad ? "FAILED" : "ok: insights render, sort, filter, degrade per source and retry");
process.exit(bad ? 1 : 0);
