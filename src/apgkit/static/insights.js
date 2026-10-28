// Query insights panel: top statements (sortable, filterable), edb_pg_tuner recommendations and query_advisor suggestions.
// initInsights(root, api): `api` is the kit's api() (or any function path -> Promise<json>). Needs `GET /api/insights?limit=50`
// from the app (docs/GUIDE.md, "Query insights"). Every source that is missing on the database shows an honest "not available" state
// with the server's reason. Text goes through textContent only; styling is base.css (no inline style or script).
import { h, fill, loading, errorState, scrollRegion } from "/kit/ui.js";

const num = (n, d = 0) => (n == null ? "" : Number(n).toLocaleString(undefined, { minimumFractionDigits: d, maximumFractionDigits: d }));

const COLS = [
  { key: "query", label: "Statement", text: true },
  { key: "calls", label: "Calls", fmt: (v) => num(v) },
  { key: "total_ms", label: "Total (ms)", fmt: (v) => num(v, 1) },
  { key: "mean_ms", label: "Mean (ms)", fmt: (v) => num(v, 2) },
  { key: "max_ms", label: "Max (ms)", fmt: (v) => num(v, 1) },
  { key: "rows", label: "Rows", fmt: (v) => num(v) },
];

function unavailable(title, part) {
  return h("section", { class: "card insights-block" },
    h("h2", {}, title),
    h("p", { class: "empty insights-na", role: "status" }, "Not available on this database."),
    part && part.reason ? h("p", { class: "hint insights-reason" }, part.reason) : null);
}

function table(caption, head, rows) {
  const wrap = scrollRegion(h("div", {}), `${caption} (scrollable)`);
  wrap.append(h("table", {}, h("caption", { class: "sr-only" }, caption), h("thead", {}, h("tr", {}, ...head)), h("tbody", {}, ...rows)));
  return wrap;
}

export function topQueriesBlock(part, state, rerender) {
  if (!part || !part.available) return unavailable("Top queries", part);
  const q = state.filter.trim().toLowerCase();
  let rows = part.queries.filter((r) => !q || r.query.toLowerCase().includes(q));
  const { sortKey: k, sortDir: dir } = state;
  rows = [...rows].sort((a, b) => ((a[k] ?? 0) > (b[k] ?? 0) ? 1 : (a[k] ?? 0) < (b[k] ?? 0) ? -1 : 0) * dir);
  const head = COLS.map((c) => {
    const active = state.sortKey === c.key;
    return h("th", { scope: "col", class: c.text ? "" : "num", "aria-sort": active ? (state.sortDir > 0 ? "ascending" : "descending") : "none" },
      h("button", { class: "ghost sort", type: "button", onclick: () => { state.sortDir = active ? -state.sortDir : -1; state.sortKey = c.key; rerender(); } },
        c.label, h("span", { class: "sr-only" }, active ? (state.sortDir > 0 ? ", sorted ascending" : ", sorted descending") : ", sort")));
  });
  const body = rows.map((r) => h("tr", {},
    ...COLS.map((c) => (c.text ? h("td", { class: "insights-sql" }, h("code", {}, r.query)) : h("td", { class: "num" }, c.fmt(r[c.key]))))));
  return h("section", { class: "card insights-block" },
    h("h2", {}, "Top queries"),
    h("p", { class: "hint" }, `From ${part.source}${part.since ? `, since ${new Date(part.since).toLocaleString()}` : ""}. Statement text is normalised: values are not shown.`),
    part.text_hidden ? h("p", { class: "hint insights-hidden" }, `${part.text_hidden} statement texts are hidden by the database for this role (it needs the pg_read_all_stats role to see other users' queries).`) : null,
    h("div", { class: "field insights-filter" }, h("label", { for: "insights-filter" }, "Filter statements"),
      h("input", { id: "insights-filter", type: "search", "aria-label": "Filter statements", value: state.filter, autocomplete: "off", onchange: (e) => { state.filter = e.target.value; state.refocus = true; rerender(); } })),
    rows.length ? table("Top queries", head, body) : h("p", { class: "empty" }, "No statements match."));
}

export function tunerBlock(part) {
  if (!part || !part.available) return unavailable("Tuning recommendations", part);
  if (!part.recommendations.length) return h("section", { class: "card insights-block" }, h("h2", {}, "Tuning recommendations"), h("p", { class: "empty" }, "The tuner has no recommendations right now."));
  const rows = part.recommendations.map((r) => h("tr", {}, h("td", {}, h("code", {}, r.setting || r.raw)), h("td", {}, r.value)));
  return h("section", { class: "card insights-block" }, h("h2", {}, "Tuning recommendations"),
    h("p", { class: "hint" }, "From edb_pg_tuner. Suggestions only: review them against your workload before changing settings."),
    table("Tuning recommendations", [h("th", { scope: "col" }, "Setting"), h("th", { scope: "col" }, "Suggested value")], rows));
}

export function advisorBlock(part) {
  if (!part || !part.available) return unavailable("Index suggestions", part);
  if (!part.suggestions.length) return h("section", { class: "card insights-block" }, h("h2", {}, "Index suggestions"), h("p", { class: "empty" }, "No filtered columns observed yet. Run some workload and refresh."));
  const rows = part.suggestions.map((r) => h("tr", {},
    h("td", {}, h("code", {}, r.table)), h("td", {}, h("code", {}, r.column)), h("td", {}, h("code", {}, r.operator)),
    h("td", { class: "num" }, num(r.executions)), h("td", { class: "num" }, num(r.rows_filtered)), h("td", { class: "num" }, num(r.filtered_per_execution, 1)),
    h("td", {}, r.suggestion || "")));
  const th = (t, n) => h("th", { scope: "col", class: n ? "num" : "" }, t);
  return h("section", { class: "card insights-block" }, h("h2", {}, "Index suggestions"),
    h("p", { class: "hint" }, "From query_advisor. \"Rows filtered\" is how many rows the condition read and then discarded: what an index could save. A hint from observed workload, not a measured speed-up."),
    table("Index suggestions", [th("Table"), th("Column"), th("Operator"), th("Executions", 1), th("Rows filtered", 1), th("Per execution", 1), th("Suggestion")], rows));
}

export async function initInsights(root, api) {
  const state = { filter: "", sortKey: "total_ms", sortDir: -1, data: null };
  const render = () => {
    const d = state.data;
    fill(root,
      h("div", { class: "row insights-head" }, h("h1", {}, "Query insights"),
        h("button", { class: "secondary", type: "button", onclick: () => load() }, "Refresh")),
      topQueriesBlock(d.top_queries, state, render), tunerBlock(d.tuner), advisorBlock(d.advisor));
    if (state.refocus) {          // a re-render replaces the filter input: keep the keyboard user where they were
      state.refocus = false;
      const input = document.getElementById("insights-filter");
      if (input) input.focus();
    }
  };
  async function load() {
    loading(root, "Loading query insights");
    try {
      state.data = await api("/api/insights?limit=50");
    } catch (e) {
      errorState(root, e && e.message ? e.message : "Could not load query insights.", load);
      return;
    }
    render();
  }
  await load();
}
