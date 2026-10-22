// Tiny DOM helpers. Text always goes through textContent, never innerHTML.

export const $ = (id) => document.getElementById(id);

export function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

let toastTimer;
export function toast(msg, bad = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (bad ? " bad" : "");
  t.hidden = false;
  // A modal <dialog> sits in the browser's top layer, above everything else. A manual popover joins that layer,
  // so messages stay visible while a review window is open.
  try { if (!t.matches(":popover-open")) t.showPopover(); } catch { /* popover API unavailable: plain fixed element */ }
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    try { t.hidePopover(); } catch { /* not shown as a popover */ }
    t.hidden = true;
  }, bad ? 8000 : 3500);
}

export async function copy(text, okMsg = "Copied") {
  try { await navigator.clipboard.writeText(text); toast(okMsg); } catch { toast("Copy failed", true); }
}

export const fmtDate = (s) => (s ? new Date(s).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "never");

export function setBusy(button, busy, label) {
  button.disabled = busy;
  if (label !== undefined) button.dataset.label = button.dataset.label || button.textContent;
  button.textContent = busy ? label : (button.dataset.label || button.textContent);
}

export function field(label, input, hint) {
  const id = input.id || `f_${Math.random().toString(36).slice(2, 8)}`;
  input.id = id;
  return h("div", { class: "field" }, h("label", { for: id }, label), input, hint ? h("p", { class: "hint" }, hint) : null);
}

// Element.replaceChildren renders null/undefined/false as the text "null"; this drops them instead.
export function fill(el, ...kids) {
  el.replaceChildren(...kids.flat().filter((k) => k != null && k !== false));
}

export const fmtDateTime = (s) => (s ? new Date(s).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "");

// Plain dates (YYYY-MM-DD) have no time zone: never run them through Date(), which would shift them by a day.
export function fmtDay(s) {
  if (!s) return "";
  const [y, m, d] = String(s).slice(0, 10).split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export const money = (amount, currency) => (amount == null ? "" : `${Number(amount).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${currency || ""}`.trim());

export const STATUS = {
  submitted: ["Validating", "plain"], pending_review: ["Needs decision", "warn"], needs_info: ["Waiting for employee", "alt"],
  approved: ["Approved", "ok"], rejected: ["Rejected", "bad"], withdrawn: ["Withdrawn", "plain"],
};
export const ADVICE = {
  approve: ["Suggests approval", "ok"], reject: ["Suggests rejection", "bad"],
  needs_info: ["Needs more information", "warn"], manual: ["No AI advice", "plain"],
};
export const COMPLIANCE = { compliant: ["Compliant", "ok"], non_compliant: ["Non-compliant", "bad"], unclear: ["Unclear", "warn"] };

export function badge(map, key, fallback = "") {
  const [label, tone] = map[key] || [fallback || key || "", "plain"];
  return h("span", { class: `badge ${tone}` }, label);
}

export function dialogClose(dlg) {
  if (dlg.open) dlg.close();
}
