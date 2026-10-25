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

// Accessible replacement for window.confirm(): resolves true on confirm, false on cancel, Escape or a backdrop click.
// Built once and appended to <body>, outside any app container, so an app re-render never wipes a typed phrase.
// typeToConfirm (a string) shows an input and keeps the confirm button disabled until that exact phrase is typed.
// Text goes through textContent; styling is CSS only (.confirm-* in base.css). One dialog at a time: later calls queue.
let confirmQueue = Promise.resolve();
let confirmSeq = 0;
export function confirmDialog(message, { title = "Are you sure?", confirmLabel = "Confirm", cancelLabel = "Cancel", danger = false, typeToConfirm = "" } = {}) {
  const run = () => new Promise((resolve) => {
    const n = ++confirmSeq;
    const opener = document.activeElement;
    const phrase = typeToConfirm ? String(typeToConfirm) : "";
    const cancelBtn = h("button", { class: "secondary", type: "button", id: `confirm-cancel-${n}` }, cancelLabel);
    const okBtn = h("button", { class: danger ? "danger-solid" : "primary", type: "button", id: `confirm-ok-${n}` }, confirmLabel);
    const input = phrase ? h("input", { type: "text", id: `confirm-phrase-${n}`, autocomplete: "off", spellcheck: "false", "aria-label": `Type ${phrase} to confirm` }) : null;
    const ready = () => !phrase || input.value === phrase;
    const sync = () => { okBtn.disabled = !ready(); };
    const box = h("div", { class: "confirm-box", role: "alertdialog", "aria-modal": "true", "aria-labelledby": `confirm-title-${n}`, "aria-describedby": `confirm-msg-${n}` },
      h("h2", { id: `confirm-title-${n}` }, title),
      h("p", { id: `confirm-msg-${n}`, class: "confirm-msg" }, message),
      phrase ? h("p", { class: "hint" }, "Type ", h("strong", {}, phrase), " to confirm.") : null,
      input,
      h("div", { class: "btns" }, cancelBtn, okBtn));
    const overlay = h("div", { class: "confirm-overlay", popover: "manual" }, box);
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      try { overlay.hidePopover(); } catch { /* not shown as a popover */ }
      overlay.remove?.();
      document.body.classList.remove("modal-open");
      if (opener && opener.focus) opener.focus();
      resolve(value);
    };
    const attempt = () => { if (ready()) finish(true); };
    cancelBtn.addEventListener("click", () => finish(false));
    okBtn.addEventListener("click", attempt);
    if (input) input.addEventListener("input", sync);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) finish(false); });
    overlay.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.preventDefault?.(); finish(false); return; }
      if (e.key === "Enter") {
        e.preventDefault?.();
        if (e.target === cancelBtn) finish(false); else attempt();
        return;
      }
      if (e.key === "Tab") {   // trap: cycle through the enabled controls only
        const order = [input, cancelBtn, okBtn].filter((x) => x && !x.disabled);
        const i = order.indexOf(document.activeElement);
        e.preventDefault?.();
        order[(i + (e.shiftKey ? -1 : 1) + order.length) % order.length].focus();
      }
    });
    sync();
    document.body.append(overlay);
    document.body.classList.add("modal-open");
    try { overlay.showPopover(); } catch { /* popover API unavailable: plain fixed element */ }
    (input || (danger ? cancelBtn : okBtn)).focus();
  });
  const result = confirmQueue.then(run);
  confirmQueue = result.then(() => {}, () => {});
  return result;
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

// Standard loading state: a status line with a spinner, so a content area is never blank while data is on its way.
// Text goes through textContent; the spinner is CSS only (.loading in base.css, no inline style or script).
export function loading(container, text = "Loading\u2026") {
  fill(container, h("div", { class: "loading", role: "status", "aria-live": "polite" },
    h("span", { class: "spinner", "aria-hidden": "true" }), h("span", { class: "loading-text" }, text)));
}

// Standard error state with a retry button. onRetry is optional; without it only the message shows.
export function errorState(container, message, onRetry) {
  fill(container, h("div", { class: "error-state", role: "alert" },
    h("p", { class: "error" }, message || "Something went wrong."),
    onRetry ? h("button", { class: "secondary", type: "button", onclick: () => onRetry() }, "Try again") : null));
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
