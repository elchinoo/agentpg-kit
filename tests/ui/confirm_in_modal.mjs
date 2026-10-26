// Regression for F-PB-1 / F-SF-1: confirmDialog and promptDialog must work while an app's own modal <dialog> is open (PayBroker
// merchant window, ShopFront order window). The old popover="manual" confirmation was inert there. The fake <dialog> models showModal/close/cancel and the browser's
// rule that everything outside the topmost modal dialog is inert, so a confirmation that is not itself a modal dialog cannot be
// clicked while an app's own modal <dialog> is open. Run: node tests/ui/confirm_in_modal.mjs
let active = null;
const modals = [];   // open modal dialogs, last = topmost
const inert = (el) => { const top = modals[modals.length - 1]; return !!top && !top.contains(el); };
class El {
  constructor(t) { this.tag = t; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ""; this.disabled = false; this.textContent = ""; this.className = ""; this.parent = null; this.id = ""; this.classes = new Set(); this.open = false; if (t === "dialog" && !globalThis.__noShowModal) this.showModal = () => { this.open = true; modals.push(this); this.setAttribute("open", ""); }; this.classList = { add: (c) => this.classes.add(c), remove: (c) => this.classes.delete(c), contains: (c) => this.classes.has(c) }; }
  get nodeType() { return 1; }
  append(...k) { for (const x of k) { if (x.parent !== undefined) x.parent = this; this.children.push(x); } }
  setAttribute(k, v) { this.attrs[k] = v; if (k === "id") this.id = v; }
  addEventListener(t, f) { this.listeners[t] = f; }
  close() { this.open = false; const i = modals.indexOf(this); if (i >= 0) modals.splice(i, 1); }
  fire(t, ev = {}) {
    const e = { target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...ev };
    if (inert(e.target)) return e;   // the browser does not deliver input to anything outside the topmost modal dialog
    let n = this; while (n) { if (n.listeners[t]) n.listeners[t](e); n = n.parent; }
    return e;
  }
  focus() { if (!this.disabled) active = this; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((c) => c !== this); this.parent = null; if (active && !document.body.contains(active)) active = null; }
  contains(n) { return n === this || this.children.some((c) => c.contains && c.contains(n)); }
  replaceChildren(...k) { this.children = k; k.forEach((x) => { if (x.parent !== undefined) x.parent = this; }); if (active && !document.body.contains(active)) active = null; }
  find(pred) { if (pred(this)) return this; for (const c of this.children) { const f = c.find && c.find(pred); if (f) return f; } return null; }
  text() { return this.textContent + this.children.map((c) => (c.text ? c.text() : c.data ?? "")).join(" "); }
}
const body = new El("body");
const main = new El("div"); body.append(main);
globalThis.document = { body, createElement: (t) => new El(t), createTextNode: (d) => ({ nodeType: 3, data: d, text: () => String(d) }), getElementById: () => null };
Object.defineProperty(document, "activeElement", { get: () => active });
const { confirmDialog, promptDialog } = await import(new URL("../../src/apgkit/static/ui.js", import.meta.url).href);
let bad = 0;
const check = (ok, msg) => { if (!ok) { console.error("FAIL:", msg); bad++; } };
const overlay = () => body.find((e) => e.attrs.role === "alertdialog");
const btn = (label) => overlay().find((e) => e.tag === "button" && e.text() === label);
const field = () => overlay().find((e) => e.tag === "input" || e.tag === "textarea");
const type = (v) => { field().value = v; field().fire("input"); };
const esc = (target) => { const e = overlay().fire("keydown", { key: "Escape", target }); if (!e.defaultPrevented && modals.length) modals[modals.length - 1].fire("cancel"); };
const tick = () => new Promise((r) => setTimeout(r, 0));
let p;

// An app's own modal <dialog> is open (showModal): the confirmation must still be clickable and typeable.
// It is a later modal dialog, so it stacks above the app dialog and the app dialog turns inert, not the confirmation.
const appDlg = new El("dialog"); appDlg.id = "merchant-window"; const revoke = new El("button"); appDlg.append(revoke); body.append(appDlg);
appDlg.showModal(); revoke.focus();
const settle = (pr) => Promise.race([pr, new Promise((r) => setTimeout(() => r("pending"), 30))]);
p = confirmDialog("Revoke key?", { confirmLabel: "Revoke", danger: true }); await tick();
check(modals[modals.length - 1] === overlay(), "the confirmation is the topmost modal above the app dialog");
check(!inert(btn("Revoke")), "the confirm button is not inert while an app modal dialog is open");
btn("Revoke").fire("click");
check(await settle(p) === true, "confirming inside an open modal <dialog> works (F-PB-1)");
check(modals.length === 1 && modals[0] === appDlg && appDlg.open, "the app dialog is the top modal again and still open afterwards");
p = promptDialog("Reason", { label: "Reason", required: true }); await tick();
type("fraud"); check(field().value === "fraud" && !btn("OK").disabled, "typing in a prompt works inside an open modal dialog");
btn("OK").fire("click"); check(await settle(p) === "fraud", "a prompt inside an open modal <dialog> resolves (chargeback)");
p = confirmDialog("again", { typeToConfirm: "GO" }); await tick();
check(inert(revoke), "the app dialog is inert while the confirmation is up");
esc(field() ?? btn("Confirm")); check(await settle(p) === false, "Escape cancels the confirmation inside a modal dialog"); check(appDlg.open && !inert(revoke), "the app dialog works again after the confirmation closes");
appDlg.close(); appDlg.remove();


console.log(bad ? "FAILED" : "ok: confirmDialog and promptDialog stay usable above an open modal <dialog>");
process.exit(bad ? 1 : 0);
