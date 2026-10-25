// Regression: confirmDialog resolves true/false, Escape and backdrop cancel, typeToConfirm gates the button and survives a re-render,
// focus returns to the opener, ARIA wiring and body scroll lock. Run: node tests/ui/confirm.mjs
let active = null;
class El {
  constructor(t) { this.tag = t; this.children = []; this.attrs = {}; this.listeners = {}; this.value = ""; this.disabled = false; this.textContent = ""; this.className = ""; this.parent = null; this.id = ""; this.classes = new Set(); this.classList = { add: (c) => this.classes.add(c), remove: (c) => this.classes.delete(c), contains: (c) => this.classes.has(c) }; }
  get nodeType() { return 1; }
  append(...k) { for (const x of k) { if (x.parent !== undefined) x.parent = this; this.children.push(x); } }
  setAttribute(k, v) { this.attrs[k] = v; if (k === "id") this.id = v; }
  addEventListener(t, f) { this.listeners[t] = f; }
  fire(t, ev = {}) { const e = { target: this, preventDefault() {}, ...ev }; let n = this; while (n) { if (n.listeners[t]) n.listeners[t](e); n = n.parent; } }
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
const { confirmDialog } = await import(new URL("../../src/apgkit/static/ui.js", import.meta.url).href);

let bad = 0;
const check = (ok, msg) => { if (!ok) { console.error("FAIL:", msg); bad++; } };
const overlay = () => body.find((e) => e.className === "confirm-overlay");
const btn = (label) => overlay().find((e) => e.tag === "button" && e.text() === label);
const opener = new El("button"); main.append(opener);
const tick = () => new Promise((r) => setTimeout(r, 0));
let p;
const show = async (...a) => { const pr = confirmDialog(...a); p = pr; await tick(); };   // the dialog mounts on the next microtask

// 1. ARIA, focus in, scroll lock; confirm resolves true; focus restored
opener.focus();
await show("Delete <b>x</b>?", { title: "Delete", confirmLabel: "Delete it" });
const box = overlay().find((e) => e.attrs.role === "alertdialog");
check(box && box.attrs["aria-modal"] === "true", "role=alertdialog and aria-modal");
check(overlay().find((e) => e.id === box.attrs["aria-labelledby"])?.text() === "Delete", "aria-labelledby points at the title");
check(overlay().find((e) => e.id === box.attrs["aria-describedby"])?.text() === "Delete <b>x</b>?", "aria-describedby points at the message, as plain text");
check(body.classes.has("modal-open"), "body scroll locked");
check(active && overlay().contains(active) && active === btn("Delete it"), "focus moved into the dialog (confirm button)");
btn("Delete it").fire("click");
check(await p === true, "confirm resolves true");
check(!overlay() && !body.classes.has("modal-open"), "dialog removed and scroll unlocked");
check(active === opener, "focus returned to the opener");

// 2. cancel button, Escape, backdrop resolve false
await show("m"); btn("Cancel").fire("click"); check(await p === false, "cancel button resolves false");
await show("m"); overlay().fire("keydown", { key: "Escape", target: btn("Confirm") }); check(await p === false, "Escape resolves false");
check(active === opener, "focus restored after Escape");
await show("m"); overlay().fire("click", { target: overlay() }); check(await p === false, "backdrop click resolves false");
await show("m"); box.fire("click", { target: btn("Confirm") }); check(overlay() !== null, "a click inside the box does not close it"); btn("Cancel").fire("click"); await p;

// 3. Enter confirms; danger focuses the safe button first; Tab is trapped
await show("m", { danger: true });
check(active === btn("Cancel"), "danger dialog focuses Cancel first");
check(btn("Confirm").className === "danger-solid", "danger styles the confirm button");
overlay().fire("keydown", { key: "Tab", target: active }); check(active === btn("Confirm"), "Tab moves to confirm");
overlay().fire("keydown", { key: "Tab", target: active }); check(active === btn("Cancel"), "Tab wraps inside the dialog");
overlay().fire("keydown", { key: "Tab", shiftKey: true, target: active }); check(active === btn("Confirm"), "Shift+Tab wraps backwards");
overlay().fire("keydown", { key: "Enter", target: active }); check(await p === true, "Enter confirms");

// 4. typeToConfirm gates confirm, Enter, and survives a re-render of the app container
await show("Erase everything", { typeToConfirm: "ERASE", confirmLabel: "Erase" });
const input = overlay().find((e) => e.tag === "input");
check(input && active === input, "typeToConfirm shows an input and focuses it");
check(btn("Erase").disabled === true, "confirm disabled until the phrase is typed");
input.value = "ERAS"; input.fire("input"); check(btn("Erase").disabled, "partial phrase keeps it disabled");
overlay().fire("keydown", { key: "Enter", target: input }); check(overlay() !== null, "Enter does nothing while the phrase is missing");
btn("Erase").fire("click"); check(overlay() !== null, "clicking a disabled confirm does nothing");
main.replaceChildren(new El("p"));   // the app re-renders
check(overlay().find((e) => e.tag === "input") === input && input.value === "ERAS", "typed text survives an app re-render");
input.value = "erase"; input.fire("input"); check(btn("Erase").disabled, "phrase is case-sensitive");
input.value = "ERASE"; input.fire("input"); check(!btn("Erase").disabled, "exact phrase enables confirm");
overlay().fire("keydown", { key: "Enter", target: input }); check(await p === true, "Enter confirms once the phrase is typed");

// 5. queued dialogs show one at a time
await show("first"); const a = p; await show("second"); const b = p;
await tick();
check(body.children.filter((c) => c.className === "confirm-overlay").length === 1, "one dialog at a time");
btn("Cancel").fire("click"); check(await a === false, "first resolves");
await tick();
check(overlay()?.find((e) => e.id.startsWith("confirm-msg"))?.text() === "second", "second shown after the first closes");
btn("Confirm").fire("click"); check(await b === true, "second resolves");

console.log(bad ? "FAILED" : "ok: confirmDialog resolves, cancels, gates typeToConfirm, traps and restores focus, sets ARIA");
process.exit(bad ? 1 : 0);
