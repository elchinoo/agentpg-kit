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
const { confirmDialog, promptDialog } = await import(new URL("../../src/apgkit/static/ui.js", import.meta.url).href);

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

// 6. promptDialog: value / null, required, validate gating, number bounds, password type, Enter / Escape, focus restore
const field = () => overlay().find((e) => e.tag === "input" || e.tag === "textarea");
const alertText = () => overlay().find((e) => e.attrs.role === "alert").text();
const type = (v) => { field().value = v; field().fire("input"); };
opener.focus();
const ask = async (...a) => { p = promptDialog(...a); await tick(); };
const enter = () => overlay().fire("keydown", { key: "Enter", target: field() });

await ask("Reason?", { title: "Chargeback", label: "Reason", defaultValue: "disputed", required: true });
check(field().value === "disputed" && active === field(), "prompt shows the default value and focuses the input");
check(overlay().find((e) => e.tag === "label")?.text() === "Reason", "prompt has a visible label");
check(overlay().find((e) => e.attrs.role === "alertdialog"), "prompt uses the same alertdialog");
type("customer says no"); enter(); check(await p === "customer says no", "Enter submits the typed value");
check(active === opener, "focus restored after prompt");

await ask("m", { required: true });
check(btn("OK").disabled, "required: empty input keeps OK disabled");
type("   "); check(btn("OK").disabled, "required: blank input keeps OK disabled");
enter(); check(overlay() !== null, "required: Enter does nothing while blank");
type("x"); check(!btn("OK").disabled, "required: typing enables OK"); btn("OK").fire("click"); check(await p === "x", "OK click resolves the value");

await ask("m", { defaultValue: "abc" }); overlay().fire("keydown", { key: "Escape", target: field() }); check(await p === null, "Escape resolves null");
await ask("m"); btn("Cancel").fire("click"); check(await p === null, "Cancel resolves null");
await ask("m"); overlay().fire("click", { target: overlay() }); check(await p === null, "backdrop resolves null");
await ask("m"); btn("OK").fire("click"); check(await p === "", "optional empty prompt resolves an empty string");

await ask("m", { validate: (v) => (v.length < 12 ? "Use at least 12 characters." : null), inputType: "password", confirmLabel: "Change" });
check(field().attrs.type === "password" && field().attrs.autocomplete === "new-password", "password input type, never autocompleted");
type("short"); check(btn("Change").disabled && alertText() === "Use at least 12 characters.", "validate error shown inline in role=alert and confirm disabled");
check(!overlay().text().includes("short"), "the typed password is not echoed into the text");
enter(); check(overlay() !== null, "Enter does nothing while invalid");
type("long enough secret"); check(!btn("Change").disabled && alertText() === "", "valid value clears the error and enables confirm");
btn("Change").fire("click"); check(await p === "long enough secret", "password value resolved as typed");

await ask("Minutes", { inputType: "number", min: 0, max: 60, defaultValue: "10", required: true });
check(field().attrs.type === "number" && field().attrs.min === "0" && field().attrs.max === "60", "number input carries min and max");
check(!btn("OK").disabled, "the default 10 is valid");
type("-1"); check(btn("OK").disabled && alertText() === "Must be at least 0.", "below min is rejected");
type("61"); check(btn("OK").disabled && alertText() === "Must be at most 60.", "above max is rejected");
type("abc"); check(btn("OK").disabled, "non-numeric is rejected");
type(""); check(btn("OK").disabled, "required number: empty is rejected");
type("0"); check(!btn("OK").disabled, "0 is within bounds"); enter(); check(await p === "0", "number resolves as a string");

await ask("m", { multiline: true, defaultValue: "a" });
check(field().tag === "textarea", "multiline renders a textarea");
overlay().fire("keydown", { key: "Enter", target: field() }); check(overlay() !== null, "Enter in a textarea does not submit");
overlay().fire("keydown", { key: "Enter", ctrlKey: true, target: field() }); check(await p === "a", "Ctrl+Enter submits a textarea");

await ask("m", { defaultValue: "kept" });   // typed text survives an app re-render; a confirm queues behind an open prompt
const firstPrompt = p;
type("typed"); main.replaceChildren(new El("p")); check(field().value === "typed", "prompt text survives an app re-render");
await show("queued confirm"); check(body.children.filter((c) => c.className === "confirm-overlay").length === 1, "a confirm queues behind an open prompt");
const queued = p;
btn("Cancel").fire("click"); check(await firstPrompt === null, "first prompt cancelled"); await tick();
check(overlay()?.find((e) => e.id.startsWith("confirm-msg"))?.text() === "queued confirm", "the queued confirm shows next");
btn("Confirm").fire("click"); check(await queued === true, "queued confirm resolves");
console.log(bad ? "FAILED" : "ok: confirmDialog and promptDialog resolve, cancel, gates typeToConfirm, traps and restores focus, sets ARIA");
process.exit(bad ? 1 : 0);
