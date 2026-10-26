// scrollRegion() makes a scrolling container keyboard-reachable and named; the shared CSS ships .scroll and .sr-only.
// Run: node tests/ui/a11y.mjs
import { readFileSync } from "node:fs";
const attrs = {}; const classes = new Set();
const el = { attrs, classList: { add: (c) => classes.add(c) }, setAttribute: (k, v) => { attrs[k] = v; } };
globalThis.document = { createElement: () => ({}), getElementById: () => null };
const { scrollRegion } = await import(new URL("../../src/apgkit/static/ui.js", import.meta.url).href);
let bad = 0;
const check = (ok, msg) => { if (!ok) { console.error("FAIL:", msg); bad++; } };
check(scrollRegion(el, "Recent payments") === el, "scrollRegion returns the element");
check(attrs.tabindex === "0" && attrs.role === "region" && attrs["aria-label"] === "Recent payments", "tabindex 0, role region and aria-label are set");
check(classes.has("scroll"), "the .scroll class is added");
const css = readFileSync(new URL("../../src/apgkit/static/base.css", import.meta.url), "utf8");
check(/\.scroll\s*\{[^}]*overflow:\s*auto/.test(css), ".scroll sets overflow: auto");
check(/\.scroll:focus-visible\s*\{[^}]*outline/.test(css), ".scroll shows a focus outline");
check(/\.sr-only\s*\{[^}]*position:\s*absolute[^}]*overflow:\s*hidden/.test(css), ".sr-only visually hides but keeps text for screen readers");
check(!/\.sr-only\s*\{[^}]*display:\s*none/.test(css) && !/\.sr-only\s*\{[^}]*visibility:\s*hidden/.test(css), ".sr-only does not use display:none or visibility:hidden");
console.log(bad ? "FAILED" : "ok: scrollRegion, .scroll and .sr-only");
process.exit(bad ? 1 : 0);
