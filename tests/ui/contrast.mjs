// WCAG AA (4.5:1) contrast of the kit's status badges and coloured text, light and dark, computed from the tokens in base.css.
// Translucent badge backgrounds (color-mix(... N%, transparent)) are composited over the surface the badge sits on (--surface or --bg).
// Run: node tests/ui/contrast.mjs        (add --report to print every ratio)
import { readFileSync } from "node:fs";
const css = readFileSync(new URL("../../src/apgkit/static/base.css", import.meta.url), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");

const tokens = (block) => Object.fromEntries([...block.matchAll(/(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{3,6})\s*[;}]/g)].map((m) => [m[1], m[2]]));
const light = tokens(css.match(/:root\s*\{([^}]*)\}/)[1]);
const dark = { ...light, ...tokens(css.match(/prefers-color-scheme:\s*dark\)\s*\{\s*:root\s*\{([^}]*)\}/)[1]) };

const rgb = (hex) => { let h = hex.slice(1); if (h.length === 3) h = [...h].map((c) => c + c).join(""); return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16)); };
const lum = (c) => { const [r, g, b] = c.map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
const over = (fg, alpha, bg) => fg.map((v, i) => v * alpha + bg[i] * (1 - alpha));

// Resolve a CSS colour expression made of var(--x), a hex, or color-mix(in srgb, <colour> N%, transparent) over `base`.
function resolve(expr, t, base) {
  expr = expr.trim();
  let m = expr.match(/^var\((--[\w-]+)\)$/); if (m) return rgb(t[m[1]]);
  m = expr.match(/^(#[0-9a-fA-F]{3,6})$/); if (m) return rgb(m[1]);
  m = expr.match(/^color-mix\(in srgb,\s*(.+?)\s+(\d+)%,\s*transparent\)$/);
  if (m) return over(resolve(m[1], t, base), Number(m[2]) / 100, base);
  throw new Error("cannot resolve " + expr);
}

// Every rule that sets a colour for a badge or a status text, with its background (badge) or none (text on the page surface).
const pairs = [];
for (const m of css.matchAll(/([^{}@]+)\{([^{}]*)\}/g)) {
  const sel = m[1].trim(); const body = m[2];
  const fg = body.match(/(?:^|[;\s])color:\s*([^;]+)/); if (!fg) continue;
  const bgm = body.match(/background:\s*([^;]+)/);
  if (/^\.badge(\.\w+)?$/.test(sel) && bgm) pairs.push({ sel, fg: fg[1], bg: bgm[1], kind: "badge" });
  else if (/^(\.ok-text|\.warn-text|\.error|\.test-result\.(ok|bad)|\.uploads \.(ok|bad)|\.muted|\.hint)$/.test(sel) && !bgm) pairs.push({ sel, fg: fg[1], bg: null, kind: "text" });
}

let bad = 0;
const rows = [];
for (const [theme, t] of [["light", light], ["dark", dark]]) {
  for (const p of pairs) {
    const surfaces = p.kind === "badge" ? ["--surface", "--bg"] : ["--surface", "--bg"];
    for (const s of surfaces) {
      const base = rgb(t[s]);
      const fg = resolve(p.fg, t, base);
      const bg = p.bg ? resolve(p.bg, t, base) : base;
      const r = ratio(fg, bg);
      rows.push(`${theme.padEnd(5)} ${p.sel.padEnd(22)} on ${s.padEnd(9)} ${r.toFixed(2)}`);
      if (r < 4.5) { console.error(`FAIL: ${theme} ${p.sel} on ${s}: ${r.toFixed(2)}:1 is below 4.5:1`); bad++; }
    }
  }
}
if (!pairs.some((p) => p.sel === ".badge.ok") || !pairs.some((p) => p.sel === ".badge.alt") || pairs.length < 8) { console.error("FAIL: badge rules were not found in base.css"); bad++; }
if (process.argv.includes("--report")) console.log(rows.join("\n"));
console.log(bad ? "FAILED" : `ok: ${rows.length} badge and status-text colour pairs meet 4.5:1 in light and dark`);
process.exit(bad ? 1 : 0);
