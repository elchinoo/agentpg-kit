// Regression: the sign-in card must not contain the text "null" (replaceChildren prints null children). Run: node tests/ui/login_card.mjs
import { pathToFileURL } from "node:url";
import { register } from "node:module";
import { writeFileSync } from "node:fs";
const root = new URL("../../src/apgkit/static/", import.meta.url).pathname;
writeFileSync("/tmp/kit-loader.mjs", `export async function resolve(s,c,n){ if(s.startsWith("/kit/")) return {url:${JSON.stringify(pathToFileURL(root).href)}+s.slice(5),shortCircuit:true}; return n(s,c);}`);
register(pathToFileURL("/tmp/kit-loader.mjs"));
class El { constructor(t){this.tag=t;this.children=[];this.attrs={};this.dataset={};this.listeners={};}
  get nodeType(){return 1;} append(...k){this.children.push(...k);} setAttribute(k,v){this.attrs[k]=v;} addEventListener(){} focus(){}
  replaceChildren(...k){ this.children = k.map((x) => (x == null || x === false ? { nodeType: 3, data: String(x), text: () => String(x) } : x)); }   // like a browser
  text(){ return this.children.map((c) => (c.text ? c.text() : c.data ?? "")).join(" "); } }
const els = {};
globalThis.document = { documentElement: { dataset: {} }, getElementById: (id) => (els[id] ||= new El(id)), createElement: (t) => new El(t), createTextNode: (d) => ({ nodeType: 3, data: d, text: () => String(d) }) };
globalThis.window = { dispatchEvent() {}, addEventListener() {} };
globalThis.location = { search: "", hash: "" };
const { renderLogin, state } = await import("/kit/session.js");
let bad = 0;
for (const session of [{ sso: { issuer: "https://id.example.org", login_url: "/auth/login" }, password_login: false, key_login: false },
                       { sso: null, password_login: true, key_login: true }, { sso: { issuer: "https://id.example.org", login_url: "/auth/login" }, password_login: true, key_login: true }]) {
  state.session = session; renderLogin(() => {}, "", "App");
  const t = els["auth-card"].text();
  if (/\bnull\b|\bundefined\b/.test(t)) { console.error("FAIL: card text contains null/undefined:", t); bad++; }
}
console.log(bad ? "FAILED" : "ok: no null/undefined in the sign-in card");
process.exit(bad ? 1 : 0);
