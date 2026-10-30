/**
 * Plays docs/VIDEO-SCRIPT.md (scenes 1 to 11) and records it with Playwright.
 *
 * LOCAL ONLY. Needs a running throwaway Postgres (UTF8, listening on 127.0.0.1, see the script's "Prerequisites"):
 *   APGKIT_REC_PG_PORT   port of that cluster                      (default 55432)
 *   APGKIT_REC_DB        database to DROP and recreate; its name MUST end in "test"   (default notes_test)
 *   APGKIT_REC_PORT      port the Notes app listens on              (default 8790)
 *   APGKIT_REC_PG_USER   Postgres user                              (default postgres)
 *   RECORD=0             rehearse without writing a video;  HEADED=1 to watch
 *
 * The browser only shows the browser; the terminal scenes are drawn on a terminal-looking page in the same browser
 * window, from real command output (the commands really run), so one video file holds the whole story.
 * Output (git-ignored): docs/video/out/video/*.webm, timings.json, work/ (the copied app, its venv, logs).
 */
import { test, expect, type Page, type Locator } from '@playwright/test';
import { ChildProcess, execFileSync, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const KIT = path.resolve(__dirname, '..', '..');
const OUT = path.join(__dirname, 'out');
const WORK = path.join(OUT, 'work');
const PG_PORT = process.env.APGKIT_REC_PG_PORT ?? '55432';
const PG_USER = process.env.APGKIT_REC_PG_USER ?? 'postgres';
const DB = process.env.APGKIT_REC_DB ?? 'notes_test';
const PORT = process.env.APGKIT_REC_PORT ?? '8790';
const BASE = `http://127.0.0.1:${PORT}`;
const DSN = `postgresql://${PG_USER}@127.0.0.1:${PG_PORT}/${DB}`;
const PW = 'correct horse battery';
const PLATFORM_KEY = 'rec-demo-platform-key-please-change';
const VERSION = /__version__ = "([^"]+)"/.exec(fs.readFileSync(path.join(KIT, 'src/apgkit/__init__.py'), 'utf8'))![1];
const APP_DIR = path.join(WORK, 'notes');
const NOTES_BIN = path.join(APP_DIR, '.venv', 'bin', 'notes');
const RECORDING = process.env.RECORD !== '0';

// ---------------------------------------------------------------- helpers: processes and database

const psqlArgs = (db: string) => ['-h', '127.0.0.1', '-p', PG_PORT, '-U', PG_USER, '-X', '-q', db];
function sh(cmd: string, cwd = WORK, env: Record<string, string> = {}): string {
  return execFileSync('/bin/bash', ['-c', cmd], { cwd, env: { ...process.env, ...env } as Record<string, string>, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}
function resetDatabase() {
  if (!DB.endsWith('test')) throw new Error(`refusing to drop "${DB}": the database name must end in "test"`);
  const enc = execFileSync('psql', [...psqlArgs('postgres'), '-Atc', 'show server_encoding'], { encoding: 'utf8' }).trim();
  if (enc !== 'UTF8') throw new Error(`the cluster is ${enc}; create it with initdb -E UTF8 (the vault fails on SQL_ASCII)`);
  execFileSync('psql', [...psqlArgs('postgres'), '-c', `DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`]);
  execFileSync('psql', [...psqlArgs('postgres'), '-c', `CREATE DATABASE ${DB}`]);
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

class Server {
  proc?: ChildProcess;
  log = '';
  async start(extraEnv: Record<string, string> = {}) {
    this.log = '';
    const env = { PATH: `${path.dirname(NOTES_BIN)}:/usr/bin:/bin`, HOME: WORK, LANG: 'en_US.UTF-8', PYTHONUNBUFFERED: '1', NO_COLOR: '1',
      DATABASE_URL: DSN, PORT, HOST: '127.0.0.1', ...extraEnv };
    this.proc = spawn(NOTES_BIN, [], { env, cwd: APP_DIR, stdio: ['ignore', 'pipe', 'pipe'] });
    this.proc.stdout!.on('data', (d) => (this.log += d));
    this.proc.stderr!.on('data', (d) => (this.log += d));
    const t0 = Date.now();
    while (!/Application startup complete/.test(this.log)) {
      if (this.proc.exitCode !== null) throw new Error(`notes exited early:\n${this.log}`);
      if (Date.now() - t0 > 60_000) throw new Error(`notes did not start:\n${this.log}`);
      await sleep(200);
    }
    if (/address already in use/i.test(this.log)) throw new Error(`port ${PORT} is taken; set APGKIT_REC_PORT`);
  }
  async stop() {
    const p = this.proc;
    if (!p || p.exitCode !== null) return;
    p.kill('SIGINT');                                    // what Ctrl+C does
    for (let i = 0; i < 50 && p.exitCode === null; i++) await sleep(100);
    if (p.exitCode === null) p.kill('SIGKILL');
  }
}

// ---------------------------------------------------------------- helpers: pacing, cursor, highlights

const SLOW = RECORDING || process.env.REAL_PACE === '1';  // a rehearsal without video runs fast unless REAL_PACE=1
const PACE = SLOW ? 1 : 0.15;
// Scene plan (from build.sh): per-scene minimum length (narration + margin) and a stretch factor for the pauses/holds, so the
// narration of a scene is never cut. Without a plan (rehearsal) every scene runs at its natural length.
const PLAN: { need?: Record<string, number>; scale?: Record<string, number>; cues?: Record<string, { text: string; start: number }[]> } = process.env.APGKIT_REC_PLAN ? JSON.parse(fs.readFileSync(process.env.APGKIT_REC_PLAN, 'utf8')) : {};
let curScene = 0;
let sceneStart = 0;                                    // ms from the start of the recording to the current scene's start
let clock0 = 0;
const events: { scene: number; t: number; what: string }[] = [];   // what appeared on screen, and when (for checking against the cues)
/** Wait until the narration starts the sentence matching `re` (a no-op in a rehearsal), so the action shows what is being said. */
async function sync(page: Page, re: RegExp) {
  if (!PLAN.cues) return;
  const cue = PLAN.cues[curScene]?.find((c) => re.test(c.text));
  if (!cue) throw new Error(`scene ${curScene}: no narration sentence matches ${re}`);
  const wait = sceneStart + 150 + cue.start * 1000 - 120 - (Date.now() - clock0);   // 150 ms: audio offset in the mux
  if (wait > 0) await page.waitForTimeout(wait);
  events.push({ scene: curScene, t: Date.now() - clock0, what: `sync ${re}` });
}
const paused: Record<string, number> = {};
const pause = (page: Page, ms: number) => {
  const eff = ms * PACE * (PLAN.scale?.[curScene] ?? 1);
  paused[curScene] = (paused[curScene] ?? 0) + eff;
  return page.waitForTimeout(eff);
};
const TYPE_DELAY = SLOW ? 85 : 8;

const CURSOR_INIT = () => {
  const mk = () => {
    if (document.getElementById('rec-cursor') || !document.body) return;
    const c = document.createElement('div');
    c.id = 'rec-cursor';
    Object.assign(c.style, { position: 'fixed', left: '0px', top: '0px', width: '22px', height: '22px', borderRadius: '50%', background: 'rgba(255,200,0,.55)',
      border: '2px solid #b45309', zIndex: '2147483647', pointerEvents: 'none', transform: 'translate(-50%,-50%)', transition: 'transform .05s' });
    document.body.appendChild(c);
    document.addEventListener('mousemove', (e) => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; }, true);
    document.addEventListener('mousedown', () => { c.style.background = 'rgba(220,38,38,.7)'; }, true);
    document.addEventListener('mouseup', () => { c.style.background = 'rgba(255,200,0,.55)'; }, true);
  };
  document.addEventListener('DOMContentLoaded', mk);
  new MutationObserver(mk).observe(document, { childList: true, subtree: true });
};

let mouse = { x: 960, y: 540 };
async function glide(page: Page, x: number, y: number) {
  await page.mouse.move(x, y, { steps: SLOW ? 28 : 3 });
  mouse = { x, y };
}
async function point(page: Page, loc: Locator) {
  await loc.scrollIntoViewIfNeeded();
  const b = (await loc.boundingBox())!;
  await glide(page, b.x + b.width / 2, b.y + b.height / 2);
  return b;
}
async function click(page: Page, loc: Locator) {
  await point(page, loc);
  await pause(page, 350);
  await loc.click();
  await pause(page, 500);
}
async function typeInto(page: Page, loc: Locator, text: string) {
  await click(page, loc);
  await loc.pressSequentially(text, { delay: TYPE_DELAY });
  await pause(page, 400);
}

/** A highlight box around `loc` (or a lower third when loc is null) with a caption. Returns a function that removes it. */
async function callout(page: Page, loc: Locator | null, text: string, low = false, top = false): Promise<() => Promise<void>> {
  const id = 'rec-co-' + Math.random().toString(36).slice(2, 8);
  const box = loc ? await loc.boundingBox() : null;
  await page.evaluate(({ id, text, box, low, top }) => {
    const wrap = document.createElement('div');
    wrap.id = id;
    Object.assign(wrap.style, { position: 'fixed', inset: '0', pointerEvents: 'none', zIndex: '2147483646' });
    if (box) {
      const r = document.createElement('div');
      Object.assign(r.style, { position: 'fixed', left: box.x - 8 + 'px', top: box.y - 6 + 'px', width: box.width + 16 + 'px', height: box.height + 12 + 'px',
        border: '4px solid #f59e0b', borderRadius: '10px', boxShadow: '0 0 0 9999px rgba(0,0,0,.18), 0 0 18px #f59e0b' });
      wrap.appendChild(r);
    }
    const cap = document.createElement('div');
    cap.textContent = text;
    const below = top ? 56 : box && !low ? Math.min(box.y + box.height + 18, window.innerHeight - 80) : window.innerHeight - 110;
    Object.assign(cap.style, { position: 'fixed', left: box && !low ? Math.max(24, Math.min(box.x, window.innerWidth - 640)) + 'px' : '48px', top: below + 'px',
      maxWidth: '620px', background: '#111827', color: '#fff', font: '600 28px/1.25 system-ui, sans-serif', padding: '12px 20px', borderRadius: '10px',
      borderLeft: '8px solid #f59e0b', boxShadow: '0 6px 24px rgba(0,0,0,.4)' });
    wrap.appendChild(cap);
    document.body.appendChild(wrap);
  }, { id, text, box, low, top });
  return async () => { await page.evaluate((id) => document.getElementById(id)?.remove(), id).catch(() => undefined); };
}
let shots = 0;
async function hold(page: Page, loc: Locator | null, text: string, ms: number, low = false, top = false) {
  const off = await callout(page, loc, text, low, top);
  events.push({ scene: curScene, t: Date.now() - clock0, what: `callout: ${text}` });
  if (!RECORDING && process.env.SHOTS === '1') {                       // rehearsal: one screenshot per callout, for a visual check
    fs.mkdirSync(path.join(OUT, 'shots'), { recursive: true });
    await page.screenshot({ path: path.join(OUT, 'shots', `${String(++shots).padStart(2, '0')}-${text.replace(/\W+/g, '-').slice(0, 30)}.png`) });
  }
  await pause(page, ms);
  await off();
}

// ---------------------------------------------------------------- helpers: the terminal page

// what the viewer sees uses the ports of the script (8790, 55432) even when the recorder runs on others
const shown = (s: string) => s.split(`127.0.0.1:${PORT}`).join('127.0.0.1:8790').split(`localhost:${PORT}`).join('localhost:8790').split(`127.0.0.1:${PG_PORT}`).join('127.0.0.1:55432');
const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

class Term {
  constructor(private page: Page, private tab = 'terminal') {}
  async open(px = 26) {
    await this.page.goto('about:blank');
    await this.page.setContent(`<!doctype html><meta charset=utf-8><title>${this.tab}</title><body style="margin:0;background:#0f172a;color:#e2e8f0;font:${px}px/1.4 Menlo,Monaco,monospace">
      <div style="padding:10px 28px;background:#1e293b;color:#94a3b8;font:20px system-ui">${esc(this.tab)}</div>
      <pre id="t" style="margin:0;padding:24px 28px;white-space:${px < 26 ? 'pre' : 'pre-wrap'};word-break:break-all;overflow:hidden"></pre>`);
    await this.page.evaluate(CURSOR_INIT);
    await this.page.evaluate(() => { document.dispatchEvent(new Event('DOMContentLoaded')); });
  }
  private async add(html: string) {
    await this.page.evaluate((h) => { const t = document.getElementById('t')!; t.insertAdjacentHTML('beforeend', h); window.scrollTo(0, document.body.scrollHeight); }, html);
  }
  /** Type a command char by char after a prompt. */
  async type(cmd: string) {
    await this.add('<span style="color:#4ade80">$ </span><span id="typing"></span>');
    for (const ch of cmd) {
      await this.page.evaluate((c) => { document.getElementById('typing')!.textContent += c; }, ch);
      await this.page.waitForTimeout(SLOW ? Math.max(12, Math.min(55, 3600 / cmd.length)) : 2);   // long commands are typed faster
    }
    await this.page.evaluate(() => document.getElementById('typing')!.removeAttribute('id'));
    await this.add('\n');
    await pause(this.page, 500);
  }
  async out(text: string, perLineMs = 120) {
    for (const line of text.replace(/\n$/, '').split('\n')) {
      await this.add(`<span class="ln">${esc(shown(line))}</span>\n`);
      await this.page.waitForTimeout(SLOW ? perLineMs : 0);
    }
    await pause(this.page, 400);
  }
  /** Type, really run in bash, show the output. */
  async run(cmd: string, opts: { cwd?: string; env?: Record<string, string>; show?: (o: string) => string } = {}) {
    await this.type(cmd);
    let o: string;
    try { o = sh(cmd, opts.cwd ?? WORK, opts.env); } catch (e: any) { o = String(e.stdout ?? '') + String(e.stderr ?? ''); }
    await this.out(opts.show ? opts.show(o) : o);
    return o;
  }
  /** Show lines of a file with line numbers; lines matching a pattern in `marks` are highlighted with a caption. */
  async file(rel: string, from: number, to: number, marks: [RegExp, string][] = [], syncs: RegExp[] = []) {
    const lines = fs.readFileSync(path.join(KIT, rel), 'utf8').split('\n').slice(from - 1, to);
    await this.open(21);
    await this.add(`<span style="color:#94a3b8">${esc(rel)}</span>\n\n`);
    const ids: string[] = [];
    let n = from;
    for (const l of lines) {
      const hit = marks.findIndex(([re]) => re.test(l));
      const id = hit >= 0 ? `m${hit}` : '';
      await this.add(`<span ${id ? `id="${id}"` : ''}><span style="color:#64748b">${String(n).padStart(3)}  </span>${esc(l.length > 125 ? l.slice(0, 125) + '…' : l)}</span>\n`);
      if (id) ids.push(id);
      n++;
    }
    await pause(this.page, 600);
    for (let i = 0; i < marks.length; i++) {
      const loc = this.page.locator(`#m${i}`);
      if (await loc.count()) { await loc.first().scrollIntoViewIfNeeded(); if (syncs[i]) await sync(this.page, syncs[i]); await hold(this.page, loc.first(), marks[i][1], 1800, true); }
    }
  }
  async highlight(text: string, caption: string, ms = 2200) {
    const loc = this.page.locator('#t').getByText(text, { exact: false }).first();
    if (!(await loc.count())) { await hold(this.page, null, caption, ms); return; }
    await hold(this.page, loc, caption, ms, true);   // caption in the lower third so it never covers the listing
  }
}

const cardHtml = (big: string, small: string) => `<!doctype html><meta charset=utf-8><title>card</title><body style="margin:0;height:100vh;display:grid;place-items:center;background:linear-gradient(135deg,#0f172a,#1e3a8a);color:#fff;font-family:system-ui;text-align:center">
    <div><div style="font-size:84px;font-weight:700;max-width:1500px">${esc(big)}</div><div style="font-size:36px;margin-top:28px;color:#bfdbfe">${esc(small)}</div></div>`;
const TITLE = ['Build an app in 10 minutes with agentpg-kit', 'Python, FastAPI, Postgres'];
async function card(page: Page, big: string, small: string, ms: number) {
  await page.goto('about:blank');
  await page.setContent(cardHtml(big, small));
  await page.waitForTimeout(ms * PACE);                  // cards keep their own length (not stretched to the narration)
}

// ---------------------------------------------------------------- the recording

test('record docs/VIDEO-SCRIPT.md', async ({ browser }) => {
  fs.rmSync(WORK, { recursive: true, force: true });
  fs.mkdirSync(WORK, { recursive: true });
  const starts: Record<string, number> = {};
  const server = new Server();

  // ---- Off-camera preparation (script: "Prerequisites and seed data"; the install output is captured for scene 3)
  resetDatabase();
  fs.symlinkSync(KIT, path.join(WORK, 'agentpg-kit'));
  const installOut = (sh(`cp -R agentpg-kit/docs/examples/notes ./notes && cd notes && uv venv 2>&1 && source .venv/bin/activate && uv pip install -e ../agentpg-kit -e . 2>&1`, WORK)).replace(/\x1b\[[0-9;]*m/g, '');   // no colour codes on screen

  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1,
    recordVideo: RECORDING ? { dir: path.join(OUT, 'video'), size: { width: 1920, height: 1080 } } : undefined,
  });
  await context.addInitScript(CURSOR_INIT);
  const page = await context.newPage();
  const term = new Term(page);
  const t0 = Date.now();
  clock0 = t0;
  /** Hold the current scene until its planned minimum length has passed (never shortens anything). */
  const padScene = async () => {
    const need = PLAN.need?.[curScene];
    if (!need) return;
    const left = starts[curScene] + need * 1000 - (Date.now() - t0);
    if (left > 0) await page.waitForTimeout(left);
  };
  const scene = async (n: number) => { await padScene(); curScene = n; starts[n] = Date.now() - t0; sceneStart = starts[n]; };

  try {
    // ---- Scene 1: introduction
    await scene(1);
    await card(page, TITLE[0], TITLE[1], 3000);
    await term.open();
    await term.run('ls', { cwd: WORK, show: (o) => o.split('\n').filter((l) => l === 'agentpg-kit').join('\n') });
    await sync(page, /agentpg-kit, the shared library/);
    await hold(page, null, `agentpg-kit ${VERSION}`, 2500);

    // ---- Scene 2: what the kit is
    await scene(2);
    await term.run('ls agentpg-kit/src/apgkit', { cwd: WORK, show: (o) => o.split('\n').filter((l) => !l.startsWith('__pycache__')).join('\n') });
    await pause(page, 800);
    await term.file('README.md', 1, 16, [[/apgkit\.vault/, 'vault: encrypts stored secrets'], [/apgkit\.auth`/, 'auth: one front door'], [/apgkit\.static/, 'static, served at /kit/']], [/First, the vault/, /Next, auth/, /shared browser interface/]);

    // ---- Scene 3: install
    await scene(3);
    await term.open();
    await sync(page, /We copy it/);
    await term.type('cp -R agentpg-kit/docs/examples/notes ./notes && cd notes');
    await term.type('uv venv && source .venv/bin/activate');
    await term.type('uv pip install -e ../agentpg-kit -e .');
    await term.out(installOut.trim().split('\n').slice(-6).join('\n'), 200);
    await sync(page, /In your own project/);
    await term.highlight('uv pip install', 'uv pip install -e ../agentpg-kit');
    await sync(page, /Now we tell the app/);
    await term.type(`export DATABASE_URL=postgresql://${PG_USER}@127.0.0.1:55432/notes_test`);
    await term.run('ls -R src | head -20', { cwd: APP_DIR });
    await sync(page, /names that AgentPG sets/);
    await hold(page, null, 'DATABASE_URL, DB_EXTERNAL_DSN or PSQL_CONNECTION_STRING', 3000, false, true);   // top: the listing fills the lower part

    // ---- Scene 4: the app's core
    await scene(4);
    const EX = 'docs/examples/notes/src/notes';
    await term.file(`${EX}/core.py`, 15, 38, [[/^ROLE_PERMISSIONS/, 'role -> permission'], [/^vault = Vault/, 'the vault: encrypted storage'], [/^fed = from_env/, 'single sign-on if configured'], [/^local = LocalAuth/, 'local login'], [/^auth = Authenticator/, 'one front door']],
      [/First, roles/, /vault line/, /single sign-on/, /local login/, /authenticator/]);
    await term.file(`${EX}/migrations/001_notes.sql`, 1, 10, [[/CREATE TABLE/, 'migrations run once']], [/Now the database/]);
    await term.file(`${EX}/app.py`, 137, 177, [[/@app\.delete/, 'one question: can()']], [/Last, a route/]);

    // ---- Scene 5: start the server
    await scene(5);
    await term.open();
    await sync(page, /We start the app/);
    await term.type('PORT=8790 notes 2>&1 | tee /tmp/notes.log');
    await server.start();
    await term.out(server.log.trim());
    const code = /Setup code: ([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})/.exec(server.log)![1];
    await sync(page, /Here it is/);
    await term.highlight(code, 'Only readable by the server’s operator', 3200);

    // ---- Scene 6: first-run setup
    await scene(6);
    await page.goto(BASE + '/');
    await expect(page.getByText('Set up Notes')).toBeVisible();
    await pause(page, 1200);
    await sync(page, /Paste the code/);
    await typeInto(page, page.locator('#setup-code'), code);
    await typeInto(page, page.locator('#setup-pw'), PW);
    await sync(page, /salted hash/);
    await hold(page, page.locator('#setup-pw'), 'stored as a salted hash', 2200);
    await typeInto(page, page.locator('#setup-pw2'), PW);
    await click(page, page.getByRole('button', { name: 'Create admin password' }));
    await expect(page.getByText('Admin password set. You are signed in.')).toBeVisible();
    await sync(page, /creates the vault/);
    await hold(page, page.locator('#toast'), 'vault created', 2200, false, true);
    await expect(page.getByText('No notes yet.')).toBeVisible();
    await pause(page, 1500);

    // ---- Scene 7: add notes, look at the database
    await scene(7);
    await sync(page, /add two notes/);
    await typeInto(page, page.locator('#n-title'), 'First');
    await typeInto(page, page.locator('#n-body'), 'hello');
    await click(page, page.getByRole('button', { name: 'Add note' }));
    await expect(page.getByText('Note saved')).toBeVisible();
    await pause(page, 1200);
    await sync(page, /Now a private one/);
    await typeInto(page, page.locator('#n-title'), 'Secret');
    await typeInto(page, page.locator('#n-body'), 'launch codes');
    await click(page, page.locator('#n-private'));
    await click(page, page.getByRole('button', { name: 'Add note' }));
    const secretRow = page.locator('tr', { hasText: 'Secret' });
    await expect(secretRow.locator('.badge')).toHaveText('private');
    await expect(page.locator('tr', { hasText: 'First' })).toBeVisible();
    await sync(page, /look the same/);
    await hold(page, secretRow, 'private note: same screen, a badge', 2200);
    await sync(page, /what the database holds/);
    const q = `select title, left(body, 40) as body, private from note order by id`;
    await term.open();
    await term.type(`psql -h 127.0.0.1 -p 55432 -U postgres notes_test -c "${q}"`);   // as in the script; really run against the rehearsal database
    const real = execFileSync('psql', [...psqlArgs(DB), '-c', q], { encoding: 'utf8' });
    await term.out(real);
    expect(real).toMatch(/Secret\s*\|\s*v2\$/);
    expect(real).toMatch(/First\s*\|\s*hello\s*\|\s*f/);
    await sync(page, /is scrambled/);
    await term.highlight('v2$', 'encrypted by the vault', 3000);

    // ---- Scene 8: confirmation dialog
    await scene(8);
    await page.goto(BASE + '/');
    const first = page.locator('tr', { hasText: 'First' });
    await expect(first).toBeVisible();
    await sync(page, /Now, deleting/);
    await click(page, first.getByRole('button', { name: 'Delete' }));
    const dlg = page.locator('dialog.confirm-dialog');
    await expect(dlg).toBeVisible();
    await sync(page, /built-in pop-up/);
    await hold(page, dlg, 'Accessible dialog from the shared kit UI', 2200);
    await sync(page, /Escape cancels/);
    await page.keyboard.press('Escape');
    await expect(dlg).toBeHidden();
    await expect(first).toBeVisible();
    await pause(page, 1000);
    await sync(page, /Confirm, and/);
    await click(page, first.getByRole('button', { name: 'Delete' }));
    await click(page, dlg.locator('button.danger-solid'));
    await expect(first).toHaveCount(0);
    await pause(page, 1500);

    // ---- Scene 9: API tokens and the CSRF header
    await scene(9);
    await term.open();
    await sync(page, /sign in from the command line/);
    await term.type(`H=(-H 'X-Notes-CSRF: 1' -H 'Content-Type: application/json')`);
    const jar = path.join(WORK, 'jar');
    const H = `-H 'X-Notes-CSRF: 1' -H 'Content-Type: application/json'`;
    const U = `127.0.0.1:${PORT}`;
    await term.type(`curl -s -c jar "\${H[@]}" -X POST localhost:8790/api/login -d '{"password":"${PW}"}'`);
    await term.out(sh(`curl -s -c ${jar} ${H} -X POST ${U}/api/login -d '{"password":"${PW}"}'`));
    await sync(page, /ask for a token/);
    await term.type(`curl -s -b jar "\${H[@]}" -X POST "localhost:8790/api/tokens?name=ci&scope=read"`);
    const tokOut = sh(`curl -s -b ${jar} ${H} -X POST "${U}/api/tokens?name=ci&scope=read"`);
    await term.out(tokOut);
    const token = JSON.parse(tokOut).token as string;
    expect(token).toMatch(/^nt_/);
    await sync(page, /It is shown once/);
    await term.highlight('nt_', 'shown once', 2500);
    await sync(page, /use it to read/);
    await term.type(`curl -s -H "Authorization: Bearer ${token}" localhost:8790/api/notes`);
    const r1 = sh(`curl -s -w '\\n%{http_code}' -H "Authorization: Bearer ${token}" ${U}/api/notes`).trim().split('\n');
    await term.out(r1[0]);
    expect(r1[r1.length - 1]).toBe('200');
    await sync(page, /try to write/);
    await term.type(`curl -s -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' -X POST localhost:8790/api/notes -d '{"title":"x"}'`);
    const r2 = sh(`curl -s -w '\\n%{http_code}' -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' -X POST ${U}/api/notes -d '{"title":"x"}'`).trim().split('\n');
    await term.out(r2[0]);
    expect(r2[r2.length - 1]).toBe('403');
    expect(r2[0]).toBe(`{"detail":"this credential cannot do that (it lacks 'notes:write')"}`);
    await sync(page, /scope does not grant/);
    await term.highlight('lacks', '403: scope read cannot write', 3000);
    await sync(page, /One more try/);
    await term.type(`curl -s -b jar -X POST localhost:8790/api/notes -d '{}'`);
    const r3 = sh(`curl -s -w '\\n%{http_code}' -b ${jar} -X POST ${U}/api/notes -d '{}'`).trim().split('\n');
    await term.out(r3[0]);
    expect(r3[r3.length - 1]).toBe('403');
    expect(r3[0]).toBe('{"detail": "missing CSRF header"}');
    await sync(page, /header defends/);
    await term.highlight('missing CSRF header', 'CSRF defence', 3000);

    // ---- Scene 10: restart, locked vault, platform key
    await scene(10);
    const restart = async (env: Record<string, string>, label: string) => {
      await term.open();
      await term.type('^C');
      await server.stop();
      await term.type(`${label}PORT=8790 notes`);
      await server.start(env);
      await term.out(server.log.trim().split('\n').slice(-3).join('\n'));
      await pause(page, 600);
    };
    const secretText = () => page.locator('tr', { hasText: 'Secret' });
    const unlock = async () => {
      await typeInto(page, page.locator('#unlock-pw'), PW);
      await click(page, page.locator('#vault-banner').getByRole('button', { name: 'Unlock' }));
      await expect(page.getByText('Unlocked', { exact: true })).toBeVisible();
      await expect(secretText()).toContainText('launch codes');
      await pause(page, 1500);
    };
    await sync(page, /We stop it/);
    await restart({}, '');
    await sync(page, /reload the browser/);
    await page.goto(BASE + '/');
    await expect(page.locator('#vault-banner')).toBeVisible();
    await expect(page.locator('#vault-banner')).toContainText('Provider keys are locked.');
    await expect(secretText()).toContainText('locked');
    await sync(page, /only lives in memory/);
    await hold(page, page.locator('#vault-banner'), 'key lives only in memory', 3000);
    await sync(page, /Type the admin password/);
    await unlock();
    await sync(page, /Give the server a platform key/);
    await restart({ NOTES_ENCRYPTION_KEY: PLATFORM_KEY }, 'NOTES_ENCRYPTION_KEY=rec-demo-platform-key-please-change ');
    await page.goto(BASE + '/');
    await expect(page.locator('#vault-banner')).toBeVisible();     // the stored wrap does not exist yet: first unlock adds it
    await sync(page, /platform stores/);
    await hold(page, null, 'NOTES_ENCRYPTION_KEY = platform key', 2200);
    await sync(page, /Unlock once/);
    await unlock();
    await sync(page, /Restart one more time/);
    await restart({ NOTES_ENCRYPTION_KEY: PLATFORM_KEY }, 'NOTES_ENCRYPTION_KEY=rec-demo-platform-key-please-change ');
    await page.goto(BASE + '/');
    await expect(page.getByRole('heading', { name: 'Notes' })).toBeVisible();
    await expect(page.locator('#vault-banner')).toBeHidden();
    await expect(secretText()).toContainText('launch codes');
    await sync(page, /no banner/);
    await hold(page, secretText(), 'no banner: unlocked at start', 3000);

    // ---- Scene 11: recap
    await scene(11);
    await term.open();
    await term.run('ls src/notes src/notes/migrations src/notes/static', { cwd: APP_DIR });
    await term.file('docs/GUIDE.md', 1, 12, [[/\[6 First run/, 'section 6: walkthrough'], [/\[7 Blocks/, 'section 7: blocks'], [/\[10 Operations/, 'section 10: operations']],
      [/Section six/, /Section seven/, /Section ten/]);
    await padScene();                                     // the narration ends before the silent end card
    await scene(12);
    await card(page, 'docs/GUIDE.md', 'docs/examples/notes', 5000);
  } finally {
    await server.stop();
    fs.mkdirSync(OUT, { recursive: true });
    const end = Date.now() - t0;
    // timings.json (milliseconds from the start of the video): scene starts, "end", and the paused time per scene (used to plan stretching)
    fs.writeFileSync(path.join(OUT, 'timings.json'), JSON.stringify({ starts, end, paused, events }, null, 1));
    await context.close();                                // flushes the video file
    // a still of the title card: when the video file starts late (a busy machine), build.py puts it in front to restore the timeline
    const still = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
    const sp = await still.newPage();
    await sp.setContent(cardHtml(TITLE[0], TITLE[1]));
    await sp.screenshot({ path: path.join(OUT, 'card1.png') });
    await still.close();
  }
});
