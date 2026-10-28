# Video script: build a new app in 10 minutes with agentpg-kit

**Running time:** about 6:59: 929 words of narration (6:44 of speech, with deliberate pauses over commands that run) in five voices that alternate by topic.
The title says 10 minutes because that is how long the work takes in real time, including typing; the video cuts the waiting.

**Audience:** customers and internal engineers who know Python and have used Postgres, but have not used the AgentPG ecosystem. No
knowledge of the kit is assumed. Terms such as "vault", "CSRF" and "single sign-on" are explained in one sentence when they first appear.

**Goal:** by the end the viewer has seen a small web app, "Notes", go from an empty folder to a running app with first-run setup,
login, encrypted private notes, read-only API tokens and a locked-vault recovery, and knows that the kit supplied all of that
infrastructure, so only the app's own logic had to be written. The viewer knows where to read next
([`docs/GUIDE.md`](GUIDE.md)).

**Companion:** the app is [`docs/examples/notes`](examples/notes). Every step below was run on 2026-10-27 against a local Postgres 17.5
and a browser; the commands and screen text are the ones that actually appeared.

---

## Prerequisites and seed data for recording

Everything is local and reproducible; no AgentPG account, no identity provider and no network access to other services are needed.

| Need | How to get it |
|---|---|
| Python 3.11+ and [uv](https://docs.astral.sh/uv/) | already installed on the recording machine |
| A throwaway Postgres, **UTF-8**, port 55432, listening on 127.0.0.1 only | `initdb -D /tmp/apgkit-rec -U postgres -E UTF8 --auth=trust && pg_ctl -D /tmp/apgkit-rec -o "-p 55432 -c listen_addresses=127.0.0.1 -c unix_socket_directories=''" -l /tmp/apgkit-rec.log start` (or the `pgvector/pgvector:pg17` Docker image, port-mapped to 127.0.0.1:55432 with `POSTGRES_PASSWORD=postgres`, and adjust the DSN). If 55432 is taken, pick another port and say so to the recorder (`APGKIT_REC_PG_PORT`) |
| An empty database named `notes_test` (the name must end in `test`: the recorder refuses to drop anything else) | `createdb -h 127.0.0.1 -p 55432 -U postgres notes_test` |
| This repository next to a working folder | `agentpg-kit/` checked out; the video starts in the folder that contains it |
| A browser at 1920x1080 (the recorder sets this), light theme | the shared UI has a dark scheme too; record light for contrast |
| A terminal with a large font (about 18 pt) and a second tab for `psql` | |

**Seed data: none.** The viewer sees the first-run setup, so the database must be empty. Reset between takes:

```bash
dropdb  -h 127.0.0.1 -p 55432 -U postgres --if-exists notes_test
createdb -h 127.0.0.1 -p 55432 -U postgres notes_test
rm -rf ./notes                      # the copied app folder, if it exists
```

Values used on camera (all test values, safe to show): admin password `correct horse battery`, platform key
`rec-demo-platform-key-please-change`, notes "First" / "hello" and "Secret" / "launch codes". The setup code is random on every start;
show whatever the log prints.

---

## Scenes

| # | Time | What the viewer sees |
|---|---|---|
| 1 | 0:00 | Title card, then a terminal |
| 2 | 0:24 | The kit's modules and README table |
| 3 | 1:00 | Copy the app, install, point at the database |
| 4 | 1:38 | The app's `core.py` and migration |
| 5 | 2:31 | Start the server, find the setup code |
| 6 | 2:55 | Browser: first-run setup |
| 7 | 3:23 | Add a note and a private note; look at the database |
| 8 | 3:56 | Delete with the shared confirmation dialog |
| 9 | 4:17 | API tokens and the CSRF header with curl |
| 10 | 5:15 | Restart: the locked vault and the platform key |
| 11 | 6:11 | Recap and next steps |

### Scene 1 (0:00 to 0:28): Introduction

**ON-SCREEN ACTION:** Title card "Build an app in 10 minutes with agentpg-kit" for 3 seconds. Cut to a terminal in an empty working
directory, prompt visible. Run `ls`; it shows `agentpg-kit`.

**NARRATION:** "Most small web apps need the same dull parts before they do anything useful. A login. A place to keep secrets. A safe way to talk to the database. In this video we build a small app called Notes. We build it on agentpg-kit, the shared library behind every app in the AgentPG ecosystem. And we get all of that without writing it."

**CALLOUTS:** lower third "agentpg-kit 0.2.5". Caption "Python, FastAPI, Postgres".

### Scene 2 (0:28 to 1:00): What the kit is

**ON-SCREEN ACTION:** In the terminal run `ls agentpg-kit/src/apgkit`. Then open `agentpg-kit/README.md` in the editor, scrolled to the
block table at the top; slowly highlight the rows `apgkit.vault`, `apgkit.auth` and the last row "static, served at /kit/".

**NARRATION:** "The kit is a library, not a server. It is a handful of small blocks. Let's look at them. First, the vault. It encrypts stored secrets. Next, auth. One front door for every kind of caller. It accepts an admin password, an API token, or a token from a company identity provider. There is also a security middleware. And a shared browser interface. It is served from a path called slash kit. The apps in this ecosystem are built from these same blocks. TrustDesk, PagerLens, and PayBroker are examples."

**CALLOUTS:** point at "vault", "auth", "/kit/" with arrows as each is named.

### Scene 3 (1:00 to 1:40): Install

**ON-SCREEN ACTION:** Run, one at a time:

```bash
cp -R agentpg-kit/docs/examples/notes ./notes && cd notes
uv venv && source .venv/bin/activate
uv pip install -e ../agentpg-kit -e .
export DATABASE_URL=postgresql://postgres@127.0.0.1:55432/notes_test
```

Pause on the output of the install (it ends with the packages installed). Then `ls -R src | head -20`.

**NARRATION:** "Now, the install. We start from a ready folder. It holds a handful of files. We copy it. Then we make a virtual environment, and install two things. The kit, and our app. In your own project you would install the kit from a release tag. The guide shows the command. Now we tell the app where its database is. One environment variable. The kit also understands the names that AgentPG sets for you. So this same app runs on a sandbox, unchanged."

**CALLOUTS:** "uv pip install -e ../agentpg-kit" highlighted. Caption: "DATABASE_URL, DB_EXTERNAL_DSN or PSQL_CONNECTION_STRING".

### Scene 4 (1:40 to 2:32): The app's core

**ON-SCREEN ACTION:** Open `src/notes/core.py`. Highlight in order: the `ROLE_PERMISSIONS` dictionary (lines for `admin`, `editor`,
`viewer`); the `Vault("NOTES")` line; the `from_env("NOTES", APP)` line; the `LocalAuth(...)` and `Authenticator(...)` lines. Then open
`src/notes/migrations/001_notes.sql` (a single `CREATE TABLE note`). Then open `src/notes/app.py` scrolled to the notes route and
highlight `dependencies=[Depends(auth.require("notes:write"))]` on the delete route.

**NARRATION:** "This is the whole security model of the app. First, roles. An admin can do everything. An editor can read and write notes. A viewer can only read. Next, the vault line. That gives us encrypted storage. The line after it turns on single sign-on, but only if an identity provider address is set. Then local login. And one authenticator, which is the front door. Now the database. It needs one table. The kit runs this migration once, on start. Last, a route. The delete route names the permission it needs. Notice that the code never asks who you are. It asks one question. Can this caller write notes? The kit answers that for every kind of credential."

**CALLOUTS:** "role -> permission" over the dictionary; "one question: can()" over the delete route; "migrations run once" over the SQL file.

### Scene 5 (2:32 to 3:02): Start the server

**ON-SCREEN ACTION:** Run `PORT=8790 notes 2>&1 | tee /tmp/notes.log`. Wait for "Application startup complete". Highlight the block:

```
=== Notes first-run setup ===
Setup code: XXXX-XXXX-XXXX
```

Copy the code (select with the mouse).

**NARRATION:** "Now, the first run. We start the app. On first start, nobody has an account. And we do not want anyone who finds the address to claim the admin role. So the app prints a one-time setup code, in its own log. Here it is. Only someone who can read the server's log can see it. That proves you run this server."

**CALLOUTS:** circle the setup code; caption "Only readable by the server's operator".

### Scene 6 (3:02 to 3:38): First-run setup in the browser

**ON-SCREEN ACTION:** Browser to `http://127.0.0.1:8790/`. The "Set up Notes" card shows. Click the setup code field, paste the code,
click the first password field, type `correct horse battery`, click the second field, type it again, click "Create admin password". A
toast "Admin password set. You are signed in." appears, then the notes screen with "No notes yet."

**NARRATION:** "The browser shows the setup screen that comes with the kit. Paste the code. Then choose a password of at least twelve characters, and confirm it. The password is stored only as a salted hash. Never as plain text. That one step also creates the vault. So the same password protects the secrets we are about to store. We are signed in. This is the Notes screen, built from the kit's shared components."

**CALLOUTS:** "stored as a salted hash" near the password; "vault created" when the toast shows.

### Scene 7 (3:38 to 4:24): Add notes, look at the database

**ON-SCREEN ACTION:** In the browser type title `First`, text `hello`, click "Add note" (toast "Note saved"). Type title `Secret`, text
`launch codes`, tick "Private (encrypted in the vault)", click "Add note". The list shows both; "Secret" has a "private" badge. Switch to
the second terminal tab and run:

```bash
psql -h 127.0.0.1 -p 55432 -U postgres notes_test -c "select title, left(body, 40) as body, private from note order by id"
```

The output shows `First | hello | f` and `Secret | gAAAAAB... | t`.

**NARRATION:** "Let's add two notes. A normal one first. Now a private one. We tick the private box. In the browser, both look the same, except for a badge. Now let's look at what the database holds. The normal note is plain text. The private note is scrambled. The vault encrypted it before it was saved. And the key is not in the database. So someone with a copy of the database, but without the admin password, could not read it."

**CALLOUTS:** highlight the `gAAAAA` value, caption "encrypted by the vault".

### Scene 8 (4:24 to 4:46): Shared UI: confirmation dialog

**ON-SCREEN ACTION:** In the browser click "Delete" on the row "First". The dialog "Delete note" appears; press Escape (it closes and
nothing is deleted); click "Delete" again and click the red "Delete" button in the dialog. The row disappears.

**NARRATION:** "Now, deleting. Deleting asks for confirmation. This is not the browser's built-in pop-up. It is an accessible dialog from the kit. It works with the keyboard, it traps focus, and it can be styled. Escape cancels. Confirm, and the note is gone."

**CALLOUTS:** caption "Accessible dialog from the shared kit UI".

### Scene 9 (4:46 to 5:26): API tokens and the CSRF header

**ON-SCREEN ACTION:** Terminal. First sign in from the command line to get a cookie, then create a read-only token, then use it:

```bash
H=(-H 'X-Notes-CSRF: 1' -H 'Content-Type: application/json')
curl -s -c jar "${H[@]}" -X POST localhost:8790/api/login -d '{"password":"correct horse battery"}'
curl -s -b jar "${H[@]}" -X POST "localhost:8790/api/tokens?name=ci&scope=read"
```

Copy the `nt_...` token. Then:

```bash
curl -s -H "Authorization: Bearer nt_..." localhost:8790/api/notes
curl -s -H "Authorization: Bearer nt_..." -H 'Content-Type: application/json' -X POST localhost:8790/api/notes -d '{"title":"x"}'
curl -s -b jar -X POST localhost:8790/api/notes -d '{}'
```

Outputs: the notes list; `{"detail":"this credential cannot do that (it lacks 'notes:write')"}`; `{"detail": "missing CSRF header"}`.

**NARRATION:** "Now, access for programs. Programs need to reach the app without a browser. So the app can create API tokens. First we sign in from the command line, to get a cookie. Then we ask for a token. A read-only one. Here it is. It is shown once. Only its fingerprint is stored. Now we use it to read the notes. Reading works. Now we try to write. Refused. The token's scope does not grant that permission. One more try. A write from a browser session, without the special header. Refused too. That header defends against another website tricking your browser into acting for you. The kit's middleware checks it for you."

**CALLOUTS:** "shown once" next to the token; "403: scope read cannot write" next to the second reply; "CSRF defence" next to the third.

### Scene 10 (5:26 to 6:06): Restart, locked vault, platform key

**ON-SCREEN ACTION:** Terminal tab running the server: press Ctrl+C, run `PORT=8790 notes` again (no platform key). Browser: reload. The
yellow banner "Provider keys are locked." shows and the Secret note's text reads "locked". Type the password in the banner field and click
"Unlock": toast "Unlocked", the text returns. Back in the terminal: Ctrl+C, then
`NOTES_ENCRYPTION_KEY=rec-demo-platform-key-please-change PORT=8790 notes`; reload the browser, unlock once more with the password;
Ctrl+C and start again with the same key; reload: no banner, text visible. (Cut the waiting; keep the banner and the final reload.)

**NARRATION:** "What happens when the server restarts? We stop it, and start it again. Now we reload the browser. The screen says the keys are locked. The encryption key only lives in memory. So after a restart, the vault is locked. Type the admin password, and it opens again. Now the better way. Give the server a platform key. That is a secret your deployment platform stores. Unlock once with the password. That adds the platform key as a second way in. Restart one more time. And this time, there is no banner. The secret note is readable at once. From now on, restarts need no one."

**CALLOUTS:** "key lives only in memory" over the banner; caption "NOTES_ENCRYPTION_KEY = platform key".

### Scene 11 (6:06 to 6:44): Recap and call to action

**ON-SCREEN ACTION:** Split screen: left, the folder tree of the app (`core.py`, `app.py`, `migrations`, `static`); right, the guide's
contents list ([`docs/GUIDE.md`](GUIDE.md)) with sections 6, 7 and 10 highlighted. Final card with the repository path
`agentpg-kit/docs/GUIDE.md`.

**NARRATION:** "Now, a recap. That is the whole app. In a few hundred lines we have first-run setup, a login, and roles. We also have encrypted secrets, API tokens, and a consistent interface. All of it came from the kit. To go further, read the guide. Section six is the walkthrough. Section seven covers the blocks. Section ten covers operations. Want single sign-on? Set one variable that points at your identity provider. Want to deploy? Add your app to the ecosystem manifest, and let the deployment tool put it on AgentPG. Clone the repository, copy the Notes example, and build your own."

**CALLOUTS:** end card "docs/GUIDE.md" and "docs/examples/notes". Keep the card for 5 seconds with no narration.

---

## Recap (spoken in scene 11, for reviewers)

1. One install, one database variable.
2. Security model in one small file: roles, permissions, vault, optional single sign-on.
3. First-run setup with a code from the log; the password also creates the vault.
4. Private data is encrypted before it reaches the database; a restart locks it until the password or a platform key opens it.
5. Browser sessions need the CSRF header; programs use scoped tokens that are shown once.

Call to action: copy `docs/examples/notes`, run it, then read `docs/GUIDE.md` sections 6 (walkthrough), 7 (blocks), 10 (operations).

## Recording notes

Check before recording: the Postgres cluster reports `UTF8` (`psql -h 127.0.0.1 -p 55432 -U postgres -Atc "select pg_encoding_to_char(encoding) from pg_database where datname='notes_test'"`
must print `UTF8`; with `SQL_ASCII` the vault code fails with a `bytes` error); port 8790 is free (if another process has it, uvicorn
logs "address already in use" and the old process keeps answering).

### The recorder: `docs/video/record.spec.ts`

A runnable Playwright spec performs scenes 1 to 11 in the installed Google Chrome (`channel: "chrome"`, no browser download),
at 1920x1080, with video on, and writes to `docs/video/out/` (git-ignored: `video/*.webm`, `timings.json`, `work/`). Everything
is local: it needs only the throwaway Postgres above. It manages the server itself (the setup code is only in the log, and the
vault scenes need restarts), copies the example app into `out/work/`, creates its virtualenv and installs the kit with `uv`.

```bash
cd agentpg-kit/docs/video
APGKIT_REC_PG_PORT=55432 ./build.sh   # the whole cut: narration, rehearsal, recording, mp4 + srt (installs @playwright/test on first use; no browser or ffmpeg download)
APGKIT_REC_PG_PORT=55432 npx playwright test          # only the recording;  RECORD=0 rehearses without video;  HEADED=1 to watch
```

`build.sh` needs no `npx playwright install ffmpeg` step: it points Playwright at the ffmpeg already on the machine. The narration is spoken by
the local neural voice Kokoro (voice `af_heart`) from [`video/narration.txt`](video/narration.txt), which is the source of the NARRATION
paragraphs of this file; `python3 build.py --write-script` copies it here, and the build refuses to run if the two differ.

Settings (environment): `APGKIT_REC_PG_PORT` (55432), `APGKIT_REC_PG_USER` (postgres), `APGKIT_REC_DB` (`notes_test`; it is
**dropped and recreated**, and the spec refuses a name that does not end in `test` or a cluster that is not UTF8), `APGKIT_REC_PORT`
(8790, the app), `REAL_PACE=1` (with `RECORD=0`: human pace, no video), `SHOTS=1` (with `RECORD=0`: one screenshot per callout in
`out/shots/`, for a storyboard check).

What it does, by scene:

| Scene | In the video |
|---|---|
| 1 to 5, 9, 11 | The browser window shows a terminal-looking page. Commands are typed character by character and **really run** (`ls`, `psql`, `curl`, the server), with their real output. The install output is captured off camera and replayed (installing takes too long). Source files (README table, `core.py`, the SQL, `app.py`, the guide's contents) are shown as listings with highlighted lines. |
| 6, 7, 8, 10 | The real app in the browser: fields are clicked with a visible cursor and typed with a 85 ms delay; each callout is a highlight box plus a caption. The same browser context is kept across the server restarts. Every step has an assertion (`expect`), so the run doubles as a check that the script is true. |

Callouts on screen: lower thirds and boxes drawn by the recorder. Arrows are boxes with captions; add real arrows in editing if wanted.
Not in the recorded video: the editor view (README and source files are shown
as listings instead).

Timing: a rehearsal at human pace (`REAL_PACE=1`) takes about 3 min 50 s of on-screen action with no waiting for installs; the narration is longer, so the recorder
waits at the main steps until the narrator reaches the sentence that describes them (`sync` in `record.spec.ts`). Keep every error message on screen for at least two seconds (the recorder holds them 3 s).

### Known caveats for the recording

- Signing in with the password unlocks the vault (`LocalAuth.login_password` calls `unlock_with_password`). In scene 10, do not
  sign out and in between the restart and the banner: the existing session cookie survives the restart (sessions are in Postgres), which is
  what lets the locked banner appear. The recorder keeps the same browser context across restarts.
- If the platform key is changed later, auto-unlock fails closed (the vault stays locked and the banner shows); unlocking once with the
  password re-wraps the data key under the new key ([GUIDE.md](GUIDE.md) section 10.3). Not part of the video.
- The first-run screen's hint mentions `agentpg sandbox logs <sandbox-id>`; that is correct on AgentPG and harmless locally. Say
  "the server's log" and do not read the hint aloud.
- The banner text says "Provider keys are locked ... external embeddings and Ask are paused". That wording comes from the shared
  kit UI and is aimed at the larger apps; in Notes it means "stored secrets". The narration in scene 10 covers this.
- Single sign-on and the ecosystem deployment are mentioned but not demonstrated; the Notes example has no browser SSO routes
  (see [GUIDE.md](GUIDE.md) section 6.5). Do not show them as working.

## Word counts (for pacing)

Counted from `video/narration.txt` (the spoken text); times are measured from the neural voice, scene length is the finished cut.

| Scene | Narration words | Speaking time (voice) | Scene length in the cut |
|---|---|---|---|
| 1 | 63 | 0:23 (af_heart) | 0:24 |
| 2 | 89 | 0:35 (af_heart) | 0:36 |
| 3 | 83 | 0:36 (am_michael) | 0:37 |
| 4 | 118 | 0:52 (am_michael) | 0:53 |
| 5 | 62 | 0:23 (af_bella) | 0:24 |
| 6 | 73 | 0:26 (af_bella) | 0:27 |
| 7 | 80 | 0:32 (af_bella) | 0:33 |
| 8 | 42 | 0:19 (am_eric) | 0:21 |
| 9 | 112 | 0:57 (am_eric) | 0:57 |
| 10 | 106 | 0:55 (af_sarah) | 0:56 |
| 11 | 101 | 0:41 (af_sarah) | 0:41 |
| **Total** | **929** | **6:44** | **6:59** |
