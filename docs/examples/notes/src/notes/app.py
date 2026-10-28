import contextlib
import sys
from pathlib import Path

from apgkit import migrate
from apgkit.auth import schema as auth_schema
from apgkit.guard import SecurityGuard
from apgkit.vault import VaultError, VaultLocked
from apgkit.web import is_https, mount_kit_static
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .core import COOKIE, CSRF_HEADER, auth, db, fed, local, metrics, vault

HERE = Path(__file__).resolve().parent


def migrate_db() -> list[str]:
    applied = migrate.run(db, HERE / "migrations", table="notes_migrations")
    with db.connect() as conn:                         # the kit's tables: settings, sessions, API tokens, OIDC state
        conn.execute(auth_schema.SQL)
        conn.commit()
    return applied


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    migrate_db()
    with db.connect() as conn:
        vault.try_unlock_with_platform_secret(conn)    # no-op without NOTES_ENCRYPTION_KEY
        if local.needs_setup(conn) and not fed.enabled:
            print(f"\n=== Notes first-run setup ===\nSetup code: {local.setup_code()}\n", file=sys.stderr, flush=True)
    yield


app = FastAPI(title="Notes", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SecurityGuard, csrf_header=CSRF_HEADER, observe=metrics.observe)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
mount_kit_static(app)


class Setup(BaseModel):
    code: str = Field(max_length=64)
    password: str = Field(max_length=256)


class Login(BaseModel):
    password: str = Field(max_length=256)


class Unlock(BaseModel):
    password: str = Field(max_length=256)


class NoteIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(default="", max_length=5000)
    private: bool = False


def start_session(conn, request: Request, response: Response) -> None:
    raw = local.create_session(conn)
    response.set_cookie(COOKIE, raw, httponly=True, samesite="strict", secure=is_https(request), max_age=12 * 3600, path="/")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": __version__}


@app.get("/readyz")
def readyz():
    try:
        with db.connect(retries=1) as conn:
            conn.execute("SELECT 1")
        return {"status": "ready"}
    except Exception:  # noqa: BLE001 - never echo connection details
        return JSONResponse({"status": "waking-database"}, status_code=503)


@app.get("/")
def index():
    return FileResponse(HERE / "static" / "index.html")


@app.get("/api/session")
def session_state(request: Request):
    principal = auth.authenticate(request)
    with db.connect(retries=1) as conn:
        setup = local.needs_setup(conn) and not fed.enabled
        vault_status = vault.status(conn)
    out = {"state": "setup_required" if setup else "logged_in" if principal else "logged_out",
           "password_login": True, "key_login": local.static_key_configured(),
           "sso": None, "vault": vault_status, "version": __version__}
    if principal:
        out["user"] = {"name": principal.name, "roles": sorted(principal.roles),
                       "permissions": ["*"] if "*" in principal.permissions else sorted(principal.permissions)}
    return out


@app.post("/api/setup")
def setup(body: Setup, request: Request, response: Response):
    with db.connect(retries=1) as conn:
        try:
            local.complete_setup(conn, body.code, body.password)
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        start_session(conn, request, response)
    return {"ok": True}


@app.post("/api/login")
def login(body: Login, request: Request, response: Response):
    if auth.limiter.limited(auth.client(request)):
        raise HTTPException(429, "too many failed attempts; wait a minute")
    with db.connect(retries=1) as conn:
        if not local.login_password(conn, body.password):
            auth.limiter.record(auth.client(request))
            raise HTTPException(401, "invalid credentials")
        start_session(conn, request, response)
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    with db.connect(retries=1) as conn:
        local.delete_session(conn, request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.post("/api/vault/unlock", dependencies=[Depends(auth.require("*"))])
def unlock(body: Unlock):
    with db.connect(retries=1) as conn:
        if not vault.unlock_with_password(conn, body.password):
            raise HTTPException(403, "wrong password")
        conn.commit()
    return {"ok": True}


@app.get("/api/notes")
def list_notes(who=Depends(auth.require("notes:read"))):
    with db.connect() as conn:
        rows = conn.execute("SELECT id, title, body, private, author, created_at FROM note ORDER BY id DESC").fetchall()
    for r in rows:
        if r["private"]:
            try:
                r["body"] = vault.decrypt(r["body"])
            except VaultError:                         # VaultLocked is one: the UI shows "locked" and the unlock banner
                r["body"] = None
    return rows


@app.post("/api/notes")
def add_note(body: NoteIn, who=Depends(auth.require("notes:write"))):
    try:
        text = vault.encrypt(body.body) if body.private else body.body
    except VaultLocked as exc:
        raise HTTPException(423, str(exc)) from exc
    with db.connect() as conn:
        row = conn.execute("INSERT INTO note (title, body, private, author) VALUES (%s,%s,%s,%s) RETURNING id",
                           (body.title.strip(), text, body.private, who.actor)).fetchone()
        conn.commit()
    return {"id": row["id"]}


@app.delete("/api/notes/{note_id}", dependencies=[Depends(auth.require("notes:write"))])
def delete_note(note_id: int):
    with db.connect() as conn:
        gone = conn.execute("DELETE FROM note WHERE id=%s RETURNING id", (note_id,)).fetchone()
        conn.commit()
    if not gone:
        raise HTTPException(404, "no such note")
    return {"ok": True}


@app.post("/api/tokens", dependencies=[Depends(auth.require("*"))])
def create_token(name: str = "cli", scope: str = "read"):
    try:
        with db.connect() as conn:
            token_id, raw = local.create_token(conn, name, scope)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"id": token_id, "token": raw, "scope": scope}


@app.get("/metrics", dependencies=[Depends(auth.require("*"))])
def prometheus():
    body, ctype = metrics.render()
    return Response(body, media_type=ctype)


def serve() -> None:
    import os

    import uvicorn
    uvicorn.run("notes.app:app", host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")),
                proxy_headers=True, forwarded_allow_ips="*")
