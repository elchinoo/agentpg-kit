"""Small helpers every FastAPI app in the fleet needs."""
import os

from fastapi import Request


def is_https(request: Request) -> bool:
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https"


def public_url(request: Request, env: str | None = None) -> str:
    """The URL this app is reached at: the configured one (`env`), else the request's own address. AgentPG terminates TLS in
    front of the sandbox, so the forwarded protocol is honoured."""
    if env and os.environ.get(env):
        return os.environ[env].rstrip("/")
    proto = "https" if is_https(request) else request.url.scheme
    return f"{proto}://{request.headers.get('host') or request.url.netloc}"


def mount_kit_static(app) -> None:
    """Serve the shared UI kit (base.css, ui.js, api.js, session.js, logos) under /kit/."""
    from pathlib import Path

    from fastapi.staticfiles import StaticFiles
    app.mount("/kit", StaticFiles(directory=Path(__file__).resolve().parent / "static"), name="kit")
