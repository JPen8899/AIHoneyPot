"""FastAPI dashboard for live threat-actor monitoring.

Subscribes to the EventBus over WebSocket and pushes every honeypot event to
the browser as it happens. Operator login (mythic-c2 style) gates every
route — credentials come from config.yaml.
"""
from __future__ import annotations

import asyncio
import html as html_lib
from pathlib import Path

from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from .auth import (
    current_user,
    redirect_if_unauthed,
    require_user_http,
    verify_credentials,
)
from .config import AppConfig
from .event_bus import EventBus

TEMPLATES_DIR = Path(__file__).parent / "templates"


def build_app(bus: EventBus, cfg: AppConfig) -> FastAPI:
    app = FastAPI(title="AI Honeypot Dashboard")
    app.add_middleware(
        SessionMiddleware,
        secret_key=cfg.dashboard.secret_key,
        max_age=cfg.dashboard.session_max_age,
        same_site="lax",
        https_only=False,
        session_cookie="honeypot_session",
    )

    @app.on_event("startup")
    async def _on_start() -> None:
        bus.attach_loop(asyncio.get_running_loop())

    # ---- auth pages ----
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, err: str | None = None) -> HTMLResponse:
        if current_user(request, cfg.dashboard):
            return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        html = (TEMPLATES_DIR / "login.html").read_text(encoding="utf-8")
        err_html = ""
        if err:
            err_html = (
                '<div class="err">Invalid username or password.</div>'
                if err == "1"
                else f'<div class="err">{err}</div>'
            )
        html = html.replace("{{ERROR}}", err_html)
        return HTMLResponse(html)

    @app.post("/login")
    async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ):
        if not cfg.dashboard.auth_enabled:
            return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        if verify_credentials(cfg.dashboard, username, password):
            request.session["user"] = username
            return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse(url="/login?err=1", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    # ---- main page (auth required) ----
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        redir = redirect_if_unauthed(request, cfg.dashboard)
        if redir is not None:
            return redir
        html = (TEMPLATES_DIR / "index.html").read_text(encoding="utf-8")
        user = current_user(request, cfg.dashboard) or ""
        html = html.replace("{{USER}}", html_lib.escape(user, quote=True))
        return HTMLResponse(html)

    @app.get("/api/snapshot")
    async def snapshot(request: Request) -> JSONResponse:
        require_user_http(request, cfg.dashboard)
        return JSONResponse(
            {
                "sessions": list(bus.sessions_snapshot().values()),
                "history": bus.history_snapshot(),
                "geo": bus.geo_snapshot(),
            }
        )

    @app.get("/api/geo")
    async def geo(request: Request) -> JSONResponse:
        require_user_http(request, cfg.dashboard)
        return JSONResponse(bus.geo_snapshot())

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        # Cookie-based auth on the WebSocket handshake.
        if cfg.dashboard.auth_enabled:
            sess = websocket.scope.get("session") or {}
            if not sess.get("user"):
                await websocket.close(code=4401)
                return
        await websocket.accept()
        await websocket.send_json(
            {
                "type": "snapshot",
                "sessions": list(bus.sessions_snapshot().values()),
                "history": bus.history_snapshot(),
                "geo": bus.geo_snapshot(),
            }
        )
        q = bus.subscribe()
        try:
            while True:
                event = await q.get()
                await websocket.send_json({"type": "event", "event": event})
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            bus.unsubscribe(q)

    return app


def run_dashboard(bus: EventBus, cfg: AppConfig, host: str, port: int) -> None:
    import uvicorn

    app = build_app(bus, cfg)
    uvicorn.run(app, host=host, port=port, log_level="warning")
