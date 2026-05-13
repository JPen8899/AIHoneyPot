"""Dashboard operator authentication.

Mythic-c2-style: usernames + passwords come from `config.yaml`. Successful
logins set a signed session cookie via Starlette's SessionMiddleware.
"""
from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse

from .config import DashboardConfig


def verify_credentials(cfg: DashboardConfig, username: str, password: str) -> bool:
    if not username or not password:
        return False
    # Walk every configured user so timing doesn't leak which usernames exist.
    matched = False
    for u in cfg.users:
        if hmac.compare_digest(u.username, username) and hmac.compare_digest(
            u.password, password
        ):
            matched = True
    return matched


def current_user(request: Request, cfg: DashboardConfig) -> str | None:
    if not cfg.auth_enabled:
        return "anonymous"
    sess = getattr(request, "session", None)
    if not sess:
        return None
    return sess.get("user")


def require_user_http(request: Request, cfg: DashboardConfig) -> str:
    """Use for API endpoints — raises 401."""
    user = current_user(request, cfg)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="auth required")
    return user


def redirect_if_unauthed(request: Request, cfg: DashboardConfig) -> RedirectResponse | None:
    """Use for HTML page routes — redirects to /login when missing."""
    if current_user(request, cfg) is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return None
