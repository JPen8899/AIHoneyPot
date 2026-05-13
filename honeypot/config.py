"""Load operator config (dashboard users, geoip toggle, etc.) from YAML."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class DashboardUser:
    username: str
    password: str  # plaintext; restrict file perms instead


@dataclass
class DashboardConfig:
    secret_key: str
    session_max_age: int = 43200
    users: list[DashboardUser] = field(default_factory=list)
    auth_enabled: bool = True


@dataclass
class GeoIPConfig:
    enabled: bool = True
    timeout: float = 2.5
    endpoint: str = (
        "http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
        "region,regionName,city,lat,lon,isp,org,as,query"
    )


@dataclass
class AppConfig:
    dashboard: DashboardConfig
    geoip: GeoIPConfig
    source_path: str | None = None


def _resolve_path(explicit: str | None) -> Path | None:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    env_path = os.environ.get("HONEYPOT_CONFIG")
    if env_path:
        candidates.append(env_path)
    candidates += [
        "/data/config.yaml",
        str(Path(__file__).resolve().parent.parent / "config.yaml"),
        "/app/config.yaml",
    ]
    for c in candidates:
        if c and Path(c).is_file():
            return Path(c)
    return None


def load(path: str | None = None) -> AppConfig:
    src = _resolve_path(path)
    data: dict = {}
    if src is not None:
        with src.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

    dash_raw = (data.get("dashboard") or {})
    users_raw = dash_raw.get("users") or []
    users: list[DashboardUser] = []
    for u in users_raw:
        if not isinstance(u, dict):
            continue
        un = str(u.get("username") or "").strip()
        pw = str(u.get("password") or "")
        if un and pw:
            users.append(DashboardUser(username=un, password=pw))

    secret_key = dash_raw.get("secret_key")
    if not secret_key:
        secret_key = os.environ.get("HONEYPOT_SECRET_KEY") or secrets.token_urlsafe(48)

    dashboard = DashboardConfig(
        secret_key=str(secret_key),
        session_max_age=int(dash_raw.get("session_max_age") or 43200),
        users=users,
        auth_enabled=bool(dash_raw.get("auth_enabled", True)),
    )

    geo_raw = (data.get("geoip") or {})
    geoip = GeoIPConfig(
        enabled=bool(geo_raw.get("enabled", True)),
        timeout=float(geo_raw.get("timeout", 2.5)),
        endpoint=str(geo_raw.get("endpoint") or GeoIPConfig.endpoint),
    )

    return AppConfig(
        dashboard=dashboard,
        geoip=geoip,
        source_path=str(src) if src else None,
    )
