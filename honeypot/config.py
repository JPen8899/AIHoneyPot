"""Load honeypot config (currently just the geoip toggle) from YAML.

Config is optional: if no `config.yaml` is found (next to the package, at
`/data/config.yaml`, `/app/config.yaml`, or `$HONEYPOT_CONFIG`), sensible
defaults are used.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml


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

    geo_raw = (data.get("geoip") or {})
    geoip = GeoIPConfig(
        enabled=bool(geo_raw.get("enabled", True)),
        timeout=float(geo_raw.get("timeout", 2.5)),
        endpoint=str(geo_raw.get("endpoint") or GeoIPConfig.endpoint),
    )

    return AppConfig(
        geoip=geoip,
        source_path=str(src) if src else None,
    )
