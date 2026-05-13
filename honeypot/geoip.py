"""IP geolocation for source IPs of inbound SSH connections.

Uses ip-api.com's free endpoint with in-memory caching. Private / loopback /
link-local addresses are short-circuited so we don't waste lookups (or leak
internal addressing to a third party).
"""
from __future__ import annotations

import ipaddress
import json
import threading
import urllib.request
from typing import Any
from urllib.error import URLError

from .config import GeoIPConfig


class GeoIPLookup:
    def __init__(self, cfg: GeoIPConfig):
        self.cfg = cfg
        self._cache: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def lookup(self, ip: str) -> dict[str, Any] | None:
        """Best-effort geolocate. Returns None when disabled, private, or failed."""
        if not self.cfg.enabled or not ip:
            return None

        with self._lock:
            cached = self._cache.get(ip)
        if cached is not None:
            return cached

        if _is_private(ip):
            entry = {
                "ip": ip,
                "country": "Private",
                "country_code": "ZZ",
                "city": None,
                "region": None,
                "lat": None,
                "lon": None,
                "isp": None,
                "org": None,
                "as": None,
                "private": True,
            }
            with self._lock:
                self._cache[ip] = entry
            return entry

        url = self.cfg.endpoint.format(ip=ip)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ai-honeypot/1.0"})
            with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
        except (URLError, TimeoutError, ValueError, OSError):
            return None

        if data.get("status") != "success":
            return None

        entry = {
            "ip": ip,
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName") or data.get("region"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "private": False,
        }
        with self._lock:
            self._cache[ip] = entry
        return entry


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )
