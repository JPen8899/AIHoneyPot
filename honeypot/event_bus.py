"""Thread <-> asyncio event bus.

The SSH server runs in OS threads (one per connection) while the dashboard
runs on an asyncio event loop. Sessions push events from threads via
`publish()`; the dashboard consumes via `subscribe()`-returned async queues.

Also retains a bounded history so newly-connected dashboard clients can
backfill the recent event stream, and aggregates geolocation stats so the
map view can render without re-walking the full event log.
"""
from __future__ import annotations

import asyncio
import threading
from collections import deque
from typing import Any


class EventBus:
    def __init__(self, history: int = 500):
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subs: list[asyncio.Queue] = []
        self._lock = threading.Lock()
        self._history: deque[dict[str, Any]] = deque(maxlen=history)
        self._sessions: dict[str, dict[str, Any]] = {}
        # Aggregate geo stats keyed by IP, used by the map view.
        self._geo_by_ip: dict[str, dict[str, Any]] = {}

    # --- lifecycle ---
    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    # --- subscriptions (asyncio side) ---
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def history_snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._history)

    def sessions_snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {sid: dict(data) for sid, data in self._sessions.items()}

    def geo_snapshot(self) -> dict[str, Any]:
        with self._lock:
            ips = [dict(v) for v in self._geo_by_ip.values()]
        countries: dict[str, int] = {}
        cities: dict[str, int] = {}
        for entry in ips:
            if entry.get("private"):
                key = "Private/RFC1918"
            else:
                key = entry.get("country") or "Unknown"
            countries[key] = countries.get(key, 0) + int(entry.get("hits", 1))
            city = entry.get("city")
            if city:
                ck = f"{city}, {entry.get('country_code') or '??'}"
                cities[ck] = cities.get(ck, 0) + int(entry.get("hits", 1))
        return {
            "ips": ips,
            "countries": sorted(countries.items(), key=lambda kv: kv[1], reverse=True),
            "cities": sorted(cities.items(), key=lambda kv: kv[1], reverse=True)[:25],
        }

    # --- publishing (thread side) ---
    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._history.append(event)
            self._update_session_state(event)
            self._update_geo_stats(event)
            subs = list(self._subs)
            loop = self._loop
        if loop is None:
            return
        for q in subs:
            try:
                loop.call_soon_threadsafe(_safe_put, q, event)
            except RuntimeError:
                # Loop is closing.
                pass

    # --- session bookkeeping for the dashboard table ---
    def _update_session_state(self, event: dict[str, Any]) -> None:
        sid = event.get("session_id")
        if not sid:
            return
        ev = event.get("event")
        s = self._sessions.setdefault(
            sid,
            {
                "session_id": sid,
                "peer": event.get("peer"),
                "username": None,
                "started_at": event.get("ts"),
                "last_event_at": event.get("ts"),
                "command_count": 0,
                "score": 0,
                "level": 1,
                "last_command": None,
                "last_tier": 0,
                "active": True,
                "geo": None,
            },
        )
        if event.get("peer"):
            s["peer"] = event["peer"]
        if event.get("geo"):
            s["geo"] = event["geo"]
        s["last_event_at"] = event.get("ts", s["last_event_at"])

        if ev == "auth":
            s["username"] = event.get("username") or s["username"]
        elif ev == "command":
            s["command_count"] += 1
            s["last_command"] = event.get("command")
            s["score"] = event.get("score", s["score"])
            s["level"] = event.get("level", s["level"])
            s["last_tier"] = event.get("tier", 0)
        elif ev == "disconnect":
            s["active"] = False

    def _update_geo_stats(self, event: dict[str, Any]) -> None:
        if event.get("event") != "connect":
            return
        geo = event.get("geo")
        if not geo:
            return
        ip = geo.get("ip")
        if not ip:
            return
        entry = self._geo_by_ip.setdefault(ip, {**geo, "hits": 0, "first_seen": event.get("ts")})
        entry["hits"] = int(entry.get("hits", 0)) + 1
        entry["last_seen"] = event.get("ts")


def _safe_put(q: asyncio.Queue, event: dict[str, Any]) -> None:
    try:
        q.put_nowait(event)
    except asyncio.QueueFull:
        # Drop oldest, then enqueue.
        try:
            q.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass
