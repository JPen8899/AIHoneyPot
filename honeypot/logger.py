"""JSONL session logger that also publishes to the dashboard event bus.

The JSONL file is the structured source of truth. Optionally, command events are
also appended to a flat CSV (`commands.csv`) for quick tabular analysis — one
row per command, joinable back to the JSONL on `session_id`.
"""
from __future__ import annotations

import csv
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any

from .event_bus import EventBus

_CSV_COLUMNS = ["ts", "iso", "session_id", "tier", "score", "level", "command"]


class SessionLogger:
    def __init__(self, path: str, bus: EventBus | None = None, csv_path: str | None = None):
        self.path = path
        self.bus = bus
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._fh = open(path, "a", buffering=1, encoding="utf-8")

        # Optional per-command CSV sink (shares the lock so writes stay serialized).
        self._csv_fh = None
        self._csv = None
        if csv_path:
            os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
            fresh = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
            self._csv_fh = open(csv_path, "a", buffering=1, encoding="utf-8", newline="")
            self._csv = csv.writer(self._csv_fh)
            if fresh:
                self._csv.writerow(_CSV_COLUMNS)

    def log(self, event: str, **fields: Any) -> None:
        record = {"ts": time.time(), "event": event, **fields}
        line = json.dumps(record, default=str, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
            if self._csv is not None and event == "command":
                self._csv.writerow([
                    record["ts"],
                    datetime.fromtimestamp(record["ts"], timezone.utc).isoformat(),
                    fields.get("session_id", ""),
                    fields.get("tier", ""),
                    fields.get("score", ""),
                    fields.get("level", ""),
                    fields.get("command", ""),
                ])
        print(line, file=sys.stdout, flush=True)
        if self.bus is not None:
            self.bus.publish(record)

    def close(self) -> None:
        for fh in (self._fh, self._csv_fh):
            try:
                if fh is not None:
                    fh.close()
            except Exception:
                pass
