"""JSONL session logger that also publishes to the dashboard event bus."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import Any

from .event_bus import EventBus


class SessionLogger:
    def __init__(self, path: str, bus: EventBus | None = None):
        self.path = path
        self.bus = bus
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._fh = open(path, "a", buffering=1, encoding="utf-8")

    def log(self, event: str, **fields: Any) -> None:
        record = {"ts": time.time(), "event": event, **fields}
        line = json.dumps(record, default=str, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
        print(line, file=sys.stdout, flush=True)
        if self.bus is not None:
            self.bus.publish(record)

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass
