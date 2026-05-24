"""Per-session activity recording: human-readable transcript + asciinema cast.

The JSONL log (`logger.py`) stays the structured source of truth. On top of it,
each SSH session produces two human-facing review artifacts:

  data/logs/transcripts/<session_id>.log   readable command/response transcript
  data/logs/casts/<session_id>.cast        asciicast v2 — replay with
                                            `asciinema play <file>` (or the web player)

Both are written incrementally and line-buffered, so a killed/crashed session
still leaves a valid, partial recording. Wrap the SSH channel in
`RecordingChannel` so every byte sent to the attacker is teed into the cast
without touching the session loop's send sites.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _hms(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")


def _safe(name: str) -> str:
    """Filesystem-safe session id."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "session"


class SessionRecorder:
    """Writes one transcript (.log) and one asciicast (.cast) per session."""

    def __init__(
        self,
        session_id: str,
        base_dir: str,
        *,
        width: int = 80,
        height: int = 24,
        enabled: bool = True,
    ):
        self.session_id = session_id
        self.start = time.time()
        self._mono = time.monotonic()
        self._tfh = None  # transcript file handle
        self._cfh = None  # cast file handle
        if not enabled:
            return
        safe = _safe(session_id)
        try:
            tdir = os.path.join(base_dir, "transcripts")
            cdir = os.path.join(base_dir, "casts")
            os.makedirs(tdir, exist_ok=True)
            os.makedirs(cdir, exist_ok=True)
            self._tfh = open(os.path.join(tdir, f"{safe}.log"), "a", buffering=1, encoding="utf-8")
            self._cfh = open(os.path.join(cdir, f"{safe}.cast"), "a", buffering=1, encoding="utf-8")
        except OSError:
            # Recording is best-effort; never break the session over it.
            self._tfh = self._cfh = None
            return
        header = {
            "version": 2,
            "width": int(width) or 80,
            "height": int(height) or 24,
            "timestamp": int(self.start),
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
            "title": f"honeypot session {session_id}",
        }
        self._safe_write(self._cfh, json.dumps(header) + "\n")

    # --- header / events ---
    def set_header(
        self,
        *,
        peer: str | None = None,
        username: str | None = None,
        client_version: str | None = None,
        company: str | None = None,
    ) -> None:
        if not self._tfh:
            return
        bar = "=" * 80
        lines = [
            bar,
            " AI Honeypot — session transcript",
            f" session : {self.session_id}",
            f" started : {_utc(self.start)}",
            f" peer    : {peer or '?'}",
            f" client  : {client_version or '?'}",
            f" user    : {username or '?'}",
            f" company : {company or '?'}",
            bar,
            "",
        ]
        self._safe_write(self._tfh, "\n".join(lines) + "\n")

    def feed_output(self, data) -> None:
        """Record one chunk of terminal output (asciicast 'o' event)."""
        if not self._cfh:
            return
        text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
        elapsed = round(time.monotonic() - self._mono, 6)
        self._safe_write(self._cfh, json.dumps([elapsed, "o", text]) + "\n")

    def record_command(self, cmd: str, tier: int, score: int, level: int) -> None:
        if not self._tfh:
            return
        self._safe_write(
            self._tfh,
            f"[{_hms(time.time())}] $ {cmd}    (tier {tier}, score {score}, L{level})\n",
        )

    def record_response(self, output: str) -> None:
        if not self._tfh:
            return
        text = output if output.endswith("\n") else output + "\n"
        self._safe_write(self._tfh, text + "\n")

    def close(self, reason: str | None = None) -> None:
        if self._tfh:
            tail = f"--- session ended {_utc(time.time())}"
            tail += f" (reason: {reason})" if reason else ""
            tail += " ---\n"
            self._safe_write(self._tfh, tail)
            self._close(self._tfh)
            self._tfh = None
        if self._cfh:
            self._close(self._cfh)
            self._cfh = None

    # --- internals ---
    @staticmethod
    def _safe_write(fh, text: str) -> None:
        try:
            fh.write(text)
        except (OSError, ValueError):
            pass

    @staticmethod
    def _close(fh) -> None:
        try:
            fh.close()
        except OSError:
            pass


class RecordingChannel:
    """Transparent proxy around a paramiko channel that tees `send` to a recorder.

    Every byte written to the attacker is captured for the asciicast; all other
    attribute access (recv, close, exec_command_payload, ...) proxies straight
    through to the wrapped channel.
    """

    def __init__(self, channel, recorder: SessionRecorder):
        self._channel = channel
        self._recorder = recorder

    def send(self, data):
        self._recorder.feed_output(data)
        return self._channel.send(data)

    def __getattr__(self, name):
        # Only reached for attributes not defined on this proxy.
        return getattr(self._channel, name)
