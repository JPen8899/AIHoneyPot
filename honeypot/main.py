"""Entrypoint: starts the SSH honeypot and the public decoy website.

All activity is written to log files (JSONL + per-command CSV + per-session
transcripts/asciicasts under the log dir) for later review — there is no
operator dashboard.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

import paramiko

from .config import load as load_config
from .decoy_web import serve_decoy_web
from .geoip import GeoIPLookup
from .logger import SessionLogger
from .session import handle_session as run_session
from .ssh_server import serve_forever


def _load_or_create_host_key(path: str) -> paramiko.PKey:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        return paramiko.RSAKey(filename=str(p))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(p))
    return key


def main() -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit(
            "ANTHROPIC_API_KEY is not set. Put it in .env or pass it via the docker-compose env."
        )

    cfg = load_config()

    ssh_host = os.environ.get("HONEYPOT_SSH_HOST", "0.0.0.0")
    ssh_port = int(os.environ.get("HONEYPOT_SSH_PORT", "22"))
    web_host = os.environ.get("HONEYPOT_WEB_HOST", "0.0.0.0")
    web_port = int(os.environ.get("HONEYPOT_WEB_PORT", "80"))
    web_enabled = os.environ.get("HONEYPOT_WEB_ENABLED", "1").lower() not in ("0", "false", "no")
    log_path = os.environ.get("HONEYPOT_LOG_PATH", "/data/logs/sessions.jsonl")
    host_key_path = os.environ.get("HONEYPOT_HOST_KEY", "/data/host_rsa.key")

    # Per-command CSV (for quick tabular analysis) lives beside the JSONL.
    csv_path = os.path.join(os.path.dirname(log_path) or ".", "commands.csv")

    logger = SessionLogger(log_path, csv_path=csv_path)
    geoip = GeoIPLookup(cfg.geoip)
    host_key = _load_or_create_host_key(host_key_path)

    def _session_handler(channel, server, session_id):
        run_session(channel, server, session_id, logger)

    # Public-facing decoy website (bait that funnels scanners toward SSH).
    # Shares the JSONL logger so web recon shows up alongside SSH events.
    if web_enabled:
        web_thread = threading.Thread(
            target=serve_decoy_web,
            args=(web_host, web_port, logger),
            daemon=True,
            name="decoy-web",
        )
        web_thread.start()

    # SSH honeypot runs in the foreground (keeps the process alive).
    serve_forever(
        host=ssh_host,
        port=ssh_port,
        host_key=host_key,
        handle_session=_session_handler,
        logger=logger,
        geoip=geoip,
    )


if __name__ == "__main__":
    main()
