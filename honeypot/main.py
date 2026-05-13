"""Entrypoint: starts the SSH honeypot and the dashboard side-by-side."""
from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import paramiko

from .config import load as load_config
from .dashboard import run_dashboard
from .event_bus import EventBus
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
    if cfg.dashboard.auth_enabled and not cfg.dashboard.users:
        print(
            "[honeypot] WARNING: dashboard auth is enabled but no users are defined "
            "in config.yaml — the dashboard will reject every login. Copy "
            "config.yaml.example to config.yaml and add at least one user.",
            file=sys.stderr,
        )
    elif not cfg.dashboard.auth_enabled:
        print(
            "[honeypot] WARNING: dashboard auth is DISABLED — bind it to localhost "
            "or behind a reverse proxy.",
            file=sys.stderr,
        )

    ssh_host = os.environ.get("HONEYPOT_SSH_HOST", "0.0.0.0")
    ssh_port = int(os.environ.get("HONEYPOT_SSH_PORT", "22"))
    ui_host = os.environ.get("HONEYPOT_UI_HOST", "0.0.0.0")
    ui_port = int(os.environ.get("HONEYPOT_UI_PORT", "8080"))
    log_path = os.environ.get("HONEYPOT_LOG_PATH", "/data/logs/sessions.jsonl")
    host_key_path = os.environ.get("HONEYPOT_HOST_KEY", "/data/host_rsa.key")

    bus = EventBus()
    logger = SessionLogger(log_path, bus=bus)
    geoip = GeoIPLookup(cfg.geoip)
    host_key = _load_or_create_host_key(host_key_path)

    def _session_handler(channel, server, session_id):
        run_session(channel, server, session_id, logger)

    def _ssh_thread():
        serve_forever(
            host=ssh_host,
            port=ssh_port,
            host_key=host_key,
            handle_session=_session_handler,
            logger=logger,
            geoip=geoip,
        )

    t = threading.Thread(target=_ssh_thread, daemon=True, name="ssh-server")
    t.start()

    # Dashboard runs in the main thread (uvicorn manages its own loop).
    run_dashboard(bus, cfg, host=ui_host, port=ui_port)


if __name__ == "__main__":
    main()
