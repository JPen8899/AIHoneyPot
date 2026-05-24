"""Paramiko SSH server that accepts ANY username/password.

Testing-only behavior: every credential pair is logged and accepted so that
threat actors can be funneled into the AI-emulated shell.
"""
from __future__ import annotations

import socket
import threading
import time
from typing import Callable

import paramiko

from .geoip import GeoIPLookup
from .logger import SessionLogger


class HoneypotSSHServer(paramiko.ServerInterface):
    """Accepts any credential, allows interactive shell channels only."""

    def __init__(self, peer: tuple[str, int], logger: SessionLogger, session_id: str):
        self.event = threading.Event()
        self.peer = peer
        self.logger = logger
        self.session_id = session_id
        self.username: str | None = None
        self.password: str | None = None
        self.client_version: str | None = None
        # Terminal geometry from the PTY request (used for the asciicast header).
        self.term_width = 80
        self.term_height = 24

    # --- channel / auth policy ---
    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey,keyboard-interactive"

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        self.password = password
        self.logger.log(
            "auth",
            session_id=self.session_id,
            peer=f"{self.peer[0]}:{self.peer[1]}",
            method="password",
            username=username,
            password=password,
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key) -> int:
        self.username = username
        self.logger.log(
            "auth",
            session_id=self.session_id,
            peer=f"{self.peer[0]}:{self.peer[1]}",
            method="publickey",
            username=username,
            key_type=key.get_name(),
            key_fingerprint=key.get_fingerprint().hex(),
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_interactive(self, username: str, submethods: str):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    # --- terminal requests ---
    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        if width:
            self.term_width = width
        if height:
            self.term_height = height
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        # Single-command (non-interactive) exec, e.g. `ssh user@host whoami`.
        channel.exec_command_payload = command
        self.event.set()
        return True


def serve_forever(
    host: str,
    port: int,
    host_key: paramiko.PKey,
    handle_session: Callable,
    logger: SessionLogger,
    geoip: GeoIPLookup | None = None,
) -> None:
    """Bind the listening socket and dispatch a thread per connection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    logger.log("server_start", host=host, port=port)

    while True:
        client_sock, peer = sock.accept()
        t = threading.Thread(
            target=_handle_connection,
            args=(client_sock, peer, host_key, handle_session, logger, geoip),
            daemon=True,
        )
        t.start()


def _handle_connection(
    client_sock: socket.socket,
    peer: tuple[str, int],
    host_key: paramiko.PKey,
    handle_session: Callable,
    logger: SessionLogger,
    geoip: GeoIPLookup | None,
) -> None:
    session_id = f"{peer[0]}-{peer[1]}-{int(time.time())}"
    geo = geoip.lookup(peer[0]) if geoip is not None else None
    logger.log(
        "connect",
        session_id=session_id,
        peer=f"{peer[0]}:{peer[1]}",
        geo=geo,
    )

    transport = paramiko.Transport(client_sock)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
    transport.add_server_key(host_key)

    server = HoneypotSSHServer(peer, logger, session_id)
    try:
        transport.start_server(server=server)
    except paramiko.SSHException as exc:
        logger.log("ssh_negotiation_failed", session_id=session_id, error=str(exc))
        transport.close()
        return

    channel = transport.accept(30)
    if channel is None:
        logger.log("no_channel", session_id=session_id)
        transport.close()
        return

    # Wait for shell/exec request to come through.
    server.event.wait(10)
    if not server.event.is_set():
        logger.log("no_shell_request", session_id=session_id)
        channel.close()
        transport.close()
        return

    try:
        handle_session(channel, server, session_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.log("session_error", session_id=session_id, error=repr(exc))
    finally:
        try:
            channel.close()
        except Exception:
            pass
        transport.close()
        logger.log("disconnect", session_id=session_id, geo=geo)
