"""Per-connection interactive shell loop.

Reads bytes from the SSH channel, assembles them into command lines (handling
backspace and basic line editing), runs each command through ClaudeShell, and
writes the response back. Per-command sophistication scoring updates the env
level so the AI environment scales up/down between commands.
"""
from __future__ import annotations

from .claude_shell import ClaudeShell
from .company import Company
from .logger import SessionLogger
from .sophistication import SophisticationTracker

EXIT_SENTINEL = "__HONEYPOT_EXIT__"


_BANNER_W = 75  # inner content width; box border is _BANNER_W + 4 (= "# " + text + " #")


def _banner(c: Company) -> str:
    """Per-session login banner, themed to the session's company persona."""
    dom = c.corp_domain
    border = "#" * (_BANNER_W + 4)

    def row(text: str) -> str:
        # Truncate defensively so an unusually long company/domain never breaks
        # the box border.
        if len(text) > _BANNER_W:
            text = text[: _BANNER_W - 1] + "…"
        return f"# {text:<{_BANNER_W}} #\r\n"

    return (
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        "\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n"
        "\r\n"
        + border + "\r\n"
        + row(f"{c.name} — Corporate Infrastructure")
        + row("Authorized use only. Monitored by CrowdStrike Falcon; all sessions")
        + row("are logged to the corporate Splunk SIEM:")
        + row(f"  splunk-search.{dom}")
        + row("Misuse will be reported to Corporate Security and may be prosecuted.")
        + row("")
        + row(f"CMDB: cmdb.{dom}   |   SSO: {c.okta_org}")
        + border + "\r\n"
        "\r\n"
        f"Last login: Mon Apr 28 09:14:22 2026 from 10.10.4.117 (vpn-east.{dom})\r\n"
    )


def handle_session(channel, server, session_id: str, logger: SessionLogger) -> None:
    username = server.username or "user"
    tracker = SophisticationTracker()
    shell = ClaudeShell(username=username)

    logger.log(
        "session_start",
        session_id=session_id,
        username=username,
        peer=f"{server.peer[0]}:{server.peer[1]}",
        client_version=server.client_version,
        company=shell.company.name,
        company_slug=shell.company.slug,
    )

    # Non-interactive `ssh user@host <cmd>` path.
    exec_cmd = getattr(channel, "exec_command_payload", None)
    if exec_cmd is not None:
        cmd = exec_cmd.decode("utf-8", errors="replace") if isinstance(exec_cmd, bytes) else exec_cmd
        _process_command(channel, shell, tracker, logger, session_id, cmd, interactive=False)
        return

    channel.send(_banner(shell.company).encode())
    channel.send(shell.prompt_string().encode())

    buf = bytearray()
    while True:
        try:
            data = channel.recv(4096)
        except Exception:
            break
        if not data:
            break

        for byte in data:
            b = bytes([byte])

            # Ctrl-C -> abort current line
            if b == b"\x03":
                channel.send(b"^C\r\n")
                buf.clear()
                channel.send(shell.prompt_string().encode())
                continue

            # Ctrl-D on empty line -> exit
            if b == b"\x04" and not buf:
                channel.send(b"logout\r\n")
                logger.log("logout", session_id=session_id, reason="ctrl-d")
                return

            # Backspace / delete
            if b in (b"\x7f", b"\x08"):
                if buf:
                    buf.pop()
                    channel.send(b"\b \b")
                continue

            # Line ending
            if b in (b"\r", b"\n"):
                channel.send(b"\r\n")
                cmd = buf.decode("utf-8", errors="replace").rstrip()
                buf.clear()
                if cmd == "":
                    channel.send(shell.prompt_string().encode())
                    continue

                done = _process_command(
                    channel, shell, tracker, logger, session_id, cmd, interactive=True
                )
                if done:
                    return
                channel.send(shell.prompt_string().encode())
                continue

            # Ignore other control chars
            if byte < 0x20:
                continue

            buf.append(byte)
            channel.send(b)  # local echo


def _process_command(
    channel,
    shell: ClaudeShell,
    tracker: SophisticationTracker,
    logger: SessionLogger,
    session_id: str,
    cmd: str,
    interactive: bool,
) -> bool:
    """Returns True if the session should terminate."""
    tier = tracker.observe(cmd)
    snap = tracker.snapshot()

    logger.log(
        "command",
        session_id=session_id,
        command=cmd,
        tier=tier,
        score=snap["score"],
        level=snap["level"],
        counts=snap["counts"],
    )

    output = shell.run(cmd, level=snap["level"])

    if EXIT_SENTINEL in output:
        channel.send(b"logout\r\n")
        logger.log("logout", session_id=session_id, reason="user_exit")
        return True

    # Normalize line endings for the SSH channel.
    out_bytes = output.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", errors="replace")
    if out_bytes and not out_bytes.endswith(b"\r\n"):
        out_bytes += b"\r\n"
    channel.send(out_bytes)

    logger.log(
        "response",
        session_id=session_id,
        command=cmd,
        output_preview=output[:400],
        output_len=len(output),
    )

    return not interactive  # exec mode: one and done
