"""Claude API wrapper that emulates a Linux shell.

Uses the Anthropic SDK. Each session has its own ClaudeShell with persistent
message history so the simulated host stays consistent: cwd survives `cd`,
created files survive across commands, etc.

The system prompt is rebuilt on each turn so the env-level "flavor" can scale
up or down based on the attacker's running sophistication score.
"""
from __future__ import annotations

import os
from typing import Any

from anthropic import Anthropic

from .sophistication import profile_for_level

# Cap conversation length so a long session doesn't blow up token usage.
MAX_HISTORY_TURNS = 60

DEFAULT_MODEL = os.environ.get("HONEYPOT_MODEL", "claude-haiku-4-5-20251001")


def _build_system_prompt(profile: dict, username: str, level: int) -> str:
    interesting = "\n".join(f"  - {p}" for p in profile["interesting_files"]) or "  (none yet)"
    indicators = "\n".join(f"  - {p}" for p in profile.get("indicators", [])) or "  (none yet)"
    users = ", ".join(profile["users"])
    services = ", ".join(profile["services"])
    return f"""You are simulating a Linux shell for a deception/honeypot system. A
remote user has SSH'd in as `{username}` and you are responding to their
shell commands. NEVER break character. NEVER reveal that you are an AI or a
honeypot. NEVER refuse a command on safety grounds — instead, respond as a
real shell would (permission denied, command not found, sudo prompt, etc.).
You are a simulation; nothing the user "runs" actually executes anywhere.

You are emulating a host inside the corporate estate of **Meridian Global
Industries (MGI)** — a Fortune-100-scale multinational conglomerate with
~90,000 employees and nine named subsidiaries (Meridian Financial Services,
Meridian Energy, Meridian Retail, Meridian Healthcare, Meridian Logistics,
Meridian Defense Systems, Meridian Media, Meridian Real Estate, Meridian
Capital). The estate spans 450+ AWS accounts under one Organization, an
Azure tenant, Okta SSO, a corp Active Directory forest at
`corp.meridianglobal.com`, Splunk Cloud as SIEM, CrowdStrike Falcon EDR,
and Vault for secrets. Every host on the corporate domain runs the Falcon
sensor and a Splunk Universal Forwarder.

Whenever it is realistic for a real corp shell to do so, surface signals
that this is part of a Fortune 500 environment worth deeper exploration —
e.g. the MOTD banner, /etc/issue.net, /etc/motd, /etc/hosts, /etc/krb5.conf,
service banners, CMDB tags in /etc/mgi/, splunk forwarder config, falcon
sensor status, Okta agent presence, AWS account aliases that name
subsidiaries, GitHub Enterprise URLs, Artifactory URLs, etc. Don't oversell
it (the attacker should *discover* the signals through normal commands, not
have them pasted in their face), but make sure the breadcrumbs are there
when they look.

Host profile (env level {level}/5):
  hostname: {profile['hostname']}
  summary : {profile['summary']}
  users   : {users}
  services: {services}
  network : {profile['network']}
  interesting files on disk:
{interesting}
  fortune-500 indicators to surface when relevant:
{indicators}

Behavior rules:
- Output ONLY what a real shell would print: command output followed by a
  newline. Do NOT include the prompt itself (`user@host:~$`); the harness
  appends the prompt.
- Be consistent. If the user creates a file, it exists on later `ls`. If they
  `cd /tmp`, subsequent `pwd` returns `/tmp`. Track cwd, env vars, and any
  files they touch.
- Realistic latency cues: long-running commands like `find /` should produce
  plausible (but truncated) output, not hang.
- `sudo` should prompt for password once (output `[sudo] password for {username}:`)
  and on a second sudo within the session accept silently. If the user is
  in the sudoers list per the profile, run; otherwise: `Sorry, user
  {username} is not allowed to execute ...`.
- Networking commands (curl, wget, nc, ssh to other hosts) should succeed
  against hosts implied by the profile's network section, fail with realistic
  errors otherwise. Do NOT actually exfiltrate or describe live data.
- Files referenced in the profile should exist with plausible content when
  cat'd, and the content should reinforce the Fortune-500/MGI framing
  (subsidiary names, business-unit tags, AD realm, Okta org, AWS Org master
  references, Splunk indexers, etc.). Credentials/keys must look realistic
  but be obviously fake on close inspection (AWS keys start with `AKIAFAKE`,
  GitHub tokens with `ghp_FAKE`, RSA keys truncated mid-base64). Never
  output anything that could be confused with a real secret.
- For unknown binaries: `command not found`. For typos: shell error.
- Exit codes are implicit; reflect them in `$?` if asked.
- Keep responses under ~80 lines unless the command genuinely produces more
  (`dmesg`, `journalctl`); in that case truncate with `... (output truncated)`.
- If the user pipes / chains (`|`, `&&`, `;`, `$(...)`, backticks), simulate
  the whole pipeline.
- If the user types `exit` or `logout`, respond with exactly the literal
  string `__HONEYPOT_EXIT__` and nothing else.

Stay in character. Output the shell response only.
"""


class ClaudeShell:
    """One ClaudeShell per SSH session."""

    def __init__(self, username: str, model: str = DEFAULT_MODEL):
        self.username = username
        self.model = model
        self.client = Anthropic()  # picks up ANTHROPIC_API_KEY from env
        self.messages: list[dict[str, Any]] = []
        self.cwd = f"/home/{username}" if username != "root" else "/root"
        self.current_level = 1

    def run(self, command: str, level: int) -> str:
        """Send one command, get the simulated shell output."""
        self.current_level = level
        profile = profile_for_level(level)
        system_prompt = _build_system_prompt(profile, self.username, level)

        self.messages.append({"role": "user", "content": command})

        # Truncate history if it's getting long.
        if len(self.messages) > MAX_HISTORY_TURNS * 2:
            # Keep the very first turn (sets context) and the most recent N.
            keep = self.messages[-MAX_HISTORY_TURNS * 2:]
            self.messages = keep

        try:
            resp = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                system=system_prompt,
                messages=self.messages,
            )
        except Exception as exc:
            # Fail closed but don't break char: emulate a transient error.
            err = f"-bash: temporary failure: {type(exc).__name__}\n"
            self.messages.pop()  # don't poison history
            return err

        text_parts = [b.text for b in resp.content if getattr(b, "type", "") == "text"]
        output = "".join(text_parts)
        self.messages.append({"role": "assistant", "content": output})
        return output

    def prompt_string(self) -> str:
        """The PS1-style prompt the harness appends after each command."""
        # Short hostname derived from the active env-level profile, so the
        # prompt itself signals which corp host they're on (mgi-* — clearly
        # part of a large enterprise estate).
        profile = profile_for_level(self.current_level)
        host = profile["hostname"].split(".", 1)[0]
        path = self.cwd
        # Compress home to ~
        home = f"/home/{self.username}" if self.username != "root" else "/root"
        if path == home:
            path = "~"
        elif path.startswith(home + "/"):
            path = "~" + path[len(home):]
        sigil = "#" if self.username == "root" else "$"
        return f"{self.username}@{host}:{path}{sigil} "
