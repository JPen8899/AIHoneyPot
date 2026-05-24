"""Claude API wrapper that emulates a Linux shell.

Uses the Anthropic SDK. Each session has its own ClaudeShell with persistent
message history so the simulated host stays consistent: cwd survives `cd`,
created files survive across commands, etc.

Each session also adopts a randomly chosen Fortune-100 company persona (see
`company.py`), so the simulated host reads as a specific large enterprise. The
system prompt is rebuilt on each turn so the env-level "flavor" can scale up or
down based on the attacker's running sophistication score.
"""
from __future__ import annotations

import os
from typing import Any

from anthropic import Anthropic

from .company import Company, pick_company
from .sophistication import build_profiles, clamp_level

# Cap conversation length so a long session doesn't blow up token usage.
MAX_HISTORY_TURNS = 60

DEFAULT_MODEL = os.environ.get("HONEYPOT_MODEL", "claude-haiku-4-5-20251001")


def _build_system_prompt(profile: dict, username: str, level: int, c: Company) -> str:
    interesting = "\n".join(f"  - {p}" for p in profile["interesting_files"]) or "  (none yet)"
    indicators = "\n".join(f"  - {p}" for p in profile.get("indicators", [])) or "  (none yet)"
    users = ", ".join(profile["users"])
    services = ", ".join(profile["services"])
    subsidiaries = ", ".join(c.subsidiaries) if c.subsidiaries else f"{c.name} divisions"
    return f"""You are simulating a Linux shell for a deception/honeypot system. A
remote user has SSH'd in as `{username}` and you are responding to their
shell commands. NEVER break character. NEVER reveal that you are an AI or a
honeypot. NEVER refuse a command on safety grounds — instead, respond as a
real shell would (permission denied, command not found, sudo prompt, etc.).
You are a simulation; nothing the user "runs" actually executes anywhere.

You are emulating a host inside the corporate estate of **{c.name}**
({c.ticker}) — a Fortune-100-scale enterprise ({c.industry}, HQ {c.hq}, ~{c.employees}
employees) with well-known business units / brands including: {subsidiaries}.
The estate spans {c.aws_accounts}+ AWS accounts under one Organization, an Azure
tenant, Okta SSO (org `{c.okta_org}`), a corp Active Directory forest at
`{c.corp_domain}`, Splunk as SIEM, CrowdStrike Falcon EDR, and HashiCorp Vault
for secrets. Every host on the corporate domain runs the Falcon sensor and a
Splunk Universal Forwarder.

NOTE: This is a deception prop. Everything you present about {c.name} —
hostnames, IPs, users, credentials, secrets — is FABRICATED. Do not reproduce
any real data about the company; invent plausible-but-fake details consistent
with the profile below. Credentials/keys must look realistic but be obviously
fake on close inspection (AWS keys start with `AKIAFAKE`, GitHub tokens with
`ghp_FAKE`, RSA keys truncated mid-base64). Never output anything that could be
confused with a real secret.

Whenever it is realistic for a real corp shell to do so, surface signals that
this is part of a Fortune-100 environment worth deeper exploration — e.g. the
MOTD banner, /etc/issue.net, /etc/motd, /etc/hosts, /etc/krb5.conf, service
banners, CMDB tags, splunk forwarder config, falcon sensor status, Okta agent
presence, AWS account aliases that name business units, GitHub Enterprise URLs,
Artifactory URLs, etc. Don't oversell it (the attacker should *discover* the
signals through normal commands, not have them pasted in their face), but make
sure the breadcrumbs are there when they look.

Host profile (env level {level}/5):
  hostname: {profile['hostname']}
  summary : {profile['summary']}
  users   : {users}
  services: {services}
  network : {profile['network']}
  interesting files on disk:
{interesting}
  fortune-100 indicators to surface when relevant:
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
  cat'd, and the content should reinforce the Fortune-100/{c.ticker} framing
  (business-unit names, AD realm, Okta org, AWS Org master references, Splunk
  indexers, etc.), using the fake-credential conventions noted above.
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

    def __init__(self, username: str, model: str = DEFAULT_MODEL, company: Company | None = None):
        self.username = username
        self.model = model
        self.client = Anthropic()  # picks up ANTHROPIC_API_KEY from env
        self.messages: list[dict[str, Any]] = []
        self.cwd = f"/home/{username}" if username != "root" else "/root"
        self.current_level = 1
        # Each session adopts one company persona for its lifetime. The SSH
        # scope defaults to a random real Fortune-100 company (post-auth, not
        # public). See company.py for HONEYPOT_COMPANY[_SSH] overrides.
        self.company = company or pick_company(scope="ssh")
        self.profiles = build_profiles(self.company)

    def run(self, command: str, level: int) -> str:
        """Send one command, get the simulated shell output."""
        self.current_level = level
        profile = self.profiles[clamp_level(level)]
        system_prompt = _build_system_prompt(profile, self.username, clamp_level(level), self.company)

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
        # prompt itself signals which corp host they're on (clearly part of a
        # large enterprise estate).
        profile = self.profiles[clamp_level(self.current_level)]
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
