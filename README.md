# AI Honeypot

An SSH honeypot whose "shell" is actually Claude. Threat actors believe they
have a real Linux box; every command they run is answered by an LLM that
maintains consistent state (cwd, files, users, fake creds) across the session.
The simulated environment **scales up or down** based on the attacker's
sophistication — the more dangerous the recon/escalation patterns, the more
tempting the box appears.

Each SSH session adopts a **randomly chosen real Fortune-100 company** persona
(Walmart, Amazon, Microsoft, UnitedHealth, JPMorgan Chase, …; see
`company.py`), so escalating attackers see clear breadcrumbs — the company's
real business units/brands, Okta SSO, Splunk SIEM, CrowdStrike Falcon, an AWS
Organization with hundreds of accounts, a corp Active Directory forest — that
mark the box as part of a large, high-value enterprise worth deeper
exploration. The persona is rerolled per session; restart and a different
company turns up.

> ⚠️ **Real names are deception props.** Every host, IP, credential and secret
> the honeypot derives from a company is **fabricated** — none of it is real or
> belongs to the company. The two surfaces default differently *by exposure*:
> the **SSH shell** uses real companies (revealed only after an intruder
> connects + authenticates — not public, not indexable), while the **public
> decoy website defaults to the fictional "Meridian Global Industries"**
> persona, since a public page impersonating a real brand is the part that
> could be indexed or flagged as phishing. Override per surface with
> `HONEYPOT_COMPANY_SSH` / `HONEYPOT_COMPANY_WEB` (or `HONEYPOT_COMPANY` for
> both); each accepts `random`, `fictional`, or a slug like `microsoft`. See
> [Company personas](#company-personas--legal-note).

In front of it sits a **decoy "vulnerable" website** on port 80 — bait whose
only job is to make a scanner conclude the box is a soft, neglected target and
that **SSH on :22 is the way in**. It advertises an end-of-life Apache/PHP
stack, leaks an `.env` / `.git` / `/backup/` directory, and spills temporary
SSH deploy credentials in a "debug mode" stack trace. Every lead points at the
SSH listener, which accepts any credentials → straight into the AI shell.

A real-time web dashboard shows every active session, every command as it's
typed, a per-session sophistication score, and a **world-map view** of
where the inbound SSH attempts are geographically originating from. The
dashboard is gated behind an **operator login** (mythic-c2 style) with
credentials declared in `config.yaml`.

> ⚠️ **SSH-side auth is still open by design**: the honeypot accepts ANY
> username and ANY password (and any pubkey) on the SSH listener so it can
> funnel attackers into the AI shell. The login screen described below is
> for the **operator dashboard only**.

## Components

```
honeypot/
  main.py            # entrypoint — boots SSH server + decoy web + dashboard
  config.py          # YAML config loader (users, geoip, secret key)
  auth.py            # operator login / session cookie helpers
  decoy_web.py       # public "vulnerable" bait site that funnels to SSH (port 80)
  company.py         # real Fortune-100 personas + random picker (HONEYPOT_COMPANY)
  ssh_server.py      # paramiko SSH server, accepts any login
  session.py         # per-connection shell loop (per-session company persona)
  claude_shell.py    # Anthropic API wrapper that emulates a Linux shell
  sophistication.py  # OSCP-grounded command rubric + per-company env profiles 1-5
  geoip.py           # ip-api.com lookup w/ in-memory cache
  event_bus.py       # thread<->asyncio bridge for live UI updates + geo aggregates
  logger.py          # JSONL session logger (+ per-command commands.csv)
  recorder.py        # per-session transcript (.log) + asciicast (.cast) recorder
  dashboard.py       # FastAPI app: login + WebSocket live feed + map APIs
  templates/
    index.html       # the dashboard UI (Leaflet map + tables + stream)
    login.html       # operator login page
```

## Sophistication tiers → env level

The command rubric (`sophistication.py`) is grounded in the operator's own
OSCP / red-team notes, so it recognizes the actual tradecraft you'd expect to
see — not just shell builtins. Patterns are matched case-insensitively, and
when a command matches multiple tiers it scores as the **most dangerous** one.

| Tier | Examples (matched case-insensitively)                                                       | Weight |
|------|---------------------------------------------------------------------------------------------|--------|
| 1    | `ls`, `pwd`, `whoami`, `id`, `uname`, `hostname`, `systeminfo`                               | +1     |
| 2    | `nmap`, `enum4linux`, `smbclient`, `gobuster`/`feroxbuster`/`ffuf`, `ldapsearch`, `kerbrute`, `net user`, `/etc/passwd` | +2 |
| 3    | `sudo -l`, suid finds, **winPEAS**/**linPEAS**, **PowerUp**, **Seatbelt**, `pspy`, **BloodHound**/**SharpHound**, PowerView, GPP/cpassword, `pkexec`/dirtypipe, `.aws/credentials` | +4 |
| 4    | **Impacket** (`psexec.py`/`wmiexec.py`/`secretsdump.py`), `evil-winrm`, `crackmapexec`/`nxc`/`netexec`, `responder`, `ntlmrelayx`, **mimikatz**, **Rubeus**, kerberoast/asreproast, `chisel`/`ligolo`/`proxychains`, `msfvenom`/`meterpreter`, `schtasks /create`, `nc -lvp` | +6 |
| 5    | DCSync (`secretsdump … -just-dc`, `lsadump::dcsync`), golden ticket, `ntds.dit`/`ntdsutil`, `wevtutil cl`/`Clear-EventLog`, `vssadmin delete`, `history -c`, `shred`, timestomp | +8 |

Cumulative score → level: `<3` L1, `<8` L2, `<18` L3, `<35` L4, `>=35` L5.

Each level swaps a richer profile into Claude's system prompt, built for the
session's chosen company (`<slug>` below = its hostname token, e.g. `walmart`,
`amazon`, `jpmc`):

| Lvl | Hostname                       | What the attacker sees                                                              |
|-----|--------------------------------|-------------------------------------------------------------------------------------|
| 1   | `<slug>-web-edge-01`           | Public DMZ web node, MOTD names the company, CrowdStrike Falcon sensor              |
| 2   | `<slug>-app-prod-12`           | Prod Node.js app, Splunk forwarder, Okta env vars, CMDB tags (business-unit names)  |
| 3   | `<slug>-ci-build-04`           | Jenkins CI w/ AWS Org build profile, GHE token, subsidiary repos, krb5 → AD         |
| 4   | `<slug>-bastion-east-02`       | Jump host into 10.0.0.0/8, known_hosts on AD DCs + Splunk indexers, 12.4k-host CMDB |
| 5   | `<slug>-vault-broker-east-01`  | Vault unseal quorum, AWS Org root creds, Azure tenant root SP, Okta super admin     |

The chosen persona is recorded on the `session_start` log event (`company`,
`company_slug`) so you can see which company each attacker was shown.

A bored, unsophisticated bot sees an empty marketing edge node; an active
attacker escalates into a "crown jewel" Vault broker — keeping them engaged
longer for telemetry while the dashboard score and map light up.

## Decoy "vulnerable" website (port 80)

`decoy_web.py` serves a deliberately broken, leaky, end-of-life-looking web app
on **port 80** — themed as a company's public edge node
(`<slug>-web-edge-01.corp.<domain>`). It picks **one** persona at startup (a
website can't change identity per page load) and, because it's the public
surface, **defaults to the fictional "Meridian Global Industries"** persona
(override with `HONEYPOT_COMPANY_WEB`; see [Company personas](#company-personas--legal-note)).
The site is pure static content from the Python stdlib HTTP server (no extra
dependencies); nothing it serves executes anything.

The point is to look like a soft target whose real foothold is SSH:

- **EoL/vulnerable stack banners** — `Server: Apache/2.4.49` (CVE-2021-41773)
  and `X-Powered-By: PHP/7.4.3` (end-of-life) on every response.
- **Leaky recon surface** — `/robots.txt` lists the goodies; `/.env`,
  `/.git/config`, `/server-status`, `/phpinfo.php`, and an Apache-style
  `/backup/` directory index are all readable.
- **Broken features** — the staff login (`POST /login`) returns a "debug mode"
  500 stack trace; nav links 503 ("mid-migration"); the genuinely juicy
  `/backup/` artifacts (DB dump, `id_rsa_deploy.bak`) 403 — a broken permission
  that nudges the attacker toward SSH instead.
- **The funnel** — the login traceback, `/.env`, `/backup/deploy_notes.txt`,
  and `/phpinfo.php` all leak the same temporary SSH deploy credential
  (`ssh <slug>-deploy@… port 22`). Because the SSH listener accepts ANY
  credentials, following any of these leads drops the attacker into the AI
  shell, where the session is logged and scored.

Every web request is written to the same JSONL log as a `web` event (with the
source IP, method, path, status, and user-agent) and shows up in the dashboard's
live event stream — without creating phantom rows in the SSH session table.

Disable it with `HONEYPOT_WEB_ENABLED=0`, or move it off :80 with
`HONEYPOT_WEB_PORT`.

## Company personas / legal note

`company.py` holds 20 real Fortune-100 personas plus a fictional fallback
("Meridian Global Industries"). A persona drives hostnames, the login banner,
the system prompt, and the decoy site's branding. **Everything derived from a
company is fabricated** — no real hosts, IPs, credentials, or data.

The two surfaces carry different exposure, so they default differently:

| Surface         | Default    | Why                                                                                   |
|-----------------|------------|---------------------------------------------------------------------------------------|
| SSH shell (:22) | `random`   | Persona is revealed only *after* an intruder connects to an "authorized use only" service and authenticates — not public, not indexable. Low public-impersonation profile. |
| Decoy web (:80) | `fictional`| Unauthenticated and public — broadcasts the brand to crawlers/scanners and could be indexed or flagged as phishing impersonating the company. Highest risk. |

Resolution (per-scope var → global var → per-scope default):

```
HONEYPOT_COMPANY_SSH=<v>   # SSH shell only
HONEYPOT_COMPANY_WEB=<v>   # decoy website only
HONEYPOT_COMPANY=<v>       # both (unless a scope var overrides)
# <v> = random | fictional | <slug>  (e.g. microsoft, walmart, jpmc)
```

Examples: `HONEYPOT_COMPANY=fictional` (everything fake, safest for public
deployment); `HONEYPOT_COMPANY=random` (real on both, incl. the web — only if
you've accepted that exposure); `HONEYPOT_COMPANY_SSH=microsoft` (pin the shell
for a repeatable demo). This is **not legal advice** — for a public deployment,
or any reuse of a real brand, confirm the implications for your jurisdiction.

## Operator authentication

The dashboard is protected by **username + password login**, declared in
`config.yaml` (mythic-c2 style):

```yaml
dashboard:
  secret_key: null   # set a long random string for stable sessions
  session_max_age: 43200
  auth_enabled: true
  users:
    - username: admin
      password: changeme
    - username: analyst
      password: another-strong-passphrase
```

`config.yaml` is **gitignored** and **dockerignored**. After cloning:

```bash
cp config.yaml.example config.yaml
chmod 600 config.yaml
$EDITOR config.yaml          # set users + a real secret_key
```

`secret_key` signs the session cookie. If left null, a random key is
generated at startup — login sessions won't survive a restart, but auth
still works.

Login page is at `http://localhost:8080/login`; the dashboard at `/` will
redirect there until you sign in. `/logout` clears the session.

WebSocket connections are also auth-gated: the browser's session cookie is
required on the WS handshake (rejected as close code `4401` otherwise),
and an expired session bounces the page back to `/login`.

## Geolocation & map view

Every inbound SSH connection's source IP is run through `ip-api.com`'s free
endpoint (no key required) with in-memory caching. Private / loopback /
link-local addresses are short-circuited and never sent to the third party.
Results are attached to the `connect`/`disconnect` events in the JSONL log
under a `geo` field, and the dashboard aggregates them into:

- **Leaflet world map** with one marker per unique source IP; marker size
  scales with hit count, color escalates from teal → red as that IP racks
  up repeat hits.
- **Top countries / top cities / top IPs** ranked lists.
- A `Countries` stat in the header.
- A per-session **Origin** column in the active-session table (country code
  + city or "private").

Disable the lookup (e.g. no outbound, or you don't want a third-party
service seeing the IPs) via `geoip.enabled: false` in `config.yaml`. Lookup
timeout is also configurable.

## Setup

1. Get an Anthropic API key. Put it in `.env`:

   ```
   ANTHROPIC_API_KEY=sk-ant-...
   HONEYPOT_MODEL=claude-haiku-4-5-20251001
   ```

   > **Rotate any key that was pasted into a chat.** Pasting a key into
   > a prompt exposes it to every layer that processed the message — revoke
   > it at <https://console.anthropic.com> and use a fresh one.

2. Create the operator config:

   ```bash
   cp config.yaml.example config.yaml
   chmod 600 config.yaml
   $EDITOR config.yaml
   ```

3. Build and run:

   ```bash
   docker compose up --build
   ```

This binds:

- **host :22 → container :22**     (SSH honeypot — open auth, the real foothold)
- **host :80 → container :80**     (decoy "vulnerable" website — bait)
- **host :8080 → container :8080** (operator dashboard — login required)

> **Ports 22 and 80 are privileged.** Binding them needs root on the host, and
> the host must not already be running a real `sshd` on 22 or a web server on
> 80. If port 22 is taken (e.g. by the host's own SSH), either move the host's
> sshd to another port or remap the honeypot to a high port in
> `docker-compose.yml` (e.g. `"2222:22"`) — at the cost of looking less like a
> normal box. Keep the dashboard (`8080`) off the public internet: bind it to
> loopback with `"127.0.0.1:8080:8080"` or put it behind a VPN/reverse proxy.

## Try it

```bash
# In one terminal
docker compose up --build
```

First, play the attacker poking the **decoy website** and following its trail
to SSH:

```bash
curl -s http://localhost/                        # EoL Apache/PHP banners; names the company
curl -s http://localhost/robots.txt              # points at the goodies
curl -s http://localhost/.env                    # leaked deploy creds + ssh hint
curl -s http://localhost/backup/                 # autoindex of a leaky dir
curl -s http://localhost/backup/deploy_notes.txt # "ssh <company>-deploy@… port 22"
curl -s -X POST http://localhost/login           # debug 500 leaks the same creds
```

Then follow the breadcrumb in — the SSH listener takes **any** username and
**any** password, so you don't even need the leaked one:

```bash
ssh anyone@localhost          # port 22; username + password: literally anything
# Then poke around — try escalating to watch the box scale up:
whoami; ls; cat /etc/motd; cat /etc/passwd
sudo -l
find / -perm -4000 2>/dev/null
./linpeas.sh                  # winPEAS/linPEAS, BloodHound, impacket, mimikatz…
GetUserSPNs.py corp/u:p -request   # …all push the sophistication score up
```

Open `http://localhost:8080`, sign in with the credentials you put in
`config.yaml`, and watch the web hits and your SSH session stream in — the map
lighting up and the session climbing the sophistication ladder in real time.

## Logs

Everything is logged to `./data/logs/sessions.jsonl` on the host (mounted as
a volume). One JSON object per line:

```json
{"ts":1714770000.12,"event":"connect","session_id":"...","peer":"203.0.113.4:51820",
 "geo":{"ip":"203.0.113.4","country":"Germany","country_code":"DE","city":"Frankfurt",
        "lat":50.11,"lon":8.68,"isp":"...","org":"...","as":"AS3320 ..."}}
{"ts":1714770001.55,"event":"command","session_id":"...","command":"sudo -l",
 "tier":3,"score":4,"level":2,...}
```

Events you'll see: `connect`, `auth`, `session_start`, `command`, `response`,
`logout`, `disconnect`, plus `server_start` and various error variants. The
decoy website logs `web` events (with `src`, `method`, `path`, `status`, `ua`)
and a `web_server_start` line.

### Per-session recordings & CSV

Alongside the JSONL, every SSH session is recorded for later review (set
`HONEYPOT_RECORD=0` to turn this off):

```
data/logs/
  sessions.jsonl                  # structured source of truth (one JSON/line)
  commands.csv                    # one row per command: ts,iso,session_id,tier,score,level,command
  transcripts/<session_id>.log    # human-readable transcript (full I/O, with tier/score)
  casts/<session_id>.cast         # asciicast v2 — a replayable terminal recording
```

- **`commands.csv`** — quick tabular analysis in Excel/pandas; joins back to the
  JSONL on `session_id`.
- **`transcripts/*.log`** — the readable "what happened": a header (peer, client,
  user, company persona) then every command (with its tier/score/level) and the
  **full** AI response (the JSONL keeps only a 400-char preview).
- **`casts/*.cast`** — replay an attacker's whole session in your terminal:
  ```bash
  asciinema play data/logs/casts/<session_id>.cast      # re-watch in real time
  asciinema play -s 3 <file>                            # 3x speed
  ```
  (Great for the talk — you literally re-run the attacker's session.)

For SQL over the JSONL without any database, point DuckDB at it:
`SELECT command, tier FROM read_json_auto('data/logs/sessions.jsonl') WHERE event='command';`

## Security notes

- **Rotate the API key** you put in `.env` once you've finished a test run.
- The SSH listener is open by design — **don't bind it on the open internet
  unless you understand the exposure**. Treat the host the honeypot runs on
  as an attacker-facing tier.
- The decoy website (port 80) is meant to face the internet and serves only
  static strings — nothing it shows executes, and the leaked "credentials" are
  fake (the SSH side accepts anything regardless).
- **Real company names are deception props, not endorsements or real data.**
  Every hostname, IP, credential, and secret tied to a company is fabricated.
  The high-exposure surface is the **public decoy web**, which defaults to the
  fictional persona; the post-auth SSH shell defaults to real companies. For a
  fully neutral public deployment set `HONEYPOT_COMPANY=fictional`; see
  [Company personas](#company-personas--legal-note) for the per-surface knobs.
- The dashboard now requires login; if `auth_enabled: false`, bind it to
  localhost or behind a reverse proxy.
- `paramiko` host key is auto-generated on first boot into `./data/host_rsa.key`.
  Persist it across rebuilds so SSH clients don't see "host key changed".
- `.env` and `config.yaml` are `chmod 600` and gitignored / dockerignored.
- Geoip lookups go to `ip-api.com` over plaintext HTTP by default. If that
  bothers you, set `geoip.enabled: false`, or change `geoip.endpoint` to a
  local GeoIP service.

## Tuning

Environment variables (all optional):

| Var                   | Default                               | What it does                                  |
|-----------------------|---------------------------------------|-----------------------------------------------|
| `ANTHROPIC_API_KEY`   | (required)                            | Claude API key                                |
| `HONEYPOT_MODEL`      | `claude-haiku-4-5-20251001`           | Switch to `claude-sonnet-4-6` for richer sims |
| `HONEYPOT_COMPANY`    | (per-scope)                           | Persona for both surfaces: `random`, `fictional`, or a slug (e.g. `microsoft`). Overridden per surface by the two below. |
| `HONEYPOT_COMPANY_SSH`| `random`                              | SSH-shell persona only (post-auth; defaults to a random real Fortune-100) |
| `HONEYPOT_COMPANY_WEB`| `fictional`                           | Decoy-website persona only (public; defaults to fictional)    |
| `HONEYPOT_SSH_PORT`   | `22`                                  | SSH listener port inside the container        |
| `HONEYPOT_WEB_PORT`   | `80`                                  | Decoy website port inside the container       |
| `HONEYPOT_WEB_ENABLED`| `1`                                   | Set `0`/`false` to disable the decoy website  |
| `HONEYPOT_RECORD`     | `1`                                   | Per-session transcript + asciicast recording; `0`/`false` to disable |
| `HONEYPOT_UI_PORT`    | `8080`                                | Dashboard port                                |
| `HONEYPOT_LOG_PATH`   | `/data/logs/sessions.jsonl`           | Where to write the JSONL                      |
| `HONEYPOT_HOST_KEY`   | `/data/host_rsa.key`                  | SSH host key path (auto-generated)            |
| `HONEYPOT_CONFIG`     | `./config.yaml`                       | Operator config path                          |
| `HONEYPOT_SECRET_KEY` | (random per restart)                  | Fallback session-cookie key if not in YAML    |
