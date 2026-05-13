# AI Honeypot

An SSH honeypot whose "shell" is actually Claude. Threat actors believe they
have a real Linux box; every command they run is answered by an LLM that
maintains consistent state (cwd, files, users, fake creds) across the session.
The simulated environment **scales up or down** based on the attacker's
sophistication — the more dangerous the recon/escalation patterns, the more
tempting the box appears.

The simulated estate is themed as **Meridian Global Industries (MGI)** — a
fictional Fortune-100 conglomerate — so escalating attackers see clear
breadcrumbs (Okta SSO, Splunk SIEM, CrowdStrike Falcon, AWS Organization
with 450+ accounts, multiple named subsidiaries) that mark the box as part
of a large, high-value enterprise worth deeper exploration.

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
  main.py            # entrypoint — boots SSH server + dashboard
  config.py          # YAML config loader (users, geoip, secret key)
  auth.py            # operator login / session cookie helpers
  ssh_server.py      # paramiko SSH server, accepts any login
  session.py         # per-connection shell loop
  claude_shell.py    # Anthropic API wrapper that emulates a Linux shell
  sophistication.py  # scores commands, picks env level 1-5 (Fortune 500 profiles)
  geoip.py           # ip-api.com lookup w/ in-memory cache
  event_bus.py       # thread<->asyncio bridge for live UI updates + geo aggregates
  logger.py          # JSONL session logger
  dashboard.py       # FastAPI app: login + WebSocket live feed + map APIs
  templates/
    index.html       # the dashboard UI (Leaflet map + tables + stream)
    login.html       # operator login page
```

## Sophistication tiers → env level

| Tier | Examples                                           | Weight |
|------|----------------------------------------------------|--------|
| 1    | `ls`, `pwd`, `whoami`, `id`, `uname`               | +1     |
| 2    | `ps`, `netstat`, `find`, `cat /etc/passwd`         | +2     |
| 3    | `sudo -l`, `/etc/shadow`, suid finds, ssh keys     | +4     |
| 4    | `crontab`, `ssh-keygen`, `nc -lvp`, `/dev/tcp/`    | +6     |
| 5    | `history -c`, log truncation, `shred`, `insmod`    | +8     |

Cumulative score → level: `<3` L1, `<8` L2, `<18` L3, `<35` L4, `>=35` L5.

Each level swaps a richer Fortune-500 profile into Claude's system prompt:

| Lvl | Hostname                                | What the attacker sees                                                              |
|-----|-----------------------------------------|-------------------------------------------------------------------------------------|
| 1   | `mgi-web-edge-01`                       | Public DMZ web node, MOTD names MGI, CrowdStrike Falcon sensor                      |
| 2   | `mgi-app-prod-12`                       | Prod Node.js app, Splunk forwarder, Okta env vars, CMDB tags (subsidiary names)     |
| 3   | `mgi-ci-build-04`                       | Jenkins CI w/ AWS Org build profile, GHE token, multiple subsidiary repos, krb5 → AD|
| 4   | `mgi-bastion-east-02`                   | Jump host into 10.0.0.0/8, known_hosts on AD DCs + Splunk indexers, 12.4k-host CMDB |
| 5   | `mgi-vault-broker-east-01`              | Vault unseal quorum, AWS Org root creds, Azure tenant root SP, Okta super admin     |

A bored, unsophisticated bot sees an empty marketing edge node; an active
attacker escalates into a "crown jewel" Vault broker — keeping them engaged
longer for telemetry while the dashboard score and map light up.

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

- **host :2222 → container :22**  (SSH honeypot — open auth)
- **host :8080 → container :8080** (dashboard — login required)

If you want the honeypot on real port 22, edit `docker-compose.yml`:

```yaml
ports:
  - "22:22"     # ← needs root / no other sshd on host
  - "8080:8080"
```

## Try it

```bash
# In one terminal
docker compose up --build

# In another — connect to the honeypot with literally any creds
ssh -p 2222 anyone@localhost
# password: literally anything

# Then poke around:
whoami
ls
cat /etc/motd
cat /etc/passwd
sudo -l
find / -perm -4000 2>/dev/null
```

Open `http://localhost:8080`, sign in with the credentials you put in
`config.yaml`, and watch the map light up plus your own session climb the
sophistication ladder in real time.

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
`logout`, `disconnect`, plus `server_start` and various error variants.

## Security notes

- **Rotate the API key** you put in `.env` once you've finished a test run.
- The SSH listener is open by design — **don't bind it on the open internet
  unless you understand the exposure**. Treat the host the honeypot runs on
  as an attacker-facing tier.
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
| `HONEYPOT_SSH_PORT`   | `22`                                  | Port inside the container                     |
| `HONEYPOT_UI_PORT`    | `8080`                                | Dashboard port                                |
| `HONEYPOT_LOG_PATH`   | `/data/logs/sessions.jsonl`           | Where to write the JSONL                      |
| `HONEYPOT_HOST_KEY`   | `/data/host_rsa.key`                  | SSH host key path (auto-generated)            |
| `HONEYPOT_CONFIG`     | `./config.yaml`                       | Operator config path                          |
| `HONEYPOT_SECRET_KEY` | (random per restart)                  | Fallback session-cookie key if not in YAML    |
