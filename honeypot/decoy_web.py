"""Decoy "vulnerable" web front-end whose only job is to funnel attackers to SSH.

This is the public-facing *bait*: a deliberately broken, leaky,
end-of-life-looking web app themed as a real Fortune-100 company's public edge
node — picked once per
process from `company.py`, the same persona pool the SSH/Claude shell draws
from — so the breadcrumbs an attacker finds here line up with the kind of box
they land on after they `ssh` in. (Because each SSH session rerolls its own
persona, a given shell may name a different company than this site; the funnel
breadcrumb is a lure, not a guarantee.)

The whole design goal: make a scanner conclude "the website is a soft, neglected
target, and SSH on :22 is the real way in." It advertises an EoL Apache/PHP
stack, leaks an `.env` / `.git` / `/backup/` directory, and — on the broken
login form — spills a debug stack trace containing temporary SSH deploy
credentials. Since the SSH listener accepts ANY credentials, every lead points
straight into the AI shell, where the session is logged and scored.

Nothing here executes anything; it's static strings served by the stdlib HTTP
server (no extra deps). All company-derived hostnames, IPs, and secrets are
fabricated props. Every request is logged to the same JSONL as SSH events (as
`web` events, without a `session_id`, so they show in the live stream but don't
pollute the SSH session table).
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .company import APACHE_VERSION, PHP_VERSION, WEB_DOCROOT, Company, pick_company
from .logger import SessionLogger

# EoL/vulnerable-looking stack (shared with the SSH edge-node profile via
# company.py). Apache 2.4.49 is CVE-2021-41773; PHP 7.4 is end-of-life.
SERVER_BANNER = f"{APACHE_VERSION} OpenSSL/1.1.1f PHP/{PHP_VERSION}"
POWERED_BY = f"PHP/{PHP_VERSION}"


@dataclass(frozen=True)
class SiteContext:
    """Company-derived values the decoy pages render from (all fabricated)."""
    name: str          # display name, e.g. "Walmart Inc."
    host: str          # <slug>-web-edge-01.corp.<domain>
    domain: str        # corp domain, e.g. corp.walmart.com
    deploy_user: str   # <slug>-deploy
    deploy_pass: str   # plausible-but-fake temp password
    db_host: str       # db-edge-01.corp.<domain>
    ghe_host: str      # ghe.corp.<domain>
    okta_org: str      # <slug>.okta.com
    docroot: str = f"{WEB_DOCROOT}/public"

    @classmethod
    def from_company(cls, c: Company) -> "SiteContext":
        return cls(
            name=c.name,
            host=c.host("web-edge-01"),
            domain=c.corp_domain,
            deploy_user=c.deploy_user,
            deploy_pass=c.deploy_pass,
            db_host=c.db_host,
            ghe_host=f"ghe.{c.corp_domain}",
            okta_org=c.okta_org,
        )


def _page(ctx: SiteContext, title: str, body: str) -> str:
    """Wrap body content in the shared (slightly broken) portal chrome."""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title} — {ctx.name}</title>
<!-- TODO({ctx.deploy_user}): re-point CSS at the CDN, temp inline since the migration -->
<!-- staging note: portal still served off the edge box; ssh access is {ctx.deploy_user}@ for now -->
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:0;color:#1c2733;background:#eef1f4}}
.top{{background:#0b2e4f;color:#fff;padding:14px 26px}}
.top b{{font-size:19px;letter-spacing:.5px}}
.nav{{background:#103f6b;padding:8px 26px;font-size:13px}}
.nav a{{color:#cfe0f0;text-decoration:none;margin-right:18px}}
.banner{{background:#fcf3cd;border:1px solid #e6d27a;color:#7a5c00;padding:10px 16px;margin:16px 26px;font-size:13px}}
.wrap{{padding:8px 26px 40px}}
.card{{background:#fff;border:1px solid #d4dae1;padding:18px 22px;margin:16px 0;max-width:760px}}
h1{{font-size:22px}} h2{{font-size:16px;color:#0b2e4f}}
.muted{{color:#7a8694;font-size:12px}}
table.sys{{border-collapse:collapse;font-size:12px;font-family:Consolas,monospace}}
table.sys td{{border:1px solid #e0e5ea;padding:3px 10px}}
.foot{{border-top:1px solid #d4dae1;margin-top:30px;padding:14px 26px;color:#7a8694;font-size:11px}}
input{{padding:6px;border:1px solid #c2cad3;width:240px}}
button{{padding:7px 16px;background:#103f6b;color:#fff;border:0;cursor:pointer}}
</style>
</head>
<body>
<div class="top"><b>{ctx.name.upper()}</b></div>
<div class="nav">
  <a href="/">Home</a><a href="/products">Products</a><a href="/investors">Investors</a>
  <a href="/careers">Careers</a><a href="/login">Operations Portal</a>
</div>
<div class="banner">⚠ Scheduled maintenance: the corporate portal is mid-migration to the new
data center. Some features are temporarily unavailable. Operations staff: use the
internal portal login below.</div>
<div class="wrap">
{body}
</div>
<div class="foot">
  &copy; 2023 {ctx.name} — Internal &amp; Confidential.<br>
  node: {ctx.host} · stack: Apache/2.4.49 PHP/7.4.3 · sshd: OpenSSH_8.9p1 (port 22, listening)
  <!-- healthcheck: sshd ok | mysql degraded | redis down | docroot {ctx.docroot} -->
</div>
</body>
</html>"""


def _home(ctx: SiteContext) -> str:
    body = f"""
<div class="card">
  <h1>Operations Portal</h1>
  <p>Welcome to the {ctx.name} internal operations portal. This edge node serves
  the public site and proxies the staff portal during the data-center migration.</p>
  <p class="muted">Most internal tooling has moved behind the new SSO. If the
  portal login is failing, fall back to direct host access — see the migration
  runbook in <code>/backup/deploy_notes.txt</code>.</p>
</div>
<div class="card">
  <h2>Edge Node Status</h2>
  <table class="sys">
    <tr><td>host</td><td>{ctx.host}</td></tr>
    <tr><td>os</td><td>Ubuntu 22.04.3 LTS (jammy)</td></tr>
    <tr><td>web</td><td>Apache/2.4.49 (Ubuntu) — PHP/7.4.3</td></tr>
    <tr><td>sshd</td><td>OpenSSH_8.9p1 — 0.0.0.0:22 (LISTEN)</td></tr>
    <tr><td>mysql</td><td>5.7.38 — 127.0.0.1:3306 (degraded)</td></tr>
    <tr><td>deploy user</td><td>{ctx.deploy_user} (password auth enabled)</td></tr>
    <tr><td>last deploy</td><td>2023-11-14 by {ctx.deploy_user} via ssh</td></tr>
  </table>
  <p class="muted">Generated by status.php — debug build. Do not expose externally.</p>
</div>
"""
    return _page(ctx, "Home", body)


def _login_page(ctx: SiteContext) -> str:
    body = """
<div class="card" style="max-width:420px">
  <h1>Staff Login</h1>
  <form method="POST" action="/login">
    <p><label>Username<br><input name="username" autocomplete="username"></label></p>
    <p><label>Password<br><input name="password" type="password" autocomplete="current-password"></label></p>
    <p><button type="submit">Sign in</button></p>
  </form>
  <p class="muted">SSO is down during the migration. Use your host login. Trouble?
  see <code>/backup/deploy_notes.txt</code>.</p>
</div>
"""
    return _page(ctx, "Staff Login", body)


def _login_traceback(ctx: SiteContext) -> str:
    """Fake "debug mode left on" stack trace returned when someone tries to log in.

    Leaks the docroot, a DB DSN, and — the payload — temp SSH deploy creds.
    """
    return f"""<!doctype html><html><head><title>500 — Whoops</title>
<style>body{{font-family:Consolas,Menlo,monospace;background:#1b1b1f;color:#e6e6e6;margin:0}}
.h{{background:#b03a3a;padding:16px 22px;font-size:16px}}
.b{{padding:18px 22px;font-size:13px;line-height:1.5}}
.f{{color:#7fd1ff}} .e{{color:#ff9b9b}} .c{{color:#8a93a0}}</style></head><body>
<div class="h">PDOException · SQLSTATE[HY000] [2002] Connection refused (debug)</div>
<div class="b">
<span class="e">PDOException</span>: SQLSTATE[HY000] [2002] Connection refused in
<span class="f">{ctx.docroot}/../app/Database/Connection.php</span>:88<br><br>
Stack trace:<br>
#0 <span class="f">{ctx.docroot}/../app/Database/Connection.php</span>(88): PDO->__construct('mysql:host={ctx.db_host};dbname=portal', 'portal', 'p0rtal-Db-Pw!')<br>
#1 <span class="f">{ctx.docroot}/../app/Auth/LoginController.php</span>(54): App\\Database\\Connection->users()<br>
#2 <span class="f">{ctx.docroot}/index.php</span>(31): App\\Auth\\LoginController->authenticate()<br><br>
<span class="c"># --- application context (APP_DEBUG=true) ---</span><br>
<span class="c"># DB unreachable during migration. TEMP WORKAROUND for ops:</span><br>
<span class="c"># direct host access is open while SSO is down —</span><br>
<span class="c">#   ssh {ctx.deploy_user}@{ctx.host}   (port 22)</span><br>
<span class="c">#   password: {ctx.deploy_pass}   # FIXME remove before GA — ticket OPS-4471</span><br>
<span class="c"># sudo runbook: /usr/local/bin/runbook</span><br>
</div></body></html>"""


ROBOTS = """User-agent: *
Disallow: /backup/
Disallow: /.git/
Disallow: /.env
Disallow: /admin/
Disallow: /server-status
Disallow: /phpinfo.php
Disallow: /.ssh/
"""


def _env_file(ctx: SiteContext) -> str:
    return f"""APP_NAME="{ctx.name} Operations Portal"
APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:Zk9hY2VtZXJpZGlhbmZ ake K3l2YWx1ZXBhZA==
APP_URL=https://portal.{ctx.domain}

DB_CONNECTION=mysql
DB_HOST={ctx.db_host}
DB_PORT=3306
DB_DATABASE=portal
DB_USERNAME=portal
DB_PASSWORD=p0rtal-Db-Pw!

# Migration fallback — direct host access while SSO is offline.
# Remove before GA (OPS-4471).
DEPLOY_SSH_USER={ctx.deploy_user}
DEPLOY_SSH_PASS={ctx.deploy_pass}
DEPLOY_SSH_PORT=22
"""


def _git_config(ctx: SiteContext) -> str:
    return f"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = git@{ctx.ghe_host}:web/portal.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = {ctx.deploy_user}
\temail = {ctx.deploy_user}@{ctx.domain}
"""


def _deploy_notes(ctx: SiteContext) -> str:
    return f"""{ctx.name.upper()} EDGE PORTAL — MIGRATION RUNBOOK (INTERNAL)
==============================================
host: {ctx.host}
docroot: {ctx.docroot}

The portal DB and SSO are intermittent during the DC migration. Until cutover,
operations staff get to the box directly over SSH instead of through the portal:

    ssh {ctx.deploy_user}@{ctx.host}        # port 22, password auth still on
    password: {ctx.deploy_pass}             # temp, rotate after cutover (OPS-4471)

Once on the host:
  - app + config under /var/www/portal
  - sudo helper: /usr/local/bin/runbook
  - this edge box can reach corp services at *.{ctx.domain}

DO NOT email these creds. Delete this file before the box is repurposed.
-- {ctx.deploy_user}
"""


HTPASSWD = "deploy:$apr1$q2x9k1lm$Hn4pQvXkq0bFv3zJ8wq8K/\n"


def _backup_index(ctx: SiteContext) -> str:
    """Apache-style autoindex of a leaky /backup/ directory."""
    rows = [
        ("deploy_notes.txt", "2023-11-14 09:42", "1.1K"),
        ("portal_2023-11-13.sql.gz", "2023-11-13 02:00", "84M"),
        ("portal_src_backup.tar.gz", "2023-11-10 23:14", "27M"),
        ("id_rsa_deploy.bak", "2023-09-02 17:30", "2.6K"),
        (".htpasswd", "2023-08-19 11:05", "62"),
    ]
    items = ['<li><a href="../">Parent Directory</a></li>']
    for name, mtime, size in rows:
        items.append(f'<li><a href="/backup/{name}">{name}</a> &nbsp; {mtime} &nbsp; {size}</li>')
    return (
        "<!doctype html><html><head><title>Index of /backup</title></head><body>"
        "<h1>Index of /backup</h1><ul style='font-family:monospace'>"
        + "".join(items)
        + f"</ul><hr><address>Apache/2.4.49 (Ubuntu) Server at {ctx.host} Port 80</address></body></html>"
    )


def _server_status(ctx: SiteContext) -> str:
    """Fake mod_status page leaking internal vhosts and a deploy request line."""
    return f"""<!doctype html><html><head><title>Apache Status</title></head><body>
<h1>Apache Server Status for {ctx.host}</h1>
<dl>
<dt>Server Version: Apache/2.4.49 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3</dt>
<dt>Server uptime: 41 days 6 hours</dt>
<dt>Total accesses: 1884213 - Total Traffic: 58.1 GB</dt>
</dl>
<pre>
Srv  Client                 VHost                                   Request
0-0  10.10.0.41             portal.{ctx.domain}                     GET /login HTTP/1.1
1-0  198.51.100.23          www.{ctx.domain}                        GET / HTTP/1.1
2-0  10.10.0.53             status.{ctx.domain}                     GET /server-status HTTP/1.1
3-0  127.0.0.1              localhost                               POST /internal/deploy?user={ctx.deploy_user} HTTP/1.1
</pre>
<hr>
<address>Apache/2.4.49 (Ubuntu) Server at {ctx.host} Port 80</address>
</body></html>"""


def _phpinfo(ctx: SiteContext) -> str:
    return f"""<!doctype html><html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 7.4.3</h1>
<h2>Apache Environment</h2>
<table border="1" cellpadding="3">
<tr><td>SERVER_SOFTWARE</td><td>Apache/2.4.49 (Ubuntu) PHP/7.4.3</td></tr>
<tr><td>SERVER_NAME</td><td>{ctx.host}</td></tr>
<tr><td>DOCUMENT_ROOT</td><td>{ctx.docroot}</td></tr>
<tr><td>SSH_CONNECTION</td><td>10.10.0.41 51022 10.10.4.18 22</td></tr>
<tr><td>DEPLOY_SSH_USER</td><td>{ctx.deploy_user}</td></tr>
<tr><td>DEPLOY_SSH_PORT</td><td>22</td></tr>
</table>
<h2>Environment</h2>
<table border="1" cellpadding="3">
<tr><td>USER</td><td>www-data</td></tr>
<tr><td>HOME</td><td>/var/www</td></tr>
<tr><td>NOTE</td><td>SSO down — ops use direct ssh {ctx.deploy_user}@ (see /backup/deploy_notes.txt)</td></tr>
</table>
</body></html>"""


def _not_found(ctx: SiteContext, path: str) -> str:
    return _page(
        ctx, "404 Not Found",
        f"""<div class="card">
  <h1>404 — Not Found</h1>
  <p>The requested URL <code>{path}</code> was not found on this server.</p>
  <p class="muted">DocumentRoot: {ctx.docroot} — file does not exist. If you
  reached this from the staff portal, the migration may have moved it. Direct
  host access is documented in <code>/backup/deploy_notes.txt</code>.</p>
</div>""",
    )


def _forbidden(ctx: SiteContext, path: str) -> str:
    return _page(
        ctx, "403 Forbidden",
        f"""<div class="card">
  <h1>403 — Forbidden</h1>
  <p>You don't have permission to access <code>{path}</code> on this server.</p>
  <p class="muted">This artifact is restricted to the deploy account. Operators
  with host access (<code>ssh {ctx.deploy_user}@{ctx.host}</code>, port 22) can
  read it directly on disk under <code>/backup</code>.</p>
</div>""",
    )


def _service_unavailable(ctx: SiteContext, path: str) -> str:
    return _page(
        ctx, "503 Service Unavailable",
        f"""<div class="card">
  <h1>503 — Service Unavailable</h1>
  <p>The backend for <code>{path}</code> is offline during the data-center migration.</p>
  <p class="muted">Try again later, or use direct host access — see
  <code>/backup/deploy_notes.txt</code>.</p>
</div>""",
    )


class _DecoyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, logger: SessionLogger, site: SiteContext):
        super().__init__(addr, handler)
        self.honeypot_logger = logger
        self.site = site


class _DecoyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Spoof the Server: header for the EoL-stack illusion.
    def version_string(self) -> str:  # noqa: D401
        return SERVER_BANNER

    # Silence the default stderr access log; we log to JSONL instead.
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    @property
    def site(self) -> SiteContext:
        return self.server.site  # type: ignore[attr-defined]

    # ---- helpers ----
    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "?"

    def _log(self, status: int) -> None:
        logger: SessionLogger = self.server.honeypot_logger  # type: ignore[attr-defined]
        logger.log(
            "web",
            src=f"{self._client_ip()}:{self.client_address[1]}",
            method=self.command,
            path=self.path,
            status=status,
            ua=self.headers.get("User-Agent", ""),
            referer=self.headers.get("Referer", ""),
        )

    def _send(
        self,
        status: int,
        body: str | bytes,
        content_type: str = "text/html; charset=utf-8",
        log: bool = True,
    ) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)  # adds Server: (spoofed) + Date:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", POWERED_BY)
        # PHP-looking session cookie to reinforce the stack illusion.
        self.send_header("Set-Cookie", f"PHPSESSID={random.randbytes(13).hex()}; path=/")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        if log:
            self._log(status)

    # ---- routing ----
    def _route(self) -> None:
        ctx = self.site
        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if path == "/":
            self._send(200, _home(ctx))
        elif path in ("/login", "/admin", "/portal"):
            if self.command == "POST":
                # Broken login: "debug" stack trace leaking SSH deploy creds.
                self._send(500, _login_traceback(ctx))
            else:
                self._send(200, _login_page(ctx))
        elif path == "/robots.txt":
            self._send(200, ROBOTS, "text/plain; charset=utf-8")
        elif path == "/.env":
            self._send(200, _env_file(ctx), "text/plain; charset=utf-8")
        elif path == "/.git/config":
            self._send(200, _git_config(ctx), "text/plain; charset=utf-8")
        elif path in ("/backup", "/backup/"):
            self._send(200, _backup_index(ctx))
        elif path == "/backup/deploy_notes.txt":
            self._send(200, _deploy_notes(ctx), "text/plain; charset=utf-8")
        elif path == "/backup/.htpasswd":
            self._send(200, HTPASSWD, "text/plain; charset=utf-8")
        elif path.startswith("/backup/"):
            # The genuinely "juicy" artifacts are unreadable over HTTP — a
            # broken permission that nudges the attacker toward SSH instead.
            self._send(403, _forbidden(ctx, path))
        elif path == "/server-status":
            self._send(200, _server_status(ctx))
        elif path in ("/phpinfo.php", "/info.php"):
            self._send(200, _phpinfo(ctx))
        elif path == "/search":
            # Broken feature.
            self._send(500, _page(ctx, "500", '<div class="card"><h1>500 — Internal Server Error</h1>'
                                              '<p class="muted">search backend unavailable (PHP Fatal error).</p></div>'))
        elif path in ("/products", "/investors", "/careers", "/api", "/api/health"):
            # Dead nav / "migrated" endpoints.
            self._send(503, _service_unavailable(ctx, path))
        else:
            self._send(404, _not_found(ctx, path))

    def _safe_route(self) -> None:
        try:
            self._route()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            # Even our own errors stay in character as a broken app.
            try:
                self._send(500, _page(self.site, "500", '<div class="card"><h1>500 — Internal Server Error</h1></div>'))
            except Exception:
                pass

    def do_GET(self) -> None:
        self._safe_route()

    def do_POST(self) -> None:
        # Drain the request body so keep-alive stays in sync.
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length > 0:
                self.rfile.read(min(length, 1 << 16))
        except (ValueError, OSError):
            pass
        self._safe_route()

    def do_HEAD(self) -> None:
        self._safe_route()


def serve_decoy_web(host: str, port: int, logger: SessionLogger) -> None:
    """Bind the decoy web listener and serve forever (blocking).

    Intended to run in its own daemon thread. The company persona is chosen once
    per process (a website can't change identity per page load). A bind failure
    (e.g. port 80 without privileges, or already in use) is logged and swallowed
    so the SSH honeypot keeps running.
    """
    # The public web scope defaults to the fictional persona (lowest exposure);
    # override with HONEYPOT_COMPANY[_WEB]. See company.py.
    site = SiteContext.from_company(pick_company(scope="web"))
    try:
        httpd = _DecoyServer((host, port), _DecoyHandler, logger, site)
    except OSError as exc:
        logger.log("web_server_error", host=host, port=port, error=str(exc))
        return
    logger.log(
        "web_server_start", host=host, port=port, banner=SERVER_BANNER,
        company=site.name, decoy_host=site.host,
    )
    httpd.serve_forever()
