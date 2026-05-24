"""Score attacker sophistication from observed commands and pick an env level.

The score is a rolling sum across a session. Each command bumps the score by a
weighted amount based on the highest-matching tier:

  Tier 0 (noise / typos)        : 0
  Tier 1 (basic recon)          : +1   ls, pwd, whoami, id, uname, systeminfo
  Tier 2 (enumeration)          : +2   nmap, enum4linux, smbclient, gobuster,
                                       feroxbuster, ffuf, ldapsearch, net user,
                                       kerbrute, /etc/passwd
  Tier 3 (privesc / cred recon) : +4   sudo -l, suid finds, winPEAS/linPEAS,
                                       PowerUp, Seatbelt, pspy, BloodHound,
                                       SharpHound, PowerView, GPP/cpassword,
                                       pkexec/dirtypipe, .aws/credentials
  Tier 4 (cred theft / lateral) : +6   impacket (psexec/wmiexec/secretsdump),
                                       evil-winrm, crackmapexec/nxc/netexec,
                                       responder, ntlmrelayx, mimikatz, Rubeus,
                                       kerberoast/asreproast, chisel/ligolo,
                                       msfvenom/meterpreter, schtasks persistence
  Tier 5 (domain dominance /    : +8   DCSync (secretsdump -just-dc, lsadump::
          anti-forensics)              dcsync), golden ticket, ntds.dit/ntdsutil,
                                       wevtutil cl / Clear-EventLog, vssadmin
                                       delete, history -c, shred, timestomp

Patterns are grounded in the operator's own OSCP/red-team notes, so the rubric
recognizes the tradecraft they actually expect to see. The score maps to
environment levels 1..5, each of which feeds a richer backstory into the Claude
system prompt — built per session for a randomly chosen real Fortune-100
company (see `company.py`) so escalating attackers see breadcrumbs (SSO, AD,
AWS Org, Splunk, named subsidiaries) marking the box as part of a large estate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .company import Company

# Patterns are checked in tier-descending order; FIRST match wins, so when a
# command matches multiple tiers it scores as the most dangerous one. Compiled
# case-insensitive because offensive tooling is typed with wildly varying case
# (Rubeus, SharpHound, Invoke-Mimikatz, GetUserSPNs.py, winPEASx64.exe, ...).
_TIER_PATTERNS: list[tuple[int, re.Pattern]] = [
    # Tier 5 - domain dominance / destructive / anti-forensics
    (5, re.compile(
        # DCSync & domain credential extraction
        r"lsadump::dcsync|\bdcsync\b|secretsdump(?:\.py)?[^\n]*--?just-dc|"
        r"\bntdsutil\b|\bntds\.dit\b|\bvss(?:admin)?\b[^\n]*\b(?:create|copy|delete)\b|"
        # Ticket forgery / domain persistence
        r"kerberos::golden|kerberos::silver|\bgolden[\s_-]?ticket\b|\bsilver[\s_-]?ticket\b|"
        r"misc::skeleton|\bdcshadow\b|"
        # Log clearing / anti-forensics
        r"wevtutil\s+cl|clear-?eventlog|remove-?eventlog|auditpol\s+/(clear|set)|"
        r"fsutil\s+usn\s+deletejournal|\bsdelete\b|cipher\s+/w|"
        r"history\s+-c|\bshred\b|\bwipe\b|timestomp|\btouch\s+-[adt]\b|"
        r":>\s*/var/log|truncate\s+-s\s*0\s*/var/log|\b/var/log/(wtmp|btmp|auth\.log)\b[^\n]*\b(rm|truncate|>)|"
        r"unset\s+HISTFILE|export\s+HISTFILE=/dev/null|"
        r"\binsmod\b|\bmodprobe\b",
        re.IGNORECASE,
    )),
    # Tier 4 - credential theft / lateral movement / persistence / C2
    (4, re.compile(
        # Impacket remote-exec & dumping
        r"\bimpacket-|\b(?:psexec|wmiexec|smbexec|atexec|dcomexec|secretsdump|reg|services|"
        r"mssqlclient|getuserspns|getnpusers|ticketer|getst)\.py\b|"
        r"\bsecretsdump\b|\bntlmrelayx\b|\bmitm6\b|\bresponder\b|"
        # Kerberos roasting / abuse
        r"\brubeus\b|\bgetuserspns\b|\bgetnpusers\b|kerberoast|asrep(?:roast)?|\boverpass-?the-?hash\b|\bpass-?the-?(hash|ticket)\b|"
        # Cred dumping on host
        r"\bmimikatz\b|sekurlsa|lsadump|\bprocdump\b[^\n]*lsass|comsvcs\.dll[^\n]*minidump|"
        r"reg\s+save\s+hk(?:lm|cu)\\?\s*\\?(?:sam|system|security)|"
        # Lateral exec / spraying
        r"\bevil-winrm\b|enter-pssession|invoke-command|\bwinrs\b|"
        r"\bcrackmapexec\b|\bnetexec\b|\bnxc\b|\bcme\b|--hashes\b|-H\s+[0-9a-fA-F:]{32}|"
        r"\bsmbexec\b|"
        # Tunneling / pivoting / payloads / C2
        r"\bchisel\b|\bligolo\b|\bsshuttle\b|\bproxychains\b|\bsocat\b|ssh\s+-[DLR]\b|plink[^\n]*-R|"
        r"\bmsfvenom\b|\bmeterpreter\b|msfconsole|cobalt\s*strike|\bbeacon\b|"
        # Persistence
        r"\bcrontab\s+-[er]\b|systemctl\s+(?:enable|edit)|/etc/systemd/system|/etc/rc\.local|"
        r"authorized_keys|ssh-keygen|schtasks\s+/create|register-scheduledtask|\bnew-service\b|sc(?:\.exe)?\s+create|reg\s+add[^\n]*\\run|"
        # Classic reverse shells / transfer
        r"\bscp\b|\brsync\b|\bnc\s+-[lev]+|\bncat\b|/dev/tcp/|\bbash\s+-i|python[0-9]?\s+-c\s+['\"][^\n]*socket",
        re.IGNORECASE,
    )),
    # Tier 3 - privesc / credential discovery / AD recon tooling
    (3, re.compile(
        # Local privesc enum frameworks (substrings tolerate winPEASx64, pspy64, .ps1, .exe suffixes)
        r"winpeas|linpeas|\blinenum\b|\bpowerup\b|\bseatbelt\b|\bjaws\b|"
        r"\bpspy\w*|\baccesschk\b|linux-exploit-suggester|\bles\.sh\b|\bgtfobins?\b|\blolbas\b|adpeas|"
        # AD situational awareness
        r"\bbloodhound\b|\bsharphound\b|\bpowerview\b|\bplumhound\b|adidnsdump|"
        r"get-net(?:user|group|computer|domain|localgroup|share)|"
        r"get-domain(?:user|group|computer|controller|trust|policy|sid)?\b|"
        r"find-localadminaccess|invoke-(?:sharefinder|userhunter|kerberoast)|"
        # Privesc primitives / kernel exploits
        r"sudo\s+-l|/etc/shadow|/etc/sudoers|find\s+[^\n]*-perm\s+-?[24]\d{3}|"
        r"\bgetcap\b|\bpkexec\b|dirty[\s_]?(?:cow|pipe)|dirtypipe|\bcapsh\b|docker\.sock|"
        # Stored credentials / secrets at rest
        r"\.ssh/id_|\.aws/credentials|aws\s+configure|unattend\.xml|sysprep\.(?:xml|inf)|"
        r"groups\.xml|\bcpassword\b|\bgpp\b|web\.config|\.pgpass|\.kdbx\b|vault\s+(?:login|read|kv|token)",
        re.IGNORECASE,
    )),
    # Tier 2 - enumeration (network / service / web / directory)
    (2, re.compile(
        # Host/process/network state
        r"\bps\b|\bnetstat\b|\bss\s|\blsof\b|\bfind\s|\blocate\s|grep\s+-r|"
        r"/etc/passwd|/etc/group|/etc/hosts|\bip\s+a\b|\bifconfig\b|\broute\b|\barp\b|"
        r"\bmount\b|\bdf\b|dpkg\s+-l|rpm\s+-qa|crontab\s+-l|\benv\b|\bhistory\b|"
        r"\bsysteminfo\b|ipconfig\s+/all|\btasklist\b|wmic\s+(?:qfe|product|service|process)|"
        # Port / host scanning
        r"\bnmap\b|\bmasscan\b|\brustscan\b|\bnaabu\b|\bnbtscan\b|\bnmblookup\b|"
        # SMB / RPC / LDAP enumeration
        r"\benum4linux\b|\bsmbclient\b|\bsmbmap\b|\brpcclient\b|\bshowmount\b|"
        r"\bldapsearch\b|ldapdomaindump|\bwindapsearch\b|"
        # Web / directory / vuln enumeration
        r"\bgobuster\b|\bferoxbuster\b|\bffuf\b|\bdirb\b|dirbuster|\bwfuzz\b|\bnikto\b|"
        r"\bwhatweb\b|\bwpscan\b|\bsqlmap\b|\bnuclei\b|gowitness|"
        # User / domain enumeration
        r"\bkerbrute\b|\bsetspn\b|\bdsquery\b|\bnltest\b|"
        r"net\s+(?:user|group|localgroup|view|share|accounts)\b|"
        r"get-ad(?:user|group|computer|domain)|whoami\s+/(?:priv|groups|all)|\bklist\b|query\s+session|qwinsta",
        re.IGNORECASE,
    )),
    # Tier 1 - basic recon
    (1, re.compile(
        r"\bls\b|\bpwd\b|\bwhoami\b|\bid\b|\buname\b|\bhostname\b|"
        r"\bwho\b|\bw\b|\blast\b|\bdate\b|\buptime\b|cat\s+/proc|"
        r"\bver\b|echo\s+%\w+%",
        re.IGNORECASE,
    )),
]

_TIER_WEIGHTS = {1: 1, 2: 2, 3: 4, 4: 6, 5: 8}


@dataclass
class SophisticationTracker:
    score: int = 0
    counts: dict[int, int] = field(default_factory=lambda: {i: 0 for i in range(1, 6)})
    last_tier: int = 0

    def observe(self, command: str) -> int:
        """Update the score for one command. Returns the tier that matched (0 if none)."""
        cmd = command.strip()
        if not cmd:
            return 0
        for tier, pattern in _TIER_PATTERNS:
            if pattern.search(cmd):
                self.counts[tier] += 1
                self.score += _TIER_WEIGHTS[tier]
                self.last_tier = tier
                return tier
        self.last_tier = 0
        return 0

    @property
    def level(self) -> int:
        """Map cumulative score to env level 1..5."""
        s = self.score
        if s < 3:
            return 1
        if s < 8:
            return 2
        if s < 18:
            return 3
        if s < 35:
            return 4
        return 5

    def snapshot(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "counts": dict(self.counts),
            "last_tier": self.last_tier,
        }


def clamp_level(level: int) -> int:
    return max(1, min(5, level))


# Per-level "flavor" injected into the Claude system prompt, built fresh for a
# given company persona. Higher level = more interesting-looking box. The
# structure mirrors a real enterprise estate so a sophisticated actor sees clear
# breadcrumbs (SSO/Okta, Active Directory, AWS Organization, Splunk SIEM,
# CrowdStrike, named subsidiaries) marking the host as part of a large company.
def build_profiles(c: Company) -> dict[int, dict]:
    dom = c.corp_domain
    realm = c.realm
    okta = c.okta_org
    subs = c.subsidiaries or [f"{c.name} Group"]

    def sub(i: int) -> str:
        return subs[i % len(subs)]

    return {
        1: {
            "hostname": c.host("web-edge-01"),
            "summary": (
                f"Public-facing marketing edge node for {c.name} ({c.ticker}). "
                "Hardened Ubuntu 22.04 behind the corporate WAF. Looks plain but "
                "the MOTD references the internal CMDB and the company's compliance stack."
            ),
            "users": ["ubuntu", c.user("deploy")],
            "interesting_files": [
                f"/etc/motd (mentions '{c.name} — Authorized use only, monitored by CrowdStrike Falcon')",
                f"/etc/issue.net ({c.name} — property of {c.name}, authorized use only)",
            ],
            "services": [f"nginx (serving www.{c.domain})", "falcon-sensor (CrowdStrike, status: running)"],
            "network": (
                f"Single public NIC; resolves *.{dom} via 10.10.0.53 (internal DNS) — "
                "but most internal nets are firewalled off from this DMZ host."
            ),
            "indicators": [
                f"MOTD names the parent corporation ({c.name})",
                "CrowdStrike Falcon sensor present",
                f"Internal DNS resolves *.{dom}",
            ],
        },
        2: {
            "hostname": c.host("app-prod-12"),
            "summary": (
                f"Production application node, part of {c.name}'s customer platform. "
                "Runs a Node.js service that talks to internal APIs in the corp "
                "network. Splunk forwarder is shipping logs to the SIEM."
            ),
            "users": ["ubuntu", c.user("deploy"), c.user("appsvc"), "j.morales", "a.patel"],
            "interesting_files": [
                f"/etc/hosts (entries for okta-agent, splunk-hf-01, vault-prod, ad-dc-01.{dom})",
                f"/opt/app/.env (DB_HOST=pgsql-prod-cust.{dom}, OKTA_ORG={okta})",
                f"/var/log/splunkforwarder.log (forwarding to {c.slug}-splunk-idx-east.{dom}:9997)",
                f"/etc/cmdb-tags.yaml (business_unit: '{sub(0)}', cost_center: 'CC-44120', data_class: 'Restricted')",
            ],
            "services": ["nginx", "node app (customer-platform on :3000)", "SplunkForwarder", "okta-aws-cli (configured)"],
            "network": (
                f"10.40.0.0/16 (Customer Platform VPC), gateway to 10.10.0.0/16 (corp services) "
                f"and 10.50.0.0/16 (data lake). Resolves *.{dom}."
            ),
            "indicators": [
                "Splunk Forwarder to corporate SIEM",
                f"Okta SSO references in env vars (org {okta})",
                f"CMDB tag '{sub(0)}' (named business unit)",
                "Data class 'Restricted' in CMDB tags",
            ],
        },
        3: {
            "hostname": c.host("ci-build-04"),
            "summary": (
                f"Internal CI/build runner for {c.name} Platform Engineering. Caches "
                "deployment artifacts for the customer-platform org. The Jenkins agent "
                "runs as a service account holding OIDC creds to AWS via Okta."
            ),
            "users": ["ubuntu", c.user("deploy"), "jenkins", c.user("builder"), "p.washington", "k.shen"],
            "interesting_files": [
                f"/home/jenkins/.aws/credentials (profile={c.slug}-platform-build, looks real but starts AKIAFAKE...)",
                f"/home/jenkins/.aws/config (region=us-east-1; sso_session={c.slug}-okta; sso_start_url=https://{okta}/home/amazon_aws_sso/...)",
                "/opt/ci/secrets.env (GHE_TOKEN=ghp_FAKE..., ARTIFACTORY_KEY=AKCp..., SNYK_TOKEN=...)",
                f"/var/lib/jenkins/jobs/ ({c.slug}-cust-platform, {c.slug}-{_token(sub(0))}, {c.slug}-{_token(sub(1))} — multiple subsidiary repos)",
                f"/etc/krb5.conf (default_realm = {realm}; kdc = ad-dc-01.{dom})",
            ],
            "services": [
                "docker (member of docker group)",
                f"jenkins agent (connected to ci.{dom})",
                "okta-aws-cli",
                "falcon-sensor",
            ],
            "network": (
                f"10.10.0.0/16 (corp), 10.40.0.0/16 (CustPlat), 10.60.0.0/16 (CI/build), 10.70.0.0/16 (Artifactory). "
                f"DNS shows: artifactory.{dom}, ghe.{dom}, splunk-search.{dom}."
            ),
            "indicators": [
                f"Multiple subsidiary repo names visible ({sub(0)}, {sub(1)})",
                "Kerberos config pointing at corp Active Directory",
                "Okta SSO -> AWS federation hint",
                "GHE (GitHub Enterprise) token and Artifactory credentials",
            ],
        },
        4: {
            "hostname": c.host("bastion-east-02"),
            "summary": (
                f"Eastern-region bastion / jump host for {c.name} Cloud Operations. "
                "Carries SSH trust into the entire 10.0.0.0/8 corp estate, including "
                "DBs, k8s, and the corporate vault cluster. Used daily by the Tier-2 SRE rotation."
            ),
            "users": [
                "ubuntu", c.user("ops"), c.user("secops"), c.user("dba"), c.user("platform"),
                "r.okafor (SRE Lead)", "v.dimitrov (SecOps)", "intern.summer25",
            ],
            "interesting_files": [
                f"/home/{c.user('ops')}/.ssh/id_rsa (passphraseless — flagged in last audit)",
                f"/home/{c.user('ops')}/.ssh/known_hosts (db-prod-cust-01, db-prod-fin-01, vault-east-01, "
                f"k8s-master-east-01, ad-dc-01, ad-dc-02, {c.slug}-splunk-idx-east-01..04, okta-agent-01 — all .{dom})",
                f"/etc/sudoers.d/{c.user('ops')} (NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl, /usr/local/bin/runbook)",
                "/var/log/auth.log (heavy traffic — corp-wide jump traffic)",
                f"/etc/runbook-index.md (refs to '{sub(0)} SOX environment', '{sub(1)} ICS DMZ jump path', '{sub(2)} PCI scope')",
                f"/opt/cmdb-export.json (lists 12,400 hosts across {len(subs)} business units)",
            ],
            "services": [
                "sshd (with corp CA trust)", "mosh-server", "tailscale (corp tenant)",
                f"node_exporter -> prometheus.{dom}", "falcon-sensor", "okta-verify-agent",
            ],
            "network": (
                f"Full 10.0.0.0/8 reachable. Resolvable: vault-east-01.{dom}, k8s-master-east-01.{dom}, "
                f"ad-dc-01.{dom}, {c.slug}-splunk-idx-east-01.{dom}, pgsql-prod-cust.{dom}, pgsql-prod-fin.{dom}."
            ),
            "indicators": [
                "12,400-host CMDB export visible — clearly enterprise-scale",
                "Multiple compliance scopes named (SOX, PCI, ICS)",
                f"References to {sub(0)}, {sub(1)}, {sub(2)} business units",
                "Active Directory DCs in known_hosts",
                "Corp Splunk indexers in known_hosts",
            ],
        },
        5: {
            "hostname": c.host("vault-broker-east-01"),
            "summary": (
                f"Crown-jewel host: privileged broker that holds Vault unseal material for "
                f"the eastern corporate Vault cluster, talks to k8s control planes, and stores "
                f"break-glass cloud admin credentials for {c.name}'s AWS Organization "
                f"({c.aws_accounts}+ accounts) and Azure tenant. Highly tempting target."
            ),
            "users": [
                "ubuntu", c.user("ops"), c.user("secops"),
                "vaultadmin (member of vault-unseal-quorum-east)",
                "k8sadmin (cluster-admin on prod-east-01)",
                "clouddev (break-glass IAM)",
                "c.iyengar (CISO staff)",
            ],
            "interesting_files": [
                f"/root/.vault-token (root token for vault-east.{dom})",
                "/root/unseal/keys.txt (5 base64 unseal shards — Shamir 3-of-5)",
                f"/home/clouddev/.aws/credentials (profile {c.slug}-org-master, looks real but AKIAFAKE..., "
                f"notes: 'BREAK-GLASS — AWS Organization root, {c.aws_accounts}+ member accounts')",
                "/home/k8sadmin/.kube/config (clusters: prod-east-01, prod-east-02, prod-west-01, "
                f"{_token(sub(0))}-east, {_token(sub(1))}-east — cluster-admin context on each)",
                f"/opt/secrets/db-master.pgpass (entries for fin-ledger-prod, customer-prod, {_token(sub(0))}-prod)",
                f"/opt/secrets/okta-api-token.txt (Super Admin scope, tenant: {okta})",
                "/opt/secrets/azure-sp.json (Owner on mgt-group 'tenant-root')",
                "/var/log/wtmp (heavily edited — gap from last week)",
                f"/etc/run-charter.md ('This host is the eastern half of the Vault unseal quorum for "
                f"{c.name}. Loss of this host triggers IR-SEV1.')",
            ],
            "services": [
                "vault (active, sealed=false)", "consul agent (corp datacenter east)",
                "kubelet (decommissioned but bin present)", "step-ca", "okta-aws-cli",
                "azure-cli (logged in as service principal)", "falcon-sensor",
            ],
            "network": (
                f"Full 10.0.0.0/8 + 172.16.0.0/12 reachable. Direct routes to: vault-east.{dom}, "
                f"vault-west.{dom}, k8s-master-east-01.{dom}, ad-forest-root.{dom}, splunk-search.{dom}, "
                f"okta-agent-01.{dom}, aws-org-master-vpce.us-east-1.amazonaws.com, "
                f"azure-tenant-root.privatelink.{c.domain}."
            ),
            "indicators": [
                f"Run charter explicitly states this is a Vault unseal quorum host for {c.name}",
                f"AWS Organization root credentials present ({c.aws_accounts}+ accounts)",
                "Azure tenant root SP credentials present",
                f"Okta Super Admin API token present (tenant {okta})",
                "k8s cluster-admin across 5 prod clusters (incl. PCI and ICS scoped)",
                "wtmp shows tampering (CISO-staff user)",
            ],
        },
    }


def _token(s: str) -> str:
    """Compress a brand/subsidiary name into a hostname-safe token."""
    import re as _re
    return _re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:18] or "biz"
