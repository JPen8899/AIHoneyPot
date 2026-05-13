"""Score attacker sophistication from observed commands and pick an env level.

The score is a rolling sum across a session. Each command bumps the score by a
weighted amount based on tier:

  Tier 0 (noise / typos)      : 0
  Tier 1 (basic recon)        : +1   ls, pwd, whoami, id, uname
  Tier 2 (enumeration)        : +2   ps, netstat, ss, find, cat /etc/passwd
  Tier 3 (privesc / creds)    : +4   sudo -l, suid finds, /etc/shadow, ssh keys
  Tier 4 (persistence/lateral): +6   crontab, systemd unit edits, ssh-keygen,
                                     scp/rsync to other hosts, nc reverse shells
  Tier 5 (anti-forensics)     : +8   history -c, log truncation, timestomp,
                                     shred, kernel module loading

The score maps to environment levels 1..5, each of which feeds a richer
backstory into the Claude system prompt. The simulated environment is themed
as **Meridian Global Industries** — a fictional Fortune 500 conglomerate —
so escalating attackers see breadcrumbs (SSO, AD, AWS Org, Splunk, multiple
subsidiaries) that mark the box as part of a large, valuable estate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Patterns are checked in order; first match wins. Mix of word-boundary tokens
# (commands) and raw substrings (paths starting with `/`).
_TIER_PATTERNS: list[tuple[int, re.Pattern]] = [
    # Tier 5 - anti-forensics
    (5, re.compile(
        r"history\s+-c|\bshred\b|\bwipe\b|timestomp|\btouch\s+-[adt]\b|"
        r":>\s*/var/log|truncate\s+-s\s*0\s*/var/log|"
        r"unset\s+HISTFILE|export\s+HISTFILE=/dev/null|"
        r"\binsmod\b|\bmodprobe\b"
    )),
    # Tier 4 - persistence / lateral movement
    (4, re.compile(
        r"\bcrontab\b|systemctl\s+(?:enable|edit)|"
        r"/etc/systemd/system|/etc/rc\.local|"
        r"authorized_keys|ssh-keygen|"
        r"\bscp\b|\brsync\b|"
        r"\bnc\s+-[lev]+|\bncat\s+|/dev/tcp/|"
        r"\bbash\s+-i|\bpython\s+-c\s+['\"].*socket"
    )),
    # Tier 3 - privesc / credentials
    (3, re.compile(
        r"sudo\s+-l|/etc/shadow|/etc/sudoers|"
        r"find\s+.*-perm\s+-?[24]\d{3}|\bgetcap\b|"
        r"\.ssh/id_|aws\s+configure|"
        r"docker\.sock|\bcapsh\b|"
        r"linpeas|linenum|pspy"
    )),
    # Tier 2 - enumeration
    (2, re.compile(
        r"\bps\b|\bnetstat\b|\bss\s|\blsof\b|"
        r"\bfind\s|\blocate\s|grep\s+-r|"
        r"/etc/passwd|/etc/group|/etc/hosts|"
        r"\bip\s+a|\bifconfig\b|\broute\b|\barp\b|"
        r"\bmount\b|\bdf\b|dpkg\s+-l|rpm\s+-qa|"
        r"crontab\s+-l|\benv\b|\bhistory\b"
    )),
    # Tier 1 - basic recon
    (1, re.compile(
        r"\bls\b|\bpwd\b|\bwhoami\b|\bid\b|\buname\b|\bhostname\b|"
        r"\bwho\b|\bw\b|\blast\b|\bdate\b|cat\s+/proc"
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


# Per-level "flavor" injected into the Claude system prompt. Higher level =
# more interesting-looking box, themed as a Fortune 500 conglomerate so a
# sophisticated actor sees clear breadcrumbs of a large enterprise estate.
#
# Fictional company: "Meridian Global Industries" (MGI) — Fortune-100-scale,
# 90k employees, multiple subsidiaries, AWS + Azure footprint, Okta SSO,
# Splunk, CrowdStrike, Active Directory.
LEVEL_PROFILES = {
    1: {
        "hostname": "mgi-web-edge-01.corp.meridianglobal.com",
        "summary": (
            "Public-facing marketing edge node for Meridian Global Industries (MGI). "
            "Hardened Ubuntu 22.04 behind the corporate WAF. Looks plain but the "
            "MOTD references the internal CMDB and the company's compliance stack."
        ),
        "users": ["ubuntu", "mgi-deploy"],
        "interesting_files": [
            "/etc/motd (mentions 'Meridian Global Industries — Property of MGI, monitored by CrowdStrike Falcon')",
            "/etc/issue.net (Meridian Global Industries — Authorized use only)",
        ],
        "services": ["nginx (serving www.meridianglobal.com)", "falcon-sensor (CrowdStrike, status: running)"],
        "network": (
            "Single public NIC; resolves *.corp.meridianglobal.com via 10.10.0.53 "
            "(internal DNS) — but most internal nets are firewalled off from this DMZ host."
        ),
        "indicators": [
            "MOTD names the parent corporation",
            "CrowdStrike Falcon sensor present",
            "Internal DNS resolves *.corp.meridianglobal.com",
        ],
    },
    2: {
        "hostname": "mgi-app-prod-12.corp.meridianglobal.com",
        "summary": (
            "Production application node, part of MGI's Customer Platform (one of 14 "
            "internal product lines). Runs a Node.js service that talks to internal "
            "APIs in the corp network. Splunk forwarder is sending logs to SIEM."
        ),
        "users": ["ubuntu", "mgi-deploy", "mgi-appsvc", "j.morales", "a.patel"],
        "interesting_files": [
            "/etc/hosts (entries for okta-agent, splunk-hf-01, vault-prod, ad-dc-01)",
            "/opt/mgi-customer-platform/.env (DB_HOST=pgsql-prod-cust.corp.meridianglobal.com, OKTA_ORG=meridianglobal)",
            "/var/log/splunkforwarder.log (forwarding to splunk-idx-east.corp.meridianglobal.com:9997)",
            "/etc/mgi/cmdb-tags.yaml (business_unit: 'Meridian Financial Services', cost_center: 'CC-44120', data_class: 'Restricted')",
        ],
        "services": [
            "nginx",
            "node app (mgi-customer-platform on :3000)",
            "SplunkForwarder",
            "okta-aws-cli (configured)",
        ],
        "network": (
            "10.40.0.0/16 (Customer Platform VPC), gateway to 10.10.0.0/16 (corp services) "
            "and 10.50.0.0/16 (data lake). Resolves *.corp.meridianglobal.com."
        ),
        "indicators": [
            "Splunk Forwarder to corporate SIEM",
            "Okta SSO references in env vars",
            "CMDB tag 'Meridian Financial Services' (named subsidiary)",
            "Data class 'Restricted' in CMDB tags",
        ],
    },
    3: {
        "hostname": "mgi-ci-build-04.corp.meridianglobal.com",
        "summary": (
            "Internal CI/build runner for MGI Platform Engineering. Caches deployment "
            "artifacts for the entire customer-platform org. The Jenkins agent runs as "
            "a service account that holds OIDC creds to AWS via Okta."
        ),
        "users": ["ubuntu", "mgi-deploy", "jenkins", "mgi-builder", "p.washington", "k.shen"],
        "interesting_files": [
            "/home/jenkins/.aws/credentials (profile=mgi-platform-build, looks real but starts AKIAFAKE...)",
            "/home/jenkins/.aws/config (region=us-east-1; sso_session=mgi-okta; sso_start_url=https://meridianglobal.okta.com/home/amazon_aws_sso/...)",
            "/opt/mgi-ci/secrets.env (GHE_TOKEN=ghp_FAKE..., ARTIFACTORY_KEY=AKCp..., SNYK_TOKEN=...)",
            "/var/lib/jenkins/jobs/ (mgi-cust-platform, mgi-fin-svc-ledger, mgi-energy-scada-fw, mgi-retail-pos — multiple subsidiary repos)",
            "/etc/krb5.conf (default_realm = CORP.MERIDIANGLOBAL.COM; kdc = ad-dc-01.corp.meridianglobal.com)",
        ],
        "services": [
            "docker (member of docker group)",
            "jenkins agent (connected to ci.corp.meridianglobal.com)",
            "okta-aws-cli",
            "falcon-sensor",
        ],
        "network": (
            "10.10.0.0/16 (corp), 10.40.0.0/16 (CustPlat), 10.60.0.0/16 (CI/build), 10.70.0.0/16 (Artifactory). "
            "DNS shows: artifactory.corp.meridianglobal.com, ghe.corp.meridianglobal.com, splunk-search.corp.meridianglobal.com."
        ),
        "indicators": [
            "Multiple subsidiary repo names visible (Meridian Financial Services, Meridian Energy, Meridian Retail)",
            "Kerberos config pointing at corp Active Directory",
            "Okta SSO -> AWS federation hint",
            "GHE (GitHub Enterprise) token and Artifactory credentials",
        ],
    },
    4: {
        "hostname": "mgi-bastion-east-02.corp.meridianglobal.com",
        "summary": (
            "Eastern-region bastion / jump host for MGI Cloud Operations. Carries SSH "
            "trust into the entire 10.0.0.0/8 corp estate, including DBs, k8s, and "
            "the corporate vault cluster. Used daily by the Tier-2 SRE rotation."
        ),
        "users": [
            "ubuntu", "mgi-ops", "mgi-secops", "mgi-dba", "mgi-platform",
            "r.okafor (SRE Lead)", "v.dimitrov (SecOps)", "intern.summer25",
        ],
        "interesting_files": [
            "/home/mgi-ops/.ssh/id_rsa (passphraseless — flagged in last audit)",
            "/home/mgi-ops/.ssh/known_hosts (db-prod-cust-01, db-prod-fin-01, vault-east-01, "
            "k8s-master-east-01, ad-dc-01, ad-dc-02, splunk-idx-east-01..04, okta-agent-01)",
            "/etc/sudoers.d/mgi-ops (NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl, /usr/local/bin/mgi-runbook)",
            "/var/log/auth.log (heavy traffic — corp-wide jump traffic)",
            "/etc/mgi/runbook-index.md (refs to 'Meridian Financial Services SOX environment', "
            "'Meridian Energy ICS DMZ jump path', 'Meridian Retail PCI scope')",
            "/opt/mgi/cmdb-export.json (lists 12,400 hosts across 9 subsidiaries)",
        ],
        "services": [
            "sshd (with corp CA trust)",
            "mosh-server",
            "tailscale (corp tenant)",
            "node_exporter -> prometheus.corp.meridianglobal.com",
            "falcon-sensor",
            "okta-verify-agent",
        ],
        "network": (
            "Full 10.0.0.0/8 reachable. Resolvable: vault-east-01.corp.meridianglobal.com, "
            "k8s-master-east-01.corp.meridianglobal.com, ad-dc-01.corp.meridianglobal.com, "
            "splunk-idx-east-01.corp.meridianglobal.com, pgsql-prod-cust.corp.meridianglobal.com, "
            "pgsql-prod-fin.corp.meridianglobal.com, scada-dmz-jump.energy.meridianglobal.com."
        ),
        "indicators": [
            "12,400-host CMDB export visible — clearly enterprise-scale",
            "Multiple compliance scopes named (SOX, PCI, ICS)",
            "References to Meridian Financial Services, Meridian Energy, Meridian Retail subsidiaries",
            "Active Directory DCs in known_hosts",
            "Corp Splunk indexers in known_hosts",
        ],
    },
    5: {
        "hostname": "mgi-vault-broker-east-01.corp.meridianglobal.com",
        "summary": (
            "Crown-jewel host: privileged broker that holds Vault unseal material for "
            "the eastern corporate Vault cluster, talks to k8s control planes, and "
            "stores break-glass cloud admin credentials for MGI's AWS Organization "
            "(450+ accounts) and Azure tenant. Highly tempting target."
        ),
        "users": [
            "ubuntu", "mgi-ops", "mgi-secops",
            "vaultadmin (member of vault-unseal-quorum-east)",
            "k8sadmin (cluster-admin on prod-east-01)",
            "clouddev (break-glass IAM)",
            "c.iyengar (CISO staff)",
        ],
        "interesting_files": [
            "/root/.vault-token (root token for vault-east.corp.meridianglobal.com)",
            "/root/unseal/keys.txt (5 base64 unseal shards — Shamir 3-of-5)",
            "/home/clouddev/.aws/credentials "
            "(profile mgi-org-master, looks real but AKIAFAKE..., notes: 'BREAK-GLASS — AWS Organization root, "
            "450+ member accounts')",
            "/home/k8sadmin/.kube/config (clusters: prod-east-01, prod-east-02, prod-west-01, "
            "energy-scada-east, fin-pci-east — cluster-admin context on each)",
            "/opt/secrets/db-master.pgpass (entries for fin-ledger-prod, customer-prod, retail-pos-prod)",
            "/opt/secrets/okta-api-token.txt (Super Admin scope, tenant: meridianglobal.okta.com)",
            "/opt/secrets/azure-sp.json (Owner on mgt-group 'meridian-tenant-root')",
            "/var/log/wtmp (heavily edited — gap from last week)",
            "/etc/mgi/run-charter.md ('This host is the eastern half of the Vault unseal "
            "quorum for Meridian Global Industries. Loss of this host triggers IR-SEV1.')",
        ],
        "services": [
            "vault (active, sealed=false)",
            "consul agent (corp datacenter east)",
            "kubelet (decommissioned but bin present)",
            "step-ca",
            "okta-aws-cli",
            "azure-cli (logged in as service principal)",
            "falcon-sensor",
        ],
        "network": (
            "Full 10.0.0.0/8 + 172.16.0.0/12 reachable. Direct routes to: "
            "vault-east.corp.meridianglobal.com, vault-west.corp.meridianglobal.com, "
            "k8s-master-{east,west}-0{1,2,3}.corp.meridianglobal.com, "
            "ad-forest-root.corp.meridianglobal.com, "
            "splunk-search.corp.meridianglobal.com, "
            "okta-agent-{01,02}.corp.meridianglobal.com, "
            "aws-org-master-vpce.us-east-1.amazonaws.com (interface endpoint), "
            "azure-tenant-root.privatelink.meridianglobal.com."
        ),
        "indicators": [
            "Run charter explicitly states this is a Vault unseal quorum host for MGI",
            "AWS Organization root credentials present (450+ accounts)",
            "Azure tenant root SP credentials present",
            "Okta Super Admin API token present",
            "k8s cluster-admin across 5 prod clusters (incl. PCI and ICS scoped)",
            "wtmp shows tampering (CISO-staff user)",
        ],
    },
}


def profile_for_level(level: int) -> dict:
    return LEVEL_PROFILES[max(1, min(5, level))]
