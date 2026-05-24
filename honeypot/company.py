"""Real Fortune-100 company personas the honeypot can impersonate.

The SSH session (and the decoy website) adopt a persona so the simulated estate
reads as a specific large enterprise — hostnames, corp domain, SSO org, named
subsidiaries, AWS Org scale, etc. The richer the persona, the more a
sophisticated attacker is tempted to keep digging, which is exactly the
telemetry we want.

⚠️ LEGAL / ETHICAL NOTE — and why the two surfaces default differently
    These are REAL company names used as deception props. Every host, IP,
    credential, and secret the honeypot derives from them is entirely
    fabricated — none of it belongs to or comes from the real company.

    The exposure is NOT equal across the two surfaces:
      * The decoy WEBSITE (port 80) is unauthenticated and public — it
        broadcasts the brand to crawlers/scanners and could be indexed or
        flagged as phishing impersonating the company. Highest risk, so it
        defaults to the made-up "Meridian Global Industries" persona.
      * The SSH SHELL (port 22) only reveals the persona AFTER an intruder
        connects to an "authorized use only" service and authenticates. It is
        not broadcast or indexable — much lower public-impersonation profile,
        so it defaults to a random real Fortune-100 company. (Still: a demo
        screenshot of a "real company breach" can be reputationally awkward.)

Selection — per-scope vars override the global one, which overrides the
per-scope default:
    HONEYPOT_COMPANY_SSH / HONEYPOT_COMPANY_WEB   scope-specific override
    HONEYPOT_COMPANY                              global override (both scopes)
    (default)                                     ssh -> "random", web -> "fictional"

Each value may be:
    "random"     -> a random Fortune-100 persona (SSH picks per session)
    "fictional"  -> the made-up Meridian Global Industries persona
    "<slug>"     -> pin a specific entry (e.g. "microsoft"; case-insensitive)
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Company:
    name: str            # display name, e.g. "Walmart Inc."
    slug: str            # lowercase token for hostnames, e.g. "walmart"
    ticker: str          # stock ticker, e.g. "WMT"
    industry: str        # one-line industry
    hq: str              # headquarters city, state
    domain: str          # base corp domain, e.g. "walmart.com"
    subsidiaries: list[str] = field(default_factory=list)  # real brands / business units
    employees: str = "tens of thousands"
    aws_accounts: int = 200
    fictional: bool = False

    # --- derived helpers (used by profile + decoy builders) ---
    @property
    def corp_domain(self) -> str:
        return f"corp.{self.domain}"

    @property
    def realm(self) -> str:
        return self.corp_domain.upper()

    @property
    def okta_org(self) -> str:
        return f"{self.slug}.okta.com"

    def host(self, role: str) -> str:
        return f"{self.slug}-{role}.{self.corp_domain}"

    def user(self, role: str) -> str:
        return f"{self.slug}-{role}"


# Curated Fortune-100 set with reasonably accurate, public metadata and a few
# well-known brands / business units per company. Subsidiary lists are kept to
# recognizable public brands; nothing here is internal or sensitive.
COMPANIES: list[Company] = [
    Company("Walmart Inc.", "walmart", "WMT", "Retail / e-commerce", "Bentonville, AR",
            "walmart.com", ["Sam's Club", "Walmart Health", "Walmart Connect", "Flipkart"],
            "2.1 million", 600),
    Company("Amazon.com, Inc.", "amazon", "AMZN", "E-commerce / cloud computing", "Seattle, WA",
            "amazon.com", ["Amazon Web Services", "Whole Foods Market", "Twitch", "Ring", "Audible", "Zappos"],
            "1.5 million", 900),
    Company("Apple Inc.", "apple", "AAPL", "Consumer electronics", "Cupertino, CA",
            "apple.com", ["Beats Electronics", "Claris", "Apple Studios", "Shazam"],
            "160,000", 300),
    Company("UnitedHealth Group", "uhg", "UNH", "Healthcare / insurance", "Minnetonka, MN",
            "uhg.com", ["Optum", "UnitedHealthcare", "Change Healthcare", "OptumRx"],
            "440,000", 350),
    Company("CVS Health", "cvshealth", "CVS", "Healthcare / pharmacy retail", "Woonsocket, RI",
            "cvshealth.com", ["Aetna", "CVS Caremark", "MinuteClinic", "Omnicare"],
            "300,000", 250),
    Company("Exxon Mobil Corporation", "exxonmobil", "XOM", "Oil & gas", "Spring, TX",
            "exxonmobil.com", ["Exxon", "Mobil", "Esso", "XTO Energy"],
            "62,000", 200),
    Company("Berkshire Hathaway Inc.", "berkshire", "BRK.A", "Conglomerate / insurance", "Omaha, NE",
            "berkshirehathaway.com", ["GEICO", "BNSF Railway", "Duracell", "Dairy Queen", "See's Candies", "NetJets"],
            "390,000", 400),
    Company("Alphabet Inc.", "alphabet", "GOOGL", "Technology / advertising", "Mountain View, CA",
            "abc.xyz", ["Google", "YouTube", "Waymo", "Verily", "DeepMind", "Fitbit"],
            "180,000", 800),
    Company("McKesson Corporation", "mckesson", "MCK", "Healthcare distribution", "Irving, TX",
            "mckesson.com", ["CoverMyMeds", "RelayHealth", "US Oncology Network"],
            "48,000", 180),
    Company("JPMorgan Chase & Co.", "jpmc", "JPM", "Financial services / banking", "New York, NY",
            "jpmorganchase.com", ["Chase", "J.P. Morgan Private Bank", "J.P. Morgan Payments"],
            "310,000", 500),
    Company("Microsoft Corporation", "microsoft", "MSFT", "Technology / cloud", "Redmond, WA",
            "microsoft.com", ["Azure", "LinkedIn", "GitHub", "Xbox", "Nuance", "Activision Blizzard"],
            "228,000", 1200),
    Company("Costco Wholesale", "costco", "COST", "Wholesale retail", "Issaquah, WA",
            "costco.com", ["Kirkland Signature", "Costco Travel", "Costco Pharmacy"],
            "330,000", 150),
    Company("The Cigna Group", "cigna", "CI", "Healthcare / insurance", "Bloomfield, CT",
            "cigna.com", ["Evernorth", "Express Scripts", "Accredo"],
            "70,000", 200),
    Company("AT&T Inc.", "att", "T", "Telecommunications", "Dallas, TX",
            "att.com", ["AT&T Mobility", "Cricket Wireless", "AT&T Business"],
            "150,000", 350),
    Company("Chevron Corporation", "chevron", "CVX", "Oil & gas", "San Ramon, CA",
            "chevron.com", ["Texaco", "Caltex", "Chevron Phillips Chemical"],
            "46,000", 180),
    Company("Ford Motor Company", "ford", "F", "Automotive", "Dearborn, MI",
            "ford.com", ["Lincoln", "Ford Pro", "Ford Credit", "Ford Motor Credit"],
            "177,000", 220),
    Company("Bank of America", "bofa", "BAC", "Financial services / banking", "Charlotte, NC",
            "bankofamerica.com", ["Merrill", "BofA Securities", "Bank of America Private Bank"],
            "213,000", 450),
    Company("General Motors", "gm", "GM", "Automotive", "Detroit, MI",
            "gm.com", ["Chevrolet", "GMC", "Cadillac", "Buick", "OnStar", "GM Financial"],
            "163,000", 240),
    Company("Verizon Communications", "verizon", "VZ", "Telecommunications", "New York, NY",
            "verizon.com", ["Verizon Wireless", "Visible", "Verizon Business"],
            "105,000", 300),
    Company("Cardinal Health", "cardinal", "CAH", "Healthcare distribution", "Dublin, OH",
            "cardinalhealth.com", ["Cardinal Health Pharmaceutical", "Cordis", "Kinray"],
            "48,000", 160),
]


# Made-up fallback persona (the project's original fiction). Selected when
# HONEYPOT_COMPANY=fictional, for operators who don't want a real trademark in
# their decoy.
FICTIONAL = Company(
    "Meridian Global Industries", "mgi", "MGI", "Diversified conglomerate", "Wilmington, DE",
    "meridianglobal.com",
    ["Meridian Financial Services", "Meridian Energy", "Meridian Retail",
     "Meridian Healthcare", "Meridian Logistics", "Meridian Defense Systems"],
    "90,000", 450, fictional=True,
)

_BY_SLUG = {c.slug: c for c in COMPANIES}
_BY_SLUG[FICTIONAL.slug] = FICTIONAL


# Per-scope defaults when nothing is configured: the public web defaults to the
# fictional persona (lowest exposure), the post-auth SSH shell to a real one.
_SCOPE_DEFAULTS = {"ssh": "random", "web": "fictional"}


def pick_company(scope: str | None = None) -> Company:
    """Pick a persona for the given scope ("ssh" | "web" | None).

    Resolution order: scope-specific env var (HONEYPOT_COMPANY_<SCOPE>), then the
    global HONEYPOT_COMPANY, then the scope's built-in default. For scope="ssh"
    (the default), call this per session to get per-session variety.
    """
    val = None
    if scope:
        val = os.environ.get(f"HONEYPOT_COMPANY_{scope.upper()}")
    if not val:
        val = os.environ.get("HONEYPOT_COMPANY")
    if not val:
        val = _SCOPE_DEFAULTS.get(scope or "", "random")

    choice = val.strip().lower()
    if choice in ("", "random"):
        return random.choice(COMPANIES)
    if choice in ("fictional", "mgi"):
        return FICTIONAL
    return _BY_SLUG.get(choice, random.choice(COMPANIES))
