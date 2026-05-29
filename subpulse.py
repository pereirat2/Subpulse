#!/usr/bin/env python3
"""
SubPulse — Subdomain recon tool (authorized use only)

DISCLAIMER / ROE
- Use ONLY with explicit authorization and within the target program scope/ROE.
- Respect rate limits, provider Terms of Service, and local laws.
- This tool performs reconnaissance and validation only. No exploitation is performed.
- Takeover module is heuristic detection only; manual verification is required.

Dependencies:
  pip install requests dnspython rich

Quick start:
  python3 subpulse.py scan example.com
  python3 subpulse.py scan example.com --mode stealth
  python3 subpulse.py scan example.com --policy strict
  python3 subpulse.py scan example.com --wordlist ./subdomains.txt
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import re
import string
import time
import threading
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import dns.resolver
import dns.exception
import dns.reversename
import dns.message
import dns.query
import dns.rdatatype
import dns.name

# Optional rich UI (pretty output)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    RICH = True
except Exception:
    RICH = False


# ----------------------------
# Constants / Disclaimer
# ----------------------------

DISCLAIMER = (
    "AUTHORIZED USE ONLY: Use only with explicit permission and within program scope/ROE. "
    "You are responsible for rate limits, provider ToS, and legal compliance."
)

# ----------------------------
# Subdomain Takeover Signature DB
# ----------------------------
#
# Each entry describes a SaaS / hosting service that has historically been
# vulnerable to subdomain takeover when a dangling CNAME points at it.
#
# Fields:
#   service           Human-readable label.
#   cname_patterns    Lowercased substrings/suffixes matched against the CNAME
#                     target. Match if the CNAME equals the pattern OR ends
#                     with "." + pattern OR contains the pattern as a substring
#                     (for patterns that are clearly distinctive).
#   http_status       Expected HTTP status from the dangling resource (None to
#                     skip the check). Some services serve 404, others 200.
#   http_fingerprints Body substrings that confirm a dangling resource.
#                     Matching one is sufficient. Compared case-insensitively.
#   nxdomain_only     If True, the takeover only manifests when the CNAME
#                     target NXDOMAINs (no A/AAAA). If False, HTTP verification
#                     is required even when the CNAME resolves.
#   vulnerable        True if the service is publicly documented as
#                     exploitable today; False if the takeover requires extra
#                     conditions / has been mitigated.
#   documentation     Short reference (project / advisory / URL).
#
# Sources: EdOverflow/can-i-take-over-xyz, projectdiscovery/nuclei-templates,
#          and historical takeover writeups.

TAKEOVER_SIGNATURES: List[Dict[str, object]] = [
    {
        "service": "AWS/S3",
        "cname_patterns": ["s3.amazonaws.com", "s3-website", ".s3.", ".s3-"],
        "http_status": 404,
        "http_fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:aws/s3",
    },
    {
        "service": "AWS/CloudFront",
        "cname_patterns": ["cloudfront.net"],
        "http_status": None,
        "http_fingerprints": ["Bad request", "ERROR: The request could not be satisfied"],
        "nxdomain_only": False,
        "vulnerable": False,
        "documentation": "can-i-take-over-xyz:aws/cloudfront",
    },
    {
        "service": "AWS/Elastic Beanstalk",
        "cname_patterns": ["elasticbeanstalk.com"],
        "http_status": None,
        "http_fingerprints": [],
        "nxdomain_only": True,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:aws/elastic-beanstalk",
    },
    {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io", "github.map.fastly.net"],
        "http_status": 404,
        "http_fingerprints": ["There isn't a GitHub Pages site here."],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:github",
    },
    {
        "service": "Heroku",
        "cname_patterns": ["herokuapp.com", "herokudns.com", "herokussl.com"],
        "http_status": 404,
        "http_fingerprints": [
            "No such app",
            "There's nothing here, yet.",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:heroku",
    },
    {
        "service": "Netlify",
        "cname_patterns": ["netlify.app", "netlify.com", "netlifyglobalcdn.com"],
        "http_status": 404,
        "http_fingerprints": ["Not Found - Request ID:"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:netlify",
    },
    {
        "service": "Vercel/Now",
        "cname_patterns": ["vercel-dns.com", "vercel.app", "now.sh"],
        "http_status": 404,
        "http_fingerprints": ["The deployment could not be found on Vercel"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:vercel",
    },
    {
        "service": "Azure/Web App",
        "cname_patterns": [
            "azurewebsites.net",
            "azure-api.net",
            "cloudapp.net",
            "cloudapp.azure.com",
            "trafficmanager.net",
            "azurefd.net",
            "azureedge.net",
            "blob.core.windows.net",
        ],
        "http_status": None,
        "http_fingerprints": [
            "404 Web Site not found",
            "Our services aren't available right now",
            "<Code>InvalidUri</Code>",
        ],
        "nxdomain_only": True,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:microsoft-azure",
    },
    {
        "service": "Fastly",
        "cname_patterns": ["fastly.net"],
        "http_status": None,
        "http_fingerprints": ["Fastly error: unknown domain"],
        "nxdomain_only": False,
        "vulnerable": False,
        "documentation": "can-i-take-over-xyz:fastly",
    },
    {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com"],
        "http_status": None,
        "http_fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:shopify",
    },
    {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "http_status": None,
        "http_fingerprints": ["Help Center Closed"],
        "nxdomain_only": False,
        "vulnerable": False,
        "documentation": "can-i-take-over-xyz:zendesk",
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["domains.tumblr.com", "tumblr.com"],
        "http_status": 404,
        "http_fingerprints": [
            "Whatever you were looking for doesn't currently exist at this address.",
            "There's nothing here.",
        ],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:tumblr",
    },
    {
        "service": "Unbounce",
        "cname_patterns": ["unbouncepages.com"],
        "http_status": None,
        "http_fingerprints": ["The requested URL was not found on this server."],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:unbounce",
    },
    {
        "service": "Tilda",
        "cname_patterns": ["tilda.ws"],
        "http_status": None,
        "http_fingerprints": ["Please renew your subscription"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:tilda",
    },
    {
        "service": "Pantheon",
        "cname_patterns": ["pantheonsite.io"],
        "http_status": None,
        "http_fingerprints": ["The gods are wise, but do not know of the site which you seek."],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:pantheon",
    },
    {
        "service": "HelpScout",
        "cname_patterns": ["helpscoutdocs.com"],
        "http_status": None,
        "http_fingerprints": ["No settings were found for this company:"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:helpscout",
    },
    {
        "service": "Readme.io",
        "cname_patterns": ["readme.io"],
        "http_status": None,
        "http_fingerprints": ["Project doesnt exist... yet!"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:readme",
    },
    {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "http_status": None,
        "http_fingerprints": ["project not found"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:surge",
    },
    {
        "service": "Bitbucket",
        "cname_patterns": ["bitbucket.io"],
        "http_status": 404,
        "http_fingerprints": ["Repository not found"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:bitbucket",
    },
    {
        "service": "GitLab Pages",
        "cname_patterns": ["gitlab.io"],
        "http_status": None,
        "http_fingerprints": ["The page you're looking for could not be found"],
        "nxdomain_only": False,
        "vulnerable": False,
        "documentation": "can-i-take-over-xyz:gitlab",
    },
    {
        "service": "Cargo Collective",
        "cname_patterns": ["cargocollective.com"],
        "http_status": 404,
        "http_fingerprints": ["404 Not Found"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:cargo",
    },
    {
        "service": "Webflow",
        "cname_patterns": ["proxy.webflow.com", "proxy-ssl.webflow.com", "webflow.io"],
        "http_status": 404,
        "http_fingerprints": ["The page you are looking for doesn't exist or has been moved"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:webflow",
    },
    {
        "service": "WordPress.com",
        "cname_patterns": ["wordpress.com"],
        "http_status": None,
        "http_fingerprints": ["Do you want to register"],
        "nxdomain_only": False,
        "vulnerable": False,
        "documentation": "can-i-take-over-xyz:wordpress",
    },
    {
        "service": "Ghost.io",
        "cname_patterns": ["ghost.io"],
        "http_status": None,
        "http_fingerprints": ["The thing you were looking for is no longer here, or never was"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:ghost",
    },
    {
        "service": "Strikingly",
        "cname_patterns": ["s.strikinglydns.com"],
        "http_status": None,
        "http_fingerprints": ["But if you're looking to build your own website,"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:strikingly",
    },
    {
        "service": "Smartling",
        "cname_patterns": ["smartling.com"],
        "http_status": None,
        "http_fingerprints": ["Domain is not configured"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:smartling",
    },
    {
        "service": "Tave",
        "cname_patterns": ["clientaccess.tave.com"],
        "http_status": None,
        "http_fingerprints": ["<h1>Error 404: Page Not Found</h1>"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:tave",
    },
    {
        "service": "Wishpond",
        "cname_patterns": ["wishpond.com"],
        "http_status": None,
        "http_fingerprints": ["https://www.wishpond.com/404?campaign=true"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:wishpond",
    },
    {
        "service": "Aftership",
        "cname_patterns": ["aftership.com"],
        "http_status": None,
        "http_fingerprints": ["Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist."],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:aftership",
    },
    {
        "service": "Aha!",
        "cname_patterns": ["ideas.aha.io"],
        "http_status": None,
        "http_fingerprints": ["There is no portal here ... sending you back to Aha!"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:aha",
    },
    {
        "service": "Brightcove",
        "cname_patterns": ["brightcovegallery.com", "gallery.video", "bcvp0rtal.com"],
        "http_status": None,
        "http_fingerprints": ["<p class=\"bc-gallery-error-code\">Error Code: 404</p>"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:brightcove",
    },
    {
        "service": "Campaign Monitor",
        "cname_patterns": ["createsend.com"],
        "http_status": None,
        "http_fingerprints": ["Trying to access your account?", "Double check the URL"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:campaign-monitor",
    },
    {
        "service": "Canny",
        "cname_patterns": ["canny.io"],
        "http_status": None,
        "http_fingerprints": ["Company Not Found", "There is no such company. Did you enter the right URL?"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:canny",
    },
    {
        "service": "Frontify",
        "cname_patterns": ["frontify.com"],
        "http_status": None,
        "http_fingerprints": ["<title>Frontify - 404</title>"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:frontify",
    },
    {
        "service": "Hatena Blog",
        "cname_patterns": ["hatenablog.com"],
        "http_status": 404,
        "http_fingerprints": ["404 Blog is not found"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:hatena",
    },
    {
        "service": "Intercom",
        "cname_patterns": ["custom.intercom.help"],
        "http_status": None,
        "http_fingerprints": ["This page is reserved for artistic dogs", "Uh oh. That page doesn't exist."],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:intercom",
    },
    {
        "service": "LaunchRock",
        "cname_patterns": ["launchrock.com"],
        "http_status": None,
        "http_fingerprints": ["It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us."],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:launchrock",
    },
    {
        "service": "Pingdom",
        "cname_patterns": ["stats.pingdom.com"],
        "http_status": None,
        "http_fingerprints": ["pingdom"],
        "nxdomain_only": True,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:pingdom",
    },
    {
        "service": "Statuspage",
        "cname_patterns": ["statuspage.io"],
        "http_status": None,
        "http_fingerprints": [
            "You are being <a href=\"https://www.statuspage.io\">redirected",
            "This page is reserved for artistic dogs.",
        ],
        "nxdomain_only": False,
        "vulnerable": False,
        "documentation": "can-i-take-over-xyz:statuspage",
    },
    {
        "service": "Uberflip",
        "cname_patterns": ["uberflip.com"],
        "http_status": None,
        "http_fingerprints": ["The URL you've accessed does not provide a hub."],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:uberflip",
    },
    {
        "service": "UserVoice",
        "cname_patterns": ["uservoice.com"],
        "http_status": None,
        "http_fingerprints": ["This UserVoice subdomain is currently available!"],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:uservoice",
    },
    {
        "service": "Worksites.net",
        "cname_patterns": ["worksites.net"],
        "http_status": None,
        "http_fingerprints": ["Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist."],
        "nxdomain_only": False,
        "vulnerable": True,
        "documentation": "can-i-take-over-xyz:worksites",
    },
]

# Backwards-compatible flat list (suffix patterns only). Derived from the
# structured signature DB above so users that pass `--fingerprints` with the
# legacy comma-separated list still get a sensible default.
DEFAULT_TAKEOVER_FPS: List[str] = sorted({
    p.lstrip(".") for sig in TAKEOVER_SIGNATURES
    for p in (sig.get("cname_patterns") or [])
    # Skip substring-only patterns (those starting with ".") for the flat
    # legacy list — only proper suffixes go here.
    if isinstance(p, str) and not p.startswith(".")
    # Skip the "s3-website" partial label — not a real suffix.
    and "." in p
})

DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$", re.IGNORECASE)

# TLD-like tokens we expect to see in concatenation artifacts produced by
# upstream sources (notably HackerTarget) when two SAN values from a shared
# CDN certificate get glued together without a separator, e.g.
#   "arquitecturamd.com.ar" + "www.fanduel.com" -> "arquitecturamd.com.arwww.fanduel.com"
# We deliberately keep this list narrow — only TLDs/ccTLDs commonly observed
# in real-world artifacts. We do NOT check these as interior labels because
# FanDuel uses 2-letter US state codes (co, ar, de, in, la, md, me, tn, ...)
# that legitimately collide with ccTLDs.
KNOWN_TLD_TOKENS_FOR_ARTIFACT = frozenset({
    # gTLDs
    "com", "net", "org", "edu", "gov", "biz", "info", "io", "ai", "app",
    "africa", "asia",
    # ccTLDs (kept narrow — only used for last-label-glue detection, not interior)
    "br", "au", "ar", "bj", "bo", "be", "uk", "jp", "fr", "es", "it",
    "ru", "cn", "us", "ca", "mx", "nz", "tr", "tw", "kr", "se", "no",
    "fi", "dk", "nl", "pl", "cz", "gr", "pt", "ch", "at", "ie", "za",
})

# Recon modes (opinionated presets)
MODES = {
    "stealth": {
        "dns_threads": 10,
        "dns_qps": 3.0,
        "dns_timeout": 3.5,
        "http_qps": 0.25,
        "http_timeout": 15.0,
        "alive_threads": 20,
        "alive_qps": 4.0,
        "alive_timeout": 7.5,
        "takeover_threads": 10,
        "takeover_dns_qps": 4.0,
        "http_retries": 2,
        "http_backoff": 1.0,
    },
    "balanced": {
        "dns_threads": 25,
        "dns_qps": 10.0,
        "dns_timeout": 2.5,
        "http_qps": 0.5,
        "http_timeout": 12.0,
        "alive_threads": 60,
        "alive_qps": 10.0,
        "alive_timeout": 6.0,
        "takeover_threads": 25,
        "takeover_dns_qps": 10.0,
        "http_retries": 2,
        "http_backoff": 1.0,
    },
    "aggressive": {
        "dns_threads": 60,
        "dns_qps": 25.0,
        "dns_timeout": 2.0,
        "http_qps": 1.0,
        "http_timeout": 10.0,
        "alive_threads": 120,
        "alive_qps": 25.0,
        "alive_timeout": 5.0,
        "takeover_threads": 60,
        "takeover_dns_qps": 20.0,
        "http_retries": 2,
        "http_backoff": 1.0,
    },
}

# Policy strict = safer guardrails (reduce rate, avoid surprise load)
STRICT_POLICY_OVERRIDES = {
    "dns_threads": 8,
    "dns_qps": 2.0,
    "dns_timeout": 4.0,
    "http_qps": 0.2,
    "http_timeout": 18.0,
    "alive_threads": 15,
    "alive_qps": 3.0,
    "alive_timeout": 9.0,
    "takeover_threads": 8,
    "takeover_dns_qps": 3.0,
    "http_retries": 3,
    "http_backoff": 1.25,
}

_RICH_CONSOLE = Console() if RICH else None


# ----------------------------
# Utility
# ----------------------------

def cprint(msg: str) -> None:
    if RICH and _RICH_CONSOLE is not None:
        _RICH_CONSOLE.print(msg)
    else:
        print(re.sub(r"\[/?[^\]]+\]", "", msg))

# SubPulse wordmark (ANSI Shadow). Kept as a module-level constant so the
# banner function stays small and so the art is easy to spot when reading
# the file.
_BANNER_WORDMARK: Tuple[str, ...] = (
    r"   ███████╗██╗   ██╗██████╗ ██████╗ ██╗   ██╗██╗     ███████╗███████╗",
    r"   ██╔════╝██║   ██║██╔══██╗██╔══██╗██║   ██║██║     ██╔════╝██╔════╝",
    r"   ███████╗██║   ██║██████╔╝██████╔╝██║   ██║██║     ███████╗█████╗",
    r"   ╚════██║██║   ██║██╔══██╗██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝",
    r"   ███████║╚██████╔╝██████╔╝██║     ╚██████╔╝███████╗███████║███████╗",
    r"   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝",
)
# Color stops applied top->bottom of the wordmark for a soft cyan gradient
# that evokes a pulse fading out. Truecolor-friendly; rich falls back to
# 256-color or 16-color on terminals that don't speak truecolor.
_BANNER_SHADES: Tuple[str, ...] = (
    "bold cyan",
    "bold bright_cyan",
    "bold #5fd7ff",
    "bold #87d7ff",
    "bold #afe7ff",
    "bold #d0f0ff",
)
_BANNER_PULSE_TOP    = r"        ╱╲     ╱╲              ╱╲     ╱╲       subdomain"
_BANNER_PULSE_BOTTOM = r"    ───╱  ╲───╱  ╲────────────╱  ╲───╱  ╲────  reconnaissance"

__version__ = "2.0"


def banner() -> None:
    if RICH and _RICH_CONSOLE is not None:
        _RICH_CONSOLE.print("")
        for line, shade in zip(_BANNER_WORDMARK, _BANNER_SHADES):
            _RICH_CONSOLE.print(line, style=shade)
        _RICH_CONSOLE.print(_BANNER_PULSE_TOP, style="bold green")
        _RICH_CONSOLE.print(_BANNER_PULSE_BOTTOM, style="green")
        _RICH_CONSOLE.print(
            f"[dim]   v{__version__}  •  single-file recon  •  "
            f"https://github.com/pereirat2/Subpulse[/dim]"
        )
        _RICH_CONSOLE.print(
            "[yellow]   ⚠  AUTHORIZED USE ONLY[/yellow][dim] — only scan "
            "targets you have explicit permission to test.[/dim]"
        )
        _RICH_CONSOLE.print("")
    else:
        for line in _BANNER_WORDMARK:
            print(line)
        print(_BANNER_PULSE_TOP)
        print(_BANNER_PULSE_BOTTOM)
        print(f"   v{__version__}  -  single-file recon")
        print(f"   AUTHORIZED USE ONLY. {DISCLAIMER}")
        print("-" * 76)

def progress() -> Optional["Progress"]:
    if not RICH or _RICH_CONSOLE is None:
        return None
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}[/bold]"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=_RICH_CONSOLE,
        transient=False,
    )

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def now_ts_folder() -> str:
    return time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())

def read_lines(path: Path) -> List[str]:
    return [x.strip() for x in path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]

def write_lines(path: Path, lines: Iterable[str]) -> None:
    # Lazily create the parent directory so callers can write directly into
    # a structured subdir layout (e.g. run_dir/hosts/all.txt) without having
    # to pre-create each subdir.
    path.parent.mkdir(parents=True, exist_ok=True)
    data = "\n".join(lines)
    if data and not data.endswith("\n"):
        data += "\n"
    path.write_text(data, encoding="utf-8")

def normalize_domain(s: str) -> str:
    s = s.strip().lower().rstrip(".")
    try:
        s.encode("idna").decode("ascii")
    except Exception:
        pass
    return s

def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(normalize_domain(domain)))

def is_subdomain_of(candidate: str, domain: str) -> bool:
    c = candidate.strip().lower().rstrip(".")
    d = domain.strip().lower().rstrip(".")
    return c == d or c.endswith("." + d)

def looks_like_concat_artifact(name: str, target: str) -> bool:
    """
    Detect names where an upstream source glued two SAN values together
    without a separator, producing structurally-valid-but-fake subdomains
    like 'foo.com.brwww.fanduel.com' or 'doing-business.africawww.fanduel.com'.

    The signature is: the rightmost label of the subdomain portion is
    '<known-tld><www>' (e.g. 'brwww', 'auwww', 'africawww', 'bizwww').
    Real *.fanduel.com subdomains never have a label of that shape, but
    this is exactly what shared-CDN cert SAN concatenation produces.

    We do NOT check for interior public-suffix labels because legitimate
    FanDuel subdomains use US state codes (co, ar, de, in, la, md, me, tn, ...)
    that collide with ccTLDs.
    """
    n = name.strip().lower().rstrip(".")
    t = target.strip().lower().rstrip(".")
    if not n.endswith("." + t):
        return False
    left = n[: -(len(t) + 1)]
    if not left:
        return False
    last_label = left.rsplit(".", 1)[-1]
    if last_label == "www" or not last_label.endswith("www") or len(last_label) <= 3:
        return False
    head = last_label[:-3]
    return head in KNOWN_TLD_TOKENS_FOR_ARTIFACT

def split_names(raw: str) -> List[str]:
    out: List[str] = []
    for line in raw.splitlines():
        x = line.strip().lower().rstrip(".")
        if not x:
            continue
        if x.startswith("*."):
            x = x[2:]
        out.append(x)
    return out

def rand_label(n: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

def records_signature(rec: Dict[str, List[str]]) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
    a = tuple(sorted({x.strip().rstrip(".") for x in rec.get("A", []) if x}))
    aaaa = tuple(sorted({x.strip().rstrip(".") for x in rec.get("AAAA", []) if x}))
    cname = tuple(sorted({x.strip().rstrip(".") for x in rec.get("CNAME", []) if x}))
    return (a, aaaa, cname)

def safe_host_from_url(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""

def norm_server(s: str) -> str:
    s = (s or "").strip().lower()
    if not s:
        return ""
    return s.split()[0].split("/")[0].strip()

def word_in_host(host: str, words: Iterable[str]) -> bool:
    h = host.lower()
    return any(w in h for w in words)


# ----------------------------
# Permutation generator
# ----------------------------
#
# Seeds: the labels we've already observed for the target (e.g. "api-dev-eu"
# in "api-dev-eu.example.com"). For each seed label we:
#   1) Split on common separators ('-', '_', '.') to get atomic tokens.
#   2) Detect "slot" positions: env tokens (dev/staging/...) and region
#      tokens (eu/us/apac/...), plus trailing digits.
#   3) Generate variants by:
#        - Swapping detected slot values with sibling values in the same
#          slot family.
#        - Replacing trailing digits with 1..MAX_DIGIT.
#        - Adding/removing prefix or suffix from a small token list.
#        - Swapping separators ('-' <-> '_').
#   4) Re-join and stitch onto the target's apex.
#
# This is a deliberately small, opinionated generator (NOT a full dnsgen
# clone). The output is capped to `max_perms` to avoid combinatorial blowup
# on labels with many tokens.

ENV_TOKENS: Tuple[str, ...] = (
    "dev", "development",
    "stg", "staging", "stage",
    "qa", "uat", "test", "tst",
    "preprod", "pre-prod", "pre", "prod", "production",
    "sandbox", "sbox",
    "internal", "intern", "int",
    "demo", "beta", "alpha", "canary",
)

REGION_TOKENS: Tuple[str, ...] = (
    "us", "use", "usw", "us-east", "us-west",
    "eu", "euw", "eue", "eu-west", "eu-east",
    "apac", "ap", "ap-east", "ap-south",
    "anz", "au", "ca", "uk", "ie", "de", "fr", "nl",
    "sa", "br", "mx", "in", "sg", "jp", "kr",
)

NUM_SUFFIX_RANGE: Tuple[int, ...] = (1, 2, 3, 4, 5)

EXTRA_PREFIXES: Tuple[str, ...] = ("dev-", "staging-", "qa-", "test-", "preprod-", "stage-")
EXTRA_SUFFIXES: Tuple[str, ...] = ("-dev", "-staging", "-qa", "-test", "-preprod", "-stage", "-prod")

_TOKEN_SPLIT_RE = re.compile(r"[-_]")


def _label_tokens(label: str) -> List[str]:
    """Split a single DNS label on hyphens/underscores. Lowercase atomic tokens."""
    return [t for t in _TOKEN_SPLIT_RE.split(label.lower()) if t]


def _join_tokens(tokens: List[str], sep: str = "-") -> str:
    return sep.join(t for t in tokens if t)


def _swap_in_family(tokens: List[str], family: Tuple[str, ...]) -> Set[Tuple[str, ...]]:
    """For each token that lives in `family`, produce variants substituting
    every other family member. Returns the set of *new* token tuples."""
    out: Set[Tuple[str, ...]] = set()
    family_set = set(family)
    for i, tok in enumerate(tokens):
        if tok in family_set:
            for repl in family:
                if repl == tok:
                    continue
                variant = list(tokens)
                variant[i] = repl
                out.add(tuple(variant))
    return out


def _numeric_variants(tokens: List[str]) -> Set[Tuple[str, ...]]:
    """If the last token is purely digits, sweep it across NUM_SUFFIX_RANGE.
    Also add a trailing numeric token when there isn't one."""
    out: Set[Tuple[str, ...]] = set()
    if not tokens:
        return out
    last = tokens[-1]
    if last.isdigit():
        for n in NUM_SUFFIX_RANGE:
            if str(n) == last:
                continue
            variant = list(tokens[:-1]) + [str(n)]
            out.add(tuple(variant))
    else:
        for n in NUM_SUFFIX_RANGE:
            out.add(tuple(list(tokens) + [str(n)]))
    return out


def generate_permutations(
    seed_hosts: Iterable[str],
    target_domain: str,
    max_perms: int = 5000,
) -> Set[str]:
    """
    Generate candidate FQDNs by permuting the labels of seed hosts. The
    target_domain is the apex we're scanning — we replace the seed's leftmost
    label set with permuted labels and keep the rest of the path (so a seed
    `api.staging.example.com` produces variants of just the leftmost label
    appended to `staging.example.com`).
    """
    target_domain = target_domain.lower().strip(".")
    apex_suffix = "." + target_domain
    out: Set[str] = set()

    for raw in seed_hosts:
        host = (raw or "").lower().strip(".")
        if not host.endswith(apex_suffix) and host != target_domain:
            continue
        # Strip the apex; what remains is the "subdomain part".
        sub = host[: -len(apex_suffix)] if host != target_domain else ""
        if not sub:
            continue
        # Split on dot — we only permute the *leftmost* label (the one most
        # likely to encode env/region/version info). The rest is preserved.
        labels = sub.split(".")
        left = labels[0]
        rest = labels[1:]
        tokens = _label_tokens(left)
        if not tokens:
            continue

        variants: Set[Tuple[str, ...]] = set()
        variants.add(tuple(tokens))
        variants |= _swap_in_family(tokens, ENV_TOKENS)
        variants |= _swap_in_family(tokens, REGION_TOKENS)
        variants |= _numeric_variants(tokens)

        for v in list(variants):
            v_list = list(v)
            for pre in EXTRA_PREFIXES:
                pre_tok = _label_tokens(pre.rstrip("-_"))
                if pre_tok and pre_tok[0] not in v_list:
                    variants.add(tuple(pre_tok + v_list))
            for suf in EXTRA_SUFFIXES:
                suf_tok = _label_tokens(suf.lstrip("-_"))
                if suf_tok and suf_tok[-1] not in v_list:
                    variants.add(tuple(v_list + suf_tok))

        # Emit FQDNs for each variant, with both '-' and '_' separators
        # (some services use _ in their internal naming).
        for v in variants:
            joined_h = _join_tokens(list(v), sep="-")
            joined_u = _join_tokens(list(v), sep="_")
            for joined in {joined_h, joined_u}:
                if not joined:
                    continue
                new_left = joined
                full = ".".join([new_left] + rest + [target_domain])
                # Validate the synthetic FQDN looks sane.
                if DOMAIN_RE.match(full) and is_subdomain_of(full, target_domain):
                    out.add(full)
                    if len(out) >= max_perms:
                        return out
    return out


# ----------------------------
# Rate Limiter
# ----------------------------

class GlobalRateLimiter:
    def __init__(self, qps: float):
        self.qps = max(0.0, float(qps))
        self._next_time = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self.qps <= 0:
            return
        interval = 1.0 / self.qps
        with self._lock:
            now = time.monotonic()
            if now < self._next_time:
                time.sleep(self._next_time - now)
                now = time.monotonic()
            self._next_time = now + interval


# ----------------------------
# Cache
# ----------------------------

class SimpleJSONCache:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        ensure_dir(self.base_dir)

    def _path_for(self, key: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in key)
        return self.base_dir / f"{safe}.json"

    def get(self, key: str, ttl_seconds: int):
        p = self._path_for(key)
        if not p.exists():
            return None
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            created_at = float(raw.get("created_at", 0))
            if ttl_seconds > 0 and (time.time() - created_at) > ttl_seconds:
                return None
            return raw.get("value")
        except Exception:
            return None

    def set(self, key: str, value) -> None:
        p = self._path_for(key)
        payload = {"created_at": time.time(), "value": value}
        p.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

def cache_stats(cache_dir: Path) -> Tuple[int, int]:
    """
    Recursive stats: scan writes cache to cache_dir/<domain>/*.json
    """
    ensure_dir(cache_dir)
    files = [p for p in cache_dir.rglob("*.json") if p.is_file()]
    total_bytes = sum(p.stat().st_size for p in files)
    return len(files), total_bytes

def cache_clear(cache_dir: Path) -> int:
    """
    Recursive clear: deletes all *.json under cache_dir (including domain subdirs).
    """
    ensure_dir(cache_dir)
    files = [p for p in cache_dir.rglob("*.json") if p.is_file()]
    n = 0
    for p in files:
        try:
            p.unlink()
            n += 1
        except Exception:
            pass

    # Best-effort cleanup of empty dirs
    try:
        for d in sorted([p for p in cache_dir.rglob("*") if p.is_dir()], reverse=True):
            try:
                d.rmdir()
            except OSError:
                pass
    except Exception:
        pass

    return n


# ----------------------------
# DNS helpers
# ----------------------------

def make_resolver(nameservers: Optional[List[str]], timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    if nameservers:
        r.nameservers = nameservers
    r.timeout = timeout
    r.lifetime = timeout
    return r

def resolve_records(resolver: dns.resolver.Resolver, fqdn: str, dns_limiter: GlobalRateLimiter) -> Dict[str, List[str]]:
    dns_limiter.acquire()
    out: Dict[str, List[str]] = {"A": [], "AAAA": [], "CNAME": []}
    for rrtype in ("A", "AAAA", "CNAME"):
        try:
            ans = resolver.resolve(fqdn, rrtype, raise_on_no_answer=False)
            if ans.rrset is None:
                continue
            for item in ans:
                out[rrtype].append(str(item).rstrip("."))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:
            continue
    return out

def looks_resolved(records: Dict[str, List[str]]) -> bool:
    return any(records.get(k) for k in ("A", "AAAA", "CNAME"))

def detect_wildcard_signatures(
    domain: str,
    resolver: dns.resolver.Resolver,
    dns_limiter: GlobalRateLimiter,
    samples: int = 3,
) -> Tuple[bool, Tuple[str, ...], Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]]]:
    """
    Legacy v1 wildcard detector — kept for backwards compatibility with any
    code path that still calls it. Wildcard signature v2 (`detect_wildcards_v2`)
    is preferred and is what the scan pipeline actually uses.
    """
    hits: List[str] = []
    sigs: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]] = set()
    for _ in range(samples):
        cand = f"{rand_label()}.{domain}"
        rec = resolve_records(resolver, cand, dns_limiter)
        if looks_resolved(rec):
            hits.append(cand)
            sigs.add(records_signature(rec))
    return (len(hits) > 0), tuple(hits), sigs


# ----------------------------
# Wildcard signature v2
# ----------------------------
#
# v1 only probed `*.<apex>` and stored RR-tuples. v2:
#   - Probes at each label depth observed in the candidate set
#     (apex + any "parent" host like `staging.example.com`,
#     `internal.dev.example.com`, ...).
#   - Stores per-depth signature sets so the filter is precise: a candidate
#     `foo.staging.example.com` is compared against the wildcard signature
#     observed at `*.staging.example.com`, not at the apex.
#   - Captures an HTTP body hash for each random sample. This isn't used to
#     filter (HTTP-probing every candidate is too expensive), but it's
#     surfaced in the report so the operator can confirm by eye whether
#     wildcard samples all serve the same page.

@dataclass
class WildcardEvidence:
    parent: str                                # parent path (e.g. "" for apex, "staging" for *.staging.<apex>)
    samples: Tuple[str, ...]                   # the actual random FQDNs probed
    signatures: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]]  # DNS sig set
    body_hashes: Tuple[str, ...]               # MD5 of each sample's HTTP body (empty if not probed)


def _http_body_fingerprint(host: str, timeout: float = 4.0) -> str:
    """
    Fetch the host with both HTTPS and HTTP and return an MD5 of the first
    16 KiB of body (lowercased & whitespace-collapsed). Returns "" on any
    failure. Used as supporting evidence in wildcard detection.
    """
    import hashlib
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{host}",
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "SubPulse/1.0 (authorized testing)"},
            )
        except Exception:
            continue
        body = (r.text or "")[:16384].lower()
        body = re.sub(r"\s+", " ", body).strip()
        if not body:
            continue
        return hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()
    return ""


def _parent_paths(domain: str, hosts: Iterable[str]) -> List[str]:
    """
    From a list of FQDNs, return the set of "parent paths" (depth markers)
    we should probe for nested wildcards. The empty string represents the
    apex (`*.<domain>`); other entries are the labels between the leftmost
    label and the apex (e.g. host `a.b.c.example.com` with apex
    `example.com` yields parent paths "" and "b.c" and "c").
    """
    apex = domain.lower().strip(".")
    apex_suffix = "." + apex
    out: Set[str] = set()
    out.add("")  # apex
    for raw in hosts:
        h = (raw or "").lower().strip(".")
        if not h.endswith(apex_suffix) and h != apex:
            continue
        if h == apex:
            continue
        sub = h[: -len(apex_suffix)]
        parts = sub.split(".")
        # parts[0] is the leftmost (most-specific) label; parents are
        # parts[1:], parts[2:], ... up to but not including apex.
        for i in range(1, len(parts)):
            parent_path = ".".join(parts[i:])
            if parent_path:
                out.add(parent_path)
    return sorted(out, key=lambda p: (p.count("."), p))


def detect_wildcards_v2(
    domain: str,
    candidate_hosts: Iterable[str],
    resolver: dns.resolver.Resolver,
    dns_limiter: GlobalRateLimiter,
    samples: int = 3,
    probe_http: bool = True,
    http_timeout: float = 4.0,
) -> Dict[str, WildcardEvidence]:
    """
    Probe random labels at each observed depth. Returns a mapping
    {parent_path -> WildcardEvidence} with one entry per depth that has a
    wildcard. The apex is keyed as "".
    """
    domain = domain.lower().strip(".")
    parents = _parent_paths(domain, candidate_hosts)

    result: Dict[str, WildcardEvidence] = {}
    for parent in parents:
        full_parent = f"{parent}.{domain}" if parent else domain
        hits: List[str] = []
        sigs: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]] = set()
        body_hashes: List[str] = []
        for _ in range(samples):
            cand = f"{rand_label()}.{full_parent}"
            rec = resolve_records(resolver, cand, dns_limiter)
            if looks_resolved(rec):
                hits.append(cand)
                sigs.add(records_signature(rec))
                if probe_http:
                    body_hashes.append(_http_body_fingerprint(cand, timeout=http_timeout))
        if hits:
            result[parent] = WildcardEvidence(
                parent=parent,
                samples=tuple(hits),
                signatures=sigs,
                body_hashes=tuple(body_hashes),
            )
    return result


def candidate_parent_path(domain: str, host: str) -> str:
    """
    Return the parent-path key (matching `detect_wildcards_v2` output) for a
    candidate host. Used to look up the correct wildcard signature set.
    """
    domain = domain.lower().strip(".")
    apex_suffix = "." + domain
    h = (host or "").lower().strip(".")
    if not h.endswith(apex_suffix) and h != domain:
        return ""
    if h == domain:
        return ""
    sub = h[: -len(apex_suffix)]
    parts = sub.split(".")
    return ".".join(parts[1:])  # everything except the leftmost label


def wildcard_match_v2(
    domain: str,
    host: str,
    rec: Dict[str, List[str]],
    wildcards: Dict[str, WildcardEvidence],
) -> bool:
    """
    Returns True iff `host`'s records match the wildcard signature observed
    at its parent depth (or any *more specific* parent we observed). We walk
    from most-specific to apex so that a nested wildcard takes precedence.
    """
    if not wildcards:
        return False
    parent = candidate_parent_path(domain, host)
    sig = records_signature(rec)
    # Try each progressively-less-specific parent path until we find one we
    # have evidence for.
    path_parts = parent.split(".") if parent else []
    candidates_paths = [".".join(path_parts[i:]) for i in range(len(path_parts) + 1)]
    for p in candidates_paths:
        ev = wildcards.get(p)
        if ev and sig in ev.signatures:
            return True
    return False

def resolve_cname(resolver: dns.resolver.Resolver, host: str, dns_limiter: GlobalRateLimiter) -> Optional[str]:
    dns_limiter.acquire()
    try:
        ans = resolver.resolve(host, "CNAME", raise_on_no_answer=False)
        if ans.rrset is None:
            return None
        for item in ans:
            return str(item).rstrip(".")
        return None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None

def nsec_walk(
    domain: str,
    dns_limiter: GlobalRateLimiter,
    timeout: float = 3.0,
    max_steps: int = 5000,
) -> Tuple[List[str], str]:
    """
    Attempt to enumerate a DNSSEC-signed zone via NSEC chain walking.

    Returns (names, mode) where:
      names = list of FQDNs that are subdomains of `domain` (deduplicated).
      mode  = "nsec" on successful walk,
              "nsec3" when the zone uses NSEC3 (cannot walk online),
              "unsigned" when no DNSSEC,
              "error" on any failure / partial walk.

    Implementation:
      * Resolve NS for the apex, then query the first NS directly for
        synthetic names that should not exist (label = "0").
      * Read NSEC RR from the AUTHORITY section to learn the next name in
        canonical order, then iterate.
      * Stops when we loop back to the apex or hit max_steps.

    NSEC3 (hashed) cannot be walked online — we just detect & report so the
    operator knows offline cracking is a follow-up option.
    """
    domain = domain.lower().strip(".")
    try:
        ns_resolver = dns.resolver.Resolver(configure=True)
        ns_resolver.timeout = timeout
        ns_resolver.lifetime = timeout
        dns_limiter.acquire()
        ans_ns = ns_resolver.resolve(domain, "NS", raise_on_no_answer=False)
    except Exception:
        return [], "error"

    if ans_ns.rrset is None or len(ans_ns.rrset) == 0:
        return [], "error"

    ns_hosts = [str(r).rstrip(".") for r in ans_ns]
    ns_ips: List[str] = []
    for nh in ns_hosts:
        try:
            dns_limiter.acquire()
            ip_ans = ns_resolver.resolve(nh, "A", raise_on_no_answer=False)
            for ip in ip_ans or []:
                ns_ips.append(str(ip))
        except Exception:
            continue
        if ns_ips:
            break
    if not ns_ips:
        return [], "error"

    ns_ip = ns_ips[0]

    # Quick NSEC3 sniff: query an obviously-nonexistent label and inspect
    # AUTHORITY for NSEC3 RR -> abort the walk and return mode="nsec3".
    try:
        probe = f"{rand_label()}.{domain}"
        q = dns.message.make_query(probe, dns.rdatatype.A, want_dnssec=True)
        dns_limiter.acquire()
        resp = dns.query.udp(q, ns_ip, timeout=timeout)
        for auth in resp.authority:
            if auth.rdtype == dns.rdatatype.NSEC3:
                return [], "nsec3"
    except Exception:
        return [], "error"

    found: Set[str] = set()
    current = domain
    apex_name = dns.name.from_text(domain)
    steps = 0
    try:
        while steps < max_steps:
            steps += 1
            # Use "\0.<current>" as the synthetic name: lexicographically
            # smallest label that should not exist, forcing the resolver to
            # return the next NSEC owner in the chain.
            probe_name = f"\\000.{current}"
            q = dns.message.make_query(probe_name, dns.rdatatype.A, want_dnssec=True)
            dns_limiter.acquire()
            resp = dns.query.udp(q, ns_ip, timeout=timeout)
            next_owner = None
            for auth in resp.authority:
                if auth.rdtype != dns.rdatatype.NSEC:
                    continue
                # rdataset items expose .next as the next owner name
                for rdata in auth:
                    nxt = getattr(rdata, "next", None)
                    if nxt is None:
                        continue
                    next_owner = str(nxt).rstrip(".").lower()
                    break
                if next_owner:
                    break
            if not next_owner:
                break
            # Termination: walked back to apex.
            if next_owner == domain:
                break
            if next_owner.endswith("." + domain) or next_owner == domain:
                found.add(next_owner)
                current = next_owner
            else:
                break
    except Exception:
        return sorted(found), "error"

    if not found:
        return [], "unsigned"
    return sorted(found), "nsec"


def reverse_dns_sweep(
    ips: Iterable[str],
    dns_limiter: GlobalRateLimiter,
    threads: int = 25,
    timeout: float = 2.0,
) -> Dict[str, List[str]]:
    """
    PTR-lookup each IP. Returns {ip -> [ptr_hostnames]}. PTRs that don't match
    a target domain are still returned; the caller filters.
    """
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout

    def _ptr(ip: str) -> Tuple[str, List[str]]:
        try:
            dns_limiter.acquire()
            rev = dns.reversename.from_address(ip)
            ans = resolver.resolve(rev, "PTR", raise_on_no_answer=False)
            if ans.rrset is None:
                return ip, []
            return ip, [str(r).rstrip(".").lower() for r in ans]
        except Exception:
            return ip, []

    out: Dict[str, List[str]] = {}
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futs = [ex.submit(_ptr, ip) for ip in ips]
        prog = progress()
        if prog:
            with prog:
                task = prog.add_task("Reverse DNS sweep", total=len(futs))
                for fut in as_completed(futs):
                    ip, names = fut.result()
                    if names:
                        out[ip] = names
                    prog.advance(task, 1)
        else:
            for fut in as_completed(futs):
                ip, names = fut.result()
                if names:
                    out[ip] = names
    return out


def cname_target_resolves(resolver: dns.resolver.Resolver, target: str, dns_limiter: GlobalRateLimiter) -> bool:
    for rr in ("A", "AAAA"):
        dns_limiter.acquire()
        try:
            ans = resolver.resolve(target, rr, raise_on_no_answer=False)
            if ans.rrset is not None:
                return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:
            continue
    return False


# ----------------------------
# Takeover-specific DNS helpers
# ----------------------------

# Possible DNS states returned by classify_dns_state. Used to drive the
# takeover decision tree and (in confidence calculation) to weight findings.
DNS_STATE_OK = "ok"                  # has A/AAAA records
DNS_STATE_NXDOMAIN = "nxdomain"      # authoritative says the name does not exist
DNS_STATE_NO_ANSWER = "no_answer"    # name exists but no A/AAAA (could be CNAME-only)
DNS_STATE_SERVFAIL = "servfail"      # nameservers returned SERVFAIL — often dangling NS
DNS_STATE_TIMEOUT = "timeout"        # resolver gave up
DNS_STATE_ERROR = "error"            # any other resolver error


def classify_dns_state(resolver: dns.resolver.Resolver, name: str, dns_limiter: GlobalRateLimiter) -> str:
    """
    Classify the DNS state of a name. We check A and AAAA; either positive
    answer is sufficient to call the name 'ok'. NXDOMAIN on A is conclusive,
    but we still verify AAAA in case the recursive returned NoAnswer for A.
    """
    saw_no_answer = False
    saw_nxdomain = False
    saw_servfail = False
    saw_timeout = False

    for rr in ("A", "AAAA"):
        dns_limiter.acquire()
        try:
            ans = resolver.resolve(name, rr, raise_on_no_answer=False)
            if ans.rrset is not None and len(ans.rrset) > 0:
                return DNS_STATE_OK
            saw_no_answer = True
        except dns.resolver.NXDOMAIN:
            saw_nxdomain = True
        except dns.resolver.NoAnswer:
            saw_no_answer = True
        except dns.resolver.NoNameservers:
            saw_servfail = True
        except dns.exception.Timeout:
            saw_timeout = True
        except Exception:
            return DNS_STATE_ERROR

    if saw_nxdomain:
        return DNS_STATE_NXDOMAIN
    if saw_servfail:
        return DNS_STATE_SERVFAIL
    if saw_no_answer:
        return DNS_STATE_NO_ANSWER
    if saw_timeout:
        return DNS_STATE_TIMEOUT
    return DNS_STATE_ERROR


def cname_chain(
    resolver: dns.resolver.Resolver,
    host: str,
    dns_limiter: GlobalRateLimiter,
    max_hops: int = 6,
) -> List[str]:
    """
    Follow CNAME records up to max_hops. Returns the chain of CNAME targets
    (not including the original host). Stops on first non-CNAME or NXDOMAIN.
    """
    chain: List[str] = []
    current = host
    seen: Set[str] = set()
    for _ in range(max_hops):
        if current in seen:
            break
        seen.add(current)
        target = resolve_cname(resolver, current, dns_limiter)
        if not target:
            break
        chain.append(target)
        current = target
    return chain


def soa_state(resolver: dns.resolver.Resolver, apex: str, dns_limiter: GlobalRateLimiter) -> str:
    """
    Probe SOA for the apex of a CNAME target. SERVFAIL/NXDOMAIN on the apex
    is a strong signal of a dangling delegation (NS-based takeover).
    """
    dns_limiter.acquire()
    try:
        ans = resolver.resolve(apex, "SOA", raise_on_no_answer=False)
        if ans.rrset is None:
            return DNS_STATE_NO_ANSWER
        return DNS_STATE_OK
    except dns.resolver.NXDOMAIN:
        return DNS_STATE_NXDOMAIN
    except dns.resolver.NoAnswer:
        return DNS_STATE_NO_ANSWER
    except dns.resolver.NoNameservers:
        return DNS_STATE_SERVFAIL
    except dns.exception.Timeout:
        return DNS_STATE_TIMEOUT
    except Exception:
        return DNS_STATE_ERROR


def apex_of(host: str) -> str:
    """
    Best-effort apex extraction (last two labels). Good enough for the SaaS
    fingerprints we care about ("foo.bar.s3.amazonaws.com" -> "amazonaws.com").
    Not a public-suffix-aware implementation.
    """
    host = (host or "").strip(".").lower()
    parts = host.split(".")
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def multi_resolver_cname(
    resolvers: List[dns.resolver.Resolver],
    host: str,
    dns_limiter: GlobalRateLimiter,
) -> Tuple[List[Optional[str]], bool]:
    """
    Resolve CNAME via several resolvers. Returns the list of observed targets
    (one per resolver, None if no CNAME) and a `disagree` flag.
    """
    seen: List[Optional[str]] = []
    for r in resolvers:
        target = resolve_cname(r, host, dns_limiter)
        seen.append(target.lower() if target else None)
    distinct = {x for x in seen if x is not None}
    disagree = len(distinct) > 1
    return seen, disagree


def match_takeover_signature(cname: str) -> Optional[Dict[str, object]]:
    """
    Return the first TAKEOVER_SIGNATURES entry whose patterns match the CNAME.
    Patterns starting with "." are treated as substring matches, otherwise as
    suffix-or-equal matches.
    """
    if not cname:
        return None
    lc = cname.lower().rstrip(".")
    for sig in TAKEOVER_SIGNATURES:
        for pat in (sig.get("cname_patterns") or []):
            if not isinstance(pat, str):
                continue
            p = pat.lower()
            if p.startswith("."):
                if p in lc:
                    return sig
            else:
                if lc == p or lc.endswith("." + p):
                    return sig
    return None


# ----------------------------
# HTTP helpers
# ----------------------------

def http_get(
    session: requests.Session,
    url: str,
    timeout: float,
    retries: int,
    backoff: float,
    limiter: GlobalRateLimiter
) -> Optional[requests.Response]:
    """
    GET helper with rate limiting + retries.

    IMPORTANT:
    - Returns the response if we got one (even if 3xx/4xx), because some OSINT
      sources still return useful bodies on non-200 responses.
    - Retries only on transient/rate-limit statuses (429, 5xx).
    """
    last_exc: Optional[Exception] = None

    for attempt in range(retries + 1):
        try:
            limiter.acquire()
            r = session.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "SubPulse/1.0 (authorized testing)"},
            )

            if r.status_code in (429, 500, 502, 503, 504):
                raise RuntimeError(f"HTTP {r.status_code}")

            return r

        except Exception as e:
            last_exc = e
            if attempt < retries:
                time.sleep(backoff * (2 ** attempt))
            else:
                logging.debug("HTTP failed: %s (%s)", url, last_exc)
                return None

    return None


# ----------------------------
# Models
# ----------------------------

@dataclass(frozen=True)
class SubdomainResult:
    name: str
    sources: Tuple[str, ...]
    resolved: bool
    records: Dict[str, List[str]]
    notes: Tuple[str, ...] = ()

@dataclass(frozen=True)
class AliveResult:
    host: str
    url: str
    status: Optional[int]
    server: str = ""
    final_url: str = ""
    error: str = ""
    # --- v2 fields (multi-port + TLS + tech) ---
    port: int = 0                          # observed port (0 if scheme-default)
    title: str = ""                        # <title> contents (trimmed)
    favicon_md5: str = ""                  # MD5 of /favicon.ico body
    tech: Tuple[str, ...] = ()             # fingerprinted technologies
    tls_sans: Tuple[str, ...] = ()         # SANs harvested from the TLS cert
    body_md5: str = ""                     # MD5 of normalized first 16 KiB of body
    redirect_chain: Tuple[str, ...] = ()   # ordered URLs from the redirect chain

@dataclass(frozen=True)
class TakeoverFinding:
    host: str
    cname: str
    cname_resolves: bool
    reason: str
    fingerprint_hit: str = ""
    # --- v2 fields (enriched detection + confirmation) ---
    # Confidence values: "HIGH" (HTTP fingerprint hit), "MEDIUM" (CNAME match
    # + matching DNS state), "LOW" (CNAME points at known SaaS but no further
    # evidence), "INFO" (dangling CNAME without a known signature — operator
    # review). Empty string = legacy detection.
    confidence: str = ""
    service: str = ""                # human-readable provider name
    dns_state: str = ""              # one of DNS_STATE_*
    http_status: Optional[int] = None
    http_fingerprint: str = ""       # body substring that confirmed the takeover
    http_body_snippet: str = ""      # short snippet from the live response
    http_url: str = ""               # URL that produced the evidence
    vulnerable: Optional[bool] = None
    documentation: str = ""
    evidence: Tuple[str, ...] = ()   # ordered list of human-readable evidence lines
    multi_resolver_disagree: bool = False


# ----------------------------
# Output / Runs
# ----------------------------

def make_run_dir(base_dir: Path, domain: str, prefix: str = "") -> Path:
    name = f"{prefix}{now_ts_folder()}" if prefix else now_ts_folder()
    run_dir = base_dir / normalize_domain(domain) / name
    ensure_dir(run_dir)
    return run_dir

def find_previous_run_dir(base_dir: Path, domain: str, current: Path) -> Optional[Path]:
    dom_dir = base_dir / normalize_domain(domain)
    if not dom_dir.exists():
        return None
    runs = [p for p in dom_dir.iterdir() if p.is_dir() and not p.is_symlink()]
    runs.sort(key=lambda p: p.name, reverse=True)
    for i, p in enumerate(runs):
        if p.resolve() == current.resolve() and i + 1 < len(runs):
            return runs[i + 1]
    return runs[0] if runs else None


def update_latest_symlink(base_dir: Path, domain: str, run_dir: Path) -> Optional[Path]:
    """
    Maintain `subpulse_data/<domain>/latest -> <run_dir>`. Best-effort: on
    Windows or filesystems that don't support symlinks we silently skip.
    """
    dom_dir = base_dir / normalize_domain(domain)
    link = dom_dir / "latest"
    try:
        if link.exists() or link.is_symlink():
            link.unlink()
        # Use a relative target so the link survives if the parent is moved.
        link.symlink_to(run_dir.name, target_is_directory=True)
        return link
    except (OSError, NotImplementedError):
        return None


def _load_scan_json(run_dir: Path) -> Optional[Dict[str, object]]:
    """Load scan.json from a run dir (supports legacy flat layout too)."""
    candidates = [run_dir / "scan.json"]
    for c in candidates:
        if c.exists():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except Exception:
                return None
    return None


def diff_scans(prev: Dict[str, object], curr: Dict[str, object]) -> Dict[str, List[Dict[str, object]]]:
    """
    Structured diff between two scan.json payloads.

    Returns: {
      "added":     [{host, ...}],          # hosts not in prev
      "removed":   [{host, ...}],          # hosts not in curr
      "changed":   [{host, deltas: [...]}],
      "takeover_new":     [...],           # takeover findings new this run
      "takeover_escalated": [...],         # confidence increased vs last run
    }
    """
    def _index_results(payload: Dict[str, object]) -> Dict[str, Dict[str, object]]:
        idx: Dict[str, Dict[str, object]] = {}
        for r in (payload.get("results") or []):
            if isinstance(r, dict) and isinstance(r.get("name"), str):
                idx[r["name"].lower()] = r
        return idx

    def _index_alive(payload: Dict[str, object]) -> Dict[str, Dict[str, object]]:
        idx: Dict[str, Dict[str, object]] = {}
        for a in (payload.get("alive") or []):
            if not isinstance(a, dict):
                continue
            host = (a.get("host") or "").lower()
            # Prefer https://host (canonical "best") if multiple ports exist.
            if not host:
                continue
            existing = idx.get(host)
            if existing is None or (a.get("status") == 200 and existing.get("status") != 200):
                idx[host] = a
        return idx

    def _index_takeover(payload: Dict[str, object]) -> Dict[str, Dict[str, object]]:
        idx: Dict[str, Dict[str, object]] = {}
        for t in (payload.get("takeover") or []):
            if isinstance(t, dict) and isinstance(t.get("host"), str):
                idx[t["host"].lower()] = t
        return idx

    prev_res = _index_results(prev)
    curr_res = _index_results(curr)
    prev_alive = _index_alive(prev)
    curr_alive = _index_alive(curr)
    prev_to = _index_takeover(prev)
    curr_to = _index_takeover(curr)

    added = [{"host": h, **curr_res[h]} for h in sorted(set(curr_res) - set(prev_res))]
    removed = [{"host": h, **prev_res[h]} for h in sorted(set(prev_res) - set(curr_res))]

    changed: List[Dict[str, object]] = []
    confidence_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "": 4}

    for host in sorted(set(prev_res) & set(curr_res)):
        deltas: List[str] = []
        p = prev_res[host]
        c = curr_res[host]
        # Resolved state flip
        if bool(p.get("resolved")) != bool(c.get("resolved")):
            deltas.append(f"resolved:{p.get('resolved')!r}->{c.get('resolved')!r}")
        # Records (compact)
        for rrtype in ("A", "AAAA", "CNAME"):
            pa = set((p.get("records") or {}).get(rrtype, []) or [])
            ca = set((c.get("records") or {}).get(rrtype, []) or [])
            if pa != ca:
                deltas.append(f"{rrtype}:{sorted(pa)}->{sorted(ca)}")
        # Server header (from alive)
        pa = prev_alive.get(host, {})
        ca = curr_alive.get(host, {})
        if pa.get("server", "") != ca.get("server", ""):
            if pa.get("server") or ca.get("server"):
                deltas.append(f"server:{pa.get('server','')!r}->{ca.get('server','')!r}")
        if pa.get("status") != ca.get("status"):
            if pa.get("status") is not None or ca.get("status") is not None:
                deltas.append(f"http_status:{pa.get('status')}->{ca.get('status')}")
        if deltas:
            changed.append({"host": host, "deltas": deltas})

    takeover_new = [{"host": h, **curr_to[h]} for h in sorted(set(curr_to) - set(prev_to))]

    takeover_escalated: List[Dict[str, object]] = []
    for host in sorted(set(prev_to) & set(curr_to)):
        old_c = (prev_to[host].get("confidence") or "")
        new_c = (curr_to[host].get("confidence") or "")
        if confidence_rank.get(new_c, 9) < confidence_rank.get(old_c, 9):
            takeover_escalated.append({
                "host": host,
                "from": old_c,
                "to": new_c,
                "service": curr_to[host].get("service", ""),
            })

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "takeover_new": takeover_new,
        "takeover_escalated": takeover_escalated,
    }


# ----------------------------
# HTML report
# ----------------------------

_HTML_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       margin: 0; padding: 24px; color: #1a1a1a; background: #fafafa; }
h1 { margin: 0 0 8px; }
h2 { margin: 32px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #ddd; }
.meta { color: #555; font-size: 13px; margin-bottom: 16px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 8px; }
.card { background: #fff; border: 1px solid #e2e2e2; border-radius: 6px; padding: 10px 12px; }
.card .label { color: #555; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
.card .value { font-size: 22px; font-weight: 600; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px;
         font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; }
.badge-HIGH    { background: #fee2e2; color: #b91c1c; }
.badge-MEDIUM  { background: #fef3c7; color: #92400e; }
.badge-LOW     { background: #dbeafe; color: #1e40af; }
.badge-INFO    { background: #e5e7eb; color: #374151; }
table { width: 100%; border-collapse: collapse; background: #fff;
        border: 1px solid #e2e2e2; border-radius: 6px; overflow: hidden; }
th, td { padding: 8px 10px; text-align: left; font-size: 13px;
         border-bottom: 1px solid #eee; vertical-align: top; }
th { background: #f4f4f5; cursor: pointer; user-select: none; position: sticky; top: 0; }
th.sort-asc::after  { content: " \\25B2"; color: #888; }
th.sort-desc::after { content: " \\25BC"; color: #888; }
tr:hover td { background: #fafafa; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
              font-size: 12px; color: #111; }
.tag { display: inline-block; background: #eef2ff; color: #3730a3; padding: 1px 7px;
       border-radius: 10px; font-size: 11px; margin: 1px 2px; }
.muted { color: #777; }
.scroll { max-height: 600px; overflow: auto; border: 1px solid #e2e2e2; border-radius: 6px; }
.scroll table { border: none; border-radius: 0; }
"""

_HTML_JS = """
document.querySelectorAll('table').forEach(function(t) {
  t.querySelectorAll('th').forEach(function(th, idx) {
    th.addEventListener('click', function() {
      var tbody = t.tBodies[0];
      var rows = Array.prototype.slice.call(tbody.rows);
      var asc = !th.classList.contains('sort-asc');
      t.querySelectorAll('th').forEach(function(o) { o.classList.remove('sort-asc','sort-desc'); });
      th.classList.add(asc ? 'sort-asc' : 'sort-desc');
      rows.sort(function(a, b) {
        var av = (a.cells[idx] && a.cells[idx].innerText) || '';
        var bv = (b.cells[idx] && b.cells[idx].innerText) || '';
        var an = parseFloat(av); var bn = parseFloat(bv);
        if (!isNaN(an) && !isNaN(bn)) { return asc ? an - bn : bn - an; }
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      rows.forEach(function(r) { tbody.appendChild(r); });
    });
  });
});
"""


def _html_escape(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def render_html_report(payload: Dict[str, object], run_dir: Path) -> str:
    """Render a self-contained HTML report. No external assets, no new deps."""
    meta = payload.get("meta") or {}
    counts = meta.get("counts") or {}
    target = meta.get("target", "")
    mode = meta.get("mode", "")
    policy = meta.get("policy", "")
    sources = ", ".join((meta.get("sources") or []))
    generated_at = meta.get("generated_at", "")

    def _card(label: str, value: object) -> str:
        return (
            f'<div class="card"><div class="label">{_html_escape(label)}</div>'
            f'<div class="value">{_html_escape(str(value))}</div></div>'
        )

    cards_html = "".join([
        _card("All", counts.get("all", 0)),
        _card("Resolved", counts.get("resolved", 0)),
        _card("Strict", counts.get("resolved_strict", 0)),
        _card("Alive URLs", counts.get("alive_urls", 0)),
        _card("Takeover (HIGH)", counts.get("takeover_high", 0)),
        _card("Takeover (MEDIUM)", counts.get("takeover_medium", 0)),
        _card("Takeover (LOW)", counts.get("takeover_low", 0)),
    ])

    # Top priorities table
    prio_rows_html: List[str] = []
    for row in (payload.get("priority") or [])[:50]:
        if not isinstance(row, dict):
            continue
        prio_rows_html.append(
            "<tr>"
            f"<td>{_html_escape(str(row.get('score', '')))}</td>"
            f"<td><code>{_html_escape(str(row.get('host', '')))}</code></td>"
            f"<td><a href=\"{_html_escape(str(row.get('best_url', '')))}\">{_html_escape(str(row.get('best_url', '')))}</a></td>"
            f"<td class=\"muted\">{_html_escape(str(row.get('reasons', '')))}</td>"
            "</tr>"
        )

    # Takeover table
    to_rows_html: List[str] = []
    for t in (payload.get("takeover") or []):
        if not isinstance(t, dict):
            continue
        conf = (t.get("confidence") or "").upper()
        to_rows_html.append(
            "<tr>"
            f"<td><span class=\"badge badge-{_html_escape(conf)}\">{_html_escape(conf or '-')}</span></td>"
            f"<td>{_html_escape(str(t.get('service','')))}</td>"
            f"<td><code>{_html_escape(str(t.get('host','')))}</code></td>"
            f"<td><code>{_html_escape(str(t.get('cname','')))}</code></td>"
            f"<td>{_html_escape(str(t.get('dns_state','')))}</td>"
            f"<td>{_html_escape(str(t.get('http_status','') or ''))} "
            f"<span class=\"mono muted\">{_html_escape(str(t.get('http_fingerprint','')))}</span></td>"
            f"<td class=\"muted\">{_html_escape(', '.join(t.get('evidence') or []))}</td>"
            "</tr>"
        )

    # Alive table
    alive_rows_html: List[str] = []
    for a in (payload.get("alive") or []):
        if not isinstance(a, dict) or a.get("status") is None:
            continue
        tech = a.get("tech") or []
        tech_html = "".join(f"<span class=\"tag\">{_html_escape(t)}</span>" for t in tech)
        alive_rows_html.append(
            "<tr>"
            f"<td>{_html_escape(str(a.get('status','')))}</td>"
            f"<td>{_html_escape(str(a.get('port','')))}</td>"
            f"<td><a href=\"{_html_escape(str(a.get('final_url') or a.get('url','')))}\">"
            f"<code>{_html_escape(str(a.get('host','')))}</code></a></td>"
            f"<td>{_html_escape(str(a.get('server','')))}</td>"
            f"<td>{_html_escape(str(a.get('title','')))[:120]}</td>"
            f"<td>{tech_html}</td>"
            f"<td class=\"mono muted\">{_html_escape(str(a.get('favicon_md5',''))[:12])}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>SubPulse Report — {_html_escape(target)}</title>
<style>{_HTML_CSS}</style>
</head><body>
<h1>SubPulse Report — <code>{_html_escape(target)}</code></h1>
<div class="meta">
  Mode: <code>{_html_escape(mode)}</code> ·
  Policy: <code>{_html_escape(policy)}</code> ·
  Sources: <code>{_html_escape(sources)}</code> ·
  Generated: <code>{_html_escape(generated_at)}</code>
</div>

<h2>Counts</h2>
<div class="grid">{cards_html}</div>

<h2>Top 50 priorities</h2>
<div class="scroll"><table>
<thead><tr><th>Score</th><th>Host</th><th>Best URL</th><th>Reasons</th></tr></thead>
<tbody>{''.join(prio_rows_html) or '<tr><td colspan="4" class="muted">(none)</td></tr>'}</tbody>
</table></div>

<h2>Takeover findings ({len(payload.get('takeover') or [])})</h2>
<div class="scroll"><table>
<thead><tr><th>Confidence</th><th>Service</th><th>Host</th><th>CNAME</th><th>DNS</th><th>HTTP</th><th>Evidence</th></tr></thead>
<tbody>{''.join(to_rows_html) or '<tr><td colspan="7" class="muted">(none)</td></tr>'}</tbody>
</table></div>

<h2>Alive hosts</h2>
<div class="scroll"><table>
<thead><tr><th>Status</th><th>Port</th><th>Host</th><th>Server</th><th>Title</th><th>Tech</th><th>Favicon</th></tr></thead>
<tbody>{''.join(alive_rows_html) or '<tr><td colspan="7" class="muted">(none)</td></tr>'}</tbody>
</table></div>

<script>{_HTML_JS}</script>
</body></html>
"""
    return html


def render_diff_markdown(diff: Dict[str, List[Dict[str, object]]]) -> str:
    lines: List[str] = []
    lines.append("# Scan diff")
    lines.append("")
    lines.append(
        "Summary: "
        f"**+{len(diff['added'])}** added, "
        f"**-{len(diff['removed'])}** removed, "
        f"**~{len(diff['changed'])}** changed, "
        f"**{len(diff['takeover_new'])}** new takeover candidates, "
        f"**{len(diff['takeover_escalated'])}** escalated."
    )
    lines.append("")
    if diff["takeover_escalated"]:
        lines.append("## Takeover escalations (most important)")
        for e in diff["takeover_escalated"]:
            lines.append(f"- `{e['host']}` ({e.get('service','-')}) {e['from'] or '-'} -> **{e['to']}**")
        lines.append("")
    if diff["takeover_new"]:
        lines.append("## New takeover candidates")
        for e in diff["takeover_new"]:
            lines.append(f"- {e.get('confidence','-')} `{e['host']}` -> `{e.get('cname','')}` ({e.get('service','')})")
        lines.append("")
    if diff["added"]:
        lines.append(f"## Added ({len(diff['added'])})")
        for e in diff["added"][:200]:
            lines.append(f"- `{e['host']}` (resolved={e.get('resolved', False)})")
        if len(diff["added"]) > 200:
            lines.append(f"- … and {len(diff['added']) - 200} more")
        lines.append("")
    if diff["removed"]:
        lines.append(f"## Removed ({len(diff['removed'])})")
        for e in diff["removed"][:200]:
            lines.append(f"- `{e['host']}`")
        if len(diff["removed"]) > 200:
            lines.append(f"- … and {len(diff['removed']) - 200} more")
        lines.append("")
    if diff["changed"]:
        lines.append(f"## Changed ({len(diff['changed'])})")
        for e in diff["changed"][:200]:
            lines.append(f"- `{e['host']}`")
            for d in e["deltas"]:
                lines.append(f"  - {d}")
        if len(diff["changed"]) > 200:
            lines.append(f"- … and {len(diff['changed']) - 200} more")
        lines.append("")
    return "\n".join(lines) + "\n"


# ----------------------------
# Core pipeline pieces
# ----------------------------

def enum_passive(
    domain: str,
    sources: List[str],
    cache: SimpleJSONCache,
    cache_ttl: int,
    session: requests.Session,
    http_limiter: GlobalRateLimiter,
    http_timeout: float,
    http_retries: int,
    http_backoff: float,
) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}

    def enum_crtsh() -> Set[str]:
        key = f"crtsh_{domain}"
        cached = cache.get(key, cache_ttl)
        if isinstance(cached, list):
            logging.info("cache hit: %s", key)
            return set(cached)

        logging.info("cache miss: %s", key)
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = http_get(session, url, http_timeout, http_retries, http_backoff, http_limiter)
        if not r:
            return set()

        try:
            data = r.json()
        except Exception:
            return set()

        found: Set[str] = set()
        for row in data:
            nv = row.get("name_value")
            if isinstance(nv, str):
                for name in split_names(nv):
                    if is_subdomain_of(name, domain):
                        found.add(name)

        cache.set(key, sorted(found))
        return found

    def enum_certspotter() -> Set[str]:
        key = f"certspotter_{domain}"
        cached = cache.get(key, cache_ttl)
        if isinstance(cached, list):
            logging.info("cache hit: %s", key)
            return set(cached)

        logging.info("cache miss: %s", key)
        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names"
        )
        r = http_get(session, url, http_timeout, http_retries, http_backoff, http_limiter)
        if not r:
            return set()

        try:
            data = r.json()
        except Exception:
            return set()

        found: Set[str] = set()
        if isinstance(data, list):
            for issuance in data:
                dns_names = issuance.get("dns_names")
                if isinstance(dns_names, list):
                    for n in dns_names:
                        if isinstance(n, str):
                            for x in split_names(n):
                                if is_subdomain_of(x, domain):
                                    found.add(x)

        cache.set(key, sorted(found))
        return found

    def enum_hackertarget() -> Set[str]:
        key = f"hackertarget_{domain}"
        cached = cache.get(key, cache_ttl)
        if isinstance(cached, list):
            logging.info("cache hit: %s", key)
            return set(cached)

        logging.info("cache miss: %s", key)
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = http_get(session, url, http_timeout, http_retries, http_backoff, http_limiter)
        if not r:
            return set()

        text = (r.text or "").strip()
        if "error" in text.lower() and "," not in text:
            # cache empty to avoid hammering
            cache.set(key, [])
            return set()

        found: Set[str] = set()
        for line in text.splitlines():
            host = line.split(",", 1)[0].strip().lower().rstrip(".")
            if host and is_subdomain_of(host, domain):
                found.add(host)

        cache.set(key, sorted(found))
        return found

    def enum_wayback() -> Set[str]:
        """
        Wayback Machine CDX API — pulls historical URLs that contain the
        domain. We extract the hostname from each URL and keep only names
        that are subdomains of the target. Free, no API key required.
        """
        key = f"wayback_{domain}"
        cached = cache.get(key, cache_ttl)
        if isinstance(cached, list):
            logging.info("cache hit: %s", key)
            return set(cached)

        logging.info("cache miss: %s", key)
        # `collapse=urlkey` deduplicates by URL key (very effective for
        # the typical noise in Wayback). Limit to 50k rows to keep memory
        # in check; tune via cache TTL if needed.
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&fl=original"
            "&collapse=urlkey&limit=50000"
        )
        r = http_get(session, url, http_timeout, http_retries, http_backoff, http_limiter)
        if not r:
            return set()

        try:
            data = r.json()
        except Exception:
            return set()

        found: Set[str] = set()
        # First row is the header; subsequent rows are [original_url]
        rows = data[1:] if isinstance(data, list) and len(data) > 1 else []
        for row in rows:
            if not row:
                continue
            original = row[0] if isinstance(row, list) else None
            if not isinstance(original, str):
                continue
            host = safe_host_from_url(original)
            if host and is_subdomain_of(host, domain):
                found.add(host)

        cache.set(key, sorted(found))
        return found

    def enum_otx() -> Set[str]:
        """
        AlienVault OTX passive DNS — no API key needed for the public
        passive_dns endpoint. Pages up to ~500 entries; if a domain has
        more we still hit the cap, but it's a great free booster.
        """
        key = f"otx_{domain}"
        cached = cache.get(key, cache_ttl)
        if isinstance(cached, list):
            logging.info("cache hit: %s", key)
            return set(cached)

        logging.info("cache miss: %s", key)
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = http_get(session, url, http_timeout, http_retries, http_backoff, http_limiter)
        if not r:
            return set()

        try:
            data = r.json()
        except Exception:
            return set()

        found: Set[str] = set()
        for entry in (data.get("passive_dns") or []) if isinstance(data, dict) else []:
            hostname = entry.get("hostname") if isinstance(entry, dict) else None
            if isinstance(hostname, str):
                host = hostname.strip().lower().rstrip(".")
                if is_subdomain_of(host, domain):
                    found.add(host)

        cache.set(key, sorted(found))
        return found

    def enum_chaos() -> Set[str]:
        """
        ProjectDiscovery Chaos API. Requires an API key via the
        `CHAOS_API_KEY` or `PDCP_API_KEY` env var. Gracefully no-ops
        when no key is configured (so the source can be listed by default
        without breaking unauthenticated users).
        """
        import os
        api_key = (os.environ.get("CHAOS_API_KEY") or os.environ.get("PDCP_API_KEY") or "").strip()
        if not api_key:
            logging.info("chaos: skipped (no CHAOS_API_KEY / PDCP_API_KEY in env)")
            return set()

        key = f"chaos_{domain}"
        cached = cache.get(key, cache_ttl)
        if isinstance(cached, list):
            logging.info("cache hit: %s", key)
            return set(cached)

        logging.info("cache miss: %s", key)
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        try:
            http_limiter.acquire()
            r = session.get(
                url,
                timeout=http_timeout,
                headers={
                    "Authorization": api_key,
                    "User-Agent": "SubPulse/1.0 (authorized testing)",
                },
            )
        except Exception as e:
            logging.debug("chaos: request failed: %s", e)
            return set()

        if r.status_code != 200:
            logging.debug("chaos: unexpected status %s", r.status_code)
            return set()

        try:
            data = r.json()
        except Exception:
            return set()

        found: Set[str] = set()
        for label in (data.get("subdomains") or []) if isinstance(data, dict) else []:
            if not isinstance(label, str):
                continue
            host = f"{label.strip().lower().rstrip('.')}.{domain}".rstrip(".")
            if is_subdomain_of(host, domain):
                found.add(host)

        cache.set(key, sorted(found))
        return found

    for s in sources:
        if s == "crtsh":
            out[s] = enum_crtsh()
        elif s == "certspotter":
            out[s] = enum_certspotter()
        elif s == "hackertarget":
            out[s] = enum_hackertarget()
        elif s == "wayback":
            out[s] = enum_wayback()
        elif s == "otx":
            out[s] = enum_otx()
        elif s == "chaos":
            out[s] = enum_chaos()
        else:
            out[s] = set()

    return out


def validate_dns_batch(
    resolver: dns.resolver.Resolver,
    dns_limiter: GlobalRateLimiter,
    names: List[str],
    dns_threads: int,
    wildcard_sigs: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]],
    *,
    domain: str = "",
    wildcards_v2: Optional[Dict[str, "WildcardEvidence"]] = None,
) -> Dict[str, Tuple[Dict[str, List[str]], bool, bool]]:
    """
    Resolve a batch of FQDNs in parallel. The wildcard-match decision
    prefers the v2 per-depth signature dict when supplied; otherwise it
    falls back to the legacy flat signature set.
    """
    def _one(fqdn: str):
        rec = resolve_records(resolver, fqdn, dns_limiter)
        ok = looks_resolved(rec)
        if not ok:
            return fqdn, rec, ok, False
        if wildcards_v2 and domain:
            mw = wildcard_match_v2(domain, fqdn, rec, wildcards_v2)
        elif wildcard_sigs:
            mw = records_signature(rec) in wildcard_sigs
        else:
            mw = False
        return fqdn, rec, ok, mw

    results: Dict[str, Tuple[Dict[str, List[str]], bool, bool]] = {}
    with ThreadPoolExecutor(max_workers=max(1, dns_threads)) as ex:
        futs = [ex.submit(_one, n) for n in names]
        prog = progress()
        if prog:
            with prog:
                task = prog.add_task("Validating DNS", total=len(futs))
                for fut in as_completed(futs):
                    fqdn, rec, ok, mw = fut.result()
                    results[fqdn] = (rec, ok, mw)
                    prog.advance(task, 1)
        else:
            for fut in as_completed(futs):
                fqdn, rec, ok, mw = fut.result()
                results[fqdn] = (rec, ok, mw)
    return results


def bruteforce_dns(
    domain: str,
    resolver: dns.resolver.Resolver,
    dns_limiter: GlobalRateLimiter,
    wordlist: Path,
    dns_threads: int,
    wildcard_sigs: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]],
    *,
    wildcards_v2: Optional[Dict[str, "WildcardEvidence"]] = None,
) -> Dict[str, Tuple[Dict[str, List[str]], bool]]:
    words = [
        w.strip().lower()
        for w in wordlist.read_text(encoding="utf-8", errors="ignore").splitlines()
        if w.strip() and not w.strip().startswith("#")
    ]

    def _brute_one(label: str):
        fqdn = f"{label}.{domain}"
        rec = resolve_records(resolver, fqdn, dns_limiter)
        if looks_resolved(rec):
            if wildcards_v2:
                mw = wildcard_match_v2(domain, fqdn, rec, wildcards_v2)
            else:
                mw = records_signature(rec) in wildcard_sigs if wildcard_sigs else False
            return fqdn, rec, mw
        return None

    out: Dict[str, Tuple[Dict[str, List[str]], bool]] = {}
    with ThreadPoolExecutor(max_workers=max(1, dns_threads)) as ex:
        futs = [ex.submit(_brute_one, w) for w in words]
        prog = progress()
        if prog:
            with prog:
                task = prog.add_task("Bruteforcing DNS", total=len(futs))
                for fut in as_completed(futs):
                    hit = fut.result()
                    if hit:
                        fqdn, rec, mw = hit
                        out[fqdn] = (rec, mw)
                    prog.advance(task, 1)
        else:
            for fut in as_completed(futs):
                hit = fut.result()
                if not hit:
                    continue
                fqdn, rec, mw = hit
                out[fqdn] = (rec, mw)
    return out


# ----------------------------
# Tech fingerprint DB
# ----------------------------
#
# Minimal, curated technology fingerprints applied at the alive stage. Each
# entry is a (tag, matcher) pair where matcher is a dict with optional keys:
#   header_name / header_value : substring match against a response header
#   body                       : substring match against the response body
#   title                      : substring match against <title>
# Patterns are case-insensitive. Matching ANY criterion tags the host.
TECH_FINGERPRINTS: List[Tuple[str, Dict[str, str]]] = [
    ("nginx",           {"header_name": "server", "header_value": "nginx"}),
    ("apache",          {"header_name": "server", "header_value": "apache"}),
    ("envoy",           {"header_name": "server", "header_value": "envoy"}),
    ("istio",           {"header_name": "server", "header_value": "istio"}),
    ("traefik",         {"header_name": "server", "header_value": "traefik"}),
    ("cloudflare",      {"header_name": "server", "header_value": "cloudflare"}),
    ("akamai",          {"header_name": "server", "header_value": "akamai"}),
    ("fastly",          {"header_name": "server", "header_value": "fastly"}),
    ("cloudfront",      {"header_name": "via",    "header_value": "cloudfront"}),
    ("gunicorn",        {"header_name": "server", "header_value": "gunicorn"}),
    ("uvicorn",         {"header_name": "server", "header_value": "uvicorn"}),
    ("express",         {"header_name": "x-powered-by", "header_value": "express"}),
    ("php",             {"header_name": "x-powered-by", "header_value": "php"}),
    ("aspnet",          {"header_name": "x-powered-by", "header_value": "asp.net"}),
    ("iis",             {"header_name": "server", "header_value": "iis"}),
    ("tomcat",          {"header_name": "server", "header_value": "tomcat"}),
    ("kestrel",         {"header_name": "server", "header_value": "kestrel"}),
    ("wordpress",       {"body": "wp-content"}),
    ("drupal",          {"header_name": "x-generator", "header_value": "drupal"}),
    ("joomla",          {"body": "/components/com_"}),
    ("nginx-default",   {"title": "welcome to nginx"}),
    ("apache-default",  {"title": "apache2 ubuntu default page"}),
    ("iis-default",     {"title": "iis windows server"}),
    ("grafana",         {"body": "<title>grafana</title>"}),
    ("grafana",         {"body": "data-react-helmet=\"true\""}),  # weak signal; tagged conservatively
    ("kibana",          {"body": "/bundles/kbn-ui-shared-deps"}),
    ("jenkins",         {"header_name": "x-jenkins", "header_value": ""}),
    ("jenkins",         {"title": "dashboard [jenkins]"}),
    ("gitlab",          {"header_name": "x-gitlab-meta", "header_value": ""}),
    ("phpmyadmin",      {"title": "phpmyadmin"}),
    ("kubernetes-dashboard", {"body": "kubernetes dashboard"}),
    ("swagger-ui",      {"title": "swagger ui"}),
    ("redoc",           {"body": "<redoc"}),
    ("graphql-playground", {"body": "graphql playground"}),
    ("graphiql",        {"title": "graphiql"}),
    ("prometheus",      {"body": "<title>prometheus"}),
    ("airflow",         {"body": "<title>airflow"}),
    ("splunk",          {"body": "<title>splunk"}),
    ("aws-s3-bucket-listing", {"body": "<ListBucketResult"}),
    ("apache-tomcat-default", {"body": "if you're seeing this, you've successfully installed tomcat"}),
    ("default-iis7",    {"body": "<title>iis7</title>"}),
    ("ftp-listing",     {"body": "directory listing"}),
    ("jboss",           {"header_name": "x-powered-by", "header_value": "jboss"}),
    ("openresty",       {"header_name": "server", "header_value": "openresty"}),
    ("haproxy",         {"header_name": "server", "header_value": "haproxy"}),
    ("kong",            {"header_name": "via", "header_value": "kong"}),
    ("varnish",         {"header_name": "via", "header_value": "varnish"}),
]


def _fingerprint_tech(headers: Dict[str, str], body: str, title: str) -> List[str]:
    """Match the curated tech-fingerprint DB; return list of unique tags."""
    headers_lc = {k.lower(): (v or "").lower() for k, v in (headers or {}).items()}
    body_lc = (body or "").lower()
    title_lc = (title or "").lower()
    tags: List[str] = []
    seen: Set[str] = set()
    for tag, matcher in TECH_FINGERPRINTS:
        hit = False
        hn = matcher.get("header_name", "")
        hv = matcher.get("header_value", "")
        if hn:
            val = headers_lc.get(hn.lower(), "")
            if hv == "" and hn.lower() in headers_lc:
                hit = True
            elif hv and hv.lower() in val:
                hit = True
        if not hit and matcher.get("body"):
            if matcher["body"].lower() in body_lc:
                hit = True
        if not hit and matcher.get("title"):
            if matcher["title"].lower() in title_lc:
                hit = True
        if hit and tag not in seen:
            tags.append(tag)
            seen.add(tag)
    return tags


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(body: str) -> str:
    m = _TITLE_RE.search(body or "")
    if not m:
        return ""
    title = m.group(1) or ""
    title = re.sub(r"\s+", " ", title).strip()
    return title[:200]


def _normalized_body_md5(body: str) -> str:
    import hashlib
    norm = re.sub(r"\s+", " ", (body or "")[:16384].lower()).strip()
    if not norm:
        return ""
    return hashlib.md5(norm.encode("utf-8", errors="ignore")).hexdigest()


def _harvest_tls_sans(host: str, port: int = 443, timeout: float = 4.0) -> List[str]:
    """
    Pull SubjectAltName DNS entries from the server's TLS cert. Uses stdlib
    ssl; if the cert fails verification (self-signed/expired) we fall back to
    binary-form parsing only if `cryptography` is available — otherwise we
    silently return [].
    """
    import ssl
    import socket
    sans: List[str] = []
    try:
        ctx = ssl.create_default_context()
        # Don't require hostname match — we want SANs even when the cert is
        # for a different name. We DO still validate against the system CA
        # bundle (so self-signed certs won't return anything via this path).
        ctx.check_hostname = False
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                for typ, val in (cert.get("subjectAltName") or []):
                    if typ.upper() == "DNS" and isinstance(val, str):
                        sans.append(val.lower().lstrip("*.").rstrip("."))
    except Exception:
        # Try without verification, parsing DER manually (no extra dep).
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True) or b""
            # Minimal heuristic: brute-search DER for ASCII DNS-like strings.
            # Cheap and good-enough for SAN harvesting when verify fails.
            text = der.decode("latin-1", errors="ignore")
            for m in re.findall(r"[A-Za-z0-9\-\.\*]{4,253}\.[A-Za-z]{2,24}", text):
                cand = m.lower().lstrip("*.").rstrip(".")
                if "." in cand:
                    sans.append(cand)
        except Exception:
            return []
    # Deduplicate while preserving order.
    seen: Set[str] = set()
    out: List[str] = []
    for s in sans:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _fetch_favicon_md5(host: str, port: int, scheme: str, timeout: float) -> str:
    """MD5 of /favicon.ico body. Empty on any failure."""
    import hashlib
    try:
        netloc = f"{host}:{port}" if (
            (scheme == "https" and port != 443) or (scheme == "http" and port != 80)
        ) else host
        r = requests.get(
            f"{scheme}://{netloc}/favicon.ico",
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "SubPulse/1.0 (authorized testing)"},
        )
    except Exception:
        return ""
    if r.status_code != 200 or not r.content:
        return ""
    return hashlib.md5(r.content).hexdigest()


def alive_check(
    hosts: List[str],
    threads: int,
    qps: float,
    timeout: float,
    *,
    ports: Optional[List[Tuple[str, int]]] = None,
    harvest_sans: bool = True,
    fetch_favicon: bool = True,
    fingerprint_tech: bool = True,
) -> List[AliveResult]:
    """
    Multi-port alive checker.

    - `ports` is a list of (scheme, port) pairs to probe. When `port` matches
      the scheme default (443 for https, 80 for http), we omit it from the
      URL to keep canonical hostnames.
    - `harvest_sans` collects SubjectAltName DNS entries from successful TLS
      probes. The caller is responsible for feeding the harvested names back
      into the candidate pool.
    - `fetch_favicon` adds one GET per (host, scheme) for /favicon.ico to
      capture an MD5 hash (used for cross-host clustering).
    - `fingerprint_tech` extracts a tech tag set from headers/body/title via
      the TECH_FINGERPRINTS DB.
    """
    if ports is None:
        ports = [("https", 443), ("http", 80)]
    limiter = GlobalRateLimiter(qps)

    def _probe_one(host: str, scheme: str, port: int) -> AliveResult:
        netloc = f"{host}:{port}" if (
            (scheme == "https" and port != 443) or (scheme == "http" and port != 80)
        ) else host
        url = f"{scheme}://{netloc}"
        try:
            limiter.acquire()
            r = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "SubPulse/1.0 (authorized testing)"},
            )
        except Exception as e:
            return AliveResult(host=host, url=url, status=None, error=str(e), port=port)

        body = (r.text or "")[:65536]
        title = _extract_title(body) if fingerprint_tech else ""
        tech_tags = _fingerprint_tech(dict(r.headers), body, title) if fingerprint_tech else []
        body_md5 = _normalized_body_md5(body)
        # Redirect chain (each Response carries the previous step in .history).
        chain = tuple(str(h.url) for h in (r.history or [])) + (str(r.url),)
        sans: Tuple[str, ...] = ()
        if scheme == "https" and harvest_sans:
            sans = tuple(_harvest_tls_sans(host, port=port, timeout=min(timeout, 4.0)))
        favicon = ""
        if fetch_favicon:
            favicon = _fetch_favicon_md5(host, port=port, scheme=scheme, timeout=min(timeout, 4.0))

        return AliveResult(
            host=host,
            url=url,
            status=r.status_code,
            server=r.headers.get("Server", ""),
            final_url=str(r.url),
            port=port,
            title=title,
            favicon_md5=favicon,
            tech=tuple(tech_tags),
            tls_sans=sans,
            body_md5=body_md5,
            redirect_chain=chain,
        )

    def _probe_host(host: str) -> List[AliveResult]:
        host = (host or "").strip()
        if not host:
            return []
        out: List[AliveResult] = []
        for scheme, port in ports:
            out.append(_probe_one(host, scheme, port))
        return out

    results: List[AliveResult] = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futs = [ex.submit(_probe_host, h) for h in hosts]
        prog = progress()
        if prog:
            with prog:
                task = prog.add_task("Checking alive", total=len(futs))
                for fut in as_completed(futs):
                    results.extend(fut.result())
                    prog.advance(task, 1)
        else:
            for fut in as_completed(futs):
                results.extend(fut.result())
    return results


def parse_ports_spec(spec: str) -> List[Tuple[str, int]]:
    """
    Parse --ports CLI input. Accepts either:
      - "80,443"       -> infers scheme from port (80 -> http, 443 -> https,
                          8443 -> https, 8080 -> http, 3000 -> http, ...)
      - "http:80,https:443,https:8443"  -> explicit scheme
    """
    out: List[Tuple[str, int]] = []
    seen: Set[Tuple[str, int]] = set()
    for raw in (spec or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        if ":" in raw:
            sch, p = raw.split(":", 1)
            scheme = sch.strip().lower()
            try:
                port = int(p.strip())
            except ValueError:
                continue
        else:
            try:
                port = int(raw)
            except ValueError:
                continue
            # Heuristic scheme inference.
            if port in (443, 8443, 9443):
                scheme = "https"
            else:
                scheme = "http"
        if scheme not in ("http", "https"):
            continue
        key = (scheme, port)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out or [("https", 443), ("http", 80)]


def verify_http_signature(
    host: str,
    timeout: float,
    fingerprints: List[str],
    expected_status: Optional[int],
    limiter: Optional[GlobalRateLimiter] = None,
) -> Tuple[Optional[int], str, str, str]:
    """
    Probe https:// and http:// for the host and search the response body for
    any of the fingerprint substrings (case-insensitive).

    Returns (status_code, matched_fingerprint, body_snippet, url).
    - status_code   : observed HTTP status (None if both schemes failed).
    - matched       : the first fingerprint substring that matched, "" if none.
    - body_snippet  : up to ~240 chars of the response body for evidence.
    - url           : the URL where the evidence (or last attempt) came from.

    `expected_status` is informational only — we still scan the body even if
    the status differs, because services don't always serve a 404. The
    classifier in takeover_check uses it for confidence weighting.
    """
    fps = [(fp or "").lower() for fp in fingerprints if fp]
    last_status: Optional[int] = None
    last_url = ""
    last_snippet = ""

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            if limiter is not None:
                limiter.acquire()
            r = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "SubPulse/1.0 (authorized testing)"},
            )
        except Exception:
            continue

        last_status = r.status_code
        last_url = str(r.url) or url
        body = (r.text or "")[:65536]  # cap memory: 64 KiB is plenty for fingerprints
        lb = body.lower()
        last_snippet = body[:240].replace("\n", " ").strip()

        for fp in fps:
            if fp and fp in lb:
                # Carve out a snippet centered on the match to provide context.
                idx = lb.find(fp)
                start = max(0, idx - 60)
                end = min(len(body), idx + len(fp) + 60)
                snippet = body[start:end].replace("\n", " ").strip()
                _ = expected_status  # status used by classifier, not here
                return r.status_code, fp, snippet, last_url

    return last_status, "", last_snippet, last_url


def _build_takeover_resolvers(
    primary: dns.resolver.Resolver,
    extra_nameservers: List[str],
    timeout: float,
) -> List[dns.resolver.Resolver]:
    """
    Build a list of resolvers used for cross-validating takeover DNS state.
    Always includes the primary; appends one resolver per public nameserver
    requested via --takeover-resolvers.
    """
    resolvers: List[dns.resolver.Resolver] = [primary]
    seen_ns: Set[str] = set()
    for ns in extra_nameservers:
        ns = (ns or "").strip()
        if not ns or ns in seen_ns:
            continue
        seen_ns.add(ns)
        try:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = [ns]
            r.timeout = timeout
            r.lifetime = timeout
            resolvers.append(r)
        except Exception:
            continue
    return resolvers


def takeover_check(
    hosts: List[str],
    resolver: dns.resolver.Resolver,
    dns_limiter: GlobalRateLimiter,
    fingerprints: List[str],
    threads: int,
    *,
    verify_http: bool = True,
    http_timeout: float = 8.0,
    http_limiter: Optional[GlobalRateLimiter] = None,
    extra_resolvers: Optional[List[dns.resolver.Resolver]] = None,
) -> List[TakeoverFinding]:
    """
    Two-stage subdomain takeover detection.

    Stage 1 — Detection
      * Follow the CNAME chain (max 6 hops) for each candidate host.
      * Match the final CNAME against TAKEOVER_SIGNATURES (structured DB) and
        also against the legacy `fingerprints` list (suffix patterns).
      * Classify the DNS state of both the host and the CNAME target apex
        (NXDOMAIN / SERVFAIL / NO_ANSWER / OK / TIMEOUT).
      * Cross-resolve the CNAME using extra resolvers and flag disagreement.

    Stage 2 — Confirmation (optional, on by default)
      * For matches in the signature DB, fetch the URL and look for
        service-specific HTTP body fingerprints.
      * Build a confidence label:
          HIGH    — HTTP fingerprint matched.
          MEDIUM  — CNAME matched a signature AND DNS state is consistent
                    (NXDOMAIN on a "nxdomain_only" service, or the host has
                    no live HTTP response at all).
          LOW     — CNAME matched a signature but neither HTTP nor DNS
                    delivered confirming evidence (still worth a manual look).
          INFO    — Dangling CNAME at host without a known signature — pure
                    operator review territory.
    """
    legacy_fps = [x.strip().lower().rstrip(".") for x in fingerprints if x.strip()]
    extras = extra_resolvers or []
    all_resolvers = [resolver] + extras

    def check_one(host: str) -> Optional[TakeoverFinding]:
        evidence: List[str] = []

        # Resolve CNAME chain (host -> ... -> final target).
        chain = cname_chain(resolver, host, dns_limiter)
        cname = chain[-1] if chain else ""
        if not cname:
            # Host has no CNAME — can still be NXDOMAIN-based takeover for some
            # services (rare), but without a target there's nothing to verify.
            return None

        if len(chain) > 1:
            evidence.append(f"cname_chain={' -> '.join([host] + chain)}")

        sig = match_takeover_signature(cname)
        legacy_hit = ""
        for fp in legacy_fps:
            lc = cname.lower()
            if lc == fp or lc.endswith("." + fp):
                legacy_hit = fp
                break

        host_state = classify_dns_state(resolver, host, dns_limiter)
        target_state = classify_dns_state(resolver, cname, dns_limiter)
        evidence.append(f"host_dns={host_state}")
        evidence.append(f"target_dns={target_state}")

        # Apex-of-target SOA probe: SERVFAIL/NXDOMAIN here suggests a dangling
        # delegation (NS-level takeover candidate).
        target_apex = apex_of(cname)
        apex_state = soa_state(resolver, target_apex, dns_limiter) if target_apex else ""
        if apex_state:
            evidence.append(f"target_apex_soa={apex_state}")

        # Multi-resolver cross-check (only if we have >1 resolver).
        disagree = False
        if len(all_resolvers) > 1:
            seen, disagree = multi_resolver_cname(all_resolvers, host, dns_limiter)
            if disagree:
                evidence.append(f"resolver_disagreement={[s or 'None' for s in seen]}")

        # If neither signature nor legacy hit AND host fully resolves AND
        # target fully resolves — nothing to flag (the common case for
        # legitimate SaaS-fronted subdomains).
        if not sig and not legacy_hit and target_state == DNS_STATE_OK and host_state == DNS_STATE_OK:
            return None

        # Stage 2: HTTP confirmation (only when we have a signature OR the
        # CNAME-target appears dangling).
        http_status: Optional[int] = None
        http_fp = ""
        http_snip = ""
        http_url = ""
        if verify_http and (sig or target_state != DNS_STATE_OK):
            fp_list: List[str] = []
            expected_status: Optional[int] = None
            if sig:
                fp_list = list(sig.get("http_fingerprints") or [])  # type: ignore[arg-type]
                expected_status = sig.get("http_status")  # type: ignore[assignment]
            http_status, http_fp, http_snip, http_url = verify_http_signature(
                host=host,
                timeout=http_timeout,
                fingerprints=fp_list,
                expected_status=expected_status,
                limiter=http_limiter,
            )
            if http_status is not None:
                evidence.append(f"http_status={http_status}")
            if http_fp:
                evidence.append(f"http_fingerprint_hit={http_fp!r}")

        # ---- Classification ----
        confidence = ""
        reason = ""
        if sig:
            service = str(sig.get("service") or "")
            vulnerable = bool(sig.get("vulnerable"))
            documentation = str(sig.get("documentation") or "")
            nxdomain_only = bool(sig.get("nxdomain_only"))

            if http_fp:
                confidence = "HIGH"
                reason = (
                    f"Confirmed via HTTP body fingerprint for {service}. "
                    f"Status={http_status}. Pattern={http_fp!r}."
                )
            elif nxdomain_only and target_state in (DNS_STATE_NXDOMAIN, DNS_STATE_SERVFAIL):
                confidence = "MEDIUM"
                reason = (
                    f"CNAME points at {service} but target apex returns "
                    f"{target_state}; service requires NXDOMAIN-style dangling."
                )
            elif target_state in (DNS_STATE_NXDOMAIN, DNS_STATE_SERVFAIL, DNS_STATE_NO_ANSWER):
                confidence = "MEDIUM"
                reason = (
                    f"CNAME points at {service} ({cname}) and target DNS state is "
                    f"{target_state}; consistent with a dangling resource."
                )
            elif http_status in (404, 410) and not http_fp:
                confidence = "LOW"
                reason = (
                    f"CNAME matches {service} and the resource returned HTTP "
                    f"{http_status} but no service fingerprint was found in the body."
                )
            else:
                confidence = "LOW"
                reason = (
                    f"CNAME matches {service} but no confirming HTTP/DNS evidence. "
                    "Manual review recommended."
                )

            return TakeoverFinding(
                host=host,
                cname=cname,
                cname_resolves=(target_state == DNS_STATE_OK),
                reason=reason,
                fingerprint_hit=str(sig.get("cname_patterns", [""])[0]) if sig.get("cname_patterns") else "",
                confidence=confidence,
                service=service,
                dns_state=target_state,
                http_status=http_status,
                http_fingerprint=http_fp,
                http_body_snippet=http_snip,
                http_url=http_url,
                vulnerable=vulnerable,
                documentation=documentation,
                evidence=tuple(evidence),
                multi_resolver_disagree=disagree,
            )

        # No signature DB match — fall back to legacy heuristic, but classify it.
        if legacy_hit and target_state != DNS_STATE_OK:
            return TakeoverFinding(
                host=host,
                cname=cname,
                cname_resolves=False,
                reason=(
                    f"CNAME target is in legacy suffix list ({legacy_hit}) and "
                    f"target DNS state is {target_state}; manual verification required."
                ),
                fingerprint_hit=legacy_hit,
                confidence="MEDIUM",
                service="(legacy fingerprint)",
                dns_state=target_state,
                http_status=http_status,
                http_fingerprint=http_fp,
                http_body_snippet=http_snip,
                http_url=http_url,
                vulnerable=None,
                documentation="",
                evidence=tuple(evidence),
                multi_resolver_disagree=disagree,
            )

        if target_state in (DNS_STATE_NXDOMAIN, DNS_STATE_SERVFAIL):
            return TakeoverFinding(
                host=host,
                cname=cname,
                cname_resolves=False,
                reason=(
                    f"Dangling CNAME: target is {target_state} but no known SaaS "
                    "fingerprint matched. Operator review required."
                ),
                fingerprint_hit="",
                confidence="INFO",
                service="",
                dns_state=target_state,
                http_status=http_status,
                http_fingerprint=http_fp,
                http_body_snippet=http_snip,
                http_url=http_url,
                vulnerable=None,
                documentation="",
                evidence=tuple(evidence),
                multi_resolver_disagree=disagree,
            )

        return None

    findings: List[TakeoverFinding] = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futs = [ex.submit(check_one, h) for h in hosts]
        prog = progress()
        if prog:
            with prog:
                task = prog.add_task("Checking takeover candidates", total=len(futs))
                for fut in as_completed(futs):
                    f = fut.result()
                    if f:
                        findings.append(f)
                    prog.advance(task, 1)
        else:
            for fut in as_completed(futs):
                f = fut.result()
                if f:
                    findings.append(f)

    confidence_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "": 4}
    findings.sort(key=lambda x: (confidence_rank.get(x.confidence, 9), x.host))
    return findings


# ----------------------------
# Prioritization & Clustering
# ----------------------------

def score_target(
    host: str,
    subr: SubdomainResult,
    alive_for_host: List[AliveResult],
    takeover_hit: bool,
    *,
    takeover_confidence: str = "",
) -> Tuple[int, List[str], Optional[str]]:
    score = 0
    reasons: List[str] = []
    best_url: Optional[str] = None

    if subr.resolved:
        score += 5
        reasons.append("dns_resolved:+5")
    if "wildcard_signature_match" in subr.notes:
        score -= 30
        reasons.append("wildcard_fp:-30")

    high_value_env = ("dev", "staging", "stage", "test", "qa", "uat", "preprod", "sandbox")
    admin_surface = ("admin", "console", "internal", "staff", "portal", "dashboard", "backoffice")
    api_surface = ("api", "graphql", "graph", "auth", "login", "sso", "oauth", "token")

    if word_in_host(host, high_value_env):
        score += 15
        reasons.append("env_keyword:+15")
    if word_in_host(host, admin_surface):
        score += 12
        reasons.append("admin_keyword:+12")
    if word_in_host(host, api_surface):
        score += 10
        reasons.append("api_auth_keyword:+10")
    if word_in_host(host, ("cdn", "static", "img", "images", "assets")):
        score += 2
        reasons.append("assets_keyword:+2")

    if takeover_hit:
        if takeover_confidence == "HIGH":
            score += 50
            reasons.append("takeover_high:+50")
        elif takeover_confidence == "MEDIUM":
            score += 25
            reasons.append("takeover_medium:+25")
        elif takeover_confidence == "LOW":
            score += 10
            reasons.append("takeover_low:+10")
        else:
            score += 25
            reasons.append("takeover_candidate:+25")

    alive_ok = [a for a in alive_for_host if a.status is not None and 100 <= a.status < 600]
    https_ok = [a for a in alive_ok if a.url.lower().startswith("https://")]

    pick = None
    if https_ok:
        pick = sorted(https_ok, key=lambda x: (x.status != 200, x.status or 999))[0]
    elif alive_ok:
        pick = sorted(alive_ok, key=lambda x: (x.status != 200, x.status or 999))[0]

    if pick:
        best_url = pick.url
        score += 10
        reasons.append("alive:+10")

        st = pick.status or 0
        if st in (200, 204):
            score += 10
            reasons.append(f"status_{st}:+10")
        elif st in (301, 302, 307, 308):
            score += 10
            reasons.append(f"status_{st}:+10")
        elif st in (401, 403):
            score += 8
            reasons.append(f"status_{st}:+8")
        elif st == 404:
            score -= 3
            reasons.append("status_404:-3")

        if pick.url.lower().startswith("https://"):
            score += 5
            reasons.append("https:+5")

        sv = norm_server(pick.server)
        if sv:
            if sv in ("nginx", "apache", "envoy", "istio", "traefik", "cloudflare"):
                score += 3
                reasons.append(f"server_{sv}:+3")
            if sv in ("gunicorn", "uvicorn", "express", "spring", "rails", "tomcat"):
                score += 5
                reasons.append(f"server_{sv}:+5")

    if len(subr.sources) >= 2:
        score += 2
        reasons.append("multi_source:+2")

    score = max(0, min(100, score))
    return score, reasons, best_url


def cluster_alive(alive_results: List[AliveResult]) -> Tuple[List[Dict[str, str]], List[str]]:
    buckets: Dict[Tuple[str, str, str], List[AliveResult]] = {}
    for r in alive_results:
        if r.status is None:
            continue
        final_host = safe_host_from_url(r.final_url) or safe_host_from_url(r.url) or r.host.lower()
        key = (final_host, str(r.status), norm_server(r.server))
        buckets.setdefault(key, []).append(r)

    rows: List[Dict[str, str]] = []
    reps: List[str] = []

    items = sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for idx, (key, arr) in enumerate(items, start=1):
        final_host, status, server = key
        example = arr[0].final_url or arr[0].url
        reps.append(example)
        rows.append({
            "cluster_id": str(idx),
            "count": str(len(arr)),
            "final_host": final_host,
            "status": status,
            "server": server,
            "example_url": example,
        })

    return rows, reps


# ----------------------------
# Diff / Cache commands
# ----------------------------

def cmd_diff_inner(old_file: Path, new_file: Path, out_dir: Path) -> Path:
    old = set(read_lines(old_file))
    new = set(read_lines(new_file))

    added = sorted(new - old)
    removed = sorted(old - new)

    lines: List[str] = []
    lines.append(f"[+] Added: {len(added)}")
    lines.extend([f"+ {x}" for x in added])
    lines.append("")
    lines.append(f"[-] Removed: {len(removed)}")
    lines.extend([f"- {x}" for x in removed])

    out_path = out_dir / "diff.txt"
    write_lines(out_path, lines)
    return out_path

def cmd_diff(args: argparse.Namespace) -> int:
    banner()

    oldf = Path(args.old).expanduser()
    newf = Path(args.new).expanduser()
    if not oldf.exists() or not newf.exists():
        cprint("[red]ERROR:[/red] --old/--new files must exist.")
        return 2

    out_dir = Path(args.outdir).expanduser() if args.outdir else Path("./subpulse_data/diff") / now_ts_folder()
    ensure_dir(out_dir)

    out_path = cmd_diff_inner(oldf, newf, out_dir)
    cprint(f"[green]DIFF[/green] {out_path}")
    return 0

def cmd_cache(args: argparse.Namespace) -> int:
    banner()

    cache_dir = Path(args.cache_dir).expanduser()
    ensure_dir(cache_dir)

    if args.action == "stats":
        n, b = cache_stats(cache_dir)
        cprint(f"[cyan]Cache entries:[/cyan] {n} | [cyan]Size:[/cyan] {b} bytes | [dim]{cache_dir}[/dim]")
        return 0

    if args.action == "clear":
        n = cache_clear(cache_dir)
        cprint(f"[yellow]Cleared[/yellow] {n} cache files in [dim]{cache_dir}[/dim]")
        return 0

    cprint("[red]ERROR:[/red] Unknown cache action.")
    return 2


# ----------------------------
# SCAN command (the "to-go" flow)
# ----------------------------

def merged_settings(mode: str, policy: str) -> Dict[str, float]:
    base = dict(MODES[mode])
    if policy == "strict":
        base.update(STRICT_POLICY_OVERRIDES)
    return base

def cmd_scan(args: argparse.Namespace) -> int:
    banner()

    domain = normalize_domain(args.domain)
    if not is_valid_domain(domain):
        cprint(f"[red]ERROR:[/red] Invalid domain: {domain}")
        return 2

    settings = merged_settings(args.mode, args.policy)

    base_dir = Path(args.base_dir)
    cache_dir = Path(args.cache_dir)
    ensure_dir(base_dir)
    ensure_dir(cache_dir)

    run_dir = make_run_dir(base_dir, domain, prefix="scan_")
    cdir = cache_dir / domain
    ensure_dir(cdir)

    cache = SimpleJSONCache(cdir)
    session = requests.Session()

    sources = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
    if not sources:
        sources = ["crtsh", "certspotter", "hackertarget", "wayback", "otx", "chaos"]

    # New feature toggles (all default to ON unless the user opts out).
    ports_spec = getattr(args, "ports", "80,443,8080,8443") or ""
    ports = parse_ports_spec(ports_spec)
    harvest_sans = not bool(getattr(args, "no_harvest_sans", False))
    fetch_favicon = not bool(getattr(args, "no_favicon_hash", False))
    fingerprint_tech = not bool(getattr(args, "no_tech_fingerprint", False))
    do_permute = not bool(getattr(args, "no_permute", False))
    permute_max = int(getattr(args, "permute_max", 5000))
    do_nsec = not bool(getattr(args, "no_nsec_walk", False))
    do_reverse_dns = not bool(getattr(args, "no_reverse_dns", False))
    do_html_report = not bool(getattr(args, "no_html_report", False))
    do_latest_symlink = not bool(getattr(args, "no_latest_symlink", False))

    # Apply mode+policy defaults; allow overrides if user set them
    dns_timeout = args.dns_timeout if args.dns_timeout is not None else float(settings["dns_timeout"])
    dns_qps = args.dns_qps if args.dns_qps is not None else float(settings["dns_qps"])
    dns_threads = args.dns_threads if args.dns_threads is not None else int(settings["dns_threads"])

    http_timeout = args.http_timeout if args.http_timeout is not None else float(settings["http_timeout"])
    http_qps = args.http_qps if args.http_qps is not None else float(settings["http_qps"])
    http_retries = args.http_retries if args.http_retries is not None else int(settings["http_retries"])
    http_backoff = args.http_backoff if args.http_backoff is not None else float(settings["http_backoff"])

    alive_threads = args.alive_threads if args.alive_threads is not None else int(settings["alive_threads"])
    alive_qps = args.alive_qps if args.alive_qps is not None else float(settings["alive_qps"])
    alive_timeout = args.alive_timeout if args.alive_timeout is not None else float(settings["alive_timeout"])

    takeover_threads = args.takeover_threads if args.takeover_threads is not None else int(settings["takeover_threads"])
    takeover_dns_qps = args.takeover_dns_qps if args.takeover_dns_qps is not None else float(settings["takeover_dns_qps"])
    takeover_verify_http = (not args.no_takeover_verify_http) if hasattr(args, "no_takeover_verify_http") else True
    takeover_http_timeout = float(getattr(args, "takeover_http_timeout", 8.0))
    takeover_include_unresolved = bool(getattr(args, "takeover_include_unresolved", True))
    takeover_resolvers_arg = getattr(args, "takeover_resolvers", "") or ""
    takeover_resolvers_list = [x.strip() for x in takeover_resolvers_arg.split(",") if x.strip()]

    if args.policy == "strict":
        cprint("[yellow]Policy:[/yellow] strict (safer rates + conservative defaults)")

    http_limiter = GlobalRateLimiter(http_qps)
    dns_limiter = GlobalRateLimiter(dns_qps)
    resolver = make_resolver(args.nameserver or None, dns_timeout)

    cprint(f"[cyan]Scan[/cyan] target={domain} mode={args.mode} policy={args.policy} sources={','.join(sources)}")

    # Wildcard v2 detection happens AFTER candidate collection (we need to
    # know the observed parent depths to probe nested wildcards). Initialise
    # empty placeholders here so the rest of the function reads cleanly.
    wildcard = False
    wildcard_hits: Tuple[str, ...] = ()
    wildcard_sigs: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]] = set()
    wildcards_v2: Dict[str, WildcardEvidence] = {}

    # 1) Passive enum
    per_source = enum_passive(
        domain=domain,
        sources=sources,
        cache=cache,
        cache_ttl=args.cache_ttl,
        session=session,
        http_limiter=http_limiter,
        http_timeout=http_timeout,
        http_retries=http_retries,
        http_backoff=http_backoff,
    )

    # Merge candidates + filter known concatenation artifacts.
    # Artifacts are kept in concat_fp_hosts (with provenance) so the operator
    # can audit them rather than relying on silent drops.
    candidates: Set[str] = set()
    concat_fp_hosts: Dict[str, Set[str]] = {}
    for src, names in per_source.items():
        for n in names:
            nn = normalize_domain(n)
            if not is_subdomain_of(nn, domain):
                continue
            if looks_like_concat_artifact(nn, domain):
                concat_fp_hosts.setdefault(nn, set()).add(src)
                logging.debug("dropped concat artifact from %s: %r", src, nn)
                continue
            candidates.add(nn)

    # 1.5) NSEC walking (DNSSEC zones can be enumerated). Off when zone is
    # unsigned or uses NSEC3 — we report the state either way.
    nsec_mode = ""
    nsec_names: List[str] = []
    if do_nsec:
        cprint("[cyan]NSEC walk[/cyan] (skipped automatically for unsigned / NSEC3 zones)")
        nsec_names, nsec_mode = nsec_walk(domain, dns_limiter)
        if nsec_mode == "nsec":
            cprint(f"[green]NSEC walk[/green]: discovered {len(nsec_names)} names")
        elif nsec_mode == "error" and nsec_names:
            cprint(f"[yellow]NSEC walk[/yellow]: partial walk — {len(nsec_names)} names before stop")
        elif nsec_mode == "nsec3":
            cprint("[yellow]NSEC walk[/yellow]: zone uses NSEC3 (offline cracking required)")
        elif nsec_mode == "unsigned":
            cprint("[cyan]NSEC walk[/cyan]: zone is not DNSSEC-signed; skipped")
        # Merge any names we did collect (works for both full and partial walks).
        for n in nsec_names:
            if is_subdomain_of(n, domain):
                candidates.add(n)

    # 1.6) Permutation generator seeded from the discovered candidates.
    perm_hits: Set[str] = set()
    if do_permute and candidates:
        perm_hits = generate_permutations(candidates, domain, max_perms=permute_max)
        # Don't permute candidates we already have.
        perm_hits -= candidates
        if perm_hits:
            cprint(f"[cyan]Permutation[/cyan]: generated {len(perm_hits)} new candidates")
            candidates.update(perm_hits)

    # Optional bruteforce
    bruteforce = bool(args.wordlist)
    wordlist = Path(args.wordlist).expanduser() if args.wordlist else None
    brute_hits: Dict[str, Tuple[Dict[str, List[str]], bool]] = {}
    if bruteforce:
        if not wordlist.exists():
            cprint(f"[red]ERROR:[/red] Wordlist does not exist: {wordlist}")
            return 2
        if wildcard and not args.allow_wildcard_results:
            cprint("[yellow]WARN:[/yellow] Wildcard DNS detected; bruteforce runs, wildcard-signature matches will be separated into wildcard_fp.txt.")
        brute_hits = bruteforce_dns(
            domain, resolver, dns_limiter, wordlist, dns_threads,
            wildcard_sigs, wildcards_v2=wildcards_v2,
        )
        candidates.update(brute_hits.keys())

    # 1.9) Wildcard signature v2: probe each observed parent depth.
    if not args.no_wildcard_check:
        wildcards_v2 = detect_wildcards_v2(
            domain=domain,
            candidate_hosts=candidates,
            resolver=resolver,
            dns_limiter=dns_limiter,
            samples=3,
            probe_http=True,
            http_timeout=min(http_timeout, 4.0),
        )
        if wildcards_v2:
            wildcard = True
            wildcard_hits = tuple(s for ev in wildcards_v2.values() for s in ev.samples)
            for ev in wildcards_v2.values():
                wildcard_sigs.update(ev.signatures)
            depths_seen = sorted(wildcards_v2.keys())
            depths_human = ", ".join((d or "<apex>") for d in depths_seen)
            cprint(f"[yellow]WARN:[/yellow] Wildcard DNS detected at depths: {depths_human}")

    # 2) DNS validate
    candidates_list = sorted(candidates)
    dns_valid = validate_dns_batch(
        resolver, dns_limiter, candidates_list, dns_threads,
        wildcard_sigs, domain=domain, wildcards_v2=wildcards_v2,
    )

    # Source map
    src_map: Dict[str, Set[str]] = {n: set() for n in candidates}
    for src, names in per_source.items():
        for n in names:
            nn = normalize_domain(n)
            if nn in src_map:
                src_map[nn].add(src)
    for n in brute_hits.keys():
        if n in src_map:
            src_map[n].add("wordlist")

    results_map: Dict[str, SubdomainResult] = {}
    for fqdn in candidates_list:
        rec, ok, mw = dns_valid.get(fqdn, ({"A": [], "AAAA": [], "CNAME": []}, False, False))
        notes: List[str] = ["dns_validated" if ok else "dns_unresolved"]
        if mw:
            notes.append("wildcard_signature_match")
        results_map[fqdn] = SubdomainResult(
            name=fqdn,
            sources=tuple(sorted(src_map.get(fqdn, set()))),
            resolved=ok,
            records=rec,
            notes=tuple(notes),
        )

    # 3) Standard outputs
    all_hosts = sorted(results_map.keys())
    resolved_hosts = sorted([h for h, r in results_map.items() if r.resolved])
    unresolved_hosts = sorted([h for h, r in results_map.items() if not r.resolved])

    wildcard_fp_hosts = sorted([h for h, r in results_map.items() if ("wildcard_signature_match" in r.notes and r.resolved)])
    resolved_strict_hosts = sorted([h for h, r in results_map.items() if r.resolved and ("wildcard_signature_match" not in r.notes)])
    if args.allow_wildcard_results:
        resolved_strict_hosts = resolved_hosts

    # cname map + ips
    cname_lines: List[str] = ["host,cname"]
    ips: Set[str] = set()
    for h in resolved_hosts:
        rec = results_map[h].records
        for ip in rec.get("A", []) + rec.get("AAAA", []):
            if ip:
                ips.add(ip.strip())
        cnames = rec.get("CNAME", [])
        if cnames:
            for c in cnames:
                cname_lines.append(f"{h},{c}")
        else:
            cname_lines.append(f"{h},")

    # Output layout
    # ----------------------------------------------------------------
    # By default we group artifacts by concern (hosts/, dns/, alive/,
    # takeover/, priority/) and keep only the four most-used files at the
    # top level: report.md, scan.json, top_targets.txt, takeover_high.txt.
    #
    # Use --flat to fall back to the legacy single-folder layout for
    # tooling that expects every artifact at run_dir root.
    flat = bool(getattr(args, "flat_layout", False))
    if flat:
        hosts_d = dns_d = alive_d = takeover_d = priority_d = run_dir
    else:
        hosts_d    = run_dir / "hosts"
        dns_d      = run_dir / "dns"
        alive_d    = run_dir / "alive"
        takeover_d = run_dir / "takeover"
        priority_d = run_dir / "priority"

    paths = {
        # ----- top-level (operator-facing) -----
        "report":         run_dir / "report.md",
        "scan_json":      run_dir / "scan.json",
        "top_targets":    run_dir / "top_targets.txt",
        "takeover_high":  run_dir / "takeover_high.txt",

        # ----- hosts/ -----
        "all":             hosts_d / "all.txt",
        "resolved":        hosts_d / "resolved.txt",
        "resolved_strict": hosts_d / "resolved_strict.txt",
        "unresolved":      hosts_d / "unresolved.txt",
        "wildcard_fp":     hosts_d / "wildcard_fp.txt",
        "concat_fp":       hosts_d / "concat_fp.txt",

        # ----- dns/ -----
        "cname_map": dns_d / ("cname_map.csv" if not flat else "cname_map.csv"),
        "ips":       dns_d / "ips.txt",

        # ----- alive/ -----
        "alive_txt":          alive_d / ("urls.txt"     if not flat else "alive.txt"),
        "alive_json":         alive_d / ("results.json" if not flat else "alive.json"),
        "alive_clusters_csv": alive_d / ("clusters.csv" if not flat else "alive_clusters.csv"),
        "alive_unique":       alive_d / ("unique.txt"   if not flat else "alive_unique.txt"),

        # ----- takeover/ -----
        "takeover_txt":  takeover_d / ("candidates.md"   if not flat else "takeover_candidates.txt"),
        "takeover_json": takeover_d / ("candidates.json" if not flat else "takeover_candidates.json"),

        # ----- priority/ -----
        "priority_csv": priority_d / "priority.csv",
        "top_urls":     priority_d / "top_urls.txt",
    }

    def _write_host_artifacts() -> None:
        """Recompute & write all host/DNS-level output files from results_map.

        Called once before the alive stage and again after the SAN/PTR
        feedback iterations so the final files always reflect every
        discovered host.
        """
        nonlocal all_hosts, resolved_hosts, unresolved_hosts, resolved_strict_hosts
        nonlocal wildcard_fp_hosts, cname_lines, ips
        all_hosts = sorted(results_map.keys())
        resolved_hosts = sorted([h for h, r in results_map.items() if r.resolved])
        unresolved_hosts = sorted([h for h, r in results_map.items() if not r.resolved])
        wildcard_fp_hosts = sorted([h for h, r in results_map.items() if ("wildcard_signature_match" in r.notes and r.resolved)])
        resolved_strict_hosts = sorted([h for h, r in results_map.items() if r.resolved and ("wildcard_signature_match" not in r.notes)])
        if args.allow_wildcard_results:
            resolved_strict_hosts = resolved_hosts

        cname_lines = ["host,cname"]
        ips = set()
        for h in resolved_hosts:
            rec = results_map[h].records
            for ip in rec.get("A", []) + rec.get("AAAA", []):
                if ip:
                    ips.add(ip.strip())
            cnames = rec.get("CNAME", [])
            if cnames:
                for c in cnames:
                    cname_lines.append(f"{h},{c}")
            else:
                cname_lines.append(f"{h},")

        write_lines(paths["all"], all_hosts)
        write_lines(paths["resolved"], resolved_hosts)
        write_lines(paths["resolved_strict"], resolved_strict_hosts)
        write_lines(paths["unresolved"], unresolved_hosts)
        write_lines(paths["wildcard_fp"], wildcard_fp_hosts)
        concat_fp_lines = [f"{h}\t# sources: {','.join(sorted(srcs))}" for h, srcs in sorted(concat_fp_hosts.items())]
        write_lines(paths["concat_fp"], concat_fp_lines)
        write_lines(paths["cname_map"], cname_lines)
        write_lines(paths["ips"], sorted(ips))

    _write_host_artifacts()

    # 4) Alive check (strict list) — multi-port + TLS SAN + tech fingerprint
    cprint(f"[cyan]Alive[/cyan] probing {len(resolved_strict_hosts)} hosts across {len(ports)} ports")
    alive_results = alive_check(
        resolved_strict_hosts,
        alive_threads,
        alive_qps,
        alive_timeout,
        ports=ports,
        harvest_sans=harvest_sans,
        fetch_favicon=fetch_favicon,
        fingerprint_tech=fingerprint_tech,
    )

    # 4.5) TLS SAN feedback — pull SANs out of the alive results, drop the ones
    # we already have (and ones out of scope), validate the rest, and merge
    # them into results_map so downstream stages benefit from the extra hosts.
    san_new: Set[str] = set()
    if harvest_sans:
        for ar in alive_results:
            for san in ar.tls_sans:
                if san and is_subdomain_of(san, domain) and san not in results_map and not looks_like_concat_artifact(san, domain):
                    san_new.add(san)
        if san_new:
            cprint(f"[cyan]TLS SAN harvest[/cyan]: {len(san_new)} new candidates")
            san_valid = validate_dns_batch(
                resolver, dns_limiter, sorted(san_new), dns_threads,
                wildcard_sigs, domain=domain, wildcards_v2=wildcards_v2,
            )
            for fqdn, (rec, ok, mw) in san_valid.items():
                src_map.setdefault(fqdn, set()).add("tls_san")
                notes: List[str] = ["dns_validated" if ok else "dns_unresolved"]
                if mw:
                    notes.append("wildcard_signature_match")
                results_map[fqdn] = SubdomainResult(
                    name=fqdn,
                    sources=tuple(sorted(src_map.get(fqdn, set()))),
                    resolved=ok,
                    records=rec,
                    notes=tuple(notes),
                )
            _write_host_artifacts()

            # Probe any newly-resolved-strict hosts to keep alive coverage honest.
            newly_resolved_strict = [h for h in resolved_strict_hosts if not any(ar.host == h for ar in alive_results)]
            if newly_resolved_strict:
                cprint(f"[cyan]Alive[/cyan] re-probing {len(newly_resolved_strict)} newly-validated hosts from SAN harvest")
                alive_results.extend(alive_check(
                    newly_resolved_strict,
                    alive_threads, alive_qps, alive_timeout,
                    ports=ports,
                    harvest_sans=False,  # no second-iteration SAN harvest to avoid loops
                    fetch_favicon=fetch_favicon,
                    fingerprint_tech=fingerprint_tech,
                ))

    # 4.6) Reverse DNS sweep on discovered IPs. PTR records that match the
    # apex domain become new candidates; everything else is recorded for
    # operator review only.
    ptr_map: Dict[str, List[str]] = {}
    ptr_new: Set[str] = set()
    if do_reverse_dns and ips:
        cprint(f"[cyan]Reverse DNS[/cyan] sweeping {len(ips)} IPs")
        ptr_map = reverse_dns_sweep(ips, dns_limiter, threads=dns_threads, timeout=dns_timeout)
        for ip, names in ptr_map.items():
            for n in names:
                if is_subdomain_of(n, domain) and n not in results_map and not looks_like_concat_artifact(n, domain):
                    ptr_new.add(n)
        if ptr_new:
            cprint(f"[cyan]Reverse DNS[/cyan]: {len(ptr_new)} new candidates from PTRs")
            ptr_valid = validate_dns_batch(
                resolver, dns_limiter, sorted(ptr_new), dns_threads,
                wildcard_sigs, domain=domain, wildcards_v2=wildcards_v2,
            )
            for fqdn, (rec, ok, mw) in ptr_valid.items():
                src_map.setdefault(fqdn, set()).add("ptr")
                notes = ["dns_validated" if ok else "dns_unresolved"]
                if mw:
                    notes.append("wildcard_signature_match")
                results_map[fqdn] = SubdomainResult(
                    name=fqdn,
                    sources=tuple(sorted(src_map.get(fqdn, set()))),
                    resolved=ok,
                    records=rec,
                    notes=tuple(notes),
                )
            _write_host_artifacts()

    alive_urls = sorted({r.url for r in alive_results if r.status is not None and 100 <= r.status < 600})
    write_lines(paths["alive_txt"], alive_urls)
    paths["alive_json"].write_text(
        json.dumps([asdict(r) for r in alive_results], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # Alive clustering
    cluster_rows, cluster_reps = cluster_alive(alive_results)
    cluster_csv_lines = ["cluster_id,count,final_host,status,server,example_url"]
    for row in cluster_rows:
        cluster_csv_lines.append(
            f'{row["cluster_id"]},{row["count"]},{row["final_host"]},{row["status"]},{row["server"]},{row["example_url"]}'
        )
    write_lines(paths["alive_clusters_csv"], cluster_csv_lines)
    write_lines(paths["alive_unique"], cluster_reps)

    # 5) Takeover detection + confirmation
    takeover_dns_limiter = GlobalRateLimiter(takeover_dns_qps)
    takeover_resolver = make_resolver(args.nameserver or None, dns_timeout)
    takeover_extra_resolvers = _build_takeover_resolvers(
        takeover_resolver, takeover_resolvers_list, dns_timeout,
    )[1:]
    # Re-use the alive HTTP limiter for takeover HTTP probes to keep the
    # global outbound rate consistent. The function tolerates None.
    takeover_http_limiter = GlobalRateLimiter(alive_qps)
    fingerprints = [x.strip() for x in args.fingerprints.split(",")] if args.fingerprints else DEFAULT_TAKEOVER_FPS

    # Candidate pool: strict-resolved + (optionally) unresolved hosts. Many
    # real takeovers manifest with NXDOMAIN at the host itself (the apex
    # CNAME is dangling), which the v1 pipeline missed entirely.
    if takeover_include_unresolved:
        takeover_candidates_hosts = sorted(set(resolved_strict_hosts) | set(unresolved_hosts))
    else:
        takeover_candidates_hosts = list(resolved_strict_hosts)

    takeover_findings = takeover_check(
        takeover_candidates_hosts,
        takeover_resolver,
        takeover_dns_limiter,
        fingerprints,
        takeover_threads,
        verify_http=takeover_verify_http,
        http_timeout=takeover_http_timeout,
        http_limiter=takeover_http_limiter,
        extra_resolvers=takeover_extra_resolvers,
    )

    takeover_high_hosts: Set[str] = set()
    takeover_medium_hosts: Set[str] = set()
    takeover_hosts: Set[str] = set()
    for f in takeover_findings:
        takeover_hosts.add(f.host)
        if f.confidence == "HIGH":
            takeover_high_hosts.add(f.host)
        elif f.confidence == "MEDIUM":
            takeover_medium_hosts.add(f.host)

    # Pretty markdown table (still .txt — keeps the legacy filename).
    md_lines: List[str] = []
    md_lines.append("# Takeover candidates")
    md_lines.append("")
    md_lines.append(
        f"- HIGH:   {sum(1 for x in takeover_findings if x.confidence == 'HIGH')}"
    )
    md_lines.append(
        f"- MEDIUM: {sum(1 for x in takeover_findings if x.confidence == 'MEDIUM')}"
    )
    md_lines.append(
        f"- LOW:    {sum(1 for x in takeover_findings if x.confidence == 'LOW')}"
    )
    md_lines.append(
        f"- INFO:   {sum(1 for x in takeover_findings if x.confidence == 'INFO')}"
    )
    md_lines.append("")
    md_lines.append("| Confidence | Service | Host | CNAME | DNS state | HTTP | Evidence |")
    md_lines.append("|---|---|---|---|---|---|---|")
    for f in takeover_findings:
        http_cell = ""
        if f.http_status is not None:
            http_cell = f"{f.http_status}"
            if f.http_fingerprint:
                http_cell += f" / `{f.http_fingerprint}`"
        evid = ", ".join(f.evidence)[:200]
        md_lines.append(
            f"| {f.confidence or '-'} | {f.service or '-'} | `{f.host}` | "
            f"`{f.cname}` | {f.dns_state or '-'} | {http_cell or '-'} | {evid} |"
        )
    md_lines.append("")
    md_lines.append(
        "_Note: Confidence HIGH = HTTP body fingerprint matched. MEDIUM = "
        "CNAME match + matching DNS state. LOW = CNAME match without "
        "confirming evidence. INFO = dangling CNAME without a known service "
        "signature. All findings still require manual validation before "
        "reporting / claiming._"
    )
    write_lines(paths["takeover_txt"], md_lines)

    paths["takeover_json"].write_text(
        json.dumps([asdict(x) for x in takeover_findings], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # Dedicated HIGH-confidence file (script-friendly).
    high_lines = [
        f"{f.host} -> {f.cname} | {f.service} | {f.reason}"
        for f in takeover_findings if f.confidence == "HIGH"
    ]
    write_lines(paths["takeover_high"], high_lines)

    # 6) Priority scoring
    alive_by_host: Dict[str, List[AliveResult]] = {}
    for r in alive_results:
        alive_by_host.setdefault(r.host.lower(), []).append(r)

    # Map host -> best (highest) confidence label observed for that host.
    confidence_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "": 4}
    host_confidence: Dict[str, str] = {}
    for f in takeover_findings:
        prev = host_confidence.get(f.host, "")
        if confidence_rank.get(f.confidence, 9) < confidence_rank.get(prev, 9):
            host_confidence[f.host] = f.confidence

    prio_rows: List[Tuple[str, int, str, str]] = []
    for h in resolved_hosts:
        subr = results_map[h]
        score, reasons, best_url = score_target(
            host=h,
            subr=subr,
            alive_for_host=alive_by_host.get(h.lower(), []),
            takeover_hit=(h in takeover_hosts),
            takeover_confidence=host_confidence.get(h, ""),
        )
        prio_rows.append((h, score, best_url or "", ";".join(reasons)))

    prio_rows.sort(key=lambda x: (-x[1], x[0]))

    prio_csv_lines = ["host,score,best_url,reasons"]
    for h, sc, url, rs in prio_rows:
        hh = f'"{h}"' if "," in h else h
        uu = f'"{url}"' if "," in url else url
        rr = f'"{rs}"' if "," in rs else rs
        prio_csv_lines.append(f"{hh},{sc},{uu},{rr}")

    write_lines(paths["priority_csv"], prio_csv_lines)
    write_lines(paths["top_targets"], [h for h, _, _, _ in prio_rows[:50]])
    write_lines(paths["top_urls"], [url for _, _, url, _ in prio_rows[:100] if url])

    # 7) scan.json + report.md
    meta = {
        "target": domain,
        "mode": args.mode,
        "policy": args.policy,
        "sources": sources,
        "bruteforce": bruteforce,
        "wildcard_dns_likely": bool(wildcard),
        "wildcard_sample_hits": list(wildcard_hits),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "disclaimer": DISCLAIMER,
        "settings": {
            "dns_threads": dns_threads,
            "dns_qps": dns_qps,
            "dns_timeout": dns_timeout,
            "http_qps": http_qps,
            "http_timeout": http_timeout,
            "http_retries": http_retries,
            "http_backoff": http_backoff,
            "alive_threads": alive_threads,
            "alive_qps": alive_qps,
            "alive_timeout": alive_timeout,
            "takeover_threads": takeover_threads,
            "takeover_dns_qps": takeover_dns_qps,
            "takeover_verify_http": takeover_verify_http,
            "takeover_http_timeout": takeover_http_timeout,
            "takeover_include_unresolved": takeover_include_unresolved,
            "takeover_resolvers": takeover_resolvers_list,
        },
        "counts": {
            "all": len(all_hosts),
            "resolved": len(resolved_hosts),
            "resolved_strict": len(resolved_strict_hosts),
            "unresolved": len(unresolved_hosts),
            "wildcard_fp": len(wildcard_fp_hosts),
            "concat_fp": len(concat_fp_hosts),
            "alive_urls": len(alive_urls),
            "alive_clusters": len(cluster_rows),
            "takeover_candidates": len(takeover_findings),
            "takeover_high": sum(1 for f in takeover_findings if f.confidence == "HIGH"),
            "takeover_medium": sum(1 for f in takeover_findings if f.confidence == "MEDIUM"),
            "takeover_low": sum(1 for f in takeover_findings if f.confidence == "LOW"),
            "takeover_info": sum(1 for f in takeover_findings if f.confidence == "INFO"),
            "nsec_walk_mode": nsec_mode,
            "nsec_walk_names": len(nsec_names),
            "permutations_generated": len(perm_hits),
            "tls_sans_new": len(san_new),
            "ptr_new": len(ptr_new),
            "ptr_total": sum(len(v) for v in ptr_map.values()),
        },
        "outputs": {k: str(v) for k, v in paths.items()},
    }

    payload = {
        "meta": meta,
        "results": [asdict(results_map[h]) for h in all_hosts],
        "alive": [asdict(r) for r in alive_results],
        "takeover": [asdict(x) for x in takeover_findings],
        "priority": [{"host": h, "score": sc, "best_url": url, "reasons": rs} for (h, sc, url, rs) in prio_rows],
        "alive_clusters": cluster_rows,
    }
    paths["scan_json"].write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # HTML report (must run before report.md so the .md can reference it).
    if do_html_report:
        paths["report_html"] = run_dir / "report.html"
        paths["report_html"].write_text(render_html_report(payload, run_dir), encoding="utf-8")

    top_targets = prio_rows[:20]
    top_targets_md = "\n".join([f"- **{sc}** — `{h}`  {('→ ' + url) if url else ''}" for (h, sc, url, _) in top_targets])

    report_lines: List[str] = []
    report_lines.append("# SubPulse Scan Report")
    report_lines.append("")
    report_lines.append(f"- Target: `{domain}`")
    report_lines.append(f"- Mode: `{args.mode}`")
    report_lines.append(f"- Policy: `{args.policy}`")
    report_lines.append(f"- Sources: `{', '.join(sources)}`")
    report_lines.append(f"- Bruteforce: `{bruteforce}`")
    report_lines.append(f"- Wildcard DNS likely: `{bool(wildcard)}`")
    if wildcard_hits:
        report_lines.append(f"- Wildcard sample hits: `{', '.join(wildcard_hits)}`")
    report_lines.append("")
    report_lines.append("## Counts")
    report_lines.append(f"- All: **{len(all_hosts)}**")
    report_lines.append(f"- Resolved (DNS): **{len(resolved_hosts)}**")
    report_lines.append(f"- Resolved (strict): **{len(resolved_strict_hosts)}**")
    report_lines.append(f"- Unresolved: **{len(unresolved_hosts)}**")
    report_lines.append(f"- Wildcard probable FP: **{len(wildcard_fp_hosts)}**")
    report_lines.append(f"- Concatenation artifacts (filtered): **{len(concat_fp_hosts)}**")
    if nsec_mode:
        report_lines.append(f"- NSEC walk mode: `{nsec_mode}` (names: **{len(nsec_names)}**)")
    if perm_hits:
        report_lines.append(f"- Permutations generated: **{len(perm_hits)}**")
    if san_new:
        report_lines.append(f"- TLS SAN harvest (new candidates): **{len(san_new)}**")
    if ptr_new:
        report_lines.append(f"- PTR-derived candidates: **{len(ptr_new)}**")
    report_lines.append(f"- Alive URLs: **{len(alive_urls)}**")
    report_lines.append(f"- Alive clusters: **{len(cluster_rows)}**")
    report_lines.append(f"- Takeover candidates: **{len(takeover_findings)}**")
    report_lines.append(
        "  - HIGH: **{h}**, MEDIUM: **{m}**, LOW: **{l}**, INFO: **{i}**".format(
            h=sum(1 for f in takeover_findings if f.confidence == "HIGH"),
            m=sum(1 for f in takeover_findings if f.confidence == "MEDIUM"),
            l=sum(1 for f in takeover_findings if f.confidence == "LOW"),
            i=sum(1 for f in takeover_findings if f.confidence == "INFO"),
        )
    )
    report_lines.append("")
    report_lines.append("## Top targets (auto-prioritized)")
    report_lines.append(top_targets_md if top_targets_md else "- (none)")
    report_lines.append("")
    def _rel(p: Path) -> str:
        """Show paths relative to the run dir when possible (cleaner report)."""
        try:
            return str(p.relative_to(run_dir))
        except ValueError:
            return str(p)

    report_lines.append("## Outputs (grouped layout)")
    report_lines.append("")
    report_lines.append("**Top-level (read these first):**")
    report_lines.append(f"- Report (this file): `{_rel(paths['report'])}`")
    if do_html_report and "report_html" in paths:
        report_lines.append(f"- HTML report (sortable tables): `{_rel(paths['report_html'])}`")
    report_lines.append(f"- Full scan JSON (single source of truth): `{_rel(paths['scan_json'])}`")
    report_lines.append(f"- Top targets: `{_rel(paths['top_targets'])}`")
    report_lines.append(f"- HIGH-confidence takeovers: `{_rel(paths['takeover_high'])}`")
    report_lines.append("")
    report_lines.append("**`hosts/` — enumeration & validation:**")
    report_lines.append(f"- All discovered: `{_rel(paths['all'])}`")
    report_lines.append(f"- Resolved: `{_rel(paths['resolved'])}`")
    report_lines.append(f"- Resolved (strict, wildcard FPs removed): `{_rel(paths['resolved_strict'])}`")
    report_lines.append(f"- Unresolved: `{_rel(paths['unresolved'])}`")
    report_lines.append(f"- Wildcard FPs: `{_rel(paths['wildcard_fp'])}`")
    report_lines.append(f"- Concatenation artifacts: `{_rel(paths['concat_fp'])}`")
    report_lines.append("")
    report_lines.append("**`dns/` — DNS-level evidence:**")
    report_lines.append(f"- CNAME map: `{_rel(paths['cname_map'])}`")
    report_lines.append(f"- IPs: `{_rel(paths['ips'])}`")
    if "ptr_map" in paths:
        report_lines.append(f"- PTR map (reverse DNS): `{_rel(paths['ptr_map'])}`")
    report_lines.append("")
    report_lines.append("**`alive/` — HTTP probing results:**")
    report_lines.append(f"- Alive URLs: `{_rel(paths['alive_txt'])}`")
    report_lines.append(f"- Full alive JSON: `{_rel(paths['alive_json'])}`")
    report_lines.append(f"- Clusters (CSV): `{_rel(paths['alive_clusters_csv'])}`")
    report_lines.append(f"- Unique representatives: `{_rel(paths['alive_unique'])}`")
    report_lines.append("")
    report_lines.append("**`takeover/` — detection & confirmation evidence:**")
    report_lines.append(f"- Markdown table: `{_rel(paths['takeover_txt'])}`")
    report_lines.append(f"- Structured JSON: `{_rel(paths['takeover_json'])}`")
    report_lines.append("")
    report_lines.append("**`priority/` — auto-scoring:**")
    report_lines.append(f"- Priority CSV: `{_rel(paths['priority_csv'])}`")
    report_lines.append(f"- Top URLs: `{_rel(paths['top_urls'])}`")
    report_lines.append("")
    report_lines.append("## Notes")
    report_lines.append("- `hosts/wildcard_fp.txt` contains hosts that resolved but match a wildcard signature observed for random labels.")
    report_lines.append("- `hosts/concat_fp.txt` contains names dropped pre-DNS as upstream-source SAN concatenation artifacts (e.g. HackerTarget gluing two SANs from a shared CDN cert). Each line shows the offending name and which source(s) produced it.")
    report_lines.append(
        "- Takeover results include HTTP body confirmation for HIGH-confidence "
        "findings; all confidence levels still require manual verification "
        "before reporting or claiming ownership of a service."
    )
    report_lines.append("- Pass `--flat` to write every artifact at the run-dir root (legacy layout) instead of the grouped layout shown above.")
    report_lines.append("")
    paths["report"].write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    # PTR map (DNS evidence) — write whatever we collected.
    if ptr_map:
        paths["ptr_map"] = run_dir / ("dns" if not flat else ".") / ("ptr_map.csv")
        ptr_lines = ["ip,ptr"]
        for ip in sorted(ptr_map.keys()):
            for ptr in ptr_map[ip]:
                ptr_lines.append(f"{ip},{ptr}")
        write_lines(paths["ptr_map"], ptr_lines)

    # Optional structured diff against previous run + `latest` symlink.
    if args.resume_diff:
        prev = find_previous_run_dir(base_dir, domain, run_dir)
        if prev:
            # Legacy line-based diff (added/removed only) — kept for tools
            # that grep `diff.txt`.
            candidates = [prev / "hosts" / "all.txt", prev / "all.txt"]
            old_all = next((c for c in candidates if c.exists()), None)
            if old_all is not None:
                diff_path = cmd_diff_inner(old_all, paths["all"], run_dir)
                cprint(f"[yellow]DIFF[/yellow] {diff_path}")

            # Structured diff (added/removed/changed + takeover deltas).
            prev_payload = _load_scan_json(prev)
            if prev_payload is not None:
                diff = diff_scans(prev_payload, payload)
                paths["diff_json"] = run_dir / "diff.json"
                paths["diff_md"]   = run_dir / "diff.md"
                paths["diff_json"].write_text(
                    json.dumps(diff, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                paths["diff_md"].write_text(render_diff_markdown(diff), encoding="utf-8")
                cprint(
                    "[yellow]DIFF[/yellow] "
                    f"+{len(diff['added'])} -{len(diff['removed'])} "
                    f"~{len(diff['changed'])} "
                    f"takeover_new={len(diff['takeover_new'])} "
                    f"escalated={len(diff['takeover_escalated'])}"
                )

    # Maintain subpulse_data/<domain>/latest -> <run_dir>.
    if do_latest_symlink:
        link = update_latest_symlink(base_dir, domain, run_dir)
        if link is not None:
            cprint(f"[green]LATEST[/green] {link} -> {run_dir.name}")

    # Summary UI
    if RICH and _RICH_CONSOLE is not None:
        t = Table(title="Scan Summary", box=box.SIMPLE_HEAVY)
        t.add_column("Metric")
        t.add_column("Value", justify="right")
        t.add_row("Target", domain)
        t.add_row("Mode", args.mode)
        t.add_row("Policy", args.policy)
        t.add_row("All", str(len(all_hosts)))
        t.add_row("Resolved (DNS)", str(len(resolved_hosts)))
        t.add_row("Resolved (strict)", str(len(resolved_strict_hosts)))
        t.add_row("Wildcard FP", str(len(wildcard_fp_hosts)))
        t.add_row("Concat artifacts", str(len(concat_fp_hosts)))
        t.add_row("Alive URLs", str(len(alive_urls)))
        t.add_row("Alive clusters", str(len(cluster_rows)))
        t.add_row("Takeover candidates", str(len(takeover_findings)))
        t.add_row(
            "  HIGH / MEDIUM / LOW / INFO",
            "{} / {} / {} / {}".format(
                sum(1 for f in takeover_findings if f.confidence == "HIGH"),
                sum(1 for f in takeover_findings if f.confidence == "MEDIUM"),
                sum(1 for f in takeover_findings if f.confidence == "LOW"),
                sum(1 for f in takeover_findings if f.confidence == "INFO"),
            ),
        )
        t.add_row("Output dir", str(run_dir))
        _RICH_CONSOLE.print(t)
    else:
        print(f"[+] Target: {domain} | mode={args.mode} | policy={args.policy}")
        print(f"[+] All: {len(all_hosts)} | Resolved: {len(resolved_hosts)} | Strict: {len(resolved_strict_hosts)} | WildcardFP: {len(wildcard_fp_hosts)}")
        print(f"[+] Alive URLs: {len(alive_urls)} | Alive clusters: {len(cluster_rows)} | Takeover candidates: {len(takeover_findings)}")
        print(f"[+] Output dir: {run_dir}")

    cprint(f"[green]RUN DIR[/green] {run_dir}")
    cprint(f"[green]REPORT[/green]  {paths['report']}")
    cprint(f"[green]JSON[/green]    {paths['scan_json']}")
    return 0


# ----------------------------
# CLI
# ----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subpulse.py",
        description="SubPulse — single-file subdomain recon tool (authorized use only).",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="One-command recon: enum + validate + outputs + alive + takeover + priority + clustering + report.")
    ps.add_argument("domain", help="Target domain (e.g., example.com)")
    ps.add_argument("--mode", default="balanced", choices=list(MODES.keys()), help="Recon mode preset (default: balanced)")
    ps.add_argument("--policy", default="normal", choices=["normal", "strict"], help="Guardrails policy (default: normal). strict = safer rates + conservative defaults.")
    ps.add_argument(
        "--sources",
        default="crtsh,certspotter,hackertarget,wayback,otx,chaos",
        help=(
            "Comma-separated passive sources. Supported: crtsh, certspotter, "
            "hackertarget, wayback, otx, chaos. Chaos requires CHAOS_API_KEY "
            "(or PDCP_API_KEY) in the environment; it auto-skips when missing."
        ),
    )
    ps.add_argument("--wordlist", help="If provided, enables DNS brute-force with this wordlist")
    ps.add_argument("--resume-diff", action="store_true", help="Diff current all.txt against previous scan run (if any)")

    ps.add_argument("--nameserver", action="append", default=[], help="Custom DNS server IP (repeatable)")
    ps.add_argument("--no-wildcard-check", action="store_true", help="Disable wildcard DNS detection")
    ps.add_argument("--allow-wildcard-results", action="store_true", help="Include wildcard-signature matches in strict outputs too")

    ps.add_argument("--cache-dir", default="./subpulse_data/cache", help="Cache directory")
    ps.add_argument("--cache-ttl", type=int, default=6 * 3600, help="Cache TTL seconds")
    ps.add_argument("--base-dir", default="./subpulse_data", help="Output base directory")
    ps.add_argument(
        "--flat",
        dest="flat_layout",
        action="store_true",
        help=(
            "Write every artifact at the run-dir root (legacy layout) instead "
            "of the default grouped layout (hosts/, dns/, alive/, takeover/, "
            "priority/). Use this if downstream tooling expects the old "
            "filenames."
        ),
    )

    ps.add_argument("--fingerprints", default=",".join(DEFAULT_TAKEOVER_FPS), help="Comma-separated SaaS suffix fingerprints for takeover heuristic")

    # Optional overrides (available but not required)
    ps.add_argument("--dns-timeout", type=float, default=None, help="Override DNS timeout seconds")
    ps.add_argument("--dns-qps", type=float, default=None, help="Override DNS QPS (global)")
    ps.add_argument("--dns-threads", type=int, default=None, help="Override DNS threads")
    ps.add_argument("--http-timeout", type=float, default=None, help="Override HTTP timeout seconds")
    ps.add_argument("--http-qps", type=float, default=None, help="Override HTTP QPS (global)")
    ps.add_argument("--http-retries", type=int, default=None, help="Override HTTP retries")
    ps.add_argument("--http-backoff", type=float, default=None, help="Override HTTP backoff base seconds")
    ps.add_argument("--alive-threads", type=int, default=None, help="Override alive threads")
    ps.add_argument("--alive-qps", type=float, default=None, help="Override alive HTTP QPS (global)")
    ps.add_argument("--alive-timeout", type=float, default=None, help="Override alive HTTP timeout seconds")
    ps.add_argument("--takeover-threads", type=int, default=None, help="Override takeover threads")
    ps.add_argument("--takeover-dns-qps", type=float, default=None, help="Override takeover DNS QPS (global)")
    ps.add_argument(
        "--no-takeover-verify-http",
        action="store_true",
        help="Disable HTTP body fingerprint confirmation (DNS-only takeover heuristic).",
    )
    ps.add_argument(
        "--takeover-http-timeout",
        type=float,
        default=8.0,
        help="HTTP timeout (seconds) for takeover confirmation probes (default: 8.0).",
    )
    ps.add_argument(
        "--no-takeover-include-unresolved",
        dest="takeover_include_unresolved",
        action="store_false",
        help="Do NOT include hosts that did not resolve at the host level in the takeover scan.",
    )
    ps.set_defaults(takeover_include_unresolved=True)
    ps.add_argument(
        "--takeover-resolvers",
        default="1.1.1.1,8.8.8.8,9.9.9.9",
        help=(
            "Comma-separated public resolver IPs used to cross-validate "
            "takeover CNAME resolution (default: 1.1.1.1,8.8.8.8,9.9.9.9). "
            "Set empty string to disable cross-validation."
        ),
    )

    # --- Alive / TLS / tech / favicon ---
    ps.add_argument(
        "--ports",
        default="80,443,8080,8443",
        help=(
            "Comma-separated alive-check ports. Accepts bare numbers "
            "(scheme inferred from port) or 'scheme:port' pairs, e.g. "
            "'80,443,8080,8443' or 'http:8080,https:443'."
        ),
    )
    ps.add_argument("--no-harvest-sans", action="store_true",
                    help="Don't collect SubjectAltName DNS entries from alive TLS certs.")
    ps.add_argument("--no-favicon-hash", action="store_true",
                    help="Don't compute MD5 of /favicon.ico on alive hosts.")
    ps.add_argument("--no-tech-fingerprint", action="store_true",
                    help="Don't run the technology-fingerprint matcher on alive hosts.")

    # --- Discovery booster toggles ---
    ps.add_argument("--no-permute", action="store_true",
                    help="Don't run the permutation generator on discovered labels.")
    ps.add_argument("--permute-max", type=int, default=5000,
                    help="Cap on permutations generated per scan (default: 5000).")
    ps.add_argument("--no-nsec-walk", action="store_true",
                    help="Skip the NSEC chain walk (auto-skipped for unsigned / NSEC3 zones anyway).")
    ps.add_argument("--no-reverse-dns", action="store_true",
                    help="Skip PTR lookups on discovered IPs.")

    # --- Reporting / monitoring ---
    ps.add_argument("--no-html-report", action="store_true",
                    help="Don't render report.html (Markdown + JSON still produced).")
    ps.add_argument("--no-latest-symlink", action="store_true",
                    help="Don't maintain subpulse_data/<domain>/latest symlink.")

    pd = sub.add_parser("diff", help="Diff two files (line-based).")
    pd.add_argument("--old", required=True, help="Old file")
    pd.add_argument("--new", required=True, help="New file")
    pd.add_argument("--outdir", help="Output directory (default: ./subpulse_data/diff/<timestamp>)")

    pc = sub.add_parser("cache", help="Cache management (stats/clear).")
    pc.add_argument("action", choices=["stats", "clear"])
    pc.add_argument("--cache-dir", default="./subpulse_data/cache", help="Cache directory")

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s"
    )

    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "diff":
        return cmd_diff(args)
    if args.cmd == "cache":
        return cmd_cache(args)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
