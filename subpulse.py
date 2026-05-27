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

DEFAULT_TAKEOVER_FPS = [
    "amazonaws.com",
    "cloudfront.net",
    "azurewebsites.net",
    "trafficmanager.net",
    "github.io",
    "herokuapp.com",
    "netlify.app",
    "fastly.net",
    "zendesk.com",
    "helpscoutdocs.com",
    "readme.io",
]

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

def banner() -> None:
    if RICH and _RICH_CONSOLE is not None:
        _RICH_CONSOLE.print(
            Panel.fit(
                f"[bold cyan]SubPulse[/bold cyan] (single-file)\n[dim]{DISCLAIMER}[/dim]",
                border_style="cyan",
                title="🧠 Subdomain Recon",
            )
        )
    else:
        print("SubPulse (single-file)")
        print(DISCLAIMER)
        print("-" * 80)

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
    hits: List[str] = []
    sigs: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]] = set()
    for _ in range(samples):
        cand = f"{rand_label()}.{domain}"
        rec = resolve_records(resolver, cand, dns_limiter)
        if looks_resolved(rec):
            hits.append(cand)
            sigs.add(records_signature(rec))
    return (len(hits) > 0), tuple(hits), sigs

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

@dataclass(frozen=True)
class TakeoverFinding:
    host: str
    cname: str
    cname_resolves: bool
    reason: str
    fingerprint_hit: str = ""


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
    runs = [p for p in dom_dir.iterdir() if p.is_dir()]
    runs.sort(key=lambda p: p.name, reverse=True)
    for i, p in enumerate(runs):
        if p.resolve() == current.resolve() and i + 1 < len(runs):
            return runs[i + 1]
    return runs[0] if runs else None


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

    for s in sources:
        if s == "crtsh":
            out[s] = enum_crtsh()
        elif s == "certspotter":
            out[s] = enum_certspotter()
        elif s == "hackertarget":
            out[s] = enum_hackertarget()
        else:
            out[s] = set()

    return out


def validate_dns_batch(
    resolver: dns.resolver.Resolver,
    dns_limiter: GlobalRateLimiter,
    names: List[str],
    dns_threads: int,
    wildcard_sigs: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]],
) -> Dict[str, Tuple[Dict[str, List[str]], bool, bool]]:
    def _one(fqdn: str):
        rec = resolve_records(resolver, fqdn, dns_limiter)
        ok = looks_resolved(rec)
        mw = records_signature(rec) in wildcard_sigs if (ok and wildcard_sigs) else False
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


def alive_check(hosts: List[str], threads: int, qps: float, timeout: float) -> List[AliveResult]:
    limiter = GlobalRateLimiter(qps)

    def check_one(host: str) -> List[AliveResult]:
        host = host.strip()
        if not host:
            return []
        out: List[AliveResult] = []
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                limiter.acquire()
                r = requests.head(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "SubPulse/1.0"},
                )
                out.append(
                    AliveResult(
                        host=host,
                        url=url,
                        status=r.status_code,
                        server=r.headers.get("Server", ""),
                        final_url=str(r.url),
                    )
                )
            except Exception:
                try:
                    limiter.acquire()
                    r = requests.get(
                        url,
                        timeout=timeout,
                        allow_redirects=True,
                        headers={"User-Agent": "SubPulse/1.0"},
                    )
                    out.append(
                        AliveResult(
                            host=host,
                            url=url,
                            status=r.status_code,
                            server=r.headers.get("Server", ""),
                            final_url=str(r.url),
                        )
                    )
                except Exception as e2:
                    out.append(AliveResult(host=host, url=url, status=None, error=str(e2)))
        return out

    results: List[AliveResult] = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futs = [ex.submit(check_one, h) for h in hosts]
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


def takeover_check(
    hosts: List[str],
    resolver: dns.resolver.Resolver,
    dns_limiter: GlobalRateLimiter,
    fingerprints: List[str],
    threads: int,
) -> List[TakeoverFinding]:
    fps = [x.strip().lower().rstrip(".") for x in fingerprints if x.strip()]

    def check_one(host: str) -> Optional[TakeoverFinding]:
        cname = resolve_cname(resolver, host, dns_limiter)
        if not cname:
            return None

        lc = cname.lower()
        hit = ""
        for fp in fps:
            if lc == fp or lc.endswith("." + fp):
                hit = fp
                break

        resolves = cname_target_resolves(resolver, cname, dns_limiter)
        if not resolves and hit:
            return TakeoverFinding(
                host=host,
                cname=cname,
                cname_resolves=False,
                reason="CNAME target did not resolve (A/AAAA) and matches known SaaS fingerprint (heuristic)",
                fingerprint_hit=hit,
            )
        if not resolves and not hit:
            return TakeoverFinding(
                host=host,
                cname=cname,
                cname_resolves=False,
                reason="CNAME target did not resolve (A/AAAA); fingerprint not matched (manual review)",
                fingerprint_hit="",
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

    findings.sort(key=lambda x: (x.fingerprint_hit == "", x.host))
    return findings


# ----------------------------
# Prioritization & Clustering
# ----------------------------

def score_target(
    host: str,
    subr: SubdomainResult,
    alive_for_host: List[AliveResult],
    takeover_hit: bool,
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
        sources = ["crtsh", "certspotter", "hackertarget"]

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

    if args.policy == "strict":
        cprint("[yellow]Policy:[/yellow] strict (safer rates + conservative defaults)")

    http_limiter = GlobalRateLimiter(http_qps)
    dns_limiter = GlobalRateLimiter(dns_qps)
    resolver = make_resolver(args.nameserver or None, dns_timeout)

    # Wildcard detection + signatures
    wildcard = False
    wildcard_hits: Tuple[str, ...] = ()
    wildcard_sigs: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]] = set()
    if not args.no_wildcard_check:
        wildcard, wildcard_hits, wildcard_sigs = detect_wildcard_signatures(domain, resolver, dns_limiter, samples=3)
        if wildcard:
            cprint(f"[yellow]WARN:[/yellow] Wildcard DNS likely (random resolves): {', '.join(wildcard_hits)}")

    cprint(f"[cyan]Scan[/cyan] target={domain} mode={args.mode} policy={args.policy} sources={','.join(sources)}")

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
        brute_hits = bruteforce_dns(domain, resolver, dns_limiter, wordlist, dns_threads, wildcard_sigs)
        candidates.update(brute_hits.keys())

    # 2) DNS validate
    candidates_list = sorted(candidates)
    dns_valid = validate_dns_batch(resolver, dns_limiter, candidates_list, dns_threads, wildcard_sigs)

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

    paths = {
        "all": run_dir / "all.txt",
        "resolved": run_dir / "resolved.txt",
        "resolved_strict": run_dir / "resolved_strict.txt",
        "unresolved": run_dir / "unresolved.txt",
        "wildcard_fp": run_dir / "wildcard_fp.txt",
        "concat_fp": run_dir / "concat_fp.txt",
        "cname_map": run_dir / "cname_map.csv",
        "ips": run_dir / "ips.txt",
        "alive_txt": run_dir / "alive.txt",
        "alive_json": run_dir / "alive.json",
        "takeover_txt": run_dir / "takeover_candidates.txt",
        "takeover_json": run_dir / "takeover_candidates.json",
        "priority_csv": run_dir / "priority.csv",
        "top_targets": run_dir / "top_targets.txt",
        "top_urls": run_dir / "top_urls.txt",
        "alive_clusters_csv": run_dir / "alive_clusters.csv",
        "alive_unique": run_dir / "alive_unique.txt",
        "scan_json": run_dir / "scan.json",
        "report": run_dir / "report.md",
    }

    write_lines(paths["all"], all_hosts)
    write_lines(paths["resolved"], resolved_hosts)
    write_lines(paths["resolved_strict"], resolved_strict_hosts)
    write_lines(paths["unresolved"], unresolved_hosts)
    write_lines(paths["wildcard_fp"], wildcard_fp_hosts)
    concat_fp_lines = [f"{h}\t# sources: {','.join(sorted(srcs))}" for h, srcs in sorted(concat_fp_hosts.items())]
    write_lines(paths["concat_fp"], concat_fp_lines)
    write_lines(paths["cname_map"], cname_lines)
    write_lines(paths["ips"], sorted(ips))

    # 4) Alive check (strict list)
    alive_results = alive_check(resolved_strict_hosts, alive_threads, alive_qps, alive_timeout)
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

    # 5) Takeover heuristic
    takeover_dns_limiter = GlobalRateLimiter(takeover_dns_qps)
    takeover_resolver = make_resolver(args.nameserver or None, dns_timeout)
    fingerprints = [x.strip() for x in args.fingerprints.split(",")] if args.fingerprints else DEFAULT_TAKEOVER_FPS
    takeover_findings = takeover_check(resolved_strict_hosts, takeover_resolver, takeover_dns_limiter, fingerprints, takeover_threads)

    takeover_lines = []
    takeover_hosts: Set[str] = set()
    for f in takeover_findings:
        takeover_hosts.add(f.host)
        fp = f" fp={f.fingerprint_hit}" if f.fingerprint_hit else ""
        takeover_lines.append(f"{f.host} -> {f.cname}{fp} | {f.reason}")

    write_lines(paths["takeover_txt"], takeover_lines)
    paths["takeover_json"].write_text(
        json.dumps([asdict(x) for x in takeover_findings], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # 6) Priority scoring
    alive_by_host: Dict[str, List[AliveResult]] = {}
    for r in alive_results:
        alive_by_host.setdefault(r.host.lower(), []).append(r)

    prio_rows: List[Tuple[str, int, str, str]] = []
    for h in resolved_hosts:
        subr = results_map[h]
        score, reasons, best_url = score_target(
            host=h,
            subr=subr,
            alive_for_host=alive_by_host.get(h.lower(), []),
            takeover_hit=(h in takeover_hosts),
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
    report_lines.append(f"- Alive URLs: **{len(alive_urls)}**")
    report_lines.append(f"- Alive clusters: **{len(cluster_rows)}**")
    report_lines.append(f"- Takeover candidates: **{len(takeover_findings)}**")
    report_lines.append("")
    report_lines.append("## Top targets (auto-prioritized)")
    report_lines.append(top_targets_md if top_targets_md else "- (none)")
    report_lines.append("")
    report_lines.append("## Key outputs")
    report_lines.append(f"- Top targets: `{paths['top_targets']}`")
    report_lines.append(f"- Priority CSV: `{paths['priority_csv']}`")
    report_lines.append(f"- Alive URLs: `{paths['alive_txt']}`")
    report_lines.append(f"- Alive clusters: `{paths['alive_clusters_csv']}`")
    report_lines.append(f"- Alive unique reps: `{paths['alive_unique']}`")
    report_lines.append(f"- Takeover candidates: `{paths['takeover_txt']}`")
    report_lines.append(f"- CNAME map: `{paths['cname_map']}`")
    report_lines.append(f"- IPs: `{paths['ips']}`")
    report_lines.append(f"- Full JSON: `{paths['scan_json']}`")
    report_lines.append("")
    report_lines.append("## Notes")
    report_lines.append("- `wildcard_fp.txt` contains hosts that resolved but match wildcard signature observed for random labels.")
    report_lines.append("- `concat_fp.txt` contains names dropped pre-DNS as upstream-source SAN concatenation artifacts (e.g. HackerTarget gluing two SANs from a shared CDN cert). Each line shows the offending name and which source(s) produced it.")
    report_lines.append("- Takeover results are heuristic only; manual verification required.")
    report_lines.append("")
    paths["report"].write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    # Optional diff against previous run
    if args.resume_diff:
        prev = find_previous_run_dir(base_dir, domain, run_dir)
        if prev:
            old_all = prev / "all.txt"
            if old_all.exists():
                diff_path = cmd_diff_inner(old_all, paths["all"], run_dir)
                cprint(f"[yellow]DIFF[/yellow] {diff_path}")

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
    ps.add_argument("--sources", default="crtsh,certspotter,hackertarget", help="Sources: crtsh,certspotter,hackertarget (comma-separated)")
    ps.add_argument("--wordlist", help="If provided, enables DNS brute-force with this wordlist")
    ps.add_argument("--resume-diff", action="store_true", help="Diff current all.txt against previous scan run (if any)")

    ps.add_argument("--nameserver", action="append", default=[], help="Custom DNS server IP (repeatable)")
    ps.add_argument("--no-wildcard-check", action="store_true", help="Disable wildcard DNS detection")
    ps.add_argument("--allow-wildcard-results", action="store_true", help="Include wildcard-signature matches in strict outputs too")

    ps.add_argument("--cache-dir", default="./subpulse_data/cache", help="Cache directory")
    ps.add_argument("--cache-ttl", type=int, default=6 * 3600, help="Cache TTL seconds")
    ps.add_argument("--base-dir", default="./subpulse_data", help="Output base directory")

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
