<div align="center">

<img src="assets/logo.svg" alt="SubPulse — subdomain reconnaissance" width="820">

<br>

**Fast, single-file subdomain reconnaissance — passive + active discovery, alive checks, takeover detection, and structured reporting.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](#license)
[![Single File](https://img.shields.io/badge/single--file-yes-success)](subpulse.py)
[![Authorized use only](https://img.shields.io/badge/use-authorized%20only-red)](#authorized-use)

</div>

---

## Table of Contents

- [What is SubPulse?](#what-is-subpulse)
- [Highlights](#highlights)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [Common recipes](#common-recipes)
  - [Passive sources](#passive-sources)
  - [Active discovery boosters](#active-discovery-boosters)
  - [Alive / TLS / tech](#alive--tls--tech)
  - [Takeover tuning](#takeover-tuning)
  - [Continuous monitoring](#continuous-monitoring)
- [How It Works](#how-it-works)
- [Output Structure](#output-structure)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Modes & Policies](#modes--policies)
- [Cache](#cache)
- [Tips](#tips)
- [Roadmap](#roadmap)
- [Authorized Use](#authorized-use)
- [License](#license)

---

## What is SubPulse?

**SubPulse** is a one-file Python recon tool that runs an end-to-end subdomain pipeline in a single command:

```
enum  →  validate  →  alive  →  takeover  →  prioritize  →  report
```

It bundles passive enumeration, DNS bruteforce, permutation generation, NSEC walking, reverse DNS sweeps, multi-port alive checks (with TLS SAN harvesting and tech fingerprinting), heuristic + active subdomain-takeover detection, and structured Markdown / JSON / HTML reports — all in one self-contained script with only three runtime dependencies.

The output is designed for both humans (`report.md`, `report.html`) and downstream tooling (`scan.json`, grouped per-stage text files).

## Highlights

<table>
<tr>
<td>

**Enumeration**

- crt.sh, CertSpotter, HackerTarget
- Wayback Machine, AlienVault OTX
- ProjectDiscovery Chaos (API key)
- DNS bruteforce (custom wordlist)
- Permutation generator (env / region / digit / separator swaps)
- NSEC walking (auto-skips NSEC3)
- Reverse-DNS sweep (PTRs fed back as new candidates)

</td>
<td>

**Validation & alive**

- Wildcard v2 — per-label-depth RR-tuple + body-hash signatures
- Multi-resolver DNS validation
- Multi-port HTTP/HTTPS probing (80/443/8080/8443 by default)
- TLS SAN harvest (SANs fed back for one extra validation pass)
- Tech fingerprinting (curated 40+ pattern DB)
- Favicon MD5 hashing
- Redirect-chain capture, title, server, status

</td>
</tr>
<tr>
<td>

**Takeover detection**

- 40+ SaaS signatures (S3, GitHub Pages, Heroku, Azure, Netlify, Vercel, Shopify, …)
- DNS state classification: `NXDOMAIN` / `SERVFAIL` / `NO_ANSWER` / `OK` / `TIMEOUT`
- CNAME chain following (up to 6 hops) + apex SOA probe
- Cross-resolver validation (suppresses stale-cache false positives)
- Active HTTP body fingerprinting for HIGH-confidence confirmation
- Confidence labels: `HIGH` / `MEDIUM` / `LOW` / `INFO`

</td>
<td>

**Reporting & ops**

- Markdown report (`report.md`) — read this first
- Self-contained HTML report (`report.html`) — sortable tables, no CDN
- Full structured JSON (`scan.json`) — single source of truth
- Auto-prioritized targets (keywords, status, headers, takeover confidence)
- Structured diff vs previous run (added / removed / **changed** / takeover escalations)
- `latest` symlink per domain for continuous-monitoring loops
- On-disk response cache, rate limiting, retries with backoff

</td>
</tr>
</table>

## Quick Start

```bash
git clone https://github.com/pereirat2/Subpulse.git
cd Subpulse
pip install -r requirements.txt
python3 subpulse.py scan example.com
```

That single command runs the full pipeline and writes a timestamped run directory under `subpulse_data/example.com/scan_<UTC>/`, plus a `latest` symlink that always points at the most recent run.

```bash
# read the human report
$ open subpulse_data/example.com/latest/report.html
# or
$ less subpulse_data/example.com/latest/report.md
```

## Installation

**Requirements:** Python 3.9+ on macOS, Linux, or WSL.

```bash
pip install -r requirements.txt
```

Dependencies (3 packages, all on PyPI):

| Package      | Purpose                                  |
|--------------|------------------------------------------|
| `requests`   | HTTP probing for alive checks + takeover |
| `dnspython`  | DNS resolution, NSEC walking, PTR lookups|
| `rich`       | Colored console output (graceful fallback if missing) |

> SubPulse is a **single Python file** (`subpulse.py`) — no build step, no install command, no package layout. Clone and run.

## Usage

### Common recipes

```bash
# Basic scan (defaults: balanced mode, all free passive sources, permutations on)
python3 subpulse.py scan example.com

# Stealth mode — slower, quieter, gentler on rate limits
python3 subpulse.py scan example.com --mode stealth

# Aggressive mode — fastest, loudest
python3 subpulse.py scan example.com --mode aggressive

# Add DNS bruteforce with a custom wordlist
python3 subpulse.py scan example.com --wordlist ./subdomains.txt

# Strict policy — extra conservative defaults
python3 subpulse.py scan example.com --policy strict

# Verbose progress
python3 subpulse.py -v scan example.com
```

### Passive sources

```bash
# Use all default sources (Chaos auto-skips when CHAOS_API_KEY / PDCP_API_KEY are missing)
python3 subpulse.py scan example.com \
    --sources crtsh,certspotter,hackertarget,wayback,otx,chaos

# Minimal & fast
python3 subpulse.py scan example.com --sources crtsh,otx

# Chaos requires an API key
CHAOS_API_KEY=... python3 subpulse.py scan example.com --sources chaos
```

### Active discovery boosters

```bash
# Permutation generator (default: on, cap 5 000)
python3 subpulse.py scan example.com --permute-max 2000
python3 subpulse.py scan example.com --no-permute

# NSEC walk (auto-skipped on unsigned / NSEC3 zones)
python3 subpulse.py scan example.com --no-nsec-walk

# Reverse-DNS sweep (PTRs matching the apex are fed back as new candidates)
python3 subpulse.py scan example.com --no-reverse-dns
```

### Alive / TLS / tech

```bash
# Probe extra dev ports
python3 subpulse.py scan example.com --ports 80,443,8080,8443,3000,5000

# Explicit scheme:port
python3 subpulse.py scan example.com --ports http:8080,https:8443

# Trim noise — skip optional probes
python3 subpulse.py scan example.com \
    --no-harvest-sans --no-favicon-hash --no-tech-fingerprint
```

### Takeover tuning

```bash
# DNS-only heuristic (no outbound HTTP confirmation)
python3 subpulse.py scan example.com --no-takeover-verify-http

# Cross-validate dangling CNAMEs against custom resolvers
python3 subpulse.py scan example.com \
    --takeover-resolvers 1.1.1.1,8.8.8.8,9.9.9.9

# Skip unresolved hosts (faster — misses NXDOMAIN-style takeovers)
python3 subpulse.py scan example.com --no-takeover-include-unresolved

# Slow target? bump the per-probe HTTP timeout
python3 subpulse.py scan example.com --takeover-http-timeout 12.0
```

### Continuous monitoring

```bash
# Diff against the previous run; emits diff.md + diff.json
python3 subpulse.py scan example.com --resume-diff

# Disable the latest/ symlink (e.g. on filesystems that don't support symlinks)
python3 subpulse.py scan example.com --no-latest-symlink
```

A cron-friendly loop:

```bash
# /etc/cron.daily/subpulse-example
cd /opt/subpulse && \
    python3 subpulse.py scan example.com --resume-diff --mode stealth
```

## How It Works

```
                          ┌──────────────────────┐
                          │  PASSIVE SOURCES     │ crt.sh, CertSpotter,
                          │  (cached, rate-      │ HackerTarget, Wayback,
                          │   limited, retries)  │ OTX, Chaos
                          └──────────┬───────────┘
                                     ▼
                          ┌──────────────────────┐
   permutation gen  ──►   │      CANDIDATES      │   ◄── wordlist bruteforce
   NSEC walk        ──►   │  (deduped, scope-    │   ◄── reverse-DNS sweep
                          │   filtered)          │
                          └──────────┬───────────┘
                                     ▼
                          ┌──────────────────────┐
                          │  DNS VALIDATION      │   wildcard v2 filter
                          │  (multi-resolver)    │   per-depth signatures
                          └──────────┬───────────┘
                                     ▼
                          ┌──────────────────────┐
                          │  ALIVE CHECK         │   multi-port HTTP/HTTPS
                          │  + TLS SAN harvest   │ ──► feedback loop (one
                          │  + tech fingerprint  │      extra validation pass)
                          │  + favicon hash      │
                          └──────────┬───────────┘
                                     ▼
                          ┌──────────────────────┐
                          │  TAKEOVER DETECTION  │   DNS state + CNAME chain
                          │  + HTTP confirmation │   + multi-resolver xcheck
                          │  + confidence label  │   + body-fingerprint match
                          └──────────┬───────────┘
                                     ▼
                          ┌──────────────────────┐
                          │  PRIORITIZE + DIFF   │   score by keywords,
                          │  + REPORT (md/html)  │   status, takeover conf.
                          └──────────────────────┘
```

## Output Structure

Outputs are grouped by concern so each run directory stays scannable. Pass `--flat` to fall back to the legacy single-folder layout.

```
subpulse_data/<domain>/
├── latest/                          # symlink → most recent scan_<timestamp>/
└── scan_2026-05-29T14-37-12Z/
    ├── report.md                    # human-readable summary (read this first)
    ├── report.html                  # self-contained HTML report (sortable tables)
    ├── scan.json                    # full structured data (single source of truth)
    ├── top_targets.txt              # top 50 prioritized hosts
    ├── takeover_high.txt            # actionable takeovers (HIGH-confidence + vulnerable=yes)
    ├── takeover_review.txt          # HIGH-fingerprint matches on services with vulnerable=no (informational; written only when present)
    ├── diff.md / diff.json          # structured diff vs previous run (--resume-diff)
    │
    ├── hosts/
    │   ├── all.txt                  # all discovered subdomains
    │   ├── resolved.txt             # subdomains with valid DNS records
    │   ├── resolved_strict.txt      # resolved minus wildcard FPs
    │   ├── unresolved.txt           # didn't resolve
    │   ├── wildcard_fp.txt          # wildcard-signature matches
    │   └── concat_fp.txt            # upstream SAN-concatenation artifacts
    │
    ├── dns/
    │   ├── cname_map.csv            # host → cname
    │   ├── ips.txt                  # union of A / AAAA
    │   └── ptr_map.csv              # IP → PTR (when reverse-DNS is on)
    │
    ├── alive/
    │   ├── urls.txt                 # live HTTP/HTTPS URLs
    │   ├── results.json             # full per-URL: status, title, tech, SANs, favicon MD5, redirect chain
    │   ├── clusters.csv             # alive results clustered by (host, status, server)
    │   └── unique.txt               # one representative URL per cluster
    │
    ├── takeover/
    │   ├── candidates.md            # findings + confidence
    │   └── candidates.json          # structured findings (service, DNS state, HTTP evidence, body snippet)
    │
    └── priority/
        ├── priority.csv             # scored targets with reasons
        └── top_urls.txt             # top 100 URLs
```

## CLI Reference

<details>
<summary><b>Top-level subcommands</b></summary>

| Subcommand | Purpose                                       |
|------------|-----------------------------------------------|
| `scan`     | One-command pipeline (enum → alive → takeover → report). |
| `diff`     | Line-based diff between two text files.       |
| `cache`    | Inspect or clear the on-disk response cache.  |

</details>

<details>
<summary><b>scan — core flags</b></summary>

| Flag                                   | Default     | What it does                                          |
|----------------------------------------|-------------|-------------------------------------------------------|
| `--mode {stealth,balanced,aggressive}` | `balanced`  | Pace / concurrency preset.                            |
| `--policy {normal,strict}`             | `normal`    | `strict` = safer rates + conservative defaults.       |
| `--sources`                            | all free    | Comma list: `crtsh,certspotter,hackertarget,wayback,otx,chaos`. |
| `--wordlist PATH`                      | off         | Enables DNS bruteforce with the given wordlist.       |
| `--nameserver IP` (repeatable)         | system      | Use a custom DNS resolver.                            |
| `--no-wildcard-check`                  | off         | Skip wildcard detection.                              |
| `--allow-wildcard-results`             | off         | Include wildcard matches in strict outputs.           |
| `--base-dir DIR`                       | `subpulse_data` | Where runs are written.                           |
| `--flat`                               | off         | Legacy single-folder output layout.                   |
| `--resume-diff`                        | off         | Diff against the previous run.                        |

</details>

<details>
<summary><b>scan — alive / TLS / tech</b></summary>

| Flag                       | Default                | What it does                                |
|----------------------------|------------------------|---------------------------------------------|
| `--ports`                  | `80,443,8080,8443`     | Bare numbers or `scheme:port` pairs.        |
| `--no-harvest-sans`        | off                    | Skip TLS SubjectAltName harvesting.         |
| `--no-favicon-hash`        | off                    | Skip favicon MD5.                           |
| `--no-tech-fingerprint`    | off                    | Skip tech fingerprint matcher.              |

</details>

<details>
<summary><b>scan — active discovery</b></summary>

| Flag                  | Default | What it does                              |
|-----------------------|---------|-------------------------------------------|
| `--no-permute`        | off     | Disable permutation generator.            |
| `--permute-max N`     | `5000`  | Cap on generated permutations.            |
| `--no-nsec-walk`      | off     | Skip NSEC chain walking.                  |
| `--no-reverse-dns`    | off     | Skip PTR sweep over discovered IPs.       |

</details>

<details>
<summary><b>scan — takeover</b></summary>

| Flag                                    | Default               | What it does                                       |
|-----------------------------------------|-----------------------|----------------------------------------------------|
| `--fingerprints`                        | curated DB            | Override SaaS suffix list (legacy heuristic).      |
| `--no-takeover-verify-http`             | off                   | Skip active HTTP confirmation.                     |
| `--takeover-http-timeout SEC`           | `8.0`                 | HTTP timeout for takeover probes.                  |
| `--no-takeover-include-unresolved`      | off                   | Don't probe unresolved hosts for takeover.         |
| `--takeover-resolvers IP,IP,…`          | `1.1.1.1,8.8.8.8,9.9.9.9` | Multi-resolver CNAME cross-validation.         |

</details>

<details>
<summary><b>scan — output</b></summary>

| Flag                    | Default | What it does                                  |
|-------------------------|---------|-----------------------------------------------|
| `--no-html-report`      | off     | Skip `report.html` generation.                |
| `--no-latest-symlink`   | off     | Don't maintain the per-domain `latest/` symlink. |

</details>

<details>
<summary><b>scan — rate / concurrency overrides</b></summary>

Mode/policy presets are usually enough — these are for fine-tuning specific stages.

| Flag                       | Stage     |
|----------------------------|-----------|
| `--dns-timeout`            | DNS       |
| `--dns-qps`                | DNS       |
| `--dns-threads`            | DNS       |
| `--http-timeout`           | HTTP (passive) |
| `--http-qps`               | HTTP (passive) |
| `--http-retries`           | HTTP (passive) |
| `--http-backoff`           | HTTP (passive) |
| `--alive-threads`          | Alive     |
| `--alive-qps`              | Alive     |
| `--alive-timeout`          | Alive     |
| `--takeover-threads`       | Takeover  |
| `--takeover-dns-qps`       | Takeover  |
| `--cache-dir`              | Cache     |
| `--cache-ttl`              | Cache     |

</details>

Get full help any time:

```bash
python3 subpulse.py scan --help
```

## Configuration

SubPulse reads three environment variables (all optional):

| Variable                                   | Purpose                                    |
|--------------------------------------------|--------------------------------------------|
| `CHAOS_API_KEY` *(or `PDCP_API_KEY`)*      | Enables the ProjectDiscovery Chaos source. |
| `HTTPS_PROXY` / `HTTP_PROXY`               | Standard `requests` proxy honoring.        |
| `NO_COLOR`                                 | Disables `rich` color output.              |

## Modes & Policies

| Mode         | Speed     | Rate       | When to use                                  |
|--------------|-----------|------------|----------------------------------------------|
| `stealth`    | Slowest   | Quietest   | Sensitive targets, third-party-managed assets. |
| `balanced`   | Default   | Moderate   | Most engagements.                            |
| `aggressive` | Fastest   | Loudest    | Big internal scopes, your own infrastructure. |

`--policy strict` additionally lowers QPS ceilings and disables a few of the more chatty probes — useful when you're not 100% sure the network operator wants you hammering them.

## Cache

SubPulse caches passive-source responses on disk under `subpulse_data/cache/` (or `--cache-dir`):

```bash
# Inspect
python3 subpulse.py cache stats

# Clear all cached responses
python3 subpulse.py cache clear

# Custom TTL (seconds)
python3 subpulse.py scan example.com --cache-ttl 86400
```

## Tips

- **Start cheap, then expand.** Run `--sources crtsh,otx` first; if results look right, add `wayback` and `hackertarget`.
- **Use `--resume-diff` from day one.** The diff output is most valuable when you have a baseline, so build the baseline immediately.
- **Wildcards trip every recon tool.** If you see suspiciously perfect resolution, check `hosts/wildcard_fp.txt` before triaging anything else.
- **Takeover confidence levels matter.** `HIGH` = HTTP body fingerprint matched. `MEDIUM` = CNAME + DNS state match, no HTTP confirmation. `LOW` / `INFO` = heuristic only — manual verification needed before reporting.
- **`takeover_high.txt` vs `takeover_review.txt`.** The actionable bucket (`takeover_high.txt`) only contains HIGH-confidence findings on services that are publicly documented as exploitable today. HIGH-confidence fingerprint matches against services with `vulnerable=no` (e.g. AWS CloudFront / Fastly — both require ACM-style ownership validation before a CNAME alias can be claimed) are split into `takeover_review.txt` so they don't get conflated with real takeovers. SubPulse also runs an active **TLS-cert claim check** on every HIGH-confidence match: if the upstream presents a cert that already covers the host (CN/SAN match), the alias is provably claimed by the legitimate owner and the finding is auto-demoted to `INFO` with the supporting evidence recorded.
- **Permutation cap.** Discovered labels can explode the candidate set. `--permute-max` is your safety valve.

## Roadmap

- Async rewrite of the alive stage (current implementation uses `ThreadPoolExecutor`).
- WHOIS / RDAP correlation on root + apex.
- Pluggable passive-source modules.
- Built-in webhook / Slack notifier for diff highlights.

## Authorized Use

> **AUTHORIZED USE ONLY.** Use SubPulse exclusively against assets you own or have explicit, documented permission to test (in-scope bug-bounty targets, signed pentest engagements, your own infrastructure).
>
> You are responsible for:
>
> - Respecting target rate limits and provider Terms of Service.
> - Operating within your engagement's rules-of-engagement (ROE).
> - Complying with all applicable laws and regulations in your jurisdiction.
>
> SubPulse performs reconnaissance and validation only — it does not exploit vulnerabilities, and shipping it does not imply consent to scan any specific target.

## License

MIT — free to use, modify, and redistribute under the terms of the [MIT License](https://opensource.org/licenses/MIT).
