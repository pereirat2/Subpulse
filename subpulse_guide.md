# SubPulse — Recon Tool (Phase 1)

> AUTHORIZED USE ONLY  
> Use only with explicit permission and strictly within the program scope / Rules of Engagement (ROE).  
> Respect rate limits and Terms of Service.

---

# What This Tool Does (In One Command)

The `scan` command executes a complete Phase 1 reconnaissance pipeline:

1. Passive enumeration (CT / OSINT sources): crtsh, certspotter, hackertarget
2. DNS validation + wildcard detection + wildcard signature filtering
3. Clean “ready-to-use” outputs (all / resolved / resolved_strict / wildcard_fp / ...)
4. HTTP/HTTPS alive check (with redirect support)
5. Heuristic takeover detection (dangling CNAME patterns)
6. Automatic prioritization (score 0–100 with reasons)
7. Alive clustering (to reduce repetition)
8. Generates report.md and scan.json

---

# Installation

pip install requests dnspython rich
python3 subpulse.py -h

---

# Recommended Workflow (Copy/Paste)

## 1) Default Scan (Balanced Mode)

python3 subpulse.py scan <domain>

---

## 2) Stealth Mode (Slower, Safer)

python3 subpulse.py scan <domain> --mode stealth

---

## 3) Strict Policy (Extra Guardrails)

Ideal if the ROE is tight or you want conservative defaults.

python3 subpulse.py scan <domain> --policy strict

---

## 4) Scan + Brute-Force (Only If Allowed)

Passing --wordlist automatically enables DNS brute-force.

python3 subpulse.py scan <domain> --wordlist ./subdomains.txt

---

## 5) Automatic Diff vs Previous Run

python3 subpulse.py scan <domain> --resume-diff

---

# Output Directory Structure

./subpulse_data/<domain>/scan_<timestamp>/

---

# Quick Triage — What To Open First

## 1) Immediate Focus

top_targets.txt  → First file to open  
top_urls.txt     → Recommended URLs (best effort ranking)  
priority.csv     → Score + reasons (why it ranked high)

---

## 2) Reduce Repetition (Clusters)

alive_clusters.csv  → Grouped by (final host, status, server)  
alive_unique.txt    → One representative URL per cluster

---

## 3) Takeover Review

takeover_candidates.txt → Heuristic results (requires manual validation)

---

## 4) Noise Control

resolved_strict.txt → Main working list (excludes wildcard signature matches)  
wildcard_fp.txt     → Likely wildcard false positives  
resolved.txt        → Includes wildcard matches (reference only)

---

# Output Files Explained

all.txt                    → All discovered subdomains (deduplicated)  
resolved.txt               → DNS-resolving subdomains (includes wildcard matches)  
resolved_strict.txt        → Resolving subdomains excluding wildcard signature matches (default working set)  
unresolved.txt             → Did not resolve (may be useful later)  
alive.txt                  → URLs that responded (HTTP/HTTPS)  
alive.json                 → Detailed alive check data (status, server, final_url, error)  
alive_clusters.csv         → Clusters by “same app/service”  
alive_unique.txt           → One representative URL per cluster  
cname_map.csv              → Host → CNAME mapping  
ips.txt                    → Aggregated A/AAAA IPs  
takeover_candidates.txt    → Heuristic takeover candidates  
priority.csv               → Score + reasons per host  
top_targets.txt            → Top 50 hosts by score  
top_urls.txt               → Top URLs by score  
report.md                  → Actionable summary  
scan.json                  → Full structured output (automation-ready)

---

# Available Commands

## scan

Full reconnaissance pipeline (recommended for Phase 1).

Examples:

python3 subpulse.py scan example.com
python3 subpulse.py scan example.com --mode stealth
python3 subpulse.py scan example.com --policy strict
python3 subpulse.py scan example.com --wordlist ./subdomains.txt
python3 subpulse.py scan example.com --nameserver 1.1.1.1 --nameserver 8.8.8.8
python3 subpulse.py scan example.com --allow-wildcard-results
python3 subpulse.py scan example.com --resume-diff

Important Flags:

--mode stealth|balanced|aggressive
--policy normal|strict
--sources crtsh,certspotter,hackertarget
--wordlist <path>
--nameserver <ip>     (repeatable)
--no-wildcard-check
--allow-wildcard-results
--resume-diff
--cache-dir
--cache-ttl
--base-dir
--fingerprints <csv>

Advanced Overrides (Usually Not Needed):

--dns-timeout
--dns-qps
--dns-threads
--http-timeout
--http-qps
--http-retries
--http-backoff
--alive-threads
--alive-qps
--alive-timeout
--takeover-threads
--takeover-dns-qps

---

## diff

Line-based diff between two files:

python3 subpulse.py diff --old old.txt --new new.txt

---

## cache

View or clear cache:

python3 subpulse.py cache stats
python3 subpulse.py cache clear

---

# How Prioritization Works (Heuristic Model)

Each host receives a score from 0–100.

Favors:

- Alive hosts (especially HTTPS)
- Status 200 / 3xx
- Also 401 / 403 (protected applications)
- Interesting keywords in hostname:
  dev, staging, admin, api, auth
- Takeover candidates
- Multi-source discovery

Penalizes:

- Wildcard signature matches (likely false positives)

---

The priority score is a focus guide, not absolute truth.
Always apply manual validation and critical thinking.
