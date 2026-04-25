# SubPulse

A fast, single-file subdomain reconnaissance tool for authorized security testing.

## Disclaimer

**For authorized use only.** Use this tool only with explicit permission and within the scope of your engagement or bug bounty program. Respect rate limits, provider Terms of Service, and local laws. No exploitation is performed — reconnaissance and validation only.

## Features

- **Passive enumeration** via crt.sh, CertSpotter, and HackerTarget
- **DNS bruteforce** with optional wordlist
- **Wildcard detection** and signature filtering
- **Alive checking** (HTTP/HTTPS probing with clustering)
- **Takeover detection** for common SaaS fingerprints
- **Auto-prioritization** based on keywords, status codes, and HTTP headers
- **Rich CLI output** with progress bars
- **JSON + markdown reports**

## Installation

```bash
pip install requests dnspython rich
```

```bash
python3 subpulse.py --help
```

## Usage

### Basic scan

```bash
python3 subpulse.py scan example.com
```

### Stealth mode (slower, quieter)

```bash
python3 subpulse.py scan example.com --mode stealth
```

### With DNS bruteforce

```bash
python3 subpulse.py scan example.com --wordlist ./subdomains.txt
```

### Strict policy (safer rates)

```bash
python3 subpulse.py scan example.com --policy strict
```

### Diff against previous scan

```bash
python3 subpulse.py scan example.com --resume-diff
```

### Custom sources

```bash
python3 subpulse.py scan example.com --sources crtsh,certspotter
```

## Output Files

| File | Description |
|------|-------------|
| `all.txt` | All discovered subdomains |
| `resolved.txt` | Subdomains with valid DNS records |
| `resolved_strict.txt` | Resolved minus wildcard FPs |
| `alive.txt` | Live HTTP/HTTPS URLs |
| `takeover_candidates.txt` | Potential subdomain takeovers |
| `priority.csv` | Scored targets with reasons |
| `top_targets.txt` | Top 50 prioritized hosts |
| `scan.json` | Full results in JSON |
| `report.md` | Markdown summary report |

## Modes

| Mode | Speed | Rate |
|------|-------|------|
| `stealth` | Slowest | Quietest |
| `balanced` | Default | Moderate |
| `aggressive` | Fastest | Loudest |

## Cache

```bash
# View cache stats
python3 subpulse.py cache stats

# Clear cache
python3 subpulse.py cache clear
```

## License

MIT — See [DISCLAIMER](/subpulse.py#L4-L9) for authorized use terms.