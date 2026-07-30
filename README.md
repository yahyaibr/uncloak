# UNCLOAK

```
██╗   ██╗███╗   ██╗ ██████╗██╗      ██████╗  █████╗ ██╗  ██╗
██║   ██║████╗  ██║██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝
██║   ██║██╔██╗ ██║██║     ██║     ██║   ██║███████║█████╔╝
██║   ██║██║╚██╗██║██║     ██║     ██║   ██║██╔══██║██╔═██╗
╚██████╔╝██║ ╚████║╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗
 ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

**Strip the CDN. Find the real server.**

A passive OSINT / reconnaissance tool that maps an organization's internet
footprint — ASNs, IP ranges, and domains sharing infrastructure — to help
identify the real origin server behind a CDN or WAF (Cloudflare, Akamai,
Fastly, etc.).

Built around the intelligence-gathering workflow described in *Web Hacking
Arsenal* (Rafay Baloch), Ch. 2 — Intelligence Gathering and Enumeration.

---

## Features

- **ASN enumeration** — look up the Autonomous System Numbers tied to an
  organization name (via [RIPEstat](https://stat.ripe.net), RIPE NCC's free
  public data API).
- **IP range enumeration** — pull all IPv4/IPv6 prefixes announced by an ASN.
- **Reverse IP lookup** — find other domains hosted on the same IP or CIDR
  block (via [rapiddns.io](https://rapiddns.io)), useful for spotting
  origin servers that still resolve directly.
- **CDN fronting check** — resolve a domain and flag if its IP's network
  owner looks like a known CDN/WAF provider, so you know the resolved IP
  is *not* the real origin.
- Structured JSON output you can pipe into other tools.

## Why RIPEstat instead of bgpview.io?

This tool originally used the `bgpview.io` API, which was **permanently
shut down on November 26, 2025**. It now uses
[RIPEstat](https://stat.ripe.net/docs/data-api/), the official, free,
no-API-key data service run by RIPE NCC — one of the five Regional Internet
Registries — as a more durable long-term data source.

## Scope & disclaimer

UNCLOAK only queries **public, passive** data sources. It does not perform
active scanning, port probing, or exploitation of any kind.

Only use this tool against assets you own or are explicitly authorized to
test (e.g. an in-scope bug bounty program). You are responsible for
complying with the terms of any target's security policy and applicable
law.

## Installation

```bash
git clone https://github.com/yahyaibr/uncloak.git
cd uncloak
pip install -r requirements.txt
```

**Requirements:** Python 3.8+, `requests`

```bash
pip install requests
```

## Usage

```bash
# Find ASNs + IP ranges + related domains for an organization
python3 origin_ip_finder.py --org "paypal"

# Look up a specific ASN directly
python3 origin_ip_finder.py --asn 26444

# Reverse IP lookup on a single IP or CIDR block
python3 origin_ip_finder.py --reverse-ip 64.4.250.0/24

# Resolve a domain and check if it's likely behind a CDN
python3 origin_ip_finder.py --domain example.com

# Save full results to a JSON file
python3 origin_ip_finder.py --org "paypal" --out results.json

# Suppress the banner (useful for scripting / piping)
python3 origin_ip_finder.py --org "paypal" --no-banner
```

### Options

| Flag           | Description                                              |
|----------------|------------------------------------------------------------|
| `--org`        | Organization name to search for ASNs                     |
| `--asn`        | Look up (or restrict to) a specific ASN number            |
| `--reverse-ip` | IP or CIDR block for reverse IP lookup                    |
| `--domain`     | Domain to resolve and check for CDN fronting               |
| `--out`        | Write full JSON results to a file                          |
| `--no-banner`  | Suppress the startup ASCII banner                           |

## How it works

1. **ASN lookup** — queries RIPEstat's `searchcomplete` endpoint for ASNs
   matching an organization name, then enriches each with its official
   holder name via `as-overview`.
2. **Prefix enumeration** — for each ASN, pulls announced IPv4/IPv6
   prefixes via `announced-prefixes`.
3. **Reverse IP lookup** — for the first few prefixes found, queries
   rapiddns.io to surface other domains sharing that IP space.
4. **Domain resolution** — resolves a given domain's IP(s) and checks
   the owning ASN's name against a list of common CDN/WAF providers.

## Notes

- These databases aren't always perfectly accurate — cross-reference
  results with other sources and review manually before drawing
  conclusions.
- Free-tier API rate limits apply; the script adds small delays between
  requests to stay polite to RIPEstat and rapiddns.io.

## License

MIT — see [LICENSE](LICENSE).

## Author

[@yahyaibr](https://github.com/yahyaibr)
