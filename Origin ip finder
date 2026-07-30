#!/usr/bin/env python3
"""
UNCLOAK  (origin_ip_finder.py)
--------------------
A passive reconnaissance tool for discovering an organization's IP
infrastructure and potential "origin" IPs (the real server behind a
CDN/WAF such as Cloudflare), based on the techniques described in
"Web Hacking Arsenal" (Ch. 2 - Intelligence Gathering and Enumeration):

  1. ASN enumeration        (via RIPEstat API      -> like bgp.he.net)
  2. IP range enumeration   (prefixes announced by each ASN)
  3. Reverse IP lookup      (via rapiddns.io        -> domains sharing an IP)
  4. Optional: resolve a domain and flag whether it's likely behind a CDN

NOTE ON DATA SOURCE
--------------------
This originally used the bgpview.io API, which was permanently shut down
on November 26, 2025. It has been switched to RIPEstat
(https://stat.ripe.net), the free, no-API-key public data service run by
RIPE NCC (one of the five Regional Internet Registries). It's a more
stable long-term source than third-party projects that can disappear.

IMPORTANT / SCOPE
------------------
This tool only queries public, passive-recon data sources (no active
scanning, no exploitation). Only use it against targets you own or are
explicitly authorized to test (e.g. an in-scope bug bounty program).

USAGE
-----
    python3 origin_ip_finder.py --org "paypal"
    python3 origin_ip_finder.py --asn 26444
    python3 origin_ip_finder.py --domain example.com
    python3 origin_ip_finder.py --org "paypal" --out results.json
    python3 origin_ip_finder.py --org "paypal" --no-banner   # skip the ASCII banner

DEPENDENCIES
------------
    pip install requests
"""

import argparse
import json
import re
import socket
import sys
import time
from typing import List, Dict, Any, Optional

import requests

RIPESTAT_SEARCHCOMPLETE = "https://stat.ripe.net/data/searchcomplete/data.json"
RIPESTAT_AS_OVERVIEW = "https://stat.ripe.net/data/as-overview/data.json"
RIPESTAT_ANNOUNCED_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPESTAT_NETWORK_INFO = "https://stat.ripe.net/data/network-info/data.json"

RAPIDDNS_SAMEIP = "https://rapiddns.io/sameip/{ip}?full=1"

# RIPEstat asks API consumers to identify themselves via "sourceapp" instead
# of a User-Agent header, so both are set here.
HEADERS = {"User-Agent": "origin-ip-finder/2.0 (authorized-recon-only)"}
SOURCEAPP = "origin-ip-finder"

# Common CDN / WAF org-name fragments — used only to flag likely
# "this domain is fronted by a CDN, so the resolved IP is NOT the origin".
CDN_HINTS = [
    "cloudflare", "akamai", "fastly", "imperva", "incapsula",
    "sucuri", "stackpath", "cloudfront", "azure front door",
]

ASN_RE = re.compile(r"\bAS(\d+)\b", re.IGNORECASE)

BANNER = r"""
██╗   ██╗███╗   ██╗ ██████╗██╗      ██████╗  █████╗ ██╗  ██╗
██║   ██║████╗  ██║██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝
██║   ██║██╔██╗ ██║██║     ██║     ██║   ██║███████║█████╔╝
██║   ██║██║╚██╗██║██║     ██║     ██║   ██║██╔══██║██╔═██╗
╚██████╔╝██║ ╚████║╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗
 ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
"""

TAGLINE = "  strip the CDN. find the real server.  |  passive OSINT only"


def print_banner() -> None:
    print(BANNER)
    print(TAGLINE)
    print("-" * 66)


def _ripestat_get(url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    params = dict(params)
    params["sourceapp"] = SOURCEAPP
    resp = requests.get(url, params=params, headers=HEADERS, timeout=20)
    resp.raise_for_status()
    return resp.json()


def get_asns_for_org(query: str) -> List[Dict[str, Any]]:
    """
    Look up ASNs associated with an organization name via RIPEstat's
    'searchcomplete' endpoint (RIPEstat's own autocomplete/search index).
    """
    data = _ripestat_get(RIPESTAT_SEARCHCOMPLETE, {"resource": query})
    categories = data.get("data", {}).get("categories", [])

    asns: Dict[int, Dict[str, Any]] = {}
    for category in categories:
        for suggestion in category.get("suggestions", []):
            value = str(suggestion.get("value", ""))
            match = ASN_RE.search(value)
            if not match:
                continue
            asn_num = int(match.group(1))
            if asn_num not in asns:
                asns[asn_num] = {
                    "asn": asn_num,
                    "name": suggestion.get("description", value),
                }

    # Enrich each hit with the official holder name from as-overview.
    results = []
    for asn_num, entry in asns.items():
        overview = get_as_overview(asn_num)
        results.append({
            "asn": asn_num,
            "name": entry["name"],
            "holder": overview.get("holder"),
            "announced": overview.get("announced"),
        })
        time.sleep(0.2)
    return results


def get_as_overview(asn: int) -> Dict[str, Any]:
    """Fetch holder name / announcement status for a single ASN."""
    try:
        data = _ripestat_get(RIPESTAT_AS_OVERVIEW, {"resource": f"AS{asn}"})
        d = data.get("data", {})
        return {"holder": d.get("holder"), "announced": d.get("announced")}
    except requests.RequestException:
        return {}


def get_prefixes_for_asn(asn: int) -> List[Dict[str, Any]]:
    """Get the IPv4/IPv6 prefixes currently announced by a given ASN."""
    data = _ripestat_get(RIPESTAT_ANNOUNCED_PREFIXES, {"resource": f"AS{asn}"})
    prefixes = data.get("data", {}).get("prefixes", [])
    out = []
    for p in prefixes:
        timelines = p.get("timelines") or []
        first_seen = timelines[0].get("starttime") if timelines else None
        out.append({"prefix": p.get("prefix"), "first_seen": first_seen})
    return out


def get_asn_for_ip(ip: str) -> Optional[Dict[str, Any]]:
    """Resolve which ASN/prefix currently announces a given IP address."""
    try:
        data = _ripestat_get(RIPESTAT_NETWORK_INFO, {"resource": ip})
        d = data.get("data", {})
        asns = d.get("asns", [])
        if not asns:
            return None
        asn_num = asns[0]
        overview = get_as_overview(asn_num)
        return {"asn": asn_num, "prefix": d.get("prefix"), "holder": overview.get("holder")}
    except requests.RequestException:
        return None


def reverse_ip_lookup(ip_or_cidr: str) -> List[str]:
    """
    Query rapiddns.io for domains hosted on the same IP (or IP/CIDR block).
    Returns a de-duplicated, sorted list of domain names.
    """
    url = RAPIDDNS_SAMEIP.format(ip=ip_or_cidr)
    resp = requests.get(url, headers=HEADERS, timeout=20)
    resp.raise_for_status()
    html = resp.text

    domains = set()
    for match in re.finditer(r'<td>([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})</td>', html):
        candidate = match.group(1).lower()
        if candidate.count(".") >= 1 and not candidate.replace(".", "").isdigit():
            domains.add(candidate)
    return sorted(domains)


def resolve_domain(domain: str) -> Dict[str, Any]:
    """Resolve a domain and flag if it looks like it's behind a known CDN."""
    result = {"domain": domain, "ips": [], "likely_cdn": False, "cdn_hint": None}
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({i[4][0] for i in infos})
        result["ips"] = ips
    except socket.gaierror as e:
        result["error"] = str(e)
        return result

    for ip in result["ips"]:
        info = get_asn_for_ip(ip)
        if not info:
            continue
        result.setdefault("asn_info", []).append(info)
        holder = (info.get("holder") or "").lower()
        for hint in CDN_HINTS:
            if hint in holder:
                result["likely_cdn"] = True
                result["cdn_hint"] = hint
                break
        time.sleep(0.2)  # be polite to the free API
    return result


def run_org_recon(org: str, asn_filter: int = None) -> Dict[str, Any]:
    print(f"[*] Searching ASNs for '{org}' via RIPEstat ...")

    if asn_filter:
        overview = get_as_overview(asn_filter)
        asns = [{"asn": asn_filter, "name": overview.get("holder", ""), "holder": overview.get("holder")}]
    else:
        asns = get_asns_for_org(org)

    if not asns:
        print("[!] No ASNs found. Try a more specific org name, or pass --asn directly if you know it.")
        return {"org": org, "asns": []}

    report = {"org": org, "asns": []}
    for a in asns:
        asn_num = a.get("asn")
        print(f"[*] ASN {asn_num} ({a.get('holder') or a.get('name')}) - fetching announced prefixes ...")
        try:
            prefixes = get_prefixes_for_asn(asn_num)
        except requests.RequestException as e:
            print(f"    [!] Failed to fetch prefixes: {e}")
            prefixes = []

        report["asns"].append({
            "asn": asn_num,
            "holder": a.get("holder") or a.get("name"),
            "prefixes": prefixes,
        })
        time.sleep(0.3)  # rate-limit friendliness

    return report


def run_reverse_ip_recon(target: str) -> Dict[str, Any]:
    print(f"[*] Reverse IP lookup for '{target}' ...")
    try:
        domains = reverse_ip_lookup(target)
    except requests.RequestException as e:
        print(f"[!] Reverse IP lookup failed: {e}")
        domains = []
    print(f"[*] Found {len(domains)} domain(s) on {target}")
    return {"target": target, "domains": domains}


def main():
    parser = argparse.ArgumentParser(
        prog="uncloak",
        description="UNCLOAK - passive origin-IP / infrastructure recon tool (RIPEstat ASN lookup + reverse IP lookup)."
    )
    parser.add_argument("--org", help="Organization name to search for ASNs (e.g. 'paypal')")
    parser.add_argument("--asn", type=int, help="Look up (or restrict to) a specific ASN number directly")
    parser.add_argument("--reverse-ip", help="IP or CIDR (e.g. 1.2.3.4 or 1.2.3.0/24) for reverse IP lookup")
    parser.add_argument("--domain", help="Domain to resolve and check for likely CDN fronting")
    parser.add_argument("--out", help="Write full JSON results to this file")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the startup banner")
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    if not any([args.org, args.asn, args.reverse_ip, args.domain]):
        parser.print_help()
        sys.exit(1)

    results: Dict[str, Any] = {}

    if args.org or args.asn:
        org_report = run_org_recon(args.org or f"AS{args.asn}", args.asn)
        results["asn_recon"] = org_report

        # Auto reverse-IP lookup on the first few prefixes of each ASN
        # found, mirroring the book's workflow: ASN -> prefixes ->
        # reverse IP -> domain list.
        reverse_results = []
        for asn_entry in org_report.get("asns", []):
            for prefix in asn_entry.get("prefixes", [])[:3]:  # cap to avoid hammering the API
                cidr = prefix["prefix"]
                if not cidr or ":" in cidr:  # skip IPv6 for rapiddns
                    continue
                print(f"[*] Reverse IP lookup on {cidr} ...")
                try:
                    domains = reverse_ip_lookup(cidr)
                except requests.RequestException as e:
                    print(f"    [!] Failed: {e}")
                    domains = []
                reverse_results.append({"prefix": cidr, "domains": domains})
                time.sleep(0.5)
        results["reverse_ip_recon"] = reverse_results

    if args.reverse_ip:
        results["manual_reverse_ip"] = run_reverse_ip_recon(args.reverse_ip)

    if args.domain:
        print(f"[*] Resolving '{args.domain}' and checking for CDN fronting ...")
        results["domain_resolution"] = resolve_domain(args.domain)

    print("\n===== SUMMARY =====")
    print(json.dumps(results, indent=2)[:3000])  # console preview

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Full results written to {args.out}")


if __name__ == "__main__":
    main()
