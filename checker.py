"""
checker.py – IP and domain reputation checking.

Checks are performed in parallel against:
  • Multiple DNSBL (DNS-based block lists) – works without any API key
  • AbuseIPDB         – requires ABUSEIPDB_API_KEY  in .env (optional)
  • VirusTotal        – requires VIRUSTOTAL_API_KEY in .env (optional)
"""

import concurrent.futures
import os
import re
from datetime import datetime, timezone

import dns.resolver
import requests

# ---------------------------------------------------------------------------
# Block-list definitions
# ---------------------------------------------------------------------------
IP_DNSBL = [
    {"name": "Spamhaus ZEN",          "host": "zen.spamhaus.org",          "url": "https://check.spamhaus.org"},
    {"name": "SpamCop BL",            "host": "bl.spamcop.net",            "url": "https://www.spamcop.net"},
    {"name": "Barracuda BRBL",        "host": "b.barracudacentral.org",    "url": "https://www.barracudacentral.org/rbl/removal-request"},
    {"name": "SORBS DNSBL",           "host": "dnsbl.sorbs.net",            "url": "https://www.sorbs.net"},
    {"name": "Composite BL (CBL)",    "host": "cbl.abuseat.org",            "url": "https://www.abuseat.org"},
    {"name": "UCEProtect Level 1",    "host": "dnsbl-1.uceprotect.net",    "url": "https://www.uceprotect.net"},
    {"name": "UCEProtect Level 2",    "host": "dnsbl-2.uceprotect.net",    "url": "https://www.uceprotect.net"},
    {"name": "UCEProtect Level 3",    "host": "dnsbl-3.uceprotect.net",    "url": "https://www.uceprotect.net"},
    {"name": "PSBL",                  "host": "psbl.surriel.com",           "url": "https://psbl.org"},
    {"name": "Manitu DNSBL",          "host": "ix.dnsbl.manitu.net",        "url": "https://www.dnsbl.manitu.net"},
    {"name": "SpamRATS All",          "host": "all.spamrats.com",           "url": "https://www.spamrats.com"},
    {"name": "Truncate",              "host": "truncate.gbudb.net",         "url": "https://www.gbudb.net"},
    {"name": "NordSpam BL",           "host": "bl.nordspam.com",            "url": "https://www.nordspam.com"},
    {"name": "DRONEBL",               "host": "dnsbl.dronebl.org",          "url": "https://dronebl.org"},
    {"name": "RATS-Dyna",             "host": "dyna.spamrats.com",          "url": "https://www.spamrats.com"},
    {"name": "RATS-NoPtr",            "host": "noptr.spamrats.com",         "url": "https://www.spamrats.com"},
]

DOMAIN_DNSBL = [
    {"name": "Spamhaus DBL",              "host": "dbl.spamhaus.org",              "url": "https://check.spamhaus.org"},
    {"name": "SURBL Multi",               "host": "multi.surbl.org",               "url": "https://www.surbl.org"},
    {"name": "URIBL Multi",               "host": "multi.uribl.com",               "url": "https://uribl.com"},
    {"name": "SORBS RHSBL",               "host": "rhsbl.sorbs.net",               "url": "https://www.sorbs.net"},
    {"name": "NordSpam DBL",              "host": "dbl.nordspam.com",              "url": "https://www.nordspam.com"},
    {"name": "SEM Fresh15",               "host": "fresh15.spameatingmonkey.net",  "url": "https://spameatingmonkey.net"},
    {"name": "SEM Urired",                "host": "urired.spameatingmonkey.net",   "url": "https://spameatingmonkey.net"},
]

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


# ---------------------------------------------------------------------------
# DNS lookup helpers
# ---------------------------------------------------------------------------
def _dnsbl_ip_check(ip: str, dnsbl: dict) -> dict:
    """Check a single IPv4 address against one DNSBL."""
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.{dnsbl['host']}"
        dns.resolver.resolve(query, "A")
        listed = True
    except dns.resolver.NXDOMAIN:
        listed = False
    except Exception as exc:
        return {**dnsbl, "listed": None, "detail": None, "error": str(exc)}
    return {**dnsbl, "listed": listed, "detail": None, "error": None}


def _dnsbl_domain_check(domain: str, dnsbl: dict) -> dict:
    """Check a domain against one domain-DNSBL."""
    try:
        query = f"{domain}.{dnsbl['host']}"
        dns.resolver.resolve(query, "A")
        listed = True
    except dns.resolver.NXDOMAIN:
        listed = False
    except Exception as exc:
        return {**dnsbl, "listed": None, "detail": None, "error": str(exc)}
    return {**dnsbl, "listed": listed, "detail": None, "error": None}


# ---------------------------------------------------------------------------
# Optional API checks
# ---------------------------------------------------------------------------
def _abuseipdb_check(ip: str) -> dict | None:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        return {
            "name": "AbuseIPDB",
            "host": "abuseipdb.com",
            "url": f"https://www.abuseipdb.com/check/{ip}",
            "listed": score > 25,
            "detail": f"Confidence score: {score}%  |  Reports: {reports}",
            "error": None,
        }
    except Exception as exc:
        return {
            "name": "AbuseIPDB",
            "host": "abuseipdb.com",
            "url": f"https://www.abuseipdb.com/check/{ip}",
            "listed": None,
            "detail": None,
            "error": str(exc),
        }


def _virustotal_check(target: str) -> dict | None:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        if IP_PATTERN.match(target):
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            vt_url = f"https://www.virustotal.com/gui/ip-address/{target}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"
            vt_url = f"https://www.virustotal.com/gui/domain/{target}"

        resp = requests.get(
            endpoint, headers={"x-apikey": api_key}, timeout=10
        )
        resp.raise_for_status()
        stats = (
            resp.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return {
            "name": "VirusTotal",
            "host": "virustotal.com",
            "url": vt_url,
            "listed": (malicious + suspicious) > 0,
            "detail": f"Malicious: {malicious}  |  Suspicious: {suspicious}",
            "error": None,
        }
    except Exception as exc:
        return {
            "name": "VirusTotal",
            "host": "virustotal.com",
            "url": "https://www.virustotal.com",
            "listed": None,
            "detail": None,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def _sort_key(r: dict):
    # Listed first, then errors, then clean; alphabetical within groups
    if r.get("listed") is True:
        return (0, r.get("name", ""))
    if r.get("listed") is None:
        return (2, r.get("name", ""))
    return (1, r.get("name", ""))


def check_ip(ip: str) -> dict:
    results: list[dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        futures = [pool.submit(_dnsbl_ip_check, ip, bl) for bl in IP_DNSBL]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    for optional in (_abuseipdb_check(ip), _virustotal_check(ip)):
        if optional:
            results.insert(0, optional)

    results.sort(key=_sort_key)
    listed = sum(1 for r in results if r.get("listed") is True)
    checked = sum(1 for r in results if r.get("error") is None)

    return {
        "type": "ip",
        "target": ip,
        "results": results,
        "listed_count": listed,
        "total_checked": checked,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def check_domain(domain: str) -> dict:
    results: list[dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(_dnsbl_domain_check, domain, bl) for bl in DOMAIN_DNSBL]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    vt = _virustotal_check(domain)
    if vt:
        results.insert(0, vt)

    results.sort(key=_sort_key)
    listed = sum(1 for r in results if r.get("listed") is True)
    checked = sum(1 for r in results if r.get("error") is None)

    return {
        "type": "domain",
        "target": domain,
        "results": results,
        "listed_count": listed,
        "total_checked": checked,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
