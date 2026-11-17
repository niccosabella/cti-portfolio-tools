#!/usr/bin/env python3
"""
pivot_out.py: automate the boring half of a domain pivot.

Companion script for CTI Portfolio Part 3 on ctijen.com.
Start from one domain and collect, PASSIVELY:
  1. registration data (RDAP)
  2. certificates and their SANs (crt.sh), looping through new SANs
  3. passive DNS (VirusTotal, only if VT_API_KEY is set), plus what else lived
     on each IP around the same time, skipping shared networks like Cloudflare

Nothing here ever touches the domain's own servers. Every request goes to
a third party that already collected the data (a registry, crt.sh, VT).

Usage:
  python3 pivot_out.py evil.example
  python3 pivot_out.py evil.example --rounds 2 --max-domains 40
  VT_API_KEY=yourkey python3 pivot_out.py evil.example

Standard library only, so there's nothing to pip install.
"""

import argparse
import csv
import json
import ipaddress
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# This is how the script introduces itself to the services it talks to
USER_AGENT = "pivot-out/0.1 (CTI portfolio script; passive lookups only)"

# A cert with more SANs than this is probably shared hosting or a CDN, so we don't loop through its SANs.
# Want to follow bigger certs? Raise this number.
BIG_CERT = 50

# An IP with this many domains on it is probably shared hosting, so we flag it and don't list the neighbors
BUSY_IP = 30

# Cloudflare's published ranges (https://www.cloudflare.com/ips/, checked Nov 2026).
# Millions of unrelated sites sit behind these, so two domains on a Cloudflare IP means NOTHING.
# Want to add another provider? Fastly and Akamai publish their ranges too. Add a new name
# with its own list, the same way Cloudflare is written here.
SHARED_NETWORKS = {
    "Cloudflare": [ipaddress.ip_network(n) for n in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    )],
}


def shared_network(ip):
    """Return the provider name if this IP belongs to a big shared network, else None."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None  # this wasn't an IP address at all
    for provider, networks in SHARED_NETWORKS.items():
        # Only compare IPv4 addresses to IPv4 ranges, and IPv6 to IPv6
        if any(address.version == n.version and address in n for n in networks):
            return provider
    return None


def days_apart(date_a, date_b):
    """How many days between two YYYY-MM-DD dates (None if either is missing)."""
    if not date_a or not date_b:
        return None
    fmt = "%Y-%m-%d"
    # abs() drops the minus sign. Without it, a neighbor seen 300 days EARLIER comes out as -300,
    # and -300 is less than 7, so it would get labeled SAME WEEK.
    return abs((datetime.strptime(date_a, fmt) - datetime.strptime(date_b, fmt)).days)


def now_utc():
    """The current time in UTC, like 2026-11-04T02:28:09Z.

    We use UTC everywhere so the dates come out the same no matter what time zone you run this in.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def defang(value):
    """evil.com -> evil[.]com and 203.0.113.7 -> 203.0.113[.]7, so nobody clicks it by accident."""
    if " " in value or "." not in value:
        return value  # not a domain or IP (registrar names, "crt.sh ID 123", etc.)
    # If it's all digits once the dots are gone, it's an IP. (replace() makes a copy for this
    # check, value itself doesn't change.) IPs only get the LAST dot bracketed, and rpartition
    # splits on the last dot: "203.0.113.7" becomes "203.0.113" and "7".
    if value.replace(".", "").isdigit():
        head, _, tail = value.rpartition(".")
        return f"{head}[.]{tail}"
    return value.replace(".", "[.]")


def clean_domain(name):
    """Lowercase, strip wildcards and trailing dots: '*.Evil.com.' -> 'evil.com'."""
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    return name


# A domain is labels of letters, digits, and hyphens (1-63 chars, no hyphen at either end),
# separated by dots, ending in a real-looking TLD (letters, or xn-- for internationalized ones).
LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"^(?:{LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})$")


def is_valid_domain(name):
    """True only for things shaped like a domain.

    SANs come from certs and hostnames come from passive DNS, and the ATTACKER controls
    both, so we check them before using them. Anything that isn't a clean domain
    (spaces, slashes, quotes, weird characters) gets dropped before we build a URL with it.
    """
    return len(name) <= 253 and bool(DOMAIN_RE.match(name))


def refang(value):
    """Undo defanging so people can paste evil[.]com or hxxps://evil[.]com/path."""
    value = value.strip().replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    value = re.sub(r"^hxxp", "http", value, flags=re.IGNORECASE)
    # Keep only the hostname: drop the https:// part, then the /path, then the :port
    return value.split("//")[-1].split("/")[0].split(":")[0]


def csv_safe(value):
    """Stop spreadsheet formula injection: a cell starting with = + - @ can RUN in Excel.

    Cert issuer names and hostnames are attacker-influenced, so we never trust them in a CSV.
    Putting a ' in front tells the spreadsheet "this is plain text, don't run it."
    """
    # text[:1] is the first character. We use [:1] because text[0] crashes on an empty string.
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def get_json(url, headers=None, tries=3):
    """Ask a URL for data and turn the JSON answer into Python. Returns None if we never got one.

    Every lookup in this script goes through here. It retries because free services
    (hi crt.sh) time out a LOT.
    """
    all_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    all_headers.update(headers or {})
    for attempt in range(1, tries + 1):
        try:
            request = urllib.request.Request(url, headers=all_headers)
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return None  # the service has nothing on this one, so there's no point retrying
            if err.code == 429:
                # 429 means we're over the rate limit. Wait a minute and try again,
                # unless that was our last try.
                if attempt < tries:
                    print("    rate limited, waiting 60s...", file=sys.stderr)
                    time.sleep(60)
                continue  # skip the shorter wait below, we already waited
            problem = f"HTTP {err.code}"
        except (OSError, json.JSONDecodeError) as err:  # OSError covers timeouts and connection errors
            problem = type(err).__name__
        if attempt < tries:
            wait = 5 * attempt  # 5 seconds after the first try, 10 after the second
            print(f"    {problem}, retrying in {wait}s ({attempt}/{tries})", file=sys.stderr)
            time.sleep(wait)
    print(f"    gave up on {url}", file=sys.stderr)
    return None


# ---------- Step 2: registration (RDAP) ----------

def lookup_registration(domain):
    """RDAP is the modern, JSON version of WHOIS. rdap.org forwards us to the right registry."""
    url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
    data = get_json(url)
    if not data:
        return None
    # Each event looks like {"eventAction": "registration", "eventDate": "2026-09-11T14:04:47Z"}.
    # This line turns that list into a lookup table, so events.get("registration") gives us the date.
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            # vcardArray looks like ["vcard", [["fn", {}, "text", "Name.com, Inc."], ...]]
            # If a registry doesn't send one, [None, []] stands in for it and the loop runs zero times.
            for field in entity.get("vcardArray", [None, []])[1]:
                if field[0] == "fn":
                    registrar = field[3]
    # Registries don't all send the same fields. .get() gives us None for a missing one
    # where square brackets would crash.
    return {
        "registrar": registrar,
        "created": events.get("registration"),
        "nameservers": sorted(ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])),
        "query": url,
    }


# ---------- Step 3: certificates (crt.sh) ----------

def lookup_certs(domain):
    """Ask crt.sh for every logged cert naming this domain (and its subdomains, if crt.sh cooperates)."""
    certs = {}
    queries = [domain, f"%.{domain}"]  # % is a wildcard, so the second search finds subdomains too
    for q in queries:
        url = "https://crt.sh/?" + urllib.parse.urlencode({"q": q, "output": "json"})
        results = get_json(url)
        if results is None:
            print(f"    crt.sh didn't answer for {q} (it's not you, it's crt.sh). Moving on.", file=sys.stderr)
            continue
        for row in results:
            # name_value holds the names on the cert, one per line. The { } makes a set, which drops duplicates.
            sans = sorted({clean_domain(n) for n in row.get("name_value", "").split("\n") if n.strip()})
            # A precertificate and its final cert share a serial number, so keying on serial
            # stores each real cert once (and the same cert from both queries once, too)
            certs[row.get("serial_number") or row["id"]] = {
                "crtsh_id": row["id"],
                "serial": row.get("serial_number"),
                "issuer": row.get("issuer_name"),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
                "sans": sans,
                "query": url,
            }
        time.sleep(2)  # be polite, crt.sh is a free community service
    return list(certs.values())


# ---------- Step 4: passive DNS (VirusTotal, optional) ----------

def lookup_resolutions(domain, api_key):
    """Every IP VirusTotal has seen this domain resolve to, with dates."""
    url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}/resolutions?limit=40"
    data = get_json(url, headers={"x-apikey": api_key})
    time.sleep(16)  # free VT keys allow 4 requests a minute: 60 / 4 = 15 seconds, plus 1 to be safe
    if not data:
        return []  # an empty list, so the for loop in pivot() runs zero times
    rows = []
    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        # VT gives dates as Unix timestamps (seconds since 1970). We convert them in UTC,
        # because converting in your local time zone can move a date by a whole day.
        seen = attrs.get("date")
        rows.append({
            "ip": attrs.get("ip_address"),
            "date": datetime.fromtimestamp(seen, timezone.utc).strftime("%Y-%m-%d") if seen else None,
            "query": url.split("?")[0],
        })
    return rows


def lookup_ip_neighbors(ip, api_key):
    """Every domain VirusTotal has seen pointing at this IP, with dates. "What else lived here?"."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip)}/resolutions?limit=40"
    data = get_json(url, headers={"x-apikey": api_key})
    time.sleep(16)  # same rate limit as above
    if not data:
        return []
    rows = []
    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        seen = attrs.get("date")
        rows.append({
            "host": clean_domain(attrs.get("host_name", "")),
            "date": datetime.fromtimestamp(seen, timezone.utc).strftime("%Y-%m-%d") if seen else None,
            "query": url.split("?")[0],
        })
    return rows


# ---------- Putting it together ----------
def resolution_is_recent(date_text, days, today=None):
    """Keep resolutions within the last N UTC calendar days."""
    if days is None:
        return True

    if today is None:
        today = datetime.now(timezone.utc).date()

    try:
        observed = datetime.strptime(date_text, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return False

    age = (today - observed).days
    return 0 <= age <= days

def pivot(start, rounds, max_domains, vt_key, neighbors=True, window=7, days=None):
    """Run the whole pivot from one starting domain and return the list of findings.

    rounds:      how many times to loop through newly found SANs
    max_domains: stop adding new domains after this many
    vt_key:      your VirusTotal key, or None to skip passive DNS
    neighbors:   False skips the "what else lived on this IP?" lookups
    window:      how many days apart still counts as the same week
    """
    findings = []  # one row per thing we learned, with where and when we learned it
    seen = {start}  # every domain we've queued so far. It's a set, so it can't hold duplicates
    registered = set()  # domains we already pulled registration data for
    seen_certs = set()  # the same cert comes back for every domain on it, only record it once
    checked_ips = set()  # two domains on one IP? only spend one VT lookup on it
    to_check = [start]  # our to-do list, starting with the one domain you typed

    def add(kind, value, related_to, source, date, query, note=""):
        """Save one finding as a row, with its source, its date, and the query that found it."""
        findings.append({
            "type": kind, "value": value, "related_to": related_to, "source": source,
            "date": date or "", "query": query, "retrieved": now_utc(), "note": note,
        })

    # rounds + 1 because round 0 is the starting domain itself
    for round_number in range(rounds + 1):
        next_round = []
        for domain in to_check:
            print(f"[round {round_number}] {domain}", file=sys.stderr)

            # Registries only know registered domains, not subdomains, so skip RDAP for
            # threatfox.abuse.ch once we've looked up abuse.ch. The "." matters here: without it,
            # notabuse.ch would count as a subdomain of abuse.ch.
            is_subdomain = any(domain.endswith("." + parent) for parent in registered)
            reg = None if is_subdomain else lookup_registration(domain)
            if not is_subdomain:
                registered.add(domain)
                if not reg:
                    print("    no RDAP data (lots of country-code TLDs don't offer RDAP), check WHOIS by hand", file=sys.stderr)
            if reg:
                add("registrar", reg["registrar"] or "unknown", domain, "RDAP", reg["created"], reg["query"])
                for ns in reg["nameservers"]:
                    add("nameserver", ns, domain, "RDAP", reg["created"], reg["query"])

            for cert in lookup_certs(domain):
                cert_key = cert["serial"] or cert["crtsh_id"]  # no serial? fall back to the crt.sh ID
                if cert_key in seen_certs:
                    continue
                seen_certs.add(cert_key)
                note = f"{len(cert['sans'])} SANs, probably shared hosting/CDN" if len(cert["sans"]) > BIG_CERT else ""
                add("certificate", f"crt.sh ID {cert['crtsh_id']}", domain, "crt.sh",
                    cert["not_before"], cert["query"], f"issuer: {cert['issuer']}; {note}".strip("; "))
                for san in cert["sans"]:
                    if san == domain:
                        continue  # the domain is always listed on its own cert
                    # Junk in a cert is still worth writing down, we just don't look it up
                    if not is_valid_domain(san):
                        add("skipped", san[:100], f"crt.sh ID {cert['crtsh_id']}", "crt.sh", cert["not_before"],
                            cert["query"], "not a valid domain, not pivoting on it")
                        continue
                    add("san", san, f"crt.sh ID {cert['crtsh_id']}", "crt.sh", cert["not_before"], cert["query"], note)
                    # Queue this SAN for the next round, unless we've already seen it, it came from
                    # a giant shared cert (note is only filled in for those), or we've hit --max-domains
                    if san not in seen and not note and len(seen) < max_domains:
                        seen.add(san)
                        next_round.append(san)

            if vt_key:
                for res in lookup_resolutions(domain, vt_key):
                    if not resolution_is_recent(res.get("date"), days):
                        print(
                            f"    skipping resolution outside --days filter: "
                            f"{res['ip']} ({res.get('date')})",
                            file=sys.stderr,
                        )
                        continue

                    provider = shared_network(res["ip"])
                    note = f"{provider} IP, shared by tons of unrelated sites, not pivoting on it" if provider else ""
                    add("resolution", res["ip"], domain, "VirusTotal", res["date"], res["query"], note)
                    # Skip the neighbor lookup if it's turned off, the IP is shared, or we already checked this IP
                    if not neighbors or provider or res["ip"] in checked_ips:
                        continue
                    checked_ips.add(res["ip"])

                    # "What else lived on this IP?" Neighbors are LEADS. We write them down but don't
                    # look each one up, because one shared server could add hundreds of unrelated domains.
                    found = lookup_ip_neighbors(res["ip"], vt_key)
                    if len(found) >= BUSY_IP:
                        add("busy_ip", res["ip"], domain, "VirusTotal", res["date"], found[0]["query"],
                            f"{len(found)}+ domains on this IP, probably shared hosting, not listing them")
                        continue
                    for n in found:
                        if n["host"] == domain or not is_valid_domain(n["host"]):
                            continue
                        gap = days_apart(n["date"], res["date"])
                        when = "unknown timing" if gap is None else (
                            f"SAME WEEK as {defang(domain)}" if gap <= window
                            else f"{gap} days apart from {defang(domain)}")
                        add("ip_neighbor", n["host"], res["ip"], "VirusTotal", n["date"], n["query"], when)

        to_check = next_round
        if not to_check:
            break  # no new domains turned up, so we're done early

    if len(seen) >= max_domains:
        print(f"Hit --max-domains ({max_domains}). Knowing when to stop is a skill!", file=sys.stderr)
    return findings


def save(findings, start, out_dir):
    """Write the findings to a .json and a .csv file in out_dir. Returns the file path without the extension."""
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    base = os.path.join(out_dir, f"{start.replace('.', '_')}-{stamp}")

    # Defang every value before it hits disk. The raw query URLs stay as-is so you can rerun them.
    safe = [dict(row, value=defang(row["value"]), related_to=defang(row["related_to"])) for row in findings]

    with open(base + ".json", "w") as f:
        json.dump({"start": defang(start), "generated": now_utc(), "findings": safe}, f, indent=2)
    with open(base + ".csv", "w", newline="") as f:  # newline="" stops blank lines between rows on Windows
        writer = csv.DictWriter(f, fieldnames=list(safe[0].keys()) if safe else ["type"])
        writer.writeheader()
        writer.writerows({k: csv_safe(v) for k, v in row.items()} for row in safe)
    return base


def main():
    parser = argparse.ArgumentParser(description="Passive domain pivot: RDAP + crt.sh (+ VirusTotal if VT_API_KEY is set).")
    parser.add_argument("domain", help="starting domain, e.g. evil.example (no http://)")
    parser.add_argument("--rounds", type=int, default=1, help="how many times to loop through new SANs (default 1)")
    parser.add_argument("--max-domains", type=int, default=25, help="stop adding new domains after this many (default 25)")
    parser.add_argument("--out", default="output", help="folder for the JSON and CSV (default ./output)")
    parser.add_argument("--skip-neighbors", action="store_true",
                        help="don't ask VT what else lived on each IP (saves your free VT quota)")
    parser.add_argument("--window", type=int, default=7,
                        help="days apart that still count as 'same time' for IP neighbors (default 7)")
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="ignore resolutions older than this many days (default: no age limit)",
    )
    args = parser.parse_args()

    if args.days is not None and args.days < 0:
        parser.error("--days must be zero or greater")

    start = clean_domain(refang(args.domain))
    if not is_valid_domain(start):
        parser.error(f"'{args.domain}' doesn't look like a domain. Try something like evil.example or evil[.]example")
    # The key comes from your environment so it never has to be typed into this file
    vt_key = os.environ.get("VT_API_KEY")
    if not vt_key:
        print("No VT_API_KEY set, skipping passive DNS. (Free key: virustotal.com, then Profile > API Key.)", file=sys.stderr)

    findings = pivot(
        start, args.rounds, args.max_domains, vt_key,
        neighbors=not args.skip_neighbors,
        window=args.window,
        days=args.days,
    )
    base = save(findings, start, args.out)

    domains = {f["value"] for f in findings if f["type"] == "san"}
    close = {f["value"] for f in findings if f["type"] == "ip_neighbor" and f["note"].startswith("SAME WEEK")}
    print(f"\nDone! {len(findings)} findings, {len(domains)} unique SAN domains, "
          f"{len(close)} IP neighbors from the same week.")
    print(f"Saved {base}.json and {base}.csv")
    print("Reminder: these are LEADS. Check each one against your other evidence before it goes on the map.")


# Only start a pivot when this file is run directly. That way the tests can import
# the functions above without kicking one off.
if __name__ == "__main__":
    main()
