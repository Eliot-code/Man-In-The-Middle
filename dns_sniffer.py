#!/usr/bin/env python3
"""
dns_sniffer.py v2.0 — Advanced DNS Traffic Monitor

New in v2.0:
  • DNS response capture (resolved IPs per domain)
  • Suspicious domain detection (high entropy / DGA-like names, unusual TLDs)
  • Domain categorization (social, streaming, banking, gaming, ad-tracking…)
  • NXDOMAIN tracking (failed resolutions)
  • Query rate monitoring per source IP
  • Domain alert system  (--alert domain.com)
  • DNS-over-TCP support (in addition to UDP port 53)
  • DNS map export on exit (domain → IPs JSON)

Usage:
    sudo python3 dns_sniffer.py
    sudo python3 dns_sniffer.py -i eth0 --no-filter
    sudo python3 dns_sniffer.py -i eth0 --alert paypal.com --alert bank.com
    sudo python3 dns_sniffer.py -i eth0 --log dns.log --export dns_map.json
"""

import scapy.all as scapy
import argparse
import json
import math
import re
import signal
import sys
import os
from datetime import datetime
from collections import defaultdict

# ── ANSI Colors ───────────────────────────────────────────────────────────────
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

VERSION = "2.0"

BANNER = f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════╗
║          DNS Traffic Monitor  v{VERSION}                  ║
║  Query Capture · Response IPs · Suspicious Detect  ║
╚══════════════════════════════════════════════════════╝{RESET}"""

# ── Default noise exclusions ──────────────────────────────────────────────────
DEFAULT_EXCLUDE = [
    "google", "gstatic", "googleapis", "googleusercontent",
    "bing", "msftconnecttest", "microsoft", "windowsupdate",
    "cloud", "static", "sensic", "mozilla", "firefox",
    "apple", "icloud", "aaplimg", "arpa",
]

# ── DNS record type mapping ───────────────────────────────────────────────────
QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}

RCODE_MAP = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP",  5: "REFUSED",
}

# ── Suspicious TLDs (commonly used in malware / phishing) ────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",       # Free Freenom TLDs
    ".xyz", ".top", ".club", ".online",       # Cheap / abused
    ".ru", ".su", ".cn", ".pw",               # Common abuse hotspots
    ".bit", ".onion",                          # Non-standard
    ".biz", ".info",                           # Phishing-heavy
}

# ── Domain categories (keyword → category label) ─────────────────────────────
DOMAIN_CATEGORIES = {
    "social":    ["facebook", "instagram", "twitter", "tiktok", "snapchat",
                  "linkedin", "reddit", "pinterest", "tumblr", "discord"],
    "streaming": ["youtube", "netflix", "spotify", "twitch", "hulu",
                  "disneyplus", "primevideo", "hbomax", "crunchyroll"],
    "banking":   ["paypal", "chase", "wellsfargo", "bankofamerica", "hsbc",
                  "barclays", "citibank", "santander", "revolut", "binance",
                  "coinbase", "kraken"],
    "gaming":    ["steam", "epicgames", "battlenet", "ea.com", "roblox",
                  "minecraft", "riot", "ubisoft", "gog.com", "origin"],
    "ads":       ["doubleclick", "googlesyndication", "adnxs", "adsrvr",
                  "amazon-adsystem", "moatads", "criteo", "taboola",
                  "outbrain", "pubmatic", "openx", "rlcdn"],
    "tracking":  ["mixpanel", "segment.io", "amplitude", "hotjar",
                  "fullstory", "newrelic", "datadog", "sentry"],
    "cdn":       ["cloudfront", "akamai", "fastly", "cloudflare",
                  "edgekey", "llnwd", "edgesuite"],
}

CATEGORY_COLORS = {
    "social":    BLUE,
    "streaming": MAGENTA,
    "banking":   RED,
    "gaming":    GREEN,
    "ads":       DIM,
    "tracking":  YELLOW,
    "cdn":       DIM,
}


# ── Helper functions ──────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_suspicious(domain: str) -> tuple:
    """
    Heuristic checks for DGA / suspicious domains.
    Returns (bool, reason_string).
    """
    parts = domain.rstrip(".").split(".")
    if len(parts) < 2:
        return False, ""

    tld  = "." + parts[-1].lower()
    host = parts[0].lower()

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        return True, f"suspicious TLD ({tld})"

    # High entropy subdomain (likely DGA)
    entropy = shannon_entropy(host)
    if entropy > 3.7 and len(host) > 10:
        return True, f"high entropy ({entropy:.2f}) — possible DGA"

    # Long random-looking label (consonant cluster check)
    consonants = re.sub(r"[aeiou0-9]", "", host)
    if len(host) > 12 and len(consonants) / max(len(host), 1) > 0.7:
        return True, f"random-looking label ({host[:20]})"

    # Very long domain
    if len(domain) > 60:
        return True, f"unusually long domain ({len(domain)} chars)"

    return False, ""


def categorize(domain: str) -> str:
    """Return category label for a domain, or empty string."""
    dl = domain.lower()
    for cat, keywords in DOMAIN_CATEGORIES.items():
        if any(kw in dl for kw in keywords):
            return cat
    return ""


# ── Main sniffer class ────────────────────────────────────────────────────────

class DNSSniffer:
    def __init__(self, interface: str, exclude_keywords: list,
                 log_file=None, no_filter: bool = False,
                 alert_domains: list = None, export_file: str = ""):
        self.interface       = interface
        self.exclude_kw      = exclude_keywords if not no_filter else []
        self.log_file        = log_file
        self.alert_domains   = {d.lower() for d in (alert_domains or [])}
        self.export_file     = export_file

        # State
        self.domains_seen:  set  = set()
        self.domain_count:  dict = defaultdict(int)
        self.domain_ips:    dict = defaultdict(set)    # domain -> {ip, ...}
        self.nxdomains:     set  = set()
        self.total_queries: int  = 0
        self.total_nx:      int  = 0
        self.suspicious:    list = []                  # [(domain, reason), ...]
        self.ip_query_rate: dict = defaultdict(int)    # src_ip -> query count
        self.start_time          = datetime.now()

        self._log_handle = None
        if self.log_file:
            try:
                self._log_handle = open(self.log_file, "a", encoding="utf-8")
                self._log_handle.write(
                    f"\n{'='*60}\n"
                    f"DNS Capture v{VERSION} started at {self.start_time.isoformat()}\n"
                    f"Interface: {self.interface}\n"
                    f"{'='*60}\n\n"
                )
                print(f"{GREEN}[+] Logging to: {self.log_file}{RESET}")
            except IOError as e:
                print(f"{RED}[!] Cannot open log file: {e}{RESET}")
                self._log_handle = None

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        if self._log_handle:
            try:
                self._log_handle.write(msg + "\n")
                self._log_handle.flush()
            except IOError:
                pass

    def _should_filter(self, domain: str) -> bool:
        dl = domain.lower()
        return any(kw in dl for kw in self.exclude_kw)

    # ── Packet processing ─────────────────────────────────────────────────────

    def process_packet(self, packet) -> None:
        """Handle both DNS queries and responses."""
        if not packet.haslayer(scapy.DNS):
            return

        dns = packet[scapy.DNS]
        src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "?"

        # ── Query ─────────────────────────────────────────────────────────────
        if dns.qr == 0 and dns.qdcount > 0:
            try:
                query  = dns.qd
                domain = query.qname.decode(errors="ignore").rstrip(".")
                qtype  = QTYPE_MAP.get(query.qtype, str(query.qtype))
            except (AttributeError, UnicodeDecodeError):
                return

            self.total_queries += 1
            self.ip_query_rate[src_ip] += 1

            if self._should_filter(domain):
                return

            is_new = domain not in self.domains_seen
            self.domains_seen.add(domain)
            self.domain_count[domain] += 1
            count = self.domain_count[domain]
            ts    = datetime.now().strftime("%H:%M:%S")

            # Category and suspicion checks
            cat    = categorize(domain)
            susp, reason = is_suspicious(domain)

            if is_new:
                cat_tag  = f" [{CATEGORY_COLORS.get(cat, '')}{cat.upper()}{RESET}]" if cat else ""
                susp_tag = f" {RED}[SUSPICIOUS: {reason}]{RESET}" if susp else ""
                line = (
                    f"  {DIM}{ts}{RESET}  "
                    f"{GREEN}{BOLD}[NEW]{RESET}  "
                    f"{YELLOW}{domain}{RESET}  "
                    f"{DIM}({qtype}){RESET}  "
                    f"{DIM}← {src_ip}{RESET}"
                    f"{cat_tag}{susp_tag}"
                )
                if susp:
                    self.suspicious.append((domain, reason))
            else:
                line = (
                    f"  {DIM}{ts}{RESET}  "
                    f"{DIM}[x{count}]{RESET}  "
                    f"{CYAN}{domain}{RESET}  "
                    f"{DIM}({qtype}) ← {src_ip}{RESET}"
                )

            # Alert check
            if any(ad in domain.lower() for ad in self.alert_domains):
                print(f"\n  {RED}{BOLD}  !! ALERT: Watched domain queried !!{RESET}")
                print(f"      Domain  : {YELLOW}{domain}{RESET}")
                print(f"      Source  : {src_ip}\n")
                self._log(f"*** ALERT: {domain}  src={src_ip}")

            print(line)
            self._log(f"{ts}  QUERY  {domain}  {qtype}  src={src_ip}  n={count}")

        # ── Response ──────────────────────────────────────────────────────────
        elif dns.qr == 1:
            rcode = dns.rcode

            # NXDOMAIN tracking
            if rcode == 3 and dns.qdcount > 0:
                try:
                    domain = dns.qd.qname.decode(errors="ignore").rstrip(".")
                except (AttributeError, UnicodeDecodeError):
                    return
                if not self._should_filter(domain):
                    self.total_nx += 1
                    if domain not in self.nxdomains:
                        self.nxdomains.add(domain)
                        ts = datetime.now().strftime("%H:%M:%S")
                        print(
                            f"  {DIM}{ts}{RESET}  "
                            f"{RED}[NXDOMAIN]{RESET}  "
                            f"{domain}  "
                            f"{DIM}src={src_ip}{RESET}"
                        )
                        self._log(f"{ts}  NXDOMAIN  {domain}  src={src_ip}")
                return

            # Extract resolved IPs from answer section
            if rcode == 0 and dns.ancount > 0 and dns.qdcount > 0:
                try:
                    domain = dns.qd.qname.decode(errors="ignore").rstrip(".")
                except (AttributeError, UnicodeDecodeError):
                    return

                if self._should_filter(domain):
                    return

                ans = dns.an
                ips = []
                while ans:
                    try:
                        if ans.type == 1 and hasattr(ans, "rdata"):  # A record
                            ips.append(str(ans.rdata))
                        elif ans.type == 28 and hasattr(ans, "rdata"):  # AAAA
                            ips.append(str(ans.rdata))
                    except Exception:
                        pass
                    ans = ans.payload if ans.payload and ans.payload.name != "NoPayload" else None
                    if ans and not hasattr(ans, "type"):
                        break

                for ip in ips:
                    self.domain_ips[domain].add(ip)

    # ── Statistics ────────────────────────────────────────────────────────────

    def print_stats(self) -> None:
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{BOLD}{'─' * 65}{RESET}")
        print(f"  {BOLD}Capture Summary  —  DNS Monitor v{VERSION}{RESET}")
        print(f"  {'─' * 50}")
        print(f"  Duration            : {elapsed:.1f}s")
        print(f"  Total queries       : {self.total_queries}")
        print(f"  Unique domains      : {len(self.domains_seen)}")
        print(f"  NXDOMAIN failures   : {RED}{self.total_nx}{RESET}")
        print(f"  Suspicious detected : {RED}{len(self.suspicious)}{RESET}")

        # Top domains
        if self.domain_count:
            top5 = sorted(self.domain_count.items(), key=lambda x: x[1], reverse=True)[:5]
            print(f"\n  {BOLD}Top domains:{RESET}")
            for d, c in top5:
                ips = ", ".join(sorted(self.domain_ips.get(d, set()))[:3])
                ip_note = f"  {DIM}→ {ips}{RESET}" if ips else ""
                print(f"    {CYAN}{c:>4}x{RESET}  {d}{ip_note}")

        # Top querying IPs
        if self.ip_query_rate:
            top_ips = sorted(self.ip_query_rate.items(), key=lambda x: x[1], reverse=True)[:3]
            print(f"\n  {BOLD}Most active sources:{RESET}")
            for ip, cnt in top_ips:
                print(f"    {CYAN}{cnt:>4}{RESET}  {ip}")

        # Suspicious domains
        if self.suspicious:
            print(f"\n  {BOLD}{RED}Suspicious domains detected:{RESET}")
            for domain, reason in self.suspicious[:10]:
                print(f"    {RED}{domain}{RESET}  {DIM}({reason}){RESET}")

        print(f"{BOLD}{'─' * 65}{RESET}\n")

        if self._log_handle:
            self._log_handle.write(
                f"\n--- Summary: {len(self.domains_seen)} unique, "
                f"{self.total_queries} total, {self.total_nx} NX "
                f"in {elapsed:.1f}s ---\n"
            )

    def export_dns_map(self) -> None:
        if not self.export_file:
            return
        data = {
            "export_time": datetime.now().isoformat(),
            "total_domains": len(self.domains_seen),
            "dns_map": {
                d: sorted(list(ips))
                for d, ips in sorted(self.domain_ips.items())
            },
            "nxdomains": sorted(list(self.nxdomains)),
            "suspicious": [
                {"domain": d, "reason": r} for d, r in self.suspicious
            ],
        }
        try:
            with open(self.export_file, "w") as f:
                json.dump(data, f, indent=2)
            print(f"{GREEN}[+] DNS map exported to: {self.export_file}{RESET}")
        except IOError as e:
            print(f"{RED}[!] Export failed: {e}{RESET}")

    def cleanup(self) -> None:
        if self._log_handle:
            self._log_handle.close()

    # ── Sniff ─────────────────────────────────────────────────────────────────

    def start(self) -> None:
        print(f"{YELLOW}[*] Sniffing DNS on: {self.interface}{RESET}")
        print(f"{YELLOW}[*] Filtering out : {len(self.exclude_kw)} keyword(s){RESET}")
        if self.alert_domains:
            print(f"{YELLOW}[*] Alert domains  : {', '.join(self.alert_domains)}{RESET}")
        print(f"{DIM}    UDP + TCP port 53. Press Ctrl+C to stop.{RESET}\n")

        print(f"  {BOLD}{'TIME':<10} {'STATUS':<12} {'DOMAIN':<38} {'TYPE':<6} {'SRC IP'}{RESET}")
        print(f"  {'─' * 80}")

        try:
            scapy.sniff(
                iface=self.interface,
                filter="port 53",          # covers both UDP and TCP
                prn=self.process_packet,
                store=0,
            )
        except PermissionError:
            print(f"{RED}[!] Permission denied. Run with sudo.{RESET}")
            sys.exit(1)
        except OSError as e:
            print(f"{RED}[!] Interface error: {e}{RESET}")
            sys.exit(1)


# ── CLI ───────────────────────────────────────────────────────────────────────

def get_arguments():
    p = argparse.ArgumentParser(
        description=f"DNS Traffic Monitor v{VERSION} — Capture DNS queries and responses",
        epilog="Example: sudo python3 dns_sniffer.py -i eth0 --alert bank.com --export map.json",
    )
    p.add_argument("-i", "--interface", dest="interface", default=scapy.conf.iface,
                   help=f"Network interface (default: {scapy.conf.iface})")
    p.add_argument("--log",       dest="log_file",     default=None,
                   help="Save captured domains to a log file")
    p.add_argument("--export",    dest="export_file",  default=None,
                   help="Export domain→IP map to JSON on exit")
    p.add_argument("--no-filter", dest="no_filter",    action="store_true",
                   help="Disable noise filtering (show all DNS traffic)")
    p.add_argument("--exclude",   dest="extra_exclude", nargs="*", default=[],
                   help="Extra keywords to exclude (e.g. --exclude amazon netflix)")
    p.add_argument("--alert",     dest="alert_domains", nargs="*", default=[],
                   help="Alert when these domain names are queried")
    return p.parse_args()


def main():
    print(BANNER)

    if os.geteuid() != 0:
        print(f"{RED}[!] This script must be run as root (sudo).{RESET}")
        sys.exit(1)

    args = get_arguments()
    exclude = DEFAULT_EXCLUDE + args.extra_exclude

    sniffer = DNSSniffer(
        interface=args.interface,
        exclude_keywords=exclude,
        log_file=args.log_file,
        no_filter=args.no_filter,
        alert_domains=args.alert_domains,
        export_file=args.export_file or "",
    )

    def handler(sig, frame):
        print(f"\n{RED}[!] Stopping capture...{RESET}")
        sniffer.print_stats()
        sniffer.export_dns_map()
        sniffer.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    sniffer.start()


if __name__ == "__main__":
    main()
