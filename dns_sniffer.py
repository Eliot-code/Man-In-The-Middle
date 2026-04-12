#!/usr/bin/env python3
"""
dns_sniffer.py — DNS Traffic Monitor
Captures and displays DNS queries passing through the network interface.
Useful for monitoring which domains are being resolved during a MITM simulation.

Usage:
    sudo python3 dns_sniffer.py
    sudo python3 dns_sniffer.py -i eth0
    sudo python3 dns_sniffer.py -i wlan0 --log dns_capture.log --no-filter
"""

import scapy.all as scapy
import argparse
import signal
import sys
import os
from datetime import datetime
from collections import defaultdict

# ── ANSI Colors ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
╔══════════════════════════════════════════╗
║          DNS Traffic Monitor             ║
║       Real-time DNS Query Capture        ║
╚══════════════════════════════════════════╝{RESET}
"""

# ── Default exclusion keywords ───────────────────────────────────────────────
DEFAULT_EXCLUDE = [
    "google", "gstatic", "googleapis", "googleusercontent",
    "bing", "msftconnecttest", "microsoft", "windowsupdate",
    "cloud", "static", "sensic", "mozilla", "firefox",
    "apple", "icloud", "aaplimg",
    "arpa",  # reverse DNS
]

# ── Record type mapping ─────────────────────────────────────────────────────
QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


class DNSSniffer:
    def __init__(self, interface, exclude_keywords, log_file=None, no_filter=False):
        self.interface = interface
        self.exclude_keywords = exclude_keywords if not no_filter else []
        self.log_file = log_file
        self.domains_seen = set()
        self.domain_count = defaultdict(int)
        self.total_queries = 0
        self.start_time = datetime.now()

        # Open log file if specified
        self._log_handle = None
        if self.log_file:
            try:
                self._log_handle = open(self.log_file, "a", encoding="utf-8")
                self._log_handle.write(f"\n{'='*60}\n")
                self._log_handle.write(f"DNS Capture started at {self.start_time.isoformat()}\n")
                self._log_handle.write(f"Interface: {self.interface}\n")
                self._log_handle.write(f"{'='*60}\n\n")
                print(f"{GREEN}[+] Logging to: {self.log_file}{RESET}")
            except IOError as e:
                print(f"{RED}[!] Cannot open log file: {e}{RESET}")
                self._log_handle = None

    def _log(self, message):
        """Write to log file if enabled."""
        if self._log_handle:
            try:
                self._log_handle.write(message + "\n")
                self._log_handle.flush()
            except IOError:
                pass

    def process_packet(self, packet):
        """Process a captured DNS packet."""
        if not packet.haslayer(scapy.DNSQR):
            return

        try:
            query = packet[scapy.DNSQR]
            domain = query.qname.decode().rstrip(".")
            qtype_num = query.qtype
            qtype = QTYPE_MAP.get(qtype_num, str(qtype_num))
            src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "?"
        except (UnicodeDecodeError, AttributeError, IndexError):
            return

        self.total_queries += 1

        # Apply exclusion filter
        domain_lower = domain.lower()
        if any(kw in domain_lower for kw in self.exclude_keywords):
            return

        # Track if first time seen
        is_new = domain not in self.domains_seen
        self.domains_seen.add(domain)
        self.domain_count[domain] += 1

        timestamp = datetime.now().strftime("%H:%M:%S")
        count = self.domain_count[domain]

        if is_new:
            # First time — highlight
            line = (
                f"  {DIM}{timestamp}{RESET}  "
                f"{GREEN}[NEW]{RESET}  "
                f"{YELLOW}{domain}{RESET}  "
                f"{DIM}({qtype}){RESET}  "
                f"{DIM}from {src_ip}{RESET}"
            )
        else:
            # Repeated
            line = (
                f"  {DIM}{timestamp}{RESET}  "
                f"{DIM}[x{count}]{RESET}  "
                f"{CYAN}{domain}{RESET}  "
                f"{DIM}({qtype}) from {src_ip}{RESET}"
            )

        print(line)
        self._log(f"{timestamp}  {domain}  {qtype}  {src_ip}  count={count}")

    def print_stats(self):
        """Print summary statistics."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{BOLD}{'─' * 55}{RESET}")
        print(f"  {BOLD}Capture Summary{RESET}")
        print(f"  {'─' * 40}")
        print(f"  Duration          : {elapsed:.1f}s")
        print(f"  Total DNS queries : {self.total_queries}")
        print(f"  Unique domains    : {len(self.domains_seen)}")
        if self.domain_count:
            top = sorted(self.domain_count.items(), key=lambda x: x[1], reverse=True)[:5]
            print(f"  Top domains       :")
            for d, c in top:
                print(f"    {CYAN}{c:>4}x{RESET}  {d}")
        print(f"{'─' * 55}\n")

        if self._log_handle:
            self._log_handle.write(f"\n--- Summary: {len(self.domains_seen)} unique domains, "
                                   f"{self.total_queries} total queries in {elapsed:.1f}s ---\n")

    def cleanup(self):
        """Close resources."""
        if self._log_handle:
            self._log_handle.close()

    def start(self):
        """Start sniffing."""
        print(f"{YELLOW}[*] Sniffing DNS on interface: {self.interface}{RESET}")
        print(f"{YELLOW}[*] Filtering out: {len(self.exclude_keywords)} keyword(s){RESET}")
        print(f"{DIM}    Press Ctrl+C to stop.{RESET}\n")
        print(f"  {BOLD}{'TIME':<10} {'STATUS':<8} {'DOMAIN':<35} {'TYPE':<6} {'SOURCE'}{RESET}")
        print(f"  {'─' * 70}")

        try:
            scapy.sniff(
                iface=self.interface,
                filter="udp port 53",
                prn=self.process_packet,
                store=0,
            )
        except PermissionError:
            print(f"{RED}[!] Permission denied. Run with sudo.{RESET}")
            sys.exit(1)
        except OSError as e:
            print(f"{RED}[!] Interface error: {e}{RESET}")
            sys.exit(1)


def get_arguments():
    parser = argparse.ArgumentParser(
        description="DNS Traffic Monitor — Capture DNS queries in real-time",
        epilog="Example: sudo python3 dns_sniffer.py -i eth0 --log dns.log",
    )
    parser.add_argument(
        "-i", "--interface",
        dest="interface",
        default=scapy.conf.iface,
        help=f"Network interface (default: {scapy.conf.iface})",
    )
    parser.add_argument(
        "--log",
        dest="log_file",
        default=None,
        help="Save captured domains to a log file",
    )
    parser.add_argument(
        "--no-filter",
        dest="no_filter",
        action="store_true",
        help="Disable keyword filtering (show all DNS queries)",
    )
    parser.add_argument(
        "--exclude",
        dest="extra_exclude",
        nargs="*",
        default=[],
        help="Additional keywords to exclude (e.g. --exclude amazon netflix)",
    )
    return parser.parse_args()


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
    )

    def handler(sig, frame):
        print(f"\n{RED}[!] Stopping capture...{RESET}")
        sniffer.print_stats()
        sniffer.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)

    sniffer.start()


if __name__ == "__main__":
    main()
