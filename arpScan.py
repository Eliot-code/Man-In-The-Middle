#!/usr/bin/env python3
"""
arpScan.py — ARP Network Scanner
Discovers live hosts on a network using ARP requests.
Displays results in a formatted table with IP, MAC, and optional vendor info.

Usage:
    sudo python3 arpScan.py -t 192.168.1.0/24
    sudo python3 arpScan.py -t 192.168.1.10 -i eth0 --timeout 3
    sudo python3 arpScan.py -t 192.168.1.0/24 -o results.csv
"""

import scapy.all as scapy
import argparse
import sys
import os
import csv
import json
from datetime import datetime

# ── ANSI Colors ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
╔══════════════════════════════════════════╗
║           ARP Network Scanner            ║
║         Host Discovery via ARP           ║
╚══════════════════════════════════════════╝{RESET}
"""


def get_arguments():
    parser = argparse.ArgumentParser(
        description="ARP Network Scanner — Discover live hosts on your network",
        epilog="Example: sudo python3 arpScan.py -t 192.168.1.0/24 -i eth0",
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        dest="target",
        help="Target IP or CIDR range (e.g. 192.168.1.0/24 or 192.168.1.10)",
    )
    parser.add_argument(
        "-i", "--interface",
        dest="interface",
        default=None,
        help="Network interface to use (default: auto-detect)",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=2,
        help="Timeout in seconds for ARP responses (default: 2)",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        default=None,
        help="Save results to file (.csv or .json)",
    )
    parser.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        help="Show additional scan details",
    )
    return parser.parse_args()


def check_root():
    """ARP scanning requires root privileges."""
    if os.geteuid() != 0:
        print(f"{RED}[!] Error: This script must be run as root (sudo).{RESET}")
        sys.exit(1)


def scan(target, interface=None, timeout=2, verbose=False):
    """
    Send ARP requests and collect responses.
    Returns a list of dicts: [{"ip": ..., "mac": ...}, ...]
    """
    arp_request = scapy.ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    if verbose:
        print(f"{YELLOW}[*] Sending ARP requests to {target} (timeout={timeout}s)...{RESET}")

    kwargs = {"timeout": timeout, "verbose": False}
    if interface:
        kwargs["iface"] = interface

    try:
        answered, _ = scapy.srp(packet, **kwargs)
    except PermissionError:
        print(f"{RED}[!] Permission denied. Run with sudo.{RESET}")
        sys.exit(1)
    except OSError as e:
        print(f"{RED}[!] Network error: {e}{RESET}")
        sys.exit(1)

    hosts = []
    for sent, received in answered:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
        })

    # Sort by IP numerically
    hosts.sort(key=lambda h: tuple(int(p) for p in h["ip"].split(".")))
    return hosts


def display_results(hosts, target):
    """Print results in a formatted table."""
    if not hosts:
        print(f"\n{RED}[!] No hosts found on {target}.{RESET}")
        print(f"{YELLOW}    Check that the target range is correct and you're on the right interface.{RESET}")
        return

    print(f"\n{GREEN}{BOLD}[+] {len(hosts)} host(s) discovered on {target}{RESET}\n")

    # Table header
    ip_width = max(len(h["ip"]) for h in hosts)
    ip_width = max(ip_width, 15)

    header = f"  {'#':<5} {'IP Address':<{ip_width + 2}} {'MAC Address':<20}"
    separator = f"  {'─' * 5} {'─' * (ip_width + 2)} {'─' * 20}"

    print(f"{BOLD}{header}{RESET}")
    print(separator)

    for idx, host in enumerate(hosts, 1):
        ip_str = f"{GREEN}{host['ip']}{RESET}"
        mac_str = f"{CYAN}{host['mac']}{RESET}"
        print(f"  {idx:<5} {ip_str:<{ip_width + 13}} {mac_str}")

    print(separator)
    print(f"  {YELLOW}Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}\n")


def export_results(hosts, filepath):
    """Export results to CSV or JSON."""
    ext = os.path.splitext(filepath)[1].lower()

    timestamp = datetime.now().isoformat()
    try:
        if ext == ".json":
            data = {
                "scan_time": timestamp,
                "total_hosts": len(hosts),
                "hosts": hosts,
            }
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
        else:
            # Default to CSV
            with open(filepath, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "mac"])
                writer.writeheader()
                writer.writerows(hosts)

        print(f"{GREEN}[+] Results saved to: {filepath}{RESET}")
    except IOError as e:
        print(f"{RED}[!] Could not write to {filepath}: {e}{RESET}")


def main():
    print(BANNER)
    check_root()
    args = get_arguments()

    hosts = scan(
        target=args.target,
        interface=args.interface,
        timeout=args.timeout,
        verbose=args.verbose,
    )
    display_results(hosts, args.target)

    if args.output and hosts:
        export_results(hosts, args.output)


if __name__ == "__main__":
    main()
