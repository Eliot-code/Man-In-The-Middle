#!/usr/bin/env python3
"""
arpScan.py v2.0 — Advanced ARP Network Scanner

New in v2.0:
  • MAC vendor lookup from built-in OUI database (~120 vendors)
  • Hostname resolution via reverse-DNS  (--resolve)
  • Default gateway auto-detection and [GW] highlighting
  • Continuous watch/monitoring mode    (--watch --interval N)
  • Richer output table: #, IP, MAC, Vendor, Hostname
  • Scan timing and summary statistics

Usage:
    sudo python3 arpScan.py -t 192.168.1.0/24
    sudo python3 arpScan.py -t 192.168.1.0/24 --resolve -v
    sudo python3 arpScan.py -t 192.168.1.0/24 --watch --interval 30
    sudo python3 arpScan.py -t 192.168.1.0/24 -o results.json
"""

import scapy.all as scapy
import argparse
import sys
import os
import csv
import json
import socket
import subprocess
import time
from datetime import datetime

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
║          ARP Network Scanner  v{VERSION}                  ║
║  Host Discovery · Vendor Lookup · Watch Mode · DNS  ║
╚══════════════════════════════════════════════════════╝{RESET}"""

# ── OUI Vendor Database ───────────────────────────────────────────────────────
# Keys: first 6 hex digits of MAC (lowercase, no separators).
OUI_DB: dict = {
    # Apple
    "000393": "Apple", "000502": "Apple", "000a27": "Apple",
    "000a95": "Apple", "000d93": "Apple", "001124": "Apple",
    "001451": "Apple", "0016cb": "Apple", "0017f2": "Apple",
    "001871": "Apple", "001b63": "Apple", "001cb3": "Apple",
    "001d4f": "Apple", "001e52": "Apple", "001f5b": "Apple",
    "002241": "Apple", "3c0754": "Apple", "3c15c2": "Apple",
    "4c74bf": "Apple", "5c96e7": "Apple", "60f81d": "Apple",
    "7c5049": "Apple", "7cf05f": "Apple", "8863df": "Apple",
    "9c4fda": "Apple", "a45e60": "Apple", "a8bbcf": "Apple",
    "b418d1": "Apple", "bc4cc4": "Apple", "d0254b": "Apple",
    "d4619d": "Apple", "dc9b9c": "Apple", "e0b9ba": "Apple",
    "f0d1a9": "Apple", "f81eff": "Apple",
    # Cisco
    "000569": "Cisco", "001012": "Cisco", "001030": "Cisco",
    "0010f6": "Cisco", "001185": "Cisco", "001201": "Cisco",
    "0013c4": "Cisco", "001427": "Cisco", "001518": "Cisco",
    "001617": "Cisco", "0016b6": "Cisco", "001709": "Cisco",
    "001801": "Cisco", "00189a": "Cisco", "001905": "Cisco",
    "001a2f": "Cisco", "001aa2": "Cisco", "001b0d": "Cisco",
    "001c58": "Cisco", "001d45": "Cisco", "001e6b": "Cisco",
    "001ebe": "Cisco", "001f26": "Cisco", "001f6c": "Cisco",
    "002040": "Cisco", "002155": "Cisco", "0021a0": "Cisco",
    "002255": "Cisco", "002290": "Cisco", "0022be": "Cisco",
    "0023be": "Cisco", "0023eb": "Cisco", "002400": "Cisco",
    "68bc0c": "Cisco", "74a0b0": "Cisco", "78bc1a": "Cisco",
    # Intel
    "001b21": "Intel", "001e67": "Intel", "001f3b": "Intel",
    "002132": "Intel", "0024d7": "Intel", "002618": "Intel",
    "00269e": "Intel", "40a36b": "Intel", "485b39": "Intel",
    "5c514f": "Intel", "7c7635": "Intel", "a4c361": "Intel",
    "b0c74e": "Intel", "dc5360": "Intel", "e4b021": "Intel",
    "f8bef8": "Intel", "fc15b4": "Intel",
    # Samsung
    "000c76": "Samsung", "001599": "Samsung", "002339": "Samsung",
    "0024e9": "Samsung", "083d88": "Samsung", "101dc0": "Samsung",
    "18f061": "Samsung", "1c62b8": "Samsung", "2c0e3d": "Samsung",
    "2cfd22": "Samsung", "30cd98": "Samsung", "3c5a37": "Samsung",
    "4c3c16": "Samsung", "4c6641": "Samsung", "5001bb": "Samsung",
    "54880e": "Samsung", "5cfb5f": "Samsung", "6c8312": "Samsung",
    "74458a": "Samsung", "78472e": "Samsung", "84250a": "Samsung",
    "9c0298": "Samsung", "a4eb75": "Samsung", "b4efd3": "Samsung",
    "bc1454": "Samsung", "c467b5": "Samsung", "c8ba94": "Samsung",
    "dc2b61": "Samsung", "e86f38": "Samsung",
    # VMware / Hypervisors
    "000c29": "VMware",     "001c14": "VMware",  "005056": "VMware",
    "001c42": "Parallels",  "080027": "VirtualBox",
    "525400": "QEMU/KVM",
    # Microsoft
    "0003ff": "Microsoft",  "000d3a": "Microsoft", "001dd8": "Microsoft",
    "00155d": "Hyper-V",    "28184d": "Microsoft",
    # Raspberry Pi
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    # Huawei
    "001e10": "Huawei", "00259e": "Huawei", "002822": "Huawei",
    "303dcf": "Huawei", "389496": "Huawei", "4477e1": "Huawei",
    "6c8a73": "Huawei", "8c0d76": "Huawei", "941802": "Huawei",
    "9c37f4": "Huawei", "a047d7": "Huawei", "f8af05": "Huawei",
    # TP-Link
    "003192": "TP-Link", "00259c": "TP-Link", "0c8268": "TP-Link",
    "107bef": "TP-Link", "14cc20": "TP-Link", "18d61c": "TP-Link",
    "1c74d7": "TP-Link", "208b37": "TP-Link", "28286c": "TP-Link",
    "30de4b": "TP-Link", "40a5ef": "TP-Link", "4cce36": "TP-Link",
    "508f4c": "TP-Link", "6466b3": "TP-Link", "7c8bca": "TP-Link",
    "90f652": "TP-Link", "a42369": "TP-Link", "b0487a": "TP-Link",
    "c4e984": "TP-Link", "d07e28": "TP-Link",
    # Netgear
    "000c91": "Netgear", "000d87": "Netgear", "000e8f": "Netgear",
    "000fb5": "Netgear", "001409": "Netgear", "001b2f": "Netgear",
    "0022b0": "Netgear", "00223f": "Netgear", "4c6004": "Netgear",
    "6c198f": "Netgear", "744401": "Netgear", "84189f": "Netgear",
    "9c3dcf": "Netgear", "a040a0": "Netgear", "a42177": "Netgear",
    "c03f0e": "Netgear", "e04136": "Netgear",
    # Realtek
    "00e04c": "Realtek", "14dae9": "Realtek", "20cf30": "Realtek",
    "4ceeb8": "Realtek", "54e1ad": "Realtek", "60a4d0": "Realtek",
    # Dell
    "001372": "Dell", "001560": "Dell", "0019b9": "Dell",
    "001a4b": "Dell", "001e4f": "Dell", "0021f6": "Dell",
    "002370": "Dell", "0024e8": "Dell", "f0761c": "Dell",
    # HP
    "001083": "HP", "001321": "HP", "001438": "HP",
    "0016b9": "HP", "001708": "HP", "0018fe": "HP",
    "001c2e": "HP", "001cc4": "HP", "001e0b": "HP",
    "0021f7": "HP", "08742e": "HP", "10604b": "HP",
    "3c4a92": "HP", "40a8f3": "HP", "54986c": "HP",
    "708bd6": "HP", "9cb654": "HP", "b499ba": "HP",
    # D-Link
    "000d88": "D-Link", "001195": "D-Link", "0015e9": "D-Link",
    "001cf0": "D-Link", "002191": "D-Link", "1c7ee5": "D-Link",
    "28107b": "D-Link", "34088e": "D-Link", "84c9b2": "D-Link",
    # Ubiquiti
    "002722": "Ubiquiti", "04182b": "Ubiquiti", "0418d6": "Ubiquiti",
    "24a43c": "Ubiquiti", "44d9e7": "Ubiquiti", "687278": "Ubiquiti",
    "70a741": "Ubiquiti", "788a20": "Ubiquiti", "e063da": "Ubiquiti",
    "f09fc2": "Ubiquiti", "fc5272": "Ubiquiti",
}


# ── Helper functions ──────────────────────────────────────────────────────────

def lookup_vendor(mac: str) -> str:
    """Return vendor name from MAC OUI prefix, or 'Unknown'."""
    oui = mac.replace(":", "").replace("-", "").lower()[:6]
    return OUI_DB.get(oui, "Unknown")


def resolve_hostname(ip: str, timeout: float = 0.8) -> str:
    """Reverse-DNS lookup. Returns hostname string or empty string on failure."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""


def get_default_gateway() -> str:
    """Return the default gateway IP by parsing 'ip route show default'."""
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


def check_root() -> None:
    if os.geteuid() != 0:
        print(f"{RED}[!] This script must be run as root (sudo).{RESET}")
        sys.exit(1)


# ── Core scan ─────────────────────────────────────────────────────────────────

def scan(target: str, interface=None, timeout: int = 2, verbose: bool = False) -> list:
    """
    Send ARP requests to *target* and return list of host dicts.
    Each dict: {"ip": str, "mac": str, "vendor": str}
    """
    if verbose:
        print(f"{YELLOW}[*] Sending ARP to {target}  (timeout={timeout}s)...{RESET}")

    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=target)
    kw  = {"timeout": timeout, "verbose": False}
    if interface:
        kw["iface"] = interface

    try:
        answered, _ = scapy.srp(pkt, **kw)
    except PermissionError:
        print(f"{RED}[!] Permission denied — run with sudo.{RESET}")
        sys.exit(1)
    except OSError as e:
        print(f"{RED}[!] Network error: {e}{RESET}")
        sys.exit(1)

    hosts = []
    for _, rx in answered:
        mac = rx.hwsrc
        hosts.append({"ip": rx.psrc, "mac": mac, "vendor": lookup_vendor(mac)})

    hosts.sort(key=lambda h: tuple(int(p) for p in h["ip"].split(".")))
    return hosts


# ── Display ───────────────────────────────────────────────────────────────────

def display_results(hosts: list, target: str, resolve: bool = False,
                    gateway: str = "", scan_time: float = 0.0) -> None:
    """Print discovered hosts in a rich formatted table."""
    if not hosts:
        print(f"\n{RED}[!] No hosts found on {target}.{RESET}")
        print(f"{YELLOW}    Verify the target range and interface.{RESET}")
        return

    if resolve:
        print(f"{DIM}[*] Resolving hostnames...{RESET}", end="\r", flush=True)
        for h in hosts:
            h["hostname"] = resolve_hostname(h["ip"])
        print(" " * 45, end="\r")

    n = len(hosts)
    vendors_unique = len({h["vendor"] for h in hosts if h["vendor"] != "Unknown"})
    print(f"\n{GREEN}{BOLD}[+] {n} host(s) discovered on {target}{RESET}",
          f" {DIM}({scan_time:.2f}s){RESET}" if scan_time else "")

    # Column widths
    iw = max(max(len(h["ip"])     for h in hosts), 15)
    vw = max(max(len(h["vendor"]) for h in hosts), 10)
    hw = max(max(len(h.get("hostname", "")) for h in hosts), 8) if resolve else 0

    hdr  = f"  {'#':<4}  {'IP Address':<{iw}}  {'MAC Address':<17}  {'Vendor':<{vw}}"
    if resolve:
        hdr += f"  {'Hostname':<{hw}}"
    sep = "  " + "─" * (len(hdr) - 2)

    print(f"\n{BOLD}{hdr}{RESET}")
    print(sep)

    for idx, h in enumerate(hosts, 1):
        is_gw   = (h["ip"] == gateway and gateway)
        ip_col  = (f"{YELLOW}{BOLD}{h['ip']:<{iw}}{RESET}"
                   if is_gw else f"{GREEN}{h['ip']:<{iw}}{RESET}")
        mac_col = f"{DIM}{h['mac']:<17}{RESET}"
        ven_col = f"{CYAN}{h['vendor']:<{vw}}{RESET}"
        gw_tag  = f" {YELLOW}[GW]{RESET}" if is_gw else ""

        row = f"  {idx:<4}  {ip_col}  {mac_col}  {ven_col}{gw_tag}"
        if resolve:
            hn = h.get("hostname", "")
            row += f"  {DIM}{hn}{RESET}"
        print(row)

    print(sep)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"  {DIM}Completed: {ts}  |  Unique vendors: {vendors_unique}{RESET}\n")


# ── Export ────────────────────────────────────────────────────────────────────

def export_results(hosts: list, filepath: str) -> None:
    """Export host list to CSV or JSON."""
    ext = os.path.splitext(filepath)[1].lower()
    ts  = datetime.now().isoformat()
    try:
        if ext == ".json":
            data = {"scan_time": ts, "total_hosts": len(hosts), "hosts": hosts}
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
        else:
            fields = list(hosts[0].keys()) if hosts else ["ip", "mac", "vendor"]
            with open(filepath, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                w.writerows(hosts)
        print(f"{GREEN}[+] Results saved to: {filepath}{RESET}")
    except IOError as e:
        print(f"{RED}[!] Could not write to {filepath}: {e}{RESET}")


# ── Watch mode ────────────────────────────────────────────────────────────────

def watch_mode(target: str, interface, timeout: int, interval: int,
               resolve: bool, gateway: str) -> None:
    """Continuously scan and alert on new/disappeared hosts."""
    print(f"{YELLOW}[*] Watch mode active — rescanning every {interval}s. Ctrl+C to stop.{RESET}\n")
    known: dict = {}  # ip -> host dict

    iteration = 0
    try:
        while True:
            iteration += 1
            t0 = time.time()
            current = scan(target, interface, timeout)
            elapsed = time.time() - t0

            current_ips = {h["ip"] for h in current}
            known_ips   = set(known.keys())

            new_ips  = current_ips - known_ips
            gone_ips = known_ips  - current_ips

            ts = datetime.now().strftime("%H:%M:%S")

            if new_ips:
                for h in current:
                    if h["ip"] in new_ips:
                        if resolve:
                            h["hostname"] = resolve_hostname(h["ip"])
                        hn = f"  ({h.get('hostname','')})" if resolve else ""
                        print(
                            f"  {DIM}{ts}{RESET}  "
                            f"{GREEN}{BOLD}[+] NEW{RESET}  "
                            f"{GREEN}{h['ip']:<15}{RESET}  "
                            f"{DIM}{h['mac']}{RESET}  "
                            f"{CYAN}{h['vendor']}{RESET}{hn}"
                        )
                        known[h["ip"]] = h

            if gone_ips:
                for ip in gone_ips:
                    print(
                        f"  {DIM}{ts}{RESET}  "
                        f"{RED}{BOLD}[-] GONE{RESET}  "
                        f"{RED}{ip:<15}{RESET}  "
                        f"{DIM}{known[ip]['mac']}{RESET}"
                    )
                    del known[ip]

            # First run: populate known
            if iteration == 1:
                for h in current:
                    if resolve:
                        h["hostname"] = resolve_hostname(h["ip"])
                    known[h["ip"]] = h
                display_results(current, target, resolve, gateway, elapsed)

            if not new_ips and not gone_ips and iteration > 1:
                print(
                    f"  {DIM}{ts}  [=] {len(known)} hosts — no changes  "
                    f"(next scan in {interval}s){RESET}",
                    end="\r", flush=True
                )

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n{RED}[!] Watch mode stopped.{RESET}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def get_arguments():
    p = argparse.ArgumentParser(
        description=f"ARP Network Scanner v{VERSION} — Discover live hosts on your network",
        epilog="Example: sudo python3 arpScan.py -t 192.168.1.0/24 --resolve --watch",
    )
    p.add_argument("-t", "--target",    required=True, dest="target",
                   help="Target IP or CIDR range (e.g. 192.168.1.0/24)")
    p.add_argument("-i", "--interface", dest="interface", default=None,
                   help="Network interface (default: auto-detect)")
    p.add_argument("--timeout",         dest="timeout", type=int, default=2,
                   help="ARP response timeout in seconds (default: 2)")
    p.add_argument("-o", "--output",    dest="output", default=None,
                   help="Save results to file (.csv or .json)")
    p.add_argument("--resolve",         dest="resolve", action="store_true",
                   help="Resolve hostnames via reverse-DNS lookup")
    p.add_argument("--watch",           dest="watch", action="store_true",
                   help="Continuously monitor for new/disappeared hosts")
    p.add_argument("--interval",        dest="interval", type=int, default=30,
                   help="Seconds between scans in watch mode (default: 30)")
    p.add_argument("-v", "--verbose",   dest="verbose", action="store_true",
                   help="Show additional scan details")
    return p.parse_args()


def main():
    print(BANNER)
    check_root()
    args = get_arguments()

    gateway = get_default_gateway()
    if gateway and args.verbose:
        print(f"{DIM}[*] Default gateway detected: {gateway}{RESET}")

    if args.watch:
        watch_mode(
            target=args.target, interface=args.interface,
            timeout=args.timeout, interval=args.interval,
            resolve=args.resolve, gateway=gateway,
        )
        return

    t0    = time.time()
    hosts = scan(args.target, args.interface, args.timeout, args.verbose)
    elapsed = time.time() - t0

    display_results(hosts, args.target, args.resolve, gateway, elapsed)

    if args.output and hosts:
        export_results(hosts, args.output)


if __name__ == "__main__":
    main()
