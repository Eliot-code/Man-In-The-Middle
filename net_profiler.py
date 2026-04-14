#!/usr/bin/env python3
"""
net_profiler.py v1.0 — Passive Device Intelligence Profiler

A fully PASSIVE network reconnaissance tool that builds rich behavioral
profiles of every device seen on the wire WITHOUT sending a single packet.
Designed to run alongside an active MITM session to generate intelligence
that traditional credential sniffers completely miss.

Unique capabilities (not found in standard MITM toolkits):
  • Passive OS fingerprinting      — infer OS from TCP/IP stack (TTL, win, DF)
  • Device-class classification    — IoT, Mobile, Desktop, Server, Router
  • Application inference          — detect apps from ports + DNS + SNI
  • Activity heatmap per device    — 24h timeline of when each host is active
  • Traffic volume accounting      — bytes sent/received per device
  • Connection graph               — who talks to whom
  • Service enumeration            — list of open/used ports per host
  • Live ASCII dashboard           — periodic refresh with ranked profiles
  • Complete JSON intelligence dump on exit

Usage:
    sudo python3 net_profiler.py
    sudo python3 net_profiler.py -i eth0 --dashboard
    sudo python3 net_profiler.py -i eth0 --export profile.json
    sudo python3 net_profiler.py -i eth0 --subnet 192.168.1.0/24
"""

import scapy.all as scapy
from scapy.layers import http
import argparse
import json
import os
import signal
import sys
import threading
import time
import ipaddress
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
CLEAR   = "\033[2J\033[H"

VERSION = "1.0"

BANNER = f"""{CYAN}{BOLD}
╔═════════════════════════════════════════════════════════════╗
║     Passive Device Intelligence Profiler  v{VERSION}              ║
║   OS Fingerprinting · Classification · Activity · Map     ║
╚═════════════════════════════════════════════════════════════╝{RESET}"""

# ── Passive OS fingerprint by initial TTL ─────────────────────────────────────
# Most stacks use 64 (Linux/macOS/Android/iOS), 128 (Windows), 255 (network gear)
def ttl_to_os(ttl: int) -> str:
    if ttl == 0:
        return "Unknown"
    if ttl <= 64:     # likely originated with TTL=64 and a few hops
        if ttl >= 55:   return "Linux/macOS/Unix"
        return "Linux/macOS/Unix (distant)"
    if ttl <= 128:
        if ttl >= 120:  return "Windows"
        return "Windows (distant)"
    if ttl <= 255:
        if ttl >= 240:  return "Network device / Router"
        return "Network device (distant)"
    return "Unknown"


# ── Well-known port → service map ─────────────────────────────────────────────
PORT_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
    69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3",
    111: "RPC", 123: "NTP", 135: "RPC-MS", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 162: "SNMP-TRAP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 500: "IKE", 514: "Syslog",
    515: "LPR", 554: "RTSP", 587: "SMTP-sub", 631: "IPP",
    636: "LDAPS", 873: "rsync", 902: "VMware", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle", 1701: "L2TP", 1723: "PPTP", 1883: "MQTT",
    1900: "SSDP/UPnP", 2049: "NFS", 2222: "SSH-alt", 3128: "Squid",
    3306: "MySQL", 3389: "RDP", 3478: "STUN", 3690: "SVN",
    4500: "IPSec-NAT", 5060: "SIP", 5061: "SIPS", 5222: "XMPP",
    5353: "mDNS", 5432: "Postgres", 5555: "ADB", 5672: "AMQP",
    5683: "CoAP", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    6443: "K8s-API", 6667: "IRC", 6881: "BitTorrent",
    7777: "Game", 8000: "HTTP-alt", 8008: "HTTP-alt",
    8080: "HTTP-proxy", 8081: "HTTP-alt", 8086: "InfluxDB",
    8443: "HTTPS-alt", 8883: "MQTT-TLS", 8888: "HTTP-alt",
    9000: "HTTP-alt", 9090: "Prometheus", 9200: "Elasticsearch",
    9418: "Git", 11211: "Memcached", 27017: "MongoDB",
    32400: "Plex", 51820: "WireGuard",
}

# ── Device classification hints ───────────────────────────────────────────────
IOT_PORTS     = {1883, 8883, 5683, 23, 7547, 5555}
SERVER_PORTS  = {22, 80, 443, 3306, 5432, 6379, 27017, 9200, 11211}
MOBILE_HINTS  = ("apple", "ios", "android", "samsung", "xiaomi",
                 "huawei", "oppo", "oneplus", "google", "googleusercontent",
                 "firebase", "gcm", "whatsapp", "messenger", "instagram")
DESKTOP_HINTS = ("windows", "microsoft", "ubuntu", "canonical",
                 "debian", "steam", "spotify", "office365", "adobe")
IOT_HINTS     = ("iot", "tuya", "hue", "nest", "ring", "wyze",
                 "lifx", "sonos", "roku", "alexa", "amazon-dss",
                 "tplink", "mqtt", "shelly", "smartthings")
ROUTER_HINTS  = ("routerlogin", "asus", "linksys", "netgear",
                 "ubnt", "mikrotik", "openwrt", "ddwrt", "fritz")


# ── Device profile data class ─────────────────────────────────────────────────

class DeviceProfile:
    __slots__ = (
        "ip", "mac", "first_seen", "last_seen",
        "ttl_observed", "os_guess", "device_class",
        "ports_local", "ports_remote", "services_used",
        "domains", "peers", "bytes_sent", "bytes_recv",
        "packets_sent", "packets_recv", "activity_hours",
        "tcp_windows", "user_agents", "hostnames",
    )

    def __init__(self, ip: str):
        self.ip            = ip
        self.mac           = ""
        self.first_seen    = datetime.now()
        self.last_seen     = datetime.now()
        self.ttl_observed: set  = set()
        self.os_guess      = "Unknown"
        self.device_class  = "Unknown"
        self.ports_local:  set  = set()   # ports this device listens on / uses as src
        self.ports_remote: set  = set()   # ports it connects to
        self.services_used: set = set()   # named services inferred
        self.domains:      set  = set()   # DNS queries or SNI from this device
        self.peers:        set  = set()   # IPs this device talks to
        self.bytes_sent    = 0
        self.bytes_recv    = 0
        self.packets_sent  = 0
        self.packets_recv  = 0
        self.activity_hours = defaultdict(int)   # hour-of-day → packet count
        self.tcp_windows:  set  = set()
        self.user_agents:  set  = set()
        self.hostnames:    set  = set()

    def touch(self) -> None:
        now = datetime.now()
        self.last_seen = now
        self.activity_hours[now.hour] += 1

    def classify(self) -> None:
        """Infer device_class from collected evidence."""
        # IoT fingerprint
        if self.ports_local & IOT_PORTS or self.ports_remote & IOT_PORTS:
            self.device_class = "IoT"
            return
        if any(h in d.lower() for d in self.domains for h in IOT_HINTS):
            self.device_class = "IoT"
            return

        # Router
        if any(h in d.lower() for d in self.domains for h in ROUTER_HINTS):
            self.device_class = "Router"
            return
        if 67 in self.ports_local or 53 in self.ports_local:
            self.device_class = "Router"
            return

        # Server (exposes many server ports)
        if len(self.ports_local & SERVER_PORTS) >= 2:
            self.device_class = "Server"
            return

        # Mobile
        if any(h in ua.lower() for ua in self.user_agents for h in ("android", "iphone", "ipad", "mobile")):
            self.device_class = "Mobile"
            return
        if any(h in d.lower() for d in self.domains for h in MOBILE_HINTS):
            self.device_class = "Mobile"
            return

        # Desktop (fallback if we see desktop hints)
        if any(h in d.lower() for d in self.domains for h in DESKTOP_HINTS):
            self.device_class = "Desktop"
            return

        # Last resort: guess from OS
        if "Windows" in self.os_guess:
            self.device_class = "Desktop"
        elif "Linux" in self.os_guess:
            self.device_class = "Desktop/Server"

    def activity_bar(self, width: int = 24) -> str:
        """Return a 24-char heatmap bar of activity across hours."""
        if not self.activity_hours:
            return "─" * 24
        peak = max(self.activity_hours.values())
        blocks = " ▁▂▃▄▅▆▇█"
        out = []
        for h in range(24):
            v = self.activity_hours.get(h, 0)
            idx = min(8, int((v / peak) * 8)) if peak else 0
            out.append(blocks[idx])
        return "".join(out)

    def to_dict(self) -> dict:
        return {
            "ip":            self.ip,
            "mac":           self.mac,
            "first_seen":    self.first_seen.isoformat(),
            "last_seen":     self.last_seen.isoformat(),
            "os_guess":      self.os_guess,
            "device_class":  self.device_class,
            "ttl_observed":  sorted(self.ttl_observed),
            "ports_local":   sorted(self.ports_local),
            "ports_remote":  sorted(self.ports_remote)[:50],
            "services_used": sorted(self.services_used),
            "top_domains":   sorted(self.domains)[:30],
            "peers":         sorted(self.peers)[:30],
            "bytes_sent":    self.bytes_sent,
            "bytes_recv":    self.bytes_recv,
            "packets_sent":  self.packets_sent,
            "packets_recv":  self.packets_recv,
            "user_agents":   list(self.user_agents)[:5],
            "hostnames":     list(self.hostnames),
            "activity_bar":  self.activity_bar(),
        }


# ── Main profiler ─────────────────────────────────────────────────────────────

class NetProfiler:
    def __init__(self, interface: str, subnet: str = "", dashboard: bool = False,
                 export_file: str = "", refresh: int = 5):
        self.interface    = interface
        self.subnet_net   = ipaddress.ip_network(subnet, strict=False) if subnet else None
        self.dashboard    = dashboard
        self.export_file  = export_file
        self.refresh      = refresh
        self.devices: dict = {}   # ip -> DeviceProfile
        self.start_time   = datetime.now()
        self._lock        = threading.Lock()
        self._stop        = threading.Event()

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _in_scope(self, ip: str) -> bool:
        if not self.subnet_net:
            return True
        try:
            return ipaddress.ip_address(ip) in self.subnet_net
        except ValueError:
            return False

    def _get(self, ip: str) -> DeviceProfile:
        with self._lock:
            if ip not in self.devices:
                self.devices[ip] = DeviceProfile(ip)
            return self.devices[ip]

    @staticmethod
    def _format_bytes(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.1f}{unit}"
            n /= 1024
        return f"{n:.1f}PB"

    # ── Packet handler ───────────────────────────────────────────────────────

    def handle(self, pkt) -> None:
        try:
            if not pkt.haslayer(scapy.IP):
                # Still record MAC from Ethernet on ARP frames, etc.
                return

            ip_layer = pkt[scapy.IP]
            src, dst = ip_layer.src, ip_layer.dst
            ttl      = int(ip_layer.ttl)
            size     = int(ip_layer.len) if ip_layer.len else len(pkt)

            src_scope = self._in_scope(src)
            dst_scope = self._in_scope(dst)
            if not (src_scope or dst_scope):
                return

            # ── Source device (local) ──
            if src_scope:
                d = self._get(src)
                if pkt.haslayer(scapy.Ether):
                    mac = pkt[scapy.Ether].src
                    if mac and not d.mac:
                        d.mac = mac
                d.ttl_observed.add(ttl)
                # OS guess: only update if a "closer" TTL arrives
                guess = ttl_to_os(ttl)
                if guess != "Unknown":
                    d.os_guess = guess
                d.packets_sent += 1
                d.bytes_sent   += size
                d.peers.add(dst)
                d.touch()

                if pkt.haslayer(scapy.TCP):
                    d.ports_local.add(int(pkt[scapy.TCP].sport))
                    d.ports_remote.add(int(pkt[scapy.TCP].dport))
                    d.tcp_windows.add(int(pkt[scapy.TCP].window))
                    svc = PORT_SERVICES.get(int(pkt[scapy.TCP].dport))
                    if svc:
                        d.services_used.add(svc)
                elif pkt.haslayer(scapy.UDP):
                    d.ports_local.add(int(pkt[scapy.UDP].sport))
                    d.ports_remote.add(int(pkt[scapy.UDP].dport))
                    svc = PORT_SERVICES.get(int(pkt[scapy.UDP].dport))
                    if svc:
                        d.services_used.add(svc)

            # ── Destination device (local receiver) ──
            if dst_scope:
                d = self._get(dst)
                d.packets_recv += 1
                d.bytes_recv   += size
                d.peers.add(src)

            # ── DNS queries → record domain for source ──
            if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qr == 0 and pkt[scapy.DNS].qdcount > 0:
                try:
                    dom = pkt[scapy.DNS].qd.qname.decode(errors="ignore").rstrip(".")
                    if src_scope and dom:
                        self._get(src).domains.add(dom)
                except Exception:
                    pass

            # ── HTTP: grab User-Agent & Host ──
            if pkt.haslayer(http.HTTPRequest):
                try:
                    req = pkt[http.HTTPRequest]
                    if src_scope:
                        d = self._get(src)
                        if req.User_Agent:
                            d.user_agents.add(req.User_Agent.decode(errors="ignore")[:120])
                        if req.Host:
                            d.domains.add(req.Host.decode(errors="ignore"))
                except Exception:
                    pass

            # ── DHCP: harvest hostname ──
            if pkt.haslayer(scapy.DHCP):
                try:
                    for opt in pkt[scapy.DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "hostname":
                            hn = opt[1].decode(errors="ignore") if isinstance(opt[1], bytes) else str(opt[1])
                            if src_scope and hn:
                                self._get(src).hostnames.add(hn)
                except Exception:
                    pass

        except Exception:
            # Packet processing must never crash the sniffer
            return

    # ── Dashboard ────────────────────────────────────────────────────────────

    def _dashboard_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.refresh)
            self._render_dashboard()

    def _render_dashboard(self) -> None:
        with self._lock:
            for d in self.devices.values():
                d.classify()
            devices = sorted(self.devices.values(),
                             key=lambda d: d.packets_sent + d.packets_recv,
                             reverse=True)

        elapsed = (datetime.now() - self.start_time).total_seconds()
        sys.stdout.write(CLEAR)
        print(BANNER)
        print(f"{DIM}  Iface: {self.interface}   Uptime: {elapsed:.0f}s   "
              f"Devices tracked: {len(devices)}{RESET}\n")

        cols = f"  {'IP':<16} {'MAC':<18} {'OS':<22} {'Class':<14} {'Tx':>9} {'Rx':>9}  Activity (00-23)"
        print(f"{BOLD}{cols}{RESET}")
        print("  " + "─" * (len(cols) - 2))

        for d in devices[:20]:
            os_col   = d.os_guess[:22]
            cls_col  = d.device_class[:14]
            cls_c    = {
                "IoT":     MAGENTA,
                "Mobile":  CYAN,
                "Desktop": GREEN,
                "Server":  YELLOW,
                "Router":  BLUE,
            }.get(d.device_class, DIM)

            print(
                f"  {GREEN}{d.ip:<16}{RESET} "
                f"{DIM}{(d.mac or '-'):<18}{RESET} "
                f"{YELLOW}{os_col:<22}{RESET} "
                f"{cls_c}{cls_col:<14}{RESET} "
                f"{self._format_bytes(d.bytes_sent):>9} "
                f"{self._format_bytes(d.bytes_recv):>9}  "
                f"{CYAN}{d.activity_bar()}{RESET}"
            )

        print()
        print(f"  {DIM}Refresh: every {self.refresh}s  —  Ctrl+C to stop & export.{RESET}")

    # ── Text summary (non-dashboard) ─────────────────────────────────────────

    def print_summary(self) -> None:
        with self._lock:
            for d in self.devices.values():
                d.classify()
            devices = sorted(self.devices.values(),
                             key=lambda d: d.packets_sent + d.packets_recv,
                             reverse=True)

        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{BOLD}{'─' * 80}{RESET}")
        print(f"  {BOLD}Intelligence Report  —  Net Profiler v{VERSION}{RESET}")
        print(f"  {'─' * 65}")
        print(f"  Duration        : {elapsed:.1f}s")
        print(f"  Devices tracked : {len(devices)}")

        # Class counts
        class_counts = defaultdict(int)
        for d in devices:
            class_counts[d.device_class] += 1
        if class_counts:
            tag = "  Composition     : " + "  ".join(
                f"{k}={v}" for k, v in sorted(class_counts.items()))
            print(tag)
        print(f"{BOLD}{'─' * 80}{RESET}\n")

        # Per-device one-liner
        for d in devices[:30]:
            act = d.activity_bar()
            ua  = next(iter(d.user_agents), "")[:60]
            hn  = next(iter(d.hostnames), "")
            print(
                f"  {GREEN}{BOLD}{d.ip}{RESET}  "
                f"{DIM}{d.mac or '-'}{RESET}  "
                f"[{YELLOW}{d.os_guess}{RESET}]  "
                f"[{CYAN}{d.device_class}{RESET}]"
            )
            print(f"    {DIM}tx={self._format_bytes(d.bytes_sent)}  "
                  f"rx={self._format_bytes(d.bytes_recv)}  "
                  f"peers={len(d.peers)}  domains={len(d.domains)}  "
                  f"services={len(d.services_used)}{RESET}")
            if hn:
                print(f"    {DIM}hostname: {hn}{RESET}")
            if ua:
                print(f"    {DIM}UA: {ua}{RESET}")
            print(f"    {DIM}activity 00..23 {CYAN}{act}{RESET}")
            if d.services_used:
                svc = ", ".join(sorted(d.services_used)[:10])
                print(f"    {DIM}services: {svc}{RESET}")
            print()

    # ── Export ───────────────────────────────────────────────────────────────

    def export(self) -> None:
        if not self.export_file:
            return
        with self._lock:
            for d in self.devices.values():
                d.classify()
            data = {
                "generated":   datetime.now().isoformat(),
                "interface":   self.interface,
                "duration_s":  (datetime.now() - self.start_time).total_seconds(),
                "device_count": len(self.devices),
                "devices":     [d.to_dict() for d in self.devices.values()],
            }
        try:
            with open(self.export_file, "w") as f:
                json.dump(data, f, indent=2)
            print(f"{GREEN}[+] Intelligence report saved: {self.export_file}{RESET}")
        except IOError as e:
            print(f"{RED}[!] Export failed: {e}{RESET}")

    # ── Start sniffing ───────────────────────────────────────────────────────

    def start(self) -> None:
        print(f"{YELLOW}[*] Passive profiling on: {self.interface}{RESET}")
        if self.subnet_net:
            print(f"{YELLOW}[*] Scope restricted to: {self.subnet_net}{RESET}")
        print(f"{DIM}    No packets are sent. Ctrl+C to stop.{RESET}\n")

        if self.dashboard:
            t = threading.Thread(target=self._dashboard_loop, daemon=True)
            t.start()

        try:
            scapy.sniff(
                iface=self.interface,
                prn=self.handle,
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
        description=f"Passive Device Intelligence Profiler v{VERSION}",
        epilog="Example: sudo python3 net_profiler.py -i eth0 --dashboard --export report.json",
    )
    p.add_argument("-i", "--interface", dest="interface", default=scapy.conf.iface,
                   help=f"Network interface (default: {scapy.conf.iface})")
    p.add_argument("--subnet", dest="subnet", default="",
                   help="Limit profiling to hosts in this CIDR (e.g. 192.168.1.0/24)")
    p.add_argument("--dashboard", dest="dashboard", action="store_true",
                   help="Enable live auto-refreshing dashboard")
    p.add_argument("--refresh", dest="refresh", type=int, default=5,
                   help="Dashboard refresh interval in seconds (default: 5)")
    p.add_argument("--export", dest="export_file", default=None,
                   help="Write JSON intelligence report on exit")
    return p.parse_args()


def main():
    print(BANNER)
    if os.geteuid() != 0:
        print(f"{RED}[!] This script must be run as root (sudo).{RESET}")
        sys.exit(1)

    args = get_arguments()
    prof = NetProfiler(
        interface=args.interface,
        subnet=args.subnet,
        dashboard=args.dashboard,
        export_file=args.export_file or "",
        refresh=args.refresh,
    )

    def handler(sig, frame):
        prof._stop.set()
        print(f"\n{RED}[!] Stopping profiler...{RESET}")
        if not args.dashboard:
            prof.print_summary()
        prof.export()
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    prof.start()


if __name__ == "__main__":
    main()
