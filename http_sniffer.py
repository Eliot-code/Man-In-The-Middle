#!/usr/bin/env python3
"""
http_sniffer.py v2.0 — Advanced HTTP Traffic Monitor

New in v2.0:
  • Per-IP session tracking (request count, User-Agent, cookies)
  • Cookie extraction from HTTP request headers
  • User-Agent parsing and display
  • JSON body detection and pretty-printing
  • Configurable port monitoring  (--ports 80,8080,8000,8888)
  • Source IP filter              (--filter-ip 192.168.1.x)
  • Brute-force login detection   (repeated POST to same URL)
  • Enhanced summary table with per-IP breakdown
  • JSON export of captured sessions (--export)

Usage:
    sudo python3 http_sniffer.py
    sudo python3 http_sniffer.py -i eth0 --ports 80,8080,8000
    sudo python3 http_sniffer.py -i eth0 --filter-ip 192.168.1.5
    sudo python3 http_sniffer.py -i eth0 --log http.log --export sessions.json
"""

import scapy.all as scapy
from scapy.layers import http
import argparse
import json
import signal
import sys
import os
import threading
from datetime import datetime
from collections import defaultdict
from urllib.parse import unquote_plus

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
║         HTTP Traffic Monitor  v{VERSION}                  ║
║  Session Tracking · Cookie Capture · Brute Detect  ║
╚══════════════════════════════════════════════════════╝{RESET}"""

# ── Credential keywords (lowercase) ──────────────────────────────────────────
CRED_KEYWORDS = {
    # Authentication
    "username", "user", "userid", "user_id", "login", "log",
    "email", "e-mail", "mail",
    "password", "pass", "passwd", "pwd", "secret",
    "token", "auth", "authorization", "bearer",
    "sessionid", "session_id", "session",
    "api_key", "apikey", "api-key", "api_token", "api-token",
    "access_token", "refresh_token", "id_token",
    "csrf", "csrf_token", "xsrf", "_token",
    "otp", "code", "pin", "2fa", "mfa", "totp",
    # Financial
    "creditcard", "cardnumber", "cc-number", "card_number", "pan",
    "cvv", "cvc", "expiry_date", "exp_date", "expiry",
    "routing_number", "account_number", "iban",
    # Personal
    "dob", "birthdate", "date_of_birth",
    "ssn", "social_security", "national_id", "passport",
    "phone", "telephone", "phone_number", "mobile",
    "address", "zip", "zipcode", "postal",
}

# Brute-force detection: same IP + URL + POST within this window (seconds)
BRUTE_WINDOW  = 10
BRUTE_MIN_REQ = 5


# ── Session tracker ───────────────────────────────────────────────────────────

class Session:
    """Tracks HTTP activity for a single source IP."""

    def __init__(self, ip: str):
        self.ip           = ip
        self.request_count = 0
        self.cred_count   = 0
        self.user_agent   = ""
        self.cookies      = set()
        self.methods      = defaultdict(int)
        self.hosts        = set()
        self.post_history: list = []   # [(timestamp, url), ...]

    def is_brute_forcing(self, url: str, now: float) -> bool:
        """True if this IP has POSTed to the same URL >= BRUTE_MIN_REQ times
        within BRUTE_WINDOW seconds."""
        cutoff = now - BRUTE_WINDOW
        recent = [(t, u) for t, u in self.post_history if t >= cutoff and u == url]
        return len(recent) >= BRUTE_MIN_REQ

    def record_post(self, url: str, ts: float) -> None:
        self.post_history.append((ts, url))
        # Trim old entries to keep memory bounded
        cutoff = ts - BRUTE_WINDOW * 3
        self.post_history = [(t, u) for t, u in self.post_history if t >= cutoff]

    def to_dict(self) -> dict:
        return {
            "ip":            self.ip,
            "requests":      self.request_count,
            "cred_hits":     self.cred_count,
            "user_agent":    self.user_agent,
            "cookies":       list(self.cookies),
            "methods":       dict(self.methods),
            "hosts":         list(self.hosts),
        }


# ── Main sniffer class ────────────────────────────────────────────────────────

class HTTPSniffer:
    def __init__(self, interface: str, ports: list, log_file=None,
                 filter_ip: str = "", export_file: str = ""):
        self.interface   = interface
        self.ports       = ports
        self.log_file    = log_file
        self.filter_ip   = filter_ip
        self.export_file = export_file

        self.total_reqs   = 0
        self.cred_total   = 0
        self.brute_alerts = 0
        self.start_time   = datetime.now()
        self.sessions: dict = {}   # ip -> Session
        self._lock        = threading.Lock()

        self._log_handle = None
        if self.log_file:
            try:
                self._log_handle = open(self.log_file, "a", encoding="utf-8")
                self._log_handle.write(
                    f"\n{'='*60}\n"
                    f"HTTP Capture v{VERSION} started at {self.start_time.isoformat()}\n"
                    f"Interface: {self.interface}  |  Ports: {ports}\n"
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

    def _get_session(self, ip: str) -> Session:
        with self._lock:
            if ip not in self.sessions:
                self.sessions[ip] = Session(ip)
            return self.sessions[ip]

    def _detect_credentials(self, data: str) -> list:
        dl = data.lower()
        return [kw for kw in CRED_KEYWORDS if kw in dl]

    def _format_post_data(self, raw: str) -> str:
        """URL-decode and pretty-print POST body (URL-encoded or JSON)."""
        # Try JSON first
        stripped = raw.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                obj = json.loads(stripped)
                lines = json.dumps(obj, indent=2).splitlines()
                return "\n".join(f"      {CYAN}{l}{RESET}" for l in lines)
            except json.JSONDecodeError:
                pass

        # URL-encoded
        try:
            decoded = unquote_plus(raw)
            if "&" in decoded and "=" in decoded:
                parts = []
                for pair in decoded.split("&"):
                    k, _, v = pair.partition("=")
                    parts.append(f"      {CYAN}{k}{RESET} = {YELLOW}{v}{RESET}")
                return "\n".join(parts)
            return f"      {decoded}"
        except Exception:
            return f"      {raw}"

    def _extract_cookies(self, request) -> list:
        """Parse Cookie header into individual name=value strings."""
        try:
            raw = request.Cookie.decode(errors="ignore") if request.Cookie else ""
            return [c.strip() for c in raw.split(";") if c.strip()]
        except AttributeError:
            return []

    def _extract_user_agent(self, request) -> str:
        try:
            return request.User_Agent.decode(errors="ignore") if request.User_Agent else ""
        except AttributeError:
            return ""

    # ── Packet processing ─────────────────────────────────────────────────────

    def process_packet(self, packet) -> None:
        if not packet.haslayer(http.HTTPRequest):
            return

        try:
            req    = packet[http.HTTPRequest]
            host   = req.Host.decode(errors="ignore")   if req.Host   else "?"
            path   = req.Path.decode(errors="ignore")   if req.Path   else "/"
            method = req.Method.decode(errors="ignore") if req.Method else "?"
        except AttributeError:
            return

        src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "?"

        # Apply source IP filter
        if self.filter_ip and src_ip != self.filter_ip:
            return

        url = f"http://{host}{path}"
        ts  = datetime.now().strftime("%H:%M:%S")
        now = datetime.now().timestamp()

        self.total_reqs += 1
        sess = self._get_session(src_ip)
        sess.request_count += 1
        sess.methods[method] += 1
        sess.hosts.add(host)

        # User-Agent
        ua = self._extract_user_agent(req)
        if ua and not sess.user_agent:
            sess.user_agent = ua

        # Cookies
        cookies = self._extract_cookies(req)
        if cookies:
            for c in cookies:
                name = c.split("=")[0].strip()
                sess.cookies.add(name)

        # Method color
        method_colors = {
            "GET":    BLUE,   "POST":   GREEN,
            "PUT":    YELLOW, "DELETE": RED,
            "PATCH":  MAGENTA,"HEAD":   DIM,
        }
        mc = method_colors.get(method, DIM)

        print(
            f"  {DIM}{ts}{RESET}  "
            f"{mc}{method:<7}{RESET}  "
            f"{CYAN}{url}{RESET}  "
            f"{DIM}← {src_ip}{RESET}"
        )

        # Show cookies if present
        if cookies:
            cookie_names = ", ".join(c.split("=")[0] for c in cookies[:4])
            extra = f" +{len(cookies)-4}" if len(cookies) > 4 else ""
            print(f"    {DIM}cookies: {CYAN}{cookie_names}{extra}{RESET}")

        self._log(f"{ts}  {method}  {url}  src={src_ip}")

        # ── POST body / credentials ──────────────────────────────────────────
        if packet.haslayer(scapy.Raw):
            try:
                raw_data = packet[scapy.Raw].load.decode(errors="ignore")
            except Exception:
                return

            if not raw_data.strip():
                return

            matched = self._detect_credentials(raw_data)

            if matched:
                self.cred_total += 1
                sess.cred_count += 1
                print(f"\n  {RED}{BOLD}  ⚠  CREDENTIALS DETECTED{RESET}")
                print(f"  {RED}  {'─' * 50}{RESET}")
                print(f"      Source  : {RED}{src_ip}{RESET}")
                print(f"      URL     : {url}")
                print(f"      Keywords: {', '.join(matched)}")
                print(f"      Data    :")
                print(self._format_post_data(raw_data))
                print(f"  {RED}  {'─' * 50}{RESET}\n")
                self._log(f"*** CRED  src={src_ip}  url={url}  kw={matched}  data={raw_data!r}")

            elif method == "POST":
                # Brute-force detection
                sess.record_post(url, now)
                if sess.is_brute_forcing(url, now):
                    self.brute_alerts += 1
                    print(f"\n  {YELLOW}{BOLD}  ⚡ BRUTE-FORCE PATTERN DETECTED{RESET}")
                    print(f"      Source : {RED}{src_ip}{RESET}")
                    print(f"      Target : {url}")
                    print(f"      Seen   : {BRUTE_MIN_REQ}+ POSTs in {BRUTE_WINDOW}s\n")
                    self._log(f"*** BRUTE  src={src_ip}  url={url}")

                print(f"    {DIM}POST body:{RESET}")
                print(self._format_post_data(raw_data))
                print()

    # ── Statistics ────────────────────────────────────────────────────────────

    def print_stats(self) -> None:
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{BOLD}{'─' * 65}{RESET}")
        print(f"  {BOLD}Capture Summary  —  HTTP Monitor v{VERSION}{RESET}")
        print(f"  {'─' * 50}")
        print(f"  Duration              : {elapsed:.1f}s")
        print(f"  Total HTTP requests   : {self.total_reqs}")
        print(f"  Credential hits       : {RED}{self.cred_total}{RESET}")
        print(f"  Brute-force alerts    : {YELLOW}{self.brute_alerts}{RESET}")
        print(f"  Unique source IPs     : {len(self.sessions)}")

        if self.sessions:
            print(f"\n  {BOLD}{'IP':<17} {'Reqs':>5}  {'Creds':>5}  {'UA (truncated)'}{RESET}")
            print(f"  {'─' * 60}")
            for ip, s in sorted(self.sessions.items(),
                                key=lambda kv: kv[1].request_count, reverse=True):
                ua_short = (s.user_agent[:35] + "…") if len(s.user_agent) > 35 else s.user_agent
                cred_col = f"{RED}{s.cred_count:>5}{RESET}" if s.cred_count else f"{s.cred_count:>5}"
                print(f"  {CYAN}{ip:<17}{RESET} {s.request_count:>5}  {cred_col}  {DIM}{ua_short}{RESET}")

        print(f"{BOLD}{'─' * 65}{RESET}\n")

    def export_sessions(self) -> None:
        if not self.export_file:
            return
        data = {
            "capture_start": self.start_time.isoformat(),
            "total_requests": self.total_reqs,
            "sessions": [s.to_dict() for s in self.sessions.values()],
        }
        try:
            with open(self.export_file, "w") as f:
                json.dump(data, f, indent=2)
            print(f"{GREEN}[+] Sessions exported to: {self.export_file}{RESET}")
        except IOError as e:
            print(f"{RED}[!] Export failed: {e}{RESET}")

    def cleanup(self) -> None:
        if self._log_handle:
            self._log_handle.close()

    # ── Sniff ─────────────────────────────────────────────────────────────────

    def start(self) -> None:
        port_filter = " or ".join(f"tcp port {p}" for p in self.ports)
        bpf = f"({port_filter})"

        print(f"{YELLOW}[*] Sniffing HTTP on: {self.interface}{RESET}")
        print(f"{YELLOW}[*] Monitoring ports: {', '.join(map(str, self.ports))}{RESET}")
        if self.filter_ip:
            print(f"{YELLOW}[*] Filter active: only traffic from {self.filter_ip}{RESET}")
        print(f"{DIM}    HTTPS requires mitmproxy. Press Ctrl+C to stop.{RESET}\n")

        print(f"  {BOLD}{'TIME':<10} {'METHOD':<8} {'URL':<50} {'SRC IP'}{RESET}")
        print(f"  {'─' * 80}")

        try:
            scapy.sniff(
                iface=self.interface,
                filter=bpf,
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
        description=f"HTTP Traffic Monitor v{VERSION} — Capture URLs, credentials, sessions",
        epilog="Example: sudo python3 http_sniffer.py -i eth0 --ports 80,8080 --log out.log",
    )
    p.add_argument("-i", "--interface", dest="interface", default=scapy.conf.iface,
                   help=f"Network interface (default: {scapy.conf.iface})")
    p.add_argument("--ports", dest="ports", default="80,8080,8000,8888",
                   help="Comma-separated list of HTTP ports to monitor (default: 80,8080,8000,8888)")
    p.add_argument("--filter-ip", dest="filter_ip", default="",
                   help="Only capture traffic from this source IP")
    p.add_argument("--log", dest="log_file", default=None,
                   help="Save captured data to a log file")
    p.add_argument("--export", dest="export_file", default=None,
                   help="Export session data to JSON file on exit")
    return p.parse_args()


def main():
    print(BANNER)

    if os.geteuid() != 0:
        print(f"{RED}[!] This script must be run as root (sudo).{RESET}")
        sys.exit(1)

    args = get_arguments()

    try:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    except ValueError:
        print(f"{RED}[!] Invalid port list: {args.ports}{RESET}")
        sys.exit(1)

    sniffer = HTTPSniffer(
        interface=args.interface,
        ports=ports,
        log_file=args.log_file,
        filter_ip=args.filter_ip,
        export_file=args.export_file or "",
    )

    def handler(sig, frame):
        print(f"\n{RED}[!] Stopping capture...{RESET}")
        sniffer.print_stats()
        sniffer.export_sessions()
        sniffer.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    sniffer.start()


if __name__ == "__main__":
    main()
