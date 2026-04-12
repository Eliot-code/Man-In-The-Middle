#!/usr/bin/env python3
"""
http_sniffer.py — HTTP Traffic Monitor
Captures HTTP requests and detects potential credentials in unencrypted traffic.
Works only on HTTP (port 80) — HTTPS traffic requires a proxy like mitmproxy.

Usage:
    sudo python3 http_sniffer.py
    sudo python3 http_sniffer.py -i eth0
    sudo python3 http_sniffer.py -i wlan0 --log http_capture.log
"""

import scapy.all as scapy
from scapy.layers import http
import argparse
import signal
import sys
import os
from datetime import datetime
from urllib.parse import unquote_plus

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
║          HTTP Traffic Monitor            ║
║    URL Capture & Credential Detection    ║
╚══════════════════════════════════════════╝{RESET}
"""

# ── Credential keywords (lowercase) ─────────────────────────────────────────
CRED_KEYWORDS = {
    # Authentication
    "username", "user", "userid", "user_id", "login", "log",
    "email", "e-mail", "mail",
    "password", "pass", "passwd", "pwd", "secret",
    "token", "auth", "authorization", "bearer",
    "sessionid", "session_id", "session",
    "api_key", "apikey", "api-key", "api_token", "api-token",
    "access_token", "refresh_token",
    "csrf", "csrf_token", "xsrf",
    "otp", "code", "pin", "2fa",
    # Financial
    "creditcard", "cardnumber", "cc-number", "card_number",
    "cvv", "cvc", "expiry_date", "exp_date",
    # Personal
    "dob", "birthdate", "date_of_birth",
    "ssn", "social_security", "national_id",
    "phone", "telephone", "phone_number",
}


class HTTPSniffer:
    def __init__(self, interface, log_file=None):
        self.interface = interface
        self.log_file = log_file
        self.url_count = 0
        self.cred_count = 0
        self.start_time = datetime.now()

        # Open log
        self._log_handle = None
        if self.log_file:
            try:
                self._log_handle = open(self.log_file, "a", encoding="utf-8")
                self._log_handle.write(f"\n{'='*60}\n")
                self._log_handle.write(f"HTTP Capture started at {self.start_time.isoformat()}\n")
                self._log_handle.write(f"Interface: {self.interface}\n")
                self._log_handle.write(f"{'='*60}\n\n")
                print(f"{GREEN}[+] Logging to: {self.log_file}{RESET}")
            except IOError as e:
                print(f"{RED}[!] Cannot open log file: {e}{RESET}")
                self._log_handle = None

    def _log(self, message):
        if self._log_handle:
            try:
                self._log_handle.write(message + "\n")
                self._log_handle.flush()
            except IOError:
                pass

    def _detect_credentials(self, raw_data):
        """
        Check if raw POST/query data contains credential-like fields.
        Returns list of matched keywords.
        """
        data_lower = raw_data.lower()
        return [kw for kw in CRED_KEYWORDS if kw in data_lower]

    def _format_post_data(self, raw_data):
        """URL-decode and format POST body for readability."""
        try:
            decoded = unquote_plus(raw_data)
            # Split key=value pairs
            if "=" in decoded and "&" in decoded:
                pairs = decoded.split("&")
                formatted_lines = []
                for pair in pairs:
                    if "=" in pair:
                        key, _, value = pair.partition("=")
                        formatted_lines.append(f"      {CYAN}{key}{RESET} = {YELLOW}{value}{RESET}")
                    else:
                        formatted_lines.append(f"      {pair}")
                return "\n".join(formatted_lines)
            return f"      {decoded}"
        except Exception:
            return f"      {raw_data}"

    def process_packet(self, packet):
        """Process each captured HTTP packet."""
        if not packet.haslayer(http.HTTPRequest):
            return

        try:
            request = packet[http.HTTPRequest]
            host = request.Host.decode() if request.Host else "?"
            path = request.Path.decode() if request.Path else "/"
            method = request.Method.decode() if request.Method else "?"
        except (UnicodeDecodeError, AttributeError):
            return

        url = f"http://{host}{path}"
        src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "?"
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.url_count += 1

        # Color the method
        method_colors = {"GET": BLUE, "POST": GREEN, "PUT": YELLOW, "DELETE": RED}
        method_color = method_colors.get(method, DIM)

        print(
            f"  {DIM}{timestamp}{RESET}  "
            f"{method_color}{method:<6}{RESET}  "
            f"{CYAN}{url}{RESET}  "
            f"{DIM}(from {src_ip}){RESET}"
        )
        self._log(f"{timestamp}  {method}  {url}  src={src_ip}")

        # Check for POST body / credentials
        if packet.haslayer(scapy.Raw):
            try:
                raw_data = packet[scapy.Raw].load.decode(errors="ignore")
            except Exception:
                return

            if not raw_data.strip():
                return

            matched_keywords = self._detect_credentials(raw_data)

            if matched_keywords:
                self.cred_count += 1
                print(f"\n  {RED}{BOLD}  ⚠  POSSIBLE CREDENTIALS DETECTED{RESET}")
                print(f"  {RED}  {'─' * 45}{RESET}")
                print(f"      URL     : {url}")
                print(f"      Keywords: {', '.join(matched_keywords)}")
                print(f"      Data    :")
                print(self._format_post_data(raw_data))
                print(f"  {RED}  {'─' * 45}{RESET}\n")
                self._log(f"*** CREDENTIALS: {url}  keywords={matched_keywords}  data={raw_data}")

            elif method == "POST":
                # Show POST data even without credential keywords
                print(f"    {DIM}POST data:{RESET}")
                print(self._format_post_data(raw_data))
                print()

    def print_stats(self):
        """Print summary."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{BOLD}{'─' * 55}{RESET}")
        print(f"  {BOLD}Capture Summary{RESET}")
        print(f"  {'─' * 40}")
        print(f"  Duration              : {elapsed:.1f}s")
        print(f"  HTTP requests captured: {self.url_count}")
        print(f"  Credential detections : {self.cred_count}")
        print(f"{'─' * 55}\n")

    def cleanup(self):
        if self._log_handle:
            self._log_handle.close()

    def start(self):
        """Start sniffing."""
        print(f"{YELLOW}[*] Sniffing HTTP on interface: {self.interface}{RESET}")
        print(f"{DIM}    Only captures unencrypted HTTP traffic (port 80).{RESET}")
        print(f"{DIM}    For HTTPS, use mitmproxy. Press Ctrl+C to stop.{RESET}\n")
        print(f"  {BOLD}{'TIME':<10} {'METHOD':<8} {'URL':<45} {'SOURCE'}{RESET}")
        print(f"  {'─' * 75}")

        try:
            scapy.sniff(
                iface=self.interface,
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
        description="HTTP Traffic Monitor — Capture URLs and credentials from HTTP traffic",
        epilog="Example: sudo python3 http_sniffer.py -i eth0 --log http.log",
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
        help="Save captured data to a log file",
    )
    return parser.parse_args()


def main():
    print(BANNER)

    if os.geteuid() != 0:
        print(f"{RED}[!] This script must be run as root (sudo).{RESET}")
        sys.exit(1)

    args = get_arguments()

    sniffer = HTTPSniffer(
        interface=args.interface,
        log_file=args.log_file,
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
