<div align="center">

# 🕸️ MITM Toolkit v2.0

**A modular penetration testing lab for ARP poisoning, traffic analysis, and passive device intelligence.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-2C2D72?style=for-the-badge)](https://scapy.net)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Español](https://img.shields.io/badge/Leer_en-Español-ef4444?style=for-the-badge)](README-Español.md)

</div>

---

## 💡 What Is This?

This toolkit simulates the **full lifecycle of a Man-in-the-Middle engagement** inside a controlled lab environment: network reconnaissance, traffic redirection via ARP poisoning, passive monitoring of DNS/HTTP flows, optional HTTPS decryption through a proxy, and — new in v2.0 — **passive device intelligence profiling** that builds behavioural fingerprints of every host on the wire.

Every tool is self-contained, richly configurable via CLI flags, runs on Kali/Debian-based distros, and is designed to be chained together.

---

## 🆕 What's new in v2.0

| Tool | Highlights |
|------|-----------|
| **`arpScan.py`** | MAC vendor lookup · hostname resolution · gateway auto-detect · continuous watch mode |
| **`http_sniffer.py`** | Per-IP session tracking · cookie & User-Agent capture · JSON body parsing · brute-force detection · multi-port monitoring · JSON export |
| **`dns_sniffer.py`** | Response IP capture · suspicious domain heuristics (entropy/DGA) · domain categorisation · NXDOMAIN tracking · domain alerting · DNS-over-TCP · JSON map export |
| **`AllNetwork_Spoof.sh`** | Target file input · activity logging · gateway validation · duration auto-stop · live status display · session summary |
| **`net_profiler.py`** 🧠 | **NEW** · Passive OS fingerprinting · device classification · activity heatmaps · traffic accounting · connection graph · live ASCII dashboard |

---

## 🧰 Toolkit at a Glance

```
mitm-toolkit/
├── arpScan.py              # Network recon — ARP discovery + vendor + watch
├── AllNetwork_Spoof.sh     # ARP poisoning of an entire subnet
├── dns_sniffer.py          # DNS monitor with suspicious-domain detection
├── http_sniffer.py         # HTTP capture + session tracking + brute detect
├── net_profiler.py         # 🧠 Passive device intelligence profiler (NEW)
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

# 2. Discover hosts + vendors (watch mode alerts on new devices)
sudo python3 arpScan.py -t 192.168.1.0/24 --resolve --watch

# 3. Poison the whole subnet (terminal 1) with logging & auto-stop
sudo bash AllNetwork_Spoof.sh --log session.log --duration 600

# 4. Sniff DNS + flag suspicious domains (terminal 2)
sudo python3 dns_sniffer.py -i eth0 --export dns_map.json

# 5. Sniff HTTP + track sessions (terminal 3)
sudo python3 http_sniffer.py -i eth0 --ports 80,8080,8000 --export sessions.json

# 6. 🧠 Build device intelligence profiles (terminal 4)
sudo python3 net_profiler.py -i eth0 --dashboard --export intel.json
```

---

## 📡 arpScan.py — Network Reconnaissance

Sends ARP who-has requests across a subnet and collects replies. Now with **MAC vendor lookup** from a built-in OUI database (~120 vendors: Apple, Cisco, Samsung, TP-Link, Netgear, Intel, VMware, Raspberry Pi, Ubiquiti, …), optional **hostname resolution**, **default gateway detection** (highlighted `[GW]` in the table), and a **continuous watch mode** that alerts on new/disappeared hosts.

```bash
sudo python3 arpScan.py -t 10.0.0.0/24 -i wlan0 --resolve -v
sudo python3 arpScan.py -t 192.168.1.0/24 --watch --interval 30
sudo python3 arpScan.py -t 192.168.1.0/24 -o scan_results.json
```

| Option | What it does | Default |
|--------|--------------|---------|
| `-t`  | Target IP or CIDR | *required* |
| `-i`  | Interface | auto |
| `--timeout` | Wait time for replies (s) | `2` |
| `-o`  | Export file (`.csv` / `.json`) | — |
| `--resolve` | Reverse-DNS lookup per host | off |
| `--watch` | Keep scanning; alert on changes | off |
| `--interval` | Seconds between watch scans | `30` |
| `-v`  | Verbose output | off |

Sample output:

```
#    IP Address       MAC Address        Vendor      Hostname
─────────────────────────────────────────────────────────────
1    192.168.1.1      ac:84:c6:xx:xx:xx  TP-Link [GW]  router.lan
2    192.168.1.42     3c:15:c2:xx:xx:xx  Apple       macbook.lan
3    192.168.1.55     b8:27:eb:xx:xx:xx  Raspberry Pi
```

---

## 🔀 AllNetwork_Spoof.sh — ARP Cache Poisoning

Launches parallel `arpspoof` instances for every IP in range *or* from a supplied target file. New in v2.0: **gateway ping validation**, **activity logging**, **duration auto-stop**, **live status line** with elapsed time + active-process counter, and a **session summary** on exit.

```bash
sudo bash AllNetwork_Spoof.sh                                         # defaults
sudo bash AllNetwork_Spoof.sh -i eth0 -s 10.0.0 -g 10.0.0.1 -j 40     # custom subnet
sudo bash AllNetwork_Spoof.sh --targets-file targets.txt --log run.log
sudo bash AllNetwork_Spoof.sh --duration 600                          # auto-stop
```

| Option | What it does | Default |
|--------|--------------|---------|
| `-i`  | Interface | `ens33` |
| `-s`  | Subnet base (3 octets) | `192.168.1` |
| `-g`  | Gateway address | `{subnet}.1` |
| `--start / --end` | Host range | `1–254` |
| `-j`  | Max parallel processes | `50` |
| `--targets-file` | Attack specific IPs from file | — |
| `--log` | Timestamped activity log | — |
| `--duration` | Auto-stop after N seconds | `0` (unlimited) |
| `--no-validate` | Skip gateway ping validation | off |

Before spraying ARP replies, the script verifies the interface exists, pings the gateway, auto-enables IP forwarding, skips the gateway IP, and kills every child process plus pre-existing `arpspoof -i <iface>` processes on `Ctrl+C`.

---

## 🔎 dns_sniffer.py — DNS Traffic Monitor

Listens on both **UDP and TCP port 53**. New in v2.0:

- Captures **DNS responses** (not just queries) and builds a `domain → [resolved IPs]` map
- **Suspicious-domain detection**: Shannon entropy on the subdomain label, unusual TLDs (`.tk`, `.ml`, `.xyz`, …), consonant-cluster heuristics, and length checks → flags possible DGA/phishing
- **Domain categorisation**: social, streaming, banking, gaming, ads, tracking, CDN
- **NXDOMAIN tracking** for unique failed resolutions
- **Domain alerting** (`--alert bank.com`) with a loud visual banner
- **Per-source-IP query rate** in the summary

```bash
sudo python3 dns_sniffer.py -i eth0
sudo python3 dns_sniffer.py -i eth0 --log captures/dns.log --exclude tiktok instagram
sudo python3 dns_sniffer.py --alert paypal.com bank.com --export dns_map.json
sudo python3 dns_sniffer.py --no-filter     # raw, unfiltered view
```

| Option | What it does | Default |
|--------|--------------|---------|
| `-i`  | Interface | auto |
| `--log` | Write to file | — |
| `--export` | Write `domain→IPs` JSON on exit | — |
| `--no-filter` | Disable noise filter | off |
| `--exclude` | Extra blocked keywords | — |
| `--alert` | Domains to alert on when queried | — |

---

## 🌐 http_sniffer.py — HTTP Traffic & Credential Capture

Intercepts unencrypted HTTP requests on configurable ports and inspects bodies for sensitive fields (passwords, tokens, API keys, credit cards, PII). v2.0 adds:

- **Per-IP session tracking** — request count, cookies, User-Agent, methods breakdown
- **Cookie extraction** from `Cookie:` headers
- **User-Agent parsing and display**
- **JSON body auto-detection and pretty-printing** (in addition to URL-encoded)
- **Brute-force detection**: ≥5 POSTs to the same URL in 10 seconds from the same IP raises a ⚡ alert
- **Configurable ports** instead of just `80` (default: `80,8080,8000,8888`)
- **Source IP filter** to isolate one victim
- **JSON session export**

```bash
sudo python3 http_sniffer.py -i eth0
sudo python3 http_sniffer.py -i eth0 --ports 80,8080,8000 --log http.log
sudo python3 http_sniffer.py -i eth0 --filter-ip 192.168.1.42 --export sessions.json
```

| Option | What it does | Default |
|--------|--------------|---------|
| `-i`  | Interface | auto |
| `--ports` | Comma-separated ports | `80,8080,8000,8888` |
| `--filter-ip` | Only capture traffic from this IP | — |
| `--log` | Write to file | — |
| `--export` | Export per-IP sessions to JSON | — |

---

## 🧠 net_profiler.py — Passive Device Intelligence Profiler (NEW)

The thing **no other open-source MITM toolkit ships**: a **100 % passive** profiler that, while the rest of the tools are actively working, builds a complete intelligence picture of every device on the wire — without sending a single packet.

What it infers:

| Feature | How |
|---------|-----|
| **Passive OS fingerprint** | Initial TTL analysis (64 → Linux/macOS/Unix, 128 → Windows, 255 → router) |
| **Device classification** | IoT / Mobile / Desktop / Server / Router, based on ports + DNS + UA + OS guess |
| **Service enumeration** | 80+ ports → named services (SSH, MQTT, Redis, RDP, mDNS, Plex…) |
| **Application inference** | DNS domains + HTTP `User-Agent` heuristics |
| **Traffic accounting** | Bytes & packets sent/received per device |
| **Connection graph** | Peer list — who talks to whom |
| **Activity heatmap** | 24-column ▁▂▃▄▅▆▇█ bar showing when each device is active |
| **DHCP hostname harvesting** | Extracts `hostname` option from DHCP traffic |

```bash
sudo python3 net_profiler.py                                       # auto interface, plain summary on exit
sudo python3 net_profiler.py -i eth0 --dashboard                   # live refreshing dashboard
sudo python3 net_profiler.py -i eth0 --subnet 192.168.1.0/24 \
                                     --dashboard --export intel.json
```

| Option | What it does | Default |
|--------|--------------|---------|
| `-i`  | Interface | auto |
| `--subnet` | Limit profiling to CIDR (ignore out-of-scope hosts) | — |
| `--dashboard` | Live auto-refreshing ASCII dashboard | off |
| `--refresh` | Dashboard refresh interval (s) | `5` |
| `--export` | Write full JSON intelligence report on exit | — |

Sample dashboard row:

```
IP               MAC                OS                     Class        Tx        Rx   Activity (00-23)
──────────────────────────────────────────────────────────────────────────────────────────────────────
192.168.1.42     3c:15:c2:xx:xx:xx  Linux/macOS/Unix       Desktop    4.2MB   18.7MB   ▁▂▃▄▅▆▇█▆▅▄▃▂▁▁▂▃▄▅▆▇█▇▆
192.168.1.87     b8:27:eb:xx:xx:xx  Linux/macOS/Unix       IoT        185KB   512KB    ▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂
192.168.1.1      ac:84:c6:xx:xx:xx  Network device/Router  Router     42MB    40MB     ▅▅▆▆▇▇██▇▇▆▆▅▅▆▆▇▇██▇▇▆▅
```

---

## 🔒 HTTPS Decryption via mitmproxy

Intercepting TLS-encrypted traffic requires installing a trusted CA certificate on the target. The workflow uses [mitmproxy](https://mitmproxy.org):

**On the attacker:**

```bash
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

## 🔁 Recommended Attack Workflow

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. arpScan.py --watch            → find + track hosts            │
│ 2. AllNetwork_Spoof.sh --log     → redirect traffic              │
│ 3. dns_sniffer.py --export       → map domains ↔ IPs             │
│ 4. http_sniffer.py --export      → capture creds + sessions      │
│ 5. net_profiler.py --dashboard   → 🧠 passive intelligence        │
│ 6. mitmproxy (optional)          → decrypt HTTPS                 │
└──────────────────────────────────────────────────────────────────┘
```

Each tool writes its own JSON report, so a complete engagement produces a **composable, analysable dataset** (hosts, sessions, DNS map, intelligence profiles) that can be diffed across runs.

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
