#!/usr/bin/env bash

# Runs a SYN scan over a port range from inside ns-research.
# Usage: sudo bash ubuntu/test/portscan.sh [port-range]
#   port-range default: 1-1000
#   full scan:          1-65535  (takes ~30s with -T4)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

require_tool nmap
check_ns

PORT_RANGE="${1:-1-80}"

echo "PORT SCAN  (range: ${PORT_RANGE})"

echo "[*] Running SYN scan from ${NS_IP} -> ${HOST_IP}:${PORT_RANGE}..."
ns_exec nmap -sS -T4 -p "$PORT_RANGE" --open "$HOST_IP"

echo ""
echo "[*] Done"