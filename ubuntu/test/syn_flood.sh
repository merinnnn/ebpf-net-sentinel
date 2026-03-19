#!/usr/bin/env bash

# Sends a high volume of TCP SYN packets to a target port, never completing the handshake.
# Usage: sudo bash ubuntu/test/syn_flood.sh [port] [duration_secs]
#   defaults: port=80, duration=10

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

require_tool hping3
check_ns

PORT="${1:-80}"
DURATION="${2:-10}"

echo "SYN FLOOD  (${HOST_IP}:${PORT}, ${DURATION}s)"

echo "[*] Flooding ${HOST_IP}:${PORT} with SYN packets for ${DURATION}s..."
echo "    (Ctrl+C to stop early)"
timeout "$DURATION" \
  ip netns exec "$NS" hping3 -S -p "$PORT" --faster "$HOST_IP" 2>&1 \
  | tail -5 || true

echo ""
echo "[*] Done"