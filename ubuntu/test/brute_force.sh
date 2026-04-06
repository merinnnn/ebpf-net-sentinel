#!/usr/bin/env bash

# Simulate SSH/FTP brute-force (CICIDS2017: SSH-Patator, FTP-Patator).
# Opens rapid repeated TCP connections to the target port, mimicking a credential-stuffing pattern without actually needing valid credentials.
# Usage: sudo bash ubuntu/test/brute_force.sh [mode] [count]
#   mode:  ssh (default) | ftp
#   count: number of attempts (default: 50)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

require_tool nc
check_ns

MODE="${1:-ssh}"
COUNT="${2:-50}"

case "$MODE" in
  ssh)  PORT=22 ;;
  ftp)  PORT=21 ;;
  *)    echo "[!] Unknown mode '$MODE'. Use: ssh | ftp"; exit 1 ;;
esac

echo "BRUTE FORCE  (${MODE^^} -> ${HOST_IP}:${PORT}, ${COUNT} attempts)"

echo "[*] Simulating brute-force: ${COUNT} rapid TCP connections from ${NS_IP} -> ${HOST_IP}:${PORT}..."
for i in $(seq 1 "$COUNT"); do
  ns_exec nc -w1 -z "$HOST_IP" "$PORT" 2>/dev/null || true
done
echo "    ${COUNT} connection attempts sent."

echo ""
echo "[*] Done"