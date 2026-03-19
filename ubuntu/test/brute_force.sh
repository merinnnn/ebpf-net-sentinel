#!/usr/bin/env bash

# Simulate SSH/FTP brute-force (CICIDS2017: SSH-Patator, FTP-Patator).
# Opens rapid repeated TCP connections to the target port, mimicking a credential-stuffing pattern without actually needing valid credentials.
# Usage: sudo bash ubuntu/test/brute_force.sh [mode] [count]
#   mode:  ssh (default) | ftp
#   count: number of attempts (default: 50)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

require_tool hydra
check_ns

MODE="${1:-ssh}"
COUNT="${2:-50}"

case "$MODE" in
  ssh)  PORT=22  PROTOCOL=ssh  ;;
  ftp)  PORT=21  PROTOCOL=ftp  ;;
  *)    echo "[!] Unknown mode '$MODE'. Use: ssh | ftp"; exit 1 ;;
esac

echo "BRUTE FORCE  (${PROTOCOL^^} -> ${HOST_IP}:${PORT}, ${COUNT} attempts)"

# Generate a small throwaway wordlist so hydra has something to iterate
TMPLIST=$(mktemp)
for i in $(seq 1 "$COUNT"); do
  echo "password${i}"
done > "$TMPLIST"

echo "[*] Running hydra ${PROTOCOL} brute-force from ${NS_IP} -> ${HOST_IP}:${PORT}..."
ns_exec hydra \
  -l root \
  -P "$TMPLIST" \
  -t 4 \
  -f \
  "${PROTOCOL}://${HOST_IP}" 2>&1 | grep -v "^$" || true

rm -f "$TMPLIST"

echo ""
echo "[*] Done"