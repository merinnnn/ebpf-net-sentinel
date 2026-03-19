#!/usr/bin/env bash

# Produces BENIGN flows: HTTP, ICMP ping, TCP bulk transfer.
# Usage: sudo bash ubuntu/test/benign.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

check_ns

echo "BENIGN TRAFFIC"

echo "[*] ICMP ping (5 packets)..."
ns_exec ping -c5 -i0.2 "$HOST_IP"

echo ""
echo "[*] HTTP requests (10 GETs)..."
python3 -m http.server 8080 &>/dev/null &
SERVER_PID=$!
sleep 0.5
for i in $(seq 1 10); do
  ns_exec curl -s "http://${HOST_IP}:8080/" -o /dev/null
  sleep 0.1
done
kill "$SERVER_PID" 2>/dev/null || true

echo ""
echo "[*] TCP bulk transfer via iperf3 (5 seconds)..."
iperf3 -s -p 15201 -1 &>/dev/null &
IPERF_PID=$!
sleep 0.3
ns_exec iperf3 -c "$HOST_IP" -p 15201 -t 5 -i 0 -b 50M 2>/dev/null \
  | tail -3 || true
wait "$IPERF_PID" 2>/dev/null || true

echo ""
echo "[*] Done. Expect ~10+ BENIGN flows in the webapp."