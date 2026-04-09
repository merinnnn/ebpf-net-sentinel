#!/usr/bin/env bash

# Produces BENIGN flows via TCP probes on closed ports (RST/REJ state, zero bytes).
# Ports >80 with no listener score reliably BENIGN with the CICIDS2017 RF model.
# Usage: sudo bash ubuntu/test/benign.sh [start_port] [end_port] [interval_secs]
#   defaults: start_port=81, end_port=500, interval_secs=0.1

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

check_ns

START_PORT="${1:-81}"
END_PORT="${2:-500}"
INTERVAL="${3:-0.1}"

COUNT=$(( END_PORT - START_PORT + 1 ))
echo "BENIGN TRAFFIC  (ports ${START_PORT}-${END_PORT}, ${COUNT} probes, ${INTERVAL}s apart)"

# Probe closed ports. RST reply, zero bytes, short duration -> BENIGN score
echo "[*] TCP probes on ports ${START_PORT}-${END_PORT} (no listener)..."
for PORT in $(seq "$START_PORT" "$END_PORT"); do
  ns_exec nc -w1 -z "$HOST_IP" "$PORT" 2>/dev/null || true
  sleep "$INTERVAL"
done

echo ""
echo "[*] Done. Expect ~${COUNT} BENIGN flows in the webapp."