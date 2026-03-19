#!/usr/bin/env bash

# Run once on the host (not inside Docker).
# Usage: sudo bash ubuntu/test/install_tools.sh

set -euo pipefail

echo "[*] Updating package lists..."
apt-get update -qq

echo "[*] Installing network tools..."
apt-get install -y \
  nmap \
  hping3 \
  hydra \
  slowhttptest \
  netcat-openbsd \
  iperf3 \
  curl \
  ethtool \
  python3

echo ""
echo "[*] Installed:"
for tool in nmap hping3 hydra slowhttptest nc iperf3 curl ethtool python3; do
  path=$(command -v "$tool" 2>/dev/null || echo "NOT FOUND")
  printf "  %-16s %s\n" "$tool" "$path"
done