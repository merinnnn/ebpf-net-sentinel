#!/usr/bin/env bash
set -euo pipefail

# Create a veth pair for local PCAP replay testing.
#
# Usage:
#   sudo bash ubuntu/setup_veth.sh [veth_a] [veth_b] [mtu]
#
# Example:
#   sudo bash ubuntu/setup_veth.sh veth0 veth1 9000

A="${1:-veth0}"
B="${2:-veth1}"
MTU="${3:-}"

if ip link show "$A" >/dev/null 2>&1 || ip link show "$B" >/dev/null 2>&1; then
  echo "[!] $A or $B already exists. Delete them first if you want a clean recreate:"
  echo "    sudo ip link del $A  # (deleting one end deletes the pair)"
  exit 1
fi

ip link add "$A" type veth peer name "$B"

if [[ -n "$MTU" ]]; then
  ip link set dev "$A" mtu "$MTU" || true
  ip link set dev "$B" mtu "$MTU" || true
fi

ip link set "$A" up
ip link set "$B" up

echo "[*] Created and brought up: $A <-> $B"
ip -s link show "$A" || true
ip -s link show "$B" || true
