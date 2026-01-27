#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:?Usage: replay_pcap.sh <pcap_file> [iface] [mbps]}"
IFACE="${2:-eth0}"
MBPS="${3:-100}"

pick_default_iface() {
  ip route show default 0.0.0.0/0 2>/dev/null | awk '{print $5; exit}'
}

iface_exists() {
  ip link show "$1" >/dev/null 2>&1
}

if ! iface_exists "$IFACE"; then
  DEF="$(pick_default_iface)"
  if [[ -n "${DEF}" ]] && iface_exists "$DEF"; then
    echo "[!] Interface '$IFACE' not found. Using default route iface: '$DEF'"
    IFACE="$DEF"
  else
    echo "[!] Interface '$IFACE' not found and no default iface detected."
    echo "    Available interfaces:"
    ip -o link show | awk -F': ' '{print "     - "$2}'
    exit 1
  fi
fi

echo "[*] Replaying pcap file '$PCAP' on interface '$IFACE' at $MBPS Mbps"
sudo tcpreplay --intf1="$IFACE" --mbps="$MBPS" --preload-pcap --stats=5 "$PCAP"
echo "[*] Replay finished."
