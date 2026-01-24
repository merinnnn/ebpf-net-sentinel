#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:?Usage: replay_pcap.sh <pcap_file> [iface] [mbps]}"
IFACE="${2:-eth0}"
MBPS="${3:-100}"

echo "[*] Replaying pcap file '$PCAP' on interface '$IFACE' at $MBPS Mbps"
sudo tcpreplay --intf1="$IFACE" --mbps="$MBPS" --preload-pcap --stats=5 "$PCAP"
echo "[*] Replay finished."
