#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:?Usage: replay_pcap.sh <pcap_file> [iface|auto] [mbps]}"
IFACE="${2:-auto}"
MBPS="${3:-100}"

pick_default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}

iface_exists() {
  ip link show "$1" >/dev/null 2>&1
}

if [[ "$IFACE" == "auto" || -z "$IFACE" ]]; then
  IFACE="$(pick_default_iface || true)"
fi

if [[ -z "${IFACE:-}" || ! "$(iface_exists "$IFACE" && echo ok)" ]]; then
  echo "[!] Invalid interface: '${IFACE:-}'" >&2
  echo "[*] Available interfaces:" >&2
  ip -o link show | awk -F': ' '{print "  - " $2}' >&2
  echo "[*] Tip: use 'auto' or pass a real interface name (e.g., ens18/enp0s3)." >&2
  exit 1
fi

if [[ ! -f "$PCAP" ]]; then
  echo "[!] PCAP not found: $PCAP" >&2
  exit 1
fi

echo "[*] Replaying pcap file '$PCAP' on interface '$IFACE' at $MBPS Mbps"
sudo tcpreplay --intf1="$IFACE" --mbps="$MBPS" "$PCAP"
echo "[*] Replay finished."
