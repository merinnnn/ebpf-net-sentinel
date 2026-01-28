#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:?Usage: run_capture.sh <pcap> [iface|auto] [mbps]}"
IFACE="${2:-auto}"
MBPS="${3:-100}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUTDIR="$ROOT_DIR/data/enriched_run/$STAMP"
ZEEK_DIR="$OUTDIR/zeek"
EBPF_OUT="$OUTDIR/ebpf_agg.jsonl"
EBPF_EVENTS="$OUTDIR/ebpf_events.jsonl"

mkdir -p "$OUTDIR" "$ZEEK_DIR"

echo "[*] Inputs:"
echo "  PCAP : $PCAP"
echo "  IFACE: $IFACE"
echo "  MBPS : $MBPS"
echo "  OUT  : $OUTDIR"

cleanup() {
  echo "[*] Cleanup..."
  if [[ -n "${EBPF_PID:-}" ]]; then
    echo "[*] Stop eBPF collector (pid=$EBPF_PID)"
    sudo kill -INT "$EBPF_PID" >/dev/null 2>&1 || true
    wait "$EBPF_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[1/4] Zeek flow extraction"
bash "$ROOT_DIR/ubuntu/zeek_extract.sh" "$PCAP" "$ZEEK_DIR"

echo "[2/4] Build eBPF collector"
pushd "$ROOT_DIR/ebpf_core" >/dev/null
make
popd >/dev/null

echo "[3/4] Start eBPF collector"
sudo "$ROOT_DIR/ebpf_core/netmon" \
  -obj "$ROOT_DIR/ebpf_core/netmon.bpf.o" \
  -out "$EBPF_OUT" \
  -events "$EBPF_EVENTS" \
  -flush 5 \
  -mode both &
EBPF_PID=$!
echo "  netmon pid: $EBPF_PID"
sleep 2

echo "[4/4] Replay PCAP"
if ! bash "$ROOT_DIR/ubuntu/replay_pcap.sh" "$PCAP" "$IFACE" "$MBPS"; then
  echo "[!] Replay failed (still keeping Zeek + eBPF outputs)."
fi

echo "[*] Outputs:"
echo "  Zeek: $ZEEK_DIR/conn.csv"
echo "  eBPF: $EBPF_OUT"
echo "  Raw:  $EBPF_EVENTS"
