#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:?Usage: run_capture.sh <pcap> [iface] [mbps]}"
IFACE="${2:-eth0}"
MBPS="${3:-100}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="$ROOT_DIR/data/enriched_run"
ZEEK_DIR="$OUTDIR/zeek"
EBPF_OUT="$OUTDIR/ebpf_agg.jsonl"

mkdir -p "$OUTDIR" "$ZEEK_DIR"

echo "[1/4] Zeek flow extraction"
bash "$ROOT_DIR/ubuntu/zeek_extract.sh" "$PCAP" "$ZEEK_DIR"

echo "[2/4] Build eBPF collector"
pushd "$ROOT_DIR/ebpf_core" >/dev/null
make
popd >/dev/null

echo "[3/4] Start eBPF collector"
sudo "$ROOT_DIR/ebpf_core/netmon" -obj "$ROOT_DIR/ebpf_core/netmon.bpf.o" -out "$EBPF_OUT" -flush 5 &
EBPF_PID=$!
sleep 2

echo "[4/4] Replay PCAP"
bash "$ROOT_DIR/ubuntu/replay_pcap.sh" "$PCAP" "$IFACE" "$MBPS" || true

echo "[*] Stop eBPF collector"
sudo kill -INT "$EBPF_PID" || true
sleep 2

echo "[*] Outputs:"
echo "  Zeek: $ZEEK_DIR/conn.csv"
echo "  eBPF: $EBPF_OUT"
