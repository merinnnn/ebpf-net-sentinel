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
TCPREPLAY_LOG="$OUTDIR/tcpreplay.log"
TCPREPLAY_META="$OUTDIR/tcpreplay_meta.json"
RUN_META="$OUTDIR/run_meta.json"

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
# Resolve interface now so netmon can bind packet capture.
RESOLVED_IFACE="$IFACE"
if [[ "$RESOLVED_IFACE" == "auto" ]]; then
  RESOLVED_IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
fi
if [[ -z "$RESOLVED_IFACE" ]]; then
  echo "[!] Could not resolve IFACE. Provide an interface name explicitly." >&2
  exit 1
fi

sudo "$ROOT_DIR/ebpf_core/netmon" \
  -obj "$ROOT_DIR/ebpf_core/netmon.bpf.o" \
  -out "$EBPF_OUT" \
  -events "$EBPF_EVENTS" \
  -flush 5 \
  -mode flow \
  -pkt_iface "$RESOLVED_IFACE" \
  -disable_kprobes \
  -meta "$RUN_META" \
  -tcpreplay_meta "$TCPREPLAY_META" &
EBPF_PID=$!
echo "  netmon pid: $EBPF_PID"
sleep 2

echo "[4/4] Replay PCAP"

TCPREPLAY_START="$(date +%s)"
set +e
sudo tcpreplay --intf1 "$RESOLVED_IFACE" --mbps "$MBPS" "$PCAP" >"$TCPREPLAY_LOG" 2>&1
TCPREPLAY_RC=$?
set -e
TCPREPLAY_END="$(date +%s)"

python3 - <<PY
import json, os
meta = {
  "pcap": os.path.abspath("$PCAP"),
  "iface": "$RESOLVED_IFACE",
  "mbps": float("$MBPS"),
  "start_epoch": int("$TCPREPLAY_START"),
  "end_epoch": int("$TCPREPLAY_END"),
  "duration_s": int("$TCPREPLAY_END") - int("$TCPREPLAY_START"),
  "exit_code": int("$TCPREPLAY_RC"),
  "log": os.path.abspath("$TCPREPLAY_LOG"),
}
with open("$TCPREPLAY_META", "w") as f:
  json.dump(meta, f, indent=2)
print("[*] Wrote tcpreplay meta:", "$TCPREPLAY_META")
PY

if [[ $TCPREPLAY_RC -ne 0 ]]; then
  echo "[!] tcpreplay failed (rc=$TCPREPLAY_RC). See $TCPREPLAY_LOG" >&2
fi

# Stop netmon so it performs a final flush and writes run_meta.json (including tcpreplay info)
if [[ -n "${EBPF_PID:-}" ]]; then
  sudo kill -INT "$EBPF_PID" >/dev/null 2>&1 || true
  wait "$EBPF_PID" >/dev/null 2>&1 || true
  unset EBPF_PID
fi

echo "[*] Outputs:"
echo "  Zeek: $ZEEK_DIR/conn.csv"
echo "  eBPF: $EBPF_OUT"
echo "  Raw:  $EBPF_EVENTS"
echo "  tcpreplay: $TCPREPLAY_LOG"
echo "  run meta:  $RUN_META"
