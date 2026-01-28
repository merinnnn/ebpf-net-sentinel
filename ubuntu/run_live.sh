#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:?Usage: run_live.sh <iface|auto> [duration_sec]}"
DUR_SEC="${2:-60}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUTDIR="$ROOT_DIR/data/live_run/$STAMP"
ZEEK_DIR="$OUTDIR/zeek"
EBPF_OUT="$OUTDIR/ebpf_agg.jsonl"
EBPF_EVENTS="$OUTDIR/ebpf_events.jsonl"

mkdir -p "$OUTDIR" "$ZEEK_DIR"

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
  exit 1
fi

cleanup() {
  echo "[*] Cleanup..."
  if [[ -n "${EBPF_PID:-}" ]]; then
    echo "[*] Stop eBPF collector (pid=$EBPF_PID)"
    sudo kill -INT "$EBPF_PID" >/dev/null 2>&1 || true
    wait "$EBPF_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${ZEEK_PID:-}" ]]; then
    echo "[*] Stop Zeek (pid=$ZEEK_PID)"
    sudo kill -INT "$ZEEK_PID" >/dev/null 2>&1 || true
    wait "$ZEEK_PID" >/dev/null 2>&1 || true
  fi

  if [[ -f "$ZEEK_DIR/conn.log" ]]; then
    echo "[*] Converting Zeek conn.log to conn.csv"
    python3 "$ROOT_DIR/ubuntu/zeek_conn_to_csv.py" --in "$ZEEK_DIR/conn.log" --out "$ZEEK_DIR/conn.csv" || true
  fi
}
trap cleanup EXIT

echo "[*] Live capture:"
echo "  IFACE: $IFACE"
echo "  DUR  : $DUR_SEC sec"
echo "  OUT  : $OUTDIR"

echo "[1/2] Start Zeek on interface"
pushd "$ZEEK_DIR" >/dev/null
sudo zeek -i "$IFACE" LogAscii::use_json=T > /dev/null &
ZEEK_PID=$!
popd >/dev/null
echo "  zeek pid: $ZEEK_PID"
sleep 1

echo "[2/2] Start eBPF collector"
pushd "$ROOT_DIR/ebpf_core" >/dev/null
make
sudo ./netmon -obj ./netmon.bpf.o -out "$EBPF_OUT" -events "$EBPF_EVENTS" -flush 5 -mode both &
EBPF_PID=$!
popd >/dev/null
echo "  netmon pid: $EBPF_PID"

sleep "$DUR_SEC"

echo "[*] Outputs:"
echo "  Zeek: $ZEEK_DIR/conn.csv"
echo "  eBPF: $EBPF_OUT"
echo "  Raw:  $EBPF_EVENTS"
