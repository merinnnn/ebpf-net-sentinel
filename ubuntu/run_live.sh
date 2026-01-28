#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:?Usage: run_live.sh <iface>}"
DUR_SEC="${2:-60}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="$ROOT_DIR/data/live_run"
ZEEK_DIR="$OUTDIR/zeek"
EBPF_OUT="$OUTDIR/ebpf_agg.jsonl"

mkdir -p "$OUTDIR" "$ZEEK_DIR"

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "[!] Interface not found: $IFACE"
  ip -o link show | awk -F': ' '{print "  - "$2}'
  exit 1
fi

NETMON_PID=""
ZEEK_PID=""

cleanup() {
  echo "[*] Cleanup..."
  if [[ -n "${ZEEK_PID}" ]]; then
    sudo kill -INT "${ZEEK_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${NETMON_PID}" ]]; then
    sudo kill -INT "${NETMON_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

echo "[1/3] Build eBPF collector"
pushd "$ROOT_DIR/ebpf_core" >/dev/null
make
popd >/dev/null

echo "[2/3] Start Zeek live on iface=$IFACE (duration=${DUR_SEC}s)"
pushd "$ZEEK_DIR" >/dev/null
sudo zeek -i "$IFACE" LogAscii::use_json=T >/dev/null 2>&1 &
ZEEK_PID="$!"
popd >/dev/null
echo "  zeek pid: $ZEEK_PID"

echo "[3/3] Start eBPF collector"
NETMON_PID="$(sudo bash -c "
  \"$ROOT_DIR/ebpf_core/netmon\" -obj \"$ROOT_DIR/ebpf_core/netmon.bpf.o\" -out \"$EBPF_OUT\" -flush 5 >/dev/null 2>&1 &
  echo \$!
")"
echo "  netmon pid: $NETMON_PID"

echo "[*] Capturing for ${DUR_SEC}s..."
sleep "$DUR_SEC"

echo "[*] Done. You can now convert Zeek conn.log -> conn.csv by running:"
echo "    bash ubuntu/zeek_extract.sh <pcap> <outdir>   (pcap mode)"
echo "Live mode writes conn.log in: $ZEEK_DIR"
echo "eBPF JSONL written in: $EBPF_OUT"
