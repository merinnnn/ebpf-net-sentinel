#!/usr/bin/env bash
set -euo pipefail

# workflow:
#   - outputs under data/runs/<stamp>/
#   - zeek logs: zeek_raw/
#   - zeek conn csv: zeek/conn.csv
#   - ebpf: ebpf_agg.jsonl + ebpf_events.jsonl
#   - tcpreplay log + meta JSON
#   - run meta JSON from netmon
#   - builds datasets/zeek_only.csv + datasets/zeek_ebpf.csv

PCAP_IN="${1:?Usage: run_capture.sh <pcap|pcap_filename> [iface|auto] [mbps]}"
IFACE="${2:-auto}"
MBPS="${3:-100}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%F_%H%M%S)"
OUTDIR="$ROOT_DIR/data/runs/$STAMP"

ZEEK_RAW_DIR="$OUTDIR/zeek_raw"
ZEEK_DIR="$OUTDIR/zeek"
DATASETS_DIR="$OUTDIR/datasets"

EBPF_OUT="$OUTDIR/ebpf_agg.jsonl"
EBPF_EVENTS="$OUTDIR/ebpf_events.jsonl"

TCPREPLAY_LOG="$OUTDIR/tcpreplay.log"
TCPREPLAY_META="$OUTDIR/tcpreplay_meta.json"
RUN_META="$OUTDIR/run_meta.json"

mkdir -p "$OUTDIR" "$ZEEK_RAW_DIR" "$ZEEK_DIR" "$DATASETS_DIR"

pick_default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

iface_exists() {
  ip link show "$1" >/dev/null 2>&1
}

resolve_pcap() {
  local in="$1"
  # If it's an existing file path, use it.
  if [[ -f "$in" ]]; then
    realpath "$in"
    return 0
  fi

  # If it's a filename, try inside data/cicids2017_pcap
  local candidate="$ROOT_DIR/data/cicids2017_pcap/$in"
  if [[ -f "$candidate" ]]; then
    realpath "$candidate"
    return 0
  fi

  # Try case-insensitive search by basename
  local found
  found="$(find "$ROOT_DIR/data/cicids2017_pcap" -maxdepth 2 -type f -iname "$(basename "$in")" 2>/dev/null | head -n 2 || true)"
  local count
  count="$(printf "%s\n" "$found" | sed '/^$/d' | wc -l | tr -d ' ')"

  if [[ "$count" == "1" ]]; then
    realpath "$found"
    return 0
  fi

  echo "[!] PCAP not found: $in" >&2
  echo "[*] Looked in:" >&2
  echo "    - $in" >&2
  echo "    - $ROOT_DIR/data/cicids2017_pcap/$in" >&2
  echo "[*] Available examples:" >&2
  ls -lah "$ROOT_DIR/data/cicids2017_pcap" | head -n 20 >&2
  exit 1
}

cleanup() {
  echo "[*] Cleanup..."
  if [[ -n "${EBPF_PID:-}" ]]; then
    echo "[*] Stop eBPF collector (pid=$EBPF_PID)"
    sudo kill -INT "$EBPF_PID" >/dev/null 2>&1 || true
    wait "$EBPF_PID" >/dev/null 2>&1 || true
    unset EBPF_PID
  fi
}
trap cleanup EXIT

PCAP="$(resolve_pcap "$PCAP_IN")"

# Resolve interface
RESOLVED_IFACE="$IFACE"
if [[ "$RESOLVED_IFACE" == "auto" || -z "$RESOLVED_IFACE" ]]; then
  RESOLVED_IFACE="$(pick_default_iface || true)"
fi
if [[ -z "${RESOLVED_IFACE:-}" || ! "$(iface_exists "$RESOLVED_IFACE" && echo ok)" ]]; then
  echo "[!] Invalid interface: '${RESOLVED_IFACE:-}'" >&2
  echo "[*] Available interfaces:" >&2
  ip -o link show | awk -F': ' '{print "  - " $2}' >&2
  exit 1
fi

echo "[*] Inputs:"
echo "  PCAP : $PCAP"
echo "  IFACE: $RESOLVED_IFACE"
echo "  MBPS : $MBPS"
echo "  OUT  : $OUTDIR"

echo "[1/5] Zeek flow extraction -> zeek/conn.csv"
# Run Zeek in zeek_raw (keeps logs separate)
pushd "$ZEEK_RAW_DIR" >/dev/null
echo "  [*] zeek -r $PCAP"
sudo zeek -r "$PCAP" LogAscii::use_json=T >/dev/null
popd >/dev/null

echo "  [*] convert conn.log -> zeek/conn.csv"
python3 "$ROOT_DIR/ubuntu/zeek_conn_to_csv.py" \
  --in  "$ZEEK_RAW_DIR/conn.log" \
  --out "$ZEEK_DIR/conn.csv"

echo "[2/5] Build eBPF collector (ebpf_core)"
pushd "$ROOT_DIR/ebpf_core" >/dev/null
make
popd >/dev/null

echo "[3/5] Start eBPF collector (netmon)"
sudo "$ROOT_DIR/ebpf_core/netmon" \
  -obj "$ROOT_DIR/ebpf_core/netmon.bpf.o" \
  -out "$EBPF_OUT" \
  -events "$EBPF_EVENTS" \
  -flush 2 \
  -mode flow \
  -pkt_iface "$RESOLVED_IFACE" \
  -disable_kprobes \
  -meta "$RUN_META" \
  -tcpreplay_meta "$TCPREPLAY_META" &
EBPF_PID=$!
echo "  netmon pid: $EBPF_PID"
sleep 2

echo "[4/5] Replay PCAP (tcpreplay)"
TCPREPLAY_START="$(date +%s)"

# Build tcpreplay args (add mtu truncation if supported to avoid 'Message too long')
TCP_ARGS=( "--intf1" "$RESOLVED_IFACE" "--mbps" "$MBPS" "--fixcsum" )

if tcpreplay --help 2>&1 | grep -q -- '--mtu'; then
  # Many tcpreplay builds support these; helps with jumbo frames in captures.
  TCP_ARGS+=( "--mtu" "1500" )
fi
if tcpreplay --help 2>&1 | grep -q -- '--mtu-trunc'; then
  TCP_ARGS+=( "--mtu-trunc" )
fi

set +e
sudo tcpreplay "${TCP_ARGS[@]}" "$PCAP" >"$TCPREPLAY_LOG" 2>&1
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

echo "[*] Stopping netmon (final flush + run_meta write)"
if [[ -n "${EBPF_PID:-}" ]]; then
  sudo kill -INT "$EBPF_PID" >/dev/null 2>&1 || true
  wait "$EBPF_PID" >/dev/null 2>&1 || true
  unset EBPF_PID
fi

echo "[5/5] Build datasets"
# Zeek-only + Zeek+eBPF datasets for this run directory
python3 "$ROOT_DIR/ubuntu/make_zeek_only.py" \
  --in_csv  "$ZEEK_DIR/conn.csv" \
  --out_csv "$DATASETS_DIR/zeek_only.csv"

if [[ -s "$EBPF_OUT" ]]; then
  python3 "$ROOT_DIR/ubuntu/merge_zeek_ebpf.py" \
    --zeek_conn "$ZEEK_DIR/conn.csv" \
    --ebpf_agg  "$EBPF_OUT" \
    --out       "$DATASETS_DIR/zeek_ebpf.csv" \
    --run_meta  "$RUN_META"
else
  echo "[!] No eBPF output found at $EBPF_OUT; skipping enriched dataset." >&2
fi

echo "[*] Outputs:"
echo "  Run dir:     $OUTDIR"
echo "  Zeek conn:   $ZEEK_DIR/conn.csv"
echo "  eBPF agg:    $EBPF_OUT"
echo "  eBPF events: $EBPF_EVENTS"
echo "  tcpreplay:   $TCPREPLAY_LOG"
echo "  tc meta:     $TCPREPLAY_META"
echo "  run meta:    $RUN_META"
echo "  datasets:    $DATASETS_DIR"
