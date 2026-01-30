#!/usr/bin/env bash
set -euo pipefail

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

NETMON_LOG="$OUTDIR/netmon.log"
NETMON_PIDFILE="$OUTDIR/netmon.pid"
TCPREPLAY_LOG="$OUTDIR/tcpreplay.log"
TCPREPLAY_META="$OUTDIR/tcpreplay_meta.json"
RUN_META="$OUTDIR/run_meta.json"

mkdir -p "$OUTDIR" "$ZEEK_RAW_DIR" "$ZEEK_DIR" "$DATASETS_DIR"

pick_default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}
iface_exists() { ip link show "$1" >/dev/null 2>&1; }

resolve_pcap() {
  local in="$1"
  if [[ -f "$in" ]]; then realpath "$in"; return 0; fi
  local candidate="$ROOT_DIR/data/cicids2017_pcap/$in"
  if [[ -f "$candidate" ]]; then realpath "$candidate"; return 0; fi
  local found
  found="$(find "$ROOT_DIR/data/cicids2017_pcap" -maxdepth 2 -type f -iname "$(basename "$in")" 2>/dev/null | head -n 2 || true)"
  local count
  count="$(printf "%s\n" "$found" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "$count" == "1" ]]; then realpath "$found"; return 0; fi
  echo "[!] PCAP not found: $in" >&2
  ls -lah "$ROOT_DIR/data/cicids2017_pcap" | head -n 30 >&2
  exit 1
}

stop_netmon() {
  local pid="$1"
  echo "[*] Stopping netmon (pid=$pid) ..."
  sudo kill -INT "$pid" >/dev/null 2>&1 || true

  # wait up to 8 seconds then escalate
  for i in {1..8}; do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "[*] netmon exited."
      return 0
    fi
    sleep 1
  done

  echo "[!] netmon did not exit after SIGINT; sending SIGTERM..." >&2
  sudo kill -TERM "$pid" >/dev/null 2>&1 || true
  sleep 2

  if kill -0 "$pid" >/dev/null 2>&1; then
    echo "[!] netmon still running; sending SIGKILL..." >&2
    sudo kill -KILL "$pid" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  echo "[*] Cleanup..."
  if [[ -n "${EBPF_PID:-}" ]]; then
    stop_netmon "$EBPF_PID" || true
    unset EBPF_PID
  fi
}
trap cleanup EXIT

PCAP="$(resolve_pcap "$PCAP_IN")"

RESOLVED_IFACE="$IFACE"
if [[ "$RESOLVED_IFACE" == "auto" || -z "$RESOLVED_IFACE" ]]; then
  RESOLVED_IFACE="$(pick_default_iface || true)"
fi
if [[ -z "${RESOLVED_IFACE:-}" || ! "$(iface_exists "$RESOLVED_IFACE" && echo ok)" ]]; then
  echo "[!] Invalid interface: '${RESOLVED_IFACE:-}'" >&2
  ip -o link show | awk -F': ' '{print "  - " $2}' >&2
  exit 1
fi

echo "[*] Inputs:"
echo "  PCAP : $PCAP"
echo "  IFACE: $RESOLVED_IFACE"
echo "  MBPS : $MBPS"
echo "  OUT  : $OUTDIR"
echo "[*] Tip: you can inspect this run folder anytime:"
echo "  RUN=$OUTDIR"

echo "[1/5] Zeek flow extraction"
pushd "$ZEEK_RAW_DIR" >/dev/null
echo "  [*] zeek -r $PCAP"
sudo zeek -r "$PCAP" >/dev/null
popd >/dev/null

echo "  [*] convert conn.log -> zeek/conn.csv"
python3 "$ROOT_DIR/ubuntu/zeek_conn_to_csv.py" \
  --in  "$ZEEK_RAW_DIR/conn.log" \
  --out "$ZEEK_DIR/conn.csv"

echo "[2/5] Build eBPF collector"
pushd "$ROOT_DIR/ebpf_core" >/dev/null
make
popd >/dev/null

echo "[3/5] Start eBPF collector (netmon)"

# Launch netmon as root, but write the *actual* netmon PID to a pidfile we control.
sudo bash -c "
  set -e
  \"$ROOT_DIR/ebpf_core/netmon\" \
    -obj \"$ROOT_DIR/ebpf_core/netmon.bpf.o\" \
    -out \"$EBPF_OUT\" \
    -events \"$EBPF_EVENTS\" \
    -flush 5 \
    -mode flow \
    -pkt_iface \"$RESOLVED_IFACE\" \
    -disable_kprobes \
    -meta \"$RUN_META\" \
    -tcpreplay_meta \"$TCPREPLAY_META\" \
    >\"$NETMON_LOG\" 2>&1 &
  echo \$! > \"$NETMON_PIDFILE\"
"

EBPF_PID="$(cat "$NETMON_PIDFILE")"
echo "  netmon pid: $EBPF_PID"
sleep 2

echo "[4/5] Replay PCAP (tcpreplay)"
TCPREPLAY_START="$(date +%s)"

# Build tcpreplay args based on supported options
TCP_ARGS=( "--intf1" "$RESOLVED_IFACE" "--mbps" "$MBPS" )

HELP="$(tcpreplay --help 2>&1 || true)"

if echo "$HELP" | grep -q -- '--fixcsum'; then
  TCP_ARGS+=( "--fixcsum" )
else
  echo "[!] tcpreplay does not support --fixcsum (old tcpreplay). Continuing without it." >&2
fi
if echo "$HELP" | grep -q -- '--mtu'; then
  TCP_ARGS+=( "--mtu" "1500" )
fi
if echo "$HELP" | grep -q -- '--mtu-trunc'; then
  TCP_ARGS+=( "--mtu-trunc" )
fi
if echo "$HELP" | grep -q -- '--stats'; then
  TCP_ARGS+=( "--stats=1" )
fi

# Show version & chosen args
echo "  [*] tcpreplay version: $(tcpreplay -V 2>&1 | grep -m1 -E 'tcpreplay \(|^tcpreplay ' || tcpreplay -V 2>&1 | tail -n 1)"
echo "  [*] tcpreplay args: ${TCP_ARGS[*]}"

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
  echo "[!] tcpreplay failed (rc=$TCPREPLAY_RC). Showing last 60 lines:" >&2
  tail -n 60 "$TCPREPLAY_LOG" >&2 || true
fi

echo "[*] Stop netmon (final flush + meta)"
if [[ -n "${EBPF_PID:-}" ]]; then
  stop_netmon "$EBPF_PID" || true
  unset EBPF_PID
fi

echo "[5/5] Build datasets"
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
echo "  RUN=$OUTDIR"
echo "  Zeek conn:    $ZEEK_DIR/conn.csv"
echo "  eBPF agg:     $EBPF_OUT"
echo "  eBPF events:  $EBPF_EVENTS"
echo "  netmon log:   $NETMON_LOG"
echo "  tcpreplay:    $TCPREPLAY_LOG"
echo "  tc meta:      $TCPREPLAY_META"
echo "  run meta:     $RUN_META"
echo "  datasets:     $DATASETS_DIR"
