#!/usr/bin/env bash
set -euo pipefail

# Capture pipeline for a single PCAP:
#   1) Run Zeek over the PCAP and produce zeek/conn.csv
#   2) Start the eBPF collector (netmon)
#   3) Replay the PCAP with tcpreplay into a chosen interface
#   4) Stop netmon and leave all artifacts in data/runs/<timestamp>/
#
# Usage:
#   bash ubuntu/run_capture.sh <pcap_name_or_path> <IFACE_CAPTURE> <MBPS>
#
# Optional env:
#   REPLAY_IFACE=<iface>     # where tcpreplay sends packets (default: IFACE_CAPTURE)
#   FLUSH_SECS=5             # netmon flush period seconds (default: 5)
#   DISABLE_KPROBES=1        # default: 1 (use tracepoints only)
#   MODE=flow                # flow|events|both (default: flow)
#   SET_MTU=9000             # optional: set MTU for IFACE_CAPTURE and REPLAY_IFACE before replay

PCAP_IN="${1:-}"
IFACE_CAPTURE="${2:-}"
MBPS="${3:-}"

if [[ -z "$PCAP_IN" || -z "$IFACE_CAPTURE" || -z "$MBPS" ]]; then
  echo "Usage: bash ubuntu/run_capture.sh <pcap> <iface_capture> <mbps>"
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/data"
PCAP_DIR="$DATA_DIR/cicids2017_pcap"

if [[ -f "$PCAP_IN" ]]; then
  PCAP_PATH="$(cd "$(dirname "$PCAP_IN")" && pwd)/$(basename "$PCAP_IN")"
else
  PCAP_PATH="$PCAP_DIR/$PCAP_IN"
fi

if [[ ! -f "$PCAP_PATH" ]]; then
  echo "[x] PCAP not found: $PCAP_PATH"
  exit 1
fi

REPLAY_IFACE="${REPLAY_IFACE:-$IFACE_CAPTURE}"
FLUSH_SECS="${FLUSH_SECS:-5}"
MODE="${MODE:-flow}"
DISABLE_KPROBES="${DISABLE_KPROBES:-1}"
SET_MTU="${SET_MTU:-}"

RUN_TS="$(date +%F_%H%M%S)"
RUN_DIR="$DATA_DIR/runs/$RUN_TS"
mkdir -p "$RUN_DIR"/{zeek,logs}

DEBUG_LOG="$RUN_DIR/run_capture.debug.log"
NETMON_LOG="$RUN_DIR/netmon.log"
NETMON_PIDFILE="$RUN_DIR/netmon.pid"
EBPF_AGG="$RUN_DIR/ebpf_agg.jsonl"
EBPF_EVENTS="$RUN_DIR/ebpf_events.jsonl"
RUN_META="$RUN_DIR/run_meta.json"
TCPREPLAY_META="$RUN_DIR/tcpreplay_meta.json"

exec > >(tee -a "$DEBUG_LOG") 2>&1

echo "[*] Inputs:"
echo "  PCAP : $PCAP_PATH"
echo "  IFACE: $IFACE_CAPTURE"
echo "  MBPS : $MBPS"
echo "  OUT  : $RUN_DIR"
echo "  REPLAY_IFACE: $REPLAY_IFACE"
echo ""
echo "[*] Debug log: $DEBUG_LOG"
echo "[*] Tip: you can inspect this run folder anytime:"
echo "  RUN=$RUN_DIR"
echo ""

NETMON_PID=""

write_fallback_meta() {
  if [[ ! -f "$RUN_META" ]]; then
    cat >"$RUN_META" <<EOF
{
  "pcap":"$PCAP_PATH",
  "iface_capture":"$IFACE_CAPTURE",
  "replay_iface":"$REPLAY_IFACE",
  "mbps":$MBPS,
  "run_dir":"$RUN_DIR",
  "timestamp":"$RUN_TS",
  "note":"fallback meta written by run_capture.sh"
}
EOF
  fi
}

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "[!] Cleanup handler fired (rc=$rc)"
  fi

  if [[ -n "${NETMON_PID:-}" ]]; then
    if sudo kill -0 "$NETMON_PID" 2>/dev/null; then
      echo "[*] Stopping netmon (pid=$NETMON_PID) ..."
      sudo kill -INT "$NETMON_PID" 2>/dev/null || true
      for _ in {1..40}; do
        if ! sudo kill -0 "$NETMON_PID" 2>/dev/null; then break; fi
        sleep 0.25
      done
      if sudo kill -0 "$NETMON_PID" 2>/dev/null; then
        sudo kill -TERM "$NETMON_PID" 2>/dev/null || true
        sleep 0.5
      fi
      if sudo kill -0 "$NETMON_PID" 2>/dev/null; then
        sudo kill -KILL "$NETMON_PID" 2>/dev/null || true
      fi
    fi
  fi

  write_fallback_meta

  # netmon writes as root; make the run dir readable/editable by the user.
  sudo chown -R "$(id -u):$(id -g)" "$RUN_DIR" 2>/dev/null || true

  exit $rc
}
trap cleanup EXIT INT TERM

# Create meta EARLY so it's never missing even if netmon fails
cat >"$RUN_META" <<EOF
{
  "pcap":"$PCAP_PATH",
  "iface_capture":"$IFACE_CAPTURE",
  "replay_iface":"$REPLAY_IFACE",
  "mbps":$MBPS,
  "run_dir":"$RUN_DIR",
  "timestamp":"$RUN_TS"
}
EOF

echo "[*] [1/5] Zeek flow extraction"
ZEEK_LOG="$RUN_DIR/zeek.log"
ZEEK_OUT_DIR="$RUN_DIR/zeek"
mkdir -p "$ZEEK_OUT_DIR"

echo "  [*] zeek -r $PCAP_PATH (logging -> $ZEEK_LOG)"
(
  cd "$ZEEK_OUT_DIR"
  zeek -r "$PCAP_PATH" >"$ZEEK_LOG" 2>&1
)

if [[ ! -f "$ZEEK_OUT_DIR/conn.log" ]]; then
  echo "[x] Zeek did not produce conn.log at $ZEEK_OUT_DIR/conn.log"
  echo "    Last 80 lines of zeek.log:"
  tail -n 80 "$ZEEK_LOG" || true
  exit 1
fi

python3 "$ROOT_DIR/ubuntu/zeek_conn_to_csv.py" "$ZEEK_OUT_DIR/conn.log" "$ZEEK_OUT_DIR/conn.csv"
echo "[*] Wrote $ZEEK_OUT_DIR/conn.csv"

echo "[*] [2/5] Build eBPF collector"
make -C "$ROOT_DIR/ebpf_core"

# Optional MTU bump (helps tcpreplay "Message too long" on veth)
if [[ -n "$SET_MTU" ]]; then
  echo "[*] Setting MTU=$SET_MTU on $REPLAY_IFACE and $IFACE_CAPTURE (best-effort)"
  sudo ip link set dev "$REPLAY_IFACE" mtu "$SET_MTU" 2>/dev/null || true
  sudo ip link set dev "$IFACE_CAPTURE" mtu "$SET_MTU" 2>/dev/null || true
fi

echo "[*] [3/5] Start eBPF collector (netmon)"
NETMON_BIN="$ROOT_DIR/ebpf_core/netmon"
OBJ="$ROOT_DIR/ebpf_core/netmon.bpf.o"

if [[ ! -x "$NETMON_BIN" ]]; then
  echo "[x] netmon binary not found/executable: $NETMON_BIN"
  exit 1
fi
if [[ ! -f "$OBJ" ]]; then
  echo "[x] BPF object not found: $OBJ"
  exit 1
fi

echo "[*]   netmon log file: $NETMON_LOG"
echo "[*]   pid file: $NETMON_PIDFILE"

START_ARGS=(
  -obj "$OBJ"
  -out "$EBPF_AGG"
  -events "$EBPF_EVENTS"
  -flush "$FLUSH_SECS"
  -mode "$MODE"
  -pkt_iface "$IFACE_CAPTURE"
  -meta "$RUN_META"
  -tcpreplay_meta "$TCPREPLAY_META"
)
if [[ "$DISABLE_KPROBES" == "1" ]]; then
  START_ARGS+=( -disable_kprobes )
fi

# Start netmon under sudo, but capture the *real* netmon PID (not the sudo PID).
# Also, keep logs in the run dir.
sudo bash -c "
  set -euo pipefail
  ulimit -l unlimited || true
  exec >>'$NETMON_LOG' 2>&1
  '$NETMON_BIN' ${START_ARGS[*]} &
  echo \$! >'$NETMON_PIDFILE'
" 

NETMON_PID="$(cat "$NETMON_PIDFILE" 2>/dev/null || true)"
if [[ -z "$NETMON_PID" ]]; then
  echo "[x] Failed to read netmon pid from $NETMON_PIDFILE"
  tail -n 120 "$NETMON_LOG" || true
  exit 1
fi

sleep 0.3
if ! sudo kill -0 "$NETMON_PID" 2>/dev/null; then
  echo "[x] netmon died immediately. Last 120 lines:";
  tail -n 120 "$NETMON_LOG" || true
  echo ""
  echo "[!] If you still see MEMLOCK/operation not permitted:"
  echo "    - Ensure you are not in a restricted container"
  echo "    - Check limits: sudo bash -c 'ulimit -l unlimited; ulimit -a'"
  exit 1
fi

echo "[*]   netmon pid: $NETMON_PID"
echo "[*] netmon running confirmed"

echo "[*] [4/5] Replay PCAP (tcpreplay)"
if ! command -v tcpreplay >/dev/null 2>&1; then
  echo "[x] tcpreplay not installed"
  exit 1
fi

TCPREPLAY_LOG="$RUN_DIR/tcpreplay.log"
echo "  [*] tcpreplay args: --intf1 $REPLAY_IFACE --mbps $MBPS --stats=1"
echo "  [*] tcpreplay log -> $TCPREPLAY_LOG"

sudo tcpreplay --intf1 "$REPLAY_IFACE" --mbps "$MBPS" --stats=1 "$PCAP_PATH" >"$TCPREPLAY_LOG" 2>&1 || {
  echo "[x] tcpreplay failed. Last 80 lines:";
  tail -n 80 "$TCPREPLAY_LOG" || true
  exit 1
}

echo "[*] [5/5] Waiting $((FLUSH_SECS + 2))s to allow netmon to flush..."
sleep "$((FLUSH_SECS + 2))"

echo "[*] Stop netmon (final flush + meta)"
if sudo kill -0 "$NETMON_PID" 2>/dev/null; then
  sudo kill -INT "$NETMON_PID" 2>/dev/null || true
  for _ in {1..40}; do
    if ! sudo kill -0 "$NETMON_PID" 2>/dev/null; then break; fi
    sleep 0.25
  done
fi

write_fallback_meta
sudo chown -R "$(id -u):$(id -g)" "$RUN_DIR" 2>/dev/null || true

echo "[*] Done."
echo "  Run folder: $RUN_DIR"
echo "  Outputs:"
ls -lah "$EBPF_AGG" "$EBPF_EVENTS" "$RUN_META" "$TCPREPLAY_META" 2>/dev/null || true
