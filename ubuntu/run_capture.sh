#!/usr/bin/env bash
set -euo pipefail

# Capture pipeline for a single PCAP:
#   1) Run Zeek over the PCAP and produce zeek/conn.csv
#   2) Start the eBPF collector (netmon)
#   3) Replay the PCAP with tcpreplay into a chosen interface
#   4) Stop netmon and leave all artifacts in data/runs/<timestamp>/
#
# Usage:
#   bash ubuntu/run_capture.sh <pcap_name_or_path> <IFACE_CAPTURE> <MBPS|topspeed>
#
# Optional env:
#   REPLAY_IFACE=<iface>     # where tcpreplay sends packets (default: IFACE_CAPTURE)
#   FLUSH_SECS=5             # netmon flush period seconds (default: 5)
#   DISABLE_KPROBES=1        # default: 1 (use tracepoints only)
#   MODE=flow                # flow|events|both (default: flow)
#   SET_MTU=9000             # optional: set MTU for IFACE_CAPTURE and REPLAY_IFACE before replay
#   FORCE_BUILD=0            # set to 1 to force rebuild netmon + BPF object (make clean all)
#   PRECHECK_IFACES=1        # default: 1; fail fast if IFACE_CAPTURE/REPLAY_IFACE don't exist
#
# Output:
#   Prints: RUN_DIR=<absolute path>

PCAP_IN="${1:-}"
IFACE_CAPTURE="${2:-}"
MBPS="${3:-}"

if [[ -z "$PCAP_IN" || -z "$IFACE_CAPTURE" || -z "${MBPS:-}" ]]; then
  echo "Usage: bash ubuntu/run_capture.sh <pcap> <iface_capture> <mbps|topspeed>"
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
FORCE_BUILD="${FORCE_BUILD:-0}"
PRECHECK_IFACES="${PRECHECK_IFACES:-1}"

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

if [[ "$PRECHECK_IFACES" == "1" ]]; then
  echo "[*] Precheck: validating interfaces exist and are UP"
  if ! ip link show "$IFACE_CAPTURE" >/dev/null 2>&1; then
    echo "[x] IFACE_CAPTURE not found: $IFACE_CAPTURE"
    exit 1
  fi
  if ! ip link show "$REPLAY_IFACE" >/dev/null 2>&1; then
    echo "[x] REPLAY_IFACE not found: $REPLAY_IFACE"
    exit 1
  fi
fi

echo "[*] Inputs:"
echo "  PCAP : $PCAP_PATH"
echo "  IFACE: $IFACE_CAPTURE"
echo "  MBPS : $MBPS"
echo "  OUT  : $RUN_DIR"
echo "  REPLAY_IFACE: $REPLAY_IFACE"
echo ""

NETMON_PID=""

if pgrep -x netmon >/dev/null; then
  echo "[x] netmon already running; refusing to start another."
  pgrep -a netmon
  exit 1
fi

write_fallback_meta() {
  [[ -f "$RUN_META" ]] && return 0
  cat >"$RUN_META" <<EOF
{
  "pcap":"$PCAP_PATH",
  "iface_capture":"$IFACE_CAPTURE",
  "replay_iface":"$REPLAY_IFACE",
  "mbps":"$MBPS",
  "run_dir":"$RUN_DIR",
  "timestamp":"$RUN_TS"
}
EOF
}

stop_netmon() {
  local pid="${1:-}"
  [[ -z "$pid" ]] && return 0

  # If it already died, we're done.
  if ! sudo kill -0 "$pid" 2>/dev/null; then
    return 0
  fi

  # NOTE: under pipefail, ps can race and fail -> must not kill the whole script.
  local pgid=""
  pgid="$(sudo ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ' || true)"

  echo "[*] Stopping netmon pid=$pid pgid=${pgid:-?}"

  # Prefer SIGINT so netmon can flush cleanly.
  if [[ -n "$pgid" ]]; then
    sudo kill -INT  -- "-$pgid" 2>/dev/null || true
  else
    sudo kill -INT  "$pid"      2>/dev/null || true
  fi

  for _ in {1..10}; do
    sudo kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.3
  done

  # Escalate to TERM.
  if [[ -n "$pgid" ]]; then
    sudo kill -TERM -- "-$pgid" 2>/dev/null || true
  else
    sudo kill -TERM "$pid"      2>/dev/null || true
  fi

  for _ in {1..10}; do
    sudo kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.3
  done

  echo "[!] netmon still alive; SIGKILL"
  if [[ -n "$pgid" ]]; then
    sudo kill -KILL -- "-$pgid" 2>/dev/null || true
  else
    sudo kill -KILL "$pid" 2>/dev/null || true
  fi

  return 0
}

cleanup() {
  local rc=$?
  stop_netmon "${NETMON_PID:-}"
  write_fallback_meta
  sudo chown -R "$(id -u):$(id -g)" "$RUN_DIR" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT INT TERM

cat >"$RUN_META" <<EOF
{
  "pcap":"$PCAP_PATH",
  "iface_capture":"$IFACE_CAPTURE",
  "replay_iface":"$REPLAY_IFACE",
  "mbps":"$MBPS",
  "run_dir":"$RUN_DIR",
  "timestamp":"$RUN_TS"
}
EOF

echo "[*] [1/6] Preprocessing PCAP (truncate to MTU 1500)"
FIXED_PCAP="$RUN_DIR/$(basename "$PCAP_PATH" .pcap)-fixed.pcap"
if command -v editcap >/dev/null 2>&1; then
  editcap -s 1500 "$PCAP_PATH" "$FIXED_PCAP"
  PCAP_TO_REPLAY="$FIXED_PCAP"
  echo "[*] Created MTU-safe PCAP: $FIXED_PCAP"
else
  echo "[!] editcap not found - using original PCAP (may hit MTU errors)"
  PCAP_TO_REPLAY="$PCAP_PATH"
fi

echo "[*] [2/6] Zeek flow extraction"
ZEEK_LOG="$RUN_DIR/zeek.log"
ZEEK_OUT_DIR="$RUN_DIR/zeek"
mkdir -p "$ZEEK_OUT_DIR"

echo "  [*] zeek -r $PCAP_PATH (logging -> $ZEEK_LOG)"
(
  cd "$ZEEK_OUT_DIR"
  zeek -r "$PCAP_PATH" >"$ZEEK_LOG" 2>&1
)

if [[ ! -f "$ZEEK_OUT_DIR/conn.log" ]]; then
  echo "[x] Zeek did not produce conn.log"
  exit 1
fi

python3 "$ROOT_DIR/ubuntu/zeek_conn_to_csv.py" --in "$ZEEK_OUT_DIR/conn.log" --out "$ZEEK_OUT_DIR/conn.csv"
echo "[*] Wrote $ZEEK_OUT_DIR/conn.csv"

echo "[*] [3/6] Build eBPF collector"
if [[ "$FORCE_BUILD" == "1" ]]; then
  make -C "$ROOT_DIR/ebpf_core" clean all
else
  make -C "$ROOT_DIR/ebpf_core"
fi

if [[ -n "$SET_MTU" ]]; then
  echo "[*] Setting MTU=$SET_MTU on $REPLAY_IFACE and $IFACE_CAPTURE"
  sudo ip link set dev "$REPLAY_IFACE" mtu "$SET_MTU" 2>/dev/null || true
  sudo ip link set dev "$IFACE_CAPTURE" mtu "$SET_MTU" 2>/dev/null || true
fi

echo "[*] [4/6] Start eBPF collector (netmon)"
NETMON_BIN="$ROOT_DIR/ebpf_core/bin/netmon"
OBJ="$ROOT_DIR/ebpf_core/bin/netmon.bpf.o"

[[ -x "$NETMON_BIN" ]] || NETMON_BIN="$ROOT_DIR/ebpf_core/netmon"
[[ -f "$OBJ" ]]        || OBJ="$ROOT_DIR/ebpf_core/netmon.bpf.o"

if [[ ! -x "$NETMON_BIN" || ! -f "$OBJ" ]]; then
  echo "[x] netmon not built (expected $ROOT_DIR/ebpf_core/bin/netmon and netmon.bpf.o)"
  exit 1
fi

# Attach socket filter to REPLAY_IFACE (where tcpreplay sends)
echo "[*]   eBPF socket filter will attach to: $REPLAY_IFACE"

START_ARGS=(
  -obj "$OBJ"
  -out "$EBPF_AGG"
  -events "$EBPF_EVENTS"
  -flush "$FLUSH_SECS"
  -mode "$MODE"
  -pkt_iface "$REPLAY_IFACE"
  -meta "$RUN_META"
  -tcpreplay_meta "$TCPREPLAY_META"
)
if [[ "$DISABLE_KPROBES" == "1" ]]; then
  START_ARGS+=( -disable_kprobes )
fi

sudo bash -c '
  set -euo pipefail
  ulimit -l unlimited || true
  exec >>"$1" 2>&1
  shift
  setsid "$@" </dev/null & # start netmon in a new session -> PID becomes PGID
  echo $! >"$0"
' "$NETMON_PIDFILE" "$NETMON_LOG" "$NETMON_BIN" "${START_ARGS[@]}"

NETMON_PID="$(cat "$NETMON_PIDFILE" 2>/dev/null || true)"
sleep 0.5

if [[ -z "$NETMON_PID" ]] || ! sudo kill -0 "$NETMON_PID" 2>/dev/null; then
  echo "[x] netmon died immediately"
  tail -n 80 "$NETMON_LOG" || true
  exit 1
fi

echo "[*]   netmon pid: $NETMON_PID"

echo "[*] [5/6] Replay PCAP (tcpreplay)"
TCPREPLAY_LOG="$RUN_DIR/tcpreplay.log"

# Respect caller intent:
# - MBPS="topspeed" -> --topspeed
# - MBPS="<number>" -> --mbps <number>
TCPREPLAY_ARGS=( --intf1 "$REPLAY_IFACE" --stats=1 )

if [[ "$MBPS" == "topspeed" || "$MBPS" == "TOPSPEED" ]]; then
  TCPREPLAY_ARGS+=( --topspeed )
else
  # basic numeric check
  if [[ "$MBPS" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    TCPREPLAY_ARGS+=( --mbps "$MBPS" )
  else
    echo "[x] Invalid MBPS arg: '$MBPS' (use number or 'topspeed')"
    exit 1
  fi
fi

echo "  [*] tcpreplay args: ${TCPREPLAY_ARGS[*]}"
echo "  [*] tcpreplay log -> $TCPREPLAY_LOG"

sudo tcpreplay "${TCPREPLAY_ARGS[@]}" "$PCAP_TO_REPLAY" >"$TCPREPLAY_LOG" 2>&1 || {
  echo "[x] tcpreplay failed"
  tail -n 80 "$TCPREPLAY_LOG" || true
  exit 1
}

echo "[*] [6/6] Waiting $((FLUSH_SECS + 2))s to allow netmon to flush..."
sleep "$((FLUSH_SECS + 2))"

echo "[*] Stop netmon (final flush)"
stop_netmon "$NETMON_PID"

write_fallback_meta
sudo chown -R "$(id -u):$(id -g)" "$RUN_DIR" 2>/dev/null || true

echo "[*] Done."
echo "  Run folder: $RUN_DIR"
echo "RUN_DIR=$RUN_DIR"
echo "  Outputs:"
ls -lah "$EBPF_AGG" "$EBPF_EVENTS" "$RUN_META" 2>/dev/null || true
