#!/usr/bin/env bash
set -euo pipefail

# Live capture pipeline:
#   - Start Zeek in live mode on IFACE
#   - Start netmon (eBPF collector) on IFACE
#   - Tail progress logs until you Ctrl+C
#   - On exit, stop both and (best-effort) export zeek/conn.csv
#
# Usage:
#   sudo bash ubuntu/run_live.sh <iface>
#
# Optional env:
#   MODE=both              # flow|events|both (default: both)
#   FLUSH_SECS=5           # netmon flush period (default: 5)
#   DISABLE_KPROBES=1      # default: 1

IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
  echo "Usage: sudo bash ubuntu/run_live.sh <iface>"
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/data"

MODE="${MODE:-both}"
FLUSH_SECS="${FLUSH_SECS:-5}"
DISABLE_KPROBES="${DISABLE_KPROBES:-1}"

RUN_TS="$(date +%F_%H%M%S)"
RUN_DIR="$DATA_DIR/runs/live_${RUN_TS}"
mkdir -p "$RUN_DIR"/{zeek,logs}

ZEEK_DIR="$RUN_DIR/zeek"
ZEEK_LOG="$RUN_DIR/zeek.log"
ZEEK_PIDFILE="$RUN_DIR/zeek.pid"

NETMON_BIN="$ROOT_DIR/ebpf_core/netmon"
OBJ="$ROOT_DIR/ebpf_core/netmon.bpf.o"
NETMON_LOG="$RUN_DIR/netmon.log"
NETMON_PIDFILE="$RUN_DIR/netmon.pid"
EBPF_AGG="$RUN_DIR/ebpf_agg.jsonl"
EBPF_EVENTS="$RUN_DIR/ebpf_events.jsonl"
RUN_META="$RUN_DIR/run_meta.json"

cat >"$RUN_META" <<EOF
{
  "mode":"live",
  "iface_capture":"$IFACE",
  "timestamp":"$RUN_TS",
  "run_dir":"$RUN_DIR"
}
EOF

cleanup() {
  local rc=$?

  if [[ -f "$NETMON_PIDFILE" ]]; then
    NETMON_PID="$(cat "$NETMON_PIDFILE" 2>/dev/null || true)"
    if [[ -n "$NETMON_PID" ]] && sudo kill -0 "$NETMON_PID" 2>/dev/null; then
      echo "[*] Stopping netmon (pid=$NETMON_PID) ..."
      sudo kill -INT "$NETMON_PID" 2>/dev/null || true
    fi
  fi

  if [[ -f "$ZEEK_PIDFILE" ]]; then
    ZEEK_PID="$(cat "$ZEEK_PIDFILE" 2>/dev/null || true)"
    if [[ -n "$ZEEK_PID" ]] && sudo kill -0 "$ZEEK_PID" 2>/dev/null; then
      echo "[*] Stopping zeek (pid=$ZEEK_PID) ..."
      sudo kill -INT "$ZEEK_PID" 2>/dev/null || true
    fi
  fi

  # Give both a moment to exit and flush logs.
  sleep 1

  # Try to export conn.csv if conn.log exists.
  if [[ -f "$ZEEK_DIR/conn.log" ]]; then
    python3 "$ROOT_DIR/ubuntu/zeek_conn_to_csv.py" "$ZEEK_DIR/conn.log" "$ZEEK_DIR/conn.csv" >/dev/null 2>&1 || true
  fi

  # If netmon wrote files as root, return ownership to the invoking user.
  if [[ -n "${SUDO_USER:-}" ]]; then
    sudo chown -R "$SUDO_USER":"$SUDO_USER" "$RUN_DIR" 2>/dev/null || true
  fi

  exit $rc
}
trap cleanup EXIT INT TERM

echo "[*] Live run folder: $RUN_DIR"
echo "[*] Starting Zeek on $IFACE ..."

sudo bash -c "
  set -e
  cd '$ZEEK_DIR'
  exec >>'$ZEEK_LOG' 2>&1
  zeek -i '$IFACE' LogAscii::use_json=T &
  echo \$! > '$ZEEK_PIDFILE'
" 

echo "[*] Building netmon ..."
make -C "$ROOT_DIR/ebpf_core" >/dev/null

if [[ ! -x "$NETMON_BIN" || ! -f "$OBJ" ]]; then
  echo "[x] netmon not built (expected $NETMON_BIN and $OBJ)"
  exit 1
fi

START_ARGS=(
  -obj "$OBJ"
  -out "$EBPF_AGG"
  -events "$EBPF_EVENTS"
  -flush "$FLUSH_SECS"
  -mode "$MODE"
  -pkt_iface "$IFACE"
  -meta "$RUN_META"
)
if [[ "$DISABLE_KPROBES" == "1" ]]; then
  START_ARGS+=( -disable_kprobes )
fi

echo "[*] Starting netmon on $IFACE ..."
sudo bash -c "
  set -e
  exec >>'$NETMON_LOG' 2>&1
  '$NETMON_BIN' ${START_ARGS[*]} &
  echo \$! > '$NETMON_PIDFILE'
"

echo "[*] Tail logs (Ctrl+C to stop):"
echo "    - $NETMON_LOG"
echo "    - $ZEEK_LOG"
echo ""
tail -n 0 -f "$NETMON_LOG" "$ZEEK_LOG"
