#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash ubuntu/run_capture.sh <pcap_name_or_path> <IFACE_CAPTURE> <MBPS>
#
# Optional env:
#   REPLAY_IFACE=<iface>     # where tcpreplay sends packets (default: IFACE_CAPTURE)
#   FLUSH_SECS=5             # netmon flush period (default: 5)
#   DISABLE_KPROBES=1        # default: 1
#   MODE=flow                # default: flow
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

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "[!] Cleanup handler fired (rc=$rc)"
  fi

  if [[ -n "${NETMON_PID:-}" ]]; then
    # Try graceful stop, then harder if needed.
    if sudo kill -0 "$NETMON_PID" 2>/dev/null; then
      echo "[*] Stopping netmon (pid=$NETMON_PID) ..."
      sudo kill -INT "$NETMON_PID" 2>/dev/null || true
      for _ in {1..30}; do
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

  # Ensure run_meta exists (create early, but keep this as final safety)
  if [[ ! -f "$RUN_META" ]]; then
    echo "[!] run_meta.json missing; writing fallback meta"
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

python3 - "$ZEEK_OUT_DIR/conn.log" "$ZEEK_OUT_DIR/conn.csv" <<'PY'
import sys, csv

in_path = sys.argv[1]
out_path = sys.argv[2]

wanted = [
    ("ts", "ts"),
    ("orig_h", "id.orig_h"),
    ("resp_h", "id.resp_h"),
    ("orig_p", "id.orig_p"),
    ("resp_p", "id.resp_p"),
    ("proto", "proto"),
    ("duration", "duration"),
    ("orig_bytes", "orig_bytes"),
    ("resp_bytes", "resp_bytes"),
    ("orig_pkts", "orig_pkts"),
    ("resp_pkts", "resp_pkts"),
    ("conn_state", "conn_state"),
]

fields = None
unset_field = "-"
empty_field = ""

with open(in_path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line.startswith("#"):
            continue
        if line.startswith("#unset_field"):
            parts = line.split("\t", 1)
            if len(parts) == 2:
                unset_field = parts[1]
        if line.startswith("#empty_field"):
            parts = line.split("\t", 1)
            if len(parts) == 2:
                empty_field = parts[1]
        if line.startswith("#fields"):
            parts = line.split("\t")
            fields = parts[1:]
            break

if not fields:
    raise SystemExit("Could not find #fields line in conn.log")

idx = {name: i for i, name in enumerate(fields)}
missing = [src for _, src in wanted if src not in idx]
if missing:
    raise SystemExit(f"conn.log missing expected fields: {missing}")

def norm(v: str) -> str:
    if v == unset_field:
        return ""
    if empty_field and v == empty_field:
        return ""
    return v

rows = 0
with open(in_path, "r", encoding="utf-8", errors="replace") as fin, \
     open(out_path, "w", newline="", encoding="utf-8") as fout:
    w = csv.writer(fout)
    for line in fin:
        if not line or line.startswith("#"):
            continue
        parts = line.rstrip("\n").split("\t")
        out = []
        for _, src in wanted:
            out.append(norm(parts[idx[src]]) if idx[src] < len(parts) else "")
        w.writerow(out)
        rows += 1

print(f"Wrote {out_path} ({rows} rows)")
PY

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

# IMPORTANT: run netmon under sudo with memlock unlimited
sudo bash -c "ulimit -l unlimited; exec '$NETMON_BIN' ${START_ARGS[*]}" >>"$NETMON_LOG" 2>&1 &
NETMON_PID=$!
echo "$NETMON_PID" >"$NETMON_PIDFILE"

# Wait a moment and validate it stays alive
sleep 0.3
if ! sudo kill -0 "$NETMON_PID" 2>/dev/null; then
  echo "[x] netmon died immediately. Last 120 lines:"
  tail -n 120 "$NETMON_LOG" || true
  echo ""
  echo "[!] If you still see MEMLOCK/operation not permitted:"
  echo "    Try: sudo bash -c 'ulimit -l unlimited; ulimit -a'"
  echo "    And ensure you're not in a restricted container."
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
  echo "[x] tcpreplay failed. Last 80 lines:"
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

echo "[*] Done."
echo "  Run folder: $RUN_DIR"
echo "  Outputs:"
ls -lah "$EBPF_AGG" "$EBPF_EVENTS" "$RUN_META" "$TCPREPLAY_META" 2>/dev/null || true
