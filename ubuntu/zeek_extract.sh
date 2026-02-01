#!/usr/bin/env bash
set -euo pipefail

# Offline Zeek extraction for a PCAP.
# Produces:
#   <OUTDIR>/conn.log
#   <OUTDIR>/conn.csv
#
# Usage:
#   bash ubuntu/zeek_extract.sh <pcap_name_or_path> <outdir>

PCAP_IN="${1:-}"
OUTDIR="${2:-}"

if [[ -z "$PCAP_IN" || -z "$OUTDIR" ]]; then
  echo "Usage: bash ubuntu/zeek_extract.sh <pcap_name_or_path> <outdir>"
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT_DIR/data"
PCAP_DIR="$DATA_DIR/cicids2017_pcap"
CONVERTER="$ROOT_DIR/ubuntu/zeek_conn_to_csv.py"

if [[ -f "$PCAP_IN" ]]; then
  PCAP_PATH="$(cd "$(dirname "$PCAP_IN")" && pwd)/$(basename "$PCAP_IN")"
else
  PCAP_PATH="$PCAP_DIR/$PCAP_IN"
fi

if [[ ! -f "$PCAP_PATH" ]]; then
  echo "[x] PCAP not found: $PCAP_PATH"
  exit 1
fi
if [[ ! -f "$CONVERTER" ]]; then
  echo "[x] Missing converter script: $CONVERTER"
  exit 1
fi
if ! command -v zeek >/dev/null 2>&1; then
  echo "[x] zeek not installed"
  exit 1
fi

mkdir -p "$OUTDIR"

# Use an absolute log path.
ZEEK_LOG="$(cd "$OUTDIR" && pwd)/zeek_extract.log"

echo "[*] Running Zeek on: $PCAP_PATH"
echo "[*] Output dir: $OUTDIR"
echo "[*] Log: $ZEEK_LOG"

(
  cd "$OUTDIR"
  zeek -r "$PCAP_PATH" >"$ZEEK_LOG" 2>&1
)

if [[ ! -f "$OUTDIR/conn.log" ]]; then
  echo "[x] Zeek did not produce conn.log"
  echo "    Last 80 lines of $ZEEK_LOG:"
  tail -n 80 "$ZEEK_LOG" || true
  exit 1
fi

python3 "$CONVERTER" "$OUTDIR/conn.log" "$OUTDIR/conn.csv"

echo "[*] Wrote: $OUTDIR/conn.csv"
ls -lah "$OUTDIR/conn.csv" "$OUTDIR/conn.log" | sed 's#^#    #' || true
