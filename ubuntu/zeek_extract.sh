#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash ubuntu/zeek_extract.sh <pcap_name_or_path> <out_dir>

PCAP_IN="${1:-}"
OUTDIR="${2:-}"

if [[ -z "$PCAP_IN" || -z "$OUTDIR" ]]; then
  echo "Usage: bash ubuntu/zeek_extract.sh <pcap> <out_dir>"
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

# Ensure output dir exists before we try to write logs/files.
mkdir -p "$OUTDIR"

LOG="$OUTDIR/zeek_extract.log"
exec > >(tee -a "$LOG") 2>&1

echo "[*] Running Zeek on: $PCAP_PATH"
echo "[*] Output dir: $OUTDIR"
echo "[*] Log: $LOG"

ZEEK_LOG="$OUTDIR/zeek.log"
(
  cd "$OUTDIR"
  zeek -r "$PCAP_PATH" >"$ZEEK_LOG" 2>&1
)

if [[ ! -f "$OUTDIR/conn.log" ]]; then
  echo "[x] Zeek did not produce conn.log at $OUTDIR/conn.log"
  echo "    Last 80 lines of zeek.log:"
  tail -n 80 "$ZEEK_LOG" || true
  exit 1
fi

python3 "$ROOT_DIR/ubuntu/zeek_conn_to_csv.py" --in "$OUTDIR/conn.log" --out "$OUTDIR/conn.csv"

echo "[*] Wrote: $OUTDIR/conn.csv"
