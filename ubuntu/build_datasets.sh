#!/usr/bin/env bash
set -euo pipefail

# Build Zeek-only and Zeek+eBPF datasets (optionally labeled) from a captured run directory.
#
# Example:
#   bash ubuntu/build_datasets.sh data/runs/2026-01-30_152438 --scenario FRI_DDOS --tz_offset_hours 0
#
# Inputs expected in <run_dir>:
#   zeek/conn.csv
#   ebpf_agg.jsonl
#
# Outputs written to <run_dir>/datasets:
#   zeek_only.csv
#   zeek_ebpf.csv
#   (optional) zeek_only_labeled.csv
#   (optional) zeek_ebpf_labeled.csv

RUN_DIR="${1:?Usage: build_datasets.sh <run_dir> [--scenario SCENARIO] [--tz_offset_hours N]}"
shift || true

SCENARIO=""
TZ_OFF="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario) SCENARIO="${2:?missing value}"; shift 2;;
    --tz_offset_hours) TZ_OFF="${2:?missing value}"; shift 2;;
    *)
      echo "Unknown arg: $1" >&2
      exit 1
      ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ZEEK_CONN="$RUN_DIR/zeek/conn.csv"
EBPF_AGG="$RUN_DIR/ebpf_agg.jsonl"
OUTDIR="$RUN_DIR/datasets"

mkdir -p "$OUTDIR"

if [[ ! -f "$ZEEK_CONN" ]]; then
  echo "[!] Missing: $ZEEK_CONN" >&2
  exit 1
fi

echo "[1/3] Create Zeek-only dataset"
python3 "$ROOT_DIR/ubuntu/make_zeek_only.py" --in_csv "$ZEEK_CONN" --out_csv "$OUTDIR/zeek_only.csv"

echo "[2/3] Create Zeek+eBPF enriched dataset"
python3 "$ROOT_DIR/ubuntu/merge_zeek_ebpf.py" \
  --zeek_conn "$ZEEK_CONN" \
  --ebpf_agg "$EBPF_AGG" \
  --out "$OUTDIR/zeek_ebpf.csv" \
  --run_meta "$RUN_DIR/run_meta.json"

if [[ -n "$SCENARIO" ]]; then
  echo "[3/3] Label datasets (scenario=$SCENARIO tz_offset_hours=$TZ_OFF)"
  python3 "$ROOT_DIR/ubuntu/label_by_attack_windows.py" \
    --in_csv "$OUTDIR/zeek_only.csv" \
    --out_csv "$OUTDIR/zeek_only_labeled.csv" \
    --scenario "$SCENARIO" \
    --tz_offset_hours "$TZ_OFF"

  python3 "$ROOT_DIR/ubuntu/label_by_attack_windows.py" \
    --in_csv "$OUTDIR/zeek_ebpf.csv" \
    --out_csv "$OUTDIR/zeek_ebpf_labeled.csv" \
    --scenario "$SCENARIO" \
    --tz_offset_hours "$TZ_OFF"
else
  echo "[3/3] Skipping labeling (no --scenario provided)"
fi

echo "[*] Done. Outputs:"
ls -lh "$OUTDIR"
