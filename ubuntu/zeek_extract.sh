#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:?Usage: zeek_extract.sh <pcap> <outdir>}"
OUTDIR="${2:?Usage: zeek_extract.sh <pcap> <outdir>}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$OUTDIR"
pushd "$OUTDIR" > /dev/null

echo "[*] Extracting Zeek logs from pcap '$PCAP'"

# Use JSON logs so we don't depend on zeek-cut
sudo zeek -r "$PCAP" LogAscii::use_json=T > /dev/null

echo "[*] Converting conn.log to conn.csv"
python3 "$ROOT_DIR/ubuntu/zeek_conn_to_csv.py" --in conn.log --out conn.csv

popd > /dev/null
echo "[*] Zeek extraction completed: $OUTDIR/conn.csv"
