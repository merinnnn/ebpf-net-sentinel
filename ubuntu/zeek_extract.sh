#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:?Usage: zeek_extract.sh <pcap> <outdir>}"
OUTDIR="${2:?Usage: zeek_extract.sh <pcap> <outdir>}"

mkdir -p "$OUTDIR"
pushd "$OUTDIR" > /dev/null

echo "[*] Extracting Zeek logs from pcap '$PCAP'"

# Use JSON logs so we don't depend on zeek-cut
sudo zeek -r "$PCAP" LogAscii::use_json=T > /dev/null

echo "[*] Converting conn.log to conn.csv (with header)"
python3 - <<'PY'
import json
import csv
from pathlib import Path

in_path = Path("conn.log")
out_path = Path("conn.csv")

fields = [
    "ts","id.orig_h","id.resp_h","id.orig_p","id.resp_p",
    "proto","duration","orig_bytes","resp_bytes","orig_pkts","resp_pkts","conn_state"
]

if not in_path.exists():
    raise SystemExit("[!] conn.log not found (Zeek didn't produce it)")

with in_path.open("r", encoding="utf-8", errors="ignore") as f, out_path.open("w", newline="", encoding="utf-8") as out:
    w = csv.writer(out)
    w.writerow(["ts","orig_h","resp_h","orig_p","resp_p","proto","duration","orig_bytes","resp_bytes","orig_pkts","resp_pkts","conn_state"])
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        row = []
        for k in fields:
            row.append(obj.get(k, ""))
        # map to friendly header order
        w.writerow([row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11]])

print(f"[*] Wrote: {out_path}")
PY

popd > /dev/null
echo "[*] Zeek extraction completed: $OUTDIR/conn.csv"
