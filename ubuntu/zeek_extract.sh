#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:Usage: zeek_extract.sh <pcap> <outdir>}"
OUTDIR="${2:Usage: zeek_extract.sh <pcap> <outdir>}"

mkdir -p "$OUTDIR"
pushd "$OUTDIR" > /dev/null

echo "[*] Extracting Zeek logs from pcap '$PCAP'"
sudo zeek -r "$PCAP" > /dev/null

echo "[*] Writing conn.csv"
zeek-cut -d ts id.orig_h id.resp_h id.orig_p id.resp_p proto duration orig_bytes resp_bytes orig_pkts resp_pkts conn_state < conn.log > conn.csv

popd > /dev/null
echo "[*] Zeek extraction completed: $OUTDIR/conn.csv"