#!/usr/bin/env python3

import argparse
import csv
import json
from pathlib import Path

FIELDS_OUT = [
    "ts", "orig_h", "resp_h", "orig_p", "resp_p", "proto", "duration",
    "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "conn_state",
]

# Maps output column names to their dotted keys in Zeek JSON.
FIELDS_JSON = {
    "ts": "ts",
    "orig_h": "id.orig_h",
    "resp_h": "id.resp_h",
    "orig_p": "id.orig_p",
    "resp_p": "id.resp_p",
    "proto": "proto",
    "duration": "duration",
    "orig_bytes": "orig_bytes",
    "resp_bytes": "resp_bytes",
    "orig_pkts": "orig_pkts",
    "resp_pkts": "resp_pkts",
    "conn_state": "conn_state",
}

def detect_format(p: Path) -> str:
    """Detect whether the file is JSON or TSV."""
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            if s.startswith("{") and s.endswith("}"):
                return "json"
            # TSV logs start with # header lines or are plain delimited records.
            return "tsv"
    return "tsv"

def parse_json(in_path: Path, out_path: Path) -> int:
    """Convert a Zeek JSON conn.log to a normalised CSV and return the row count."""
    n = 0
    with in_path.open("r", encoding="utf-8", errors="replace") as fin, out_path.open("w", newline="") as fout:
        w = csv.DictWriter(fout, fieldnames=FIELDS_OUT)
        w.writeheader()
        for line in fin:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            row = {out_k: obj.get(zeek_k, "") for out_k, zeek_k in FIELDS_JSON.items()}
            w.writerow(row)
            n += 1
    return n

def parse_tsv(in_path: Path, out_path: Path) -> int:
    """Convert a Zeek TSV conn.log (with #fields header) to a normalised CSV and return the row count."""
    fields = None
    sep = "\t"
    n = 0

    with in_path.open("r", encoding="utf-8", errors="replace") as fin:
        for line in fin:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#separator"):
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "\\x09":
                    sep = "\t"
                continue
            if line.startswith("#fields"):
                fields = line.split()[1:]
                continue
            if line.startswith("#"):
                continue
            if fields is None:
                raise RuntimeError("TSV format detected but no #fields header found.")
            break

    with in_path.open("r", encoding="utf-8", errors="replace") as fin, out_path.open("w", newline="") as fout:
        w = csv.DictWriter(fout, fieldnames=FIELDS_OUT)
        w.writeheader()
        for line in fin:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split(sep)
            rec = dict(zip(fields, parts))
            row = {
                "ts":         rec.get("ts", ""),
                "orig_h":     rec.get("id.orig_h", ""),
                "resp_h":     rec.get("id.resp_h", ""),
                "orig_p":     rec.get("id.orig_p", ""),
                "resp_p":     rec.get("id.resp_p", ""),
                "proto":      rec.get("proto", ""),
                "duration":   rec.get("duration", ""),
                "orig_bytes": rec.get("orig_bytes", ""),
                "resp_bytes": rec.get("resp_bytes", ""),
                "orig_pkts":  rec.get("orig_pkts", ""),
                "resp_pkts":  rec.get("resp_pkts", ""),
                "conn_state": rec.get("conn_state", ""),
            }
            w.writerow(row)
            n += 1

    return n

def main():
    """CLI entry point. Auto-detects format and converts a Zeek conn.log to CSV."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    args = ap.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)

    if not in_path.exists():
        raise FileNotFoundError(str(in_path))

    fmt = detect_format(in_path)
    if fmt == "json":
        n = parse_json(in_path, out_path)
    else:
        n = parse_tsv(in_path, out_path)

    print(f"[*] Wrote: {out_path} ({n} rows)")

if __name__ == "__main__":
    main()
