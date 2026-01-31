#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


WANTED = [
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


def _detect_format(p: Path) -> str:
    # Zeek JSON logs are typically *.log with one JSON object per line.
    # TSV logs start with several "#" header lines.
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                return "tsv"
            if line.startswith("{"):
                return "json"
            # Fallback: if it's not obviously JSON and not Zeek headers, treat as TSV.
            return "tsv"
    return "tsv"


def _parse_tsv(in_path: Path, out_path: Path) -> int:
    fields: list[str] | None = None
    unset_field = "-"
    empty_field = ""

    # Read Zeek header block.
    with in_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.startswith("#"):
                continue
            if line.startswith("#unset_field"):
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    unset_field = parts[1]
            elif line.startswith("#empty_field"):
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    empty_field = parts[1]
            elif line.startswith("#fields"):
                parts = line.split("\t")
                fields = parts[1:]
                break

    if not fields:
        raise SystemExit("Could not find #fields line in conn.log")

    idx = {name: i for i, name in enumerate(fields)}
    missing = [src for _, src in WANTED if src not in idx]
    if missing:
        raise SystemExit(f"conn.log missing expected fields: {missing}")

    def norm(v: str) -> str:
        if v == unset_field:
            return ""
        if empty_field and v == empty_field:
            return ""
        return v

    rows = 0
    with in_path.open("r", encoding="utf-8", errors="replace") as fin, out_path.open(
        "w", newline="", encoding="utf-8"
    ) as fout:
        w = csv.writer(fout)
        for line in fin:
            if not line or line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            out_row = [norm(parts[idx[src]]) if idx[src] < len(parts) else "" for _, src in WANTED]
            w.writerow(out_row)
            rows += 1
    return rows


def _parse_json(in_path: Path, out_path: Path) -> int:
    rows = 0
    with in_path.open("r", encoding="utf-8", errors="replace") as fin, out_path.open(
        "w", newline="", encoding="utf-8"
    ) as fout:
        w = csv.writer(fout)
        for line in fin:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            out_row = []
            for _, src in WANTED:
                v = obj.get(src, "")
                if v in (None, "-"):
                    v = ""
                out_row.append(str(v))
            w.writerow(out_row)
            rows += 1
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path")
    ap.add_argument("--out", dest="out_path")
    ap.add_argument("pos_in", nargs="?")
    ap.add_argument("pos_out", nargs="?")
    args = ap.parse_args()

    in_path = args.in_path or args.pos_in
    out_path = args.out_path or args.pos_out

    if not in_path or not out_path:
        ap.error("Expected --in/--out or positional <in_path> <out_path>")

    in_p = Path(in_path)
    out_p = Path(out_path)
    if not in_p.exists():
        raise SystemExit(f"Input does not exist: {in_p}")

    fmt = _detect_format(in_p)
    if fmt == "json":
        rows = _parse_json(in_p, out_p)
    else:
        rows = _parse_tsv(in_p, out_p)

    print(f"Wrote: {out_p} ({rows} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
