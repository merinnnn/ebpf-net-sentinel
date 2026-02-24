#!/usr/bin/env python3
"""
Reads a merged Parquet and writes:
- baseline.parquet: Zeek-ish features (+ day, label_family)
- enhanced.parquet: baseline + eBPF-ish features (+ day, label_family)
"""

from datetime import datetime
import argparse
import json
import os
import sys
import subprocess
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pandas as pd

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except Exception as e:  # pragma: no cover
    raise SystemExit("pyarrow is required. Please `pip install pyarrow`.") from e

LABEL_COL = "label_family"
DAY_COL   = "day"


# Backwards-compatible API
def run(
    *,
    in_parquet: str,
    out_baseline: str,
    out_enhanced: str,
    report_dir: str,
    drop_unknown: bool = True,
    batch_size: int = 131072,
):
    """
    Run dataset builder via the module CLI to keep one codepath.
    """
    cmd = [
        sys.executable,
        "-m",
        "ml.data_prep.make_datasets",
        "--in_parquet",
        str(in_parquet),
        "--out_baseline",
        str(out_baseline),
        "--out_enhanced",
        str(out_enhanced),
        "--report_dir",
        str(report_dir),
        "--batch_size",
        str(batch_size),
    ]
    if drop_unknown:
        cmd += ["--drop_unknown"]
    else:
        cmd += ["--keep_unknown"]
    subprocess.run(cmd, check=True)
    return Path(report_dir)


def make_report(report_dir: str):
    """Load and return make_datasets_meta.json as a dict."""
    p = Path(report_dir) / "make_datasets_meta.json"
    return json.loads(p.read_text())

EBPF_HINTS = (
    "ebpf", "bpf", "pid", "ppid", "uid", "gid", "comm", "exe", "cmd", "cgroup",
    "sock", "sk_", "tcp_", "udp_", "netns", "inode", "tgid", "task", "ns_", "mount"
)

DROP_ALWAYS = {LABEL_COL, DAY_COL}

def looks_like_ebpf(col: str) -> bool:
    c = col.lower()
    return any(h in c for h in EBPF_HINTS)

def select_feature_columns(columns: List[str]) -> Tuple[List[str], List[str], List[str]]:
    baseline = []
    ebpf_cols = []
    for c in columns:
        if c in DROP_ALWAYS:
            continue
        if looks_like_ebpf(c):
            ebpf_cols.append(c)
        else:
            baseline.append(c)
    enhanced = baseline + ebpf_cols
    return baseline, enhanced, ebpf_cols

def _iter_batches(parquet_path: str, batch_size: int, columns=None):
    pf = pq.ParquetFile(parquet_path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=columns):
        yield batch.to_pandas()


def build_datasets(
    *,
    in_parquet: str,
    out_baseline: str,
    out_enhanced: str,
    report_dir: str,
    drop_unknown: bool = True,
    batch_size: int = 131072,
) -> dict:
    """
    Build baseline/enhanced feature-set Parquets.

    Entry point used by notebooks (no argparse / sys.argv mutation).
    Returns the report metadata dict written to report_dir.
    """

    os.makedirs(os.path.dirname(out_baseline), exist_ok=True)
    os.makedirs(os.path.dirname(out_enhanced), exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)

    pf = pq.ParquetFile(in_parquet)
    schema = pf.schema_arrow
    cols = [f.name for f in schema]
    if LABEL_COL not in cols:
        raise ValueError(f"Missing required column: '{LABEL_COL}'")
    if DAY_COL not in cols:
        print(f"[!] Warning: '{DAY_COL}' not found; some splits (Split 4) require it.")

    baseline_cols, enhanced_cols, ebpf_cols = select_feature_columns(cols)

    # Output columns (keep day+label if available)
    base_out_cols = [c for c in [DAY_COL, LABEL_COL] if c in cols] + baseline_cols
    enh_out_cols = [c for c in [DAY_COL, LABEL_COL] if c in cols] + enhanced_cols

    base_writer = None
    enh_writer = None

    before_rows = int(pf.metadata.num_rows)
    after_rows = 0
    unknown_removed = 0

    label_counts = {}
    day_counts = {}

    for df in _iter_batches(in_parquet, batch_size, columns=list(set(base_out_cols + enh_out_cols))):
        if drop_unknown:
            unknown_mask = df[LABEL_COL].astype(str).str.lower().eq("unknown")
            unknown_removed += int(unknown_mask.sum())
            df = df.loc[~unknown_mask].copy()

        after_rows += len(df)

        labs = df[LABEL_COL].astype(str)
        vc = labs.value_counts(dropna=False)
        for k, v in vc.items():
            label_counts[str(k)] = label_counts.get(str(k), 0) + int(v)
        if DAY_COL in df.columns:
            days = df[DAY_COL].astype(str)
            dvc = days.value_counts(dropna=False)
            for d, v in dvc.items():
                day_counts[str(d)] = day_counts.get(str(d), 0) + int(v)

        # write baseline
        base_df = df[base_out_cols]
        if base_writer is None:
            base_schema = pa.Table.from_pandas(base_df.head(1), preserve_index=False).schema
            base_writer = pq.ParquetWriter(out_baseline, schema=base_schema, compression="snappy")
        base_writer.write_table(pa.Table.from_pandas(base_df, preserve_index=False))

        # write enhanced
        enh_df = df[enh_out_cols]
        if enh_writer is None:
            enh_schema = pa.Table.from_pandas(enh_df.head(1), preserve_index=False).schema
            enh_writer = pq.ParquetWriter(out_enhanced, schema=enh_schema, compression="snappy")
        enh_writer.write_table(pa.Table.from_pandas(enh_df, preserve_index=False))

    if base_writer:
        base_writer.close()
    if enh_writer:
        enh_writer.close()

    meta = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "input": str(in_parquet),
        "rows_before": before_rows,
        "rows_after": after_rows,
        "unknown_dropped": bool(drop_unknown),
        "unknown_rows_removed": unknown_removed,
        "baseline_num_features": len(baseline_cols),
        "enhanced_num_features": len(enhanced_cols),
        "num_ebpf_features_added": len(ebpf_cols),
        "example_ebpf_cols": ebpf_cols[:25],
        "baseline_columns": base_out_cols,
        "enhanced_columns": enh_out_cols,
        "label_counts_after": label_counts,
        "day_counts_after": day_counts,
        "batch_size": int(batch_size),
        "baseline_out": str(out_baseline),
        "enhanced_out": str(out_enhanced),
    }

    out_meta = Path(report_dir) / "make_datasets_meta.json"
    out_meta.write_text(json.dumps(meta, indent=2))
    return meta

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True)
    ap.add_argument("--out_baseline", required=True)
    ap.add_argument("--out_enhanced", required=True)
    ap.add_argument("--drop_unknown", action="store_true", default=True)
    ap.add_argument("--keep_unknown", action="store_true", default=False,
                    help="Override: keep Unknown instead of dropping")
    ap.add_argument("--report_dir", required=True)
    ap.add_argument("--batch_size", type=int, default=131072)
    args = ap.parse_args()

    drop_unknown = args.drop_unknown and (not args.keep_unknown)

    build_datasets(
        in_parquet=args.in_parquet,
        out_baseline=args.out_baseline,
        out_enhanced=args.out_enhanced,
        report_dir=args.report_dir,
        drop_unknown=drop_unknown,
        batch_size=args.batch_size,
    )
    print(f"[*] Wrote baseline -> {args.out_baseline}")
    print(f"[*] Wrote enhanced -> {args.out_enhanced}")
    print(f"[*] Report -> {Path(args.report_dir) / 'make_datasets_meta.json'}")

if __name__ == "__main__":
    main()
