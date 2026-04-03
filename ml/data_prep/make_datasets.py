#!/usr/bin/env python3
"""
Reads a merged Parquet and writes:
  - baseline.parquet : Zeek features (+ day, label_family)
  - enhanced.parquet : baseline + eBPF features (+ day, label_family)
"""

from datetime import datetime
import argparse
import json
import os
import sys
import subprocess
from pathlib import Path
from typing import List, Tuple

import pandas as pd

import pyarrow as pa
import pyarrow.parquet as pq

LABEL_COL = "label_family"
DAY_COL   = "day"


def run(
    *,
    in_parquet: str,
    out_baseline: str,
    out_enhanced: str,
    report_dir: str,
    drop_unknown: bool = True,
    batch_size: int = 131072,
):
    """Notebook entry point. Delegates to the module CLI to keep one codepath."""
    cmd = [
        sys.executable, "-m", "ml.data_prep.make_datasets",
        "--in_parquet",  str(in_parquet),
        "--out_baseline", str(out_baseline),
        "--out_enhanced", str(out_enhanced),
        "--report_dir",  str(report_dir),
        "--batch_size",  str(batch_size),
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
    """Heuristic to classify a column as eBPF-derived."""
    c = col.lower()
    return any(h in c for h in EBPF_HINTS)

def select_feature_columns(columns: List[str]) -> Tuple[List[str], List[str], List[str]]:
    """
    Split the source schema into baseline and eBPF-specific columns.
    The baseline keeps every non-eBPF feature; enhanced appends the eBPF columns.
    """
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

def _encode_categorical_ebpf(df: pd.DataFrame, ebpf_cols: list,
                              freq_maps: dict | None = None,
                              fit: bool = False) -> tuple:
    """
    Frequency-encode categorical eBPF columns (e.g. comm/exe).
    When fit=True, freq_maps are fit on all rows, which leaks test-day frequencies.
    Pass pre-fit freq_maps from make_train_aligned_encoding() to avoid this.
    """
    cat_cols = [c for c in ebpf_cols if c in df.columns
                and not pd.api.types.is_numeric_dtype(df[c])]
    if not cat_cols:
        return df, freq_maps or {}

    if fit:
        freq_maps = {}
        for c in cat_cols:
            vc = df[c].astype(str).value_counts(normalize=True)
            freq_maps[c] = vc.to_dict()

    df = df.copy()
    for c in cat_cols:
        fmap = (freq_maps or {}).get(c, {})
        df[c] = df[c].astype(str).map(fmap).fillna(0.0).astype(float)

    return df, freq_maps or {}

def make_train_aligned_encoding(
    train_parquet_path: str,
    ebpf_cols: list,
    batch_size: int = 131072,
) -> dict:
    """
    Compute frequency maps from a training-split parquet only (leakage-free).
    Returns {col_name: {category: normalised_freq}} for use with _encode_categorical_ebpf(..., fit=False).
    """
    from collections import Counter
    counters: dict = {}
    for df in _iter_batches(str(train_parquet_path), batch_size, columns=ebpf_cols):
        for c in ebpf_cols:
            if c not in df.columns:
                continue
            if pd.api.types.is_numeric_dtype(df[c]):
                continue
            if c not in counters:
                counters[c] = Counter()
            counters[c].update(df[c].astype(str).dropna())

    freq_maps = {}
    for c, ctr in counters.items():
        total = sum(ctr.values())
        if total > 0:
            freq_maps[c] = {k: v / total for k, v in ctr.items()}
    return freq_maps

def _iter_batches(parquet_path: str, batch_size: int, columns=None):
    """Yield pandas DataFrames from a Parquet file in fixed-size batches."""
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
    Notebook entry point (no argparse). Returns the metadata dict written to report_dir.
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

    # Always preserve day and label so downstream split builders can use them.
    base_out_cols = [c for c in [DAY_COL, LABEL_COL] if c in cols] + baseline_cols
    enh_out_cols  = [c for c in [DAY_COL, LABEL_COL] if c in cols] + enhanced_cols

    base_writer = None
    enh_writer  = None

    before_rows    = int(pf.metadata.num_rows)
    after_rows     = 0
    unknown_removed = 0
    label_counts   = {}
    day_counts     = {}

    # Pass 1: build frequency maps for categorical eBPF columns from all rows.
    # This matches the historical dataset build but leaks across days; 
    # use make_train_aligned_encoding(train_parquet) for a leakage-free alternative.
    freq_maps_ebpf = make_train_aligned_encoding(in_parquet, ebpf_cols, batch_size)
    if freq_maps_ebpf:
        print(f"[make_datasets] Fitted full-dataset freq maps for: {list(freq_maps_ebpf)}")
        print("  WARNING: encoding uses all rows (train+test). For leakage-free")
        print("  encoding, call make_train_aligned_encoding(train_parquet) instead.")
    else:
        print("[make_datasets] No categorical eBPF columns found to encode.")

    # Pass 2: stream the dataset and write the two output parquets.
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

        enh_df_raw = df[enh_out_cols].copy()
        enh_df_enc, _ = _encode_categorical_ebpf(
            enh_df_raw, ebpf_cols, freq_maps=freq_maps_ebpf, fit=False
        )

        base_df = df[base_out_cols]
        if base_writer is None:
            base_schema = pa.Table.from_pandas(base_df.head(1), preserve_index=False).schema
            base_writer = pq.ParquetWriter(out_baseline, schema=base_schema, compression="snappy")
        base_writer.write_table(pa.Table.from_pandas(base_df, preserve_index=False))

        if enh_writer is None:
            enh_schema = pa.Table.from_pandas(enh_df_enc.head(1), preserve_index=False).schema
            enh_writer = pq.ParquetWriter(out_enhanced, schema=enh_schema, compression="snappy")
        enh_writer.write_table(pa.Table.from_pandas(enh_df_enc, preserve_index=False))

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
        "categorical_ebpf_encoded": {
            "method": "frequency_encoding (two-pass: full-dataset normalised count)",
            "leakage_warning": (
                "Freq maps are fit on ALL rows (train+val+test days). "
                "Friday test rows receive frequency codes derived partly from Friday data. "
                "Use make_train_aligned_encoding(train_parquet) for leakage-free encoding."
            ),
            "note": "Categorical eBPF columns converted to float [0,1] freq codes for numeric-only pipelines.",
            "columns_encoded": list(freq_maps_ebpf.keys()) if freq_maps_ebpf else [],
        },
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
    ap.add_argument("--in_parquet",   required=True)
    ap.add_argument("--out_baseline", required=True)
    ap.add_argument("--out_enhanced", required=True)
    ap.add_argument("--drop_unknown", action="store_true", default=True)
    ap.add_argument("--keep_unknown", action="store_true", default=False,
                    help="override: keep Unknown labels instead of dropping")
    ap.add_argument("--report_dir",   required=True)
    ap.add_argument("--batch_size",   type=int, default=131072)
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
