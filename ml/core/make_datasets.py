#!/usr/bin/env python3
from datetime import datetime
import argparse
import json
import os
from datetime import datetime
from typing import List, Tuple

import pandas as pd

from pathlib import Path

LABEL_COL = "label_family"
DAY_COL = "day"

# Heuristic: eBPF columns usually carry obvious naming.
EBPF_HINTS = (
    "ebpf", "bpf", "pid", "ppid", "uid", "gid", "comm", "exe", "cmd", "cgroup",
    "sock", "sk_", "tcp_", "udp_", "netns", "inode", "tgid", "task", "ns_", "mount"
)

DROP_ALWAYS = {LABEL_COL, DAY_COL}

def looks_like_ebpf(col: str) -> bool:
    c = col.lower()
    return any(h in c for h in EBPF_HINTS)

def select_feature_columns(columns: List[str]) -> Tuple[List[str], List[str]]:
    # Baseline (Zeek-only): everything except label/day and ebpf-ish cols
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
    return baseline, enhanced

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True)
    ap.add_argument("--out_baseline", required=True)
    ap.add_argument("--out_enhanced", required=True)
    ap.add_argument("--drop_unknown", action="store_true", default=True)
    ap.add_argument("--keep_unknown", action="store_true", default=False,
                    help="Override: keep Unknown instead of dropping")
    ap.add_argument("--report_dir", required=True)
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out_baseline), exist_ok=True)
    os.makedirs(os.path.dirname(args.out_enhanced), exist_ok=True)
    os.makedirs(args.report_dir, exist_ok=True)

    drop_unknown = args.drop_unknown and (not args.keep_unknown)

    # Load full parquet once; for 2.1M rows this is usually OK on a dev machine.
    df = pd.read_parquet(args.in_parquet)

    if LABEL_COL not in df.columns or DAY_COL not in df.columns:
        raise SystemExit(f"[!] Missing required columns: need '{LABEL_COL}' and '{DAY_COL}'")

    before_rows = len(df)

    # Drop Unknown if requested
    unknown_removed = 0
    if drop_unknown:
        unknown_mask = df[LABEL_COL].astype(str).str.lower().eq("unknown")
        unknown_removed = int(unknown_mask.sum())
        df = df.loc[~unknown_mask].copy()

    after_rows = len(df)

    # Feature selection
    baseline_cols, enhanced_cols = select_feature_columns(list(df.columns))

    # Save datasets (keep label+day)
    baseline_df = df[[DAY_COL, LABEL_COL] + baseline_cols].copy()
    enhanced_df = df[[DAY_COL, LABEL_COL] + enhanced_cols].copy()

    baseline_df.to_parquet(args.out_baseline, index=False)
    enhanced_df.to_parquet(args.out_enhanced, index=False)

    # Report what happened
    meta = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "input": args.in_parquet,
        "rows_before": before_rows,
        "rows_after": after_rows,
        "unknown_dropped": bool(drop_unknown),
        "unknown_rows_removed": unknown_removed,
        "baseline_num_features": len(baseline_cols),
        "enhanced_num_features": len(enhanced_cols),
        "num_ebpf_features_added": len(enhanced_cols) - len(baseline_cols),
        "example_ebpf_cols": [c for c in enhanced_cols if c not in baseline_cols][:50],
    }
    with open(os.path.join(args.report_dir, "dataset_build_report.json"), "w") as f:
        json.dump(meta, f, indent=2)

    # Also save feature lists for reproducibility
    pd.Series(baseline_cols).to_csv(os.path.join(args.report_dir, "baseline_features.txt"),
                                    index=False, header=False)
    pd.Series(enhanced_cols).to_csv(os.path.join(args.report_dir, "enhanced_features.txt"),
                                    index=False, header=False)

    print("[*] Wrote:")
    print("  ", args.out_baseline)
    print("  ", args.out_enhanced)
    print("[*] Report:")
    print("  ", os.path.join(args.report_dir, "dataset_build_report.json"))

if __name__ == "__main__":
    main()