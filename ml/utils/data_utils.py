#!/usr/bin/env python3
"""Data loading and preprocessing utilities."""
from pathlib import Path
from typing import Tuple
import pandas as pd

def load_splits(splits_dir: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load train/val/test parquet files from a splits directory."""
    d = Path(splits_dir)
    return (
        pd.read_parquet(d / "train.parquet"),
        pd.read_parquet(d / "val.parquet"),
        pd.read_parquet(d / "test.parquet"),
    )

def prepare_features(df: pd.DataFrame, include_ebpf: bool = True) -> pd.DataFrame:
    """Extract feature matrix from a merged dataframe.

    This is a conservative drop-list of known non-feature columns.
    If include_ebpf is False, you can additionally drop columns with an 'ebpf_' prefix.
    """
    drop = [
        "label_family",
        "is_attack",
        "day",
        "label_raw",
        "run_id",
        "ts",
        "start_ts",
        "end_ts",
        "t_end",
        "orig_h",
        "resp_h",
        "src_ip",
        "dst_ip",
        "k",
        "label_time_offset_sec",
        "label_halfday_shift_sec",
        "label_window_pre_slop_sec",
        "label_window_post_slop_sec",
    ]
    X = df.drop(columns=drop, errors="ignore")

    if not include_ebpf:
        ebpf_cols = [c for c in X.columns if c.startswith("ebpf_")]
        if ebpf_cols:
            X = X.drop(columns=ebpf_cols)

    return X
