#!/usr/bin/env python3
"""
Leakage-controlled split by grouping flows on (orig_h, resp_h) and then
stratifying groups by a dominant label.

Dominant label rule (safer than plain mode)
- If a group contains any attack labels: dominant is the most frequent attack label.
- Otherwise: dominant is BENIGN.

This avoids groups with mixed benign+attack being labelled BENIGN just because
BENIGN is the majority.

Output
Writes:
  train.parquet, val.parquet, test.parquet, split_report.json

Implementation
Two-pass streaming:
1) Build group table (dominant label + group size) using small in-RAM dicts
2) Stream rows again and write to Parquet incrementally using group->split mapping

KNOWN LIMITATION
This split stratifies by *number of groups*, not by row volume per group. 
If a small number of host-pairs generate the bulk of attack traffic, train gets most 
attacks while val/test may end up with near-zero attack rows.

Use this split for LEAKAGE DIAGNOSTICS only (research question: "am I memorising host pairs?").
Use Split 2 for balanced model selection and Split 4 for realistic evaluation.

"""

import argparse
import json
import sys
import subprocess
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except Exception as e:  # pragma: no cover
    raise SystemExit("pyarrow is required. Please `pip install pyarrow`.") from e

LABEL_COL   = "label_family"
SRC_COL     = "orig_h"
DST_COL     = "resp_h"
BENIGN_LIKE = frozenset({"BENIGN", "Unknown", "nan", "NaN", ""})


# Backwards-compatible API (for older notebooks)
def run(
    *,
    in_parquet: str,
    out_dir: str,
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    test_frac: float = 0.15,
    seed: int = 42,
    batch_size: int = 131072,
):
    """
    Entry point used by notebooks (in-process).

    Historically this file exposed a CLI-only implementation. This wrapper keeps the
    old import path stable while running the shared implementation directly.
    """
    return run_streaming(
        in_parquet=str(in_parquet),
        out_dir=str(out_dir),
        train_frac=train_frac,
        val_frac=val_frac,
        test_frac=test_frac,
        seed=seed,
        batch_size=batch_size,
    )


def make_report(out_dir: str):
    """Load and return split_report.json as a dict."""
    p = Path(out_dir) / "split_report.json"
    return json.loads(p.read_text())

def _iter_batches(parquet_path: str, batch_size: int, columns=None):
    pf = pq.ParquetFile(parquet_path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=columns):
        yield batch.to_pandas()

def _dom_label_from_counter(counter: dict) -> str:
    attacks = {k:v for k,v in counter.items() if k not in BENIGN_LIKE and k != "BENIGN"}
    if attacks:
        return max(attacks.items(), key=lambda kv: kv[1])[0]
    return "BENIGN"

def build_group_table(in_parquet: str, batch_size: int):
    counters = defaultdict(lambda: defaultdict(int))
    sizes = defaultdict(int)

    cols = [SRC_COL, DST_COL, LABEL_COL]
    for df in _iter_batches(in_parquet, batch_size, columns=cols):
        df[SRC_COL] = df[SRC_COL].astype(str)
        df[DST_COL] = df[DST_COL].astype(str)
        labs = df[LABEL_COL].astype(str)
        grps = df[SRC_COL] + "||" + df[DST_COL]
        for g, lab in zip(grps.tolist(), labs.tolist()):
            sizes[g] += 1
            counters[g][str(lab)] += 1

    groups, doms, ns = [], [], []
    for g in sizes.keys():
        groups.append(g)
        doms.append(_dom_label_from_counter(counters[g]))
        ns.append(int(sizes[g]))

    return pd.DataFrame({"group": groups, "dom_label": doms, "n_rows": ns})


def _collapse_rare_for_stratify(y: pd.Series, min_count: int = 2, other: str = "RARE") -> pd.Series:
    """
    Return a copy of y where classes with <min_count are replaced by `other`.

    Sklearn stratified splitting requires every class in y to have at least 2 samples.
    We collapse ultra-rare classes to a shared bucket so we can still stratify
    without crashing. If stratification is still impossible, callers should fall back
    to non-stratified splits.
    """
    y = y.astype(str)
    vc = y.value_counts(dropna=False)
    rare = set(vc[vc < min_count].index.tolist())
    if not rare:
        return y
    return y.where(~y.isin(rare), other=other)

def _can_stratify(y: pd.Series, min_count: int = 2) -> bool:
    y = y.astype(str)
    if y.nunique(dropna=False) <= 1:
        return False
    vc = y.value_counts(dropna=False)
    return int(vc.min()) >= min_count

def _safe_train_test_split(df: pd.DataFrame, *, test_size: float, seed: int, y: pd.Series):
    """train_test_split with best-effort stratification.

    - Tries stratify on y
    - If y has rare classes, collapses them to RARE
    - If still impossible, falls back to non-stratified split
    """
    y0 = y.astype(str)
    y1 = _collapse_rare_for_stratify(y0, min_count=2, other="RARE")
    strat = y1 if _can_stratify(y1, min_count=2) else None
    return train_test_split(df, test_size=test_size, random_state=seed, stratify=strat)


def run_streaming(
    *,
    in_parquet: str,
    out_dir: str,
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    test_frac: float = 0.15,
    seed: int = 42,
    batch_size: int = 131072,
) -> Path:
    """Shared implementation for notebook and CLI: write train/val/test.parquet + split_report.json."""
    assert abs(train_frac + val_frac + test_frac - 1.0) < 1e-9

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("[*] Pass 1/2: building group table (streaming)...")
    grp_df = build_group_table(in_parquet, batch_size)

    # stratify groups by dominant label (best-effort)
    y = grp_df["dom_label"].astype(str)
    g_train, g_tmp = _safe_train_test_split(
        grp_df,
        test_size=(1 - train_frac),
        seed=seed,
        y=y,
    )

    val_size = val_frac / (val_frac + test_frac)
    y_tmp = g_tmp["dom_label"].astype(str)
    g_val, g_test = _safe_train_test_split(
        g_tmp,
        test_size=(1 - val_size),
        seed=seed,
        y=y_tmp,
    )

    split_map = {}
    for g in g_train["group"].tolist():
        split_map[g] = "train"
    for g in g_val["group"].tolist():
        split_map[g] = "val"
    for g in g_test["group"].tolist():
        split_map[g] = "test"

    # pass 2: stream and write
    print("[*] Pass 2/2: writing train/val/test (streaming)...")
    writers = {"train": None, "val": None, "test": None}
    schema = None
    counts = {"train": 0, "val": 0, "test": 0}

    for df in _iter_batches(in_parquet, batch_size, columns=None):
        df[SRC_COL] = df[SRC_COL].astype(str)
        df[DST_COL] = df[DST_COL].astype(str)
        grp = df[SRC_COL] + "||" + df[DST_COL]
        split = grp.map(split_map)

        if schema is None and len(df):
            schema = pa.Table.from_pandas(df.head(1), preserve_index=False).schema

        for s in ["train", "val", "test"]:
            sub = df[split == s]
            if len(sub):
                if writers[s] is None:
                    writers[s] = pq.ParquetWriter(
                        str(out / f"{s}.parquet"), schema=schema, compression="snappy"
                    )
                writers[s].write_table(pa.Table.from_pandas(sub, preserve_index=False))
                counts[s] += len(sub)

    for w in writers.values():
        if w:
            w.close()

    # reports (counts by label per split) via streaming value_counts
    def _vc(path: Path):
        pf = pq.ParquetFile(str(path))
        c = {}
        for batch in pf.iter_batches(batch_size=batch_size, columns=[LABEL_COL]):
            s = batch.column(0).to_pandas().astype(str)
            vc = s.value_counts(dropna=False)
            for k, v in vc.items():
                c[str(k)] = c.get(str(k), 0) + int(v)
        return c

    report = {s: _vc(out / f"{s}.parquet") for s in ["train", "val", "test"]}

    meta = {
        "protocol": "split_1_group_stratified_streaming",
        "seed": int(seed),
        "fractions": {"train": train_frac, "val": val_frac, "test": test_frac},
        "batch_size": int(batch_size),
        "group_table_rows": int(len(grp_df)),
        "rows": {k: int(v) for k, v in counts.items()},
        "dominant_label_group_counts": {
            k: int(v) for k, v in grp_df["dom_label"].value_counts().to_dict().items()
        },
        "splits": report,
        "notes": [
            "Groups are (orig_h, resp_h). All rows in a group go to the same split.",
            "Dominant label: any-attack-wins; otherwise BENIGN.",
            "Best-effort stratification: ultra-rare dominant labels are collapsed for stratify; if still impossible we fall back to non-stratified splits.",
            "LIMITATION: stratification is by group count, not row volume. Val/test may have very few attack rows if attack traffic is concentrated in few large groups. USE FOR LEAKAGE DIAGNOSTICS ONLY, not for headline metrics.",
        ],
    }
    (out / "split_report.json").write_text(json.dumps(meta, indent=2))
    print(f"[*] Written -> {out}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True)
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--train_frac", type=float, default=0.70)
    ap.add_argument("--val_frac", type=float, default=0.15)
    ap.add_argument("--test_frac", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--batch_size", type=int, default=131072)
    a = ap.parse_args()

    run_streaming(
        in_parquet=a.in_parquet,
        out_dir=a.out_dir,
        train_frac=a.train_frac,
        val_frac=a.val_frac,
        test_frac=a.test_frac,
        seed=a.seed,
        batch_size=a.batch_size,
    )

if __name__ == "__main__":
    main()
