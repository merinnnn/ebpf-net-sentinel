#!/usr/bin/env python3
"""Dual-eval split: produces a balanced test set (fixed per-class quota) and a realistic test set (held-out day)."""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

import pyarrow as pa
import pyarrow.parquet as pq

LABEL_COL   = "label_family"
DAY_COL     = "day"
BENIGN_LIKE = frozenset({"BENIGN", "Unknown", "nan", "NaN", ""})

TRAIN_DAYS     = {"Monday", "Tuesday", "Wednesday"}
VAL_DAYS       = {"Thursday"}
REALISTIC_DAYS = {"Friday"}


def run(
    df_or_parquet=None,
    *,
    in_parquet: str = None,
    out_dir: str,
    quota: int          = 500,
    benign_ratio: float = 1.0,
    seed: int           = 104,
    batch_size: int     = 131072,
    min_effective_quota: int = 1,
):
    """
    Notebook entry point. Accepts a DataFrame (legacy) or in_parquet path.
    """
    import tempfile, os as _os

    if df_or_parquet is not None and hasattr(df_or_parquet, "to_parquet"):
        tmp = tempfile.NamedTemporaryFile(suffix=".parquet", delete=False)
        tmp.close()
        df_or_parquet.to_parquet(tmp.name, index=False)
        _in = tmp.name
        _cleanup = True
    else:
        _in = str(df_or_parquet) if df_or_parquet is not None else str(in_parquet)
        _cleanup = False

    try:
        return write_split(
            in_parquet=_in,
            out_dir=str(out_dir),
            quota=quota,
            benign_ratio=benign_ratio,
            seed=seed,
            batch_size=batch_size,
            min_effective_quota=min_effective_quota,
        )
    finally:
        if _cleanup:
            _os.unlink(_in)


def load_report(out_dir: str):
    """Load the split report for a previously written Split 4 directory."""
    p = Path(out_dir) / "split_report.json"
    return json.loads(p.read_text())

def make_report(out_dir: str):
    """Backward-compatible alias that returns the written JSON report."""
    return load_report(out_dir)

def _iter_batches(parquet_path: str, batch_size: int, columns=None):
    """Yield parquet data in pandas batches."""
    pf = pq.ParquetFile(parquet_path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=columns):
        yield batch.to_pandas()

def _reservoir_update(res, k, row_dict, row_id, seen, rng):
    """Reservoir sample of (row_id, row_dict) pairs."""
    seen += 1
    if k <= 0:
        return res, seen
    item = (row_id, row_dict)
    if len(res) < k:
        res.append(item)
    else:
        j = int(rng.integers(0, seen))
        if j < k:
            res[j] = item
    return res, seen

def _counts_pass(in_parquet: str, batch_size: int):
    """Count attack families, BENIGN rows, and day totals in one streaming pass."""
    fam_counts   = {}
    benign_count = 0
    day_counts   = {}
    for df in _iter_batches(in_parquet, batch_size, columns=[LABEL_COL, DAY_COL]):
        labs = df[LABEL_COL].astype(str)
        days = df[DAY_COL].astype(str)
        vc   = labs.value_counts(dropna=False)
        for k, v in vc.items():
            k = str(k)
            if k in BENIGN_LIKE:
                continue
            fam_counts[k] = fam_counts.get(k, 0) + int(v)
        benign_count += int((labs == "BENIGN").sum())
        dvc = days.value_counts(dropna=False)
        for d, v in dvc.items():
            day_counts[str(d)] = day_counts.get(str(d), 0) + int(v)
    return fam_counts, benign_count, day_counts

def _ensure_writer(path: Path, schema: pa.Schema):
    """Create a Snappy-compressed parquet writer."""
    return pq.ParquetWriter(str(path), schema=schema, compression="snappy")

def _to_schema_table(df: pd.DataFrame, schema: pa.Schema) -> pa.Table:
    """Convert DataFrame to Arrow table, coercing dtypes to the fixed schema."""
    tbl = pa.Table.from_pandas(df, preserve_index=False)
    if tbl.schema != schema:
        tbl = tbl.cast(schema, safe=False)
    return tbl


def write_split(
    *,
    in_parquet: str,
    out_dir: str,
    quota: int          = 500,
    benign_ratio: float = 1.0,
    seed: int           = 104,
    batch_size: int     = 131072,
    min_effective_quota: int = 1,
) -> dict:
    """Notebook helper: runs the full streaming split and returns the report metadata."""
    import sys as _sys

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    _old_argv = _sys.argv
    _sys.argv = [
        "split_4_dual_eval",
        "--in_parquet",         str(in_parquet),
        "--out_dir",            str(out_dir),
        "--quota",              str(quota),
        "--benign_ratio",       str(benign_ratio),
        "--seed",               str(seed),
        "--batch_size",         str(batch_size),
        "--min_effective_quota", str(min_effective_quota),
    ]
    try:
        main()
    finally:
        _sys.argv = _old_argv

    meta = json.loads((out / "split_report.json").read_text())
    return {
        **meta,
        "paths": {
            "train":          str(out / "train.parquet"),
            "val":            str(out / "val.parquet"),
            "test_balanced":  str(out / "test_balanced.parquet"),
            "test_realistic": str(out / "test_realistic.parquet"),
            "report":         str(out / "split_report.json"),
        },
    }

def main():
    """CLI entry point. Parses arguments and runs the dual-eval split builder."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet",         required=True)
    ap.add_argument("--out_dir",            required=True)
    ap.add_argument("--quota",              type=int,   default=500)
    ap.add_argument("--benign_ratio",       type=float, default=1.0)
    ap.add_argument("--seed",               type=int,   default=104)
    ap.add_argument("--batch_size",         type=int,   default=131072)
    ap.add_argument("--min_effective_quota", type=int,  default=50,
                    help="fail if effective quota drops below this (prevents tiny balanced tests)")
    a = ap.parse_args()

    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(a.seed)

    # Pass 1: determine effective quota from the smallest attack family.
    fam_counts, benign_count, day_counts = _counts_pass(a.in_parquet, a.batch_size)
    fams = sorted(fam_counts.keys())
    if not fams:
        raise SystemExit("No attack families found (label_family).")

    eff_q = min(a.quota, min(fam_counts.values()))
    if eff_q < a.min_effective_quota:
        raise SystemExit(
            f"Effective quota is {eff_q}, below --min_effective_quota={a.min_effective_quota}. "
            "Regenerate with a larger quota or check labels."
        )
    target_benign = min(int(a.benign_ratio * (eff_q * len(fams))), benign_count)

    print(f"  Balanced test quota : {a.quota:,} -> effective: {eff_q:,} "
          f"(bottleneck: {min(fam_counts, key=fam_counts.get)}={min(fam_counts.values())})")
    print(f"  BENIGN in balanced  : {target_benign:,} (ratio {a.benign_ratio:.1f}x)")
    print()

    # Pass 2: reservoir-sample balanced test, stream Thursday val and Friday realistic test.
    res_by_fam  = {f: [] for f in fams}
    seen_by_fam = {f: 0 for f in fams}
    benign_res  = []
    benign_seen = 0

    val_writer  = None
    real_writer = None
    schema      = None

    row_id = 0
    for df in _iter_batches(a.in_parquet, a.batch_size, columns=None):
        df[DAY_COL] = df[DAY_COL].astype(str)
        labs = df[LABEL_COL].astype(str)

        if schema is None:
            schema     = pa.Table.from_pandas(df.head(1), preserve_index=False).schema
            val_writer  = _ensure_writer(out / "val.parquet",           schema)
            real_writer = _ensure_writer(out / "test_realistic.parquet", schema)

        v = df[df[DAY_COL].isin(VAL_DAYS)]
        if len(v):
            val_writer.write_table(_to_schema_table(v, schema))
        r = df[df[DAY_COL].isin(REALISTIC_DAYS)]
        if len(r):
            real_writer.write_table(_to_schema_table(r, schema))

        for i, row in enumerate(df.to_dict(orient="records")):
            rid = row_id + i
            lab = str(row.get(LABEL_COL))
            if lab == "BENIGN" and target_benign > 0:
                benign_res, benign_seen = _reservoir_update(benign_res, target_benign, row, rid, benign_seen, rng)
            elif lab in res_by_fam:
                res_by_fam[lab], seen_by_fam[lab] = _reservoir_update(
                    res_by_fam[lab], eff_q, row, rid, seen_by_fam[lab], rng
                )

        row_id += len(df)

    if val_writer:
        val_writer.close()
    if real_writer:
        real_writer.close()

    # Write balanced test and record every sampled row id to exclude from training.
    exclude_ids = set()
    parts = []
    for fam in fams:
        items = res_by_fam[fam]
        exclude_ids.update(rid for rid, _ in items)
        parts.append(pd.DataFrame([r for _, r in items]))
    exclude_ids.update(rid for rid, _ in benign_res)
    parts.append(pd.DataFrame([r for _, r in benign_res]))
    test_bal = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()
    test_bal.to_parquet(out / "test_balanced.parquet", index=False)

    # Pass 3: write Mon-Wed training rows, skipping any row in the balanced test.
    train_writer = None
    row_id = 0
    for df in _iter_batches(a.in_parquet, a.batch_size, columns=None):
        df[DAY_COL] = df[DAY_COL].astype(str)
        if train_writer is None:
            if schema is None:
                schema = pa.Table.from_pandas(df.head(1), preserve_index=False).schema
            train_writer = _ensure_writer(out / "train.parquet", schema)

        if not df[DAY_COL].isin(TRAIN_DAYS).any():
            row_id += len(df)
            continue

        keep = [
            row for i, row in enumerate(df.to_dict(orient="records"))
            if (row_id + i) not in exclude_ids and str(row.get(DAY_COL)) in TRAIN_DAYS
        ]
        if keep:
            train_writer.write_table(_to_schema_table(pd.DataFrame(keep), schema))

        row_id += len(df)

    if train_writer:
        train_writer.close()

    def _vc(path: Path):
        pf     = pq.ParquetFile(str(path))
        counts = {}
        for batch in pf.iter_batches(batch_size=a.batch_size, columns=[LABEL_COL]):
            s  = batch.column(0).to_pandas().astype(str)
            vc = s.value_counts(dropna=False)
            for k, v in vc.items():
                counts[str(k)] = counts.get(str(k), 0) + int(v)
        return counts

    report = {
        "train":          _vc(out / "train.parquet"),
        "val":            _vc(out / "val.parquet"),
        "test_balanced":  _vc(out / "test_balanced.parquet"),
        "test_realistic": _vc(out / "test_realistic.parquet"),
    }

    meta = {
        "protocol":        "split_4_dual_eval_streaming",
        "seed":            int(a.seed),
        "quota":           int(a.quota),
        "effective_quota": int(eff_q),
        "benign_ratio":    float(a.benign_ratio),
        "batch_size":      int(a.batch_size),
        "day_counts":      {k: int(v) for k, v in day_counts.items()},
        "targets":         {**{f: int(eff_q) for f in fams}, "BENIGN": int(target_benign)},
        "notes": {
            "train":          "Mon-Wed excluding rows sampled into test_balanced",
            "val":            "Thu untouched",
            "test_balanced":  "all days quota-sampled per family + benign ratio",
            "test_realistic": "Fri untouched",
        },
        "splits": report,
    }
    (out / "split_report.json").write_text(json.dumps(meta, indent=2))
    print(f"[*] Written -> {out}")

if __name__ == "__main__":
    main()
