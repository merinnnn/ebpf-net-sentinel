#!/usr/bin/env python3
"""
Produces:
- train          : Mon-Wed excluding any rows sampled into test_balanced
- val            : Thu untouched
- test_realistic : Fri untouched
- test_balanced  : quota-sampled per attack family across all days (+ BENIGN ratio)

Implementation is fully streaming (no full dataset in RAM).
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except Exception as e:  # pragma: no cover
    raise SystemExit("pyarrow is required. Please `pip install pyarrow`.") from e

LABEL_COL   = "label_family"
DAY_COL     = "day"
BENIGN_LIKE = frozenset({"BENIGN", "Unknown", "nan", "NaN", ""})

TRAIN_DAYS     = {"Monday", "Tuesday", "Wednesday"}
VAL_DAYS       = {"Thursday"}
REALISTIC_DAYS = {"Friday"}


# API used by notebooks
def run(
    df_or_parquet=None,
    *,
    in_parquet: str = None,
    out_dir: str,
    quota: int = 500,
    benign_ratio: float = 1.0,
    seed: int = 42,
    batch_size: int = 131072,
):
    """
    Entry point used by notebooks (in-process).

    Accepts either a DataFrame as the first positional argument (legacy API)
    or in_parquet as a keyword argument (current API).
    """
    import tempfile, os as _os

    if df_or_parquet is not None and hasattr(df_or_parquet, "to_parquet"):
        # Legacy: caller passed a DataFrame - write it to a temp file
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
        )
    finally:
        if _cleanup:
            _os.unlink(_in)


def load_report(out_dir: str):
    p = Path(out_dir) / "split_report.json"
    return json.loads(p.read_text())


def make_report(out_dir: str):

    p = Path(out_dir) / "split_report.json"
    return json.loads(p.read_text())

def _iter_batches(parquet_path: str, batch_size: int, columns=None):
    pf = pq.ParquetFile(parquet_path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=columns):
        yield batch.to_pandas()

def _reservoir_update(res, k, row_dict, row_id, seen, rng):
    """Reservoir sample of (row_id, row_dict)."""
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
    fam_counts = {}
    benign_count = 0
    day_counts = {}
    for df in _iter_batches(in_parquet, batch_size, columns=[LABEL_COL, DAY_COL]):
        labs = df[LABEL_COL].astype(str)
        days = df[DAY_COL].astype(str)

        vc = labs.value_counts(dropna=False)
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
    return pq.ParquetWriter(str(path), schema=schema, compression="snappy")


def _to_schema_table(df: pd.DataFrame, schema: pa.Schema) -> pa.Table:
    """
    Convert DataFrame to Arrow table and coerce dtypes to a fixed schema.

    Source parquet row-groups can surface slightly different integer dtypes
    (e.g. int8 vs int64). Casting avoids writer schema mismatch failures.
    """
    tbl = pa.Table.from_pandas(df, preserve_index=False)
    if tbl.schema != schema:
        tbl = tbl.cast(schema, safe=False)
    return tbl


def write_split(
    *,
    in_parquet: str,
    out_dir: str,
    quota: int = 500,
    benign_ratio: float = 1.0,
    seed: int = 42,
    batch_size: int = 131072,
) -> dict:
    """
    Helper used by notebooks: runs the full streaming split, writes all four
    parquet files + split_report.json, and returns a dict of DataFrames + meta.

    Returns {"train": df, "val": df, "test_balanced": df, "test_realistic": df, "meta": dict}.
    """
    import sys as _sys

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Temporarily redirect argv so main() can be called in-process
    _old_argv = _sys.argv
    _sys.argv = [
        "split_4_dual_eval",
        "--in_parquet",    str(in_parquet),
        "--out_dir",       str(out_dir),
        "--quota",         str(quota),
        "--benign_ratio",  str(benign_ratio),
        "--seed",          str(seed),
        "--batch_size",    str(batch_size),
    ]
    try:
        main()
    finally:
        _sys.argv = _old_argv

    train_df   = pd.read_parquet(out / "train.parquet")
    val_df     = pd.read_parquet(out / "val.parquet")
    test_bal   = pd.read_parquet(out / "test_balanced.parquet")
    test_real  = pd.read_parquet(out / "test_realistic.parquet")
    meta       = json.loads((out / "split_report.json").read_text())

    return {
        "train":          train_df,
        "val":            val_df,
        "test_balanced":  test_bal,
        "test_realistic": test_real,
        "meta":           meta,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True)
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--quota", type=int, default=500)
    ap.add_argument("--benign_ratio", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--batch_size", type=int, default=131072)
    a = ap.parse_args()

    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    rng = np.random.default_rng(a.seed)

    # pass 1: counts
    fam_counts, benign_count, day_counts = _counts_pass(a.in_parquet, a.batch_size)
    fams = sorted(fam_counts.keys())
    if not fams:
        raise SystemExit("No attack families found (label_family).")

    eff_q = min(a.quota, min(fam_counts.values()))
    target_benign = min(int(a.benign_ratio * (eff_q * len(fams))), benign_count)

    print(f"  Balanced test quota : {a.quota:,} -> effective: {eff_q:,} "
          f"(bottleneck: {min(fam_counts, key=fam_counts.get)}={min(fam_counts.values())})")
    print(f"  BENIGN in balanced  : {target_benign:,} (ratio {a.benign_ratio:.1f}x)")
    print()

    # pass 2: reservoir balanced test + write val/test_realistic
    res_by_fam = {f: [] for f in fams}
    seen_by_fam = {f: 0 for f in fams}
    benign_res = []
    benign_seen = 0

    val_writer = None
    real_writer = None
    schema = None

    row_id = 0
    for df in _iter_batches(a.in_parquet, a.batch_size, columns=None):
        df[DAY_COL] = df[DAY_COL].astype(str)
        labs = df[LABEL_COL].astype(str)

        if schema is None:
            schema = pa.Table.from_pandas(df.head(1), preserve_index=False).schema
            val_writer  = _ensure_writer(out / "val.parquet", schema)
            real_writer = _ensure_writer(out / "test_realistic.parquet", schema)

        # write val / realistic
        v = df[df[DAY_COL].isin(VAL_DAYS)]
        if len(v):
            val_writer.write_table(_to_schema_table(v, schema))
        r = df[df[DAY_COL].isin(REALISTIC_DAYS)]
        if len(r):
            real_writer.write_table(_to_schema_table(r, schema))

        # reservoir sampling (row-by-row once)
        for i, row in enumerate(df.to_dict(orient="records")):
            rid = row_id + i
            lab = str(row.get(LABEL_COL))
            if lab == "BENIGN" and target_benign > 0:
                benign_res, benign_seen = _reservoir_update(
                    benign_res, target_benign, row, rid, benign_seen, rng
                )
            elif lab in res_by_fam:
                res_by_fam[lab], seen_by_fam[lab] = _reservoir_update(
                    res_by_fam[lab], eff_q, row, rid, seen_by_fam[lab], rng
                )

        row_id += len(df)

    if val_writer:
        val_writer.close()
    if real_writer:
        real_writer.close()

    # build balanced test + exclusion set
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

    # pass 3: write train (Mon-Wed excluding sampled ids)
    train_writer = None
    row_id = 0
    for df in _iter_batches(a.in_parquet, a.batch_size, columns=None):
        df[DAY_COL] = df[DAY_COL].astype(str)
        if train_writer is None:
            # reuse schema from earlier if available
            if schema is None:
                schema = pa.Table.from_pandas(df.head(1), preserve_index=False).schema
            train_writer = _ensure_writer(out / "train.parquet", schema)

        days_mask = df[DAY_COL].isin(TRAIN_DAYS)
        if not days_mask.any():
            row_id += len(df)
            continue

        keep = []
        recs = df.to_dict(orient="records")
        for i, row in enumerate(recs):
            rid = row_id + i
            if rid in exclude_ids:
                continue
            if str(row.get(DAY_COL)) in TRAIN_DAYS:
                keep.append(row)

        if keep:
            tdf = pd.DataFrame(keep)
            train_writer.write_table(_to_schema_table(tdf, schema))

        row_id += len(df)

    if train_writer:
        train_writer.close()

    # report
    def _vc(path: Path):
        pf = pq.ParquetFile(str(path))
        # stream value counts
        counts = {}
        for batch in pf.iter_batches(batch_size=a.batch_size, columns=[LABEL_COL]):
            s = batch.column(0).to_pandas().astype(str)
            vc = s.value_counts(dropna=False)
            for k, v in vc.items():
                counts[str(k)] = counts.get(str(k), 0) + int(v)
        return counts

    report = {
        "train": _vc(out / "train.parquet"),
        "val": _vc(out / "val.parquet"),
        "test_balanced": _vc(out / "test_balanced.parquet"),
        "test_realistic": _vc(out / "test_realistic.parquet"),
    }

    meta = {
        "protocol": "split_4_dual_eval_streaming",
        "seed": int(a.seed),
        "quota": int(a.quota),
        "effective_quota": int(eff_q),
        "benign_ratio": float(a.benign_ratio),
        "batch_size": int(a.batch_size),
        "day_counts": {k: int(v) for k, v in day_counts.items()},
        "targets": {**{f: int(eff_q) for f in fams}, "BENIGN": int(target_benign)},
        "notes": {
            "train": "Mon-Wed excluding any rows sampled into test_balanced",
            "val": "Thu untouched",
            "test_balanced": "all days quota-sampled per family + benign ratio",
            "test_realistic": "Fri untouched",
        },
        "splits": report,
    }
    (out / "split_report.json").write_text(json.dumps(meta, indent=2))
    print(f"[*] Written -> {out}")

if __name__ == "__main__":
    main()
