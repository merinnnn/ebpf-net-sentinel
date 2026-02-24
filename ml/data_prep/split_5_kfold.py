#!/usr/bin/env python3
"""
Provides robust, repeated CV over groups (src,dst) to reduce session leakage.
This is mainly for analysis / statistical stability checks.

Important
Materialising full train+test parquet for every fold is huge (and was the main
OOM/disk blow-up in the previous implementation). This version:

- streams the dataset to build a group table (no full df in RAM)
- computes repeated stratified folds over groups
- writes ONLY:
    * folds.json  (group lists per fold)
    * folds_meta.json (size + unseen classes diagnostics per fold)
- optionally writes each fold's **test.parquet** (small-ish) if you pass
  --write_test_parquet. Train can be defined as "all rows not in test groups".

If you truly need materialised train.parquet too, do it for ONE fold at a time
using the group lists (see notes in folds.json), not for all folds at once.
"""

import argparse
import json
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.model_selection import RepeatedStratifiedKFold, KFold

try:
    import pyarrow.parquet as pq
    import pyarrow as pa
except Exception as e:  # pragma: no cover
    raise SystemExit("pyarrow is required. Please `pip install pyarrow`.") from e

LABEL_COL   = "label_family"
SRC_COL     = "orig_h"
DST_COL     = "resp_h"
BENIGN_LIKE = frozenset({"BENIGN", "Unknown", "nan", "NaN", ""})


def _iter_repeated_splits(groups, y_grp, n_splits: int, n_repeats: int, seed: int):
    """
    Yield repeated fold indices with stratification when feasible.

    If a dominant-label class has fewer groups than n_splits, we cannot use
    RepeatedStratifiedKFold. In that case, fall back to repeated shuffled KFold.
    """
    n_groups = len(groups)
    if n_groups < 2:
        raise ValueError(f"Need at least 2 groups for k-fold, got {n_groups}.")

    eff_splits = min(int(n_splits), int(n_groups))
    if eff_splits < n_splits:
        print(f"[!] Requested n_splits={n_splits}, but only {n_groups} groups available; using n_splits={eff_splits}.")
    n_splits = eff_splits

    fam_counts = pd.Series(y_grp).value_counts().to_dict()
    min_cls = min(fam_counts.values())

    if min_cls >= n_splits:
        splitter = RepeatedStratifiedKFold(
            n_splits=n_splits, n_repeats=n_repeats, random_state=seed
        )
        for fold_idx, (tr_idx, te_idx) in enumerate(splitter.split(groups, y_grp)):
            yield fold_idx, tr_idx, te_idx, "stratified", n_splits
        return

    print(
        f"[!] Smallest dominant-label group count is {min_cls}; "
        f"falling back to repeated shuffled KFold (non-stratified)."
    )
    n = len(groups)
    idx = np.arange(n)
    fold_idx = 0
    for rep in range(n_repeats):
        kf = KFold(n_splits=n_splits, shuffle=True, random_state=seed + rep)
        for tr_idx, te_idx in kf.split(idx):
            yield fold_idx, tr_idx, te_idx, "kfold", n_splits
            fold_idx += 1


# API used by notebooks
def run(
    df_or_parquet=None,
    *,
    in_parquet: str = None,
    out_dir: str = None,
    n_splits: int = 5,
    n_repeats: int = 3,
    seed: int = 42,
    batch_size: int = 131072,
    write_test_parquet: bool = False,
):
    """
    Entry point used by notebooks (in-process).

    Accepts either a DataFrame as the first positional argument (legacy API)
    or in_parquet/out_dir as keyword arguments (current API).
    When a DataFrame is passed, out_dir defaults to a temp directory.
    """
    import tempfile, os as _os

    if df_or_parquet is not None and hasattr(df_or_parquet, "to_parquet"):
        # Legacy: caller passed a DataFrame
        tmp_parquet = tempfile.NamedTemporaryFile(suffix=".parquet", delete=False)
        tmp_parquet.close()
        df_or_parquet.to_parquet(tmp_parquet.name, index=False)
        _in = tmp_parquet.name
        _cleanup_parquet = True
    else:
        _in = str(df_or_parquet) if df_or_parquet is not None else str(in_parquet)
        _cleanup_parquet = False

    # out_dir: use temp dir if not provided (caller will write folds themselves)
    if out_dir is None:
        tmp_dir = tempfile.mkdtemp()
        _in_out = tmp_dir
        _cleanup_dir = False  # caller's responsibility
    else:
        _in_out = str(out_dir)
        _cleanup_dir = False

    try:
        return run_streaming(
            in_parquet=_in,
            out_dir=_in_out,
            n_splits=n_splits,
            n_repeats=n_repeats,
            seed=seed,
            batch_size=batch_size,
            write_test_parquet=write_test_parquet,
        )
    finally:
        if _cleanup_parquet:
            _os.unlink(_in)


def run_streaming(
    *,
    in_parquet: str,
    out_dir: str,
    n_splits: int = 5,
    n_repeats: int = 3,
    seed: int = 42,
    batch_size: int = 131072,
    write_test_parquet: bool = False,
) -> dict:
    """
    Run the full k-fold split, materialise each fold's train+test parquets,
    and return {"folds": [...], "meta": {...}} matching the notebook's expected shape.

    Each fold dict contains:
      "name", "train" (DataFrame), "test" (DataFrame),
      "train_rows", "test_rows", "test_attacks", "unseen_in_train"

    meta contains: total_folds, n_splits, n_repeats, folds (list of fold metadata)
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("[*] Building group table (streaming)\u2026")
    grp_df = build_group_table(in_parquet, batch_size)

    groups = grp_df["group"].values
    y_grp  = grp_df["dom_label"].values

    # Build split_map per fold by streaming - collect group sets first
    fold_defs = []
    split_mode = "stratified"
    eff_splits = n_splits
    for fold_idx, tr_idx, te_idx, mode, cur_splits in _iter_repeated_splits(
        groups, y_grp, n_splits=n_splits, n_repeats=n_repeats, seed=seed
    ):
        eff_splits = cur_splits
        split_mode = mode
        rep_n  = fold_idx // eff_splits
        split  = fold_idx % eff_splits
        name   = f"fold_{split:02d}_rep{rep_n}"
        tr_set = set(groups[tr_idx].tolist())
        te_set = set(groups[te_idx].tolist())
        tr_labels = set(y_grp[tr_idx])
        te_labels = set(y_grp[te_idx])
        fold_defs.append({
            "name":      name,
            "tr_groups": tr_set,
            "te_groups": te_set,
            "unseen":    sorted(te_labels - tr_labels),
        })

    # Stream the dataset ONCE per fold (memory-safe: only one fold in RAM at a time)
    BENIGN_SET = frozenset({"BENIGN", "Unknown", "nan", "NaN", ""})
    result_folds = []
    for fd in fold_defs:
        print(f"  Materialising {fd['name']}\u2026")
        tr_rows, te_rows = [], []
        for df in _iter_batches(in_parquet, batch_size):
            df[SRC_COL] = df[SRC_COL].astype(str)
            df[DST_COL] = df[DST_COL].astype(str)
            grp_col = df[SRC_COL] + "||" + df[DST_COL]
            tr_mask = grp_col.isin(fd["tr_groups"])
            te_mask = grp_col.isin(fd["te_groups"])
            if tr_mask.any():
                tr_rows.append(df[tr_mask])
            if te_mask.any():
                te_rows.append(df[te_mask])

        train_df = pd.concat(tr_rows, ignore_index=True) if tr_rows else pd.DataFrame()
        test_df  = pd.concat(te_rows, ignore_index=True) if te_rows else pd.DataFrame()

        test_attacks = int((~test_df[LABEL_COL].astype(str).isin(BENIGN_SET)).sum()) if len(test_df) else 0

        result_folds.append({
            "name":          fd["name"],
            "train":         train_df,
            "test":          test_df,
            "train_rows":    int(len(train_df)),
            "test_rows":     int(len(test_df)),
            "test_attacks":  test_attacks,
            "unseen_in_train": fd["unseen"],
        })

    total_folds = eff_splits * n_repeats
    meta = {
        "total_folds": total_folds,
        "n_splits":    eff_splits,
        "requested_n_splits": n_splits,
        "n_repeats":   n_repeats,
        "seed":        seed,
        "split_mode":  split_mode,
        "folds": [
            {
                "fold":          f["name"],
                "train_rows":    f["train_rows"],
                "test_rows":     f["test_rows"],
                "test_attacks":  f["test_attacks"],
                "unseen_in_train": f["unseen_in_train"],
            }
            for f in result_folds
        ],
    }
    return {"folds": result_folds, "meta": meta}


def run_metadata_streaming(
    *,
    in_parquet: str,
    out_dir: str,
    n_splits: int = 5,
    n_repeats: int = 3,
    seed: int = 42,
    batch_size: int = 131072,
) -> dict:
    """
    Memory-safe k-fold run that computes metadata only.

    Does not materialize fold train/test DataFrames in RAM.
    Returns {"folds": [], "meta": {...}} where meta["folds"] has per-fold stats.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("[*] Building group table (streaming)...")
    grp_df = build_group_table(in_parquet, batch_size)
    groups = grp_df["group"].values
    y_grp = grp_df["dom_label"].values

    fold_defs = []
    split_mode = "stratified"
    eff_splits = n_splits
    for fold_idx, tr_idx, te_idx, mode, cur_splits in _iter_repeated_splits(
        groups, y_grp, n_splits=n_splits, n_repeats=n_repeats, seed=seed
    ):
        eff_splits = cur_splits
        split_mode = mode
        rep_n = fold_idx // eff_splits
        split = fold_idx % eff_splits
        name = f"fold_{split:02d}_rep{rep_n}"
        tr_set = set(groups[tr_idx].tolist())
        te_set = set(groups[te_idx].tolist())
        tr_labels = set(y_grp[tr_idx])
        te_labels = set(y_grp[te_idx])
        fold_defs.append(
            {
                "name": name,
                "tr_groups": tr_set,
                "te_groups": te_set,
                "unseen": sorted(te_labels - tr_labels),
            }
        )

    benign_set = frozenset({"BENIGN", "Unknown", "nan", "NaN", ""})
    meta_folds = []
    for fd in fold_defs:
        print(f"  Counting {fd['name']}...")
        train_rows = 0
        test_rows = 0
        test_attacks = 0
        for df in _iter_batches(in_parquet, batch_size):
            df[SRC_COL] = df[SRC_COL].astype(str)
            df[DST_COL] = df[DST_COL].astype(str)
            grp_col = df[SRC_COL] + "||" + df[DST_COL]
            tr_mask = grp_col.isin(fd["tr_groups"])
            te_mask = grp_col.isin(fd["te_groups"])
            if tr_mask.any():
                train_rows += int(tr_mask.sum())
            if te_mask.any():
                te_df = df[te_mask]
                test_rows += int(len(te_df))
                test_attacks += int((~te_df[LABEL_COL].astype(str).isin(benign_set)).sum())

        meta_folds.append(
            {
                "fold": fd["name"],
                "train_rows": int(train_rows),
                "test_rows": int(test_rows),
                "test_attacks": int(test_attacks),
                "unseen_in_train": fd["unseen"],
            }
        )

    total_folds = eff_splits * n_repeats
    meta = {
        "total_folds": total_folds,
        "n_splits": eff_splits,
        "requested_n_splits": n_splits,
        "n_repeats": n_repeats,
        "seed": seed,
        "split_mode": split_mode,
        "folds": meta_folds,
    }
    return {"folds": [], "meta": meta}


def make_report(out_dir: str):
    """Load folds_meta.json if present; else folds.json."""
    out = Path(out_dir)
    meta = out / "folds_meta.json"
    if meta.exists():
        return json.loads(meta.read_text())
    return json.loads((out / "folds.json").read_text())

def _iter_batches(parquet_path: str, batch_size: int, columns=None):
    pf = pq.ParquetFile(parquet_path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=columns):
        yield batch.to_pandas()

def _dom_label_from_counter(counter: dict) -> str:
    """
    Dominant label for a group:
       - if any attack present: most frequent attack label
       - else: BENIGN
    """
    attacks = {k:v for k,v in counter.items() if k not in BENIGN_LIKE and k != "BENIGN"}
    if attacks:
        return max(attacks.items(), key=lambda kv: kv[1])[0]
    return "BENIGN"

def build_group_table(in_parquet: str, batch_size: int):
    # group -> label_counter + n
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

    groups = []
    y = []
    n = []
    for g in sizes.keys():
        dom = _dom_label_from_counter(counters[g])
        groups.append(g)
        y.append(dom)
        n.append(int(sizes[g]))

    grp_df = pd.DataFrame({"group": groups, "dom_label": y, "n_rows": n})
    return grp_df

def maybe_write_fold_tests(in_parquet: str, out_dir: Path, folds: list, batch_size: int):
    """Optionally write fold test.parquet per fold by streaming + filtering groups."""
    pf = pq.ParquetFile(in_parquet)
    schema = None

    for fold in folds:
        name = fold["name"]
        test_groups = set(fold["test_groups"])
        out_path = out_dir / name / "test.parquet"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        writer = None
        for batch in pf.iter_batches(batch_size=batch_size):
            tbl = pa.Table.from_batches([batch])
            df = tbl.to_pandas()
            df[SRC_COL] = df[SRC_COL].astype(str)
            df[DST_COL] = df[DST_COL].astype(str)
            g = df[SRC_COL] + "||" + df[DST_COL]
            keep = df[g.isin(test_groups)]
            if len(keep):
                if writer is None:
                    schema = pa.Table.from_pandas(keep.head(1), preserve_index=False).schema
                    writer = pq.ParquetWriter(str(out_path), schema=schema, compression="snappy")
                writer.write_table(pa.Table.from_pandas(keep, preserve_index=False))
        if writer:
            writer.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True)
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--n_splits", type=int, default=5)
    ap.add_argument("--n_repeats", type=int, default=3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--batch_size", type=int, default=131072)
    ap.add_argument("--write_test_parquet", action="store_true",
                    help="Optionally materialise each fold's test.parquet (train is implicit).")
    a = ap.parse_args()

    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("[*] Building group table (streaming)...")
    grp_df = build_group_table(a.in_parquet, a.batch_size)

    fam_counts = grp_df["dom_label"].value_counts().to_dict()
    groups = grp_df["group"].values
    y_grp  = grp_df["dom_label"].values

    folds = []
    folds_meta = []
    split_mode = "stratified"

    eff_splits = a.n_splits
    for fold_idx, tr_idx, te_idx, mode, cur_splits in _iter_repeated_splits(
        groups, y_grp, n_splits=a.n_splits, n_repeats=a.n_repeats, seed=a.seed
    ):
        eff_splits = cur_splits
        split_mode = mode
        rep   = fold_idx // eff_splits
        split = fold_idx % eff_splits
        name  = f"fold_{split:02d}_rep{rep}"

        train_groups = groups[tr_idx].tolist()
        test_groups  = groups[te_idx].tolist()

        # unseen dominant labels diagnostic
        tr_labels = set(y_grp[tr_idx])
        te_labels = set(y_grp[te_idx])
        unseen = sorted(te_labels - tr_labels)

        folds.append({"name": name, "train_groups": train_groups, "test_groups": test_groups})
        folds_meta.append({
            "fold": name,
            "repeat": int(rep),
            "split": int(split),
            "train_groups": int(len(train_groups)),
            "test_groups": int(len(test_groups)),
            "unseen_dom_labels_in_train": unseen,
        })

    (out / "folds.json").write_text(json.dumps(folds, indent=2))
    (out / "folds_meta.json").write_text(json.dumps({
        "protocol": "split_5_kfold_groups_streaming",
        "seed": int(a.seed),
        "n_splits": int(eff_splits),
        "requested_n_splits": int(a.n_splits),
        "n_repeats": int(a.n_repeats),
        "split_mode": split_mode,
        "batch_size": int(a.batch_size),
        "group_table_rows": int(len(grp_df)),
        "dominant_label_group_counts": {k:int(v) for k,v in fam_counts.items()},
        "folds": folds_meta,
        "notes": [
            "This split stores group membership only (folds.json).",
            "Define train rows as 'not in test_groups' for a fold.",
            "Materialising train.parquet for every fold is intentionally avoided."
        ]
    }, indent=2))

    if a.write_test_parquet:
        print("[*] Writing per-fold test.parquet (streaming)...")
        maybe_write_fold_tests(a.in_parquet, out, folds, a.batch_size)

    print(f"[*] Written -> {out}")

if __name__ == "__main__":
    main()
