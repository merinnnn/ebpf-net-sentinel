#!/usr/bin/env python3
"""
Builds a balanced-core dataset then splits it stratified 70/15/15.

This split is not leakage-controlled by design: it's for clean, readable
confusion matrices / macro-F1 comparisons under balanced class proportions.
Use Split 1 for leakage control.

Key features
- Memory-safe: streams Parquet in batches (does not load the full dataset).
- Sampling uses per-class reservoir sampling so RAM ~= O(quota x num_classes).

Output
Writes:
  train.parquet, val.parquet, test.parquet, split_report.json
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except Exception as e:  # pragma: no cover
    raise SystemExit("pyarrow is required for memory-safe splitting. Please `pip install pyarrow`.") from e

LABEL_COL   = "label_family"
BENIGN_LIKE = frozenset({"BENIGN", "Unknown", "nan", "NaN", ""})


# API used by notebooks
def run(
    *,
    in_parquet: str,
    out_dir: str,
    quota: int = 5000,
    benign_ratio: float = 1.0,
    equal: bool = False,
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    test_frac: float = 0.15,
    seed: int = 42,
    batch_size: int = 131072,
):
    """
    Entry point used by notebooks (in-process).

    Writes train/val/test.parquet + split_report.json into out_dir and returns Path(out_dir).
    """
    return write_split(
        in_parquet=str(in_parquet),
        out_dir=str(out_dir),
        quota=quota,
        benign_ratio=benign_ratio,
        equal=equal,
        train_frac=train_frac,
        val_frac=val_frac,
        test_frac=test_frac,
        seed=seed,
        batch_size=batch_size,
    )


def load_report(out_dir: str):
    """Load split_report.json as dict."""
    p = Path(out_dir) / "split_report.json"
    return json.loads(p.read_text())


# reservoir sampling
def _reservoir_update(res, k, row_dict, seen, rng):
    """Keep a uniform random sample of size k from a stream."""
    seen += 1
    if k <= 0:
        return res, seen
    if len(res) < k:
        res.append(row_dict)
    else:
        j = int(rng.integers(0, seen))
        if j < k:
            res[j] = row_dict
    return res, seen

# streaming helpers
def _iter_batches(parquet_path: str, batch_size: int, columns=None):
    pf = pq.ParquetFile(parquet_path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=columns):
        yield batch.to_pandas()

def _build_meta(seed, parts, **extra):
    total = sum(len(v) for v in parts.values())
    atk   = {s: int((~parts[s][LABEL_COL].astype(str).isin(BENIGN_LIKE)).sum())
             for s in parts}
    tr    = set(parts["train"][LABEL_COL].astype(str).unique()) - BENIGN_LIKE
    va    = set(parts["val"][LABEL_COL].astype(str).unique())   - BENIGN_LIKE
    te    = set(parts["test"][LABEL_COL].astype(str).unique())  - BENIGN_LIKE
    unseen = sorted(te - tr)
    return {
        "protocol": "split_2_balanced_quota_streaming",
        "seed": seed,
        "rows_total": int(total),
        "attack_rows": atk,
        "train_attack_families": sorted(tr),
        "val_attack_families": sorted(va),
        "test_attack_families": sorted(te),
        "unseen_in_train": unseen,
        **extra,
    }

def make_report(parts: dict) -> dict:
    rep = {}
    for k, df in parts.items():
        vc = df[LABEL_COL].astype(str).value_counts(dropna=False)
        rep[k] = {str(idx): int(v) for idx, v in vc.items()}
    return rep


def _collapse_rare_for_stratify(y: pd.Series, min_count: int = 2, other: str = "RARE") -> pd.Series:
    """Collapse ultra-rare classes so stratified splitting does not crash."""
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
    """Best-effort stratification with robust fallback for tiny datasets."""
    if len(df) == 0:
        return df.copy(), df.copy()
    if len(df) == 1:
        return df.iloc[0:0].copy(), df.copy()

    y0 = y.astype(str)
    y1 = _collapse_rare_for_stratify(y0, min_count=2, other="RARE")
    strat = y1 if _can_stratify(y1, min_count=2) else None
    try:
        return train_test_split(df, test_size=test_size, random_state=seed, stratify=strat)
    except ValueError:
        # Fallback for edge cases where sklearn still cannot split.
        n = len(df)
        n_test = int(round(float(test_size) * n))
        n_test = max(1, min(n - 1, n_test))
        rng = np.random.default_rng(seed)
        idx = np.arange(n)
        rng.shuffle(idx)
        te_idx = idx[:n_test]
        tr_idx = idx[n_test:]
        return df.iloc[tr_idx].copy(), df.iloc[te_idx].copy()

def run_streaming(in_parquet: str,
                  quota: int = 5000,
                  benign_ratio: float = 1.0,
                  equal: bool = False,
                  train_frac: float = 0.70,
                  val_frac: float = 0.15,
                  test_frac: float = 0.15,
                  seed: int = 42,
                  batch_size: int = 131072) -> dict:
    assert abs(train_frac + val_frac + test_frac - 1.0) < 1e-9

    rng = np.random.default_rng(seed)

    # pass 1: counts
    counts = {}
    benign_count = 0
    for df in _iter_batches(in_parquet, batch_size, columns=[LABEL_COL]):
        labels = df[LABEL_COL].astype(str)
        vc = labels.value_counts(dropna=False)
        for lab, n in vc.items():
            lab = str(lab)
            if lab in BENIGN_LIKE:
                continue
            counts[lab] = counts.get(lab, 0) + int(n)
        benign_count += int((labels == "BENIGN").sum())

    fams = sorted(counts.keys())
    if not fams:
        raise ValueError(f"No attack families found in {LABEL_COL}.")
    eff_q = min(quota, min(counts.values())) if equal else quota

    print(f"  Mode              : {'equal (all classes same size)' if equal else 'capped (each class up to quota)'}")
    print(f"  Requested quota   : {quota:,}")
    if equal:
        print(f"  Effective quota   : {eff_q:,}  (bottleneck: {min(counts, key=counts.get)}={min(counts.values())})")
    print(f"  BENIGN ratio      : {benign_ratio:.1f}x  (benign = ratio x total_attack_rows)")
    print()

    # Determine targets
    target = {}
    for fam in fams:
        if equal:
            target[fam] = min(eff_q, counts[fam])
        else:
            target[fam] = min(quota, counts[fam])

    total_attack_target = sum(target.values())
    target_benign = min(int(benign_ratio * total_attack_target), benign_count)

    # pass 2: reservoirs
    reservoirs = {fam: [] for fam in fams}
    seen = {fam: 0 for fam in fams}
    benign_res = []
    benign_seen = 0

    cols = None  # keep all columns for the output
    for df in _iter_batches(in_parquet, batch_size, columns=cols):
        labels = df[LABEL_COL].astype(str)

        # benign
        if target_benign > 0:
            ben = df[labels == "BENIGN"]
            if len(ben):
                for row in ben.to_dict(orient="records"):
                    benign_res, benign_seen = _reservoir_update(
                        benign_res, target_benign, row, benign_seen, rng
                    )

        # attacks
        for fam in fams:
            k = target[fam]
            if k <= 0:
                continue
            sub = df[labels == fam]
            if len(sub):
                for row in sub.to_dict(orient="records"):
                    reservoirs[fam], seen[fam] = _reservoir_update(
                        reservoirs[fam], k, row, seen[fam], rng
                    )

    parts = []
    for fam in fams:
        n_take = len(reservoirs[fam])
        flag = " <- ALL" if n_take == counts[fam] else ""
        print(f"    {fam:<22s}  have={counts[fam]:>7,}  take={n_take:>6,}{flag}")
        parts.append(pd.DataFrame(reservoirs[fam]))
    print(f"    {'BENIGN':<22s}  have={benign_count:>7,}  take={len(benign_res):>6,}  (ratio {benign_ratio:.1f}x)")

    parts.append(pd.DataFrame(benign_res))

    balanced = pd.concat(parts, ignore_index=True)
    balanced[LABEL_COL] = balanced[LABEL_COL].astype(str)

    # split stratified
    y = balanced[LABEL_COL].astype(str)
    train_df, temp_df = _safe_train_test_split(
        balanced,
        test_size=(1 - train_frac),
        seed=seed,
        y=y,
    )
    y_temp = temp_df[LABEL_COL].astype(str)
    val_size = val_frac / (val_frac + test_frac)
    val_df, test_df = _safe_train_test_split(
        temp_df,
        test_size=(1 - val_size),
        seed=seed,
        y=y_temp,
    )

    out_parts = {"train": train_df.reset_index(drop=True),
                 "val":   val_df.reset_index(drop=True),
                 "test":  test_df.reset_index(drop=True)}

    meta = _build_meta(seed, out_parts,
                      quota=int(quota), equal=bool(equal),
                      benign_ratio=float(benign_ratio),
                      targets={**{k:int(v) for k,v in target.items()}, "BENIGN": int(target_benign)},
                      batch_size=int(batch_size))
    return {**out_parts, "meta": meta}


def write_split(
    *,
    in_parquet: str,
    out_dir: str,
    quota: int = 5000,
    benign_ratio: float = 1.0,
    equal: bool = False,
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    test_frac: float = 0.15,
    seed: int = 42,
    batch_size: int = 131072,
) -> Path:
    """Helper used by notebooks: run streaming split and write Parquets + report."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    result = run_streaming(
        in_parquet,
        quota=quota,
        benign_ratio=benign_ratio,
        equal=equal,
        train_frac=train_frac,
        val_frac=val_frac,
        test_frac=test_frac,
        seed=seed,
        batch_size=batch_size,
    )

    for s in ["train", "val", "test"]:
        result[s].to_parquet(out / f"{s}.parquet", index=False)
    (out / "split_report.json").write_text(
        json.dumps({**result["meta"], "splits": make_report({k: result[k] for k in ["train","val","test"]})}, indent=2)
    )
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True)
    ap.add_argument("--out_dir",    required=True)
    ap.add_argument("--quota",      type=int,   default=5000)
    ap.add_argument("--benign_ratio", type=float, default=1.0)
    ap.add_argument("--equal",      action="store_true",
                    help="force all attack families to the same size (bottlenecked by smallest class)")
    ap.add_argument("--train_frac", type=float, default=0.70)
    ap.add_argument("--val_frac",   type=float, default=0.15)
    ap.add_argument("--test_frac",  type=float, default=0.15)
    ap.add_argument("--seed",       type=int,   default=42)
    ap.add_argument("--batch_size", type=int,   default=131072)
    a = ap.parse_args()

    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    result = run_streaming(
        a.in_parquet, a.quota, a.benign_ratio, a.equal,
        a.train_frac, a.val_frac, a.test_frac, a.seed, a.batch_size
    )
    for s in ["train", "val", "test"]:
        result[s].to_parquet(out / f"{s}.parquet", index=False)
    (out / "split_report.json").write_text(
        json.dumps({**result["meta"], "splits": make_report({k: result[k] for k in ["train","val","test"]})}, indent=2)
    )
    print(f"[*] Written -> {out}")

if __name__ == "__main__":
    main()
