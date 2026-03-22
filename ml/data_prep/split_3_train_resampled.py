#!/usr/bin/env python3
"""
Takes Split 1 output and rebalances only the training set.
val and test are passed through untouched (copied as-is).

Key features
- Memory-safe: streams Split-1 train.parquet in batches.
- Downsampling uses reservoir sampling; rare classes are kept fully then oversampled.
- Does not load val/test into RAM (file copy).

Output
Writes:
  train.parquet (rebalanced), val.parquet (copied), test.parquet (copied),
  split_report.json
"""

import argparse
import json
import shutil
from pathlib import Path

import numpy as np
import pandas as pd

import pyarrow.parquet as pq

LABEL_COL   = "label_family"
BENIGN_LIKE = frozenset({"BENIGN", "Unknown", "nan", "NaN", ""})


# API used by notebooks
def run(
    *,
    split1_dir: str,
    out_dir: str,
    target_n: int = 5000,
    benign_ratio: float = 3.0,
    seed: int = 42,
    batch_size: int = 131072,
):
    """
    Entry point used by notebooks (in-process).

    Rebalances ONLY Split-1 train.parquet, copies val/test untouched, and writes split_report.json.
    Returns Path(out_dir).
    """
    return write_split(
        split1_dir=str(split1_dir),
        out_dir=str(out_dir),
        target_n=target_n,
        benign_ratio=benign_ratio,
        seed=seed,
        batch_size=batch_size,
    )


def load_report(out_dir: str):
    """Load the JSON report for a previously written Split 3 directory."""
    p = Path(out_dir) / "split_report.json"
    return json.loads(p.read_text())


def _reservoir_update(res, k, row_dict, seen, rng):
    """Maintain a uniform reservoir sample from a streaming sequence of rows."""
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

def _iter_batches(parquet_path: str, batch_size: int, columns=None):
    """Yield the input parquet in pandas batches so the resampler stays memory-safe."""
    pf = pq.ParquetFile(parquet_path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=columns):
        yield batch.to_pandas()

def _value_counts_stream(parquet_path: str, col: str, batch_size: int):
    """Count values in one parquet column without reading the full file at once."""
    counts = {}
    for df in _iter_batches(parquet_path, batch_size, columns=[col]):
        vc = df[col].astype(str).value_counts(dropna=False)
        for k, v in vc.items():
            counts[str(k)] = counts.get(str(k), 0) + int(v)
    return counts

def resample_train_stream(train_parquet: str,
                          target_n: int = 5000,
                          benign_ratio: float = 3.0,
                          seed: int = 42,
                          batch_size: int = 131072) -> pd.DataFrame:
    """
    Rebalance the Split 1 training parquet while leaving evaluation data untouched.

    Small attack classes are kept in full and oversampled up to `target_n`. Larger
    classes are downsampled with a reservoir. BENIGN is sampled separately to the
    requested ratio relative to the attack total.
    """
    rng = np.random.default_rng(seed)

    # Pass 1 counts the current training distribution so we know which path each
    # family should take during resampling.
    counts = _value_counts_stream(train_parquet, LABEL_COL, batch_size)
    fams = sorted(set(counts.keys()) - BENIGN_LIKE - {"BENIGN"})
    benign_count = counts.get("BENIGN", 0)
    if not fams:
        raise ValueError("No attack families found in training set.")

    print(f"  target_n per family : {target_n:,}")
    print(f"  benign_ratio        : {benign_ratio:.1f}x")
    print()

    # Families at or below target_n can be kept in full before oversampling.
    keep_full = {f for f in fams if counts.get(f, 0) <= target_n}
    need_down = {f for f in fams if counts.get(f, 0) > target_n}

    # These families are small enough to keep in memory directly.
    full_rows = {f: [] for f in keep_full}

    # Larger families are capped with reservoir sampling.
    reservoirs = {f: [] for f in need_down}
    seen = {f: 0 for f in need_down}

    # BENIGN is sampled after we know the total target size for all attack families.
    total_attack_target = target_n * len(fams)
    target_benign = min(int(benign_ratio * total_attack_target), benign_count)
    benign_res = []
    benign_seen = 0

    # Pass 2 actually collects the rows using the strategy chosen above.
    for df in _iter_batches(train_parquet, batch_size, columns=None):
        labels = df[LABEL_COL].astype(str)

        # Sample BENIGN rows into its own reservoir.
        if target_benign > 0:
            ben = df[labels == "BENIGN"]
            if len(ben):
                for row in ben.to_dict(orient="records"):
                    benign_res, benign_seen = _reservoir_update(
                        benign_res, target_benign, row, benign_seen, rng
                    )

        # Either keep rows directly or feed them through a family-specific reservoir.
        for fam in fams:
            sub = df[labels == fam]
            if not len(sub):
                continue
            if fam in keep_full:
                full_rows[fam].extend(sub.to_dict(orient="records"))
            else:
                for row in sub.to_dict(orient="records"):
                    reservoirs[fam], seen[fam] = _reservoir_update(
                        reservoirs[fam], target_n, row, seen[fam], rng
                    )

    # Convert the collected rows into the final rebalanced training table.
    parts = []
    print("  Family resampling:")
    for fam in fams:
        n_have = counts.get(fam, 0)
        if fam in keep_full:
            base = pd.DataFrame(full_rows[fam])
            # Oversample the small family with replacement until it reaches target_n.
            if len(base) == 0:
                continue
            n_extra = max(0, target_n - len(base))
            if n_extra > 0:
                extra = base.sample(n=n_extra, replace=True, random_state=int(rng.integers(1e6)))
                samp = pd.concat([base, extra], ignore_index=True)
                action = "up oversample"
            else:
                samp = base
                action = "<- keep all"
        else:
            samp = pd.DataFrame(reservoirs[fam])
            action = "down downsample"

        parts.append(samp)
        print(f"    {fam:<22s}  {n_have:>6,} -> {len(samp):>6,}  {action}")

    # BENIGN is appended after the attack families so its size is easy to inspect.
    benign_df = pd.DataFrame(benign_res)
    print(f"    {'BENIGN':<22s}  {benign_count:>6,} -> {len(benign_df):>6,}  reservoir(sample)")
    parts.append(benign_df)

    train_new = pd.concat(parts, ignore_index=True)
    # Shuffle once at the end so the written parquet does not preserve class blocks.
    train_new = train_new.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return train_new

def write_split(
    *,
    split1_dir: str,
    out_dir: str,
    target_n: int = 5000,
    benign_ratio: float = 3.0,
    seed: int = 42,
    batch_size: int = 131072,
) -> dict:
    """
    Helper used by notebooks: resample train, copy val/test, write report.
    Returns the report metadata after all parquet artifacts are written.
    """
    split1 = Path(split1_dir)
    out    = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    train_p = split1 / "train.parquet"
    val_p   = split1 / "val.parquet"
    test_p  = split1 / "test.parquet"

    # Only the training split is resampled. Validation and test remain untouched.
    train_new = resample_train_stream(str(train_p), target_n, benign_ratio, seed, batch_size)
    train_new.to_parquet(out / "train.parquet", index=False)

    # Preserve the original evaluation splits exactly so comparisons stay honest.
    shutil.copy2(val_p, out / "val.parquet")
    shutil.copy2(test_p, out / "test.parquet")

    meta = {
        "protocol": "split_3_train_resampled_streaming",
        "seed": int(seed),
        "target_n": int(target_n),
        "benign_ratio": float(benign_ratio),
        "batch_size": int(batch_size),
        "source_split1": str(split1),
        "rows": {
            "train": int(len(train_new)),
            "val":   int(pq.ParquetFile(str(val_p)).metadata.num_rows),
            "test":  int(pq.ParquetFile(str(test_p)).metadata.num_rows),
        },
        "splits": make_report(train_new, str(val_p), str(test_p), batch_size),
    }
    (out / "split_report.json").write_text(json.dumps(meta, indent=2))
    return {
        **meta,
        "meta": meta,
        "paths": {
            "train": str(out / "train.parquet"),
            "val": str(out / "val.parquet"),
            "test": str(out / "test.parquet"),
            "report": str(out / "split_report.json"),
        },
    }


def make_report(train_df: pd.DataFrame, val_parquet: str, test_parquet: str, batch_size: int):
    """Return per-split label counts after the resampled training set is written."""
    rep = {}
    rep["train"] = {k: int(v) for k, v in train_df[LABEL_COL].astype(str).value_counts(dropna=False).items()}
    rep["val"]   = {k: int(v) for k, v in _value_counts_stream(val_parquet, LABEL_COL, batch_size).items()}
    rep["test"]  = {k: int(v) for k, v in _value_counts_stream(test_parquet, LABEL_COL, batch_size).items()}
    return rep

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split1_dir", required=True, help="Directory containing Split 1 outputs: train/val/test.parquet")
    ap.add_argument("--out_dir",    required=True)
    ap.add_argument("--target_n",   type=int,   default=5000)
    ap.add_argument("--benign_ratio", type=float, default=3.0)
    ap.add_argument("--seed",       type=int,   default=42)
    ap.add_argument("--batch_size", type=int,   default=131072)
    a = ap.parse_args()

    split1 = Path(a.split1_dir)
    out    = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    train_p = split1 / "train.parquet"
    val_p   = split1 / "val.parquet"
    test_p  = split1 / "test.parquet"
    for p in [train_p, val_p, test_p]:
        if not p.exists():
            raise SystemExit(f"Missing required file: {p}. Run split_1_group_stratified.py first.")

    print(f"[*] Rebalancing Split 1 train: {train_p}")
    train_new = resample_train_stream(str(train_p), a.target_n, a.benign_ratio, a.seed, a.batch_size)
    train_new.to_parquet(out / "train.parquet", index=False)

    # Copy validation and test directly from Split 1 to avoid unnecessary RAM use.
    shutil.copy2(val_p, out / "val.parquet")
    shutil.copy2(test_p, out / "test.parquet")

    meta = {
        "protocol": "split_3_train_resampled_streaming",
        "seed": int(a.seed),
        "target_n": int(a.target_n),
        "benign_ratio": float(a.benign_ratio),
        "batch_size": int(a.batch_size),
        "source_split1": str(split1),
        "rows": {
            "train": int(len(train_new)),
            "val":   int(pq.ParquetFile(str(val_p)).metadata.num_rows),
            "test":  int(pq.ParquetFile(str(test_p)).metadata.num_rows),
        },
        "splits": make_report(train_new, str(val_p), str(test_p), a.batch_size),
    }
    (out / "split_report.json").write_text(json.dumps(meta, indent=2))
    print(f"[*] Written -> {out}")

if __name__ == "__main__":
    main()
