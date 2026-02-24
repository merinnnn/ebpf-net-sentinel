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

try:
    import pyarrow.parquet as pq
except Exception as e:  # pragma: no cover
    raise SystemExit("pyarrow is required for memory-safe resampling. Please `pip install pyarrow`.") from e

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
    p = Path(out_dir) / "split_report.json"
    return json.loads(p.read_text())


def _reservoir_update(res, k, row_dict, seen, rng):
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
    pf = pq.ParquetFile(parquet_path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=columns):
        yield batch.to_pandas()

def _value_counts_stream(parquet_path: str, col: str, batch_size: int):
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
    rng = np.random.default_rng(seed)

    # pass 1: counts
    counts = _value_counts_stream(train_parquet, LABEL_COL, batch_size)
    fams = sorted(set(counts.keys()) - BENIGN_LIKE - {"BENIGN"})
    benign_count = counts.get("BENIGN", 0)
    if not fams:
        raise ValueError("No attack families found in training set.")

    print(f"  target_n per family : {target_n:,}")
    print(f"  benign_ratio        : {benign_ratio:.1f}x")
    print()

    # decide which families need reservoir vs full-keep
    keep_full = {f for f in fams if counts.get(f, 0) <= target_n}
    need_down = {f for f in fams if counts.get(f, 0) > target_n}

    # collect small classes fully (still small)
    full_rows = {f: [] for f in keep_full}

    # reservoirs for big classes
    reservoirs = {f: [] for f in need_down}
    seen = {f: 0 for f in need_down}

    # benign reservoir (size decided after attack resampling target)
    total_attack_target = target_n * len(fams)
    target_benign = min(int(benign_ratio * total_attack_target), benign_count)
    benign_res = []
    benign_seen = 0

    # pass 2: stream and fill
    for df in _iter_batches(train_parquet, batch_size, columns=None):
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

    # build resampled attack parts
    parts = []
    print("  Family resampling:")
    for fam in fams:
        n_have = counts.get(fam, 0)
        if fam in keep_full:
            base = pd.DataFrame(full_rows[fam])
            # oversample with replacement to reach target_n
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

    # benign
    benign_df = pd.DataFrame(benign_res)
    print(f"    {'BENIGN':<22s}  {benign_count:>6,} -> {len(benign_df):>6,}  reservoir(sample)")
    parts.append(benign_df)

    train_new = pd.concat(parts, ignore_index=True)
    # shuffle
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
    Returns {"train": df, "val": df, "test": df, "meta": dict}.
    """
    split1 = Path(split1_dir)
    out    = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    train_p = split1 / "train.parquet"
    val_p   = split1 / "val.parquet"
    test_p  = split1 / "test.parquet"

    train_new = resample_train_stream(str(train_p), target_n, benign_ratio, seed, batch_size)

    # copy val/test unchanged
    shutil.copy2(val_p, out / "val.parquet")
    shutil.copy2(test_p, out / "test.parquet")

    val_df  = pd.read_parquet(out / "val.parquet")
    test_df = pd.read_parquet(out / "test.parquet")

    meta = {
        "protocol": "split_3_train_resampled_streaming",
        "seed": int(seed),
        "target_n": int(target_n),
        "benign_ratio": float(benign_ratio),
        "batch_size": int(batch_size),
        "source_split1": str(split1),
        "rows": {
            "train": int(len(train_new)),
            "val":   int(len(val_df)),
            "test":  int(len(test_df)),
        },
        "splits": make_report(train_new, str(out / "val.parquet"), str(out / "test.parquet"), batch_size),
    }
    (out / "split_report.json").write_text(json.dumps(meta, indent=2))
    return {"train": train_new, "val": val_df, "test": test_df, "meta": meta}


def make_report(train_df: pd.DataFrame, val_parquet: str, test_parquet: str, batch_size: int):
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

    # copy val/test unchanged (no RAM)
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
