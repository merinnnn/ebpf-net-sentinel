#!/usr/bin/env python3
"""Create train/val/test splits with sane attack coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import argparse
import itertools
import json
import os
from typing import Dict, Tuple

import numpy as np
import pandas as pd


DAY_COL = "day"
LABEL_COL = "label_family"
IS_ATTACK_COL = "is_attack"


@dataclass(frozen=True)
class SplitSpec:
    train_days: Tuple[str, ...]
    val_days: Tuple[str, ...]
    test_days: Tuple[str, ...]


def _attack_counts(df: pd.DataFrame) -> Tuple[int, int]:
    y = (df[IS_ATTACK_COL] == 1).astype(int)
    return int((y == 0).sum()), int((y == 1).sum())


def _family_diversity(df: pd.DataFrame) -> int:
    fam = df[LABEL_COL].astype(str)
    fam = fam[fam != "BENIGN"]
    return int(fam.nunique())


def _score_partition(parts: Dict[str, pd.DataFrame]) -> float:
    score = 0.0

    for name, df in parts.items():
        benign, atk = _attack_counts(df)
        if atk <= 0:
            return -1e18

        ratio = atk / max(1, (benign + atk))
        # Encourage ratios not being extreme (val with ~0 attacks is bad).
        score += 10.0 * (1.0 - abs(ratio - 0.20))  # target ~20% (loose)

        if name in ("val", "test"):
            score += 3.0 * _family_diversity(df)

    # Slight preference for bigger train.
    score += 0.000001 * len(parts["train"])
    return score


def choose_day_split(
    df: pd.DataFrame,
    min_attacks_train: int,
    min_attacks_val: int,
    min_attacks_test: int,
) -> SplitSpec:
    days = sorted(df[DAY_COL].astype(str).unique())
    if len(days) < 3:
        raise SystemExit(f"[!] Need >=3 distinct days, got {days}")

    best: Tuple[float, SplitSpec] | None = None

    for val_days in itertools.combinations(days, 1):
        remaining = [d for d in days if d not in val_days]
        for test_days in itertools.combinations(remaining, 1):
            train_days = tuple(d for d in days if d not in val_days and d not in test_days)
            spec = SplitSpec(train_days=tuple(train_days), val_days=tuple(val_days), test_days=tuple(test_days))

            parts = {
                "train": df[df[DAY_COL].astype(str).isin(spec.train_days)],
                "val": df[df[DAY_COL].astype(str).isin(spec.val_days)],
                "test": df[df[DAY_COL].astype(str).isin(spec.test_days)],
            }

            _, atk_tr = _attack_counts(parts["train"])
            _, atk_va = _attack_counts(parts["val"])
            _, atk_te = _attack_counts(parts["test"])

            if atk_tr < min_attacks_train or atk_va < min_attacks_val or atk_te < min_attacks_test:
                continue

            s = _score_partition(parts)
            if best is None or s > best[0]:
                best = (s, spec)

    if best is None:
        raise SystemExit(
            "[!] Could not find a day-based split meeting minimum attack constraints. "
            "Try lowering --min_attacks_* or use --protocol stratified_flow."
        )
    return best[1]


def write_split(df: pd.DataFrame, out_dir: str, spec: SplitSpec) -> None:
    os.makedirs(out_dir, exist_ok=True)

    parts = {
        "train": df[df[DAY_COL].astype(str).isin(spec.train_days)].copy(),
        "val": df[df[DAY_COL].astype(str).isin(spec.val_days)].copy(),
        "test": df[df[DAY_COL].astype(str).isin(spec.test_days)].copy(),
    }

    stats = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "protocol": "day_holdout",
        "mapping": {
            "train": list(spec.train_days),
            "val": list(spec.val_days),
            "test": list(spec.test_days),
        },
        "sets": {},
    }

    for name, part_df in parts.items():
        out_path = os.path.join(out_dir, f"{name}.parquet")
        part_df.to_parquet(out_path, index=False)

        benign, atk = _attack_counts(part_df)
        counts = part_df[LABEL_COL].astype(str).value_counts(dropna=False).to_dict()
        stats["sets"][name] = {
            "rows": int(len(part_df)),
            "benign": int(benign),
            "attacks": int(atk),
            "attack_ratio": float(atk / max(1, (benign + atk))),
            "attack_family_diversity": int(_family_diversity(part_df)),
            "label_counts": {str(k): int(v) for k, v in counts.items()},
        }

    with open(os.path.join(out_dir, "split_report.json"), "w") as f:
        json.dump(stats, f, indent=2)

    print("[*] Wrote splits to:", out_dir)
    for part in ("train", "val", "test"):
        print(f"  {part}: {os.path.join(out_dir, part + '.parquet')}")
    print("[*] split report:", os.path.join(out_dir, "split_report.json"))


def write_stratified_flow(df: pd.DataFrame, out_dir: str, seed: int, train_frac: float, val_frac: float) -> None:
    os.makedirs(out_dir, exist_ok=True)

    y = (df[IS_ATTACK_COL] == 1).astype(int).to_numpy()
    idx = np.arange(len(df))
    rng = np.random.default_rng(seed)

    idx0 = idx[y == 0]
    idx1 = idx[y == 1]
    rng.shuffle(idx0)
    rng.shuffle(idx1)

    def split_indices(ix: np.ndarray):
        n = len(ix)
        n_train = int(n * train_frac)
        n_val = int(n * val_frac)
        tr = ix[:n_train]
        va = ix[n_train : n_train + n_val]
        te = ix[n_train + n_val :]
        return tr, va, te

    tr0, va0, te0 = split_indices(idx0)
    tr1, va1, te1 = split_indices(idx1)

    train_idx = np.concatenate([tr0, tr1])
    val_idx = np.concatenate([va0, va1])
    test_idx = np.concatenate([te0, te1])
    rng.shuffle(train_idx)
    rng.shuffle(val_idx)
    rng.shuffle(test_idx)

    parts = {
        "train": df.iloc[train_idx].copy(),
        "val": df.iloc[val_idx].copy(),
        "test": df.iloc[test_idx].copy(),
    }

    stats = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "protocol": "stratified_flow",
        "fractions": {"train": train_frac, "val": val_frac, "test": float(1.0 - train_frac - val_frac)},
        "sets": {},
    }

    for name, part_df in parts.items():
        out_path = os.path.join(out_dir, f"{name}.parquet")
        part_df.to_parquet(out_path, index=False)
        benign, atk = _attack_counts(part_df)
        stats["sets"][name] = {
            "rows": int(len(part_df)),
            "benign": int(benign),
            "attacks": int(atk),
            "attack_ratio": float(atk / max(1, (benign + atk))),
            "attack_family_diversity": int(_family_diversity(part_df)),
        }

    with open(os.path.join(out_dir, "split_report.json"), "w") as f:
        json.dump(stats, f, indent=2)

    print("[*] Wrote splits to:", out_dir)
    for part in ("train", "val", "test"):
        print(f"  {part}: {os.path.join(out_dir, part + '.parquet')}")
    print("[*] split report:", os.path.join(out_dir, "split_report.json"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True)
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--protocol", choices=["day_holdout", "stratified_flow"], default="day_holdout")

    ap.add_argument("--min_attacks_train", type=int, default=5000)
    ap.add_argument("--min_attacks_val", type=int, default=1000)
    ap.add_argument("--min_attacks_test", type=int, default=1000)

    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--train_frac", type=float, default=0.70)
    ap.add_argument("--val_frac", type=float, default=0.15)
    args = ap.parse_args()

    df = pd.read_parquet(args.in_parquet)
    for c in (DAY_COL, LABEL_COL, IS_ATTACK_COL):
        if c not in df.columns:
            raise SystemExit(f"[!] Missing required column: {c}")

    if args.protocol == "stratified_flow":
        write_stratified_flow(df, args.out_dir, seed=args.seed, train_frac=args.train_frac, val_frac=args.val_frac)
        return

    spec = choose_day_split(
        df,
        min_attacks_train=args.min_attacks_train,
        min_attacks_val=args.min_attacks_val,
        min_attacks_test=args.min_attacks_test,
    )
    write_split(df, args.out_dir, spec)


if __name__ == "__main__":
    main()
