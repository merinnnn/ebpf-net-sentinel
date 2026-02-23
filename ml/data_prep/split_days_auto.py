#!/usr/bin/env python3
"""
Create train/val/test splits for CICIDS2017-style data where attack types are uneven across days.

Protocols:
  - within_day_time: for EACH day, split by time (ts) into train/val/test fractions, then concat.
    This ensures every day contributes to every split, so rare attack families don't end up ONLY in test.

  - day_holdout: hold out whole days (useful for "generalize to unseen day" evaluation).
    WARNING: If some attack families only exist on a single day, they will be missing from train.

  - stratified_label: ignore days, split by label_col with stratification. Robust to rare classes via min_class_count.

Outputs:
  out_dir/{train,val,test}.parquet and a split_report.json with per-split label counts.
"""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


LABEL_COL_CANDIDATES = ["label_family", "label", "attack_type", "Label"]
DAY_COL_CANDIDATES = ["day", "Day", "capture_day"]


def find_first_col(df: pd.DataFrame, candidates):
    for c in candidates:
        if c in df.columns:
            return c
    return None


def _report_split(df: pd.DataFrame, label_col: str | None):
    out = {"rows": int(len(df))}
    if label_col and label_col in df.columns:
        vc = df[label_col].fillna("Unknown").astype(str).value_counts()
        out[label_col] = {k: int(v) for k, v in vc.items()}
    if "is_attack" in df.columns:
        vc2 = df["is_attack"].value_counts(dropna=False)
        out["is_attack"] = {str(k): int(v) for k, v in vc2.items()}
    if "day" in df.columns:
        vc3 = df["day"].astype(str).value_counts()
        out["day"] = {k: int(v) for k, v in vc3.items()}
    return out


def split_within_day_time(df: pd.DataFrame, train_frac: float, val_frac: float, test_frac: float, seed: int):
    """Split within each day by **time order**.

    If a day column exists, we do the split per-day then concatenate.
    Within each day, we sort by timestamp if available (ts/start_ts), otherwise we shuffle.
    """
    if not np.isclose(train_frac + val_frac + test_frac, 1.0):
        raise ValueError("train_frac + val_frac + test_frac must sum to 1.0")

    day_col = find_first_col(df, DAY_COL_CANDIDATES)
    ts_col = None
    for c in ["ts", "start_ts", "t_start", "time", "timestamp"]:
        if c in df.columns:
            ts_col = c
            break

    def _split_one(part: pd.DataFrame):
        n = len(part)
        if n == 0:
            return {"train": part, "val": part, "test": part}
        if ts_col:
            part2 = part.sort_values(ts_col, kind="mergesort")
        else:
            part2 = part.sample(frac=1.0, random_state=seed)
        n_train = int(round(train_frac * n))
        n_val = int(round(val_frac * n))
        n_test = n - n_train - n_val
        train = part2.iloc[:n_train]
        val = part2.iloc[n_train:n_train + n_val]
        test = part2.iloc[n_train + n_val:]
        return {"train": train, "val": val, "test": test}

    if day_col:
        parts = {"train": [], "val": [], "test": []}
        for d, g in df.groupby(day_col, sort=False):
            out = _split_one(g)
            for k in parts:
                parts[k].append(out[k])
        result = {k: pd.concat(parts[k], ignore_index=True) for k in parts}
    else:
        out = _split_one(df)
        result = {k: out[k].reset_index(drop=True) for k in out}

    # Label-coverage safety check
    label_col = find_first_col(df, LABEL_COL_CANDIDATES)
    if label_col and label_col in result["train"].columns:
        train_labels = set(result["train"][label_col].astype(str).unique())

        for src_split in ["val", "test"]:
            src_df = result[src_split].copy().reset_index(drop=True)
            split_labels = set(src_df[label_col].astype(str).unique())
            orphaned = split_labels - train_labels - {"BENIGN", "Unknown", "nan"}

            if not orphaned:
                continue

            print(f"[!] within_day_time: attack families with 0 train rows (found in {src_split}): {sorted(orphaned)}")
            print(f"    Relocating minimum flows to train for label coverage...")

            move_indices = []
            for lbl in sorted(orphaned):
                lbl_mask = src_df[label_col].astype(str) == lbl
                lbl_idx  = src_df.index[lbl_mask].tolist()
                # Move all but the last row; keep ≥1 in the original split for evaluation
                to_move = lbl_idx[:-1] if len(lbl_idx) > 1 else lbl_idx
                move_indices.extend(to_move)
                kept = len(lbl_idx) - len(to_move)
                print(f"    '{lbl}': {len(lbl_idx)} rows -> moving {len(to_move)} to train, keeping {kept} in {src_split}")

            if move_indices:
                moved_df = src_df.loc[move_indices]
                result["train"] = pd.concat([result["train"], moved_df], ignore_index=True)
                result[src_split] = src_df.drop(index=move_indices).reset_index(drop=True)
                train_labels = set(result["train"][label_col].astype(str).unique())

    return result


def split_day_holdout(df: pd.DataFrame, day_col: str, train_days, val_days, test_days):
    df_day = df.copy()
    df_day[day_col] = df_day[day_col].astype(str)

    train = df_day[df_day[day_col].isin(set(map(str, train_days)))]
    val = df_day[df_day[day_col].isin(set(map(str, val_days)))]
    test = df_day[df_day[day_col].isin(set(map(str, test_days)))]

    return {
        "train": train.reset_index(drop=True),
        "val": val.reset_index(drop=True),
        "test": test.reset_index(drop=True),
    }


def split_stratified_label(
    df: pd.DataFrame,
    label_col: str,
    train_frac: float,
    val_frac: float,
    test_frac: float,
    seed: int,
    min_class_count: int,
):
    """
    Stratified split by label_col.
    Robust to rare classes:
      - Any class with count < min_class_count is mapped to "__RARE__"
      - If "__RARE__" still has < 2 samples, we disable stratification for the 2nd split as needed.
    """
    if not np.isclose(train_frac + val_frac + test_frac, 1.0):
        raise ValueError("train_frac + val_frac + test_frac must sum to 1.0")

    if train_frac <= 0 or val_frac <= 0 or test_frac <= 0:
        raise ValueError("fractions must be > 0")

    y = df[label_col].fillna("Unknown").astype(str)

    vc = y.value_counts()
    rare = vc[vc < int(min_class_count)].index
    y2 = y.where(~y.isin(rare), other="__RARE__")

    # First split: train vs temp (val+test)
    temp_frac = (1.0 - train_frac)
    if not (0.0 < temp_frac < 1.0):
        raise ValueError(f"Invalid temp_frac computed: {temp_frac}")

    # Stratification requires each class >= 2
    strat1 = y2
    if strat1.value_counts().min() < 2:
        # Fall back to unstratified if the dataset is too weird
        strat1 = None

    idx_all = np.arange(len(df))
    idx_train, idx_temp = train_test_split(
        idx_all,
        test_size=float(temp_frac),
        random_state=int(seed),
        stratify=strat1,
    )

    # Second split: val vs test inside temp
    y_temp = y2.iloc[idx_temp]
    val_plus_test = val_frac + test_frac
    test_frac_of_temp = test_frac / val_plus_test  # proportion of temp that becomes test

    if not (0.0 < test_frac_of_temp < 1.0):
        raise ValueError(f"Invalid test_frac_of_temp computed: {test_frac_of_temp}")

    strat2 = y_temp
    if strat2.value_counts().min() < 2:
        strat2 = None  # avoid sklearn crash on rare leftover classes

    idx_val, idx_test = train_test_split(
        idx_temp,
        test_size=float(test_frac_of_temp),
        random_state=int(seed),
        stratify=strat2,
    )

    return {
        "train": df.iloc[idx_train].reset_index(drop=True),
        "val": df.iloc[idx_val].reset_index(drop=True),
        "test": df.iloc[idx_test].reset_index(drop=True),
        "meta": {
            "min_class_count": int(min_class_count),
            "rare_classes_mapped": sorted([str(x) for x in rare]),
            "label_col": label_col,
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True)
    ap.add_argument("--out_dir", required=True)

    ap.add_argument("--protocol", choices=["within_day_time", "day_holdout", "stratified_label"], default="within_day_time")
    ap.add_argument("--seed", type=int, default=42)

    # fraction params
    ap.add_argument("--train_frac", type=float, default=0.70)
    ap.add_argument("--val_frac", type=float, default=0.15)
    ap.add_argument("--test_frac", type=float, default=0.15)

    # day_holdout params (comma-separated days)
    ap.add_argument("--train_days", default="")
    ap.add_argument("--val_days", default="")
    ap.add_argument("--test_days", default="")

    # stratified_label params
    ap.add_argument("--min_class_count", type=int, default=10, help="labels with < this count get mapped to __RARE__")

    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_parquet(args.in_parquet)

    label_col = find_first_col(df, LABEL_COL_CANDIDATES)
    day_col = find_first_col(df, DAY_COL_CANDIDATES)

    meta = {"protocol": args.protocol, "seed": int(args.seed)}

    if args.protocol == "within_day_time":
        splits = split_within_day_time(df, args.train_frac, args.val_frac, args.test_frac, args.seed)
        chosen = {"mode": "within_day_time"}

    elif args.protocol == "day_holdout":
        if not args.train_days or not args.val_days or not args.test_days:
            raise SystemExit("day_holdout requires --train_days, --val_days, --test_days")
        if not day_col:
            raise SystemExit("day_holdout requires a day column (e.g. 'day') but none was found.")
        day_train = [x.strip() for x in args.train_days.split(",") if x.strip()]
        day_val = [x.strip() for x in args.val_days.split(",") if x.strip()]
        day_test = [x.strip() for x in args.test_days.split(",") if x.strip()]
        splits = split_day_holdout(df, day_col, day_train, day_val, day_test)
        chosen = {"train_days": day_train, "val_days": day_val, "test_days": day_test}

    else:  # stratified_label
        if not label_col:
            raise SystemExit("stratified_label requires a label column, but none was found.")
        out = split_stratified_label(
            df=df,
            label_col=label_col,
            train_frac=args.train_frac,
            val_frac=args.val_frac,
            test_frac=args.test_frac,
            seed=args.seed,
            min_class_count=args.min_class_count,
        )
        splits = {k: out[k] for k in ["train", "val", "test"]}
        meta.update(out["meta"])
        chosen = {"mode": "stratified_label", "label_col": label_col}

    # save splits
    for k in ["train", "val", "test"]:
        splits[k].to_parquet(out_dir / f"{k}.parquet", index=False)

    report = {
        **meta,
        "chosen": chosen,
        "splits": {k: _report_split(splits[k], label_col) for k in ["train", "val", "test"]},
    }

    # label coverage diagnostics (set membership)
    if label_col and label_col in df.columns:
        fam_sets = {
            k: set(pd.Series(list(report["splits"][k].get(label_col, {}).keys())).astype(str))
            for k in ["train", "val", "test"]
        }
        report["diagnostics"] = {
            "labels_only_in_train": sorted(list(fam_sets["train"] - fam_sets["val"] - fam_sets["test"])),
            "labels_only_in_val": sorted(list(fam_sets["val"] - fam_sets["train"] - fam_sets["test"])),
            "labels_only_in_test": sorted(list(fam_sets["test"] - fam_sets["train"] - fam_sets["val"])),
            "labels_in_all": sorted(list(fam_sets["train"] & fam_sets["val"] & fam_sets["test"])),
        }

    with open(out_dir / "split_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"[*] Wrote splits to: {out_dir}")
    for k in ["train", "val", "test"]:
        print(f"  {k}: {out_dir / f'{k}.parquet'}")
    print(f"[*] split report: {out_dir / 'split_report.json'}")


if __name__ == "__main__":
    main()
