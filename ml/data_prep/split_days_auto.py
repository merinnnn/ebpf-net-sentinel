#!/usr/bin/env python3
"""
Create train/val/test splits for CICIDS2017-style data where attack types are uneven across days.

Protocols:
  - within_day_time: for EACH day, split by time (ts) into train/val/test fractions, then concat.
    This ensures every day contributes to every split, so rare attack families don't end up ONLY in test.

  - day_holdout: hold out whole days (useful for "generalize to unseen day" evaluation).
    WARNING: If some attack families only exist on a single day, they will be missing from train.

Outputs:
  out_dir/{train,val,test}.parquet and a split_report.json with per-split label counts.
"""
import argparse, json, os
from pathlib import Path
import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)

def _value_counts(df, col):
    if col not in df.columns:
        return {}
    vc = df[col].fillna("Unknown").value_counts()
    return {str(k): int(v) for k, v in vc.items()}

def _attack_counts(df):
    if "is_attack" not in df.columns:
        return {"attacks": None, "benign": None, "attack_pct": None}
    attacks = int((df["is_attack"] == 1).sum())
    benign  = int((df["is_attack"] == 0).sum())
    pct = float(attacks / max(1, (attacks + benign)) * 100.0)
    return {"attacks": attacks, "benign": benign, "attack_pct": pct}

def _report_split(df):
    rep = {
        "rows": int(len(df)),
        **_attack_counts(df),
        "label_family": _value_counts(df, "label_family"),
        "day": _value_counts(df, "day"),
    }
    return rep

def split_within_day_time(df, train_frac, val_frac, test_frac):
    if abs((train_frac + val_frac + test_frac) - 1.0) > 1e-6:
        raise ValueError("train/val/test fractions must sum to 1.0")

    if "day" not in df.columns:
        raise ValueError("missing required column: day")

    # Use ts if present; otherwise fall back to row order within day.
    has_ts = "ts" in df.columns
    parts = {"train": [], "val": [], "test": []}

    for day, g in df.groupby("day", sort=False):
        g2 = g.copy()
        if has_ts:
            g2 = g2.sort_values("ts")
        else:
            g2 = g2.reset_index(drop=True)

        n = len(g2)
        n_train = int(n * train_frac)
        n_val   = int(n * val_frac)
        # remainder -> test
        n_test  = n - n_train - n_val

        parts["train"].append(g2.iloc[:n_train])
        parts["val"].append(g2.iloc[n_train:n_train+n_val])
        parts["test"].append(g2.iloc[n_train+n_val:])

    out = {k: pd.concat(v, ignore_index=True) if v else df.iloc[0:0].copy() for k, v in parts.items()}
    return out

def split_day_holdout(df, day_train, day_val, day_test):
    parts = {
        "train": df[df["day"].isin(day_train)].copy(),
        "val":   df[df["day"].isin(day_val)].copy(),
        "test":  df[df["day"].isin(day_test)].copy(),
    }
    return parts

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True)
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--protocol", choices=["within_day_time", "day_holdout"], default="within_day_time")

    # within_day_time params
    ap.add_argument("--train_frac", type=float, default=0.70)
    ap.add_argument("--val_frac", type=float, default=0.15)
    ap.add_argument("--test_frac", type=float, default=0.15)

    # day_holdout params (comma-separated days)
    ap.add_argument("--train_days", default="")
    ap.add_argument("--val_days", default="")
    ap.add_argument("--test_days", default="")

    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_parquet(args.in_parquet)

    if args.protocol == "within_day_time":
        splits = split_within_day_time(df, args.train_frac, args.val_frac, args.test_frac)
        chosen = {"train_days": "ALL", "val_days": "ALL", "test_days": "ALL"}
    else:
        if not args.train_days or not args.val_days or not args.test_days:
            raise SystemExit("day_holdout requires --train_days, --val_days, --test_days")
        day_train = [x.strip() for x in args.train_days.split(",") if x.strip()]
        day_val   = [x.strip() for x in args.val_days.split(",") if x.strip()]
        day_test  = [x.strip() for x in args.test_days.split(",") if x.strip()]
        splits = split_day_holdout(df, day_train, day_val, day_test)
        chosen = {"train_days": day_train, "val_days": day_val, "test_days": day_test}

    # Save
    for k in ["train", "val", "test"]:
        p = out_dir / f"{k}.parquet"
        splits[k].to_parquet(p, index=False)

    report = {
        "protocol": args.protocol,
        "chosen": chosen,
        "splits": {k: _report_split(splits[k]) for k in ["train", "val", "test"]},
    }

    # Extra diagnostics: which label families are exclusive to a split?
    fam_sets = {k: set(pd.Series(list(report["splits"][k]["label_family"].keys())).astype(str)) for k in ["train","val","test"]}
    report["diagnostics"] = {
        "families_only_in_train": sorted(list(fam_sets["train"] - fam_sets["val"] - fam_sets["test"])),
        "families_only_in_val":   sorted(list(fam_sets["val"] - fam_sets["train"] - fam_sets["test"])),
        "families_only_in_test":  sorted(list(fam_sets["test"] - fam_sets["train"] - fam_sets["val"])),
    }

    rp = out_dir / "split_report.json"
    rp.write_text(json.dumps(report, indent=2))

    print(f"[*] Wrote splits to: {out_dir}")
    for k in ["train","val","test"]:
        print(f"  {k}: {out_dir / (k+'.parquet')}")
    print(f"[*] split report: {rp}")

if __name__ == "__main__":
    main()
