#!/usr/bin/env python3
from datetime import datetime
import argparse
import json
import os
import pandas as pd


LABEL_COL = "label_family"
DAY_COL = "day"

PRIMARY = {
    "train": ["Monday", "Tuesday", "Wednesday"],
    "val":   ["Thursday"],
    "test":  ["Friday"],
}

SECONDARY = {
    "train": ["Monday", "Wednesday", "Friday"],
    "val":   ["Tuesday"],
    "test":  ["Thursday"],
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True)
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--split", choices=["primary", "secondary"], default="primary")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    df = pd.read_parquet(args.in_parquet)
    if DAY_COL not in df.columns or LABEL_COL not in df.columns:
        raise SystemExit(f"[!] Missing required columns: '{DAY_COL}', '{LABEL_COL}'")

    mapping = PRIMARY if args.split == "primary" else SECONDARY

    stats = {"timestamp": datetime.utcnow().isoformat() + "Z", "split": args.split, "sets": {}}
    parts = {}

    for part in ["train", "val", "test"]:
        days = set(mapping[part])
        part_df = df[df[DAY_COL].astype(str).isin(days)].copy()
        out_path = os.path.join(args.out_dir, f"{part}.parquet")
        part_df.to_parquet(out_path, index=False)
        parts[part] = part_df

        counts = part_df[LABEL_COL].value_counts(dropna=False).to_dict()
        stats["sets"][part] = {
            "days": sorted(list(days)),
            "rows": int(len(part_df)),
            "label_counts": {str(k): int(v) for k, v in counts.items()},
        }

    train_labels = set(parts["train"][LABEL_COL].astype(str).unique())
    val_labels = set(parts["val"][LABEL_COL].astype(str).unique())
    test_labels = set(parts["test"][LABEL_COL].astype(str).unique())

    stats["label_analysis"] = {
        "train_labels": sorted(train_labels),
        "val_labels": sorted(val_labels),
        "test_labels": sorted(test_labels),
        "unseen_in_train_but_in_val": sorted(list(val_labels - train_labels)),
        "unseen_in_train_but_in_test": sorted(list(test_labels - train_labels)),
    }

    with open(os.path.join(args.out_dir, "split_report.json"), "w") as f:
        json.dump(stats, f, indent=2)

    print("[*] Wrote splits to:", args.out_dir)
    for part in ["train", "val", "test"]:
        print(f"  {part}: {os.path.join(args.out_dir, part + '.parquet')}")
    print("[*] split report:", os.path.join(args.out_dir, "split_report.json"))

if __name__ == "__main__":
    main()
