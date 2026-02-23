#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

# Column candidates
LABEL_CANDIDATES = ["label_family", "label", "attack_type", "Label"]
SRC_CANDIDATES   = ["orig_h", "src_ip", "src", "source_ip"]
DST_CANDIDATES   = ["resp_h", "dst_ip", "dst", "dest_ip"]
PROTO_CANDIDATES = ["proto", "protocol", "ip_proto"]


def _first(df: pd.DataFrame, candidates):
    for c in candidates:
        if c in df.columns:
            return c
    return None

def _report_split(df: pd.DataFrame, label_col: str | None) -> dict:
    out = {"rows": int(len(df))}
    if label_col and label_col in df.columns:
        vc = df[label_col].fillna("Unknown").astype(str).value_counts()
        out[label_col] = {k: int(v) for k, v in vc.items()}
    return out

def split_group_stratified(
    df: pd.DataFrame,
    train_frac: float = 0.70,
    val_frac:   float = 0.15,
    test_frac:  float = 0.15,
    seed:       int   = 42,
) -> dict:
    """
    Group-stratified train/val/test split.

    Returns {"train": df, "val": df, "test": df, "meta": dict}
    """
    assert abs(train_frac + val_frac + test_frac - 1.0) < 1e-9, \
        "fractions must sum to 1.0"

    rng = np.random.default_rng(seed)
    label_col = _first(df, LABEL_CANDIDATES)
    src_col   = _first(df, SRC_CANDIDATES)
    dst_col   = _first(df, DST_CANDIDATES)
    proto_col = _first(df, PROTO_CANDIDATES)

    # Build group key
    group_parts = []
    group_col_names = []
    for col, name in [(src_col, "src"), (dst_col, "dst"), (proto_col, "proto")]:
        if col:
            group_parts.append(df[col].astype(str))
            group_col_names.append(col)

    if not group_parts:
        # Fallback: treat each row as its own group (no grouping columns found)
        print("[!] No grouping columns found, falling back to stratified row split")
        df = df.copy()
        df["_group"] = np.arange(len(df))
    else:
        df = df.copy()
        df["_group"] = group_parts[0]
        for p in group_parts[1:]:
            df["_group"] = df["_group"] + "||" + p

    print(f"[*] Grouping columns: {group_col_names}")

    # Build group-level summary
    # Each group gets a dominant label = the most common label_family within it
    # (almost always uniform since attacks target specific host pairs)
    if label_col:
        dominant = (
            df.groupby("_group")[label_col]
            .agg(lambda s: s.mode().iloc[0])
            .rename("_dominant_label")
        )
    else:
        dominant = pd.Series("UNKNOWN", index=df["_group"].unique(), name="_dominant_label")

    group_sizes = df.groupby("_group").size().rename("_n_rows")
    group_df = pd.DataFrame({"_dominant_label": dominant, "_n_rows": group_sizes}).reset_index()
    group_df.columns = ["_group", "_dominant_label", "_n_rows"]

    n_groups = len(group_df)
    print(f"[*] Total groups: {n_groups:,}  |  Total rows: {len(df):,}")

    # Assign groups to splits with label stratification
    # Within each dominant-label class, shuffle groups and cut at train/val fracs.
    # This ensures each attack family is proportionally represented in all splits.
    group_df["_split"] = "train"  # default

    label_counts = group_df["_dominant_label"].value_counts()
    print(f"[*] Dominant-label distribution across groups:")
    for lbl, cnt in label_counts.items():
        print(f"    {lbl:25s}: {cnt:6,} groups")

    for lbl, lbl_group_df in group_df.groupby("_dominant_label"):
        idx = lbl_group_df.index.tolist()
        n   = len(idx)

        if n == 1:
            # Only 1 group for this label, keep in train (cannot split)
            print(f"[!] '{lbl}': only 1 group, kept in train only (will be absent from val/test)")
            continue
        elif n == 2:
            # 2 groups: train + test (skip val)
            shuffled = rng.permutation(idx)
            group_df.loc[shuffled[0], "_split"] = "train"
            group_df.loc[shuffled[1], "_split"] = "test"
            print(f"[!] '{lbl}': only 2 groups, 1 -> train, 1 -> test (none in val)")
            continue

        # Shuffle groups within this label class
        shuffled = rng.permutation(idx)

        # Allocate at least 1 group to val and 1 to test for this class
        n_val  = max(1, int(round(val_frac   * n)))
        n_test = max(1, int(round(test_frac  * n)))
        n_train = n - n_val - n_test
        if n_train < 1:
            # Edge: class has very few groups, give train 1, val 1, test rest
            n_train = 1
            n_test  = max(0, n - n_train - n_val)

        group_df.loc[shuffled[:n_train],                    "_split"] = "train"
        group_df.loc[shuffled[n_train:n_train + n_val],     "_split"] = "val"
        group_df.loc[shuffled[n_train + n_val:],            "_split"] = "test"

    # Map splits back to rows
    split_map = group_df.set_index("_group")["_split"].to_dict()
    df["_split"] = df["_group"].map(split_map)

    train_df = df[df["_split"] == "train"].drop(columns=["_group", "_split"])
    val_df   = df[df["_split"] == "val"  ].drop(columns=["_group", "_split"])
    test_df  = df[df["_split"] == "test" ].drop(columns=["_group", "_split"])

    total = len(df)
    print(f"\n[*] Split result:")
    print(f"    train : {len(train_df):>8,} rows  ({len(train_df)/total*100:.1f}%)")
    print(f"    val   : {len(val_df):>8,} rows  ({len(val_df)/total*100:.1f}%)")
    print(f"    test  : {len(test_df):>8,} rows  ({len(test_df)/total*100:.1f}%)")

    # Label coverage report
    if label_col:
        benign_etc = {"BENIGN", "Unknown", "nan"}
        tr_lbl = set(train_df[label_col].astype(str).unique()) - benign_etc
        va_lbl = set(val_df[label_col].astype(str).unique())   - benign_etc
        te_lbl = set(test_df[label_col].astype(str).unique())  - benign_etc

        tr_atk = int((train_df[label_col].astype(str).isin(tr_lbl)).sum())
        va_atk = int((val_df[label_col].astype(str).isin(va_lbl)).sum())
        te_atk = int((test_df[label_col].astype(str).isin(te_lbl)).sum())
        print(f"\n    Attack flows  train={tr_atk:,}  val={va_atk:,}  test={te_atk:,}")

        missing_val  = sorted(tr_lbl - va_lbl)
        missing_test = sorted(tr_lbl - te_lbl)
        if missing_val or missing_test:
            print(f"    [!] Attack families absent from val : {missing_val}")
            print(f"    [!] Attack families absent from test: {missing_test}")
        else:
            print("    [+] All attack families present in train, val, and test ✓")

    meta = {
        "protocol":          "group_stratified",
        "seed":              seed,
        "train_frac_req":    train_frac,
        "val_frac_req":      val_frac,
        "test_frac_req":     test_frac,
        "actual_row_frac":   {
            "train": round(len(train_df) / total, 4),
            "val":   round(len(val_df)   / total, 4),
            "test":  round(len(test_df)  / total, 4),
        },
        "n_groups_total":    int(n_groups),
        "group_cols":        group_col_names,
        "label_col":         label_col,
    }

    return {
        "train": train_df.reset_index(drop=True),
        "val":   val_df.reset_index(drop=True),
        "test":  test_df.reset_index(drop=True),
        "meta":  meta,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in_parquet",  required=True)
    ap.add_argument("--out_dir",     required=True)
    ap.add_argument("--train_frac",  type=float, default=0.70)
    ap.add_argument("--val_frac",    type=float, default=0.15)
    ap.add_argument("--test_frac",   type=float, default=0.15)
    ap.add_argument("--seed",        type=int,   default=42)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Loading: {args.in_parquet}")
    df = pd.read_parquet(args.in_parquet)
    print(f"[*] {len(df):,} rows, {len(df.columns)} columns")

    result = split_group_stratified(
        df,
        train_frac=args.train_frac,
        val_frac=args.val_frac,
        test_frac=args.test_frac,
        seed=args.seed,
    )

    label_col = result["meta"]["label_col"]
    for split in ["train", "val", "test"]:
        path = out_dir / f"{split}.parquet"
        result[split].to_parquet(path, index=False)
        print(f"[*] Wrote {split}: {path}")

    report = {
        **result["meta"],
        "splits": {k: _report_split(result[k], label_col) for k in ["train", "val", "test"]},
    }
    (out_dir / "split_report.json").write_text(json.dumps(report, indent=2))
    print(f"[*] Report: {out_dir / 'split_report.json'}")


if __name__ == "__main__":
    main()
