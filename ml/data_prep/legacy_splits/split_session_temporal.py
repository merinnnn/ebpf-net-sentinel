#!/usr/bin/env python3
"""
Session-Aware Temporal Split for CICIDS2017
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

# Column name candidates
LABEL_CANDIDATES = ["label_family", "label", "attack_type", "Label"]
TS_CANDIDATES    = ["ts", "start_ts", "t_start", "time", "timestamp"]
DAY_CANDIDATES   = ["day", "Day", "capture_day"]
SRC_CANDIDATES   = ["orig_h", "src_ip", "src", "source_ip"]
DST_CANDIDATES   = ["resp_h", "dst_ip", "dst", "dest_ip"]
PROTO_CANDIDATES = ["proto", "protocol", "ip_proto"]

def _first(df: pd.DataFrame, candidates: list[str]) -> str | None:
    for c in candidates:
        if c in df.columns:
            return c
    return None

# Core split logic
def build_session_groups(df: pd.DataFrame) -> pd.Series:
    """
    Assign every row a session-group key: (src_ip, dst_ip, proto, day).
    Falls back gracefully when columns are missing.
    """
    src   = _first(df, SRC_CANDIDATES)
    dst   = _first(df, DST_CANDIDATES)
    proto = _first(df, PROTO_CANDIDATES)
    day   = _first(df, DAY_CANDIDATES)

    parts = []
    if src:   parts.append(df[src].astype(str))
    if dst:   parts.append(df[dst].astype(str))
    if proto: parts.append(df[proto].astype(str))
    if day:   parts.append(df[day].astype(str))

    if not parts:
        # No grouping columns at all, fall back to index-based groups of 1
        print("[!] No session-group columns found; each row is its own group.")
        return pd.Series(df.index.astype(str), index=df.index)

    group_key = parts[0]
    for p in parts[1:]:
        group_key = group_key + "||" + p

    cols_used = [c for c, flag in [(src, src), (dst, dst), (proto, proto), (day, day)] if flag]
    print(f"[*] Session groups built from columns: {cols_used}")
    return group_key


def _report_split(df: pd.DataFrame, label_col: str | None) -> dict:
    out: dict = {"rows": int(len(df))}
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

def split_session_temporal(
    df: pd.DataFrame,
    train_frac: float = 0.70,
    val_frac: float   = 0.15,
    test_frac: float  = 0.15,
    seed: int         = 42,
) -> dict[str, pd.DataFrame]:
    """
    Main split function.

    Returns {"train": df, "val": df, "test": df, "meta": dict}
    """
    if not np.isclose(train_frac + val_frac + test_frac, 1.0):
        raise ValueError("train_frac + val_frac + test_frac must sum to 1.0")

    label_col = _first(df, LABEL_CANDIDATES)
    ts_col    = _first(df, TS_CANDIDATES)

    # Build session groups
    df = df.copy()
    df["_session_group"] = build_session_groups(df)

    # Find the earliest timestamp per group
    if ts_col:
        group_min_ts = df.groupby("_session_group")[ts_col].min().rename("_group_min_ts")
    else:
        # No timestamp: use row index as a proxy for order
        print("[!] No timestamp column found; using row index as ordering proxy.")
        df["_row_idx"] = np.arange(len(df))
        group_min_ts = df.groupby("_session_group")["_row_idx"].min().rename("_group_min_ts")

    # Sort groups by earliest timestamp -> stable chronological order
    group_order = (
        group_min_ts
        .reset_index()
        .sort_values("_group_min_ts", kind="mergesort")
        ["_session_group"]
        .values
    )
    n_groups = len(group_order)
    print(f"[*] Total session groups: {n_groups:,}  |  Total rows: {len(df):,}")

    # Assign groups to splits by chronological position 
    n_train = int(round(train_frac * n_groups))
    n_val   = int(round(val_frac   * n_groups))
    n_test  = n_groups - n_train - n_val   # absorb rounding remainder

    train_groups = set(group_order[:n_train])
    val_groups   = set(group_order[n_train : n_train + n_val])
    test_groups  = set(group_order[n_train + n_val :])

    def assign(row_groups: pd.Series) -> pd.Series:
        s = row_groups.map(
            lambda g: "train" if g in train_groups
                      else ("val" if g in val_groups else "test")
        )
        return s

    df["_split"] = assign(df["_session_group"])

    # Label-coverage safety check 
    relocated_groups: dict[str, list[str]] = {}   # label -> groups moved
    if label_col and label_col in df.columns:
        train_labels = set(df.loc[df["_split"] == "train", label_col].astype(str).unique())

        for target_split in ["val", "test"]:
            split_labels = set(df.loc[df["_split"] == target_split, label_col].astype(str).unique())
            orphaned = split_labels - train_labels - {"BENIGN", "Unknown", "nan"}

            if orphaned:
                print(f"[!] Labels orphaned in {target_split} (not in train): {sorted(orphaned)}")
                for lbl in sorted(orphaned):
                    # Find session groups for this label in the target split, sorted chronologically
                    lbl_groups_in_split = (
                        df.loc[(df["_split"] == target_split) & (df[label_col].astype(str) == lbl),
                               "_session_group"]
                        .unique()
                        .tolist()
                    )
                    # Move the earliest group(s) to train (keep at least one in test/val)
                    if len(lbl_groups_in_split) > 1:
                        to_move = lbl_groups_in_split[:-1]   # keep last in original split
                    else:
                        to_move = lbl_groups_in_split         # only one group: move it all

                    for g in to_move:
                        df.loc[df["_session_group"] == g, "_split"] = "train"
                    relocated_groups[lbl] = to_move
                    print(f"    -> relocated {len(to_move)} group(s) for '{lbl}' -> train")

        # Update sets after relocation
        train_labels = set(df.loc[df["_split"] == "train", label_col].astype(str).unique())
        val_labels   = set(df.loc[df["_split"] == "val",   label_col].astype(str).unique())
        test_labels  = set(df.loc[df["_split"] == "test",  label_col].astype(str).unique())
    else:
        train_labels = val_labels = test_labels = set()
        print("[!] No label column found; skipping coverage check.")

    # Build final DataFrames
    train_df = df[df["_split"] == "train"].drop(columns=["_session_group", "_split"], errors="ignore")
    val_df   = df[df["_split"] == "val"  ].drop(columns=["_session_group", "_split"], errors="ignore")
    test_df  = df[df["_split"] == "test" ].drop(columns=["_session_group", "_split"], errors="ignore")

    # Drop helper column if we added it
    for part in [train_df, val_df, test_df]:
        if "_row_idx" in part.columns:
            part.drop(columns=["_row_idx"], inplace=True, errors="ignore")

    print(f"\n[*] Split result:")
    print(f"    train : {len(train_df):>8,} rows  ({len(train_df)/len(df)*100:.1f}%)")
    print(f"    val   : {len(val_df):>8,} rows  ({len(val_df)/len(df)*100:.1f}%)")
    print(f"    test  : {len(test_df):>8,} rows  ({len(test_df)/len(df)*100:.1f}%)")

    orphaned_test  = sorted(test_labels  - train_labels - {"BENIGN", "Unknown", "nan"})
    orphaned_val   = sorted(val_labels   - train_labels - {"BENIGN", "Unknown", "nan"})
    if orphaned_test or orphaned_val:
        print(f"[!] Residual orphaned labels in test : {orphaned_test}")
        print(f"[!] Residual orphaned labels in val  : {orphaned_val}")
        print("    (These classes had only ONE session group; they appear in test/val only.)")
        print("    Supervised models cannot learn these, report their recall as 0.")
    else:
        print("[+] All attack families in val/test are also in train. ✓")

    meta = {
        "protocol": "session_temporal",
        "seed": seed,
        "train_frac_requested": train_frac,
        "val_frac_requested": val_frac,
        "test_frac_requested": test_frac,
        "n_session_groups_total": int(n_groups),
        "n_session_groups_train": int(n_train),
        "n_session_groups_val": int(n_val),
        "n_session_groups_test": int(n_test),
        "ts_col_used": ts_col,
        "label_col": label_col,
        "relocated_groups_for_coverage": {k: v for k, v in relocated_groups.items()},
        "train_labels": sorted(train_labels),
        "val_labels": sorted(val_labels),
        "test_labels": sorted(test_labels),
        "labels_only_in_val": sorted(val_labels   - train_labels),
        "labels_only_in_test": sorted(test_labels  - train_labels),
        "labels_in_all_splits": sorted(train_labels & val_labels & test_labels),
    }

    return {
        "train": train_df.reset_index(drop=True),
        "val":   val_df.reset_index(drop=True),
        "test":  test_df.reset_index(drop=True),
        "meta":  meta,
    }

def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--in_parquet",  required=True,  help="Input parquet file")
    ap.add_argument("--out_dir",     required=True,  help="Output directory for train/val/test parquets")
    ap.add_argument("--train_frac",  type=float, default=0.70)
    ap.add_argument("--val_frac",    type=float, default=0.15)
    ap.add_argument("--test_frac",   type=float, default=0.15)
    ap.add_argument("--seed",        type=int,   default=42)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Loading: {args.in_parquet}")
    df = pd.read_parquet(args.in_parquet)
    print(f"[*] Loaded {len(df):,} rows, {len(df.columns)} columns")

    result = split_session_temporal(
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
        "splits": {
            k: _report_split(result[k], label_col) for k in ["train", "val", "test"]
        },
    }
    report_path = out_dir / "split_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"[*] split report: {report_path}")


if __name__ == "__main__":
    main()
