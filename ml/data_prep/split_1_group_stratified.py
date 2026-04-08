#!/usr/bin/env python3
"""Group-stratified split: all flows per host pair stay together to prevent host-identity leakage."""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

import pyarrow as pa
import pyarrow.parquet as pq


LABEL_COL  = "label_family"
ATTACK_COL = "is_attack"
GROUP_COLS = ("orig_h", "resp_h")
BENIGN_LIKE = frozenset({"BENIGN", "Unknown", "nan", "NaN", ""})


def _iter_batches(parquet_path: str, batch_size: int, columns=None):
    """Yield pandas batches from a Parquet file without loading it all into memory."""
    pf = pq.ParquetFile(parquet_path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=columns):
        yield batch.to_pandas()


def _dominant_label(s: pd.Series) -> str:
    """Return the dominant label for a group; attack labels take priority over BENIGN."""
    vc = s.astype(str).value_counts(dropna=False)
    for k, _v in vc.items():
        if str(k) not in BENIGN_LIKE:
            return str(k)
    return str(vc.index[0]) if len(vc) else "Unknown"


def build_group_table(in_parquet: str, batch_size: int = 131072) -> pd.DataFrame:
    """
    Return DataFrame with columns: orig_h, resp_h, n_rows, dom_label, attack_rows, benign_rows.
    """
    key_to_rows: Dict[Tuple[str, str], int] = {}
    key_to_attack: Dict[Tuple[str, str], int] = {}
    key_to_label_counts: Dict[Tuple[str, str], Dict[str, int]] = {}

    cols = list(GROUP_COLS) + [LABEL_COL, ATTACK_COL]
    for df in _iter_batches(in_parquet, batch_size, columns=cols):
        df[LABEL_COL]  = df[LABEL_COL].astype(str)
        df[ATTACK_COL] = pd.to_numeric(df[ATTACK_COL], errors="coerce").fillna(0).astype(int)

        g       = df.groupby(list(GROUP_COLS), dropna=False)
        sizes   = g.size()
        attacks = g[ATTACK_COL].sum()

        for (oh, rh), n in sizes.items():
            k = (str(oh), str(rh))
            key_to_rows[k] = key_to_rows.get(k, 0) + int(n)

        for (oh, rh), a in attacks.items():
            k = (str(oh), str(rh))
            key_to_attack[k] = key_to_attack.get(k, 0) + int(a)

        tmp = df.groupby(list(GROUP_COLS) + [LABEL_COL], dropna=False).size()
        for (oh, rh, lab), n in tmp.items():
            k = (str(oh), str(rh))
            d = key_to_label_counts.get(k)
            if d is None:
                d = {}
                key_to_label_counts[k] = d
            lab = str(lab)
            d[lab] = d.get(lab, 0) + int(n)

    rows = []
    for k, n_rows in key_to_rows.items():
        label_counts = key_to_label_counts.get(k, {})
        if label_counts:
            labs = pd.Series(label_counts)
            dom  = _dominant_label(pd.Series(np.repeat(list(labs.index), list(labs.values))))
        else:
            dom = "Unknown"
        arows = key_to_attack.get(k, 0)
        rows.append({
            GROUP_COLS[0]: k[0],
            GROUP_COLS[1]: k[1],
            "n_rows":      int(n_rows),
            "attack_rows": int(arows),
            "benign_rows": int(n_rows - arows),
            "dom_label":   str(dom),
        })
    return pd.DataFrame(rows)


def assign_groups_row_weighted(
    grp: pd.DataFrame,
    *,
    train_ratio: float,
    val_ratio: float,
    test_ratio: float,
    seed: int,
) -> Dict[str, List[int]]:
    """Greedy group assignment weighted by row count, not just group count."""
    rng  = np.random.default_rng(seed)
    grp  = grp.reset_index(drop=True)
    grp["_gid"] = grp.index.astype(int)

    assignments = {"train": [], "val": [], "test": []}

    for lab, sub in grp.groupby("dom_label", sort=False):
        sub   = sub.sample(frac=1.0, random_state=seed).copy()
        total = int(sub["n_rows"].sum())
        targets = {
            "train": int(round(total * train_ratio)),
            "val":   int(round(total * val_ratio)),
            "test":  total - int(round(total * train_ratio)) - int(round(total * val_ratio)),
        }
        remaining = targets.copy()

        # Largest groups first so they are assigned while slots are still open.
        sub = sub.sort_values("n_rows", ascending=False)

        for _, row in sub.iterrows():
            gid = int(row["_gid"])
            w   = int(row["n_rows"])
            best_splits = sorted(remaining.items(), key=lambda kv: kv[1], reverse=True)
            top  = best_splits[0][1]
            cand = [s for s, rem in best_splits if rem == top]
            chosen = cand[int(rng.integers(0, len(cand)))]
            assignments[chosen].append(gid)
            remaining[chosen] -= w

    return assignments


def assign_groups_naive_stratified(
    grp: pd.DataFrame, *, train_ratio: float, val_ratio: float, seed: int
):
    """Stratified group assignment by group count (legacy behavior, ignores row volume)."""
    from sklearn.model_selection import train_test_split

    grp = grp.reset_index(drop=True)
    grp["_gid"] = grp.index.astype(int)

    g_train, g_tmp = train_test_split(
        grp, test_size=(1.0 - train_ratio), random_state=seed, stratify=grp["dom_label"]
    )
    rel_val = val_ratio / (1.0 - train_ratio)
    g_val, g_test = train_test_split(
        g_tmp, test_size=(1.0 - rel_val), random_state=seed, stratify=g_tmp["dom_label"]
    )

    return {
        "train": g_train["_gid"].tolist(),
        "val":   g_val["_gid"].tolist(),
        "test":  g_test["_gid"].tolist(),
    }


def write_splits_streaming(
    *,
    in_parquet: str,
    out_dir: str,
    group_table: pd.DataFrame,
    group_assign: Dict[str, List[int]],
    batch_size: int = 131072,
):
    """Stream source parquet and write rows to train/val/test, keeping host pairs together."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    gid_to_split = {}
    for split, gids in group_assign.items():
        for gid in gids:
            gid_to_split[int(gid)] = split
    key_to_gid = {
        (str(r[GROUP_COLS[0]]), str(r[GROUP_COLS[1]])): int(r["_gid"])
        for r in group_table.reset_index(drop=True).assign(_gid=lambda d: d.index).to_dict(orient="records")
    }

    writers = {}
    schema  = None

    def _writer(name: str, schema: pa.Schema):
        path = out / f"{name}.parquet"
        return pq.ParquetWriter(str(path), schema=schema, compression="snappy")

    def _to_table(df: pd.DataFrame, schema: pa.Schema) -> pa.Table:
        tbl = pa.Table.from_pandas(df, preserve_index=False)
        if tbl.schema != schema:
            tbl = tbl.cast(schema, safe=False)
        return tbl

    stats = {k: {"rows": 0, "attacks": 0} for k in ["train", "val", "test"]}

    for df in _iter_batches(in_parquet, batch_size, columns=None):
        df[GROUP_COLS[0]] = df[GROUP_COLS[0]].astype(str)
        df[GROUP_COLS[1]] = df[GROUP_COLS[1]].astype(str)
        df[ATTACK_COL]    = pd.to_numeric(df[ATTACK_COL], errors="coerce").fillna(0).astype(int)

        if schema is None:
            schema = pa.Table.from_pandas(df.head(1), preserve_index=False).schema
            writers["train"] = _writer("train", schema)
            writers["val"]   = _writer("val",   schema)
            writers["test"]  = _writer("test",  schema)

        keys   = list(zip(df[GROUP_COLS[0]].tolist(), df[GROUP_COLS[1]].tolist()))
        gids   = [key_to_gid.get(k, None) for k in keys]
        splits = [gid_to_split.get(g, "train") if g is not None else "train" for g in gids]
        df     = df.copy()
        df["_split"] = splits

        for split in ["train", "val", "test"]:
            part = df[df["_split"] == split].drop(columns=["_split"])
            if len(part):
                writers[split].write_table(_to_table(part, schema))
                stats[split]["rows"]    += int(len(part))
                stats[split]["attacks"] += int((part[ATTACK_COL] == 1).sum())

    for w in writers.values():
        w.close()

    return stats


def make_report(stats: Dict[str, Dict[str, int]]) -> Dict[str, Dict[str, int]]:
    """Backward-compatible helper for notebook imports."""
    return {
        split: {"rows": int(v.get("rows", 0)), "attacks": int(v.get("attacks", 0))}
        for split, v in stats.items()
    }


def run(
    *,
    in_parquet: str,
    out_dir: str,
    train_frac: float = 0.70,
    val_frac: float   = 0.15,
    test_frac: float  = 0.15,
    seed: int         = 104,
    batch_size: int   = 131072,
    row_weighted: bool = True,
):
    """Notebook entry point: build group table, assign splits, write parquets and report."""
    if abs((train_frac + val_frac + test_frac) - 1.0) > 1e-6:
        raise ValueError("Fractions must sum to 1.0")

    grp = build_group_table(str(in_parquet), batch_size=batch_size)
    if row_weighted:
        assign = assign_groups_row_weighted(
            grp, train_ratio=train_frac, val_ratio=val_frac, test_ratio=test_frac, seed=seed,
        )
    else:
        assign = assign_groups_naive_stratified(grp, train_ratio=train_frac, val_ratio=val_frac, seed=seed)

    stats  = write_splits_streaming(
        in_parquet=str(in_parquet), out_dir=str(out_dir),
        group_table=grp, group_assign=assign, batch_size=batch_size,
    )
    report = {
        "split":          "split1_group_stratified",
        "in_parquet":     str(in_parquet),
        "out_dir":        str(out_dir),
        "seed":           int(seed),
        "row_weighted":   bool(row_weighted),
        "groups":         int(len(grp)),
        "rows_total":     int(grp["n_rows"].sum()),
        "attacks_total":  int(grp["attack_rows"].sum()),
        "splits":         make_report(stats),
    }
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    (out_path / "split_report.json").write_text(json.dumps(report, indent=2))
    return out_path


def main():
    """CLI entry point. Parses arguments and runs the group-stratified split builder."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet",   required=True)
    ap.add_argument("--out_dir",      required=True)
    ap.add_argument("--train_ratio",  type=float, default=0.70)
    ap.add_argument("--val_ratio",    type=float, default=0.15)
    ap.add_argument("--test_ratio",   type=float, default=0.15)
    ap.add_argument("--seed",         type=int,   default=104)
    ap.add_argument("--batch_size",   type=int,   default=131072)
    ap.add_argument("--row_weighted", type=str,   default="true")
    a = ap.parse_args()

    if abs((a.train_ratio + a.val_ratio + a.test_ratio) - 1.0) > 1e-6:
        raise SystemExit("Ratios must sum to 1.0")

    row_weighted = str(a.row_weighted).lower() in ("1", "true", "yes", "y")

    print("[*] Building group table...")
    grp = build_group_table(a.in_parquet, batch_size=a.batch_size)
    print(f"  groups      : {len(grp):,}")
    print(f"  rows        : {int(grp['n_rows'].sum()):,}")
    print(f"  attack rows : {int(grp['attack_rows'].sum()):,}")
    print()

    print("[*] Assigning groups to splits...")
    if row_weighted:
        assign = assign_groups_row_weighted(
            grp, train_ratio=a.train_ratio, val_ratio=a.val_ratio, test_ratio=a.test_ratio, seed=a.seed
        )
    else:
        assign = assign_groups_naive_stratified(
            grp, train_ratio=a.train_ratio, val_ratio=a.val_ratio, seed=a.seed
        )

    print("[*] Writing parquet splits...")
    stats = write_splits_streaming(
        in_parquet=a.in_parquet, out_dir=a.out_dir,
        group_table=grp, group_assign=assign, batch_size=a.batch_size,
    )

    report = {
        "protocol":       "split1_group_stratified",
        "in_parquet":     str(a.in_parquet),
        "out_dir":        str(a.out_dir),
        "seed":           int(a.seed),
        "row_weighted":   bool(row_weighted),
        "groups":         int(len(grp)),
        "rows_total":     int(grp["n_rows"].sum()),
        "attacks_total":  int(grp["attack_rows"].sum()),
        "splits": {
            k: {"rows": int(v["rows"]), "attacks": int(v["attacks"])}
            for k, v in stats.items()
        },
        "notes": [
            "Groups are (orig_h, resp_h). All rows in a group go to the same split.",
            "Dominant label: any-attack-wins; otherwise BENIGN.",
            "Stratification is by group count, not row volume. Val/test may have very few attack rows if attack traffic is concentrated in few large groups. USE FOR LEAKAGE DIAGNOSTICS ONLY.",
        ],
    }
    Path(a.out_dir).mkdir(parents=True, exist_ok=True)
    (Path(a.out_dir) / "split_report.json").write_text(json.dumps(report, indent=2))
    print("[*] Done.")
    for s in ["train", "val", "test"]:
        print(f"  {s:5s}: rows={stats[s]['rows']:,} attacks={stats[s]['attacks']:,}")


if __name__ == "__main__":
    main()
