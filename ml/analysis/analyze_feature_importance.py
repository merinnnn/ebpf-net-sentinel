#!/usr/bin/env python3
"""
Permutation feature importance for two saved models (baseline vs eBPF).

Robust to:
- different feature sets (baseline 10 vs enhanced 18)
- models saved as dict {"model","scaler","features",...} (our training format)
- missing columns in test parquet (will error with a clear message)

Outputs:
- feature_importance_summary.json
- plots (bar charts) for each model
"""
import argparse, json, os
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.inspection import permutation_importance
from sklearn.pipeline import Pipeline

def load_pack(path: str):
    import joblib
    pack = joblib.load(path)
    if isinstance(pack, dict) and "model" in pack:
        return pack
    # allow raw estimator
    return {"model": pack, "scaler": None, "features": None}

def select_X(df: pd.DataFrame, features):
    missing = [c for c in features if c not in df.columns]
    if missing:
        raise ValueError(f"Test data is missing expected features: {missing}")
    return df[features].copy()

def compute_perm(model_pack, df_test: pd.DataFrame, y: np.ndarray, n_repeats: int, random_state: int):
    model = model_pack["model"]
    scaler = model_pack.get("scaler")
    features = model_pack.get("features")
    if features is None:
        # fallback: use numeric columns except labels
        drop_cols = {"label","label_family","is_attack","day"}
        features = [c for c in df_test.columns if c not in drop_cols and pd.api.types.is_numeric_dtype(df_test[c])]
    X = select_X(df_test, features)

    if scaler is not None:
        est = Pipeline([("scaler", scaler), ("model", model)])
        # Use DataFrame so scaler gets arrays but keeps column order; pipeline handles it.
        X_use = X
    else:
        est = model
        X_use = X

    res = permutation_importance(
        est, X_use, y,
        n_repeats=n_repeats,
        random_state=random_state,
        scoring="roc_auc",
        n_jobs=-1,
    )

    importances = res.importances_mean
    stds = res.importances_std
    order = np.argsort(importances)[::-1]
    rows = []
    for i in order:
        rows.append({
            "feature": str(features[i]),
            "importance_mean": float(importances[i]),
            "importance_std": float(stds[i]),
        })
    return rows

def plot_top(rows, out_png: Path, top_k: int):
    top = rows[:top_k]
    feats = [r["feature"] for r in top][::-1]
    vals = [r["importance_mean"] for r in top][::-1]
    errs = [r["importance_std"] for r in top][::-1]

    plt.figure(figsize=(10, max(4, 0.35*len(feats))))
    plt.barh(feats, vals, xerr=errs)
    plt.xlabel("Permutation importance (ROC-AUC drop)")
    plt.tight_layout()
    plt.savefig(out_png, dpi=160)
    plt.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model_baseline", required=True)
    ap.add_argument("--model_ebpf", required=True)
    ap.add_argument("--test_data_baseline", required=True)
    ap.add_argument("--test_data_ebpf", required=True)
    ap.add_argument("--out_dir", required=True)
    ap.add_argument("--n_repeats", type=int, default=10)
    ap.add_argument("--top_k", type=int, default=20)
    ap.add_argument("--random_state", type=int, default=42)
    ap.add_argument(
        "--sample_n",
        type=int,
        default=50000,
        help="Downsample test set to this many rows per model (stratified by is_attack). 0 = use all rows.",
    )
    ap.add_argument(
        "--n_jobs",
        type=int,
        default=4,
        help="Parallel jobs for permutation importance. Use small values to avoid OOM.",
    )
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    pack_b = load_pack(args.model_baseline)
    pack_e = load_pack(args.model_ebpf)

    # Read only required columns to avoid loading multi-million-row parquets into memory.
    # Our training scripts save a feature list into the model pack.
    feats_b = pack_b.get("features")
    feats_e = pack_e.get("features")

    if feats_b is None or feats_e is None:
        # Fallback: read everything (may be large). We keep the older behavior.
        df_b = pd.read_parquet(args.test_data_baseline)
        df_e = pd.read_parquet(args.test_data_ebpf)
    else:
        df_b = pd.read_parquet(args.test_data_baseline, columns=list(dict.fromkeys(list(feats_b) + ["is_attack"])))
        df_e = pd.read_parquet(args.test_data_ebpf, columns=list(dict.fromkeys(list(feats_e) + ["is_attack"])))

    # We evaluate importance for binary ATTACK vs BENIGN.
    if "is_attack" not in df_b.columns or "is_attack" not in df_e.columns:
        raise SystemExit("test parquet must contain is_attack column (0/1)")

    # Optional stratified downsample to keep runtime/memory reasonable.
    def stratified_sample(df: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
        if n <= 0 or len(df) <= n:
            return df
        # Stratify on is_attack (binary)
        g = df.groupby("is_attack", group_keys=False)
        parts = []
        for _, part in g:
            frac = n / len(df)
            # sample at least 1 row if group is tiny
            k = max(1, int(round(len(part) * frac)))
            parts.append(part.sample(n=min(k, len(part)), random_state=seed))
        out = pd.concat(parts, axis=0).sample(frac=1.0, random_state=seed)  # shuffle
        # Trim to exactly n if we overshot due to rounding
        if len(out) > n:
            out = out.sample(n=n, random_state=seed)
        return out

    df_b = stratified_sample(df_b, args.sample_n, args.random_state)
    df_e = stratified_sample(df_e, args.sample_n, args.random_state)

    y_b = df_b["is_attack"].astype(int).to_numpy()
    y_e = df_e["is_attack"].astype(int).to_numpy()

    # Thread control: permutation_importance uses joblib; too many workers can OOM.
    os.environ.setdefault("JOBLIB_TEMP_FOLDER", str(out_dir / "_joblib_tmp"))

    def compute_perm_with_jobs(model_pack, df_test, y):
        model = model_pack["model"]
        scaler = model_pack.get("scaler")
        features = model_pack.get("features")
        if features is None:
            drop_cols = {"label","label_family","is_attack","day"}
            features = [c for c in df_test.columns if c not in drop_cols and pd.api.types.is_numeric_dtype(df_test[c])]
        X = select_X(df_test, features)
        if scaler is not None:
            est = Pipeline([("scaler", scaler), ("model", model)])
            X_use = X
        else:
            est = model
            X_use = X
        res = permutation_importance(
            est,
            X_use,
            y,
            n_repeats=args.n_repeats,
            random_state=args.random_state,
            scoring="roc_auc",
            n_jobs=args.n_jobs,
        )
        importances = res.importances_mean
        stds = res.importances_std
        order = np.argsort(importances)[::-1]
        return [
            {"feature": str(features[i]), "importance_mean": float(importances[i]), "importance_std": float(stds[i])}
            for i in order
        ]

    rows_b = compute_perm_with_jobs(pack_b, df_b, y_b)
    rows_e = compute_perm_with_jobs(pack_e, df_e, y_e)

    plot_top(rows_b, out_dir/"baseline_perm_importance.png", args.top_k)
    plot_top(rows_e, out_dir/"ebpf_perm_importance.png", args.top_k)

    summary = {
        "baseline": rows_b[:args.top_k],
        "ebpf": rows_e[:args.top_k],
    }
    (out_dir/"feature_importance_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"[*] Summary saved: {out_dir/'feature_importance_summary.json'}")
    print(f"[*] Plots saved in: {out_dir}")

if __name__ == "__main__":
    main()
