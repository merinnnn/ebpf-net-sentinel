#!/usr/bin/env python3
import argparse
import json
import os
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, f1_score, precision_recall_fscore_support
from sklearn.preprocessing import StandardScaler

# TODO: implement chunked reading for large CSVs
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--label_col", default="is_attack", help="Binary label column (0 benign, 1 attack)")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    df = pd.read_csv(args.csv)

    if args.label_col not in df.columns:
        raise ValueError(f"Missing label column: {args.label_col}")

    y = df[args.label_col].astype(int).to_numpy()

    # feature columns: numeric columns except label-ish
    drop_cols = {args.label_col, "Label"}
    feat_cols = []
    for c in df.columns:
        if c in drop_cols:
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            feat_cols.append(c)

    X = df[feat_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float32)

    # 60/20/20 stratified split
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.25, random_state=args.seed, stratify=y_temp
    )

    # Train IF on BENIGN only
    X_train_b = X_train[y_train == 0]

    scaler = StandardScaler()
    X_train_b_s = scaler.fit_transform(X_train_b)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)

    def score(model, Xs):
        return -model.decision_function(Xs)

    grid = []
    for n_estimators in [200, 400]:
        for max_samples in [0.2, 0.5, 1.0]:
            for contamination in [0.01, 0.02, 0.05]:
                grid.append((n_estimators, max_samples, contamination))

    best_auc = -1.0
    best_params = None
    best_model = None

    for n_est, max_s, cont in grid:
        model = IsolationForest(
            n_estimators=n_est,
            max_samples=max_s,
            contamination=cont,
            random_state=args.seed,
            n_jobs=-1
        )
        model.fit(X_train_b_s)
        val_scores = score(model, X_val_s)
        auc = roc_auc_score(y_val, val_scores)
        if auc > best_auc:
            best_auc = auc
            best_params = {"n_estimators": n_est, "max_samples": max_s, "contamination": cont}
            best_model = model

    # Choose threshold by best F1 on validation
    val_scores = score(best_model, X_val_s)
    thresholds = np.quantile(val_scores, np.linspace(0.80, 0.995, 50))

    best_thr, best_f1 = None, -1.0
    for thr in thresholds:
        yhat = (val_scores >= thr).astype(int)
        f1 = f1_score(y_val, yhat)
        if f1 > best_f1:
            best_f1 = f1
            best_thr = float(thr)

    test_scores = score(best_model, X_test_s)
    yhat_test = (test_scores >= best_thr).astype(int)

    p, r, f1, _ = precision_recall_fscore_support(y_test, yhat_test, average="binary", zero_division=0)
    test_auc = roc_auc_score(y_test, test_scores)

    metrics = {
        "best_params": best_params,
        "val_auc": float(best_auc),
        "val_best_f1": float(best_f1),
        "threshold": float(best_thr),
        "test_auc": float(test_auc),
        "test_precision": float(p),
        "test_recall": float(r),
        "test_f1": float(f1),
        "n_features": len(feat_cols),
        "seed": args.seed,
        "label_col": args.label_col,
    }

    joblib.dump(best_model, os.path.join(args.outdir, "model.joblib"))
    joblib.dump(scaler, os.path.join(args.outdir, "scaler.joblib"))
    with open(os.path.join(args.outdir, "features.json"), "w") as f:
        json.dump(feat_cols, f, indent=2)
    with open(os.path.join(args.outdir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    main()
