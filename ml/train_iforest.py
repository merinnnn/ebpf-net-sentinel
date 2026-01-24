#!/usr/bin/env python3
import argparse
import json
import os
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

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

    drop_cols = {args.label_col, "Label"}
    feat_cols = [c for c in df.columns if c not in drop_cols and pd.api.types.is_numeric_dtype(df[c])]
    X = df[feat_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float32)

    # 60/20/20 stratified split
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.25, random_state=args.seed, stratify=y_temp
    )

    X_train_b = X_train[y_train == 0]

    scaler = StandardScaler()
    X_train_b_s = scaler.fit_transform(X_train_b)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)

    model = IsolationForest(random_state=args.seed, n_estimators=200, n_jobs=-1)
    model.fit(X_train_b_s)

    def score(m, Xs):
        return -m.decision_function(Xs)

    val_scores = score(model, X_val_s)
    test_scores = score(model, X_test_s)

    metrics = {
        "val_auc": float(roc_auc_score(y_val, val_scores)),
        "test_auc": float(roc_auc_score(y_test, test_scores)),
        "n_features": len(feat_cols),
        "seed": args.seed,
        "label_col": args.label_col,
    }

    joblib.dump(model, os.path.join(args.outdir, "model.joblib"))
    joblib.dump(scaler, os.path.join(args.outdir, "scaler.joblib"))
    with open(os.path.join(args.outdir, "features.json"), "w") as f:
        json.dump(feat_cols, f, indent=2)
    with open(os.path.join(args.outdir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    main()
