#!/usr/bin/env python3
import argparse, json
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import roc_auc_score, classification_report

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--modeldir", required=True)
    ap.add_argument("--label_col", default="is_attack")
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    y = df[args.label_col].astype(int).to_numpy()

    feat_cols = json.load(open(f"{args.modeldir}/features.json"))
    X = df[feat_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float32)

    model = joblib.load(f"{args.modeldir}/model.joblib")
    scaler = joblib.load(f"{args.modeldir}/scaler.joblib")
    metrics = json.load(open(f"{args.modeldir}/metrics.json"))
    thr = metrics["threshold"]

    Xs = scaler.transform(X)
    scores = -model.decision_function(Xs)
    auc = roc_auc_score(y, scores)
    yhat = (scores >= thr).astype(int)

    print(f"AUC: {auc:.4f}")
    print(classification_report(y, yhat, digits=4))

if __name__ == "__main__":
    main()
