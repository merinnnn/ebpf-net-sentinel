#!/usr/bin/env python3

import argparse
import json
import os
import time

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
)

LABEL_COL = "label_family"
IS_ATTACK_COL = "is_attack"
DAY_COL = "day"


def load_split(split_dir: str, split_name: str) -> pd.DataFrame:
    path = os.path.join(split_dir, f"{split_name}.parquet")
    if not os.path.exists(path):
        raise SystemExit(f"[!] Missing split file: {path}")
    return pd.read_parquet(path)


def print_split_stats(df: pd.DataFrame, name: str) -> None:
    y = df[IS_ATTACK_COL].astype(int)
    n = len(df)
    n_atk = int((y == 1).sum())
    n_ben = n - n_atk
    print(f"{name}: {n:,} (attacks={n_atk:,}, benign={n_ben:,}, attack%={100*n_atk/max(1,n):.2f}%)")


def get_numeric_features(df: pd.DataFrame):
    exclude = {LABEL_COL, IS_ATTACK_COL, DAY_COL, "label_raw", "run_id"}
    cols = []
    for c in df.columns:
        if c in exclude:
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            # Exclude all-null columns (prevents sklearn imputer warnings downstream)
            if df[c].isna().all():
                continue
            cols.append(c)
    return cols


def plot_confusion_matrix(y_true, y_pred, out_png: str, title: str = "Confusion"):
    from sklearn.metrics import confusion_matrix

    cm = confusion_matrix(y_true, y_pred)
    cm_norm = cm.astype(float) / np.maximum(1.0, cm.sum(axis=1, keepdims=True))
    plt.figure(figsize=(7, 6))
    plt.imshow(cm_norm, interpolation="nearest", cmap="Blues")
    plt.title(title)
    plt.colorbar()
    labels = ["BENIGN", "ATTACK"]
    ticks = np.arange(len(labels))
    plt.xticks(ticks, labels)
    plt.yticks(ticks, labels)
    for i in range(2):
        for j in range(2):
            plt.text(j, i, f"{cm[i,j]}\n({cm_norm[i,j]:.2%})", ha="center", va="center",
                     color="white" if cm_norm[i,j] > 0.5 else "black")
    plt.ylabel("True")
    plt.xlabel("Pred")
    plt.tight_layout()
    plt.savefig(out_png, dpi=200)
    plt.close()


def per_attack_detection(test_df: pd.DataFrame, y_pred: np.ndarray):
    labels = test_df[LABEL_COL].astype(str).to_numpy()
    out = {}
    for fam in sorted(set(labels)):
        if fam == "BENIGN":
            continue
        mask = labels == fam
        total = int(mask.sum())
        if total == 0:
            continue
        hit = int((y_pred[mask] == 1).sum())
        out[fam] = (hit, total, 100.0 * hit / max(1, total))
    return out


def compute_metrics(y_true, y_pred, y_proba=None):
    m = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }
    if y_proba is not None:
        try:
            m["roc_auc"] = float(roc_auc_score(y_true, y_proba))
        except Exception:
            m["roc_auc"] = None
        try:
            m["pr_auc"] = float(average_precision_score(y_true, y_proba))
        except Exception:
            m["pr_auc"] = None
    else:
        m["roc_auc"] = None
        m["pr_auc"] = None
    return m


def tune_threshold_for_f1(y_true: np.ndarray, proba: np.ndarray) -> float:
    # Small, cheap sweep. This fixes the "predict all benign" failure mode.
    ts = np.linspace(0.01, 0.99, 99)
    f1s = [f1_score(y_true, (proba >= t).astype(int), zero_division=0) for t in ts]
    return float(ts[int(np.argmax(f1s))])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits_dir", required=True)
    ap.add_argument("--run_name", default="rf")
    ap.add_argument("--out_models_dir", required=True)
    ap.add_argument("--out_reports_dir", required=True)

    # Hyperparams
    ap.add_argument("--n_estimators", type=int, default=200)
    ap.add_argument("--max_depth", type=int, default=20)
    ap.add_argument("--min_samples_leaf", type=int, default=5)
    ap.add_argument("--random_state", type=int, default=42)
    ap.add_argument("--balance_classes", action="store_true", help="Use class_weight='balanced'")
    ap.add_argument("--class_weight", default=None, help="Override class_weight (e.g. balanced_subsample)")
    ap.add_argument("--tune_threshold", action="store_true", help="Tune decision threshold on validation for best F1")
    args = ap.parse_args()

    out_model = os.path.join(args.out_models_dir, f"{args.run_name}_rf.joblib")
    out_report = os.path.join(args.out_reports_dir, f"{args.run_name}_rf_summary.json")
    out_conf = os.path.join(args.out_reports_dir, f"{args.run_name}_rf_confusion.png")

    train = load_split(args.splits_dir, "train")
    val = load_split(args.splits_dir, "val")
    test = load_split(args.splits_dir, "test")

    print_split_stats(train, "Train")
    print_split_stats(val, "Val")
    print_split_stats(test, "Test")

    features = get_numeric_features(train)
    X_train = train[features]
    y_train = train["is_attack"].astype(int).to_numpy()
    X_val = val[features]
    y_val = val["is_attack"].astype(int).to_numpy()
    X_test = test[features]
    y_test = test["is_attack"].astype(int).to_numpy()

    # Fit scaler on numpy arrays to avoid sklearn "feature names" warnings.
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train.to_numpy(dtype=float, copy=False))
    X_val_s = scaler.transform(X_val.to_numpy(dtype=float, copy=False))
    X_test_s = scaler.transform(X_test.to_numpy(dtype=float, copy=False))

    if args.class_weight not in (None, "None", ""):
        cw = args.class_weight
    elif args.balance_classes:
        cw = "balanced"
    else:
        cw = None
    rf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        min_samples_leaf=args.min_samples_leaf,
        random_state=args.random_state,
        n_jobs=-1,
        class_weight=cw,
    )

    print(f"[*] Training Random Forest (n={args.n_estimators}, depth={args.max_depth})...")
    t0 = time.time()
    rf.fit(X_train_s, y_train)
    fit_s = time.time() - t0
    print(f"[*] Training completed in {fit_s:.1f}s")

    # Validation thresholding
    val_proba = rf.predict_proba(X_val_s)[:, 1]
    threshold = 0.5
    if args.tune_threshold:
        threshold = tune_threshold_for_f1(y_val, val_proba)
    val_pred = (val_proba >= threshold).astype(int)
    val_metrics = compute_metrics(y_val, val_pred, val_proba)
    val_metrics["threshold"] = threshold

    # Test
    test_proba = rf.predict_proba(X_test_s)[:, 1]
    test_pred = (test_proba >= threshold).astype(int)
    test_metrics = compute_metrics(y_test, test_pred, test_proba)
    test_metrics["threshold"] = threshold

    # Train metrics (for overfitting signal)
    train_proba = rf.predict_proba(X_train_s)[:, 1]
    train_pred = (train_proba >= threshold).astype(int)
    train_metrics = compute_metrics(y_train, train_pred, train_proba)
    train_metrics["threshold"] = threshold

    per_attack = per_attack_detection(test, test_pred)

    # Feature importances
    fi = rf.feature_importances_
    top = sorted(zip(features, fi), key=lambda x: x[1], reverse=True)[:10]
    top_features = [{"feature": f, "importance": float(v)} for f, v in top]

    os.makedirs(os.path.dirname(out_model), exist_ok=True)
    os.makedirs(os.path.dirname(out_report), exist_ok=True)
    os.makedirs(os.path.dirname(out_conf), exist_ok=True)

    joblib.dump(
        {"model": rf, "scaler": scaler, "features": features, "threshold": threshold},
        out_model,
    )

    plot_confusion_matrix(y_test, test_pred, out_conf, title="Random Forest Confusion")

    def _gap(a, b):
        if a is None or b is None:
            return None
        return float(a - b)

    summary = {
        "model": "RandomForest",
        "train_seconds": float(fit_s),
        "hyperparams": {
            "n_estimators": args.n_estimators,
            "max_depth": args.max_depth,
            "min_samples_leaf": args.min_samples_leaf,
            "random_state": args.random_state,
            "class_weight": cw,
            "tune_threshold": bool(args.tune_threshold),
            "threshold": threshold,
        },
        "features": features,
        "train_metrics": train_metrics,
        "val_metrics": val_metrics,
        "test_metrics": test_metrics,
        "overfit_gaps": {
            "f1_train_minus_val": _gap(train_metrics.get("f1"), val_metrics.get("f1")),
            "rocauc_train_minus_val": _gap(train_metrics.get("roc_auc"), val_metrics.get("roc_auc")),
            "prauc_train_minus_val": _gap(train_metrics.get("pr_auc"), val_metrics.get("pr_auc")),
        },
        "per_attack_detection": per_attack,
        "top_features": top_features,
    }

    with open(out_report, "w") as f:
        json.dump(summary, f, indent=2)

    print("[*] VALIDATION METRICS:")
    for k, v in val_metrics.items():
        print(f"  {k:12s}: {v}")
    print("[*] TEST METRICS:")
    for k, v in test_metrics.items():
        print(f"  {k:12s}: {v}")
    print("[*] PER-ATTACK DETECTION:")
    for fam, (hit, total, pct) in per_attack.items():
        print(f"  {fam:15s}: {hit:6d}/{total:6d} ({pct:5.1f}%)")

    print("\nModel:", out_model)
    print("Summary:", out_report)
    print("Confusion:", out_conf)


if __name__ == "__main__":
    main()
