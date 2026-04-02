#!/usr/bin/env python3
"""Isolation Forest for network anomaly detection."""

from datetime import datetime
import argparse
import json
import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    roc_curve,
)

from ml.methods.logging_utils import (
    print_artifacts,
    print_feature_summary,
    print_metrics_block,
    print_per_attack_block,
    print_preprocessing_summary,
    print_run_header,
    print_split_summary,
    print_tuning_summary,
)

LABEL_COL     = "label_family"
IS_ATTACK_COL = "is_attack"
DAY_COL       = "day"
RANDOM_SEED   = 1337

def split_xy_binary(df: pd.DataFrame):
    """For Isolation Forest: returns X, binary y, label series, and day series."""
    y_binary = (df[IS_ATTACK_COL] == 1).astype(int)
    y_labels = df[LABEL_COL].astype(str)
    day      = df[DAY_COL].astype(str)
    X = df.drop(columns=[LABEL_COL, IS_ATTACK_COL, DAY_COL,
                          'label_raw', 'label_time_offset_sec',
                          'label_halfday_shift_sec', 'label_window_pre_slop_sec',
                          'label_window_post_slop_sec'], errors='ignore')
    return X, y_binary, y_labels, day

def make_preprocessor(X_train: pd.DataFrame):
    """Numeric-only preprocessor. Drops all-NaN columns before building the pipeline."""
    numeric_cols = [c for c in X_train.columns
                    if X_train[c].dtype in ['int64', 'float64', 'int32', 'float32']]
    exclude      = ['ts', 'start_ts', 'end_ts', 't_end', 'run_id']
    numeric_cols = [c for c in numeric_cols if c not in exclude]

    kept, dropped = [], []
    for c in numeric_cols:
        if c in X_train.columns and X_train[c].notna().any():
            kept.append(c)
        else:
            dropped.append(c)
    if dropped:
        print(f"[*] Dropping all-NaN columns: {dropped}")
    numeric_cols = kept

    numeric = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler",  StandardScaler()),
    ])
    pre = ColumnTransformer(
        transformers=[("num", numeric, numeric_cols)],
        remainder="drop",
    )
    return pre, numeric_cols, dropped

def plot_confusion(cm: np.ndarray, labels: list, out_png: str):
    """Plot a normalized confusion matrix."""
    plt.figure(figsize=(8, 6))
    cm_norm  = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    plt.imshow(cm_norm, interpolation='nearest', cmap='Blues')
    plt.title('Confusion Matrix (Normalized)')
    plt.colorbar()
    tick_marks = np.arange(len(labels))
    plt.xticks(tick_marks, labels)
    plt.yticks(tick_marks, labels)
    for i in range(len(labels)):
        for j in range(len(labels)):
            plt.text(j, i, f'{cm[i, j]}\n({cm_norm[i, j]:.2%})',
                     ha="center", va="center",
                     color="white" if cm_norm[i, j] > 0.5 else "black")
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.tight_layout()
    plt.savefig(out_png, dpi=200)
    plt.close()

def evaluate_binary(y_true: np.ndarray, y_pred: np.ndarray,
                    y_scores: np.ndarray = None):
    metrics = {
        "accuracy":  float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall":    float(recall_score(y_true, y_pred, zero_division=0)),
        "f1":        float(f1_score(y_true, y_pred, zero_division=0)),
    }
    if y_scores is not None:
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_scores))
        except Exception:
            metrics["roc_auc"] = None
    return metrics

def per_attack_metrics(y_labels: pd.Series, y_true: np.ndarray, y_pred: np.ndarray):
    """Detection rate per attack type."""
    results = {}
    for attack_type in sorted(y_labels.unique()):
        if attack_type == "BENIGN":
            continue
        mask = (y_labels == attack_type).to_numpy()
        if mask.sum() == 0:
            continue
        results[attack_type] = {
            "count":          int(mask.sum()),
            "detected":       int((y_pred[mask] == 1).sum()),
            "detection_rate": float((y_pred[mask] == 1).mean()),
        }
    return results

def tune_contamination_on_val(pre, X_train_benign, X_val, y_val,
                               n_estimators, max_samples,
                               candidates=None):
    """
    Grid-search contamination on val F1. Falls back to 'auto' if val has <10 positives.
    """
    if candidates is None:
        candidates = [0.001, 0.005, 0.01, 0.02, 0.05, 0.10, 0.15, 0.20]

    n_pos = int((y_val == 1).sum())
    if n_pos < 10:
        print(f"  [!] Only {n_pos} attack samples in val; skipping contamination tuning, using 'auto'.")
        return "auto"

    best_c, best_f1 = "auto", -1.0
    print("  Tuning contamination on val F1:")
    for c in candidates:
        clf_try  = IsolationForest(n_estimators=n_estimators, max_samples=max_samples,
                                   contamination=c, random_state=RANDOM_SEED, n_jobs=-1)
        pipe_try = Pipeline(steps=[("pre", pre), ("clf", clf_try)])
        pipe_try.fit(X_train_benign)
        yhat = (pipe_try.predict(X_val) == -1).astype(int)
        f1   = f1_score(y_val, yhat, zero_division=0)
        print(f"    contamination={c:.3f}  val_f1={f1:.4f}")
        if f1 > best_f1:
            best_f1, best_c = f1, c

    print(f"  Best contamination: {best_c} (val_f1={best_f1:.4f})")
    return best_c

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits_dir",       required=True)
    ap.add_argument("--run_name",         required=True)
    ap.add_argument("--out_models_dir",   default="data/models")
    ap.add_argument("--out_reports_dir",  default="data/reports")
    ap.add_argument("--contamination",    type=float, default=None,
                    help="contamination for IsolationForest; if omitted, auto-tuned on val F1")
    ap.add_argument("--n_estimators",     type=int, default=100)
    ap.add_argument("--max_samples",      type=int, default=512)
    args = ap.parse_args()

    os.makedirs(args.out_models_dir,  exist_ok=True)
    os.makedirs(args.out_reports_dir, exist_ok=True)

    print_run_header(
        model_name="Isolation Forest",
        run_name=args.run_name,
        splits_dir=args.splits_dir,
        out_models_dir=args.out_models_dir,
        out_reports_dir=args.out_reports_dir,
        params={
            "n_estimators":  args.n_estimators,
            "max_samples":   args.max_samples,
            "contamination": args.contamination if args.contamination is not None else "auto",
            "random_state":  RANDOM_SEED,
        },
    )

    train_df = pd.read_parquet(os.path.join(args.splits_dir, "train.parquet"))
    val_df   = pd.read_parquet(os.path.join(args.splits_dir, "val.parquet"))
    test_df  = pd.read_parquet(os.path.join(args.splits_dir, "test.parquet"))

    X_train, y_train, labels_train, _ = split_xy_binary(train_df)
    X_val,   y_val,   labels_val,   _ = split_xy_binary(val_df)
    X_test,  y_test,  labels_test,  _ = split_xy_binary(test_df)

    print("[*] Split sizes")
    print_split_summary("train", len(X_train), int((y_train == 1).sum()))
    print_split_summary("val",   len(X_val),   int((y_val   == 1).sum()))
    print_split_summary("test",  len(X_test),  int((y_test  == 1).sum()))

    X_train_benign = X_train[y_train == 0]
    pre, numeric_cols, dropped = make_preprocessor(X_train_benign)

    print_preprocessing_summary(
        "numeric-only ColumnTransformer with median imputation + StandardScaler, fit on benign train rows only"
    )
    print_feature_summary(numeric_cols, dropped=dropped)
    print(f"  benign_train_rows : {len(X_train_benign):,}")

    if args.contamination is not None:
        chosen_contamination = args.contamination
        tuning_lines = [
            "strategy         : user-supplied contamination",
            f"contamination    : {chosen_contamination}",
        ]
    else:
        print("[*] Contamination search")
        chosen_contamination = tune_contamination_on_val(
            pre, X_train_benign, X_val, y_val.to_numpy(),
            args.n_estimators, args.max_samples,
        )
        tuning_lines = [
            "strategy         : maximize validation F1",
            f"contamination    : {chosen_contamination}",
            f"val_attack_rows  : {int((y_val == 1).sum()):,}",
        ]
    print_tuning_summary("Contamination selection", tuning_lines)

    model = IsolationForest(
        n_estimators=args.n_estimators,
        max_samples=args.max_samples,
        contamination=chosen_contamination,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    pipe = Pipeline(steps=[("pre", pre), ("clf", model)])

    print("[*] Training")
    pipe.fit(X_train_benign)

    # Negate decision_function so higher score = more anomalous.
    def get_scores(X):
        return -pipe.decision_function(X)

    scores_train = get_scores(X_train)
    scores_val   = get_scores(X_val)
    scores_test  = get_scores(X_test)

    n_pos_val = int((y_val == 1).sum())
    if n_pos_val >= 10:
        _, _, thresholds = roc_curve(y_val.to_numpy(), scores_val)
        f1s      = [f1_score(y_val.to_numpy(), (scores_val >= thr).astype(int), zero_division=0)
                    for thr in thresholds]
        best_thr = float(thresholds[int(np.argmax(f1s))])
        threshold_lines = [
            "strategy         : maximize validation F1",
            f"threshold        : {best_thr:.5f}",
            f"best_val_f1      : {max(f1s):.4f}",
        ]
    else:
        # Fallback: 90th percentile of training anomaly scores.
        best_thr = float(np.percentile(scores_train, 90))
        threshold_lines = [
            "strategy         : fallback train-score percentile",
            "percentile       : 90",
            f"threshold        : {best_thr:.5f}",
        ]
    print_tuning_summary("Decision-threshold selection", threshold_lines)

    y_train_pred = (scores_train >= best_thr).astype(int)
    y_val_pred   = (scores_val   >= best_thr).astype(int)
    y_test_pred  = (scores_test  >= best_thr).astype(int)

    train_metrics = evaluate_binary(y_train.to_numpy(), y_train_pred, scores_train)
    val_metrics   = evaluate_binary(y_val.to_numpy(),   y_val_pred,   scores_val)
    test_metrics  = evaluate_binary(y_test.to_numpy(),  y_test_pred,  scores_test)
    print_metrics_block("Train metrics",      train_metrics)
    print_metrics_block("Validation metrics", val_metrics)
    print_metrics_block("Test metrics",       test_metrics)

    per_attack = per_attack_metrics(labels_test, y_test.to_numpy(), y_test_pred)
    print_per_attack_block("Per-attack detection (test)", per_attack)

    cm     = confusion_matrix(y_test, y_test_pred, labels=[0, 1])
    cm_png = os.path.join(args.out_reports_dir, f"{args.run_name}_iforest_confusion.png")
    plot_confusion(cm, ["BENIGN", "ATTACK"], cm_png)

    model_path = os.path.join(args.out_models_dir, f"{args.run_name}_iforest.joblib")
    joblib.dump(pipe, model_path)

    results = {
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "run_name":    args.run_name,
        "splits_dir":  args.splits_dir,
        "model_params": {
            "n_estimators":     args.n_estimators,
            "max_samples":      args.max_samples,
            "contamination":    chosen_contamination,
            "tuned_threshold":  best_thr,
            "random_state":     RANDOM_SEED,
        },
        "features": {
            "numeric_features": numeric_cols,
            "num_features":     len(numeric_cols),
        },
        "training": {
            "train_on_benign_only":   True,
            "num_benign_samples":     int((y_train == 0).sum()),
        },
        "train":                 train_metrics,
        "validation":            val_metrics,
        "test":                  test_metrics,
        "per_attack_detection":  per_attack,
        "model_path":            model_path,
        "confusion_png":         cm_png,
    }

    summary_path = os.path.join(args.out_reports_dir, f"{args.run_name}_iforest_summary.json")
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)

    print_artifacts(model_path=model_path, summary_path=summary_path, extras={"confpng": cm_png})

if __name__ == "__main__":
    main()
