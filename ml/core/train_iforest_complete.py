#!/usr/bin/env python3
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
    classification_report,
)
LABEL_COL = "label_family"
IS_ATTACK_COL = "is_attack"
DAY_COL = "day"
RANDOM_SEED = 1337


def split_xy_binary(df: pd.DataFrame, use_only_benign_for_train=True):
    """
    For Isolation Forest: train on BENIGN only, test on everything
    """
    # Binary labels: 0=BENIGN, 1=ATTACK
    y_binary = (df[IS_ATTACK_COL] == 1).astype(int)
    
    # Keep original labels for per-attack analysis
    y_labels = df[LABEL_COL].astype(str)
    day = df[DAY_COL].astype(str)
    
    # Drop label columns from features
    X = df.drop(columns=[LABEL_COL, IS_ATTACK_COL, DAY_COL, 
                          'label_raw', 'label_time_offset_sec',
                          'label_halfday_shift_sec', 'label_window_pre_slop_sec',
                          'label_window_post_slop_sec'], errors='ignore')
    
    return X, y_binary, y_labels, day


def make_preprocessor(X_train: pd.DataFrame):
    """Preprocessor for numeric features only (drop categoricals for IF)"""
    # For Isolation Forest, we typically use only numeric features
    # Categorical features like IP addresses don't work well
    
    numeric_cols = [c for c in X_train.columns 
                    if X_train[c].dtype in ['int64', 'float64', 'int32', 'float32']]
    
    # Remove non-feature columns
    exclude = ['ts', 'start_ts', 'end_ts', 't_end', 'run_id']
    numeric_cols = [c for c in numeric_cols if c not in exclude]
    
    numeric = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
    ])
    
    pre = ColumnTransformer(
        transformers=[("num", numeric, numeric_cols)],
        remainder="drop",
    )
    
    return pre, numeric_cols


def plot_confusion(cm: np.ndarray, labels: list, out_png: str):
    """Plot confusion matrix"""
    plt.figure(figsize=(8, 6))
    
    # Normalize
    cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    
    plt.imshow(cm_norm, interpolation='nearest', cmap='Blues')
    plt.title('Confusion Matrix (Normalized)')
    plt.colorbar()
    
    tick_marks = np.arange(len(labels))
    plt.xticks(tick_marks, labels)
    plt.yticks(tick_marks, labels)
    
    # Add text annotations
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
    """Evaluate binary classification"""
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }
    
    if y_scores is not None:
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_scores))
        except:
            metrics["roc_auc"] = None
    
    return metrics


def per_attack_metrics(y_labels: pd.Series, y_true: np.ndarray, 
                       y_pred: np.ndarray):
    """Calculate detection rate per attack type"""
    results = {}
    
    for attack_type in sorted(y_labels.unique()):
        if attack_type == "BENIGN":
            continue
            
        mask = (y_labels == attack_type).to_numpy()
        if mask.sum() == 0:
            continue
            
        results[attack_type] = {
            "count": int(mask.sum()),
            "detected": int((y_pred[mask] == 1).sum()),
            "detection_rate": float((y_pred[mask] == 1).mean()),
        }
    
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits_dir", required=True)
    ap.add_argument("--run_name", required=True)
    ap.add_argument("--out_models_dir", default="data/models")
    ap.add_argument("--out_reports_dir", default="data/reports")
    ap.add_argument("--contamination", type=float, default=0.1,
                   help="Expected proportion of outliers (attacks) in training data")
    ap.add_argument("--n_estimators", type=int, default=100)
    ap.add_argument("--max_samples", type=int, default=256)
    args = ap.parse_args()
    
    os.makedirs(args.out_models_dir, exist_ok=True)
    os.makedirs(args.out_reports_dir, exist_ok=True)
    
    # Load data
    train_df = pd.read_parquet(os.path.join(args.splits_dir, "train.parquet"))
    val_df = pd.read_parquet(os.path.join(args.splits_dir, "val.parquet"))
    test_df = pd.read_parquet(os.path.join(args.splits_dir, "test.parquet"))
    
    # Split features and labels
    X_train, y_train, labels_train, day_train = split_xy_binary(train_df)
    X_val, y_val, labels_val, day_val = split_xy_binary(val_df)
    X_test, y_test, labels_test, day_test = split_xy_binary(test_df)
    
    print(f"[*] Training set: {len(X_train)} samples")
    print(f"  BENIGN: {(y_train == 0).sum()} ({(y_train == 0).mean()*100:.1f}%)")
    print(f"  ATTACK: {(y_train == 1).sum()} ({(y_train == 1).mean()*100:.1f}%)")
    
    print(f"[*] Validation set: {len(X_val)} samples")
    print(f"  BENIGN: {(y_val == 0).sum()} ({(y_val == 0).mean()*100:.1f}%)")
    print(f"  ATTACK: {(y_val == 1).sum()} ({(y_val == 1).mean()*100:.1f}%)")
    
    print(f"[*] Test set: {len(X_test)} samples")
    print(f"  BENIGN: {(y_test == 0).sum()} ({(y_test == 0).mean()*100:.1f}%)")
    print(f"  ATTACK: {(y_test == 1).sum()} ({(y_test == 1).mean()*100:.1f}%)")

    # drop all-null columns (prevents sklearn imputer warning)
    all_null = [c for c in X_train.columns if X_train[c].isna().all()]
    if all_null:
        X_train = X_train.drop(columns=all_null)
        X_val = X_val.drop(columns=all_null, errors="ignore")
        X_test = X_test.drop(columns=all_null, errors="ignore")
    
    # Build preprocessor
    pre, numeric_cols = make_preprocessor(X_train)
    
    print(f"\nUsing {len(numeric_cols)} numeric features:")
    print(f"  {', '.join(numeric_cols[:10])}...")
    
    # Train Isolation Forest on BENIGN data only (unsupervised)
    X_train_benign = X_train[y_train == 0]
    print(f"\nTraining on BENIGN samples only: {len(X_train_benign)}")
    
    model = IsolationForest(
        n_estimators=args.n_estimators,
        max_samples=args.max_samples,
        contamination=args.contamination,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    
    pipe = Pipeline(steps=[
        ("pre", pre),
        ("clf", model),
    ])
    
    print("\n[*] Training Isolation Forest...")
    pipe.fit(X_train_benign)
    
    # Predict (IF returns -1 for outliers/attacks, 1 for inliers/benign)
    # Convert to 0/1 (0=benign, 1=attack)
    def predict_binary(X):
        pred = pipe.predict(X)
        return (pred == -1).astype(int)
    
    def get_scores(X):
        """Get anomaly scores (more negative = more anomalous)"""
        return -pipe.decision_function(X)
    
    y_train_pred = predict_binary(X_train)
    y_val_pred = predict_binary(X_val)
    y_test_pred = predict_binary(X_test)
    
    scores_val = get_scores(X_val)
    scores_test = get_scores(X_test)
    
    # Evaluate
    print("\n[*] VALIDATION METRICS:")
    val_metrics = evaluate_binary(y_val.to_numpy(), y_val_pred, scores_val)
    for k, v in val_metrics.items():
        print(f"  {k}: {v:.4f}" if v is not None else f"  {k}: N/A")
    
    print("\n[*] TEST METRICS:")
    test_metrics = evaluate_binary(y_test.to_numpy(), y_test_pred, scores_test)
    for k, v in test_metrics.items():
        print(f"  {k}: {v:.4f}" if v is not None else f"  {k}: N/A")
    
    # Per-attack-type detection
    print("\n[*] PER-ATTACK DETECTION (TEST):")
    per_attack = per_attack_metrics(labels_test, y_test.to_numpy(), y_test_pred)
    for attack, stats in sorted(per_attack.items()):
        print(f"  {attack:15s}: {stats['detected']:4d}/{stats['count']:4d} "
              f"({stats['detection_rate']*100:5.1f}%)")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_test_pred, labels=[0, 1])
    cm_png = os.path.join(args.out_reports_dir, 
                           f"{args.run_name}_iforest_confusion.png")
    plot_confusion(cm, ["BENIGN", "ATTACK"], cm_png)
    
    # Save model
    model_path = os.path.join(args.out_models_dir, 
                              f"{args.run_name}_iforest.joblib")
    joblib.dump(pipe, model_path)
    
    # Save detailed report
    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "run_name": args.run_name,
        "splits_dir": args.splits_dir,
        "model_params": {
            "n_estimators": args.n_estimators,
            "max_samples": args.max_samples,
            "contamination": args.contamination,
            "random_state": RANDOM_SEED,
        },
        "features": {
            "numeric_features": numeric_cols,
            "num_features": len(numeric_cols),
        },
        "training": {
            "train_on_benign_only": True,
            "num_benign_samples": int((y_train == 0).sum()),
        },
        "validation": val_metrics,
        "test": test_metrics,
        "per_attack_detection": per_attack,
        "model_path": model_path,
        "confusion_png": cm_png,
    }
    
    summary_path = os.path.join(args.out_reports_dir, 
                                f"{args.run_name}_iforest_summary.json")
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[*] Saved model: {model_path}")
    print(f"[*] Saved confusion: {cm_png}")
    print(f"[*] Saved summary: {summary_path}")


if __name__ == "__main__":
    main()