#!/usr/bin/env python3
"""Random Forest for network anomaly detection."""

import argparse, json, os, time, joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve,
    average_precision_score,
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

DROP_COLS = [
    'label_family', 'is_attack', 'day', 'label_raw', 'run_id',
    'ts', 'start_ts', 'end_ts', 't_end', 'orig_h', 'resp_h',
    'src_ip', 'dst_ip', 'k',
    'label_time_offset_sec', 'label_halfday_shift_sec',
    'label_window_pre_slop_sec', 'label_window_post_slop_sec',
]

def prepare_data(df):
    """Extract numeric features. Excludes columns in DROP_COLS."""
    X = df.drop(columns=DROP_COLS, errors='ignore')
    numeric = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])
               and not X[c].isna().all()]
    return X[numeric], (df['is_attack'] == 1).astype(int), df['label_family'].astype(str)

def evaluate(y_true, y_pred, y_prob=None):
    m = {
        'accuracy':  float(accuracy_score(y_true, y_pred)),
        'precision': float(precision_score(y_true, y_pred, zero_division=0)),
        'recall':    float(recall_score(y_true, y_pred, zero_division=0)),
        'f1':        float(f1_score(y_true, y_pred, zero_division=0)),
    }
    if y_prob is not None:
        try:
            m['roc_auc'] = float(roc_auc_score(y_true, y_prob))
            m['pr_auc']  = float(average_precision_score(y_true, y_prob))
        except Exception:
            m['roc_auc'] = None
            m['pr_auc']  = None
    return m

def per_attack(labels, y_true, y_pred):
    r = {}
    for a in sorted(labels.unique()):
        if a == "BENIGN":
            continue
        mask = (labels == a).to_numpy()
        if mask.sum() == 0:
            continue
        det  = (y_pred[mask] == 1).sum()
        r[a] = {'count': int(mask.sum()), 'detected': int(det),
                'detection_rate': float(det / mask.sum())}
    return r

def tune_threshold_on_val(y_val, y_prob_val):
    """Return the threshold that maximises F1 on the validation set."""
    _, _, thresholds = roc_curve(y_val, y_prob_val)
    f1s  = [f1_score(y_val, (y_prob_val >= t).astype(int), zero_division=0) for t in thresholds]
    best = thresholds[int(np.argmax(f1s))]
    print(f"  Val-tuned threshold: {best:.5f}  (val F1={max(f1s):.4f})")
    return float(best), float(max(f1s))

def plot_cm(cm, out):
    plt.figure(figsize=(8, 6))
    cm_n = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    plt.imshow(cm_n, cmap='Blues')
    plt.title('Confusion Matrix (tuned threshold)')
    plt.colorbar()
    for i in range(2):
        for j in range(2):
            plt.text(j, i, f'{cm[i,j]}\n({cm_n[i,j]:.2%})',
                     ha="center", va="center",
                     color="white" if cm_n[i, j] > 0.5 else "black")
    plt.ylabel('True')
    plt.xlabel('Predicted')
    plt.xticks([0, 1], ['BENIGN', 'ATTACK'])
    plt.yticks([0, 1], ['BENIGN', 'ATTACK'])
    plt.tight_layout()
    plt.savefig(out, dpi=200)
    plt.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--splits_dir",       required=True)
    p.add_argument("--run_name",         required=True)
    p.add_argument("--out_models_dir",   default="data/models")
    p.add_argument("--out_reports_dir",  default="data/reports")
    p.add_argument("--n_estimators",     type=int,  default=200)
    p.add_argument("--max_depth",        type=int,  default=20)
    p.add_argument("--n_jobs",           type=int,  default=1)
    p.add_argument("--balance_classes",  action="store_true", default=True)
    args = p.parse_args()

    os.makedirs(args.out_models_dir,  exist_ok=True)
    os.makedirs(args.out_reports_dir, exist_ok=True)

    print_run_header(
        model_name="Random Forest",
        run_name=args.run_name,
        splits_dir=args.splits_dir,
        out_models_dir=args.out_models_dir,
        out_reports_dir=args.out_reports_dir,
        params={
            "n_estimators": args.n_estimators,
            "max_depth":    args.max_depth,
            "n_jobs":       args.n_jobs,
            "class_weight": "balanced" if args.balance_classes else "none",
        },
    )

    train_df = pd.read_parquet(f"{args.splits_dir}/train.parquet")
    val_df   = pd.read_parquet(f"{args.splits_dir}/val.parquet")
    test_df  = pd.read_parquet(f"{args.splits_dir}/test.parquet")

    X_train_raw, y_train, _           = prepare_data(train_df)
    X_val_raw,   y_val,   _           = prepare_data(val_df)
    X_test_raw,  y_test,  labels_test = prepare_data(test_df)

    print("[*] Split sizes")
    print_split_summary("train", len(X_train_raw), int((y_train == 1).sum()))
    print_split_summary("val",   len(X_val_raw),   int((y_val   == 1).sum()))
    print_split_summary("test",  len(X_test_raw),  int((y_test  == 1).sum()))

    # Fit imputer on training only then reuse for val/test.
    imputer      = SimpleImputer(strategy="median")
    X_train      = imputer.fit_transform(X_train_raw)
    X_val        = imputer.transform(X_val_raw)
    X_test       = imputer.transform(X_test_raw)
    feature_names = X_train_raw.columns.tolist()
    print_preprocessing_summary("SimpleImputer(median) fitted on train only; no scaling for RF")
    print_feature_summary(feature_names)

    print("[*] Training")
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        class_weight='balanced' if args.balance_classes else None,
        random_state=104,
        n_jobs=args.n_jobs,
    )
    rf.fit(X_train, y_train)
    train_time = time.time() - t0
    print(f"  fit_seconds     : {train_time:.2f}")

    y_val_prob   = rf.predict_proba(X_val)[:, 1]
    y_test_prob  = rf.predict_proba(X_test)[:, 1]
    y_train_prob = rf.predict_proba(X_train)[:, 1]

    # Choose the decision threshold from the validation split.
    n_pos_val = int((y_val == 1).sum())
    if n_pos_val >= 10:
        best_thr, best_val_f1 = tune_threshold_on_val(y_val.to_numpy(), y_val_prob)
        tuning_lines = [
            "strategy         : maximize validation F1",
            f"val_attack_rows  : {n_pos_val:,}",
            f"threshold        : {best_thr:.5f}",
            f"best_val_f1      : {best_val_f1:.4f}",
        ]
    else:
        best_thr = 0.5
        tuning_lines = [
            "strategy         : fallback default threshold",
            f"val_attack_rows  : {n_pos_val:,}",
            f"threshold        : {best_thr:.5f}",
        ]
    print_tuning_summary("Threshold selection", tuning_lines)

    y_train_pred = (y_train_prob >= best_thr).astype(int)
    y_val_pred   = (y_val_prob   >= best_thr).astype(int)
    y_test_pred  = (y_test_prob  >= best_thr).astype(int)

    train_m = evaluate(y_train, y_train_pred, y_train_prob)
    val_m   = evaluate(y_val,   y_val_pred,   y_val_prob)
    test_m  = evaluate(y_test,  y_test_pred,  y_test_prob)

    print_metrics_block("Train metrics",      train_m)
    print_metrics_block("Validation metrics", val_m)
    print_metrics_block("Test metrics",       test_m)

    pa = per_attack(labels_test, y_test.to_numpy(), y_test_pred)
    print_per_attack_block("Per-attack detection (test)", pa)

    cm     = confusion_matrix(y_test, y_test_pred)
    cm_png = f"{args.out_reports_dir}/{args.run_name}_rf_confusion.png"
    plot_cm(cm, cm_png)

    fi = (pd.DataFrame({'feature': feature_names, 'importance': rf.feature_importances_})
            .sort_values('importance', ascending=False))
    print("[*] Top 10 features")
    for _, r in fi.head(10).iterrows():
        print(f"  {r['feature']:30s} {r['importance']:.4f}")

    model_path = f"{args.out_models_dir}/{args.run_name}_rf.joblib"
    joblib.dump({'model': rf, 'imputer': imputer, 'features': feature_names,
                 'threshold': best_thr}, model_path)

    results = {
        'timestamp':             datetime.utcnow().isoformat() + "Z",
        'run_name':              args.run_name,
        'model':                 'RandomForest',
        'params': {
            'n_estimators':  args.n_estimators,
            'max_depth':     args.max_depth,
            'n_jobs':        args.n_jobs,
            'class_weight':  'balanced' if args.balance_classes else None,
        },
        'preprocessing':         'SimpleImputer(median) on train only; no StandardScaler needed for RF',
        'tuned_threshold':       best_thr,
        'training_time_seconds': float(train_time),
        'features':              feature_names,
        'train':                 train_m,
        'validation':            val_m,
        'test':                  test_m,
        'per_attack_detection':  pa,
        'feature_importance':    fi.head(20).to_dict('records'),
        'model_path':            model_path,
        'confusion_png':         cm_png,
    }

    summary_path = f"{args.out_reports_dir}/{args.run_name}_rf_summary.json"
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)

    print_artifacts(model_path=model_path, summary_path=summary_path, extras={"confpng": cm_png})

if __name__ == "__main__":
    main()
