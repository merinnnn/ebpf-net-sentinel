#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.dummy import DummyClassifier


LABEL_COL = "label_family"
DAY_COL = "day"
RANDOM_SEED = 1337


def make_onehot():
    # sklearn >= 1.2 uses sparse_output; older uses sparse
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=True)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=True)


def split_xy(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    y = df[LABEL_COL].astype(str)
    day = df[DAY_COL].astype(str)
    X = df.drop(columns=[LABEL_COL, DAY_COL])
    return X, y, day


def drop_all_null_columns(X_train, X_val, X_test):
    # Drop columns that have no observed values in TRAIN (keeps schema aligned)
    all_null = [c for c in X_train.columns if X_train[c].isna().all()]
    if all_null:
        X_train = X_train.drop(columns=all_null)
        X_val = X_val.drop(columns=all_null, errors="ignore")
        X_test = X_test.drop(columns=all_null, errors="ignore")
    return X_train, X_val, X_test, all_null


def cap_high_cardinality(X_train: pd.DataFrame, X_other: pd.DataFrame, col: str, top_k: int) -> Tuple[pd.DataFrame, pd.DataFrame, List[str]]:
    """
    For a categorical column: keep top_k values from TRAIN, map the rest to __OTHER__.
    Returns transformed train/other and the kept categories.
    """
    tr = X_train[col].astype(str).fillna("__MISSING__")
    vc = tr.value_counts()
    keep = vc.head(top_k).index.tolist()
    keep_set = set(keep)

    def apply(series: pd.Series) -> pd.Series:
        s = series.astype(str).fillna("__MISSING__")
        s.loc[~s.isin(keep_set)] = "__OTHER__"
        return s

    X_train2 = X_train.copy()
    X_other2 = X_other.copy()
    X_train2[col] = apply(X_train2[col])
    X_other2[col] = apply(X_other2[col])
    return X_train2, X_other2, keep


def cap_all_high_cardinality(X_train: pd.DataFrame, X_val: pd.DataFrame, X_test: pd.DataFrame, cat_cols: List[str], top_k: int):
    mappings: Dict[str, List[str]] = {}
    Xt, Xv, Xs = X_train.copy(), X_val.copy(), X_test.copy()
    for c in cat_cols:
        Xt, Xv, keep = cap_high_cardinality(Xt, Xv, c, top_k)
        Xt, Xs, keep2 = cap_high_cardinality(Xt, Xs, c, top_k)
        mappings[c] = keep  # keep list from first pass (sufficient)
    return Xt, Xv, Xs, mappings


def make_preprocessor(X_train: pd.DataFrame) -> Tuple[ColumnTransformer, List[str], List[str]]:
    # Detect categorical vs numeric
    cat_cols = [c for c in X_train.columns if X_train[c].dtype == "object" or str(X_train[c].dtype).startswith("string")]
    num_cols = [c for c in X_train.columns if c not in cat_cols]

    numeric = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler(with_mean=False)),
    ])

    categorical = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("onehot", make_onehot()),
    ])

    pre = ColumnTransformer(
        transformers=[
            ("num", numeric, num_cols),
            ("cat", categorical, cat_cols),
        ],
        remainder="drop",
        sparse_threshold=0.3,
    )
    return pre, num_cols, cat_cols


def plot_confusion(cm: np.ndarray, labels: List[str], out_png: str, normalize: bool = True):
    if normalize:
        cm = cm.astype(float)
        row_sums = cm.sum(axis=1, keepdims=True)
        cm = np.divide(cm, row_sums, out=np.zeros_like(cm), where=row_sums != 0)

    plt.figure(figsize=(12, 10))
    plt.imshow(cm, interpolation="nearest")
    plt.title("Confusion Matrix" + (" (normalized)" if normalize else ""))
    plt.colorbar()
    tick_marks = np.arange(len(labels))
    plt.xticks(tick_marks, labels, rotation=45, ha="right")
    plt.yticks(tick_marks, labels)
    plt.ylabel("True label")
    plt.xlabel("Predicted label")
    plt.tight_layout()
    plt.savefig(out_png, dpi=200)
    plt.close()


def eval_metrics(y_true: np.ndarray, y_pred: np.ndarray, labels: List[str]) -> Dict:
    acc = float(accuracy_score(y_true, y_pred))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", labels=labels, zero_division=0))
    per = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    per_class = {
        labels[i]: {
            "precision": float(per[0][i]),
            "recall": float(per[1][i]),
            "f1": float(per[2][i]),
            "support": int(per[3][i]),
        }
        for i in range(len(labels))
    }
    return {"accuracy": acc, "macro_f1": macro_f1, "per_class": per_class}


def per_day_metrics(days: pd.Series, y_true: np.ndarray, y_pred: np.ndarray, labels: List[str]) -> Dict[str, Dict]:
    out = {}
    for d in sorted(days.unique()):
        m = days.eq(d).to_numpy()
        if m.sum() == 0:
            continue
        out[d] = {
            "rows": int(m.sum()),
            "accuracy": float(accuracy_score(y_true[m], y_pred[m])),
            "macro_f1": float(f1_score(y_true[m], y_pred[m], average="macro", labels=labels, zero_division=0)),
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits_dir", required=True, help="Directory containing train/val/test parquet")
    ap.add_argument("--run_name", required=True, help="Used for output naming")
    ap.add_argument("--out_models_dir", default="data/models")
    ap.add_argument("--out_reports_dir", default="data/reports")
    ap.add_argument("--topk_cats", type=int, default=50, help="Top-K categories to keep per categorical column")
    ap.add_argument("--balanced_logreg", action="store_true", help="Use class_weight='balanced' for LogisticRegression")
    args = ap.parse_args()

    os.makedirs(args.out_models_dir, exist_ok=True)
    os.makedirs(args.out_reports_dir, exist_ok=True)

    train_df = pd.read_parquet(os.path.join(args.splits_dir, "train.parquet"))
    val_df = pd.read_parquet(os.path.join(args.splits_dir, "val.parquet"))
    test_df = pd.read_parquet(os.path.join(args.splits_dir, "test.parquet"))

    X_train, y_train, day_train = split_xy(train_df)
    X_val, y_val, day_val = split_xy(val_df)
    X_test, y_test, day_test = split_xy(test_df)

    # Drop all-null cols based on TRAIN (fixes ebpf_comm warnings cleanly)
    X_train, X_val, X_test, dropped_all_null = drop_all_null_columns(X_train, X_val, X_test)

    # Build preprocessor from train schema
    pre, num_cols, cat_cols = make_preprocessor(X_train)

    # Cap categorical cardinality (important for eBPF-like fields)
    if cat_cols:
        X_train2, X_val2, X_test2, mappings = cap_all_high_cardinality(X_train, X_val, X_test, cat_cols, args.topk_cats)
    else:
        X_train2, X_val2, X_test2 = X_train, X_val, X_test
        mappings = {}

    # IMPORTANT: we evaluate on the union of ALL labels seen across splits
    labels_all = sorted(pd.unique(pd.concat([y_train, y_val, y_test], axis=0)))
    labels_train = sorted(y_train.unique())
    labels_test = sorted(y_test.unique())

    # Models
    models = {
        # Always include a sanity baseline
        "dummy_mostfreq": DummyClassifier(strategy="most_frequent", random_state=RANDOM_SEED),

        # Linear baseline
        "logreg": LogisticRegression(
            max_iter=2000,
            n_jobs=-1,
            solver="saga",
            class_weight=("balanced" if args.balanced_logreg else None),
            random_state=RANDOM_SEED,
            tol=1e-3,
        ),

        # Stronger tree model
        "rf": RandomForestClassifier(
            n_estimators=400,
            max_depth=None,
            n_jobs=-1,
            class_weight="balanced_subsample",
            random_state=RANDOM_SEED,
        ),
    }

    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "run_name": args.run_name,
        "splits_dir": args.splits_dir,
        "seed": RANDOM_SEED,
        "num_features_after_drop": int(X_train2.shape[1]),
        "num_numeric": len(num_cols),
        "num_categorical": len(cat_cols),
        "categorical_topk": args.topk_cats,
        "dropped_all_null_cols": dropped_all_null,
        "capped_categorical_columns": list(mappings.keys()),
        "labels_all": labels_all,
        "labels_train": labels_train,
        "labels_test": labels_test,
        "note": (
            "If labels_test contains classes not in labels_train (unseen classes), "
            "multiclass supervised models cannot learn them; expect poor macro-F1 for those classes."
        ),
        "models": {},
    }

    for model_key, clf in models.items():
        pipe = Pipeline(steps=[
            ("pre", pre),
            ("clf", clf),
        ])

        print(f"\nTraining: {model_key} ({args.run_name}):")
        pipe.fit(X_train2, y_train)

        # Predict
        yv_pred = pipe.predict(X_val2)
        yt_pred = pipe.predict(X_test2)

        # Metrics (macro-F1 across ALL labels seen anywhere)
        val_metrics = eval_metrics(y_val.to_numpy(), yv_pred, labels_all)
        test_metrics = eval_metrics(y_test.to_numpy(), yt_pred, labels_all)

        # Confusion on TEST over test label space (more readable)
        cm_labels = labels_test
        cm = confusion_matrix(y_test, yt_pred, labels=cm_labels)
        cm_png = os.path.join(args.out_reports_dir, f"{args.run_name}_{model_key}_confusion.png")
        plot_confusion(cm, cm_labels, cm_png, normalize=True)

        # Per-day metrics on VAL/TEST
        val_per_day = per_day_metrics(day_val, y_val.to_numpy(), yv_pred, labels_all)
        test_per_day = per_day_metrics(day_test, y_test.to_numpy(), yt_pred, labels_all)

        # Save model
        model_path = os.path.join(args.out_models_dir, f"{args.run_name}_{model_key}.joblib")
        joblib.dump(pipe, model_path)

        # Save text report
        txt_path = os.path.join(args.out_reports_dir, f"{args.run_name}_{model_key}_classification_report.txt")
        with open(txt_path, "w") as f:
            f.write("INFO:\n")
            f.write(f"labels_train={labels_train}\n")
            f.write(f"labels_test={labels_test}\n")
            unseen = sorted(set(labels_test) - set(labels_train))
            f.write(f"unseen_test_labels={unseen}\n\n")

            f.write("VALIDATION (labels_all macro):\n")
            f.write(classification_report(y_val, yv_pred, labels=labels_all, zero_division=0))

            f.write("\n\nTEST (labels_all macro):\n")
            f.write(classification_report(y_test, yt_pred, labels=labels_all, zero_division=0))

        results["models"][model_key] = {
            "model_path": model_path,
            "val": val_metrics,
            "test": test_metrics,
            "val_per_day": val_per_day,
            "test_per_day": test_per_day,
            "confusion_png": cm_png,
            "classification_report_txt": txt_path,
        }

        print(f"[*] Saved model: {model_path}")
        print(f"[*] Saved confusion: {cm_png}")
        print(f"[*] Saved report: {txt_path}")

    summary_path = os.path.join(args.out_reports_dir, f"{args.run_name}_metrics_summary.json")
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)
    print("\n[*] Metrics summary:", summary_path)


if __name__ == "__main__":
    main()
