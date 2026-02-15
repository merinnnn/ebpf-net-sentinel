#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime

import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.dummy import DummyClassifier

LABEL_COL = "label_family"
DAY_COL = "day"
SEED = 1337

def make_onehot():
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=True)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=True)

def make_preprocessor(X_train: pd.DataFrame):
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

def drop_all_null_cols(Xtr, Xte):
    all_null = [c for c in Xtr.columns if Xtr[c].isna().all()]
    if all_null:
        Xtr = Xtr.drop(columns=all_null)
        Xte = Xte.drop(columns=all_null, errors="ignore")
    return Xtr, Xte, all_null

def cap_topk_train_categories(Xtr, Xte, cat_cols, topk):
    mappings = {}
    Xtr2, Xte2 = Xtr.copy(), Xte.copy()
    for c in cat_cols:
        tr = Xtr2[c].astype(str).fillna("__MISSING__")
        keep = tr.value_counts().head(topk).index.tolist()
        keep_set = set(keep)
        mappings[c] = keep

        def apply(series):
            s = series.astype(str).fillna("__MISSING__")
            s.loc[~s.isin(keep_set)] = "__OTHER__"
            return s

        Xtr2[c] = apply(Xtr2[c])
        Xte2[c] = apply(Xte2[c])
    return Xtr2, Xte2, mappings

def eval_fold(y_true, y_pred, labels_all):
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", labels=labels_all, zero_division=0)),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_parquet", required=True, help="Dataset parquet containing day + label + features")
    ap.add_argument("--run_name", required=True)
    ap.add_argument("--out_reports_dir", default="data/reports")
    ap.add_argument("--topk_cats", type=int, default=50)
    args = ap.parse_args()

    os.makedirs(args.out_reports_dir, exist_ok=True)

    df = pd.read_parquet(args.in_parquet)
    df[DAY_COL] = df[DAY_COL].astype(str)
    df[LABEL_COL] = df[LABEL_COL].astype(str)

    all_days = sorted(df[DAY_COL].unique().tolist())
    labels_all = sorted(df[LABEL_COL].unique().tolist())

    models = {
        "dummy_mostfreq": DummyClassifier(strategy="most_frequent", random_state=SEED),
        "logreg": LogisticRegression(
            max_iter=2000, n_jobs=-1, solver="saga",
            random_state=SEED, tol=1e-3
        ),
        "rf": RandomForestClassifier(
            n_estimators=400, n_jobs=-1,
            class_weight="balanced_subsample",
            random_state=SEED
        )
    }

    out = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "run_name": args.run_name,
        "seed": SEED,
        "days": all_days,
        "labels_all": labels_all,
        "models": {k: {"folds": {}} for k in models.keys()},
    }

    for test_day in all_days:
        train_df = df[df[DAY_COL] != test_day].copy()
        test_df = df[df[DAY_COL] == test_day].copy()

        y_train = train_df[LABEL_COL].astype(str)
        y_test = test_df[LABEL_COL].astype(str)
        X_train = train_df.drop(columns=[LABEL_COL, DAY_COL])
        X_test = test_df.drop(columns=[LABEL_COL, DAY_COL])

        # drop all-null based on train
        X_train, X_test, dropped_null = drop_all_null_cols(X_train, X_test)

        # preprocessor based on train schema
        pre, _, cat_cols = make_preprocessor(X_train)

        # cap categoricals
        if cat_cols:
            X_train2, X_test2, mappings = cap_topk_train_categories(X_train, X_test, cat_cols, args.topk_cats)
        else:
            X_train2, X_test2 = X_train, X_test
            mappings = {}

        unseen = sorted(list(set(y_test.unique()) - set(y_train.unique())))

        for model_key, clf in models.items():
            pipe = Pipeline(steps=[("pre", pre), ("clf", clf)])
            pipe.fit(X_train2, y_train)
            yp = pipe.predict(X_test2)

            metrics = eval_fold(y_test.to_numpy(), yp, labels_all)
            out["models"][model_key]["folds"][test_day] = {
                "rows": int(len(test_df)),
                "metrics": metrics,
                "unseen_labels_in_train": unseen,
                "dropped_all_null_cols": dropped_null,
                "num_features": int(X_train2.shape[1]),
                "num_capped_cat_cols": int(len(mappings)),
            }

        print(f"[*] Fold done: test_day={test_day}  unseen_in_train={unseen}")

    # Aggregate
    for model_key in models.keys():
        accs = []
        f1s = []
        for day, d in out["models"][model_key]["folds"].items():
            accs.append(d["metrics"]["accuracy"])
            f1s.append(d["metrics"]["macro_f1"])
        out["models"][model_key]["mean_accuracy"] = float(np.mean(accs)) if accs else 0.0
        out["models"][model_key]["mean_macro_f1"] = float(np.mean(f1s)) if f1s else 0.0

    out_path = os.path.join(args.out_reports_dir, f"{args.run_name}_lodo_summary.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print("[*] Wrote:", out_path)
    for mk in models.keys():
        print(f"{mk}: mean_acc={out['models'][mk]['mean_accuracy']:.4f} mean_macroF1={out['models'][mk]['mean_macro_f1']:.4f}")

if __name__ == "__main__":
    main()
