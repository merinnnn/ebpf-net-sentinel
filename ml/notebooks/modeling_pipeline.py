#!/usr/bin/env python3
"""Shared helpers for notebook model training and evaluation."""

import gc
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.base import clone
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score, average_precision_score, roc_curve, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

DROP_COLS = [
    "label_family",
    "is_attack",
    "day",
    "label_raw",
    "run_id",
    "ts",
    "start_ts",
    "end_ts",
    "t_end",
    "orig_h",
    "resp_h",
    "src_ip",
    "dst_ip",
    "k",
    "label_time_offset_sec",
    "label_halfday_shift_sec",
    "label_window_pre_slop_sec",
    "label_window_post_slop_sec",
]

BENIGN_LIKE = {"BENIGN", "Unknown", "nan", "NaN", ""}

@dataclass
class PreparedSplit:
    X: pd.DataFrame
    y: np.ndarray
    labels: pd.Series
    features: List[str]

def load_split(
    splits_dir: Path,
    test_file: str = "test.parquet",
    columns: List[str] | None = None,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    train = pd.read_parquet(splits_dir / "train.parquet", columns=columns)
    val = pd.read_parquet(splits_dir / "val.parquet", columns=columns)
    test = pd.read_parquet(splits_dir / test_file, columns=columns)
    return train, val, test

def prepare_split(df: pd.DataFrame, feature_list: List[str] | None = None) -> PreparedSplit:
    X = df.drop(columns=DROP_COLS, errors="ignore")
    num_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c]) and not X[c].isna().all()]
    if feature_list is not None:
        num_cols = [c for c in feature_list if c in X.columns and pd.api.types.is_numeric_dtype(X[c])]
    X = X[num_cols].astype(np.float32, copy=False)
    y = (df["is_attack"] == 1).astype(int).to_numpy()
    labels = df["label_family"].astype(str)
    return PreparedSplit(X=X, y=y, labels=labels, features=num_cols)

def align_to_features(X: pd.DataFrame, features: List[str]) -> pd.DataFrame:
    out = X.copy()
    for c in features:
        if c not in out.columns:
            out[c] = 0.0
    return out[features]

def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray | None = None) -> Dict[str, float | None]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / max(fp + tn, 1))
    metrics: Dict[str, float | None] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": fpr,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "roc_auc": None,
        "pr_auc": None,    # Average Precision (honest with imbalanced data)
    }
    if y_prob is not None and len(np.unique(y_true)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_prob))
        metrics["pr_auc"] = float(average_precision_score(y_true, y_prob))
    return metrics

def tune_threshold_on_val(y_val: np.ndarray, y_prob_val: np.ndarray) -> float:
    """Find the F1-maximising decision threshold on the validation set. Falls back to 0.5 with < 10 positives."""
    n_pos = int((y_val == 1).sum())
    if n_pos < 10:
        return 0.5
    _, _, thresholds = roc_curve(y_val, y_prob_val)
    f1s = np.array([
        f1_score(y_val, (y_prob_val >= t).astype(int), zero_division=0)
        for t in thresholds
    ])
    return float(thresholds[int(np.argmax(f1s))])

def tune_threshold_for_fpr(y_val: np.ndarray, y_prob_val: np.ndarray, target_fpr: float = 0.001) -> float:
    """Choose the highest threshold where FPR <= target_fpr on the validation set. Falls back to 0.5 with one class."""
    if len(np.unique(y_val)) < 2:
        return 0.5
    # roc_curve returns thresholds in decreasing score order
    fpr, tpr, thr = roc_curve(y_val, y_prob_val)
    # Candidate thresholds that satisfy constraint
    ok = np.where(fpr <= target_fpr)[0]
    if len(ok) == 0:
        # can't hit target, return strictest threshold
        return float(np.max(thr))
    # pick threshold with max TPR among ok; if ties, prefer higher threshold (fewer alerts)
    best = ok[np.argmax(tpr[ok])]
    return float(thr[int(best)])

def tune_threshold_for_recall(y_val: np.ndarray, y_prob_val: np.ndarray, target_recall: float = 0.40) -> float:
    """Choose the highest threshold that still achieves recall >= target_recall on validation."""
    if len(np.unique(y_val)) < 2:
        return 0.5
    target_recall = float(np.clip(target_recall, 0.0, 1.0))
    fpr, tpr, thr = roc_curve(y_val, y_prob_val)
    ok = np.where(tpr >= target_recall)[0]
    if len(ok) == 0:
        return float(np.min(thr))
    best = ok[np.argmin(fpr[ok])]
    tied = ok[np.where(fpr[ok] == fpr[best])[0]]
    if len(tied) > 1:
        best = tied[np.argmax(thr[tied])]
    return float(thr[int(best)])

def select_threshold(
    y_val: np.ndarray,
    y_prob_val: np.ndarray,
    *,
    threshold_mode: str = "f1",
    target_fpr: float = 0.001,
    target_recall: float | None = None,
) -> float:
    mode = str(threshold_mode).lower()
    if mode == "fpr":
        return tune_threshold_for_fpr(y_val, y_prob_val, target_fpr=target_fpr)
    if mode == "recall":
        if target_recall is None:
            raise ValueError("threshold_mode='recall' requires target_recall")
        return tune_threshold_for_recall(y_val, y_prob_val, target_recall=target_recall)
    if mode != "f1":
        raise ValueError(f"Unsupported threshold_mode: {threshold_mode}")
    return tune_threshold_on_val(y_val, y_prob_val)

def metrics_at_threshold(y_true: np.ndarray, y_score: np.ndarray, threshold: float) -> Dict[str, float | None]:
    y_pred = (y_score >= float(threshold)).astype(int)
    metrics = binary_metrics(y_true, y_pred, y_score)
    metrics["threshold"] = float(threshold)
    return metrics

def model_candidates(seed: int = 104) -> Dict[str, Pipeline]:
    """Candidate models used across notebooks. Hyperparameters match experiment_config.py for consistency."""
    from ml.notebooks.experiment_config import RF_PARAMS, HGB_PARAMS
    _rf = dict(RF_PARAMS)
    _hgb = dict(HGB_PARAMS)

    # Ensure seed is applied even if config already includes it
    _rf["random_state"] = seed
    _hgb["random_state"] = seed

    return {
        "hgb_balanced": Pipeline(
            steps=[
                ("impute", SimpleImputer(strategy="median")),
                ("clf", HistGradientBoostingClassifier(**_hgb)),
            ]
        ),
        "rf_balanced": Pipeline(
            steps=[
                ("impute", SimpleImputer(strategy="median")),
                ("clf", RandomForestClassifier(**_rf)),
            ]
        ),
        "et_balanced": Pipeline(
            steps=[
                ("impute", SimpleImputer(strategy="median")),
                (
                    "clf",
                    ExtraTreesClassifier(
                        n_estimators=500,
                        max_depth=24,
                        min_samples_leaf=2,
                        class_weight="balanced_subsample",
                        n_jobs=-1,
                        random_state=seed,
                    ),
                ),
            ]
        ),
        "logreg_balanced": Pipeline(
            steps=[
                ("impute", SimpleImputer(strategy="median")),
                ("scale", StandardScaler(with_mean=False)),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=1200,
                        C=1.0,
                        class_weight="balanced",
                        solver="liblinear",
                        random_state=seed,
                    ),
                ),
            ]
        ),
    }

def _predict_scores(model: Pipeline, X: pd.DataFrame) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    score = model.decision_function(X)
    score = (score - np.min(score)) / (np.max(score) - np.min(score) + 1e-12)
    return score

def evaluate_candidate(model: Pipeline, X_tr: pd.DataFrame, y_tr: np.ndarray, X_va: pd.DataFrame, y_va: np.ndarray,
                       *, threshold_mode: str = "f1", target_fpr: float = 0.001,
                       target_recall: float | None = None) -> dict:
    model.fit(X_tr, y_tr)
    tr_prob = _predict_scores(model, X_tr)
    va_prob = _predict_scores(model, X_va)

    # Choose decision threshold on validation
    best_thr = select_threshold(
        y_va,
        va_prob,
        threshold_mode=threshold_mode,
        target_fpr=target_fpr,
        target_recall=target_recall,
    )

    tr_pred = (tr_prob >= best_thr).astype(int)
    va_pred = (va_prob >= best_thr).astype(int)
    tr = binary_metrics(y_tr, tr_pred, tr_prob)
    va = binary_metrics(y_va, va_pred, va_prob)

    tr_auc = tr["roc_auc"] if tr["roc_auc"] is not None else 0.0
    va_auc = va["roc_auc"] if va["roc_auc"] is not None else 0.0
    gap_auc = float(max(0.0, tr_auc - va_auc))
    gap_f1 = float(max(0.0, tr["f1"] - va["f1"]))
    score = float(va_auc - 0.50 * gap_auc - 0.25 * gap_f1)

    return {
        "model": model,
        "train": tr,
        "val": va,
        "train_pred": tr_pred,
        "val_pred": va_pred,
        "train_prob": tr_prob,
        "val_prob": va_prob,
        "tuned_threshold": best_thr,
        "overfit_gap_auc": gap_auc,
        "overfit_gap_f1": gap_f1,
        "selection_score": score,
    }

def rank_models(X_tr: pd.DataFrame, y_tr: np.ndarray, X_va: pd.DataFrame, y_va: np.ndarray, seed: int = 104):
    rows = []
    fitted = {}
    for name, model in model_candidates(seed).items():
        res = evaluate_candidate(model, X_tr, y_tr, X_va, y_va)
        fitted[name] = res
        rows.append(
            {
                "model": name,
                "val_auc": res["val"]["roc_auc"],
                "val_f1": res["val"]["f1"],
                "train_auc": res["train"]["roc_auc"],
                "train_f1": res["train"]["f1"],
                "overfit_gap_auc": res["overfit_gap_auc"],
                "overfit_gap_f1": res["overfit_gap_f1"],
                "selection_score": res["selection_score"],
            }
        )
    board = pd.DataFrame(rows).sort_values("selection_score", ascending=False).reset_index(drop=True)
    best_name = board.iloc[0]["model"]
    return best_name, fitted[best_name], board

def bootstrap_metric_ci(
    y_true: np.ndarray,
    y_score: np.ndarray,
    *,
    metric: str = "roc_auc",
    n_boot: int = 300,
    seed: int = 104,
) -> Dict[str, float | None]:
    if len(y_true) == 0:
        return {"mean": None, "low": None, "high": None, "n_boot": 0}

    rng = np.random.default_rng(seed)
    values: list[float] = []
    for _ in range(n_boot):
        idx = rng.integers(0, len(y_true), size=len(y_true))
        ys = y_true[idx]
        ps = y_score[idx]
        if metric in {"roc_auc", "pr_auc"} and len(np.unique(ys)) < 2:
            continue
        if metric == "roc_auc":
            values.append(float(roc_auc_score(ys, ps)))
        elif metric == "pr_auc":
            values.append(float(average_precision_score(ys, ps)))
        else:
            raise ValueError(f"Unsupported metric for bootstrap CI: {metric}")

    if not values:
        return {"mean": None, "low": None, "high": None, "n_boot": 0}

    arr = np.asarray(values, dtype=float)
    return {
        "mean": float(np.mean(arr)),
        "low": float(np.quantile(arr, 0.025)),
        "high": float(np.quantile(arr, 0.975)),
        "n_boot": int(len(arr)),
    }

def load_model_pack(fs_name: str, *, artifact: str = "headline", seed: int = 104) -> dict:
    from ml.notebooks.experiment_config import MODELS_DIR

    artifact_map = {
        "headline": [
            MODELS_DIR / f"{fs_name}_headline_model_seed{seed}.joblib",
            MODELS_DIR / f"{fs_name}_hgb_split4_seed{seed}.joblib",
        ],
        "selection": [
            MODELS_DIR / f"{fs_name}_selected_model_split2_seed{seed}.joblib",
            MODELS_DIR / f"{fs_name}_best_model_seed{seed}.joblib",
            MODELS_DIR / f"{fs_name}_hgb_split2_seed{seed}.joblib",
        ],
        "best": [
            MODELS_DIR / f"{fs_name}_best_model_seed{seed}.joblib",
            MODELS_DIR / f"{fs_name}_headline_model_seed{seed}.joblib",
            MODELS_DIR / f"{fs_name}_selected_model_split2_seed{seed}.joblib",
        ],
    }
    paths = artifact_map.get(artifact)
    if paths is None:
        raise ValueError(f"Unknown artifact type: {artifact}")

    for path in paths:
        if path.exists():
            pack = joblib.load(path)
            if isinstance(pack, dict) and "model" in pack and "features" in pack:
                pack.setdefault("artifact_path", str(path))
                return pack

    searched = ", ".join(str(p) for p in paths)
    raise FileNotFoundError(
        f"No model artifact found for {fs_name} ({artifact}). Searched: {searched}"
    )

def evaluate_saved_pack(pack: dict, df: pd.DataFrame) -> Dict[str, object]:
    prep = prepare_split(df, feature_list=pack["features"])
    X = align_to_features(prep.X, pack["features"])
    score = _predict_scores(pack["model"], X)
    threshold = float(pack.get("threshold", 0.5))
    pred = (score >= threshold).astype(int)
    metrics = binary_metrics(prep.y, pred, score)
    return {
        "X": X,
        "y": prep.y,
        "labels": prep.labels,
        "score": score,
        "pred": pred,
        "metrics": metrics,
        "threshold": threshold,
    }

def fit_model_family_on_split(
    split_dir: Path,
    *,
    feature_list: List[str] | None,
    model_name: str,
    test_file: str = "test.parquet",
    seed: int = 104,
    threshold_mode: str = "f1",
    target_fpr: float = 0.001,
    target_recall: float | None = None,
) -> Dict[str, object]:
    load_cols = None
    if feature_list is not None:
        load_cols = list(dict.fromkeys(["label_family", "is_attack", *feature_list]))
    train_df, val_df, test_df = load_split(split_dir, test_file=test_file, columns=load_cols)
    tr = prepare_split(train_df, feature_list=feature_list)
    va = prepare_split(val_df, feature_list=feature_list)
    te = prepare_split(test_df, feature_list=feature_list)
    del train_df, val_df, test_df
    gc.collect()

    features = tr.features if feature_list is None else list(feature_list)
    Xtr = align_to_features(tr.X, features)
    Xva = align_to_features(va.X, features)
    Xte = align_to_features(te.X, features)

    model = clone(model_candidates(seed)[model_name])
    res = evaluate_candidate(
        model,
        Xtr,
        tr.y,
        Xva,
        va.y,
        threshold_mode=threshold_mode,
        target_fpr=target_fpr,
        target_recall=target_recall,
    )
    del Xtr, Xva
    gc.collect()

    te_prob = _predict_scores(res["model"], Xte)
    thr = float(res["tuned_threshold"])
    te_pred = (te_prob >= thr).astype(int)
    te_metrics = binary_metrics(te.y, te_pred, te_prob)
    del Xte
    gc.collect()

    return {
        "model": res["model"],
        "model_name": model_name,
        "features": features,
        "threshold": thr,
        "train_metrics": res["train"],
        "val_metrics": res["val"],
        "test_metrics": te_metrics,
        "selection_score": float(res["selection_score"]),
        "overfit_gap_auc": float(res["overfit_gap_auc"]),
        "overfit_gap_f1": float(res["overfit_gap_f1"]),
        "y_test": te.y,
        "y_score": te_prob,
        "y_pred": te_pred,
        "y_val": va.y,
        "y_val_score": res["val_prob"],
        "y_val_pred": res["val_pred"],
        "labels_test": te.labels,
        "n_rows": int(len(te.y)),
        "n_attacks": int(te.y.sum()),
        "threshold_mode": threshold_mode,
        "target_fpr": float(target_fpr),
        "target_recall": None if target_recall is None else float(target_recall),
    }

def per_attack_detection_rates(model: Pipeline, X: pd.DataFrame, labels: pd.Series) -> pd.DataFrame:
    pred = model.predict(X)
    rows = []
    for attack in sorted(labels.unique()):
        if attack in BENIGN_LIKE:
            continue
        mask = (labels == attack).to_numpy()
        n = int(mask.sum())
        if n == 0:
            continue
        detected = int((pred[mask] == 1).sum())
        rows.append(
            {
                "attack": attack,
                "n": n,
                "detected": detected,
                "detection_rate": float(detected / max(n, 1)),
            }
        )
    return pd.DataFrame(rows).sort_values("attack").reset_index(drop=True)
