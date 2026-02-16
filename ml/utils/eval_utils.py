#!/usr/bin/env python3
"""Evaluation utilities.

Note: kept dependency-free (no ml_complete.utils imports) so this module is safe to use
from notebooks or scripts without side effects.
"""

from typing import Dict, Any
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

def evaluate_binary(y_true, y_pred) -> Dict[str, float]:
    """Compute standard binary classification metrics."""
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }

def per_attack_metrics(labels: pd.Series, y_true, y_pred) -> Dict[str, Dict[str, Any]]:
    """Per-attack detection rates for multiclass 'labels' with binary predictions.

    Returns a dict keyed by attack name (excluding BENIGN) with counts and detection rate.
    """
    labels = labels.astype(str)
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    results: Dict[str, Dict[str, Any]] = {}
    for attack in sorted(labels.unique()):
        if attack == "BENIGN":
            continue
        mask = (labels == attack).to_numpy()
        n = int(mask.sum())
        if n == 0:
            continue
        # For these rows, y_true should be 1; we still compute detected rate from y_pred.
        detected = int(y_pred[mask].sum())
        results[attack] = {
            "n": n,
            "detected": detected,
            "detected_rate": float(detected / n) if n else 0.0,
        }
    return results
