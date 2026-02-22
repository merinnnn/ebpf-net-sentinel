#!/usr/bin/env python3
"""
Single source of truth for paths, seeds, and split settings shared across
all experiment notebooks.  Import this at the top of each notebook:

    import sys, os
    sys.path.insert(0, str(Path.cwd()))        # repo root
    from ml.notebooks.experiment_config import *
"""

from pathlib import Path
import os

# Repo root
# Walk upward from this file's directory until we find the repo root
def _find_repo_root(start: Path) -> Path:
    for p in [start] + list(start.parents):
        if (p / "ml").exists() and (p / "data").exists():
            return p
    raise RuntimeError(
        f"Cannot find repo root from {start}. "
        "Expected a folder containing both 'ml/' and 'data/'."
    )

REPO_ROOT = _find_repo_root(Path(__file__).resolve().parent)

# Seeds & reproducibility
RANDOM_SEED = int(os.environ.get("RANDOM_SEED", 42))

# Raw / prepared datasets
DATA_DIR     = REPO_ROOT / "data"
DATASETS_DIR = DATA_DIR / "datasets"
MODELS_DIR   = DATA_DIR / "models"
REPORTS_DIR  = DATA_DIR / "reports"

# Input merged parquet (produced by your feature-engineering pipeline)
MERGED_PARQUET = DATASETS_DIR / "cicids2017_multiclass_zeek_ebpf.parquet"

# Prepared feature-set parquets (produced by make_datasets.py)
ZEEK_ONLY_PARQUET = DATASETS_DIR / "cicids2017_multiclass_zeek_only.parquet"
ZEEK_EBPF_PARQUET = DATASETS_DIR / "cicids2017_multiclass_zeek_plus_ebpf.parquet"

# Split directories (one per strategy × feature-set)
#
# PRIMARY strategy: session-aware temporal split  ← new recommended default
SPLITS_SESSION_TEMPORAL_BASELINE = DATASETS_DIR / f"splits_session_temporal_zeek_only_seed{RANDOM_SEED}"
SPLITS_SESSION_TEMPORAL_EBPF     = DATASETS_DIR / f"splits_session_temporal_zeek_ebpf_seed{RANDOM_SEED}"

# SECONDARY strategy: within-day time split  (kept for comparison / reference)
SPLITS_WITHIN_DAY_BASELINE = DATASETS_DIR / f"splits_within_day_time_zeek_only_seed{RANDOM_SEED}"
SPLITS_WITHIN_DAY_EBPF     = DATASETS_DIR / f"splits_within_day_time_zeek_ebpf_seed{RANDOM_SEED}"

# TERTIARY strategy: day holdout (generalisation stress-test)
SPLITS_DAY_HOLDOUT_BASELINE = DATASETS_DIR / "splits_day_holdout_primary_zeek_only"
SPLITS_DAY_HOLDOUT_EBPF     = DATASETS_DIR / "splits_day_holdout_primary_zeek_ebpf"

# Output directories
FEATURE_IMPORTANCE_DIR = REPORTS_DIR / "feature_importance"

# Experiment naming helpers
SPLIT_TAG = f"session_temporal_seed{RANDOM_SEED}"

def run_name(prefix: str, model: str) -> str:
    """Canonical run name used for output file prefixes."""
    return f"{prefix}_{SPLIT_TAG}_{model}"

# Model hyper-parameters (defaults, override per notebook as needed)
HGB_PARAMS = dict(
    max_iter=300,
    max_depth=8,
    learning_rate=0.05,
    min_samples_leaf=20,
    class_weight="balanced",
    random_state=RANDOM_SEED,
    early_stopping=True,
    validation_fraction=0.1,
    n_iter_no_change=20,
)

RF_PARAMS = dict(
    n_estimators=200,
    max_depth=20,
    class_weight="balanced_subsample",
    n_jobs=-1,
    random_state=RANDOM_SEED,
)

IFOREST_PARAMS = dict(
    n_estimators=100,
    max_samples=256,
    contamination="auto",   # avoid hardcoding attack ratio
    random_state=RANDOM_SEED,
    n_jobs=-1,
)

# Ensure output dirs exist (safe to call at import time)
for _d in [MODELS_DIR, REPORTS_DIR, FEATURE_IMPORTANCE_DIR]:
    _d.mkdir(parents=True, exist_ok=True)
