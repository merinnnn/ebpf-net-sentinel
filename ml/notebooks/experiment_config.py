#!/usr/bin/env python3
"""
Single source of truth for all experiment notebooks.

Split index
1  split1_group_strat_*      PRIMARY       RQ1-RQ5, all main experiments
2  split2_balanced_quota_*   COMPARISON    headline confusion matrices / macro-F1
3  split3_train_resampled_*  IMPROVED      better rare-class learning, same test as Split 1
4  split4_dual_eval_*        NARRATIVE     balanced + realistic dual evaluation
5  split5_kfold_groups_*            ROBUSTNESS    mean+/-std over 15 folds
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

# Split 1: group-stratified (PRIMARY)
SPLITS_1_BASELINE = DATASETS_DIR / f"split1_group_strat_baseline_seed{RANDOM_SEED}"
SPLITS_1_EBPF     = DATASETS_DIR / f"split1_group_strat_ebpf_seed{RANDOM_SEED}"

# Canonical alias used by all experiment notebooks
PRIMARY_SPLITS_BASELINE = SPLITS_1_BASELINE
PRIMARY_SPLITS_EBPF     = SPLITS_1_EBPF
PRIMARY_SPLIT_TAG       = f"split1_group_strat_seed{RANDOM_SEED}"
SPLIT_TAG               = PRIMARY_SPLIT_TAG   # backward compat

# Split 2: balanced quota (headline comparison)
SPLITS_2_BASELINE = DATASETS_DIR / f"split2_balanced_quota_baseline_seed{RANDOM_SEED}"
SPLITS_2_EBPF     = DATASETS_DIR / f"split2_balanced_quota_ebpf_seed{RANDOM_SEED}"

# Split 3: train-resampled (improved learning)
SPLITS_3_BASELINE = DATASETS_DIR / f"split3_train_resampled_baseline_seed{RANDOM_SEED}"
SPLITS_3_EBPF     = DATASETS_DIR / f"split3_train_resampled_ebpf_seed{RANDOM_SEED}"

# Split 4: dual-eval (balanced + realistic)
SPLITS_4_BASELINE = DATASETS_DIR / f"split4_dual_eval_baseline_seed{RANDOM_SEED}"
SPLITS_4_EBPF     = DATASETS_DIR / f"split4_dual_eval_ebpf_seed{RANDOM_SEED}"

# Split 5: repeated k-fold (statistical robustness)
# Keep canonical names aligned with generated dataset folders.
SPLITS_5_BASELINE = DATASETS_DIR / f"split5_kfold_baseline_seed{RANDOM_SEED}"
SPLITS_5_EBPF     = DATASETS_DIR / f"split5_kfold_ebpf_seed{RANDOM_SEED}"

# Canonical splits used by current end-to-end notebooks
# - model selection/training: Split 2 (balanced quota)
# - distribution-shift generalization check: Split 4 realistic test
MODEL_SELECTION_SPLITS_BASELINE = SPLITS_2_BASELINE
MODEL_SELECTION_SPLITS_EBPF     = SPLITS_2_EBPF
GENERALIZATION_SPLITS_BASELINE  = SPLITS_4_BASELINE
GENERALIZATION_SPLITS_EBPF      = SPLITS_4_EBPF

# Backward-compatible generic aliases used by older notebooks/scripts.
# These map to the current training split by default.
SPLITS_BASELINE = MODEL_SELECTION_SPLITS_BASELINE
SPLITS_EBPF     = MODEL_SELECTION_SPLITS_EBPF

def run_name(prefix: str, model: str) -> str:
    return f"{prefix}_{SPLIT_TAG}_{model}"

# Model hyperparameters
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
    n_jobs=1,
    random_state=RANDOM_SEED,
)

IFOREST_PARAMS = dict(
    n_estimators=100,
    max_samples=512,
    random_state=RANDOM_SEED,
    n_jobs=-1,
)

# Ensure output dirs exist (safe to call at import time)
for _d in [MODELS_DIR, REPORTS_DIR, REPORTS_DIR / "feature_importance"]:
    _d.mkdir(parents=True, exist_ok=True)
