# ML

This folder contains the dataset split builders, model training scripts, notebooks, and a small benchmark harness used in the repo.

## Layout

- `ml/data_prep/`: build feature parquets and materialize split directories
- `ml/methods/`: command-line training scripts for Random Forest and Isolation Forest
- `ml/deep_learning/`: command-line MLP trainer
- `ml/notebooks/`: notebook pipeline and shared notebook config
- `ml/benchmarks/`: overhead / runtime measurement helpers

## Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r ml/requirements.txt
```

Most scripts expect to be run from the repo root.

## Current split strategy

The project uses the current split set:

- `split1_group_strat_*`: leakage diagnostic only
- `split2_balanced_quota_*`: model selection and threshold tuning
- `split3_train_resampled_*`: rare-class training ablation
- `split4_dual_eval_*`: headline evaluation
- `split5_kfold_*`: robustness metadata across repeated grouped folds

For Split 4:

- `train.parquet`: Monday-Wednesday
- `val.parquet`: Thursday
- `test_realistic.parquet`: Friday holdout
- `test_balanced.parquet`: class-balanced support set

The notebook aliases for these directories live in [experiment_config.py](/mnt/c/Users/merin/Documents/GitHub/ebpf-net-sentinel/ml/notebooks/experiment_config.py).

## Recommended workflow

1. Build the feature parquets with `ml/data_prep/make_datasets.py`.
2. Materialize the split directories from `ml/data_prep/`.
3. Run `ml/notebooks/00_data_preparation.ipynb` to validate the split outputs.
4. Run `ml/notebooks/01_baseline_vs_ebpf.ipynb` for the full experiment:
   use Split 2 for model selection, then Split 4 `test_realistic` for the headline result.
5. Use notebooks `02` to `05` for supporting analysis.

## Command-line trainers

All training scripts expect a split directory that contains at least:

- `train.parquet`
- `val.parquet`
- `test.parquet`

Examples:

```bash
python3 ml/methods/supervised_rf/train_random_forest.py \
  --splits_dir data/datasets/split2_balanced_quota_baseline_seed104 \
  --run_name baseline_rf_split2_seed104 \
  --out_models_dir data/models \
  --out_reports_dir data/reports

python3 ml/methods/unsupervised_iforest/train_iforest.py \
  --splits_dir data/datasets/split2_balanced_quota_baseline_seed104 \
  --run_name baseline_iforest_split2_seed104 \
  --out_models_dir data/models \
  --out_reports_dir data/reports

python3 ml/deep_learning/train_mlp_binary.py \
  --splits_dir data/datasets/split2_balanced_quota_baseline_seed104 \
  --run_name baseline_mlp_split2_seed104 \
  --out_models_dir data/models \
  --out_reports_dir data/reports
```

The scripts emit the same high-level log structure:

- run header and paths
- split sizes
- preprocessing summary
- feature summary
- tuning decisions
- train / validation / test metrics
- per-attack test detection
- saved artifact paths

## Overheads benchmark

Use [overheads.py](/mnt/c/Users/merin/Documents/GitHub/ebpf-net-sentinel/ml/benchmarks/overheads.py) with the same Split 4 directories used for the headline evaluation:

```bash
python3 ml/benchmarks/overheads.py \
  --baseline_splits_dir data/datasets/split4_dual_eval_baseline_seed104 \
  --ebpf_splits_dir     data/datasets/split4_dual_eval_ebpf_seed104 \
  --test_file test_realistic \
  --out_json data/reports/rq4_overheads/rq4_overheads.json \
  --out_dir  data/reports/rq4_overheads/artifacts
```

## Common failure modes

- Missing split files: verify the target split directory contains the parquet files the script expects.
- Missing parquet engine: install `pyarrow`.
- Schema drift: if a dataset changed column names, update the feature-drop lists in the relevant training script.
