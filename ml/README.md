# ML Complete — Single Guide

## Overview

This folder contains the **ML experiment runners** for NetSentinel.

- **Scripts** (`core/`, `supervised/`) are meant to be executed from the command line.
- **Notebook utilities** (`utils/`) are intended for **Jupyter notebooks only**.

---

## Requirements

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r ml/requirements.txt
```

---

## Expected inputs (splits)

Most experiments take a `--splits_dir` that contains:

- `train.parquet`
- `val.parquet`
- `test.parquet`

Example:

```bash
data/datasets/
  splits_zeek_only/
    train.parquet
    val.parquet
    test.parquet
  splits_zeek_plus_ebpf/
    train.parquet
    val.parquet
    test.parquet
```

---

## Outputs

By default experiments write to:

- models: `data/models/`
- reports: `data/reports/`

The `--run_name` is used as a prefix for output filenames.

---

## How to Run Experiments

All commands below assume you are at the **repo root** (the folder that contains `ml/` and `data/`).

> Tip: use a virtualenv and install requirements first.

---

## 0) Prepare data

```bash
python3 ml/data_prep/make_datasets.py --in_parquet data/datasets/cicids2017_multiclass_merged.parquet --out_baseline data/datasets/cicids2017_multiclass_zeek_only.parquet --out_enhanced data/datasets/cicids2017_multiclass_zeek_plus_ebpf.parquet --report_dir data/reports

python3 ml/data_prep/split_by_day.py --in_parquet data/datasets/cicids2017_multiclass_zeek_only.parquet --out_dir data/datasets/splits_zeek_only_primary --split primary

python3 ml/data_prep/split_by_day.py --in_parquet data/datasets/cicids2017_multiclass_zeek_plus_ebpf.parquet --out_dir data/datasets/splits_zeek_plus_ebpf_primary --split primary
```

---

## 1) Train/evaluate supervised baselines (Zeek-only vs Zeek+eBPF)

This is the main “baseline suite” runner (dummy + logistic regression, etc.):

```bash
python3 ml/scripts/train_eval.py \
  --splits_dir data/datasets/splits_zeek_only \
  --run_name zeek_only_primary_v2 \
  --out_models_dir data/models \
  --out_reports_dir data/reports \
  --topk_cats 50

python3 ml/scripts/train_eval.py \
  --splits_dir data/datasets/splits_zeek_plus_ebpf \
  --run_name zeek_plus_ebpf_primary_v2 \
  --out_models_dir data/models \
  --out_reports_dir data/reports \
  --topk_cats 50
```

Optional flags (see `--help` for full list):

- `--balanced_logreg` to use `class_weight='balanced'` for LogisticRegression.

---

## 2) Train Isolation Forest (unsupervised anomaly detector)

```bash
python3 ml/methods/unsupervised_iforest/train_iforest.py \
  --splits_dir data/datasets/splits_zeek_only \
  --run_name iforest_zeek_only \
  --out_models_dir data/models \
  --out_reports_dir data/reports

python3 ml/methods/unsupervised_iforest/train_iforest.py \
  --splits_dir data/datasets/splits_zeek_plus_ebpf \
  --run_name iforest_zeek_plus_ebpf \
  --out_models_dir data/models \
  --out_reports_dir data/reports
```

---

## 3) Train Random Forest (supervised classifier)

```bash
python3 ml/methods/supervised_rf/train_random_forest.py \
  --splits_dir data/datasets/splits_zeek_only \
  --run_name rf_zeek_only \
  --out_models_dir data/models \
  --out_reports_dir data/reports

python3 ml/methods/supervised_rf/train_random_forest.py \
  --splits_dir data/datasets/splits_zeek_plus_ebpf \
  --run_name rf_zeek_plus_ebpf \
  --out_models_dir data/models \
  --out_reports_dir data/reports
```

---

## 4) Split dataset by day (helper)

If your merged dataset has a `day` column and you want consistent day-based train/val/test splits:

```bash
python3 ml/data_prep/split_by_day.py \
  --in_parquet data/datasets/your_merged.parquet \
  --out_dir data/datasets/splits_custom_primary
```

This writes `train.parquet`, `val.parquet`, `test.parquet` under `--out_dir`.

---

## 5) Run everything (batch script)

```bash
bash ml/RUN_ALL_EXPERIMENTS.sh
```

This expects the standard split directories to exist (see the script header for the exact names).

---

## What to Expect

This file is here so you can quickly sanity-check that an experiment ran correctly.

---

## Logging format

Scripts print a small number of lines in the format:

- `[*]` progress / stage
- `[+]` success
- `[!]` warning (non-fatal)
- `[x]` error (fatal)

---

## Expected outputs

### Supervised baselines (`supervised/train_eval.py`)

Typical outputs:

- `data/models/<run_name>_dummy_mostfreq.joblib`
- `data/models/<run_name>_logreg.joblib` (and/or variants)
- `data/reports/<run_name>_*_classification_report.txt`
- `data/reports/<run_name>_*_confusion.png`

If you run both **zeek-only** and **zeek+eBPF** with the same settings, you should end up with two comparable sets of reports.

### Isolation Forest (`core/train_iforest_complete.py`)

Typical outputs:

- `data/models/<run_name>_iforest.joblib`
- `data/reports/<run_name>_iforest_*.txt`
- `data/reports/<run_name>_iforest_*.png`

### Random Forest (`core/train_random_forest.py`)

Typical outputs:

- `data/models/<run_name>_rf.joblib`
- `data/reports/<run_name>_rf_*.txt`
- `data/reports/<run_name>_rf_*.png`

---

## Common failure modes

### 1) “file not found” for splits

Your `--splits_dir` must contain:

- `train.parquet`
- `val.parquet`
- `test.parquet`

### 2) Missing columns

Some scripts expect at least:

- labels: `label_family` (and/or `is_attack`)
- metadata: `day` (only for day-based splitting)

If your dataset schema differs, check `drop = [...]` lists in the scripts and adjust.

### 3) Parquet engine errors

If pandas complains about Parquet support, install the recommended engine:

```bash
pip install pyarrow
```

---

## Quick sanity-checks

- Reports directory contains new files with your `--run_name`
- Confusion matrix PNGs open correctly
- Classification report shows non-zero support for major classes (not everything collapsed to one class)

## Folder structure (recommended)

- `ml/data_prep/` – build datasets and create splits (including `within_day_time` split to avoid missing attack families)
- `ml/methods/` – training scripts grouped by methodology
  - `supervised_rf/`
  - `unsupervised_iforest/`
- `ml/analysis/` – feature importance + comparisons
- `ml/scripts/` – full pipeline runners (wrapper remains at `ml/RUN_ALL_EXPERIMENTS.sh`)

### Why `within_day_time` splits?

CICIDS2017 attack families are concentrated on specific days. Holding out an entire day often means some attack families are **never seen during training**, which makes supervised results look "broken". `within_day_time` keeps every day present across train/val/test while still being time-ordered.
