#!/bin/bash
# Complete experimental pipeline
# Run this script to execute all experiments automatically

set -euo pipefail

echo "eBPF Network Anomaly Detection - Full Pipeline"

# Configuration
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE_DIR"

echo ""
echo "[*] Current directory: $(pwd)"
echo "[*] Expected structure:"
echo "  data/datasets/splits_zeek_only_primary/"
echo "  data/datasets/splits_zeek_plus_ebpf_primary/"
echo ""

# Path to your merged dataset produced by ubuntu scripts
MERGED_PARQUET="${MERGED_PARQUET:-data/datasets/cicids2017_multiclass_zeek_ebpf.parquet}"

ZEEK_ONLY_PARQUET="data/datasets/cicids2017_multiclass_zeek_only.parquet"
ZEEK_EBPF_PARQUET="data/datasets/cicids2017_multiclass_zeek_plus_ebpf.parquet"

echo "[*] Checking merged parquet: $MERGED_PARQUET"
if [ ! -f "$MERGED_PARQUET" ]; then
  echo "[x] ERROR: merged parquet not found: $MERGED_PARQUET"
  echo "Make sure the ubuntu pipeline has produced it."
  exit 1
fi

echo "[*] Building baseline/enhanced datasets"
python3 ml/data_prep/make_datasets.py \
  --in_parquet "$MERGED_PARQUET" \
  --out_baseline "$ZEEK_ONLY_PARQUET" \
  --out_enhanced "$ZEEK_EBPF_PARQUET" \
  --report_dir data/reports/make_datasets

echo "[+] Datasets ready:"
echo "    baseline: $ZEEK_ONLY_PARQUET"
echo "    enhanced: $ZEEK_EBPF_PARQUET"
echo ""

echo "[*] Creating primary splits (baseline)"
python3 ml/data_prep/split_days_auto.py \
  --in_parquet "$ZEEK_ONLY_PARQUET" \
  --out_dir data/datasets/splits_zeek_only_primary \
  --protocol day_holdout \
  --min_attacks_train 5000 \
  --min_attacks_val 1000 \
  --min_attacks_test 1000

echo "[*] Creating primary splits (enhanced)"
python3 ml/data_prep/split_days_auto.py \
  --in_parquet "$ZEEK_EBPF_PARQUET" \
  --out_dir data/datasets/splits_zeek_plus_ebpf_primary \
  --protocol day_holdout \
  --min_attacks_train 5000 \
  --min_attacks_val 1000 \
  --min_attacks_test 1000

echo "[+] Splits created"
echo ""

# Check prerequisites
if [ ! -d "data/datasets/splits_zeek_only_primary" ]; then
    echo "[x] ERROR: Baseline splits not found!"
    echo "Run: python3 ml/core/split_by_day.py ..."
    exit 1
fi

if [ ! -d "data/datasets/splits_zeek_plus_ebpf_primary" ]; then
    echo "[x] ERROR: eBPF splits not found!"
    exit 1
fi

echo "[*] Prerequisites checked"
echo ""

# Create output directories
mkdir -p data/models data/reports/feature_importance

# Experiment 1: Isolation Forest - Baseline
echo "[*] EXPERIMENT 1: Isolation Forest (Baseline)"
python3 ml/methods/unsupervised_iforest/train_iforest.py \
  --splits_dir data/datasets/splits_zeek_only_primary \
  --run_name baseline_if \
  --out_models_dir data/models \
  --out_reports_dir data/reports \
  --contamination 0.1 \
  --n_estimators 100

echo ""
echo "[+] Experiment 1 complete"
echo ""

# Experiment 2: Random Forest - Baseline
echo "[*] EXPERIMENT 2: Random Forest (Baseline)"
python3 ml/methods/supervised_rf/train_random_forest.py \
  --splits_dir data/datasets/splits_zeek_only_primary \
  --run_name baseline_rf \
  --out_models_dir data/models \
  --out_reports_dir data/reports \
  --n_estimators 200 \
  --max_depth 20 \
  --balance_classes

echo ""
echo "[+] Experiment 2 complete"
echo ""

# Experiment 3: Isolation Forest - eBPF
echo "[*] EXPERIMENT 3: Isolation Forest (eBPF)"
python3 ml/methods/unsupervised_iforest/train_iforest.py \
  --splits_dir data/datasets/splits_zeek_plus_ebpf_primary \
  --run_name ebpf_if \
  --out_models_dir data/models \
  --out_reports_dir data/reports \
  --contamination 0.1 \
  --n_estimators 100

echo ""
echo "[+] Experiment 3 complete"
echo ""

# Experiment 4: Random Forest - eBPF
echo "[*] EXPERIMENT 4: Random Forest (eBPF)"
python3 ml/methods/supervised_rf/train_random_forest.py \
  --splits_dir data/datasets/splits_zeek_plus_ebpf_primary \
  --run_name ebpf_rf \
  --out_models_dir data/models \
  --out_reports_dir data/reports \
  --n_estimators 200 \
  --max_depth 20 \
  --balance_classes

echo ""
echo "[+] Experiment 4 complete"
echo ""

# Comparison
echo "[*] Statistical Comparison"

echo "[*] Comparing Isolation Forest..."
python3 ml/analysis/statistical_comparison.py \
  --baseline_summary data/reports/baseline_if_iforest_summary.json \
  --ebpf_summary data/reports/ebpf_if_iforest_summary.json \
  --out_json data/reports/comparison_if.json

echo ""
echo "[*] Comparing Random Forest..."
python3 ml/analysis/statistical_comparison.py \
  --baseline_summary data/reports/baseline_rf_rf_summary.json \
  --ebpf_summary data/reports/ebpf_rf_rf_summary.json \
  --out_json data/reports/comparison_rf.json

echo ""
echo "[+] Comparisons complete"
echo ""

# Feature importance
echo "[*] Feature Importance Analysis"
python3 ml/analysis/analyze_feature_importance.py \
  --model_baseline data/models/baseline_rf_rf.joblib \
  --model_ebpf data/models/ebpf_rf_rf.joblib \
  --test_data_baseline data/datasets/splits_zeek_only_primary/test.parquet \
  --test_data_ebpf data/datasets/splits_zeek_plus_ebpf_primary/test.parquet \
  --out_dir data/reports/feature_importance \
  --n_repeats 10 \
  --top_k 20

echo ""
echo "[+] Feature importance complete"
echo ""

# Summary
echo "[+] ALL EXPERIMENTS COMPLETE!"
echo ""
echo "Results saved to:"
echo "  data/models/          - Trained models"
echo "  data/reports/         - Metrics and plots"
echo ""
echo "Key files:"
echo "  data/reports/comparison_rf.json"
echo "  data/reports/feature_importance/"
echo ""
