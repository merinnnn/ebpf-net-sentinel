#!/usr/bin/env bash
# Complete experimental pipeline
# Runs: dataset build -> splitting -> IF + RF (baseline & eBPF) -> comparisons -> feature importance

set -euo pipefail

echo "eBPF Network Anomaly Detection - Full Pipeline"

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo ""
echo "[*] Current directory: $(pwd)"
echo "[*] Expected structure:"
echo "  data/datasets/"
echo "  data/reports/"
echo ""

# Path to merged dataset produced by ubuntu scripts
MERGED_PARQUET="${MERGED_PARQUET:-data/datasets/cicids2017_multiclass_zeek_ebpf.parquet}"

# Split protocol (stratified_label, stratified_attack, day_holdout)
SPLIT_PROTOCOL="${SPLIT_PROTOCOL:-stratified_label}"
SPLIT_SEED="${SPLIT_SEED:-42}"
TRAIN_FRAC="${TRAIN_FRAC:-0.70}"
VAL_FRAC="${VAL_FRAC:-0.15}"
TEST_FRAC="${TEST_FRAC:-0.15}"
MIN_CLASS_COUNT="${MIN_CLASS_COUNT:-10}"

# Output dataset paths
ZEEK_ONLY_PARQUET="data/datasets/cicids2017_multiclass_zeek_only.parquet"
ZEEK_EBPF_PARQUET="data/datasets/cicids2017_multiclass_zeek_plus_ebpf.parquet"

# Protocol-specific split dirs (prevents overwriting)
BASE_SPLITS_DIR="data/datasets/splits_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}"
SPLITS_BASELINE="${BASE_SPLITS_DIR}/zeek_only_primary"
SPLITS_EBPF="${BASE_SPLITS_DIR}/zeek_plus_ebpf_primary"

echo "[*] Using split protocol: $SPLIT_PROTOCOL"
echo "[*] Split seed: $SPLIT_SEED"
echo "[*] Split fractions: train=$TRAIN_FRAC val=$VAL_FRAC test=$TEST_FRAC"
echo "[*] Split output:"
echo "    baseline: $SPLITS_BASELINE"
echo "    enhanced: $SPLITS_EBPF"
echo ""

echo "[*] Checking merged parquet: $MERGED_PARQUET"
if [[ ! -f "$MERGED_PARQUET" ]]; then
  echo "[x] ERROR: merged parquet not found: $MERGED_PARQUET"
  echo "Make sure the ubuntu pipeline has produced it."
  exit 1
fi

# Build baseline/enhanced datasets
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

# Create splits
mkdir -p "$SPLITS_BASELINE" "$SPLITS_EBPF"

echo "[*] Creating splits (baseline)"
python3 ml/data_prep/split_days_auto.py \
  --in_parquet "$ZEEK_ONLY_PARQUET" \
  --out_dir "$SPLITS_BASELINE" \
  --protocol "$SPLIT_PROTOCOL" \
  --seed "$SPLIT_SEED" \
  --train_frac "$TRAIN_FRAC" --val_frac "$VAL_FRAC" --test_frac "$TEST_FRAC" \
  --min_class_count "$MIN_CLASS_COUNT"

echo "[*] Creating splits (enhanced)"
python3 ml/data_prep/split_days_auto.py \
  --in_parquet "$ZEEK_EBPF_PARQUET" \
  --out_dir "$SPLITS_EBPF" \
  --protocol "$SPLIT_PROTOCOL" \
  --seed "$SPLIT_SEED" \
  --train_frac "$TRAIN_FRAC" --val_frac "$VAL_FRAC" --test_frac "$TEST_FRAC" \
  --min_class_count "$MIN_CLASS_COUNT"

echo "[+] Splits created"
echo ""

# Create output directories
mkdir -p data/models data/reports/feature_importance

# Experiment 1: Isolation Forest - Baseline
echo "[*] EXPERIMENT 1: Isolation Forest (Baseline)"
python3 ml/methods/unsupervised_iforest/train_iforest.py \
  --splits_dir "$SPLITS_BASELINE" \
  --run_name "baseline_if_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}" \
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
  --splits_dir "$SPLITS_BASELINE" \
  --run_name "baseline_rf_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}" \
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
  --splits_dir "$SPLITS_EBPF" \
  --run_name "ebpf_if_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}" \
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
  --splits_dir "$SPLITS_EBPF" \
  --run_name "ebpf_rf_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}" \
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
  --baseline_summary "data/reports/baseline_if_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}_iforest_summary.json" \
  --ebpf_summary "data/reports/ebpf_if_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}_iforest_summary.json" \
  --out_json "data/reports/comparison_if_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}.json"

echo ""
echo "[*] Comparing Random Forest..."
python3 ml/analysis/statistical_comparison.py \
  --baseline_summary "data/reports/baseline_rf_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}_rf_summary.json" \
  --ebpf_summary  "data/reports/ebpf_rf_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}_rf_summary.json" \
  --out_json "data/reports/comparison_rf_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}.json"

echo ""
echo "[+] Comparisons complete"
echo ""

# Feature importance
echo "[*] Feature Importance Analysis"
python3 ml/analysis/analyze_feature_importance.py \
  --model_baseline "data/models/baseline_rf_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}_rf.joblib" \
  --model_ebpf "data/models/ebpf_rf_${SPLIT_PROTOCOL}_seed${SPLIT_SEED}_rf.joblib" \
  --test_data_baseline "$SPLITS_BASELINE/test.parquet" \
  --test_data_ebpf "$SPLITS_EBPF/test.parquet" \
  --out_dir "data/reports/feature_importance/${SPLIT_PROTOCOL}_seed${SPLIT_SEED}" \
  --n_repeats 10 \
  --top_k 20

echo ""
echo "[+] Feature importance complete"
echo ""

# Summary
echo "[+] ALL EXPERIMENTS COMPLETE!"
echo ""
echo "Splits saved to:"
echo "  $BASE_SPLITS_DIR"
echo ""
