# Machine Learning Pipeline

## Quick Start (Recommended Approach)

Use Isolation Forest for binary anomaly detection:

```bash
# Train models
python3 core/train_iforest_complete.py \
  --splits_dir ../data/datasets/splits_zeek_only_primary \
  --run_name zeek_only_primary

# Analyze
python3 core/statistical_comparison.py \
  --baseline_summary ../data/reports/zeek_only_primary_summary.json \
  --ebpf_summary ../data/reports/zeek_plus_ebpf_primary_summary.json
```

## Alternative Approaches

### Supervised Classification

See `supervised/train_eval.py` for LogReg/RF/Dummy classifiers.

**Note**: These struggle with class imbalance and unseen attack types.
Kept for baseline comparison purposes.

### Legacy Scripts

See `legacy/` for initial implementation attempts.
Kept for reference and reproducibility.

## Results Summary

| Approach | Test F1 | Notes |
| --- | --- | --- |
| Isolation Forest (Zeek only) | 0.7826 | Works |
| Isolation Forest (eBPF) | 0.8547 | +9.2% improvement |
| Random Forest (supervised) | 0.1107 | Fails (class imbalance) |
| Logistic Regression | 0.1068 | Fails (class imbalance) |
