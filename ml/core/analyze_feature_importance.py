#!/usr/bin/env python3
"""
Feature Importance Analysis for Isolation Forest using permutation importance
(SHAP TreeExplainer doesn't work well with IF anomaly scores)
"""
import argparse
import json
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib
from sklearn.inspection import permutation_importance

from pathlib import Path

def categorize_features(feature_names):
    """Categorize features as eBPF vs baseline"""
    ebpf_features = []
    baseline_features = []
    
    for feat in feature_names:
        if any(kw in feat.lower() for kw in ['ebpf', 'pid', 'uid', 'comm']):
            ebpf_features.append(feat)
        else:
            baseline_features.append(feat)
    
    return ebpf_features, baseline_features


def get_feature_names(pipe, X_sample):
    """Extract feature names from pipeline"""
    # Get numeric columns from preprocessor
    if hasattr(pipe.named_steps['pre'], 'transformers_'):
        for name, trans, cols in pipe.named_steps['pre'].transformers_:
            if name == 'num':
                return list(cols)
    return []


def compute_permutation_importance(pipe, X_test, y_test, feature_names, n_repeats=10):
    """Compute permutation-based feature importance"""
    print(f"[*] Computing permutation importance ({n_repeats} repeats)")
    
    # Sample if too large
    if len(X_test) > 5000:
        idx = np.random.choice(len(X_test), 5000, replace=False)
        X_sample = X_test.iloc[idx]
        y_sample = y_test.iloc[idx] if isinstance(y_test, pd.Series) else y_test[idx]
    else:
        X_sample = X_test
        y_sample = y_test
    
    # Compute importance
    result = permutation_importance(
        pipe, X_sample, y_sample,
        n_repeats=n_repeats,
        random_state=42,
        n_jobs=-1,
        scoring='f1'
    )
    
    return result


def plot_feature_importance(importances, feature_names, out_png, top_k=20):
    """Plot feature importance"""
    # Get top features
    indices = np.argsort(importances)[::-1][:top_k]
    
    plt.figure(figsize=(10, 8))
    plt.barh(range(len(indices)), importances[indices])
    plt.yticks(range(len(indices)), [feature_names[i] for i in indices])
    plt.xlabel('Importance (F1 score decrease)')
    plt.title(f'Top {top_k} Most Important Features')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(out_png, dpi=200)
    plt.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model_baseline", required=True)
    ap.add_argument("--model_ebpf", required=True)
    ap.add_argument("--test_data_baseline", required=True)
    ap.add_argument("--test_data_ebpf", required=True)
    ap.add_argument("--out_dir", default="data/reports/feature_importance")
    ap.add_argument("--top_k", type=int, default=20)
    ap.add_argument("--n_repeats", type=int, default=10)
    args = ap.parse_args()
    
    os.makedirs(args.out_dir, exist_ok=True)
    
    # Load models
    print("[*] Loading models...")
    pipe_baseline = joblib.load(args.model_baseline)
    pipe_ebpf = joblib.load(args.model_ebpf)
    
    # Load test data
    print("[*] Loading test data...")
    test_baseline = pd.read_parquet(args.test_data_baseline)
    test_ebpf = pd.read_parquet(args.test_data_ebpf)
    
    # Prepare features and labels
    y_baseline = (test_baseline['is_attack'] == 1).astype(int)
    y_ebpf = (test_ebpf['is_attack'] == 1).astype(int)
    
    drop_cols = ['label_family', 'is_attack', 'day', 'label_raw', 
                 'label_time_offset_sec', 'label_halfday_shift_sec',
                 'label_window_pre_slop_sec', 'label_window_post_slop_sec',
                 'run_id', 'ts', 'start_ts', 'end_ts', 't_end',
                 'orig_h', 'resp_h', 'src_ip', 'dst_ip', 'k']
    
    X_baseline = test_baseline.drop(columns=drop_cols, errors='ignore')
    X_ebpf = test_ebpf.drop(columns=drop_cols, errors='ignore')
    
    # Get feature names
    features_baseline = get_feature_names(pipe_baseline, X_baseline)
    features_ebpf = get_feature_names(pipe_ebpf, X_ebpf)
    
    # Filter to numeric only
    numeric_baseline = [c for c in X_baseline.columns if X_baseline[c].dtype in ['int64', 'float64']]
    numeric_ebpf = [c for c in X_ebpf.columns if X_ebpf[c].dtype in ['int64', 'float64']]
    
    X_baseline = X_baseline[numeric_baseline]
    X_ebpf = X_ebpf[numeric_ebpf]
    
    print(f"\n[*] Baseline features: {len(numeric_baseline)}")
    print(f"[*] eBPF features: {len(numeric_ebpf)}")
    
    # Compute importance for baseline
    print("\n[*] BASELINE MODEL:")
    result_baseline = compute_permutation_importance(
        pipe_baseline, X_baseline, y_baseline, numeric_baseline, args.n_repeats
    )
    
    # Compute importance for eBPF
    print("\n[*] eBPF-ENHANCED MODEL:")
    result_ebpf = compute_permutation_importance(
        pipe_ebpf, X_ebpf, y_ebpf, numeric_ebpf, args.n_repeats
    )
    
    # Plot
    plot_feature_importance(
        result_baseline.importances_mean,
        numeric_baseline,
        os.path.join(args.out_dir, "importance_baseline.png"),
        args.top_k
    )
    
    plot_feature_importance(
        result_ebpf.importances_mean,
        numeric_ebpf,
        os.path.join(args.out_dir, "importance_ebpf.png"),
        args.top_k
    )
    
    # Get top features
    top_baseline = []
    indices = np.argsort(result_baseline.importances_mean)[::-1][:args.top_k]
    for rank, idx in enumerate(indices, 1):
        top_baseline.append({
            "rank": rank,
            "feature": numeric_baseline[idx],
            "importance": float(result_baseline.importances_mean[idx]),
            "std": float(result_baseline.importances_std[idx]),
        })
    
    top_ebpf = []
    indices = np.argsort(result_ebpf.importances_mean)[::-1][:args.top_k]
    for rank, idx in enumerate(indices, 1):
        top_ebpf.append({
            "rank": rank,
            "feature": numeric_ebpf[idx],
            "importance": float(result_ebpf.importances_mean[idx]),
            "std": float(result_ebpf.importances_std[idx]),
        })
    
    # Categorize
    ebpf_feats, baseline_feats = categorize_features(numeric_ebpf)
    top_ebpf_names = [x['feature'] for x in top_ebpf]
    ebpf_in_top = [f for f in top_ebpf_names if f in ebpf_feats]
    
    # Print results
    print(f"\n[*] Top {args.top_k} features (BASELINE):")
    for item in top_baseline[:10]:
        print(f"  {item['rank']:2d}. {item['feature']:30s}  "
              f"Importance={item['importance']:.4f} ±{item['std']:.4f}")
    
    print(f"\n[*] Top {args.top_k} features (eBPF-enhanced):")
    for item in top_ebpf[:10]:
        is_ebpf = "⭐" if item['feature'] in ebpf_feats else "  "
        print(f"  {item['rank']:2d}. {item['feature']:30s}  "
              f"Importance={item['importance']:.4f} ±{item['std']:.4f} {is_ebpf}")
    
    print(f"\n[*] eBPF features in top-{args.top_k}: {len(ebpf_in_top)}/{len(ebpf_feats)}")
    for feat in ebpf_in_top:
        print(f"  - {feat}")
    
    # Save results
    results = {
        "baseline": {
            "model_path": args.model_baseline,
            "num_features": len(numeric_baseline),
            "top_features": top_baseline,
        },
        "ebpf": {
            "model_path": args.model_ebpf,
            "num_features": len(numeric_ebpf),
            "top_features": top_ebpf,
            "feature_categories": {
                "ebpf_count": len(ebpf_feats),
                "baseline_count": len(baseline_feats),
                "ebpf_in_topk": len(ebpf_in_top),
                "ebpf_features_in_topk": ebpf_in_top,
            },
        },
    }
    
    summary_path = os.path.join(args.out_dir, "feature_importance_summary.json")
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[*] Summary saved: {summary_path}")
    print(f"[*] Plots saved in: {args.out_dir}")


if __name__ == "__main__":
    main()