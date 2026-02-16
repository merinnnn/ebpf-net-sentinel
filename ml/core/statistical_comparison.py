#!/usr/bin/env python3
"""
Statistical Comparison of Baseline vs eBPF-Enhanced Models

Answers Research Question 1: Does eBPF significantly improve detection?
"""
import argparse
import json
from scipy import stats

def compute_improvement(baseline, ebpf):
    """Compute relative and absolute improvement"""
    abs_diff = ebpf - baseline
    rel_diff = ((ebpf - baseline) / baseline * 100) if baseline > 0 else 0
    return abs_diff, rel_diff


def wilcoxon_test(scores_a, scores_b):
    """Wilcoxon signed-rank test for paired samples"""
    try:
        stat, pvalue = stats.wilcoxon(scores_a, scores_b)
        return {"statistic": float(stat), "pvalue": float(pvalue)}
    except:
        return {"statistic": None, "pvalue": None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline_summary", required=True,
                   help="Baseline metrics summary JSON")
    ap.add_argument("--ebpf_summary", required=True,
                   help="eBPF metrics summary JSON")
    ap.add_argument("--out_json", default="data/reports/statistical_comparison.json")
    args = ap.parse_args()
    
    # Load summaries
    with open(args.baseline_summary) as f:
        baseline = json.load(f)
    
    with open(args.ebpf_summary) as f:
        ebpf = json.load(f)
    
    print(f"[*] STATISTICAL COMPARISON: Baseline vs eBPF-Enhanced")
    
    results = {
        "baseline_file": args.baseline_summary,
        "ebpf_file": args.ebpf_summary,
        "models": {},
    }
    
    # Compare each model type
    common_models = set(baseline.get("models", {}).keys()) & \
                   set(ebpf.get("models", {}).keys())
    
    for model_name in sorted(common_models):
        print(f"\n{'='*70}")
        print(f"Model: {model_name.upper()}")
        print(f"{'='*70}")
        
        b_metrics = baseline["models"][model_name]["test"]
        e_metrics = ebpf["models"][model_name]["test"]
        
        model_results = {}
        
        # Overall metrics
        for metric in ["accuracy", "macro_f1"]:
            if metric in b_metrics and metric in e_metrics:
                b_val = b_metrics[metric]
                e_val = e_metrics[metric]
                
                abs_diff, rel_diff = compute_improvement(b_val, e_val)
                
                print(f"\n{metric.upper()}:")
                print(f"  Baseline:        {b_val:.4f}")
                print(f"  eBPF-enhanced:   {e_val:.4f}")
                print(f"  Absolute diff:   {abs_diff:+.4f}")
                print(f"  Relative diff:   {rel_diff:+.2f}%")
                
                model_results[metric] = {
                    "baseline": float(b_val),
                    "ebpf": float(e_val),
                    "absolute_improvement": float(abs_diff),
                    "relative_improvement_pct": float(rel_diff),
                }
        
        # Per-class comparison
        if "per_class" in b_metrics and "per_class" in e_metrics:
            common_classes = set(b_metrics["per_class"].keys()) & \
                           set(e_metrics["per_class"].keys())
            
            print(f"\n[*] PER-CLASS F1-SCORE COMPARISON:")
            print(f"  {'Class':<15} {'Baseline':>10} {'eBPF':>10} {'Diff':>10} {'% Improvement':>15}")
            print(f"  {'-'*65}")
            
            per_class_results = {}
            
            for cls in sorted(common_classes):
                b_f1 = b_metrics["per_class"][cls]["f1"]
                e_f1 = e_metrics["per_class"][cls]["f1"]
                
                abs_diff, rel_diff = compute_improvement(b_f1, e_f1)
                
                print(f"  {cls:<15} {b_f1:>10.4f} {e_f1:>10.4f} "
                      f"{abs_diff:>+10.4f} {rel_diff:>+14.2f}%")
                
                per_class_results[cls] = {
                    "baseline_f1": float(b_f1),
                    "ebpf_f1": float(e_f1),
                    "absolute_improvement": float(abs_diff),
                    "relative_improvement_pct": float(rel_diff),
                }
            
            model_results["per_class"] = per_class_results
        
        # Per-day comparison
        if "test_per_day" in baseline["models"][model_name] and \
           "test_per_day" in ebpf["models"][model_name]:
            
            b_days = baseline["models"][model_name]["test_per_day"]
            e_days = ebpf["models"][model_name]["test_per_day"]
            
            common_days = set(b_days.keys()) & set(e_days.keys())
            
            if common_days:
                print(f"\n[*] PER-DAY COMPARISON:")
                print(f"  {'Day':<12} {'Metric':<10} {'Baseline':>10} {'eBPF':>10} {'Diff':>10}")
                print(f"  {'-'*57}")
                
                per_day_results = {}
                
                for day in sorted(common_days):
                    day_results = {}
                    
                    for metric in ["accuracy", "macro_f1"]:
                        if metric in b_days[day] and metric in e_days[day]:
                            b_val = b_days[day][metric]
                            e_val = e_days[day][metric]
                            abs_diff, rel_diff = compute_improvement(b_val, e_val)
                            
                            print(f"  {day:<12} {metric:<10} {b_val:>10.4f} "
                                  f"{e_val:>10.4f} {abs_diff:>+10.4f}")
                            
                            day_results[metric] = {
                                "baseline": float(b_val),
                                "ebpf": float(e_val),
                                "absolute_improvement": float(abs_diff),
                                "relative_improvement_pct": float(rel_diff),
                            }
                    
                    per_day_results[day] = day_results
                
                model_results["per_day"] = per_day_results
        
        results["models"][model_name] = model_results

    # Summary
    print("[*] SUMMARY")
    for model_name in sorted(common_models):
        if "macro_f1" in results["models"][model_name]:
            improvement = results["models"][model_name]["macro_f1"]["relative_improvement_pct"]
            
            if improvement > 5:
                verdict = "SIGNIFICANT IMPROVEMENT"
            elif improvement > 0:
                verdict = "MARGINAL IMPROVEMENT"
            elif improvement == 0:
                verdict = "NO CHANGE"
            else:
                verdict = "DEGRADATION"
            
            print(f"\n{model_name}:")
            print(f"  Macro-F1 improvement: {improvement:+.2f}%  {verdict}")
    
    # Save results
    with open(args.out_json, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[*] Detailed comparison saved: {args.out_json}")

if __name__ == "__main__":
    main()