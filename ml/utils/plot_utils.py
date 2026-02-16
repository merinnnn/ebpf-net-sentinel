#!/usr/bin/env python3
"""Plotting utilities"""
import matplotlib.pyplot as plt
import numpy as np

def plot_comparison(baseline, ebpf, metric='f1', save_path=None):
    """Plot baseline vs eBPF comparison"""
    try:
        # When running as a module: python -m ml_complete.supervised.train_eval
        from ml.utils.log_utils import info, ok, warn, err, die
    except Exception:
        # When running as a script from repo root
        from utils.log_utils import info, ok, warn, err, die

        models = list(baseline.keys())
        b_vals = [baseline[m][metric] for m in models]
        e_vals = [ebpf[m][metric] for m in models]
        x = np.arange(len(models))
        plt.figure(figsize=(10,6))
        plt.bar(x-0.2, b_vals, 0.4, label='Baseline', alpha=0.8)
        plt.bar(x+0.2, e_vals, 0.4, label='eBPF', alpha=0.8)
        plt.ylabel(metric.upper())
        plt.title(f'{metric.upper()} Comparison')
        plt.xticks(x, models)
        plt.legend()
        plt.grid(axis='y', alpha=0.3)
        if save_path: plt.savefig(save_path, dpi=200, bbox_inches='tight')
        plt.show()
