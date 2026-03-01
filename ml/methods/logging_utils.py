#!/usr/bin/env python3
"""Shared console logging helpers for ML training scripts."""

from __future__ import annotations

def print_run_header(
    *,
    model_name: str,
    run_name: str,
    splits_dir: str,
    out_models_dir: str,
    out_reports_dir: str,
    params: dict | None = None,
) -> None:
    print(f"[*] {model_name}: {run_name}")
    print(f"  splits_dir      : {splits_dir}")
    print(f"  out_models_dir  : {out_models_dir}")
    print(f"  out_reports_dir : {out_reports_dir}")
    if params:
        print("  parameters:")
        for key, value in params.items():
            print(f"    {key:<18s} {value}")

def print_split_summary(name: str, n_rows: int, n_attack: int) -> None:
    benign = int(n_rows - n_attack)
    attack_pct = (100.0 * n_attack / n_rows) if n_rows else 0.0
    benign_pct = (100.0 * benign / n_rows) if n_rows else 0.0
    print(f"  {name:<5s}: rows={n_rows:>9,}  benign={benign:>9,} ({benign_pct:>5.1f}%)"
          f"  attack={n_attack:>9,} ({attack_pct:>5.1f}%)")

def print_feature_summary(features: list[str], *, dropped: list[str] | None = None) -> None:
    print(f"[*] Feature space: {len(features)} numeric features")
    if features:
        preview = ", ".join(features[:10])
        suffix = " ..." if len(features) > 10 else ""
        print(f"  preview         : {preview}{suffix}")
    if dropped:
        print(f"  dropped_all_nan : {', '.join(dropped)}")

def print_preprocessing_summary(text: str) -> None:
    print(f"[*] Preprocessing: {text}")

def print_tuning_summary(title: str, lines: list[str]) -> None:
    print(f"[*] {title}")
    for line in lines:
        print(f"  {line}")

def print_metrics_block(title: str, metrics: dict) -> None:
    print(f"[*] {title}")
    order = ["accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc"]
    for key in order:
        if key not in metrics:
            continue
        value = metrics.get(key)
        print(f"  {key:12s}: {value:.4f}" if value is not None else f"  {key:12s}: N/A")

def print_per_attack_block(title: str, rows: dict) -> None:
    print(f"[*] {title}")
    if not rows:
        print("  none")
        return
    for attack, stats in sorted(rows.items()):
        print(
            f"  {attack:15s}: {stats['detected']:>5}/{stats['count']:>6}"
            f" ({stats['detection_rate']:>5.1%})"
        )

def print_artifacts(*, model_path: str, summary_path: str, extras: dict | None = None) -> None:
    print("[+] Saved artifacts")
    print(f"  model   : {model_path}")
    print(f"  summary : {summary_path}")
    if extras:
        for key, value in extras.items():
            print(f"  {key:<7s}: {value}")
