#!/usr/bin/env python3
"""
RQ4: Computational trade-offs of eBPF-enhanced detection.

This script produces reproducible overhead measurements for:
  1) Dataset load + preprocessing time (baseline vs eBPF)
  2) Model training time (baseline vs eBPF)
  3) Saved-artifact inference latency under one canonical protocol
  4) Optional: runtime overhead of the eBPF collector process ("netmon") by sampling CPU/RSS.

Outputs:
  - JSON summary (default: overheads.json)
  - Optional CSV time-series for netmon sampling

Notes:
  - Results depend on hardware; record CPU model, RAM, kernel, and dataset sizes in your report.
  - Use the SAME split files for baseline and eBPF to make comparisons fair.
  - The canonical saved-artifact benchmark loads the joblib pack, prepares the requested test split,
    runs one warmup scoring pass, then times repeated scoring on a fixed row sample.
"""
from __future__ import annotations

import argparse, json, os, platform, sys, time
from pathlib import Path
from typing import Dict, Any, Tuple

import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score, average_precision_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.notebooks.modeling_pipeline import prepare_split, align_to_features

import psutil


def read_split_parquet(splits_dir: Path, split_name: str) -> pd.DataFrame:
    p = splits_dir / f"{split_name}.parquet"
    if not p.exists():
        raise FileNotFoundError(f"Missing split parquet: {p}")
    t0 = time.perf_counter()
    df = pd.read_parquet(p)
    dt = time.perf_counter() - t0
    return df, dt


def build_preprocessor(df: pd.DataFrame, label_col: str) -> Tuple[Pipeline, list[str]]:
    feat_cols = [c for c in df.columns if c != label_col]
    # Everything numeric in your current datasets; keep robust handling anyway.
    num_cols = [c for c in feat_cols if pd.api.types.is_numeric_dtype(df[c])]
    other_cols = [c for c in feat_cols if c not in num_cols]

    # Numeric: median + scale
    num_pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler(with_mean=True, with_std=True)),
    ])

    transformers = [("num", num_pipe, num_cols)]
    if other_cols:
        # If you later add categoricals, they will be imputed then passthrough as-is.
        other_pipe = Pipeline([("imputer", SimpleImputer(strategy="most_frequent"))])
        transformers.append(("other", other_pipe, other_cols))

    pre = ColumnTransformer(transformers=transformers, remainder="drop", sparse_threshold=0.0)
    return pre, feat_cols


def fit_eval_model(
    model_name: str,
    model,
    df_tr: pd.DataFrame,
    df_te: pd.DataFrame,
    label_col: str,
    out_dir: Path,
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build preprocessor based on train schema
    pre, feat_cols = build_preprocessor(df_tr, label_col)

    Xtr = df_tr.drop(columns=[label_col])
    ytr = df_tr[label_col].astype(int).to_numpy()
    Xte = df_te.drop(columns=[label_col])
    yte = df_te[label_col].astype(int).to_numpy()

    pipe = Pipeline([("pre", pre), ("model", model)])

    # Fit timing
    t0 = time.perf_counter()
    pipe.fit(Xtr, ytr)
    fit_s = time.perf_counter() - t0

    # Predict timing (probability)
    # Use 10k samples max for stable timing.
    n = min(len(Xte), 10_000)
    Xbench = Xte.iloc[:n]
    t0 = time.perf_counter()
    if hasattr(pipe, "predict_proba"):
        proba = pipe.predict_proba(Xbench)[:, 1]
    else:
        # HGB has predict_proba; fallback just in case.
        proba = pipe.predict(Xbench)
    infer_s = time.perf_counter() - t0
    infer_ms_per_1k = (infer_s / max(n, 1)) * 1000 * 1000

    # Basic quality metrics on full test (not the core of RQ4 but helps sanity-check)
    if hasattr(pipe, "predict_proba"):
        p_full = pipe.predict_proba(Xte)[:, 1]
    else:
        p_full = pipe.predict(Xte)
    try:
        auc = float(roc_auc_score(yte, p_full))
    except Exception:
        auc = float("nan")
    try:
        ap = float(average_precision_score(yte, p_full))
    except Exception:
        ap = float("nan")

    # Model size
    model_path = out_dir / f"{model_name}.joblib"
    dump(pipe, model_path)
    size_bytes = model_path.stat().st_size

    return {
        "model": model_name,
        "fit_seconds": fit_s,
        "infer_ms_per_1k": infer_ms_per_1k,
        "model_size_bytes": int(size_bytes),
        "test_auc": auc,
        "test_ap": ap,
        "n_train": int(len(df_tr)),
        "n_test": int(len(df_te)),
        "n_features": int(df_tr.shape[1] - 1),
    }


def benchmark_saved_pack(
    dataset_name: str,
    pack_path: Path,
    df_te: pd.DataFrame,
    out_dir: Path,
    sample_n: int = 10_000,
    repeats: int = 7,
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    pack = load(pack_path)
    artifact_load_s = time.perf_counter() - t0
    if not isinstance(pack, dict) or "model" not in pack or "features" not in pack:
        raise ValueError(f"Unsupported model pack format: {pack_path}")

    prep = prepare_split(df_te, feature_list=pack["features"])
    Xte = align_to_features(prep.X, pack["features"])
    yte = prep.y

    n = min(len(Xte), sample_n)
    Xbench = Xte.iloc[:n]
    model = pack["model"]
    score_fn = model.predict_proba if hasattr(model, "predict_proba") else model.decision_function
    score_method = "predict_proba" if hasattr(model, "predict_proba") else "decision_function"

    # Warm up estimator internals before timing.
    warm_rows = min(256, len(Xbench))
    _ = score_fn(Xbench.iloc[:warm_rows])

    timings = []
    score = None
    for _ in range(max(int(repeats), 1)):
        t0 = time.perf_counter()
        score = score_fn(Xbench)
        timings.append(time.perf_counter() - t0)

    infer_s = float(np.mean(timings))
    infer_std_s = float(np.std(timings))
    infer_ms_per_1k = (infer_s / max(n, 1)) * 1_000_000.0

    if np.ndim(score) != 1:
        score = score[:, 1]

    full_score = score_fn(Xte)
    if np.ndim(full_score) != 1:
        full_score = full_score[:, 1]

    try:
        auc = float(roc_auc_score(yte, full_score))
    except Exception:
        auc = float("nan")
    try:
        ap = float(average_precision_score(yte, full_score))
    except Exception:
        ap = float("nan")

    artifact_copy = out_dir / f"{dataset_name}_headline_model.joblib"
    if not artifact_copy.exists() or artifact_copy.stat().st_mtime < pack_path.stat().st_mtime:
        dump(pack, artifact_copy)
    size_bytes = int(pack_path.stat().st_size)

    return {
        "model": pack.get("selected_model_name", artifact_copy.stem),
        "artifact_path": str(pack_path),
        "artifact_copy_path": str(artifact_copy),
        "artifact_load_seconds": float(artifact_load_s),
        "fit_seconds": None,
        "latency_mean_seconds": infer_s,
        "latency_std_seconds": infer_std_s,
        "infer_ms_per_1k": infer_ms_per_1k,
        "model_size_bytes": size_bytes,
        "test_auc": auc,
        "test_ap": ap,
        "n_train": None,
        "n_test": int(len(Xte)),
        "n_features": int(len(pack["features"])),
        "threshold_mode": pack.get("threshold_mode"),
        "threshold": pack.get("threshold"),
        "infer_rows_benchmarked": int(n),
        "latency_repeats": int(max(int(repeats), 1)),
        "latency_warmup_rows": int(warm_rows),
        "score_method": score_method,
        "sample_selection": "first_n_rows_after_feature_alignment",
        "benchmark_mode": "saved_artifact_split4_realistic_fixed_sample",
    }


def sample_process(pid: int, duration_s: int, interval_s: float, out_csv: Path) -> Dict[str, Any]:
    if psutil is None:
        raise RuntimeError("psutil is not installed; add it to requirements.txt or pip install psutil")

    p = psutil.Process(pid)
    rows = []
    t_end = time.time() + duration_s
    # Prime CPU measurement
    p.cpu_percent(interval=None)
    while time.time() < t_end:
        ts = time.time()
        cpu = p.cpu_percent(interval=None)  # percent over last interval
        mem = p.memory_info().rss
        rows.append({"ts": ts, "cpu_percent": cpu, "rss_bytes": mem})
        time.sleep(interval_s)

    df = pd.DataFrame(rows)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_csv, index=False)

    return {
        "pid": pid,
        "samples": int(len(df)),
        "cpu_percent_mean": float(df["cpu_percent"].mean()) if len(df) else float("nan"),
        "cpu_percent_p95": float(df["cpu_percent"].quantile(0.95)) if len(df) else float("nan"),
        "rss_mb_mean": float(df["rss_bytes"].mean() / (1024**2)) if len(df) else float("nan"),
        "rss_mb_p95": float(df["rss_bytes"].quantile(0.95) / (1024**2)) if len(df) else float("nan"),
        "csv": str(out_csv),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline_splits_dir", type=Path, required=True, help="Directory containing train.parquet/test_*.parquet for baseline")
    ap.add_argument("--ebpf_splits_dir", type=Path, required=True, help="Directory containing train.parquet/test_*.parquet for eBPF")
    ap.add_argument("--baseline_model_pack", type=Path, default=None, help="Saved model pack for baseline inference benchmark")
    ap.add_argument("--ebpf_model_pack", type=Path, default=None, help="Saved model pack for eBPF inference benchmark")
    ap.add_argument("--test_file", type=str, default="test_realistic", choices=["test_realistic","test_balanced","test"], help="Which test parquet to use")
    ap.add_argument("--label_col", type=str, default="is_attack", help="Binary label column (0/1)")
    ap.add_argument("--out_json", type=Path, default=Path("overheads.json"))
    ap.add_argument("--out_dir", type=Path, default=Path("rq4_artifacts"))
    ap.add_argument("--skip_training", action="store_true", help="Skip retraining benchmark and use saved model packs if provided")
    ap.add_argument("--infer_sample_n", type=int, default=10000, help="Rows used for latency timing")
    ap.add_argument("--infer_repeats", type=int, default=7, help="Repeated scoring runs for latency timing")
    ap.add_argument("--rf_n_estimators", type=int, default=300)
    ap.add_argument("--rf_max_depth", type=int, default=None)
    ap.add_argument("--hgb_max_iter", type=int, default=250)
    ap.add_argument("--hgb_learning_rate", type=float, default=0.05)
    # Optional netmon sampling
    ap.add_argument("--sample_pid", type=int, default=0, help="PID to sample (e.g., netmon). 0 disables.")
    ap.add_argument("--sample_duration_s", type=int, default=60)
    ap.add_argument("--sample_interval_s", type=float, default=1.0)
    ap.add_argument("--sample_out_csv", type=Path, default=Path("rq4_netmon_samples.csv"))

    args = ap.parse_args()

    sysinfo = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
    }

    # Load baseline
    base_tr, base_tr_load = read_split_parquet(args.baseline_splits_dir, "train")
    base_te, base_te_load = read_split_parquet(args.baseline_splits_dir, args.test_file)

    # Load ebpf
    ebpf_tr, ebpf_tr_load = read_split_parquet(args.ebpf_splits_dir, "train")
    ebpf_te, ebpf_te_load = read_split_parquet(args.ebpf_splits_dir, args.test_file)

    # Sanity: same split sizes recommended but not enforced (some pipelines differ)
    summary: Dict[str, Any] = {
        "system": sysinfo,
        "inputs": {
            "baseline_splits_dir": str(args.baseline_splits_dir),
            "ebpf_splits_dir": str(args.ebpf_splits_dir),
            "baseline_model_pack": str(args.baseline_model_pack) if args.baseline_model_pack else None,
            "ebpf_model_pack": str(args.ebpf_model_pack) if args.ebpf_model_pack else None,
            "test_file": args.test_file,
            "label_col": args.label_col,
            "skip_training": bool(args.skip_training),
        },
        "load_times_seconds": {
            "baseline_train": base_tr_load,
            "baseline_test": base_te_load,
            "ebpf_train": ebpf_tr_load,
            "ebpf_test": ebpf_te_load,
        },
        "dataset_shapes": {
            "baseline_train": [int(base_tr.shape[0]), int(base_tr.shape[1])],
            "baseline_test": [int(base_te.shape[0]), int(base_te.shape[1])],
            "ebpf_train": [int(ebpf_tr.shape[0]), int(ebpf_tr.shape[1])],
            "ebpf_test": [int(ebpf_te.shape[0]), int(ebpf_te.shape[1])],
        },
        "benchmark_protocol": {
            "train_load_measurement": "wall_clock_seconds_to_read_train_parquet",
            "test_load_measurement": "wall_clock_seconds_to_read_requested_test_parquet",
            "inference_measurement": (
                "saved-artifact scoring latency on a fixed first-N-row sample after one warmup pass; "
                "reported as mean/std seconds and ms per 1k rows"
            ),
            "test_file": args.test_file,
            "infer_sample_n": int(args.infer_sample_n),
            "infer_repeats": int(args.infer_repeats),
            "skip_training": bool(args.skip_training),
        },
        "models": [],
        "netmon_overhead": None,
    }

    out_dir = args.out_dir
    if args.skip_training:
        if not args.baseline_model_pack or not args.ebpf_model_pack:
            raise ValueError("--skip_training requires --baseline_model_pack and --ebpf_model_pack")
        summary["models"].append({
            "dataset": "baseline",
            **benchmark_saved_pack(
                "baseline",
                args.baseline_model_pack,
                base_te,
                out_dir,
                sample_n=args.infer_sample_n,
                repeats=args.infer_repeats,
            ),
        })
        summary["models"].append({
            "dataset": "ebpf",
            **benchmark_saved_pack(
                "ebpf",
                args.ebpf_model_pack,
                ebpf_te,
                out_dir,
                sample_n=args.infer_sample_n,
                repeats=args.infer_repeats,
            ),
        })
    else:
        # Models for overhead measurement
        rf = RandomForestClassifier(
            n_estimators=args.rf_n_estimators,
            max_depth=args.rf_max_depth,
            n_jobs=-1,
            random_state=104,
        )
        hgb = HistGradientBoostingClassifier(
            max_iter=args.hgb_max_iter,
            learning_rate=args.hgb_learning_rate,
            random_state=104,
        )

        # Fit baseline
        summary["models"].append({"dataset": "baseline", **fit_eval_model("baseline_rf", rf, base_tr, base_te, args.label_col, out_dir)})
        summary["models"].append({"dataset": "baseline", **fit_eval_model("baseline_hgb", hgb, base_tr, base_te, args.label_col, out_dir)})

        # Fit ebpf
        summary["models"].append({"dataset": "ebpf", **fit_eval_model("ebpf_rf", rf, ebpf_tr, ebpf_te, args.label_col, out_dir)})
        summary["models"].append({"dataset": "ebpf", **fit_eval_model("ebpf_hgb", hgb, ebpf_tr, ebpf_te, args.label_col, out_dir)})

    # Optional netmon sampling
    if args.sample_pid:
        summary["netmon_overhead"] = sample_process(args.sample_pid, args.sample_duration_s, args.sample_interval_s, args.sample_out_csv)

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(summary, indent=2))
    print(f"[OK] Wrote {args.out_json}")


if __name__ == "__main__":
    main()
