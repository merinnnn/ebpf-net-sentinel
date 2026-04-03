#!/usr/bin/env python3
"""
RQ4: Computational trade-offs of eBPF-enhanced detection.

Measures:
  1) Dataset load and preprocessing time (baseline vs eBPF)
  2) Model training time (baseline vs eBPF)
  3) Saved-artifact inference latency under a canonical protocol
  4) Optional: runtime overhead of the eBPF collector (netmon) via CPU/RSS sampling

Outputs a JSON summary and an optional netmon sample CSV.
Results depend on hardware; record CPU model, RAM, kernel, and dataset sizes in your report.
"""

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
    num_cols = [c for c in feat_cols if pd.api.types.is_numeric_dtype(df[c])]
    other_cols = [c for c in feat_cols if c not in num_cols]

    num_pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler(with_mean=True, with_std=True)),
    ])

    transformers = [("num", num_pipe, num_cols)]
    if other_cols:
        # Categoricals are imputed then passed through as-is.
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

    pre, feat_cols = build_preprocessor(df_tr, label_col)

    Xtr = df_tr.drop(columns=[label_col])
    ytr = df_tr[label_col].astype(int).to_numpy()
    Xte = df_te.drop(columns=[label_col])
    yte = df_te[label_col].astype(int).to_numpy()

    pipe = Pipeline([("pre", pre), ("model", model)])

    t0 = time.perf_counter()
    pipe.fit(Xtr, ytr)
    fit_s = time.perf_counter() - t0

    # Time on up to 10k rows for stable measurement.
    n = min(len(Xte), 10_000)
    Xbench = Xte.iloc[:n]
    t0 = time.perf_counter()
    if hasattr(pipe, "predict_proba"):
        proba = pipe.predict_proba(Xbench)[:, 1]
    else:
        proba = pipe.predict(Xbench)
    infer_s = time.perf_counter() - t0
    infer_ms_per_1k = (infer_s / max(n, 1)) * 1000 * 1000

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

    # One warmup pass before timing.
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
        raise RuntimeError("psutil is not installed; pip install psutil")

    p = psutil.Process(pid)
    rows = []
    t_end = time.time() + duration_s
    p.cpu_percent(interval=None)  # prime the CPU measurement
    while time.time() < t_end:
        ts = time.time()
        cpu = p.cpu_percent(interval=None)
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
    ap.add_argument("--baseline_splits_dir", type=Path, required=True)
    ap.add_argument("--ebpf_splits_dir", type=Path, required=True)
    ap.add_argument("--baseline_model_pack", type=Path, default=None)
    ap.add_argument("--ebpf_model_pack", type=Path, default=None)
    ap.add_argument("--test_file", type=str, default="test_realistic",
                    choices=["test_realistic", "test_balanced", "test"])
    ap.add_argument("--label_col", type=str, default="is_attack")
    ap.add_argument("--out_json", type=Path, default=Path("overheads.json"))
    ap.add_argument("--out_dir", type=Path, default=Path("rq4_artifacts"))
    ap.add_argument("--skip_training", action="store_true",
                    help="skip retraining and use saved model packs")
    ap.add_argument("--infer_sample_n", type=int, default=10000)
    ap.add_argument("--infer_repeats", type=int, default=7)
    ap.add_argument("--rf_n_estimators", type=int, default=300)
    ap.add_argument("--rf_max_depth", type=int, default=None)
    ap.add_argument("--hgb_max_iter", type=int, default=250)
    ap.add_argument("--hgb_learning_rate", type=float, default=0.05)
    ap.add_argument("--sample_pid", type=int, default=0,
                    help="PID to sample (e.g. netmon). 0 disables.")
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

    base_tr, base_tr_load = read_split_parquet(args.baseline_splits_dir, "train")
    base_te, base_te_load = read_split_parquet(args.baseline_splits_dir, args.test_file)
    ebpf_tr, ebpf_tr_load = read_split_parquet(args.ebpf_splits_dir, "train")
    ebpf_te, ebpf_te_load = read_split_parquet(args.ebpf_splits_dir, args.test_file)

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
            **benchmark_saved_pack("baseline", args.baseline_model_pack, base_te, out_dir,
                                   sample_n=args.infer_sample_n, repeats=args.infer_repeats),
        })
        summary["models"].append({
            "dataset": "ebpf",
            **benchmark_saved_pack("ebpf", args.ebpf_model_pack, ebpf_te, out_dir,
                                   sample_n=args.infer_sample_n, repeats=args.infer_repeats),
        })
    else:
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

        summary["models"].append({"dataset": "baseline", **fit_eval_model("baseline_rf",  rf,  base_tr, base_te, args.label_col, out_dir)})
        summary["models"].append({"dataset": "baseline", **fit_eval_model("baseline_hgb", hgb, base_tr, base_te, args.label_col, out_dir)})
        summary["models"].append({"dataset": "ebpf",     **fit_eval_model("ebpf_rf",      rf,  ebpf_tr, ebpf_te, args.label_col, out_dir)})
        summary["models"].append({"dataset": "ebpf",     **fit_eval_model("ebpf_hgb",     hgb, ebpf_tr, ebpf_te, args.label_col, out_dir)})

    if args.sample_pid:
        summary["netmon_overhead"] = sample_process(
            args.sample_pid, args.sample_duration_s, args.sample_interval_s, args.sample_out_csv
        )

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(summary, indent=2))
    print(f"[OK] Wrote {args.out_json}")

if __name__ == "__main__":
    main()
