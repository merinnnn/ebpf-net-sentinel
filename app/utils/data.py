from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import streamlit as st

from utils.styles import COLORS


ATTACK_TYPES: list[str] = [
    "Bot",
    "DDoS",
    "DoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "DoS Slowloris",
    "FTP-Patator",
    "Heartbleed",
    "PortScan",
    "SSH-Patator",
]

PACKET_FEATURES: list[str] = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "src_port",
    "dst_port",
    "proto_i",
    "service",
    "conn_state",
    "missed_bytes",
    "history",
    "orig_p",
    "resp_p",
    "local_orig",
    "local_resp",
    "flow_packets_per_second",
    "flow_bytes_per_second",
]

EBPF_FEATURES: list[str] = [
    "ebpf_pkt_rate",
    "ebpf_byte_rate",
    "ebpf_syn_rate",
    "ebpf_ack_rate",
    "ebpf_rst_rate",
    "ebpf_fin_rate",
    "ebpf_psh_rate",
    "ebpf_urg_rate",
    "ebpf_retransmissions",
    "ebpf_avg_rtt_us",
    "ebpf_tcp_handshake_ms",
    "ebpf_socket_fanout",
    "ebpf_pid_count",
    "ebpf_unique_dst_ips",
    "ebpf_unique_dst_ports",
]

def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]

def _reports_dir(reports_dir: str | Path | None = None) -> Path:
    return Path(reports_dir) if reports_dir else _repo_root() / "data" / "reports"

def _coerce_feature_set(run_name: str) -> str:
    return "ebpf" if "ebpf" in run_name.lower() else "baseline"

def _coerce_model_name(model: str) -> str:
    normalized = model.lower()
    if "randomforest" in normalized or normalized == "rf":
        return "Random Forest"
    if "iforest" in normalized or "isolation" in normalized:
        return "Isolation Forest"
    if "histgradientboosting" in normalized or normalized == "hgb":
        return "HistGradientBoosting"
    return model

def _selection_score(report: dict[str, Any]) -> float:
    test = report.get("test", {})
    return float(test.get("roc_auc", 0.0)) * 0.65 + float(test.get("f1", 0.0)) * 0.35

def _deterministic_rng(seed: int = 42) -> np.random.Generator:
    return np.random.default_rng(seed)

def _mock_report_rows() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    return [
        {
            "timestamp": (now - timedelta(hours=10)).isoformat(),
            "run_name": "baseline_rf_split2_seed42",
            "model": "RandomForest",
            "tuned_threshold": 0.72,
            "training_time_seconds": 328.4,
            "features": PACKET_FEATURES[:10],
            "validation": {
                "accuracy": 0.983,
                "precision": 0.914,
                "recall": 0.842,
                "f1": 0.877,
                "roc_auc": 0.985,
                "pr_auc": 0.812,
            },
            "test": {
                "accuracy": 0.981,
                "precision": 0.901,
                "recall": 0.836,
                "f1": 0.867,
                "roc_auc": 0.978,
                "pr_auc": 0.804,
            },
            "per_attack_detection": {
                "Bot": {"count": 2208, "detected": 2206, "detection_rate": 0.9991},
                "PortScan": {"count": 159109, "detected": 158918, "detection_rate": 0.9988},
            },
            "feature_importance": [
                {"feature": "proto_i", "importance": 0.24},
                {"feature": "dst_port", "importance": 0.18},
                {"feature": "orig_bytes", "importance": 0.15},
            ],
        },
        {
            "timestamp": (now - timedelta(hours=9)).isoformat(),
            "run_name": "ebpf_rf_split2_seed42",
            "model": "RandomForest",
            "tuned_threshold": 0.69,
            "training_time_seconds": 341.1,
            "features": PACKET_FEATURES[:10] + EBPF_FEATURES[:5],
            "validation": {
                "accuracy": 0.988,
                "precision": 0.944,
                "recall": 0.892,
                "f1": 0.917,
                "roc_auc": 0.993,
                "pr_auc": 0.881,
            },
            "test": {
                "accuracy": 0.986,
                "precision": 0.934,
                "recall": 0.887,
                "f1": 0.910,
                "roc_auc": 0.991,
                "pr_auc": 0.873,
            },
            "per_attack_detection": {
                "Bot": {"count": 2208, "detected": 2206, "detection_rate": 0.9991},
                "PortScan": {"count": 159109, "detected": 158946, "detection_rate": 0.9990},
            },
            "feature_importance": [
                {"feature": "ebpf_syn_rate", "importance": 0.20},
                {"feature": "dst_port", "importance": 0.16},
                {"feature": "ebpf_unique_dst_ports", "importance": 0.15},
            ],
        },
    ]

@st.cache_data(show_spinner=False)
def load_real_reports(reports_dir: str | Path | None = None) -> list[dict[str, Any]]:
    report_dir = _reports_dir(reports_dir)
    if not report_dir.exists():
        return _mock_report_rows()

    reports: list[dict[str, Any]] = []
    for path in sorted(report_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(payload, dict):
            payload["_source_file"] = str(path)
            reports.append(payload)
    return reports or _mock_report_rows()

@st.cache_data(show_spinner=False)
def get_reports_frame(reports_dir: str | Path | None = None) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for report in load_real_reports(reports_dir):
        run_name = str(report.get("run_name") or Path(report.get("_source_file", "")).stem)
        validation = report.get("validation", {})
        test = report.get("test", {})
        rows.append(
            {
                "timestamp": report.get("timestamp"),
                "run_name": run_name,
                "feature_set": _coerce_feature_set(run_name),
                "model": _coerce_model_name(str(report.get("model", "Unknown"))),
                "threshold": float(report.get("tuned_threshold", 0.5) or 0.5),
                "training_time_seconds": float(report.get("training_time_seconds", 0.0) or 0.0),
                "feature_count": len(report.get("features", [])),
                "val_accuracy": float(validation.get("accuracy", 0.0) or 0.0),
                "val_precision": float(validation.get("precision", 0.0) or 0.0),
                "val_recall": float(validation.get("recall", 0.0) or 0.0),
                "val_f1": float(validation.get("f1", 0.0) or 0.0),
                "val_auc": float(validation.get("roc_auc", 0.0) or 0.0),
                "test_accuracy": float(test.get("accuracy", 0.0) or 0.0),
                "test_precision": float(test.get("precision", 0.0) or 0.0),
                "test_recall": float(test.get("recall", 0.0) or 0.0),
                "test_f1": float(test.get("f1", 0.0) or 0.0),
                "test_auc": float(test.get("roc_auc", 0.0) or 0.0),
                "test_pr_auc": float(test.get("pr_auc", 0.0) or 0.0),
                "selection_score": _selection_score(report),
                "source_file": report.get("_source_file", ""),
            }
        )

    frame = pd.DataFrame(rows)
    if frame.empty:
        return frame

    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    return frame.sort_values(["selection_score", "test_auc"], ascending=False).reset_index(drop=True)

@st.cache_data(show_spinner=False)
def get_available_runs() -> list[str]:
    frame = get_reports_frame()
    if frame.empty:
        return ["Latest Run"]
    return ["Latest Run"] + frame["run_name"].dropna().astype(str).unique().tolist()

@st.cache_data(show_spinner=False)
def get_model_summary_table() -> pd.DataFrame:
    frame = get_reports_frame()
    if frame.empty:
        return pd.DataFrame(
            columns=[
                "run_name",
                "feature_set",
                "model",
                "test_auc",
                "test_f1",
                "test_precision",
                "test_recall",
                "training_time_seconds",
            ]
        )
    columns = [
        "run_name",
        "feature_set",
        "model",
        "test_auc",
        "test_f1",
        "test_precision",
        "test_recall",
        "training_time_seconds",
        "threshold",
    ]
    return frame[columns].copy()

@st.cache_data(show_spinner=False)
def get_dashboard_snapshot() -> dict[str, Any]:
    frame = get_reports_frame()
    benchmark = get_cost_performance_snapshot()

    if frame.empty:
        return {
            "headline": [],
            "best_run": {},
            "feature_coverage": {"packet": len(PACKET_FEATURES), "ebpf": len(EBPF_FEATURES)},
        }

    best_run = frame.iloc[0].to_dict()
    best_baseline = frame[frame["feature_set"] == "baseline"]["test_auc"].max()
    best_ebpf = frame[frame["feature_set"] == "ebpf"]["test_auc"].max()
    latency_gain = benchmark["summary"]["latency_gain_pct"]

    headline = [
        {"label": "Best Test AUC", "value": f"{best_run['test_auc']:.3f}", "delta": best_run["run_name"]},
        {"label": "Best Test F1", "value": f"{best_run['test_f1']:.3f}", "delta": best_run["model"]},
        {"label": "eBPF Lift", "value": f"{(best_ebpf - best_baseline):+.3f}", "delta": "AUC vs baseline"},
        {"label": "Latency Delta", "value": f"{latency_gain:+.1f}%", "delta": "eBPF inference"},
    ]

    return {
        "headline": headline,
        "best_run": best_run,
        "feature_coverage": {"packet": len(PACKET_FEATURES), "ebpf": len(EBPF_FEATURES)},
        "run_counts": frame["feature_set"].value_counts().to_dict(),
    }


@st.cache_data(show_spinner=False)
def get_dashboard_kpis() -> list[dict[str, str]]:
    return [
        {"label": "FLOWS ANALYSED", "value": "1.24M", "delta": "+12.4% vs prev hour", "color": COLORS["cyan"]},
        {"label": "ANOMALIES DETECTED", "value": "348", "delta": "28.1% FPR (baseline)", "color": COLORS["red"]},
        {"label": "ROC-AUC (EBPF)", "value": "0.947", "delta": "+0.041 vs baseline", "color": COLORS["green"]},
        {"label": "EBPF OVERHEAD", "value": "4.2%", "delta": "CPU · 18ms avg latency", "color": COLORS["amber"]},
    ]


@st.cache_data(show_spinner=False)
def get_dashboard_alerts() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "time": "14:32:01",
                "src_ip": "192.168.1.105",
                "dst": "10.0.0.1:443",
                "attack": "DDoS",
                "score": 0.97,
                "model": "eBPF",
                "run": "RUN-043",
                "status": "OPEN",
            },
            {
                "time": "14:31:44",
                "src_ip": "10.0.0.42",
                "dst": "8.8.8.8:53",
                "attack": "Port Scan",
                "score": 0.84,
                "model": "eBPF",
                "run": "RUN-043",
                "status": "REVIEW",
            },
            {
                "time": "14:30:12",
                "src_ip": "172.16.0.8",
                "dst": "10.0.0.1:22",
                "attack": "Brute Force",
                "score": 0.93,
                "model": "BASE",
                "run": "RUN-042",
                "status": "OPEN",
            },
            {
                "time": "14:28:55",
                "src_ip": "192.168.0.201",
                "dst": "192.168.0.1:80",
                "attack": "Benign",
                "score": 0.12,
                "model": "eBPF",
                "run": "RUN-043",
                "status": "CLOSED",
            },
            {
                "time": "14:27:33",
                "src_ip": "10.0.1.15",
                "dst": "10.0.0.1:3306",
                "attack": "SQL Inject",
                "score": 0.96,
                "model": "eBPF",
                "run": "RUN-043",
                "status": "OPEN",
            },
        ]
    )


@st.cache_data(show_spinner=False)
def get_threat_distribution_snapshot() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "attack": ["DDoS", "Port Scan", "Brute Force", "Other"],
            "alerts": [132, 90, 59, 67],
            "share": [0.38, 0.26, 0.17, 0.19],
            "color": [COLORS["red"], COLORS["amber"], COLORS["cyan"], COLORS["green"]],
        }
    )


@st.cache_data(show_spinner=False)
def get_live_event_stream() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"time": "14:32:05", "src_ip": "192.168.1.105", "proto": "TCP", "score": 0.97, "classification": "DDoS · Hulk"},
            {"time": "14:32:03", "src_ip": "10.0.0.42", "proto": "UDP", "score": 0.08, "classification": "BENIGN"},
            {"time": "14:32:01", "src_ip": "172.16.0.8", "proto": "TCP", "score": 0.72, "classification": "Port Scan"},
            {"time": "14:31:58", "src_ip": "10.0.1.15", "proto": "TCP", "score": 0.94, "classification": "Brute Force · SSH"},
            {"time": "14:31:55", "src_ip": "192.168.0.201", "proto": "DNS", "score": 0.04, "classification": "BENIGN"},
        ]
    )


@st.cache_data(show_spinner=False)
def get_protocol_breakdown_snapshot() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "protocol": ["TCP", "UDP", "DNS", "ICMP"],
            "share": [72, 18, 6, 4],
            "color": [COLORS["cyan"], COLORS["purple"], COLORS["green"], COLORS["amber"]],
        }
    )


@st.cache_data(show_spinner=False)
def get_probe_status_snapshot() -> list[dict[str, str]]:
    return [
        {"name": "kprobe/tcp_connect", "status": "ACTIVE", "rate": "2.1k ev/s", "color": COLORS["green"]},
        {"name": "tracepoint/net/netif_rx", "status": "ACTIVE", "rate": "38.4k ev/s", "color": COLORS["green"]},
        {"name": "kprobe/sys_bind", "status": "DEGRADED", "rate": "0.0 ev/s", "color": COLORS["amber"]},
        {"name": "uprobe/libssl_read", "status": "ACTIVE", "rate": "1.8k ev/s", "color": COLORS["green"]},
    ]


@st.cache_data(show_spinner=False)
def get_live_monitor_snapshot(hours: int = 6) -> dict[str, Any]:
    rng = _deterministic_rng(7)
    periods = max(hours * 12, 12)
    timeline = pd.date_range(end=pd.Timestamp.utcnow().floor("min"), periods=periods, freq="5min")

    baseline_score = np.clip(0.32 + np.cumsum(rng.normal(0, 0.008, periods)), 0.12, 0.74)
    ebpf_score = np.clip(0.28 + np.cumsum(rng.normal(0, 0.007, periods)), 0.08, 0.67)
    packets = np.clip(18000 + np.cumsum(rng.normal(0, 420, periods)), 12000, 28000)
    drops = np.clip(14 + np.abs(rng.normal(0, 4, periods)), 1, 48)
    alerts = np.clip(12 + np.abs(rng.normal(0, 5, periods)), 2, 56)

    probes = [
        {"name": "Capture Probe", "status": "Nominal", "rate": "18.7 kpps", "color": "#00d4ff"},
        {"name": "eBPF Hooks", "status": "Attached", "rate": "99.97%", "color": "#10b981"},
        {"name": "Model Bus", "status": "Streaming", "rate": "24.1 ms", "color": "#7c3aed"},
        {"name": "Alert Queue", "status": "Backpressure", "rate": "14 queued", "color": "#f59e0b"},
    ]

    return {
        "timeline": timeline.to_pydatetime().tolist(),
        "series": {
            "Packets/sec": packets.round(0).tolist(),
            "Drops/min": drops.round(1).tolist(),
            "Alerts/min": alerts.round(1).tolist(),
            "Baseline Score": baseline_score.round(3).tolist(),
            "eBPF Score": ebpf_score.round(3).tolist(),
        },
        "probes": probes,
    }

@st.cache_data(show_spinner=False)
def get_live_monitor_page_snapshot(window_seconds: int = 60) -> dict[str, Any]:
    rng = _deterministic_rng(17)
    points = 31
    now = pd.Timestamp.utcnow().floor("s")
    timeline = pd.date_range(end=now, periods=points, freq=f"{max(window_seconds // (points - 1), 1)}s")

    base_wave = np.sin(np.linspace(0, 5 * np.pi, points)) * 4200
    packets_per_sec = np.clip(84200 + base_wave + rng.normal(0, 850, points), 71000, 97800).round(0)
    anomaly_score = np.clip(0.03 + np.abs(rng.normal(0, 0.01, points)), 0.01, 0.10)
    spike_indices = [15, 16, 17]
    spike_values = [0.62, 0.79, 0.68]
    for idx, value in zip(spike_indices, spike_values):
        anomaly_score[idx] = value

    classification_stream = pd.DataFrame(
        [
            {
                "time": "14:32:05.112",
                "flow_id": "f-82491",
                "src_dst": "192.168.1.105→10.0.0.1",
                "proto": "TCP",
                "pid": 38142,
                "exe": "/tmp/.x/hulk",
                "score": 0.97,
                "classification": "DDoS",
                "model": "eBPF",
            },
            {
                "time": "14:32:04.891",
                "flow_id": "f-82490",
                "src_dst": "10.0.0.22→8.8.8.8",
                "proto": "UDP",
                "pid": 1102,
                "exe": "systemd-resolve",
                "score": 0.04,
                "classification": "BENIGN",
                "model": "eBPF",
            },
            {
                "time": "14:32:04.440",
                "flow_id": "f-82489",
                "src_dst": "10.0.0.42→10.0.0.1",
                "proto": "TCP",
                "pid": 29811,
                "exe": "nmap",
                "score": 0.79,
                "classification": "Port Scan",
                "model": "eBPF",
            },
            {
                "time": "14:32:03.201",
                "flow_id": "f-82488",
                "src_dst": "10.0.1.15→10.0.0.1",
                "proto": "TCP",
                "pid": 44022,
                "exe": "hydra",
                "score": 0.94,
                "classification": "Brute Force",
                "model": "eBPF",
            },
            {
                "time": "14:32:02.011",
                "flow_id": "f-82487",
                "src_dst": "172.16.0.8→10.0.0.1",
                "proto": "TCP",
                "pid": 51200,
                "exe": "python3",
                "score": 0.31,
                "classification": "BENIGN",
                "model": "BASE",
            },
            {
                "time": "14:32:01.742",
                "flow_id": "f-82486",
                "src_dst": "192.168.0.91→10.0.0.1",
                "proto": "TCP",
                "pid": 21202,
                "exe": "curl",
                "score": 0.18,
                "classification": "BENIGN",
                "model": "BASE",
            },
            {
                "time": "14:32:01.301",
                "flow_id": "f-82485",
                "src_dst": "10.2.0.14→10.0.0.1",
                "proto": "TCP",
                "pid": 40212,
                "exe": "masscan",
                "score": 0.91,
                "classification": "Critical",
                "model": "eBPF",
            },
        ]
    )

    return {
        "research_notice": "This is a research prototype - NOT a production IDS. Do not rely on alerts for security decisions.",
        "safe_mode": "ON",
        "controls": {
            "interfaces": ["eth0 + eth1", "eth0", "eth1", "lo"],
            "thresholds": ["0.30", "0.50", "0.70", "0.90"],
            "default_interface": "eth0 + eth1",
            "default_threshold": "0.50",
        },
        "kpis": [
            {"label": "PACKETS / SEC", "value": "84.2k", "delta": "↑ eth0 + eth1", "color": COLORS["cyan"]},
            {"label": "ANOMALY RATE", "value": "2.8%", "delta": "Above 2% threshold", "color": COLORS["red"]},
            {"label": "AVG LATENCY", "value": "18ms", "delta": "eBPF classification", "color": COLORS["green"]},
            {"label": "EBPF EVENTS/S", "value": "124k", "delta": "4 active probes", "color": COLORS["amber"]},
        ],
        "timeseries": pd.DataFrame(
            {
                "time": timeline.to_pydatetime().tolist(),
                "packets_per_sec": packets_per_sec.tolist(),
                "anomaly_score": anomaly_score.round(3).tolist(),
                "is_alert": [idx in spike_indices for idx in range(points)],
            }
        ),
        "classification_stream": classification_stream,
    }

@st.cache_data(show_spinner=False)
def get_compare_models_snapshot() -> dict[str, Any]:
    frame = get_reports_frame()
    selection_path = _reports_dir() / "model_selection_split2_seed42.csv"
    if selection_path.exists():
        comparison = pd.read_csv(selection_path)
    else:
        comparison = pd.DataFrame(
            [
                {"split": "split2_balanced_quota", "feature_set": "baseline", "model": "rf_balanced", "val_auc": 0.998, "val_f1": 0.985},
                {"split": "split2_balanced_quota", "feature_set": "ebpf", "model": "hgb_balanced", "val_auc": 0.999, "val_f1": 0.990},
            ]
        )

    top_runs = frame.groupby(["feature_set", "model"], as_index=False)[["test_auc", "test_f1"]].max() if not frame.empty else pd.DataFrame()
    return {"selection": comparison, "top_runs": top_runs}

@st.cache_data(show_spinner=False)
def get_attack_breakdown() -> pd.DataFrame:
    path = _reports_dir() / "per_attack_delta_best_model_seed42.csv"
    if path.exists():
        frame = pd.read_csv(path)
    else:
        frame = pd.DataFrame(
            {
                "attack": ["PortScan", "DDoS", "Bot"],
                "n": [159109, 86636, 2208],
                "detected": [158946, 86636, 2206],
                "detection_rate_baseline": [0.9988, 0.9999, 0.9991],
                "detection_rate_ebpf": [0.9990, 1.0, 0.9991],
                "delta": [0.0002, 0.0001, 0.0],
            }
        )

    if "attack" not in frame.columns:
        return pd.DataFrame(columns=["attack", "n", "detected", "detection_rate_baseline", "detection_rate_ebpf", "delta"])

    seen = set(frame["attack"].astype(str))
    missing = [attack for attack in ATTACK_TYPES if attack not in seen]
    if missing:
        filler = pd.DataFrame(
            {
                "attack": missing,
                "n": [0] * len(missing),
                "detected": [0] * len(missing),
                "detection_rate_baseline": [0.0] * len(missing),
                "detection_rate_ebpf": [0.0] * len(missing),
                "delta": [0.0] * len(missing),
            }
        )
        frame = pd.concat([frame, filler], ignore_index=True)

    return frame.sort_values("delta", ascending=False).reset_index(drop=True)

@st.cache_data(show_spinner=False)
def get_explainability_snapshot() -> dict[str, Any]:
    reports = load_real_reports()
    ranked: list[dict[str, Any]] = []
    for report in reports:
        for item in report.get("feature_importance", []):
            ranked.append(
                {
                    "run_name": report.get("run_name", "unknown"),
                    "feature_set": _coerce_feature_set(str(report.get("run_name", ""))),
                    "feature": item.get("feature", "unknown"),
                    "importance": float(item.get("importance", 0.0) or 0.0),
                }
            )

    frame = pd.DataFrame(ranked)
    if frame.empty:
        frame = pd.DataFrame(
            {
                "run_name": ["ebpf_rf_split2_seed42"] * 6,
                "feature_set": ["ebpf"] * 6,
                "feature": EBPF_FEATURES[:3] + PACKET_FEATURES[:3],
                "importance": [0.21, 0.18, 0.15, 0.14, 0.11, 0.09],
            }
        )

    summary = (
        frame.groupby("feature", as_index=False)["importance"]
        .mean()
        .sort_values("importance", ascending=False)
        .head(12)
        .reset_index(drop=True)
    )
    summary["kind"] = summary["feature"].apply(lambda value: "eBPF" if value in EBPF_FEATURES else "Packet")

    return {"feature_importance": frame, "top_features": summary}

@st.cache_data(show_spinner=False)
def get_cost_performance_snapshot() -> dict[str, Any]:
    path = _reports_dir() / "compute_benchmark_best_model_seed42.json"
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
    else:
        payload = {
            "baseline": {
                "mean_latency_s": 2.32,
                "std_latency_s": 0.03,
                "per_sample_ms": 0.00425,
                "peak_memory_mb": 50.0,
                "n_samples": 546207,
            },
            "ebpf": {
                "mean_latency_s": 2.03,
                "std_latency_s": 0.01,
                "per_sample_ms": 0.00371,
                "peak_memory_mb": 79.2,
                "n_samples": 546207,
            },
        }

    benchmark = pd.DataFrame(payload).T.reset_index().rename(columns={"index": "feature_set"})
    benchmark["latency_gain_pct"] = (
        (benchmark["mean_latency_s"].iloc[0] - benchmark["mean_latency_s"]) / benchmark["mean_latency_s"].iloc[0] * 100.0
    )

    summary = {
        "baseline_latency_s": float(benchmark.loc[benchmark["feature_set"] == "baseline", "mean_latency_s"].iloc[0]),
        "ebpf_latency_s": float(benchmark.loc[benchmark["feature_set"] == "ebpf", "mean_latency_s"].iloc[0]),
        "latency_gain_pct": float(benchmark.loc[benchmark["feature_set"] == "ebpf", "latency_gain_pct"].iloc[0]),
        "memory_delta_mb": float(
            benchmark.loc[benchmark["feature_set"] == "ebpf", "peak_memory_mb"].iloc[0]
            - benchmark.loc[benchmark["feature_set"] == "baseline", "peak_memory_mb"].iloc[0]
        ),
    }
    return {"benchmark": benchmark, "summary": summary}

@st.cache_data(show_spinner=False)
def get_runs_snapshot() -> dict[str, Any]:
    frame = get_reports_frame().copy()
    if frame.empty:
        return {"runs": frame, "latest_timestamp": None}

    frame["status"] = np.where(frame["selection_score"] > frame["selection_score"].median(), "Candidate", "Archived")
    latest_timestamp = frame["timestamp"].dropna().max()
    return {"runs": frame.sort_values("timestamp", ascending=False), "latest_timestamp": latest_timestamp}

@st.cache_data(show_spinner=False)
def get_model_testing_snapshot() -> dict[str, Any]:
    generalization_path = _reports_dir() / "generalization_comparison_seed42.csv"
    robustness_path = _reports_dir() / "robustness_split5_metadata_seed42.csv"

    if generalization_path.exists():
        generalization = pd.read_csv(generalization_path)
    else:
        generalization = pd.DataFrame(
            {
                "feature_set": ["baseline", "ebpf"],
                "model": ["hgb_balanced", "hgb_balanced"],
                "split": ["split4_realistic", "split4_realistic"],
                "role": ["headline_generalization", "headline_generalization"],
                "test_f1": [0.511, 0.514],
                "test_auc": [0.920, 0.712],
            }
        )

    if robustness_path.exists():
        robustness = pd.read_csv(robustness_path)
    else:
        robustness = pd.DataFrame(
            {
                "feature_set": ["baseline", "ebpf"],
                "n_folds": [15, 15],
                "mean_train_rows": [1692188.8, 1692188.8],
                "mean_test_rows": [423047.2, 423047.2],
                "mean_test_attacks": [89471.6, 89471.6],
                "folds_with_unseen_families": [9, 9],
            }
        )

    return {"generalization": generalization, "robustness": robustness}

@st.cache_data(show_spinner=False)
def get_dataset_explorer_snapshot(sample_size: int = 1500) -> dict[str, Any]:
    rng = _deterministic_rng(21)
    attack_frame = get_attack_breakdown()

    sample_size = max(sample_size, 250)
    labels = rng.choice(["Benign"] + ATTACK_TYPES, size=sample_size, p=[0.62] + [0.38 / len(ATTACK_TYPES)] * len(ATTACK_TYPES))
    duration = np.clip(rng.lognormal(mean=1.8, sigma=0.75, size=sample_size), 0, 900)
    orig_bytes = np.clip(rng.lognormal(mean=7.2, sigma=1.05, size=sample_size), 40, 2_500_000)
    ebpf_pkt_rate = np.clip(rng.lognormal(mean=6.0, sigma=0.9, size=sample_size), 20, 150_000)

    sample = pd.DataFrame(
        {
            "label": labels,
            "duration": duration,
            "orig_bytes": orig_bytes,
            "ebpf_pkt_rate": ebpf_pkt_rate,
            "src_port": rng.integers(1024, 65535, size=sample_size),
            "dst_port": rng.choice([22, 53, 80, 123, 443, 8080], size=sample_size),
        }
    )

    dataset_summary = pd.DataFrame(
        {
            "feature_group": ["Packet", "eBPF", "Combined"],
            "feature_count": [len(PACKET_FEATURES), len(EBPF_FEATURES), len(PACKET_FEATURES) + len(EBPF_FEATURES)],
            "rows": [546207, 546207, 546207],
        }
    )

    label_distribution = (
        attack_frame[["attack", "n"]].rename(columns={"attack": "label", "n": "count"}).sort_values("count", ascending=False)
    )
    return {"sample": sample, "summary": dataset_summary, "label_distribution": label_distribution}

@st.cache_data(show_spinner=False)
def get_feature_catalog() -> pd.DataFrame:
    rows = [{"feature": feature, "group": "Packet"} for feature in PACKET_FEATURES]
    rows.extend({"feature": feature, "group": "eBPF"} for feature in EBPF_FEATURES)
    return pd.DataFrame(rows)


__all__ = [
    "ATTACK_TYPES",
    "PACKET_FEATURES",
    "EBPF_FEATURES",
    "load_real_reports",
    "get_reports_frame",
    "get_available_runs",
    "get_model_summary_table",
    "get_dashboard_snapshot",
    "get_dashboard_kpis",
    "get_dashboard_alerts",
    "get_threat_distribution_snapshot",
    "get_live_event_stream",
    "get_protocol_breakdown_snapshot",
    "get_probe_status_snapshot",
    "get_live_monitor_snapshot",
    "get_live_monitor_page_snapshot",
    "get_compare_models_snapshot",
    "get_attack_breakdown",
    "get_explainability_snapshot",
    "get_cost_performance_snapshot",
    "get_runs_snapshot",
    "get_model_testing_snapshot",
    "get_dataset_explorer_snapshot",
    "get_feature_catalog",
]
