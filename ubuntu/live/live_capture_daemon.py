#!/usr/bin/env python3

import argparse
import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer

# Import merge helpers in-process to avoid Python+pandas startup overhead on every poll cycle.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "data_collection"))
from merge_zeek_ebpf import _process_ebpf_rows, load_zeek_conn, run_merge  # noqa: E402

# Maps output column names to their dotted keys in Zeek JSON.
_ZEEK_JSON_FIELDS: dict[str, str] = {
    "ts": "ts", "orig_h": "id.orig_h", "resp_h": "id.resp_h",
    "orig_p": "id.orig_p", "resp_p": "id.resp_p", "proto": "proto",
    "duration": "duration", "orig_bytes": "orig_bytes", "resp_bytes": "resp_bytes",
    "orig_pkts": "orig_pkts", "resp_pkts": "resp_pkts", "conn_state": "conn_state",
}

def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()

def repo_root() -> Path:
    """Return the repository root (three directories above this file)."""
    return Path(__file__).resolve().parent.parent.parent

REPO = repo_root()
RUNTIME_DIR = REPO / "data" / "runtime"
STATE_PATH = RUNTIME_DIR / "live_capture_state.json"
DAEMON_LOG = RUNTIME_DIR / "live_capture_daemon.log"

def write_json_atomic(path: Path, payload: dict) -> None:
    """Write payload as JSON to a temp file then rename it atomically so readers never see a partial write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)

def append_log(line: str) -> None:
    """Append a timestamped line to the daemon log file."""
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    with DAEMON_LOG.open("a", encoding="utf-8") as fh:
        fh.write(f"{utc_now()} {line.rstrip()}\n")

def info(line: str) -> None:
    """Print a line to stdout and append it to the daemon log."""
    print(line, flush=True)
    append_log(line)

def require_root() -> None:
    """Abort with an error message if the process is not running as root."""
    if os.geteuid() != 0:
        raise SystemExit("run this program as root (for Zeek live capture and eBPF attach)")

def require_cmd(name: str) -> None:
    """Raise RuntimeError if a required external command is not found on PATH."""
    if shutil.which(name) is None:
        raise RuntimeError(f"required command not found on PATH: {name}")

def count_lines(path: Path) -> int:
    """Count non-empty lines in a file, returning 0 if the file does not exist."""
    if not path.exists():
        return 0
    n = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                n += 1
    return n

def run_sync(cmd: list[str], log_path: Path, *, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    """Run a command synchronously, logging its stdout and stderr to log_path."""
    with log_path.open("a", encoding="utf-8") as log_fh:
        log_fh.write(f"\n[{utc_now()}] RUN {' '.join(cmd)}\n")
        log_fh.flush()
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

def stop_process(proc: Optional[subprocess.Popen[str]], name: str, timeout_s: float = 8.0) -> None:
    """Gracefully stop a subprocess: SIGINT first, then SIGTERM, then SIGKILL if it won't exit."""
    if proc is None or proc.poll() is not None:
        return
    append_log(f"stopping {name} pid={proc.pid}")
    proc.send_signal(signal.SIGINT)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.2)
    proc.terminate()
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.2)
    proc.kill()

@dataclass
class LivePaths:
    run_dir: Path
    zeek_dir: Path
    zeek_log: Path
    netmon_log: Path
    merge_log: Path
    zeek_conn_log: Path
    zeek_conn_csv: Path
    ebpf_agg: Path
    ebpf_events: Path
    scored_events: Path
    merged_csv: Path
    run_meta: Path


PROTO_MAP = {"tcp": 6.0, "udp": 17.0, "icmp": 1.0}

# Maximum eBPF flow entries kept in memory.
# SYN floods can produce 600k+ entries per cycle; capping here prevents unbounded DataFrame growth.
# Oldest entries are evicted first.
_MAX_EBPF_CACHE = 50_000

# Models were trained on CICIDS2017 replay data whose feature ranges differ from live traffic.
# Scale replay-calibrated thresholds down by this factor for live capture.
_DEFAULT_THRESHOLD_MULTIPLIER = float(os.environ.get("SCORE_THRESHOLD_MULTIPLIER", "0.1"))


class LiveScorer:
    def __init__(self, repo: Path, paths: LivePaths,
                 threshold_multiplier: float = _DEFAULT_THRESHOLD_MULTIPLIER):
        self.repo = repo
        self.paths = paths
        self.threshold_multiplier = threshold_multiplier
        self.last_scored_rows = 0
        self.enabled = False
        self.message = "live scoring unavailable"
        self.baseline_pack: dict | None = None
        self.ebpf_pack: dict | None = None
        self._load_models()

    def _load_pack(self, name: str) -> dict:
        """Load a headline model pack by name and scale its threshold down for live traffic."""
        path = self.repo / "data" / "models" / f"{name}_headline_model_seed104.joblib"
        if not path.exists():
            raise FileNotFoundError(path)
        pack = joblib.load(path)
        model = pack.get("model")
        features = pack.get("features")
        if model is None or not isinstance(features, list) or not features:
            raise RuntimeError(f"invalid model pack: {path}")
        self._repair_model_compat(model)
        raw_threshold = float(pack.get("threshold", 0.5))
        # Models were trained on compressed PCAP replay; live traffic scores are lower, so the threshold is scaled down.
        live_threshold = raw_threshold * self.threshold_multiplier
        return {
            "path": path,
            "model": model,
            "features": features,
            "threshold": live_threshold,
            "threshold_replay": raw_threshold,
        }

    def _repair_model_compat(self, obj: object) -> None:
        """Fix missing dtype attributes on SimpleImputer when loading models across sklearn versions."""
        if isinstance(obj, SimpleImputer):
            dtype = getattr(obj, "_fit_dtype", None) or getattr(obj, "_fill_dtype", None)
            if dtype is None and hasattr(obj, "statistics_"):
                dtype = getattr(obj.statistics_, "dtype", None)
            if dtype is not None:
                dtype = np.dtype(dtype)
                obj._fit_dtype = dtype
                obj._fill_dtype = dtype
        steps = getattr(obj, "steps", None)
        if steps:
            for _, step in steps:
                self._repair_model_compat(step)
        named_transformers = getattr(obj, "named_transformers_", None)
        if named_transformers:
            for step in named_transformers.values():
                self._repair_model_compat(step)
        transformer_list = getattr(obj, "transformers", None)
        if transformer_list:
            for _, step, _ in transformer_list:
                if step not in {"drop", "passthrough"}:
                    self._repair_model_compat(step)

    def _load_models(self) -> None:
        """Attempt to load baseline and eBPF model packs; disable scoring if either is unavailable."""
        try:
            self.baseline_pack = self._load_pack("baseline")
            self.ebpf_pack = self._load_pack("ebpf")
            self.enabled = True
            self.message = "baseline + ebpf models loaded"
        except Exception as exc:
            self.enabled = False
            self.message = f"live scoring disabled: {exc}"

    def state_extra(self) -> dict:
        """Return scoring-related fields to be merged into the daemon state JSON."""
        payload = {
            "scoring_enabled": self.enabled,
            "scoring_message": self.message,
        }
        if self.baseline_pack is not None:
            payload["baseline_threshold"] = self.baseline_pack["threshold"]
        if self.ebpf_pack is not None:
            payload["ebpf_threshold"] = self.ebpf_pack["threshold"]
        return payload

    def _resolve_exe(self, pid: int, comm: str) -> str:
        """Resolve the full exe path via /proc/<pid>/exe. Falls back to comm if the process is gone."""
        if pid <= 0:
            return comm
        try:
            exe_link = Path(f"/proc/{pid}/exe")
            if exe_link.is_symlink():
                resolved = os.readlink(str(exe_link))
                return resolved if resolved else comm
        except (PermissionError, OSError):
            pass
        return comm

    def _coerce_numeric(self, series: pd.Series, default: float = 0.0) -> pd.Series:
        """Convert a Series to float, filling any non-numeric values with default."""
        return pd.to_numeric(series, errors="coerce").fillna(default).astype(float)

    def _series_or_default(self, frame: pd.DataFrame, column: str, default: object) -> pd.Series:
        """Return frame[column] if the column exists, otherwise a constant-value Series."""
        if column in frame.columns:
            return frame[column]
        return pd.Series([default] * len(frame), index=frame.index)

    def _scalar_int(self, value: object) -> int:
        """Coerce a single value to int, returning 0 for NaN or non-numeric input."""
        num = pd.to_numeric(pd.Series([value]), errors="coerce").iloc[0]
        if pd.isna(num):
            return 0
        return int(num)

    def _scalar_float(self, value: object) -> float:
        """Coerce a single value to float, returning 0.0 for NaN or non-numeric input."""
        num = pd.to_numeric(pd.Series([value]), errors="coerce").iloc[0]
        if pd.isna(num):
            return 0.0
        return float(num)

    def _build_features(self, frame: pd.DataFrame, features: list[str]) -> pd.DataFrame:
        """Derive and align all model input features from a merged flow DataFrame."""
        df = frame.copy()
        df["duration"]   = self._coerce_numeric(df.get("duration", 0.0))
        df["orig_p"]     = self._coerce_numeric(df.get("orig_p", 0.0))
        df["resp_p"]     = self._coerce_numeric(df.get("resp_p", 0.0))
        df["orig_bytes"] = self._coerce_numeric(df.get("orig_bytes", 0.0))
        df["resp_bytes"] = self._coerce_numeric(df.get("resp_bytes", 0.0))
        df["orig_pkts"]  = self._coerce_numeric(df.get("orig_pkts", 0.0))
        df["resp_pkts"]  = self._coerce_numeric(df.get("resp_pkts", 0.0))
        df["src_port"]   = self._coerce_numeric(df.get("orig_p", 0.0))
        df["dst_port"]   = self._coerce_numeric(df.get("resp_p", 0.0))
        proto_series = self._series_or_default(df, "proto", "").astype(str).str.lower()
        df["proto_i"] = proto_series.map(PROTO_MAP).fillna(self._coerce_numeric(proto_series, 0.0))
        for col in [
            "ebpf_bytes_sent", "ebpf_bytes_recv", "ebpf_retransmits",
            "ebpf_state_changes", "ebpf_samples", "ebpf_pid", "ebpf_uid",
        ]:
            df[col] = self._coerce_numeric(df.get(col, 0.0))
        for feature in features:
            if feature not in df.columns:
                df[feature] = 0.0
        return df[features].copy().astype(float)

    def _predict(self, frame: pd.DataFrame, pack: dict) -> tuple[np.ndarray, np.ndarray]:
        """Run a model pack against frame and return (score_array, binary_pred_array)."""
        X = self._build_features(frame, pack["features"])
        model = pack["model"]
        try:
            if hasattr(model, "predict_proba"):
                score = model.predict_proba(X)[:, 1]
            else:
                raw = model.decision_function(X)
                score = (raw - np.min(raw)) / (np.max(raw) - np.min(raw) + 1e-12)
        except AttributeError:
            self._repair_model_compat(model)
            if hasattr(model, "predict_proba"):
                score = model.predict_proba(X)[:, 1]
            else:
                raw = model.decision_function(X)
                score = (raw - np.min(raw)) / (np.max(raw) - np.min(raw) + 1e-12)
        threshold = float(pack["threshold"])
        pred = (score >= threshold).astype(int)
        return score, pred

    def score_new_rows(self, *, force_reset: bool = False) -> bool:
        """Score only the rows added to merged.csv since the last call and append results to scored_events.jsonl."""
        if not self.enabled or not self.paths.merged_csv.exists():
            return False

        merged = pd.read_csv(self.paths.merged_csv)
        total_rows = len(merged)
        if total_rows == 0:
            return False

        mode = "a"
        start_idx = self.last_scored_rows
        if force_reset or total_rows < self.last_scored_rows:
            start_idx = 0
            mode = "w"

        if total_rows <= start_idx:
            return False

        new_rows = merged.iloc[start_idx:].copy()
        self.last_scored_rows = total_rows

        # Drop multicast/broadcast destinations; the models were not trained on them and they produce false ATTACK labels.
        dst_str = new_rows.get("resp_h", pd.Series(dtype=str)).astype(str)
        noise_mask = dst_str.str.match(
            r"^(2(?:2[4-9]|3\d)\.|255\.255\.255\.255|[Ff][Ff][0-9a-fA-F]{2}:)"
        )
        new_rows = new_rows[~noise_mask].reset_index(drop=True)
        if new_rows.empty:
            return False

        baseline_score, baseline_pred = self._predict(new_rows, self.baseline_pack)
        ebpf_score, ebpf_pred = self._predict(new_rows, self.ebpf_pack)
        ts_series = self._coerce_numeric(self._series_or_default(new_rows, "ts", time.time()), time.time())

        records: list[dict] = []
        for idx, row in new_rows.reset_index(drop=True).iterrows():
            pid = self._scalar_int(row.get("ebpf_pid", 0))
            raw_comm = row.get("ebpf_comm", "")
            comm = "" if str(raw_comm).lower() in ("nan", "none", "") else str(raw_comm)
            exe = self._resolve_exe(pid, comm)
            records.append({
                "ts_s": float(ts_series.iloc[idx]),
                "src_ip": str(row.get("orig_h", "")),
                "dst_ip": str(row.get("resp_h", "")),
                "src_port": self._scalar_int(row.get("orig_p", 0)),
                "dst_port": self._scalar_int(row.get("resp_p", 0)),
                "proto": str(row.get("proto", "")),
                "pid": pid,
                "uid": self._scalar_int(row.get("ebpf_uid", 0)),
                "exe": exe,
                "duration": self._scalar_float(row.get("duration", 0.0)),
                "baseline_score": float(baseline_score[idx]),
                "baseline_threshold": float(self.baseline_pack["threshold"]),
                "baseline_pred": int(baseline_pred[idx]),
                "ebpf_score": float(ebpf_score[idx]),
                "ebpf_threshold": float(self.ebpf_pack["threshold"]),
                "ebpf_pred": int(ebpf_pred[idx]),
                "anomaly_score": float(ebpf_score[idx]),
                "label": "ATTACK" if int(ebpf_pred[idx]) else "BENIGN",
            })

        self.paths.scored_events.parent.mkdir(parents=True, exist_ok=True)
        with self.paths.scored_events.open(mode, encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record) + "\n")
            fh.flush()  # ensure the UI can read complete lines promptly

        self.message = f"live scoring active ({self.last_scored_rows} flow rows scored)"
        return True

class LiveCaptureDaemon:
    def __init__(self, iface: str, flush_secs: int, poll_secs: float, mode: str,
                 disable_kprobes: bool, threshold_multiplier: float = _DEFAULT_THRESHOLD_MULTIPLIER):
        """Set up all run paths, incremental reader state, and the LiveScorer for this capture session."""
        self.iface = iface
        self.flush_secs = flush_secs
        self.poll_secs = poll_secs
        self.mode = mode
        self.disable_kprobes = disable_kprobes
        self._threshold_multiplier = threshold_multiplier

        run_ts = datetime.now().strftime("%F_%H%M%S")
        run_dir = REPO / "data" / "runs" / f"live_{run_ts}"
        self.paths = LivePaths(
            run_dir=run_dir,
            zeek_dir=run_dir / "zeek",
            zeek_log=run_dir / "zeek.log",
            netmon_log=run_dir / "netmon.log",
            merge_log=run_dir / "merge.log",
            zeek_conn_log=run_dir / "zeek" / "conn.log",
            zeek_conn_csv=run_dir / "zeek" / "conn.csv",
            ebpf_agg=run_dir / "ebpf_agg.jsonl",
            ebpf_events=run_dir / "ebpf_events.jsonl",
            scored_events=run_dir / "scored_events.jsonl",
            merged_csv=run_dir / "merged.csv",
            run_meta=run_dir / "run_meta.json",
        )
        self.paths.zeek_dir.mkdir(parents=True, exist_ok=True)
        self.started_at = utc_now()
        self.stop_requested = False
        self.netmon_proc: Optional[subprocess.Popen[str]] = None
        self.zeek_proc: Optional[subprocess.Popen[str]] = None
        self.last_conn_log_mtime_ns = -1
        self.last_agg_mtime_ns = -1
        self.last_conn_csv_mtime_ns = -1
        self.last_convert_ok = False
        self.last_merge_ok = False

        # Incremental eBPF reader state.
        # _ebpf_cache_df holds the accumulated deduplicated DataFrame.
        # _ebpf_cache_offset is the byte position in ebpf_agg.jsonl read so far.
        self._ebpf_cache_df: pd.DataFrame = pd.DataFrame()
        self._ebpf_cache_offset: int = 0
        self._ebpf_line_count: int = 0

        # Incremental Zeek conn.log reader state.
        # _zeek_csv_rows_merged tracks how many conn.csv 
        # rows have been merged so each poll only processes newly appended rows.
        self._zeek_log_offset: int = 0
        self._zeek_csv_rows: int = 0
        self._zeek_csv_rows_merged: int = 0

        self.scorer = LiveScorer(REPO, self.paths, threshold_multiplier=self._threshold_multiplier)

    def write_state(self, status: str, message: str, **extra: object) -> None:
        """Write the current daemon status, counters, and paths atomically to the shared state JSON file."""
        payload = {
            "status": status,
            "interface": self.iface,
            "pid": os.getpid(),
            "started_at": self.started_at,
            "updated_at": utc_now(),
            "run_dir": str(self.paths.run_dir),
            "message": message,
            "zeek_conn_path": str(self.paths.zeek_conn_csv),
            "ebpf_agg_path": str(self.paths.ebpf_agg),
            "ebpf_events_path": str(self.paths.ebpf_events),
            "scored_events_path": str(self.paths.scored_events),
            "merged_path": str(self.paths.merged_csv),
            "zeek_flow_count": self._zeek_csv_rows,
            "merged_flow_count": self._zeek_csv_rows_merged,
            "ebpf_flow_count": self._ebpf_line_count,
            "scored_flow_count": count_lines(self.paths.scored_events),
            "mode": self.mode,
            "flush_secs": self.flush_secs,
            "poll_secs": self.poll_secs,
        }
        payload.update(self.scorer.state_extra())
        payload.update(extra)
        write_json_atomic(STATE_PATH, payload)

    def build_netmon(self) -> tuple[Path, Path]:
        """Run make in ebpf_core and return paths to the compiled netmon binary and BPF object."""
        info("Building ebpf_core")
        res = run_sync(["make", "-C", str(REPO / "ebpf_core")], self.paths.netmon_log)
        if res.returncode != 0:
            raise RuntimeError("failed to build ebpf_core; check netmon.log")

        bin_path = REPO / "ebpf_core" / "bin" / "netmon"
        obj_path = REPO / "ebpf_core" / "bin" / "netmon.bpf.o"
        if not bin_path.exists():
            legacy = REPO / "ebpf_core" / "netmon"
            if legacy.exists():
                bin_path = legacy
        if not obj_path.exists():
            legacy = REPO / "ebpf_core" / "netmon.bpf.o"
            if legacy.exists():
                obj_path = legacy
        if not bin_path.exists() or not obj_path.exists():
            raise RuntimeError("netmon build completed but expected binary/object were not found")
        return bin_path, obj_path

    def start_zeek(self) -> None:
        """Start a Zeek live capture process on the configured interface with JSON output enabled."""
        # Reduce inactivity timeout from the 5 min default so that 
        # long-lived or flood connections appear in conn.log well within 
        # a minute of the last packet.
        tuning = self.paths.zeek_dir / "netsentinel_tuning.zeek"
        tuning.write_text(
            "redef tcp_inactivity_timeout = 60 secs;\n",
            encoding="utf-8",
        )
        cmd = ["zeek", "-i", self.iface, "LogAscii::use_json=T", "netsentinel_tuning.zeek"]
        info(f"Starting Zeek on {self.iface}")
        append_log(f"starting zeek: {' '.join(cmd)}")
        zeek_fh = self.paths.zeek_log.open("a", encoding="utf-8")
        self.zeek_proc = subprocess.Popen(
            cmd,
            cwd=str(self.paths.zeek_dir),
            stdout=zeek_fh,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )

    def start_netmon(self, bin_path: Path, obj_path: Path) -> None:
        """Launch the netmon eBPF collector as a background process on the configured interface."""
        cmd = [
            str(bin_path),
            "-obj", str(obj_path),
            "-out", str(self.paths.ebpf_agg),
            "-events", str(self.paths.ebpf_events),
            "-flush", str(self.flush_secs),
            "-mode", self.mode,
            "-pkt_iface", self.iface,
            "-meta", str(self.paths.run_meta),
        ]
        if self.disable_kprobes:
            cmd.append("-disable_kprobes")

        info(f"Starting netmon on {self.iface}")
        append_log(f"starting netmon: {' '.join(cmd)}")
        netmon_fh = self.paths.netmon_log.open("a", encoding="utf-8")
        self.netmon_proc = subprocess.Popen(
            cmd,
            cwd=str(REPO),
            stdout=netmon_fh,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )

    def _load_ebpf_incremental(self) -> pd.DataFrame:
        """
        Read only newly-appended lines from ebpf_agg.jsonl each poll cycle.

        Maintains an accumulated deduplicated DataFrame so that a SYN flood only incurs full-file I/O on the first read; 
        subsequent polls parse only the delta.
        """
        if not self.paths.ebpf_agg.exists():
            return self._ebpf_cache_df

        try:
            file_size = self.paths.ebpf_agg.stat().st_size
        except OSError:
            return self._ebpf_cache_df

        if file_size < self._ebpf_cache_offset:
            # File was truncated or replaced; reset state.
            self._ebpf_cache_df = pd.DataFrame()
            self._ebpf_cache_offset = 0
            self._ebpf_line_count = 0

        if file_size == self._ebpf_cache_offset:
            return self._ebpf_cache_df

        new_rows: list = []
        try:
            with self.paths.ebpf_agg.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._ebpf_cache_offset)
                for raw in fh:
                    stripped = raw.strip()
                    if stripped:
                        try:
                            new_rows.append(json.loads(stripped))
                        except json.JSONDecodeError:
                            pass
                self._ebpf_cache_offset = fh.tell()
        except OSError:
            return self._ebpf_cache_df

        if not new_rows:
            return self._ebpf_cache_df

        self._ebpf_line_count += len(new_rows)
        new_df = _process_ebpf_rows(new_rows)
        if new_df.empty:
            return self._ebpf_cache_df

        combined = new_df if self._ebpf_cache_df.empty else pd.concat([self._ebpf_cache_df, new_df], ignore_index=True)

        # Deduplicate by 5-tuple, keeping the entry with the most samples.
        # High-throughput flows (iperf3, SYN floods) can flush thousands of entries and cause a one-to-many join explosion in the merge step.
        key_cols = ["saddr_u32", "daddr_u32", "sport", "dport", "proto"]
        valid_keys = [c for c in key_cols if c in combined.columns]
        if valid_keys:
            if "samples" in combined.columns:
                combined = (combined
                            .sort_values("samples", ascending=False)
                            .drop_duplicates(subset=valid_keys, keep="first")
                            .reset_index(drop=True))
            else:
                combined = combined.drop_duplicates(subset=valid_keys, keep="first").reset_index(drop=True)

        # Evict oldest entries when the cache exceeds the cap.
        # A SYN flood with unique source ports bypasses 5-tuple dedup (all entries are distinct),
        # so we keep the most recent rows since those are the ones Zeek hasn't expired yet.
        if len(combined) > _MAX_EBPF_CACHE:
            ts_col = "last_ts_s" if "last_ts_s" in combined.columns else (
                "first_ts_s" if "first_ts_s" in combined.columns else None)
            if ts_col:
                combined = (combined
                            .sort_values(ts_col, ascending=False)
                            .iloc[:_MAX_EBPF_CACHE]
                            .reset_index(drop=True))
            else:
                combined = combined.iloc[-_MAX_EBPF_CACHE:].reset_index(drop=True)
            append_log(
                f"ebpf cache capped at {_MAX_EBPF_CACHE} rows "
                f"(total lines seen: {self._ebpf_line_count}); "
                "oldest entries evicted"
            )

        self._ebpf_cache_df = combined
        return self._ebpf_cache_df

    def _get_nested(self, obj: dict, dotted_path: str) -> object:
        """Resolve a key from a Zeek JSON record.

        Zeek JSON uses literal flat keys with dots (e.g. "id.orig_h"), not nested dicts.
        Try the full dotted path as a literal key first and fall back to nested traversal.
        """
        if dotted_path in obj:
            return obj[dotted_path]
        parts = dotted_path.split(".")
        cur: object = obj
        for p in parts:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
        return cur

    def refresh_zeek_csv(self, force: bool = False) -> bool:
        """Parse only newly-appended JSON lines from Zeek's conn.log.

        New rows are appended to conn.csv so each call is O(new_lines) rather than O(total_lines).
        """
        if not self.paths.zeek_conn_log.exists():
            return False
        stat = self.paths.zeek_conn_log.stat()
        if not force and stat.st_mtime_ns == self.last_conn_log_mtime_ns:
            return False

        if stat.st_size < self._zeek_log_offset or force:
            self._zeek_log_offset = 0
            self._zeek_csv_rows = 0
            self._zeek_csv_rows_merged = 0
            if self.paths.zeek_conn_csv.exists():
                self.paths.zeek_conn_csv.unlink()

        new_rows: list[dict] = []
        try:
            with self.paths.zeek_conn_log.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._zeek_log_offset)
                for raw in fh:
                    stripped = raw.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    try:
                        obj = json.loads(stripped)
                    except json.JSONDecodeError:
                        continue
                    row = {col: self._get_nested(obj, path)
                           for col, path in _ZEEK_JSON_FIELDS.items()}
                    if any(row[k] is None for k in ("ts", "orig_h", "resp_h")):
                        continue
                    new_rows.append(row)
                self._zeek_log_offset = fh.tell()
        except OSError as exc:
            append_log(f"zeek conn.log read error: {exc}")
            self.last_convert_ok = False
            return False

        if not new_rows:
            self.last_conn_log_mtime_ns = stat.st_mtime_ns
            self.last_convert_ok = True
            return False

        write_header = not self.paths.zeek_conn_csv.exists() or self._zeek_csv_rows == 0
        try:
            with self.paths.zeek_conn_csv.open("a", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(_ZEEK_JSON_FIELDS.keys()),
                                        extrasaction="ignore")
                if write_header:
                    writer.writeheader()
                writer.writerows(new_rows)
        except OSError as exc:
            append_log(f"zeek conn.csv write error: {exc}")
            self.last_convert_ok = False
            return False

        self._zeek_csv_rows += len(new_rows)
        self.last_conn_log_mtime_ns = stat.st_mtime_ns
        self.last_convert_ok = True
        return True

    def refresh_merged_csv(self, force: bool = False) -> bool:
        """Merge only new Zeek rows against the eBPF cache and append results.

        Both the merge computation and merged.csv writes are O(new_rows) per cycle
        regardless of how many total flows have accumulated.
        """
        if not self.paths.zeek_conn_csv.exists() or not self.paths.ebpf_agg.exists():
            return False
        agg_stat = self.paths.ebpf_agg.stat()
        conn_csv_mtime = self.paths.zeek_conn_csv.stat().st_mtime_ns

        new_zeek_count = self._zeek_csv_rows - self._zeek_csv_rows_merged
        ebpf_changed = agg_stat.st_mtime_ns != self.last_agg_mtime_ns

        if (not force
                and new_zeek_count <= 0
                and not ebpf_changed
                and self.paths.merged_csv.exists()):
            return False

        if new_zeek_count <= 0 and not force:
            self.last_agg_mtime_ns = agg_stat.st_mtime_ns
            return False

        ebpf_df = self._load_ebpf_incremental()

        try:
            zeek_all = load_zeek_conn(str(self.paths.zeek_conn_csv))
        except Exception as exc:
            append_log(f"zeek conn.csv load error: {exc}")
            self.last_merge_ok = False
            return False

        start_idx = self._zeek_csv_rows_merged if not force else 0
        new_zeek = zeek_all.iloc[start_idx:].copy()
        if new_zeek.empty:
            self.last_agg_mtime_ns = agg_stat.st_mtime_ns
            self.last_conn_csv_mtime_ns = conn_csv_mtime
            return False

        # Hold back flows younger than one eBPF flush cycle so the kprobe has time to
        # write its entry before the merge runs.
        # Without this, a short-lived flow gets scored with pid=0/exe="" because its eBPF entry hasn't appeared yet.
        ebpf_ready_cutoff = time.time() - float(self.flush_secs)
        if "ts" in new_zeek.columns:
            new_zeek = new_zeek[
                pd.to_numeric(new_zeek["ts"], errors="coerce").fillna(0) <= ebpf_ready_cutoff
            ]
        if new_zeek.empty:
            return False

        tmp_out = self.paths.merged_csv.with_suffix(".csv.tmp")
        try:
            run_merge(
                zeek_csv=None,
                zeek_df=new_zeek,
                ebpf_df=ebpf_df,
                out=str(tmp_out),
                time_slop=max(float(self.flush_secs) * 2.0, 5.0),
                run_meta=str(self.paths.run_meta),
            )
        except Exception as exc:
            append_log(f"in-process merge error: {exc}")
            self.last_merge_ok = False
            return False

        if not tmp_out.exists():
            self.last_merge_ok = False
            return False

        try:
            new_merged = pd.read_csv(str(tmp_out))
            tmp_out.unlink(missing_ok=True)
            write_header = not self.paths.merged_csv.exists() or start_idx == 0
            new_merged.to_csv(
                self.paths.merged_csv,
                mode="w" if write_header else "a",
                header=write_header,
                index=False,
            )
            self._zeek_csv_rows_merged = self._zeek_csv_rows
        except Exception as exc:
            append_log(f"merged.csv write error: {exc}")
            tmp_out.unlink(missing_ok=True)
            self.last_merge_ok = False
            return False

        self.last_agg_mtime_ns = agg_stat.st_mtime_ns
        self.last_conn_csv_mtime_ns = conn_csv_mtime
        self.last_merge_ok = True
        return True

    def check_children(self) -> None:
        """Raise RuntimeError if either child process has exited unexpectedly."""
        if self.zeek_proc and self.zeek_proc.poll() is not None:
            raise RuntimeError(f"zeek exited unexpectedly with code {self.zeek_proc.returncode}")
        if self.netmon_proc and self.netmon_proc.poll() is not None:
            raise RuntimeError(f"netmon exited unexpectedly with code {self.netmon_proc.returncode}")

    def setup_run_meta(self) -> None:
        """Write initial run_meta.json with mode, interface, and timestamp."""
        payload = {
            "mode": "live",
            "iface_capture": self.iface,
            "timestamp": datetime.now().strftime("%F_%H%M%S"),
            "run_dir": str(self.paths.run_dir),
        }
        write_json_atomic(self.paths.run_meta, payload)

    def run(self) -> int:
        """Start Zeek and netmon, then poll and refresh outputs until stopped."""
        self.setup_run_meta()
        self.write_state("starting", f"preparing live capture on {self.iface}")
        info(f"Live run folder: {self.paths.run_dir}")
        info(f"Runtime state file: {STATE_PATH}")
        bin_path, obj_path = self.build_netmon()
        self.start_zeek()
        self.start_netmon(bin_path, obj_path)

        # Touch scored_events immediately so the webapp never falls back to reading
        # raw ebpf_events.jsonl, which contains unscored host-wide traffic.
        self.paths.scored_events.parent.mkdir(parents=True, exist_ok=True)
        self.paths.scored_events.touch()

        self.write_state("running", f"live capture started on {self.iface}")
        info(f"Zeek flow output: {self.paths.zeek_conn_csv}")
        info(f"eBPF and Zeek flow output: {self.paths.merged_csv}")
        info(f"Raw eBPF events: {self.paths.ebpf_events}")
        info(f"Scored monitor events: {self.paths.scored_events}")
        info(self.scorer.message)
        info("Press Ctrl+C to stop")

        while not self.stop_requested:
            self.check_children()

            # Write a heartbeat before the blocking conversion steps so updated_at stays fresh even when run_sync() takes many seconds. 
            # The UI uses updated_at to detect a stalled daemon.
            self.write_state(
                "running",
                "capture running",
                zeek_pid=self.zeek_proc.pid if self.zeek_proc else None,
                netmon_pid=self.netmon_proc.pid if self.netmon_proc else None,
                convert_ok=self.last_convert_ok,
                merge_ok=self.last_merge_ok,
            )

            converted = self.refresh_zeek_csv()
            merged = self.refresh_merged_csv()
            scored = False
            if merged or (self.paths.merged_csv.exists() and self.scorer.last_scored_rows == 0):
                try:
                    scored = self.scorer.score_new_rows()
                except Exception as exc:
                    self.scorer.message = f"live scoring error: {exc}"

            if converted or merged:
                message = (
                    f"live outputs refreshed: zeek={self.paths.zeek_conn_csv.name} "
                    f"merged={self.paths.merged_csv.name if self.paths.merged_csv.exists() else 'pending'}"
                )
                if scored:
                    message += f" scored={self.paths.scored_events.name}"
            else:
                message = "capture running"

            self.write_state(
                "running",
                message,
                zeek_pid=self.zeek_proc.pid if self.zeek_proc else None,
                netmon_pid=self.netmon_proc.pid if self.netmon_proc else None,
                convert_ok=self.last_convert_ok,
                merge_ok=self.last_merge_ok,
            )
            time.sleep(self.poll_secs)

        return 0

    def stop(self) -> None:
        """Signal the main loop to stop at the next iteration."""
        self.stop_requested = True

    def finalize(self, status: str, message: str) -> None:
        """Stop child processes, flush final outputs, and write terminal state."""
        stop_process(self.netmon_proc, "netmon")
        stop_process(self.zeek_proc, "zeek")
        try:
            self.refresh_zeek_csv(force=True)
            self.refresh_merged_csv(force=True)
            self.scorer.score_new_rows(force_reset=True)
        except Exception as exc:
            append_log(f"final refresh failed: {exc}")
        self.write_state(status, message)
        info(message)


def install_signal_handlers(daemon: LiveCaptureDaemon) -> None:
    """Register SIGINT and SIGTERM handlers that call daemon.stop()."""
    def _handler(signum: int, _frame: object) -> None:
        append_log(f"received signal {signum}, shutting down")
        daemon.stop()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

def main() -> int:
    """CLI entry point. Parses arguments, builds the daemon, and runs until stopped."""
    ap = argparse.ArgumentParser(description="Run live Zeek + netmon capture and keep outputs refreshed")
    ap.add_argument("iface", help="network interface to capture")
    ap.add_argument("--flush-secs", type=int, default=int(os.environ.get("FLUSH_SECS", "5")))
    ap.add_argument("--poll-secs", type=float, default=float(os.environ.get("POLL_SECS", "3")))
    ap.add_argument("--mode", default=os.environ.get("MODE", "both"), choices=["flow", "event", "both"])
    ap.add_argument("--disable-kprobes", action="store_true", default=os.environ.get("DISABLE_KPROBES", "0") == "1")
    ap.add_argument("--score-threshold-multiplier", type=float,
                    default=_DEFAULT_THRESHOLD_MULTIPLIER,
                    help="scale model thresholds to compensate for CICIDS2017 to live-capture domain shift (default: %(default)s)")
    args = ap.parse_args()

    require_root()
    for cmd in ["zeek", "make"]:
        require_cmd(cmd)

    daemon = LiveCaptureDaemon(
        iface=args.iface,
        flush_secs=args.flush_secs,
        poll_secs=args.poll_secs,
        mode=args.mode,
        disable_kprobes=args.disable_kprobes,
        threshold_multiplier=args.score_threshold_multiplier,
    )
    install_signal_handlers(daemon)

    try:
        rc = daemon.run()
    except Exception as exc:
        append_log(f"fatal error: {exc}")
        daemon.finalize("error", str(exc))
        raise SystemExit(1) from exc

    daemon.finalize("stopped", "live capture stopped cleanly")
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
