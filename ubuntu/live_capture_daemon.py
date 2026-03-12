#!/usr/bin/env python3

import argparse
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

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent

REPO = repo_root()
RUNTIME_DIR = REPO / "data" / "runtime"
STATE_PATH = RUNTIME_DIR / "live_capture_state.json"
DAEMON_LOG = RUNTIME_DIR / "live_capture_daemon.log"

def write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)

def append_log(line: str) -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    with DAEMON_LOG.open("a", encoding="utf-8") as fh:
        fh.write(f"{utc_now()} {line.rstrip()}\n")

def info(line: str) -> None:
    print(line, flush=True)
    append_log(line)

def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("run this program as root (for Zeek live capture and eBPF attach)")

def require_cmd(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"required command not found on PATH: {name}")

def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                n += 1
    return n

def run_sync(cmd: list[str], log_path: Path, *, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
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
    merged_csv: Path
    run_meta: Path

class LiveCaptureDaemon:
    def __init__(self, iface: str, flush_secs: int, poll_secs: float, mode: str, disable_kprobes: bool):
        self.iface = iface
        self.flush_secs = flush_secs
        self.poll_secs = poll_secs
        self.mode = mode
        self.disable_kprobes = disable_kprobes

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
        self.last_convert_ok = False
        self.last_merge_ok = False

    def write_state(self, status: str, message: str, **extra: object) -> None:
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
            "merged_path": str(self.paths.merged_csv),
            "zeek_flow_count": count_lines(self.paths.zeek_conn_csv),
            "merged_flow_count": max(0, count_lines(self.paths.merged_csv) - (1 if self.paths.merged_csv.exists() else 0)),
            "ebpf_flow_count": count_lines(self.paths.ebpf_agg),
            "mode": self.mode,
            "flush_secs": self.flush_secs,
            "poll_secs": self.poll_secs,
        }
        payload.update(extra)
        write_json_atomic(STATE_PATH, payload)

    def build_netmon(self) -> tuple[Path, Path]:
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
        cmd = ["zeek", "-i", self.iface, "LogAscii::use_json=T"]
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

    def refresh_zeek_csv(self, force: bool = False) -> bool:
        if not self.paths.zeek_conn_log.exists():
            return False
        stat = self.paths.zeek_conn_log.stat()
        if not force and stat.st_mtime_ns == self.last_conn_log_mtime_ns:
            return False
        tmp_out = self.paths.zeek_conn_csv.with_suffix(".csv.tmp")
        res = run_sync(
            [
                sys.executable,
                str(REPO / "ubuntu" / "zeek_conn_to_csv.py"),
                "--in", str(self.paths.zeek_conn_log),
                "--out", str(tmp_out),
            ],
            self.paths.merge_log,
        )
        if res.returncode != 0 or not tmp_out.exists():
            self.last_convert_ok = False
            return False
        tmp_out.replace(self.paths.zeek_conn_csv)
        self.last_conn_log_mtime_ns = stat.st_mtime_ns
        self.last_convert_ok = True
        return True

    def refresh_merged_csv(self, force: bool = False) -> bool:
        if not self.paths.zeek_conn_csv.exists() or not self.paths.ebpf_agg.exists():
            return False
        agg_stat = self.paths.ebpf_agg.stat()
        if not force and agg_stat.st_mtime_ns == self.last_agg_mtime_ns and self.paths.merged_csv.exists():
            return False
        tmp_out = self.paths.merged_csv.with_suffix(".csv.tmp")
        res = run_sync(
            [
                sys.executable,
                str(REPO / "ubuntu" / "merge_zeek_ebpf.py"),
                "--zeek_conn", str(self.paths.zeek_conn_csv),
                "--ebpf_agg", str(self.paths.ebpf_agg),
                "--run_meta", str(self.paths.run_meta),
                "--out", str(tmp_out),
                "--time_slop", str(max(float(self.flush_secs) * 2.0, 5.0)),
            ],
            self.paths.merge_log,
        )
        if res.returncode != 0 or not tmp_out.exists():
            self.last_merge_ok = False
            return False
        tmp_out.replace(self.paths.merged_csv)
        self.last_agg_mtime_ns = agg_stat.st_mtime_ns
        self.last_merge_ok = True
        return True

    def check_children(self) -> None:
        if self.zeek_proc and self.zeek_proc.poll() is not None:
            raise RuntimeError(f"zeek exited unexpectedly with code {self.zeek_proc.returncode}")
        if self.netmon_proc and self.netmon_proc.poll() is not None:
            raise RuntimeError(f"netmon exited unexpectedly with code {self.netmon_proc.returncode}")

    def setup_run_meta(self) -> None:
        payload = {
            "mode": "live",
            "iface_capture": self.iface,
            "timestamp": datetime.now().strftime("%F_%H%M%S"),
            "run_dir": str(self.paths.run_dir),
        }
        write_json_atomic(self.paths.run_meta, payload)

    def run(self) -> int:
        self.setup_run_meta()
        self.write_state("starting", f"preparing live capture on {self.iface}")
        info(f"Live run folder: {self.paths.run_dir}")
        info(f"Runtime state file: {STATE_PATH}")
        bin_path, obj_path = self.build_netmon()
        self.start_zeek()
        self.start_netmon(bin_path, obj_path)
        self.write_state("running", f"live capture started on {self.iface}")
        info(f"Zeek flow output: {self.paths.zeek_conn_csv}")
        info(f"eBPF and Zeek flow output: {self.paths.merged_csv}")
        info(f"Raw eBPF events: {self.paths.ebpf_events}")
        info("Press Ctrl+C to stop")

        while not self.stop_requested:
            self.check_children()
            converted = self.refresh_zeek_csv()
            merged = self.refresh_merged_csv()
            if converted or merged:
                message = (
                    f"live outputs refreshed: zeek={self.paths.zeek_conn_csv.name} "
                    f"merged={self.paths.merged_csv.name if self.paths.merged_csv.exists() else 'pending'}"
                )
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
        self.stop_requested = True

    def finalize(self, status: str, message: str) -> None:
        stop_process(self.netmon_proc, "netmon")
        stop_process(self.zeek_proc, "zeek")
        try:
            self.refresh_zeek_csv(force=True)
            self.refresh_merged_csv(force=True)
        except Exception as exc:
            append_log(f"final refresh failed: {exc}")
        self.write_state(status, message)
        info(message)


def install_signal_handlers(daemon: LiveCaptureDaemon) -> None:
    def _handler(signum: int, _frame: object) -> None:
        append_log(f"received signal {signum}, shutting down")
        daemon.stop()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

def main() -> int:
    ap = argparse.ArgumentParser(description="Run live Zeek + netmon capture and keep zeek/conn.csv + merged.csv refreshed")
    ap.add_argument("iface", help="network interface to capture")
    ap.add_argument("--flush-secs", type=int, default=int(os.environ.get("FLUSH_SECS", "5")))
    ap.add_argument("--poll-secs", type=float, default=float(os.environ.get("POLL_SECS", "3")))
    ap.add_argument("--mode", default=os.environ.get("MODE", "both"), choices=["flow", "event", "both"])
    ap.add_argument("--disable-kprobes", action="store_true", default=os.environ.get("DISABLE_KPROBES", "1") == "1")
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
