from collections import deque
import json
import os
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st


# Resolve the repo root from the env var or by searching parent directories.
def get_repo_root() -> Path:
    """Return the repository root path from env var or by walking up parent directories."""
    env = os.environ.get("NETSENTINEL_ROOT")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    for parent in [here.parent, here.parent.parent, here.parent.parent.parent]:
        if (parent / "data").exists() and (parent / "ubuntu").exists():
            return parent
    return Path.cwd()

REPO = get_repo_root()
RUNTIME_STATE_PATH = REPO / "data" / "runtime" / "live_capture_state.json"
DAEMON_LOG_PATH    = REPO / "data" / "runtime" / "live_capture_launcher.log"
_UI_SETTINGS_PATH  = REPO / "data" / "ui_settings.json"

# Seconds updated_at may lag before the daemon is considered stalled.
# Conservative: daemon can block in run_sync() for 10-30s plus poll_secs.
_STALE_SECS = 90

# Maximum graph data-points kept in session state.
_MAX_GRAPH_POINTS = 50_000

# Bump this string when graph-state semantics change so hot-reloads get a clean slate.
_GRAPH_STATE_VERSION = "v2"

# Design tokens
ACCENT   = "#00d4ff"
PURPLE   = "#7c3aed"
GREEN    = "#10b981"
ORANGE   = "#f59e0b"
RED      = "#ef4444"
DIM      = "#5a7090"
SURFACE  = "#111722"
SURFACE2 = "#161e2c"
BORDER   = "#1e2d3d"
TEXT     = "#ccd6e8"

ATTACK_COLORS = {
    "BENIGN":        GREEN,
    "ATTACK":        RED,
    "DDoS":          RED,
    "PortScan":      ORANGE,
    "Brute Force":   PURPLE,
    "Bot":           "#06b6d4",
    "Infiltration":  "#ec4899",
    "Web Attack":    "#84cc16",
    "Heartbleed":    "#f97316",
    "SQL Injection": "#a855f7",
    "Unknown":       DIM,
}

# Styles
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

:root {
  --bg:       #0b0e14;
  --surface:  #111722;
  --surface2: #161e2c;
  --border:   #1e2d3d;
  --border2:  #253347;
  --text:     #ccd6e8;
  --dim:      #5a7090;
  --accent:   #00d4ff;
  --purple:   #7c3aed;
  --green:    #10b981;
  --orange:   #f59e0b;
  --red:      #ef4444;
}

html, body, [class*="css"] {
  font-family: 'IBM Plex Mono', 'Courier New', monospace !important;
  background: var(--bg) !important;
  color: var(--text) !important;
}

div[data-testid="stMainBlockContainer"] {
  background: var(--bg) !important;
  padding-top: 52px !important;
  padding-left: 0 !important;
  padding-right: 0 !important;
  padding-bottom: 32px !important;
  max-width: 100% !important;
}

[data-testid="stHorizontalBlock"] {
  gap: 10px !important;
  align-items: start !important;
}

[data-testid="stSidebar"] {
  background: var(--surface) !important;
  border-right: 1px solid var(--border) !important;
}

[data-testid="stSidebar"] > div {
  background: var(--surface) !important;
  padding: 20px 16px !important;
}

.sb-section {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--dim);
  padding: 10px 0 6px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 10px;
}

.sb-section:first-child { padding-top: 2px; }

.sb-note {
  font-size: 11px;
  color: var(--dim);
  line-height: 1.6;
  margin-top: 8px;
}

.ns-topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
  height: 42px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}

.ns-topbar-left { display: flex; align-items: center; }

.ns-logo {
  font-family: 'Inter', sans-serif;
  font-size: 14px;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

.ns-vdivider {
  width: 1px;
  height: 18px;
  background: var(--border2);
  margin: 0 16px;
}

.ns-page-label {
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.1em;
  color: var(--dim);
  text-transform: uppercase;
}

.ns-topbar-right { display: flex; align-items: center; gap: 10px; }

.ns-badge {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  padding: 3px 10px;
  border-radius: 2px;
  border: 1px solid;
}

.ns-badge-warn {
  color: var(--orange);
  background: rgba(245,158,11,0.08);
  border-color: rgba(245,158,11,0.25);
}

.ns-status-pill {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  padding: 4px 12px;
  border-radius: 2px;
  border: 1px solid;
}

.ns-status-live  { color: var(--green);  background: rgba(16,185,129,0.07);  border-color: rgba(16,185,129,0.28); }
.ns-status-idle  { color: var(--orange); background: rgba(245,158,11,0.07);  border-color: rgba(245,158,11,0.28); }
.ns-status-error { color: var(--red);    background: rgba(239,68,68,0.07);   border-color: rgba(239,68,68,0.28); }

.ns-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; }
.ns-dot-live  { background: var(--green);  animation: pulse-dot 1.4s ease-in-out infinite; }
.ns-dot-idle  { background: var(--orange); }
.ns-dot-error { background: var(--red); }

@keyframes pulse-dot {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.25; }
}

.ns-body {
  padding: 12px 16px 8px;
}

[data-testid="stColumn"] > div:first-child {
  padding: 0 !important;
  min-width: 0 !important;
}

.ns-stat-strip {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 1px;
  background: var(--border);
  border: 1px solid var(--border);
  border-radius: 3px;
  overflow: hidden;
  margin-bottom: 10px;
}

.ns-stat {
  background: var(--surface);
  padding: 11px 14px;
  border-left: 3px solid transparent;
}

.ns-stat:hover { background: var(--surface2); }

.ns-stat-label {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--dim);
  margin-bottom: 6px;
}

.ns-stat-value {
  font-size: 24px;
  font-weight: 700;
  line-height: 1;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.02em;
}

.ns-stat-meta {
  font-size: 11px;
  color: var(--dim);
  margin-top: 5px;
  font-variant-numeric: tabular-nums;
}

.ns-panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 3px;
  overflow: hidden;
  margin-bottom: 10px;
}

.ns-panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 7px 14px;
  border-bottom: 1px solid var(--border);
  background: var(--surface2);
}

.ns-panel-title {
  font-size: 16px;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--dim);
}

.ns-panel-meta {
  font-size: 11px;
  color: var(--dim);
  font-variant-numeric: tabular-nums;
}

.ns-empty-state {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 80px;
  font-size: 12px;
  color: var(--dim);
  letter-spacing: 0.06em;
}

.ns-dist-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 7px 14px;
  border-bottom: 1px solid rgba(30,45,61,0.55);
  font-size: 12px;
}

.ns-dist-row:last-child { border-bottom: none; }

.ns-dist-dot {
  width: 8px;
  height: 8px;
  border-radius: 1px;
  flex-shrink: 0;
}

.ns-dist-label {
  flex: 1;
  min-width: 90px;
  color: var(--text);
}

.ns-dist-bar-wrap {
  flex: 2;
  height: 4px;
  background: rgba(30,45,61,0.8);
  border-radius: 1px;
  overflow: hidden;
}

.ns-dist-bar {
  height: 100%;
  border-radius: 1px;
  min-width: 2px;
}

.ns-dist-count {
  width: 60px;
  text-align: right;
  color: var(--dim);
  font-variant-numeric: tabular-nums;
  flex-shrink: 0;
}

.ns-dist-pct {
  width: 36px;
  text-align: right;
  color: var(--dim);
  font-size: 11px;
  flex-shrink: 0;
}

.ev-wrap {
  max-height: 380px;
  overflow-y: auto;
  overflow-x: auto;
}

.ev-wrap::-webkit-scrollbar { width: 5px; height: 5px; }
.ev-wrap::-webkit-scrollbar-track { background: transparent; }
.ev-wrap::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

.ev-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
}

.ev-table thead th {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.1em;
  color: var(--dim);
  text-transform: uppercase;
  padding: 7px 14px;
  border-bottom: 1px solid var(--border);
  background: var(--surface2);
  text-align: left;
  white-space: nowrap;
  position: sticky;
  top: 0;
  z-index: 1;
}

.ev-table tbody tr { border-bottom: 1px solid rgba(30,45,61,0.45); transition: background 0.1s; }
.ev-table tbody tr:hover { background: rgba(22,30,44,0.85); }
.ev-table tbody tr.ev-anom { border-left: 2px solid rgba(239,68,68,0.65); background: rgba(239,68,68,0.03); }
.ev-table tbody tr.ev-anom:hover { background: rgba(239,68,68,0.06); }
.ev-table td { padding: 7px 14px; vertical-align: middle; white-space: nowrap; }

.ev-time  { color: var(--dim); font-size: 11px; }
.ev-proto { color: var(--dim); }
.ev-addr  { font-variant-numeric: tabular-nums; }
.ev-exe   { color: var(--dim); font-size: 11px; }
.ev-exe-col { color: var(--dim); font-size: 11px; font-variant-numeric: tabular-nums; }
.ev-dur   { color: var(--dim); font-size: 11px; font-variant-numeric: tabular-nums; text-align: right; }

.ev-score-low  { color: var(--green);  font-weight: 600; font-variant-numeric: tabular-nums; }
.ev-score-mid  { color: var(--orange); font-weight: 600; font-variant-numeric: tabular-nums; }
.ev-score-high { color: var(--red);    font-weight: 600; font-variant-numeric: tabular-nums; }

.ev-lbl {
  display: inline-block;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.05em;
  padding: 2px 8px;
  border-radius: 2px;
  border: 1px solid;
  text-transform: uppercase;
}

.probe-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 7px 14px;
  border-bottom: 1px solid rgba(30,45,61,0.45);
  font-size: 14px;
}

.probe-row:last-child { border-bottom: none; }
.probe-name { color: var(--text); }

.probe-ok   { color: var(--green);  font-size: 10px; font-weight: 700; letter-spacing: 0.07em; padding: 2px 9px; background: rgba(16,185,129,0.1);  border: 1px solid rgba(16,185,129,0.28);  border-radius: 2px; }
.probe-warn { color: var(--orange); font-size: 10px; font-weight: 700; letter-spacing: 0.07em; padding: 2px 9px; background: rgba(245,158,11,0.1);  border: 1px solid rgba(245,158,11,0.28);  border-radius: 2px; }
.probe-err  { color: var(--red);    font-size: 10px; font-weight: 700; letter-spacing: 0.07em; padding: 2px 9px; background: rgba(239,68,68,0.1);    border: 1px solid rgba(239,68,68,0.28);    border-radius: 2px; }

.info-row {
  display: grid;
  grid-template-columns: minmax(72px, 92px) minmax(0, 1fr);
  gap: 10px;
  align-items: start;
  padding: 8px 14px;
  border-bottom: 1px solid rgba(30,45,61,0.45);
  font-size: 12px;
}

.info-row:last-child { border-bottom: none; }
.info-key {
  color: var(--dim);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 10px;
  padding-top: 2px;
}
.info-val {
  color: var(--text);
  font-variant-numeric: tabular-nums;
  min-width: 0;
  text-align: right;
}
.info-main {
  display: block;
  color: var(--text);
  font-size: 12px;
  font-weight: 600;
  line-height: 1.35;
  word-break: break-word;
}
.info-sub {
  display: block;
  margin-top: 3px;
  color: var(--dim);
  font-size: 10px;
  line-height: 1.35;
  word-break: break-word;
}
.info-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 3px 8px;
  border-radius: 999px;
  border: 1px solid rgba(30,45,61,0.7);
  background: rgba(22,30,44,0.8);
}
.info-main.info-pill {
  display: inline-flex;
  width: auto;
}

[data-testid="metric-container"] { display: none !important; }

[data-testid="stSidebar"] .stSelectbox label,
[data-testid="stSidebar"] .stTextInput label,
[data-testid="stSidebar"] .stSlider label,
[data-testid="stSidebar"] .stCheckbox label,
[data-testid="stSidebar"] .stRadio label,
[data-testid="stSidebar"] .stSelectSlider label {
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 11px !important;
  color: var(--dim) !important;
  letter-spacing: 0.06em !important;
  text-transform: uppercase !important;
}

[data-testid="stSidebar"] .stSelectbox > div > div,
[data-testid="stSidebar"] .stTextInput > div > div > input {
  background: var(--surface2) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 2px !important;
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 12px !important;
  color: var(--text) !important;
}

[data-testid="stSidebar"] .stButton > button {
  font-family: 'IBM Plex Mono', monospace !important;
  background: var(--surface2) !important;
  border: 1px solid var(--border2) !important;
  color: var(--dim) !important;
  border-radius: 2px !important;
  font-size: 12px !important;
  letter-spacing: 0.04em !important;
  min-height: 36px !important;
  width: 100% !important;
  transition: all 0.15s !important;
}

[data-testid="stSidebar"] .stButton > button:hover {
  background: rgba(0,212,255,0.07) !important;
  border-color: rgba(0,212,255,0.38) !important;
  color: var(--accent) !important;
}

[data-testid="stSidebar"] .stButton > button:disabled {
  opacity: 0.3 !important;
}

[data-testid="stSidebar"] .stSlider [data-baseweb="slider"] {
  padding: 6px 0 !important;
}

[data-testid="stSidebar"] .stCheckbox > label > div:first-child {
  background: var(--surface2) !important;
  border-color: var(--border2) !important;
  border-radius: 2px !important;
}

.stAlert {
  border-radius: 2px !important;
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 12px !important;
}

[data-testid="stPlotlyChart"] > div {
  padding: 0 !important;
}
[data-testid="stPlotlyChart"] {
  margin: 0 !important;
  padding: 0 !important;
  line-height: 0 !important;
}

[data-testid="stVerticalBlock"] > [data-testid="stVerticalBlockBorderWrapper"],
[data-testid="stVerticalBlock"] > div {
  gap: 0 !important;
}

hr { border-color: var(--border) !important; margin: 0 !important; }

[data-testid="stSidebarNav"] { display: none !important; }

[data-testid="stStatusWidget"]          { display: none !important; }
[data-testid="stDeployButton"]          { display: none !important; }
[data-testid="stToolbarActionButtonIcon"] { display: none !important; }
#MainMenu                               { display: none !important; }

[data-testid="collapsedControl"] {
  background: var(--surface2) !important;
  border-right: 1px solid var(--border) !important;
}

@media (max-width: 1100px) {
  .ns-stat-strip { grid-template-columns: repeat(3, 1fr); }
}

@media (max-width: 700px) {
  .ns-stat-strip { grid-template-columns: 1fr 1fr; }
  .ns-body { padding: 16px 16px 8px; }
}
</style>
""", unsafe_allow_html=True)


# Runtime state helpers
def load_runtime_state() -> dict:
    """Load and return the daemon's runtime state JSON, or {} on missing/parse error."""
    if not RUNTIME_STATE_PATH.exists():
        return {}
    try:
        return json.loads(RUNTIME_STATE_PATH.read_text())
    except Exception:
        return {}

def append_launcher_log(line: str) -> None:
    """Append a timestamped line to the daemon launcher log file."""
    DAEMON_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DAEMON_LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(f"{datetime.now().isoformat()} {line.rstrip()}\n")

def list_interfaces() -> list[str]:
    """Return sorted list of non-loopback network interface names from ip-link."""
    try:
        out = subprocess.run(["ip", "-o", "link", "show"],
                             check=False, capture_output=True, text=True)
    except Exception:
        return []
    names: list[str] = []
    for line in out.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip().split("@", 1)[0]
        if name != "lo":
            names.append(name)
    return sorted(dict.fromkeys(names))

def rank_interface(name: str) -> tuple[int, str]:
    """Return a (priority, name) tuple where lower priority means preferred for capture."""
    lo = name.lower()
    if lo == "lo":                                              return (100, name)
    if lo == "ns0":                                             return (-1,  name)
    if lo.startswith(("eno","enp","ens","eth","wlan","wlp")):   return (0,   name)
    if lo.startswith(("tailscale","tun","tap")):                return (20,  name)
    if lo.startswith(("docker","br-","veth","virbr")):          return (50,  name)
    return (10, name)

def preferred_interface(names: list[str]) -> str:
    """Return the best capture interface, honouring NETSENTINEL_DEFAULT_IFACE if set."""
    if not names:
        return ""
    env_iface = os.environ.get("NETSENTINEL_DEFAULT_IFACE", "").strip()
    if env_iface and env_iface in names:
        return env_iface
    return sorted(names, key=rank_interface)[0]

def live_capture_is_running(runtime_state: dict | None) -> bool:
    """Return True only when runtime state shows status=running and the PID is alive."""
    if not runtime_state:
        return False
    if runtime_state.get("status") != "running":
        return False
    pid = runtime_state.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True

def start_live_capture(iface: str) -> tuple[bool, str]:
    """Launch the live capture daemon as a detached subprocess and return (ok, message)."""
    if not iface:
        return False, "Choose an interface first."
    if os.geteuid() != 0:
        return False, "Live capture must be started as root."
    rt = load_runtime_state()
    if live_capture_is_running(rt):
        return False, f"Already running on {rt.get('interface','unknown')}."
    cmd = [
        "python3", str(REPO / "ubuntu" / "live" / "live_capture_daemon.py"), iface,
        "--flush-secs",                 os.environ.get("FLUSH_SECS", "5"),
        "--poll-secs",                  os.environ.get("POLL_SECS",  "3"),
        "--mode",                       os.environ.get("MODE",       "both"),
        "--score-threshold-multiplier", os.environ.get("SCORE_THRESHOLD_MULTIPLIER", "0.5"),
    ]
    DAEMON_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_fh = DAEMON_LOG_PATH.open("a", encoding="utf-8")
    append_launcher_log(f"starting: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd, cwd=str(REPO), stdout=log_fh,
                                stderr=subprocess.STDOUT, text=True, start_new_session=True)
    except Exception as exc:
        log_fh.close()
        append_launcher_log(f"failed: {exc}")
        return False, f"Failed: {exc}"
    log_fh.close()
    return True, f"Launched on {iface} (pid {proc.pid})."

def stop_live_capture() -> tuple[bool, str]:
    """Send SIGINT to the running daemon PID and return (ok, message)."""
    rt = load_runtime_state()
    pid = rt.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False, "No PID in runtime state."
    try:
        os.kill(pid, signal.SIGINT)
    except ProcessLookupError:
        return False, f"Process {pid} not running."
    except PermissionError:
        return False, f"Permission denied for pid {pid}."
    append_launcher_log(f"sent SIGINT to pid={pid}")
    return True, f"Stop signal sent to pid {pid}."

def maybe_autostart_live_capture() -> None:
    """Auto-start live capture once if NETSENTINEL_AUTOSTART_LIVE_CAPTURE is set."""
    if os.environ.get("NETSENTINEL_AUTOSTART_LIVE_CAPTURE","false").lower() not in {"1","true","yes","on"}:
        return
    if st.session_state.get("autostart_attempted"):
        return
    if st.session_state.get("source") != "Live":
        return
    rt = load_runtime_state()
    if live_capture_is_running(rt):
        st.session_state["autostart_attempted"] = True
        return
    iface = st.session_state.get("iface","").strip()
    if not iface:
        iface = preferred_interface(list_interfaces())
        st.session_state["iface"] = iface
    if not iface:
        return
    ok, msg = start_live_capture(iface)
    st.session_state["capture_feedback"] = msg
    st.session_state["autostart_attempted"] = True
    if ok:
        st.rerun()

def resolve_repo_path(path_str: str) -> Path:
    """Resolve path_str relative to REPO if not already absolute."""
    p = Path(path_str).expanduser()
    return p if p.is_absolute() else (REPO / p).resolve()

def _rebase_daemon_path(p_str: str) -> Path:
    """Rebase an absolute daemon path to the UI's REPO by re-anchoring from the first 'data/' component."""
    p = Path(p_str)
    if p.exists():
        return p
    parts = p.parts
    for i, part in enumerate(parts):
        if part == "data":
            candidate = REPO.joinpath(*parts[i:])
            if candidate.exists():
                return candidate
    return p

def default_live_event_path() -> str:
    """Return the default scored events file path from runtime state, or empty string."""
    state = load_runtime_state()
    for key in ("scored_events_path",):
        raw = state.get(key)
        if raw:
            p = _rebase_daemon_path(raw)
            if p.exists():
                return str(p)
    rd = state.get("run_dir")
    if rd:
        run_dir = _rebase_daemon_path(rd)
        for name in ("scored_events.jsonl", "ebpf_events.jsonl"):
            candidate = run_dir / name
            if candidate.exists():
                return str(candidate)
    return ""

def resolve_live_event_path(rt: dict) -> str:
    """Return the scored events path from runtime state, falling back to the default."""
    raw = rt.get("scored_events_path")
    if raw:
        p = _rebase_daemon_path(raw)
        if p.exists():
            return str(p)
    return default_live_event_path()

def file_line_count(path_str: str) -> int:
    """Count non-empty lines in the file at path_str, returning 0 if absent."""
    if not path_str:
        return 0
    path = Path(path_str)
    if not path.exists() or not path.is_file():
        return 0
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                count += 1
    return count

def tail_offset_for_path(path_str: str) -> int:
    """Return the current byte size of the file so new polling starts from the tail."""
    if not path_str:
        return 0
    path = resolve_repo_path(path_str)
    if not path.exists() or not path.is_file():
        return 0
    return int(path.stat().st_size)

def _pid_alive(pid: object) -> bool:
    """Return True if the process with the given PID exists and is signal-reachable."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def _state_age_secs(rt: dict) -> float | None:
    """Return how many seconds ago updated_at was written, or None if unparseable."""
    raw = rt.get("updated_at")
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return time.time() - dt.timestamp()
    except Exception:
        return None

def runtime_probe_status(rt: dict) -> list[str]:
    """Map runtime state to a per-probe status list of 'ok', 'warn', or 'err'."""
    if not rt:
        return ["err"] * len(PROBES)
    s = rt.get("status")
    alive = _pid_alive(rt.get("pid"))
    if s == "running" and alive:
        age = _state_age_secs(rt)
        if age is not None and age > _STALE_SECS:
            return ["warn"] * len(PROBES)
        return ["ok"] * len(PROBES)
    if s == "error" or not alive:
        return ["err"] * len(PROBES)
    return ["warn"] * len(PROBES)

def runtime_capture_status(rt: dict | None) -> tuple[str, str]:
    """Return (status_key, html_pill) describing the current capture health."""
    if not rt:
        return (
            "missing",
            '<span class="ns-status-pill ns-status-idle">'
            '<span class="ns-dot ns-dot-idle"></span>No Capture</span>',
        )
    raw = rt.get("status", "missing")
    if raw == "error":
        return (
            "error",
            '<span class="ns-status-pill ns-status-error">'
            '<span class="ns-dot ns-dot-error"></span>Capture Error</span>',
        )
    if raw == "stopped":
        return (
            "stopped",
            '<span class="ns-status-pill ns-status-idle">'
            '<span class="ns-dot ns-dot-idle"></span>Stopped</span>',
        )
    if raw == "starting":
        return (
            "starting",
            '<span class="ns-status-pill ns-status-idle">'
            '<span class="ns-dot ns-dot-idle"></span>Starting\u2026</span>',
        )
    if raw != "running":
        return (
            "missing",
            '<span class="ns-status-pill ns-status-idle">'
            '<span class="ns-dot ns-dot-idle"></span>No Capture</span>',
        )
    # raw == "running": verify PID is actually alive
    if not _pid_alive(rt.get("pid")):
        return (
            "error",
            '<span class="ns-status-pill ns-status-error">'
            '<span class="ns-dot ns-dot-error"></span>Daemon Dead</span>',
        )
    # Verify daemon is still updating its state file (not silently stalled)
    age = _state_age_secs(rt)
    if age is not None and age > _STALE_SECS:
        return (
            "stalled",
            '<span class="ns-status-pill ns-status-idle">'
            '<span class="ns-dot ns-dot-idle"></span>Stalled</span>',
        )
    return (
        "running",
        '<span class="ns-status-pill ns-status-live">'
        '<span class="ns-dot ns-dot-live"></span>Capture Running</span>',
    )

def sync_live_source_from_runtime() -> None:
    """Sync session state interface and file path from the daemon's runtime state."""
    rt = load_runtime_state()
    if not rt:
        return
    # Only sync the interface when the daemon is actually running;
    # otherwise the user's sidebar selection would be overwritten by a stale state file.
    if rt.get("interface") and live_capture_is_running(rt):
        S.iface = rt["interface"]
    rf = resolve_live_event_path(rt)
    if rf and S.file_path != rf:
        S.file_path     = rf
        S.file_offset   = tail_offset_for_path(rf)
        S.events        = []
        S.total_flows   = 0
        S.total_anom    = 0
        S.threat_counts = {}
        S.graph_points  = []
    rd = rt.get("run_dir")
    S.run_dir = str(_rebase_daemon_path(rd)) if rd else ""

_UI_SETTINGS_KEYS = ["threshold", "model", "source", "file_path",
                     "poll_interval", "graph_window_s", "filter_anom", "iface"]

def _save_ui_settings() -> None:
    """Persist sidebar settings to disk so they survive a page refresh."""
    try:
        data = {k: st.session_state[k] for k in _UI_SETTINGS_KEYS if k in st.session_state}
        tmp = _UI_SETTINGS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(_UI_SETTINGS_PATH)
    except Exception:
        pass

def _load_ui_settings() -> dict:
    """Load previously saved sidebar settings, returning an empty dict on any error."""
    try:
        return json.loads(_UI_SETTINGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _init():
    """Initialise Streamlit session state with defaults on first page load."""
    rt     = load_runtime_state()
    ifaces = list_interfaces()
    live_path = default_live_event_path()
    defaults = {
        "is_live":            True,
        "source":             "Live",
        "file_path":          live_path,

        "iface":              rt.get("interface") or preferred_interface(ifaces),
        "model":              "eBPF Enriched",
        "threshold":          float(rt.get("ebpf_threshold", 0.50) or 0.50),
        "poll_interval":      1,
        "events":             [],
        "total_flows":        0,
        "total_anom":         0,
        "start_time":         time.time(),
        "threat_counts":      {},
        "graph_points":       [],
        "file_offset":        tail_offset_for_path(live_path),
        "filter_anom":        False,
        "graph_window_s":     300,
        "run_dir":            "",
        "capture_feedback":   "",
        "last_action_time":   0.0,
        "autostart_attempted": False,
        "loaded_path":        "",
        "loaded_model":       "",
        "loaded_threshold":   None,
    }
    saved = _load_ui_settings()
    defaults.update({k: v for k, v in saved.items() if k in defaults})
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

    # Clear graph state when the stored version doesn't match the current constant.
    # This handles hot-reloads where graph_points may contain stale history.
    if st.session_state.get("_graph_state_version") != _GRAPH_STATE_VERSION:
        st.session_state["graph_points"]     = []
        st.session_state["loaded_path"]      = ""
        st.session_state["loaded_model"]     = ""
        st.session_state["loaded_threshold"] = None
        st.session_state["_graph_state_version"] = _GRAPH_STATE_VERSION

_init()
S = st.session_state
maybe_autostart_live_capture()

PROBES = [
    "kprobe/tcp_connect",
    "kprobe/tcp_close",
    "kprobe/udp_sendmsg",
    "socket/filter",
    "tracepoint/sys_bind",
]

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}
GRAPH_WINDOW_OPTIONS = [
    ("30 sec", 30),
    ("2 min", 120),
    ("5 min", 300),
    ("15 min", 900),
    ("1 hr", 3600),
    ("6 hr", 21600),
    ("24 hr", 86400),
]

# Event parsing and scoring
def normalise_event(ev: dict) -> dict:
    """Normalise raw event dict to canonical field names used by the UI."""
    out = dict(ev)
    if "_ts" not in out:
        try:    out["_ts"] = datetime.fromtimestamp(float(out.get("ts_s"))).strftime("%H:%M:%S")
        except (TypeError, ValueError): out["_ts"] = datetime.now().strftime("%H:%M:%S")
    if "src_ip"   not in out: out["src_ip"]   = out.get("saddr_str") or out.get("saddr") or "?"
    if "dst_ip"   not in out: out["dst_ip"]   = out.get("daddr_str") or out.get("daddr") or "?"
    if "src_port" not in out: out["src_port"] = out.get("sport", "?")
    if "dst_port" not in out: out["dst_port"] = out.get("dport", "?")
    if "exe" not in out:
        raw_exe = (out.get("comm") or out.get("comm_mode") or
                   out.get("ebpf_comm") or out.get("process_name") or "")
        out["exe"] = "" if str(raw_exe).lower() in ("nan", "none", "") else str(raw_exe)
    elif str(out.get("exe","")).lower() in ("nan", "none"):
        out["exe"] = ""
    if "pid" not in out:
        out["pid"] = out.get("pid_mode") or out.get("ebpf_pid") or 0
    proto = out.get("proto")
    if isinstance(proto, (int, float)):
        out["proto"] = PROTO_MAP.get(int(proto), str(int(proto)))
    else:
        try:    out["proto"] = PROTO_MAP.get(int(str(proto)), str(proto).upper())
        except (TypeError, ValueError): out["proto"] = str(proto or "TCP").upper()
    return out

# 512 KB per poll, ~1 000 events, keeps UI responsive
_READ_CHUNK_BYTES = 512 * 1024

def read_file_events(path: str, offset: int) -> tuple[list[dict], int]:
    """Read new JSONL events from path at byte offset; return (events, new_offset)."""
    p = resolve_repo_path(path)
    if not p.exists():
        # Daemon is still starting; preserve offset so we don't rewind to 0 once the file appears.
        return [], offset
    size = p.stat().st_size
    if offset > size:
        offset = 0  # file was rotated or truncated
    if offset == size:
        return [], offset
    with open(p, "rb") as f:
        f.seek(offset)
        chunk = f.read(_READ_CHUNK_BYTES)
    if not chunk:
        return [], offset
    # Only consume up to the last complete newline so a partial write at the boundary
    # is left for the next poll rather than dropped.
    last_nl = chunk.rfind(b"\n")
    if last_nl < 0:
        return [], offset
    complete_bytes = chunk[: last_nl + 1]
    new_offset = offset + len(complete_bytes)
    evs = []
    for line in complete_bytes.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evs.append(normalise_event(json.loads(line)))
        except Exception:
            pass
    return evs, new_offset

def score_class(s):
    """Return (css_class, formatted_value) for a numeric anomaly score."""
    try:
        v = float(s)
        fmt = f"{v:.2e}" if v < 0.001 else f"{v:.3f}"
        if v < 0.35: return "ev-score-low",  fmt
        if v < 0.65: return "ev-score-mid",  fmt
        return "ev-score-high", fmt
    except Exception:
        return "ev-score-low", "N/A"

def graph_window_label(window_s: int) -> str:
    """Return the display label for a graph window duration in seconds."""
    for label, value in GRAPH_WINDOW_OPTIONS:
        if int(value) == int(window_s):
            return label
    return f"{window_s}s"

def chart_bucket_seconds(window_s: int) -> int:
    """Return the aggregation bucket width in seconds appropriate for the given window."""
    window_s = int(max(window_s, 1))
    if window_s <= 120:   return 2
    if window_s <= 300:   return 10
    if window_s <= 900:   return 15
    if window_s <= 3600:  return 60
    if window_s <= 21600: return 300
    return 900

def selected_model_key() -> str:
    """Return 'baseline' or 'ebpf' based on the currently selected model name."""
    return "baseline" if S.model == "Baseline" else "ebpf"

def runtime_model_threshold(rt: dict, model_name: str) -> float | None:
    """Read the model's threshold from runtime state, or None if absent or invalid."""
    key = "baseline_threshold" if model_name == "Baseline" else "ebpf_threshold"
    try:
        value = rt.get(key)
        return None if value is None else float(value)
    except Exception:
        return None

def event_score(ev: dict) -> float:
    """Extract the anomaly score for the active model from an event dict."""
    model_key = selected_model_key()
    for key in (f"{model_key}_score", "anomaly_score"):
        try:
            if key in ev:
                return float(ev.get(key, 0.0))
        except Exception:
            pass
    return 0.0

def event_label(ev: dict) -> str:
    """Return the human-readable label ('ATTACK'/'BENIGN'/family name) for an event."""
    model_key = selected_model_key()
    pred_key = f"{model_key}_pred"
    if pred_key in ev:
        try:
            return "ATTACK" if int(float(ev.get(pred_key, 0))) == 1 else "BENIGN"
        except Exception:
            pass
    label_key = f"{model_key}_label"
    if label_key in ev:
        return str(ev.get(label_key) or "Unknown")
    return str(ev.get("label") or "BENIGN")

def label_style(lbl: str) -> str:
    """Return an inline CSS style string for a label badge using its attack-family colour."""
    col = ATTACK_COLORS.get(lbl, ATTACK_COLORS["Unknown"])
    return f"background:{col}14;color:{col};border-color:{col}44;"

def uptime_str(start: float) -> str:
    """Format elapsed seconds since start as MM:SS or HH:MM:SS."""
    s = max(0, int(time.time() - start))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}" if h else f"{m:02d}:{sec:02d}"

def daemon_start_epoch(rt: dict) -> float | None:
    """Parse the daemon's started_at field into a Unix epoch float."""
    raw = (rt or {}).get("started_at")
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None

def rebuild_state_from_file(path: str, populate_graph: bool = True) -> None:
    """Reread the event file from the start to rebuild all cumulative counters and the event list."""
    resolved = resolve_repo_path(path)
    if not resolved.exists():
        S.events = []
        S.total_flows = 0
        S.total_anom = 0
        S.threat_counts = {}
        S.graph_points = []
        S.file_offset = 0
        S.loaded_path = path
        S.loaded_model = S.model
        S.loaded_threshold = float(S.threshold)
        return

    recent = deque(maxlen=300)
    threat_counts: dict[str, int] = {}
    total_flows = 0
    total_anom = 0
    graph_points: list[dict] = []

    with resolved.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = normalise_event(json.loads(line))
            except Exception:
                continue
            total_flows += 1
            score_val = event_score(ev)
            if score_val >= S.threshold:
                total_anom += 1
            lbl = event_label(ev)
            threat_counts[lbl] = threat_counts.get(lbl, 0) + 1
            recent.append(ev)
            if populate_graph:
                try:
                    ts_val = float(ev.get("ts_s"))
                except Exception:
                    ts_val = float(time.time())
                graph_points.append({"ts_s": ts_val, "score": score_val})

    S.events = list(reversed(list(recent)))
    S.total_flows = total_flows
    S.total_anom = total_anom
    S.threat_counts = threat_counts
    S.graph_points = graph_points
    S.file_offset = int(resolved.stat().st_size)
    S.loaded_path = path
    S.loaded_model = S.model
    S.loaded_threshold = float(S.threshold)

def ingest(evs: list[dict]):
    """Append new events to session counters, graph points, and the rolling event list."""
    if not evs:
        return
    S.total_flows += len(evs)
    S.total_anom  += sum(1 for e in evs if event_score(e) >= S.threshold)
    for e in evs:
        lbl = event_label(e)
        S.threat_counts[lbl] = S.threat_counts.get(lbl, 0) + 1
        try:
            ts_val = float(e.get("ts_s"))
        except Exception:
            ts_val = float(time.time())
        S.graph_points.append({"ts_s": ts_val, "score": event_score(e)})
    if len(S.graph_points) > _MAX_GRAPH_POINTS:
        S.graph_points = S.graph_points[-_MAX_GRAPH_POINTS:]
    S.events = list(reversed(evs)) + S.events
    S.events = S.events[:300]

def build_chart_frame(points: list[dict], window_s: int) -> pd.DataFrame:
    """Bucket graph_points into time-aggregated rows covering the last window_s seconds."""
    if not points:
        return pd.DataFrame(columns=["bucket", "pps", "score", "t"])
    df = pd.DataFrame(points)
    if df.empty or "ts_s" not in df.columns:
        return pd.DataFrame(columns=["bucket", "pps", "score", "t"])
    df["ts_s"] = pd.to_numeric(df["ts_s"], errors="coerce")
    df["score"] = pd.to_numeric(df.get("score", 0.0), errors="coerce").fillna(0.0)
    df = df.dropna(subset=["ts_s"])
    if df.empty:
        return pd.DataFrame(columns=["bucket", "pps", "score", "t"])
    # Anchor the window to now so the live graph always shows the last N seconds
    # relative to the current clock, preventing a startup spike from historical events.
    end_ts = max(float(df["ts_s"].max()), float(time.time()))
    start_ts = end_ts - float(window_s)
    df = df[df["ts_s"] >= start_ts].copy()
    if df.empty:
        return pd.DataFrame(columns=["bucket", "pps", "score", "t"])
    step = chart_bucket_seconds(window_s)
    df["bucket"] = (df["ts_s"] // step) * step
    out = (
        df.groupby("bucket", as_index=False)
          .agg(flows=("score", "size"), score=("score", "mean"))
          .sort_values("bucket")
    )
    out["pps"] = out["flows"] / float(step)
    # 3-bucket rolling average to smooth batch-delivery spikes.
    out["pps_smooth"] = out["pps"].rolling(3, min_periods=1, center=True).mean()
    fmt = "%H:%M:%S" if window_s <= 3600 else "%m-%d %H:%M"
    out["t"] = pd.to_datetime(out["bucket"], unit="s").dt.strftime(fmt)
    return out

# Ingest
iface_options   = list_interfaces()

new_evs: list[dict] = []
runtime_state = load_runtime_state()
if S.source == "Live":
    sync_live_source_from_runtime()
    runtime_state = load_runtime_state()
capture_running = live_capture_is_running(runtime_state)

_just_cleared = bool(S.get("_just_cleared", False))
S._just_cleared = False  # consume the flag immediately

if (
    not _just_cleared
    and S.source in {"Live", "File"}
    and S.file_path
    and (
        S.loaded_path != S.file_path
        or S.loaded_model != S.model
        or S.loaded_threshold is None
        or float(S.loaded_threshold) != float(S.threshold)
    )
):
    # In Live mode, count historical flows for the stat strip but skip loading
    # them into graph_points to avoid a spike on the first render.
    rebuild_state_from_file(S.file_path, populate_graph=(S.source != "Live"))

if S.is_live and S.source in {"Live","File"} and S.file_path:
    new_evs, S.file_offset = read_file_events(S.file_path, S.file_offset)

ingest(new_evs)

capture_state, status_html = runtime_capture_status(
    runtime_state if S.source == "Live" else None
)

chart_df = build_chart_frame(S.graph_points, S.graph_window_s)
anom_rate  = (S.total_anom / S.total_flows * 100) if S.total_flows > 0 else 0.0
last_pps   = float(chart_df["pps_smooth"].iloc[-1]) if not chart_df.empty else float(len(new_evs))
last_score = float(chart_df["score"].iloc[-1]) if not chart_df.empty else ((sum(event_score(e) for e in new_evs) / len(new_evs)) if new_evs else 0.0)
last_pps_text = f"{last_pps:.2f}"


# Sidebar
with st.sidebar:
    st.markdown(
        '<div style="'
        'padding:14px 0 16px;'
        'border-bottom:1px solid var(--border);'
        'margin-bottom:14px;'
        '">'
        '<span style="'
        'font-family:\'Inter\',sans-serif;'
        'font-size:18px;'
        'font-weight:800;'
        'letter-spacing:0.16em;'
        'text-transform:uppercase;'
        f'color:{ACCENT};'
        'display:block;line-height:1;'
        '">Settings</span>'
        '</div>',
        unsafe_allow_html=True,
    )

    # Controls
    st.markdown('<div class="sb-section">Capture controls</div>', unsafe_allow_html=True)

    if S.capture_feedback:
        st.info(S.capture_feedback)

    sb_c1, sb_c2 = st.columns(2)
    with sb_c1:
        if st.button("Start", disabled=capture_running, use_container_width=True):
            _, msg = start_live_capture(S.iface)
            S.capture_feedback = msg
            S.last_action_time = time.time()
            st.rerun()
    with sb_c2:
        if st.button("Stop", disabled=not capture_running, use_container_width=True):
            _, msg = stop_live_capture()
            S.capture_feedback = msg
            S.last_action_time = time.time()
            S.is_live = False  # halt webapp polling immediately
            st.rerun()

    sb_c3, sb_c4 = st.columns(2)
    with sb_c3:
        lbl_pause = "Pause" if S.is_live else "Resume"
        if st.button(lbl_pause, use_container_width=True):
            S.is_live = not S.is_live
            st.rerun()
    with sb_c4:
        if st.button("Clear", use_container_width=True):
            S.events = []; S.total_flows = 0; S.total_anom = 0
            S.threat_counts = {}; S.graph_points = []
            S.file_offset = tail_offset_for_path(S.file_path)
            S.start_time = time.time()
            S._just_cleared = True  # suppress rebuild on next rerun
            st.rerun()

    # Source
    st.markdown('<div class="sb-section">Source</div>', unsafe_allow_html=True)

    source_options = ["Live", "File"]
    current_source = S.source if S.source in source_options else "Live"
    S.source = st.selectbox("Mode", source_options, index=source_options.index(current_source))

    if iface_options:
        iface_index = iface_options.index(S.iface) if S.iface in iface_options else 0
        sel = st.selectbox("Interface", iface_options, index=iface_index)
        if sel != S.iface:
            S.iface = sel
            S.autostart_attempted = False
    else:
        S.iface = st.text_input("Interface", value=S.iface, placeholder="eth0")

    # Show a Restart button when the running daemon is on a different interface than selected.
    running_iface = runtime_state.get("interface", "") if runtime_state else ""
    if capture_running and running_iface and running_iface != S.iface:
        st.warning(f"Daemon is on **{running_iface}**. Restart to switch to **{S.iface}**.")
        if st.button("Restart on selected interface", use_container_width=True):
            stop_live_capture()
            time.sleep(0.5)
            _, msg = start_live_capture(S.iface)
            S.capture_feedback = msg
            S.autostart_attempted = True
            st.rerun()

    if S.source == "Live":
        st.markdown(
            '<p class="sb-note">Follows <code>ubuntu/live/run_live.sh</code><br></p>',
            unsafe_allow_html=True,
        )
    elif S.source == "File":
        S.file_path = st.text_input(
            "JSONL file path", value=S.file_path,
            placeholder="data/runs/live_.../ebpf_events.jsonl",
        )

    # Detection settings
    st.markdown('<div class="sb-section">Detection</div>', unsafe_allow_html=True)

    selected_model = st.selectbox("Model", ["eBPF Enriched", "Baseline"],
                                  index=0 if S.model == "eBPF Enriched" else 1)
    if selected_model != S.model:
        S.model = selected_model
        threshold = runtime_model_threshold(runtime_state, selected_model)
        if threshold is not None:
            S.threshold = threshold
        S.loaded_model = ""
        S.loaded_threshold = None
        st.rerun()
    S.threshold    = st.slider("Anomaly threshold", 0.0, 1.0, S.threshold, 0.01)
    st.checkbox("Show anomalies only", key="filter_anom")
    S.poll_interval = st.select_slider("Refresh interval (s)", options=[0.5, 1, 2, 3, 5], value=S.poll_interval)
    window_labels = [label for label, _ in GRAPH_WINDOW_OPTIONS]
    current_window_label = graph_window_label(S.graph_window_s)
    if current_window_label not in window_labels:
        current_window_label = window_labels[2]
    selected_window_label = st.selectbox("Graph window", window_labels, index=window_labels.index(current_window_label))
    S.graph_window_s = dict(GRAPH_WINDOW_OPTIONS)[selected_window_label]
    _save_ui_settings()

# Main Content
# Title banner
st.markdown(
    '<div style="'
    'display:flex;align-items:center;justify-content:space-between;'
    'padding:16px 24px 12px;'
    'background:var(--surface);'
    'border-bottom:1px solid var(--border);'
    '">'
    '<div>'
    '<span style="'
    'font-family:\'Inter\',sans-serif;'
    'font-size:28px;'
    'font-weight:800;'
    'letter-spacing:0.18em;'
    'text-transform:uppercase;'
    f'color:{ACCENT};'
    'display:block;line-height:1;'
    '">NetSentinel</span>'
    '<span style="'
    'font-size:11px;font-weight:500;letter-spacing:0.12em;'
    f'color:{DIM};text-transform:uppercase;margin-top:4px;display:block;'
    '">eBPF Network Intrusion Detection</span>'
    '</div>'
    f'<div style="display:flex;align-items:center;gap:10px;">'
    f'<span class="ns-badge ns-badge-warn">Research Build</span>'
    f'{status_html}'
    '</div>'
    '</div>',
    unsafe_allow_html=True,
)

# Alert banners
if S.source == "Live":
    rt_msg  = runtime_state.get("message") if runtime_state else None
    runtime_event_path = resolve_live_event_path(runtime_state) if runtime_state else None
    if capture_state == "error":
        st.error("Capture not running.")
    elif capture_state == "missing":
        st.warning("No live capture state found. Run `sudo bash ubuntu/live/run_live.sh <iface>` first.")
    elif capture_state == "starting":
        st.warning(rt_msg or "Live capture is starting...")
    elif capture_state == "stalled":
        age = _state_age_secs(runtime_state) if runtime_state else None
        age_txt = f" (last update {age:.0f}s ago)" if age is not None else ""
        st.warning(
            f"Daemon is running (PID {runtime_state.get('pid')}) but its state file "
            f"has not been updated for over {_STALE_SECS}s{age_txt}. "
            "The daemon may be blocked in a long conversion step. Check "
            "`data/runtime/live_capture_daemon.log` for details."
        )
    if capture_state == "running" and runtime_event_path:
        st.info(f"Current live event file: `{runtime_event_path}`")
    if (capture_state == "running" and not new_evs
            and int(runtime_state.get("ebpf_flow_count", 0) or 0) == 0):
        st.warning(f"No packets captured on {S.iface} yet. Check interface and generate traffic.")

# Body
st.markdown('<div class="ns-body">', unsafe_allow_html=True)

# Stat strip. Uptime is derived from the daemon's started_at so it reflects
# how long the backend has been running, not just the browser session.
_daemon_epoch  = daemon_start_epoch(runtime_state)
_uptime_source = "daemon uptime" if _daemon_epoch is not None else "page uptime"
_uptime_epoch  = _daemon_epoch if _daemon_epoch is not None else S.start_time
stats_data = [
    ("Flows / sec",  last_pps_text,          f"Total {S.total_flows:,}",      ACCENT,  ACCENT),
    ("Anomaly rate", f"{anom_rate:.1f}%",     f"{S.total_anom:,} detected",   RED,     RED),
    ("eBPF events",  f"{S.total_flows:,}",    "Raw kernel events",            PURPLE,  PURPLE),
    ("Avg score",    f"{last_score:.3f}",      f"Threshold {S.threshold:.2f}", ORANGE,  ORANGE),
    ("Uptime",       uptime_str(_uptime_epoch), f"{_uptime_source} · {S.iface}", GREEN, GREEN),
]

cards_html = "".join(
    f'<div class="ns-stat" style="border-left:3px solid {accent};">'
    f'  <div class="ns-stat-label">{label}</div>'
    f'  <div class="ns-stat-value" style="color:{color};">{value}</div>'
    f'  <div class="ns-stat-meta">{meta}</div>'
    f'</div>'
    for label, value, meta, color, accent in stats_data
)
st.markdown(f'<div class="ns-stat-strip">{cards_html}</div>', unsafe_allow_html=True)

# Chart row
col_ts, col_dist = st.columns([3, 2], gap="medium")

with col_ts:
    st.markdown(
        '<div class="ns-panel">'
        '  <div class="ns-panel-header">'
        '    <span class="ns-panel-title">Flow rate &amp; anomaly score</span>'
        f'    <span class="ns-panel-meta">{graph_window_label(S.graph_window_s)}</span>'
        '  </div>',
        unsafe_allow_html=True,
    )
    if not chart_df.empty:
        fig = go.Figure()
        # Dim background area showing the raw per-bucket rate.
        fig.add_trace(go.Scatter(
            x=chart_df["t"], y=chart_df["pps"],
            name="Flows/s (raw)",
            line=dict(color="rgba(0,212,255,0.25)", width=0.8),
            fill="tozeroy",
            fillcolor="rgba(0,212,255,0.04)",
            hovertemplate="%{x}  Raw: %{y:.2f}<extra></extra>",
        ))
        # 3-bucket rolling average as the prominent line.
        fig.add_trace(go.Scatter(
            x=chart_df["t"], y=chart_df["pps_smooth"],
            name="Flows/s",
            line=dict(color=ACCENT, width=2.2),
            hovertemplate="%{x}  Flows/s: %{y:.2f}<extra></extra>",
        ))
        fig.add_trace(go.Scatter(
            x=chart_df["t"], y=chart_df["score"],
            name="Avg score",
            line=dict(color=RED, width=1.4, dash="dot"),
            yaxis="y2",
            hovertemplate="%{x}  Score: %{y:.3f}<extra></extra>",
        ))
        fig.add_hline(
            y=S.threshold, yref="y2",
            line=dict(color=ORANGE, width=1, dash="dash"),
            annotation_text=f"threshold {S.threshold:.2f}",
            annotation_font_size=10,
            annotation_font_color=ORANGE,
        )
        fig.update_layout(
            paper_bgcolor=SURFACE, plot_bgcolor=SURFACE,
            font=dict(family="IBM Plex Mono, monospace", color=DIM, size=11),
            margin=dict(l=46, r=50, t=8, b=28),
            height=440,
            xaxis=dict(gridcolor=BORDER, linecolor=BORDER, zeroline=False,
                       tickfont=dict(size=10), nticks=10),
            yaxis=dict(title=dict(text="Flows/s", font=dict(size=10)),
                       gridcolor=BORDER, linecolor=BORDER, zeroline=False,
                       tickfont=dict(size=10)),
            yaxis2=dict(title=dict(text="Score", font=dict(size=10)),
                        overlaying="y", side="right", range=[0,1],
                        gridcolor="rgba(0,0,0,0)", zeroline=False, tickfont=dict(size=10)),
            legend=dict(bgcolor=SURFACE2, bordercolor=BORDER, borderwidth=1,
                        font=dict(size=10), x=0.01, y=0.99, orientation="h"),
            hovermode="x unified",
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.markdown('<div class="ns-empty-state" style="height:440px;">No data in selected time window</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_dist:
    total_threat = sum(S.threat_counts.values())
    st.markdown(
        '<div class="ns-panel">'
        '  <div class="ns-panel-header">'
        '    <span class="ns-panel-title">Anomaly distribution</span>'
        f'    <span class="ns-panel-meta">{total_threat:,} flows</span>'
        '  </div>',
        unsafe_allow_html=True,
    )

    if S.threat_counts:
        df_th = (pd.DataFrame(list(S.threat_counts.items()), columns=["Label","Count"])
                   .sort_values("Count", ascending=False))
        colors_pie = [ATTACK_COLORS.get(r, DIM) for r in df_th["Label"]]
        fig_pie = go.Figure(go.Pie(
            labels=df_th["Label"], values=df_th["Count"],
            marker=dict(colors=colors_pie, line=dict(color=SURFACE, width=2)),
            hole=0.60,
            textfont=dict(size=10, family="IBM Plex Mono"),
            hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
            showlegend=False, direction="clockwise", sort=True,
        ))
        fig_pie.update_layout(
            paper_bgcolor=SURFACE,
            margin=dict(l=4, r=4, t=4, b=4),
            height=440,
            annotations=[dict(
                text=f'{df_th["Count"].sum():,}<br><span style="font-size:10px">flows</span>',
                x=0.5, y=0.5, xref="paper", yref="paper", showarrow=False,
                font=dict(family="IBM Plex Mono", size=16, color=TEXT),
            )],
        )
        st.plotly_chart(fig_pie, use_container_width=True, config={"displayModeBar": False})

        total_d = df_th["Count"].sum()
        rows = ""
        for _, row in df_th.head(8).iterrows():
            col  = ATTACK_COLORS.get(row["Label"], DIM)
            pct  = row["Count"] / total_d * 100 if total_d > 0 else 0
            rows += (
                f'<div class="ns-dist-row">'
                f'  <div class="ns-dist-dot" style="background:{col};"></div>'
                f'  <span class="ns-dist-label">{row["Label"]}</span>'
                f'  <div class="ns-dist-bar-wrap">'
                f'    <div class="ns-dist-bar" style="width:{pct:.1f}%;background:{col};"></div>'
                f'  </div>'
                f'  <span class="ns-dist-count">{int(row["Count"]):,}</span>'
                f'  <span class="ns-dist-pct">{pct:.0f}%</span>'
                f'</div>'
            )
        st.markdown(rows, unsafe_allow_html=True)
    else:
        st.markdown('<div class="ns-empty-state" style="height:280px;">No data yet</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

# Event stream
display_evs = S.events
if S.filter_anom:
    display_evs = [e for e in display_evs if event_score(e) >= S.threshold]

count_label = (
    f"{len(display_evs):,} events"
    + (" - anomalies only" if S.filter_anom else "")
    + f" - {'live' if S.is_live else 'paused'}"
)

st.markdown(
    '<div class="ns-panel">'
    '  <div class="ns-panel-header">'
    '    <span class="ns-panel-title">Event stream</span>'
    f'    <span class="ns-panel-meta">{count_label}</span>'
    '  </div>',
    unsafe_allow_html=True,
)

if display_evs:
    rows_html = ""
    for ev in display_evs[:80]:
        score_val  = event_score(ev)
        is_anom    = score_val >= S.threshold
        scls, stxt = score_class(score_val)
        lbl        = event_label(ev)
        proto      = str(ev.get("proto","TCP")).upper()[:4]
        src        = f'{ev.get("src_ip","?")}:{ev.get("src_port","?")}'
        dst        = f'{ev.get("dst_ip","?")}:{ev.get("dst_port","?")}'
        raw_exe    = str(ev.get("exe") or "")
        exe        = "" if raw_exe.lower() in ("nan", "none", "") else raw_exe
        pid        = ev.get("pid", 0)
        pid_val    = int(pid) if str(pid) not in ("", "nan", "0") else 0
        if exe and pid_val:
            exe_cell = f"{exe} <span style='opacity:0.5'>pid:{pid_val}</span>"
        elif pid_val:
            exe_cell = f"<span style='opacity:0.5'>pid:{pid_val}</span>"
        elif exe:
            exe_cell = exe
        else:
            exe_cell = "<span style='opacity:0.8; font-size:1.4em; letter-spacing:2px'>---</span>"
        dur_raw    = ev.get("duration", 0.0)
        try:
            dur_f = float(dur_raw)
        except (TypeError, ValueError):
            dur_f = 0.0
        if dur_f <= 0:
            dur_str = "\u2014"
        elif dur_f < 0.001:
            dur_str = "&lt;1ms"
        elif dur_f < 1.0:
            dur_str = f"{dur_f*1000:.0f}ms"
        else:
            dur_str = f"{dur_f:.2f}s"
        row_cls    = "ev-anom" if is_anom else ""
        lbl_sty    = label_style(lbl)
        rows_html += (
            f'<tr class="{row_cls}">'
            f'<td class="ev-time">{ev.get("_ts","")}</td>'
            f'<td class="ev-proto">{proto}</td>'
            f'<td class="ev-addr">{src}</td>'
            f'<td class="ev-addr" style="color:{DIM};">{dst}</td>'
            f'<td class="ev-exe-col">{exe_cell}</td>'
            f'<td class="ev-dur">{dur_str}</td>'
            f'<td class="{scls}" style="text-align:right;">{stxt}</td>'
            f'<td style="text-align:right;"><span class="ev-lbl" style="{lbl_sty}">{lbl}</span></td>'
            f'</tr>'
        )
    st.markdown(
        f'<div class="ev-wrap">'
        f'<table class="ev-table"><thead><tr>'
        f'<th>Time</th><th>Proto</th><th>Source</th>'
        f'<th>Destination</th><th>Exe / PID</th>'
        f'<th style="text-align:right;">Duration</th>'
        f'<th style="text-align:right;">Score</th>'
        f'<th style="text-align:right;">Label</th>'
        f'</tr></thead><tbody>{rows_html}</tbody></table></div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="ns-empty-state">No events yet. Start capture or load a data file.</div>',
        unsafe_allow_html=True,
    )

st.markdown('</div>', unsafe_allow_html=True)

# eBPF probe status
probe_statuses = runtime_probe_status(runtime_state)
probe_html = "".join(
    f'<div class="probe-row">'
    f'  <span class="probe-name">{name}</span>'
    f'  <span class="probe-{status}">{status.upper()}</span>'
    f'</div>'
    for name, status in zip(PROBES, probe_statuses)
)
st.markdown(
    '<div class="ns-panel">'
    '  <div class="ns-panel-header">'
    '    <span class="ns-panel-title">eBPF probe status</span>'
    '    <span class="ns-panel-meta">attach state only</span>'
    '  </div>'
    f'  {probe_html}'
    '</div>',
    unsafe_allow_html=True,
)

# Session info and live diagnostics
session_pairs = [
    ("Interface", S.iface or "(none)",                              "info-pill"),
    ("Model",     S.model,                                          ""),
    ("Source",    S.source,                                         ""),
    ("Threshold", f"{S.threshold:.2f}",                             "info-pill"),
    ("Flows",     f"{S.total_flows:,}",                             ""),
    ("Anomalies", f"{S.total_anom:,}",                              ""),
    ("Runtime",   runtime_state.get("status", "missing") if runtime_state else "missing", "info-pill"),
]
session_html = "".join(
    f'<div class="info-row">'
    f'<span class="info-key">{k}</span>'
    f'<span class="info-val">'
    f'<span class="info-main {cls}" style="{"color:" + RED + ";" if k == "Anomalies" and S.total_anom > 0 else ""}">{v}</span>'
    f'</span>'
    f'</div>'
    for k, v, cls in session_pairs
)

diag_html = ""
if S.source == "Live":
    resolved_live_path = resolve_live_event_path(runtime_state)
    _rb = _rebase_daemon_path
    scored_path = str(_rb(runtime_state.get("scored_events_path") or "") if runtime_state.get("scored_events_path") else "")
    raw_path    = str(_rb(runtime_state.get("ebpf_events_path")    or "") if runtime_state.get("ebpf_events_path")    else "")
    merged_path = str(_rb(runtime_state.get("merged_path")         or "") if runtime_state.get("merged_path")         else "")
    state_age     = _state_age_secs(runtime_state) if runtime_state else None
    state_age_txt = f"{state_age:.0f}s ago" if state_age is not None else "unknown"
    diag_pairs = [
        ("State age",     state_age_txt),
        ("Runtime msg",   str(runtime_state.get("message", ""))),
        ("Scoring",       str(runtime_state.get("scoring_message", runtime_state.get("scoring_enabled", "unknown")))),
        ("Live file",     resolved_live_path or "(none)"),
        ("Scored exists", "yes" if scored_path and Path(scored_path).exists() else "no"),
        ("Scored lines",  f"{file_line_count(scored_path):,}"),
        ("Raw exists",    "yes" if raw_path and Path(raw_path).exists() else "no"),
        ("Raw lines",     f"{file_line_count(raw_path):,}"),
        ("Merged exists", "yes" if merged_path and Path(merged_path).exists() else "no"),
        ("Merged lines",  f"{file_line_count(merged_path):,}"),
        ("UI file",       S.file_path or "(none)"),
        ("UI file lines", f"{file_line_count(S.file_path):,}" if S.file_path else "0"),
    ]
    diag_html = "".join(
        f'<div class="info-row">'
        f'<span class="info-key">{k}</span>'
        f'<span class="info-val">{v}</span>'
        f'</div>'
        for k, v in diag_pairs
    )

panel_meta = "runtime + file checks" if S.source == "Live" else "current session"
st.markdown(
    '<div class="ns-panel">'
    '  <div class="ns-panel-header">'
    '    <span class="ns-panel-title">Session &amp; diagnostics</span>'
    f'    <span class="ns-panel-meta">{panel_meta}</span>'
    '  </div>'
    f'  {session_html}'
    f'  {diag_html}'
    '</div>',
    unsafe_allow_html=True,
)

st.markdown('</div>', unsafe_allow_html=True)

# Auto-refresh
should_refresh = False
if S.is_live:
    if S.source == "Live":
        # Refresh when the daemon is active so sync_live_source_from_runtime() can
        # pick up new file paths and stall/recovery transitions are detected promptly.
        # S.file_path may be empty while the daemon is starting up.
        in_transition = (time.time() - (S.last_action_time or 0)) < 12
        should_refresh = capture_state in {"running", "starting", "stalled"} or in_transition
    elif S.source == "File":
        should_refresh = bool(S.file_path)

if should_refresh:
    # If a full chunk is consumed, there is more data pending.
    # Skip the sleep so catch-up runs as fast as possible.
    pending = resolve_repo_path(S.file_path).stat().st_size > S.file_offset if S.file_path else False
    if not pending:
        time.sleep(S.poll_interval)
    st.rerun()
