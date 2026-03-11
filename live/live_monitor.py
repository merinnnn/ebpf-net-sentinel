"""Live monitor page."""

from __future__ import annotations

import json
import math
import os
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

def get_repo_root() -> Path:
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

st.set_page_config(
    page_title="NetSentinel · Live Monitor",
    layout="wide",
    initial_sidebar_state="expanded",
)

ACCENT  = "#00d4ff"
PURPLE  = "#7c3aed"
GREEN   = "#10b981"
ORANGE  = "#f59e0b"
RED     = "#ef4444"
DIM     = "#6b7f96"
SURFACE = "#111620"
BORDER  = "#1e2633"
BG      = "#0a0d12"
TEXT    = "#c8d4e3"

ATTACK_COLORS = {
    "BENIGN":        GREEN,
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

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Syne:wght@700;800&display=swap');

:root {
  --bg:      #0a0d12; --surface: #111620; --surface2: #161d2a;
  --border:  #1e2633; --border2: #2a3444;
  --text:    #c8d4e3; --dim:     #6b7f96;
  --accent:  #00d4ff; --purple:  #7c3aed;
  --green:   #10b981; --orange:  #f59e0b; --red: #ef4444;
}

html, body, [class*="css"] {
  font-family: 'JetBrains Mono', 'Courier New', monospace !important;
  background: var(--bg) !important;
  color: var(--text) !important;
}

.main .block-container {
  background: var(--bg) !important;
  padding-top: 2rem !important;
  padding-left: clamp(1.25rem, 3vw, 2.5rem) !important;
  padding-right: clamp(1.25rem, 3vw, 2.5rem) !important;
  max-width: min(1120px, calc(100vw - 22rem)) !important;
  width: 100% !important;
  margin: 0 auto !important;
}

/* Sidebar */
[data-testid="stSidebar"] {
  background: var(--surface) !important;
  border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { font-family: 'JetBrains Mono', monospace !important; }

/* Metric cards */
[data-testid="metric-container"] {
  background: var(--surface) !important;
  border: 1px solid var(--border) !important;
  border-radius: 7px !important;
  padding: 12px 14px !important;
}
[data-testid="metric-container"] label {
  font-size: 11px !important; letter-spacing: 0.08em !important;
  color: var(--dim) !important; text-transform: uppercase !important;
}
[data-testid="stMetricValue"] { font-weight: 700 !important; font-size: 1.5rem !important; }
[data-testid="stMetricDelta"]  { font-size: 11px !important; }

/* Buttons */
.stButton > button {
  font-family: 'JetBrains Mono', monospace !important;
  background: transparent !important;
  border: 1px solid var(--border2) !important;
  color: var(--dim) !important;
  border-radius: 5px !important;
  font-size: 13px !important;
  letter-spacing: 0.04em !important;
  min-height: 2.75rem !important;
  transition: all 0.12s !important;
}
.stButton > button:hover {
  background: rgba(0,212,255,0.08) !important;
  border-color: var(--accent) !important;
  color: var(--accent) !important;
}

/* Selectbox / inputs */
.stSelectbox > div > div, .stTextInput > div > div > input, .stNumberInput input {
  background: var(--surface2) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 5px !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 13px !important;
  color: var(--text) !important;
}

/* Dataframe */
[data-testid="stDataFrame"] {
  border: 1px solid var(--border) !important;
  border-radius: 7px !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
  background: var(--surface) !important;
  border-bottom: 1px solid var(--border) !important;
}
.stTabs [data-baseweb="tab"] {
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 13px !important;
  color: var(--dim) !important;
  background: transparent !important;
  white-space: normal !important;
  min-height: 2.5rem !important;
}
.stTabs [aria-selected="true"] {
  color: var(--accent) !important;
  border-bottom: 2px solid var(--accent) !important;
}

/* Toggle / radio */
.stRadio > div { gap: 6px !important; }
.stRadio [data-testid="stMarkdownContainer"] p {
  font-size: 13px !important;
  font-family: 'JetBrains Mono', monospace !important;
}

/* Slider */
[data-testid="stSlider"] { padding: 4px 0 !important; }

/* Expander */
[data-testid="stExpander"] {
  background: var(--surface) !important;
  border: 1px solid var(--border) !important;
  border-radius: 7px !important;
}

/* Alerts */
.stAlert { border-radius: 6px !important; font-family: 'JetBrains Mono', monospace !important; }

/* Divider */
hr { border-color: var(--border) !important; }

/* Custom page elements */
.ns-topbar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 0 16px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 18px;
}
.ns-logo {
  font-family: 'Syne', sans-serif;
  font-size: 25px; font-weight: 800;
  color: var(--accent); letter-spacing: 0.01em;
}
.ns-page-label {
  font-size: 11px; font-weight: 700;
  letter-spacing: 0.08em; color: var(--dim);
  text-transform: uppercase; margin-left: 14px;
}
.ns-research-badge {
  font-size: 11px; font-weight: 600;
  color: var(--orange);
  background: rgba(245,158,11,0.1);
  border: 1px solid rgba(245,158,11,0.3);
  border-radius: 4px; padding: 4px 12px;
  letter-spacing: 0.05em;
}
.ns-status-live {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.08em;
  color: var(--green);
  background: rgba(16,185,129,0.1);
  border: 1px solid rgba(16,185,129,0.35);
  border-radius: 20px; padding: 4px 12px;
}
.ns-status-paused {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.08em;
  color: var(--orange);
  background: rgba(245,158,11,0.1);
  border: 1px solid rgba(245,158,11,0.35);
  border-radius: 20px; padding: 4px 12px;
}
.ns-dot-live {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--green);
  animation: blink 1.3s ease-in-out infinite;
  display: inline-block;
}
.ns-dot-paused { width: 7px; height: 7px; border-radius: 50%; background: var(--orange); display: inline-block; }
@keyframes blink { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.35;transform:scale(.65)} }

.ns-panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 12px;
}
.ns-panel-title {
  font-size: 1rem; font-weight: 700;
  letter-spacing: 0.12em; color: var(--dim);
  text-transform: uppercase; margin-bottom: 10px;
}
.ns-section {
  font-size: 1rem; font-weight: 700;
  letter-spacing: 0.12em; color: var(--dim);
  text-transform: uppercase; margin: 10px 0 6px;
}

/* Event list table */
.ev-table { width: 100%; border-collapse: collapse; }
.ev-table thead th {
  font-size: 0.9rem; font-weight: 700;
  letter-spacing: 0.08em; color: var(--dim);
  text-transform: uppercase;
  padding: 5px 8px;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  text-align: left;
}
.ev-table tbody tr {
  border-bottom: 1px solid rgba(26,35,51,0.7);
  transition: background 0.1s;
}
.ev-table tbody tr:hover { background: rgba(22,29,42,0.8); }
.ev-table tbody tr.ev-anom { border-left: 2px solid var(--red); background: rgba(239,68,68,0.04); }
.ev-table tbody tr.ev-anom:hover { background: rgba(239,68,68,0.07); }
.ev-table td { font-size: 1rem; padding: 7px 8px; }
.ev-time  { color: var(--dim); font-size: 0.95rem !important; white-space: nowrap; }
.ev-proto { color: var(--dim); }
.ev-addr  { font-variant-numeric: tabular-nums; white-space: nowrap; }
.ev-score-low  { color: var(--green);  font-weight: 600; }
.ev-score-mid  { color: var(--orange); font-weight: 600; }
.ev-score-high { color: var(--red);    font-weight: 600; }

.lbl {
  display: inline-block;
  font-size: 0.9rem; font-weight: 700;
  letter-spacing: 0.05em;
  padding: 2px 6px; border-radius: 2px;
}

/* Probe status rows */
.probe-row {
  display: flex; align-items: center; justify-content: space-between;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 5px; padding: 8px 10px;
  margin-bottom: 6px; font-size: 1rem;
}
.probe-name { color: var(--text); }
.probe-count { color: var(--dim); font-variant-numeric: tabular-nums; font-size: 0.95rem; }
.probe-ok   { color: var(--green);  background: rgba(16,185,129,0.12); border-radius: 3px; padding: 2px 8px; font-size: 0.9rem; font-weight: 700; }
.probe-warn { color: var(--orange); background: rgba(245,158,11,0.12);  border-radius: 3px; padding: 2px 8px; font-size: 0.9rem; font-weight: 700; }
.probe-err  { color: var(--red);    background: rgba(239,68,68,0.12);   border-radius: 3px; padding: 2px 8px; font-size: 0.9rem; font-weight: 700; }

.iface-stat {
  display: flex; justify-content: space-between; align-items: center;
  padding: 5px 0; border-bottom: 1px solid var(--border);
  font-size: 1rem;
}
.iface-stat:last-child { border-bottom: none; }
.iface-key { color: var(--dim); }
.iface-val { color: var(--text); font-variant-numeric: tabular-nums; }
</style>
""", unsafe_allow_html=True)

def load_runtime_state() -> dict:
    if not RUNTIME_STATE_PATH.exists():
        return {}
    try:
        return json.loads(RUNTIME_STATE_PATH.read_text())
    except Exception:
        return {}

def resolve_repo_path(path_str: str) -> Path:
    p = Path(path_str).expanduser()
    if p.is_absolute():
        return p
    return (REPO / p).resolve()

def default_live_event_path() -> str:
    state = load_runtime_state()
    event_path = state.get("ebpf_events_path")
    if event_path and Path(event_path).exists():
        return str(Path(event_path))
    run_dir = state.get("run_dir")
    if run_dir:
        candidate = Path(run_dir) / "ebpf_events.jsonl"
        if candidate.exists():
            return str(candidate)
    return ""

def runtime_probe_status(runtime_state: dict) -> list[str]:
    status = runtime_state.get("status")
    if status == "running":
        return ["ok"] * len(PROBES)
    if status == "error":
        return ["err"] * len(PROBES)
    if status == "starting":
        return ["warn"] * len(PROBES)
    return ["warn"] * len(PROBES)

def sync_live_source_from_runtime() -> None:
    runtime_state = load_runtime_state()
    if not runtime_state:
        return

    runtime_iface = runtime_state.get("interface")
    runtime_file = runtime_state.get("ebpf_events_path") or default_live_event_path()

    if runtime_iface:
        S.iface = runtime_iface

    if runtime_file and S.file_path != runtime_file:
        S.file_path = runtime_file
        S.file_offset = 0
        S.events = []
        S.total_flows = 0
        S.total_anom = 0
        S.threat_counts = {}
        S.pps_series = []
        S.start_time = time.time()

    S.run_dir = runtime_state.get("run_dir") or ""

def _init():
    runtime_state = load_runtime_state()
    defaults = {
        "is_live":        True,
        "source":         "Live",
        "file_path":      default_live_event_path(),
        "ws_url":         "ws://localhost:8765/events",
        "iface":          runtime_state.get("interface") or "",
        "model":          "eBPF Enriched",
        "threshold":      0.50,
        "poll_interval":  1,
        "events":         [],
        "total_flows":    0,
        "total_anom":     0,
        "start_time":     time.time(),
        "threat_counts":  {},
        "pps_series":     [],
        "file_offset":    0,
        "filter_anom":    False,
        "run_dir":        "",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init()
S = st.session_state

PROBES = [
    "kprobe/tcp_connect",
    "kprobe/tcp_close",
    "kprobe/udp_sendmsg",
    "socket/filter",
    "tracepoint/sys_bind",
]
def read_file_events(path: str, offset: int) -> tuple[list[dict], int]:
    p = resolve_repo_path(path)
    if not p.exists():
        return [], 0
    size = p.stat().st_size
    if offset > size:
        offset = 0
    evs = []
    with open(p, "rb") as f:
        f.seek(offset)
        chunk = f.read()
        new_offset = offset + len(chunk)
    for line in chunk.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
            ev.setdefault("_ts", datetime.now().strftime("%H:%M:%S"))
            evs.append(ev)
        except Exception:
            pass
    return evs, new_offset

def score_class(s):
    try:
        v = float(s)
        if v < 0.35:  return "ev-score-low",  f"{v:.3f}"
        if v < 0.65:  return "ev-score-mid",  f"{v:.3f}"
        return "ev-score-high", f"{v:.3f}"
    except Exception:
        return "ev-score-low", "—"

def label_style(lbl: str):
    col = ATTACK_COLORS.get(lbl, ATTACK_COLORS["Unknown"])
    return f'background:{col}18;color:{col};border:1px solid {col}44;'

def uptime_str(start: float) -> str:
    s = int(time.time() - start)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}" if h else f"{m:02d}:{sec:02d}"

def ingest(evs: list[dict]):
    if not evs:
        return
    S.total_flows += len(evs)
    anom = [e for e in evs if float(e.get("anomaly_score", 0)) >= S.threshold]
    S.total_anom += len(anom)
    for e in evs:
        lbl = e.get("label", "BENIGN")
        if lbl not in S.threat_counts:
            S.threat_counts[lbl] = 0
        S.threat_counts[lbl] += 1
    new_rows = list(reversed(evs[-50:]))  # cap per tick
    S.events = new_rows + S.events
    S.events = S.events[:300]   # keep last 300

with st.sidebar:
    st.markdown(
        '<div style="font-family:\'Syne\',\'Segoe UI Semibold\',sans-serif;font-size:25px;font-weight:800;'
        'color:#00d4ff;letter-spacing:0.01em;padding:8px 0 2px;line-height:1;">NET·SENTINEL</div>'
        '<div style="font-size:11px;color:#6b7f96;margin:4px 0 14px;">Live Monitor</div>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("Stop" if S.is_live else "Start", use_container_width=True):
            S.is_live = not S.is_live
    with col_b:
        if st.button("Clear", use_container_width=True):
            S.events        = []
            S.total_flows   = 0
            S.total_anom    = 0
            S.threat_counts = {}
            S.pps_series    = []
            S.file_offset   = 0
            S.start_time    = time.time()

    st.markdown('<p class="ns-section">Data Source</p>', unsafe_allow_html=True)
    source_options = ["Live", "File", "WebSocket"]
    current_source = S.source if S.source in source_options else "Live"
    S.source = st.selectbox("Source", source_options,
                             index=source_options.index(current_source),
                             label_visibility="collapsed")

    if S.source == "Live":
        runtime_state = load_runtime_state()
        live_path = runtime_state.get("ebpf_events_path") or S.file_path or "(waiting for live capture)"
        st.caption("Following the current live capture selected in `ubuntu/run_live.sh`.")
        st.caption(f"Live event file: `{live_path}`")
    elif S.source == "File":
        S.file_path = st.text_input("JSONL file path", value=S.file_path,
                                     placeholder="data/runs/live_YYYY-MM-DD_HHMMSS/ebpf_events.jsonl")
        st.caption(
            "Point this at a real capture file under `data/runs/live_*/ebpf_events.jsonl`."
        )
    elif S.source == "WebSocket":
        S.ws_url = st.text_input("WebSocket URL", value=S.ws_url)
        st.caption("Backend sends JSON events over WebSocket. The merged Zeek and eBPF stream is not connected here yet.")

    st.markdown('<p class="ns-section">Capture Config</p>', unsafe_allow_html=True)
    S.iface     = st.text_input("Interface", value=S.iface)
    S.model     = st.selectbox("Model", ["eBPF Enriched","Baseline"],
                                index=0 if S.model=="eBPF Enriched" else 1)
    S.threshold = st.slider("Anomaly threshold", 0.0, 1.0, S.threshold, 0.01)
    S.poll_interval = st.select_slider("Refresh (s)",
                                        options=[0.5, 1, 2, 3, 5],
                                        value=S.poll_interval)
    S.filter_anom = st.checkbox("Show anomalies only", value=S.filter_anom)

    st.markdown("---")
    runtime_state = load_runtime_state()
    if runtime_state:
        status = runtime_state.get("status", "unknown")
        message = runtime_state.get("message") or "no message"
        st.caption(f"Runtime state: `{RUNTIME_STATE_PATH}` | {status}: {message}")
        zeek_conn_path = runtime_state.get("zeek_conn_path")
        merged_path = runtime_state.get("merged_path")
        if zeek_conn_path:
            st.caption(f"Zeek live flow file: `{zeek_conn_path}`")
        if merged_path:
            st.caption(f"eBPF+Zeek live flow file: `{merged_path}`")
    st.markdown(
        f'<div style="font-size:8px;color:{ORANGE};background:rgba(245,158,11,0.08);'
        f'border:1px solid rgba(245,158,11,0.25);border-radius:4px;padding:7px 10px;">'
        f'For research use only.<br>Not for production use.</div>',
        unsafe_allow_html=True,
    )

new_evs: list[dict] = []
runtime_state = load_runtime_state()
if S.source == "Live":
    sync_live_source_from_runtime()
    runtime_state = load_runtime_state()

if S.is_live:
    if S.source in {"Live", "File"} and S.file_path:
        new_evs, S.file_offset = read_file_events(S.file_path, S.file_offset)
    # WebSocket data is handled on the client side.

ingest(new_evs)

status_html = (
    f'<span class="ns-status-live"><span class="ns-dot-live"></span>Live</span>'
    if S.is_live else
    f'<span class="ns-status-paused"><span class="ns-dot-paused"></span>Paused</span>'
)
st.markdown(
    f'<div class="ns-topbar">'
    f'<div style="display:flex;align-items:baseline;gap:14px;">'
    f'  <span class="ns-logo">NET·SENTINEL</span>'
    f'  <span class="ns-page-label">Live Monitor</span>'
    f'</div>'
    f'<div style="display:flex;align-items:center;gap:12px;">'
    f'  <span class="ns-research-badge">Research use only</span>'
    f'  {status_html}'
    f'</div>'
    f'</div>',
    unsafe_allow_html=True,
)

anom_rate = (S.total_anom / S.total_flows * 100) if S.total_flows > 0 else 0.0
last_pps  = len(new_evs)
last_score = (
    sum(float(e.get("anomaly_score", 0)) for e in new_evs) / len(new_evs)
    if new_evs else 0.0
)
ebpf_eps  = S.total_flows

k1, k2, k3, k4, k5 = st.columns(5)
with k1:
    st.metric("Flows / sec",   last_pps,
              delta=f"total {S.total_flows:,}")
with k2:
    st.metric("Anomaly Rate",  f"{anom_rate:.1f}%",
              delta=f"{S.total_anom:,} anomalies")
with k3:
    st.metric("eBPF Events",   f"{ebpf_eps:,}",
              delta="raw event rows")
with k4:
    st.metric("Avg Score",     f"{last_score:.3f}")
with k5:
    st.metric("Uptime",        uptime_str(S.start_time),
              delta=f"iface: {S.iface}")

st.markdown(f"""
<style>
div[data-testid="metric-container"]:nth-of-type(1) [data-testid="stMetricValue"] {{ color:{ACCENT} !important; }}
div[data-testid="metric-container"]:nth-of-type(2) [data-testid="stMetricValue"] {{ color:{RED} !important; }}
div[data-testid="metric-container"]:nth-of-type(3) [data-testid="stMetricValue"] {{ color:{PURPLE} !important; }}
div[data-testid="metric-container"]:nth-of-type(4) [data-testid="stMetricValue"] {{ color:{ORANGE} !important; }}
div[data-testid="metric-container"]:nth-of-type(5) [data-testid="stMetricValue"] {{ color:{GREEN} !important; }}
</style>
""", unsafe_allow_html=True)

st.markdown('<hr style="margin:10px 0;">', unsafe_allow_html=True)

col_main, col_side = st.columns([3, 1], gap="medium")

with col_main:
    try:
        import plotly.graph_objects as go
        HAS_PLOTLY = True
    except ImportError:
        HAS_PLOTLY = False

    S.pps_series.append({
        "t":     datetime.now().strftime("%H:%M:%S"),
        "pps":   last_pps,
        "score": last_score,
    })
    S.pps_series = S.pps_series[-120:]

    st.markdown('<p class="ns-section">Flow rate &amp; anomaly score · rolling window</p>',
                unsafe_allow_html=True)

    if HAS_PLOTLY and len(S.pps_series) >= 2:
        df_ts = pd.DataFrame(S.pps_series)
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df_ts["t"], y=df_ts["pps"],
            name="Flows/s",
            line=dict(color=ACCENT, width=1.8),
            fill="tozeroy",
            fillcolor="rgba(0,212,255,0.10)",
            hovertemplate="%{x}  Flows/s: %{y}<extra></extra>",
        ))
        fig.add_trace(go.Scatter(
            x=df_ts["t"], y=df_ts["score"],
            name="Avg score",
            line=dict(color=RED, width=1.4, dash="dot"),
            yaxis="y2",
            hovertemplate="%{x}  Score: %{y:.3f}<extra></extra>",
        ))
        fig.add_hline(y=S.threshold, yref="y2",
                      line=dict(color=ORANGE, width=1, dash="dash"),
                      annotation_text=f"threshold {S.threshold:.2f}",
                      annotation_font_size=8,
                      annotation_font_color=ORANGE)
        fig.update_layout(
            paper_bgcolor=BG, plot_bgcolor=SURFACE,
            font=dict(family="JetBrains Mono, Courier New, monospace",
                      color=TEXT, size=9),
            margin=dict(l=40, r=50, t=14, b=30),
            height=160,
            xaxis=dict(gridcolor=BORDER, linecolor=BORDER,
                       tickfont=dict(size=8), nticks=8),
            yaxis=dict(title="Flows/s", gridcolor=BORDER,
                       linecolor=BORDER, tickfont=dict(size=8)),
            yaxis2=dict(title="Score", overlaying="y", side="right",
                        range=[0, 1], gridcolor="rgba(0,0,0,0)",
                        tickfont=dict(size=8)),
            legend=dict(bgcolor=SURFACE, bordercolor=BORDER,
                        font=dict(size=9), x=0.01, y=0.98,
                        orientation="h"),
            hovermode="x unified",
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    elif not HAS_PLOTLY:
        st.info("Install plotly for the time-series chart:  pip install plotly")
    else:
        st.markdown(
            f'<div style="height:160px;background:{SURFACE};border:1px solid {BORDER};'
            f'border-radius:7px;display:flex;align-items:center;justify-content:center;'
            f'font-size:1rem;color:{DIM};">Waiting for data.</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<p class="ns-section" style="margin-top:14px;">Event stream</p>',
                unsafe_allow_html=True)

    display_evs = S.events
    if S.filter_anom:
        display_evs = [e for e in display_evs
                       if float(e.get("anomaly_score", 0)) >= S.threshold]

    count_label = f"{len(display_evs)} events" + (" (anomalies only)" if S.filter_anom else "")
    st.markdown(
        f'<p style="font-size:0.95rem;color:{DIM};margin:0 0 6px;">{count_label}</p>',
        unsafe_allow_html=True,
    )

    if display_evs:
        rows_html = ""
        for ev in display_evs[:80]:
            score_val = float(ev.get("anomaly_score", 0))
            is_anom   = score_val >= S.threshold
            scls, stxt = score_class(ev.get("anomaly_score"))
            lbl       = ev.get("label", "BENIGN")
            proto     = str(ev.get("proto","TCP")).upper()[:4]
            src       = f'{ev.get("src_ip","?")}:{ev.get("src_port","?")}'
            dst       = f'{ev.get("dst_ip","?")}:{ev.get("dst_port","?")}'
            exe       = ev.get("exe","")
            pid_str   = f'<span style="color:{DIM};font-size:0.95rem;">&nbsp;{exe}:{ev.get("pid","")}</span>' if exe else ""
            row_cls   = "ev-anom" if is_anom else ""
            lbl_sty   = label_style(lbl)
            rows_html += (
                f'<tr class="{row_cls}">'
                f'<td class="ev-time">{ev.get("_ts","")}</td>'
                f'<td class="ev-proto">{proto}</td>'
                f'<td class="ev-addr">{src}{pid_str}</td>'
                f'<td class="ev-addr" style="color:{DIM};">{dst}</td>'
                f'<td class="{scls}" style="text-align:right;">{stxt}</td>'
                f'<td style="text-align:right;">'
                f'<span class="lbl" style="{lbl_sty}">{lbl}</span>'
                f'</td>'
                f'</tr>'
            )

        st.markdown(
            f'<div style="max-height:340px;overflow-y:auto;'
            f'border:1px solid {BORDER};border-radius:7px;">'
            f'<table class="ev-table">'
            f'<thead><tr>'
            f'<th>TIME</th><th>PROTO</th><th>SOURCE</th>'
            f'<th>DESTINATION</th><th style="text-align:right;">SCORE</th>'
            f'<th style="text-align:right;">LABEL</th>'
            f'</tr></thead>'
            f'<tbody>{rows_html}</tbody>'
            f'</table></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div style="background:{SURFACE};border:1px solid {BORDER};'
            f'border-radius:7px;padding:32px;text-align:center;'
            f'font-size:1rem;color:{DIM};">No events yet. Start capture or load data.</div>',
            unsafe_allow_html=True,
        )

with col_side:
    st.markdown('<p class="ns-section">eBPF Attach Status</p>', unsafe_allow_html=True)
    st.caption("Per-probe event counters are not emitted by the live daemon; only attach status is shown.")
    probe_statuses = runtime_probe_status(runtime_state)
    probe_html = ""
    for i, (name, status) in enumerate(zip(PROBES, probe_statuses)):
        probe_html += (
            f'<div class="probe-row">'
            f'<span class="probe-name" style="font-size:0.95rem;">{name}</span>'
            f'<div style="display:flex;align-items:center;gap:8px;">'
            f'<span class="probe-{status}">{status.upper()}</span>'
            f'</div></div>'
        )
    st.markdown(probe_html, unsafe_allow_html=True)

    st.markdown('<p class="ns-section">Threat Distribution</p>', unsafe_allow_html=True)
    if S.threat_counts:
        df_th = (pd.DataFrame(list(S.threat_counts.items()), columns=["Label","Count"])
                   .sort_values("Count", ascending=False))

        if HAS_PLOTLY:
            colors = [ATTACK_COLORS.get(r, DIM) for r in df_th["Label"]]
            fig2 = go.Figure(go.Pie(
                labels=df_th["Label"], values=df_th["Count"],
                marker_colors=colors,
                hole=0.52,
                textfont=dict(size=11, family="JetBrains Mono"),
                hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
                showlegend=False,
            ))
            fig2.update_layout(
                paper_bgcolor=BG,
                margin=dict(l=10, r=10, t=10, b=10),
                height=160,
            )
            st.plotly_chart(fig2, use_container_width=True,
                            config={"displayModeBar": False})

        for _, row in df_th.head(6).iterrows():
            col = ATTACK_COLORS.get(row["Label"], DIM)
            pct = row["Count"] / df_th["Count"].sum() * 100
            st.markdown(
                f'<div style="display:flex;align-items:center;justify-content:space-between;'
                f'padding:4px 0;font-size:1rem;">'
                f'<div style="display:flex;align-items:center;gap:7px;">'
                f'<div style="width:8px;height:8px;border-radius:2px;background:{col};flex-shrink:0;"></div>'
                f'<span style="color:{TEXT};">{row["Label"]}</span></div>'
                f'<span style="color:{DIM};font-variant-numeric:tabular-nums;">'
                f'{int(row["Count"]):,} &nbsp;<span style="color:{DIM}88;">{pct:.0f}%</span>'
                f'</span></div>',
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            f'<div style="font-size:1rem;color:{DIM};padding:12px 0;">No data yet.</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<p class="ns-section" style="margin-top:12px;">Capture Info</p>',
                unsafe_allow_html=True)
    stats = [
        ("Interface",  S.iface),
        ("Model",      S.model),
        ("Threshold",  f"{S.threshold:.2f}"),
        ("Source",     S.source),
        ("Total flows",f"{S.total_flows:,}"),
        ("Anomalies",  f"{S.total_anom:,}"),
    ]
    info_html = ""
    for k, v in stats:
        val_style = f"color:{RED};" if k == "Anomalies" and S.total_anom > 0 else ""
        info_html += (
            f'<div class="iface-stat">'
            f'<span class="iface-key">{k}</span>'
            f'<span class="iface-val" style="{val_style}">{v}</span>'
            f'</div>'
        )
    st.markdown(
        f'<div style="background:{SURFACE};border:1px solid {BORDER};'
        f'border-radius:7px;padding:10px 12px;">{info_html}</div>',
        unsafe_allow_html=True,
    )

if S.is_live:
    time.sleep(S.poll_interval)
    st.rerun()
