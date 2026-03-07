from __future__ import annotations

import html

import streamlit as st

from utils.charts import donut_chart, horizontal_bar
from utils.data import (
    get_dashboard_alerts,
    get_dashboard_kpis,
    get_live_event_stream,
    get_probe_status_snapshot,
    get_protocol_breakdown_snapshot,
    get_threat_distribution_snapshot,
)
from utils.styles import COLORS, inject_css, probe_card, render_app_sidebar


st.set_page_config(page_title="Dashboard · NetSentinel", layout="wide", initial_sidebar_state="expanded")
inject_css()


def _inject_dashboard_css() -> None:
    st.markdown(
        f"""
        <style>
        .block-container {{
            padding-top: 1rem;
            max-width: 1480px;
        }}
        .ns-dashboard-top {{
            border-top: 1px solid {COLORS["border"]};
            border-bottom: 1px solid {COLORS["border"]};
            padding: 1rem 0 1.05rem 0;
            margin-bottom: 0.85rem;
        }}
        .ns-dashboard-title {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
        }}
        .ns-dashboard-title h1 {{
            margin: 0;
            font-size: 2rem;
            line-height: 1;
        }}
        .ns-dashboard-title p {{
            margin: 0.45rem 0 0 0;
            color: {COLORS["text_muted"]};
            font-size: 0.88rem;
        }}
        .ns-status-line {{
            color: {COLORS["text_muted"]};
            font-size: 0.84rem;
            padding-top: 0.1rem;
            white-space: nowrap;
        }}
        .ns-filter-shell {{
            background: {COLORS["surface"]};
            border-top: 1px solid {COLORS["border"]};
            border-bottom: 1px solid {COLORS["border"]};
            padding: 0.58rem 0;
            margin-bottom: 0.7rem;
        }}
        .ns-filter-row {{
            display: flex;
            align-items: center;
            gap: 2rem;
            flex-wrap: nowrap;
        }}
        .ns-filter-group {{
            display: flex;
            align-items: center;
            gap: 0.45rem;
            min-width: 0;
        }}
        .ns-filter-label {{
            color: {COLORS["text_muted"]};
            font-size: 0.68rem;
            letter-spacing: 0.18em;
            text-transform: uppercase;
            margin-right: 0.3rem;
            white-space: nowrap;
        }}
        .ns-filter-link {{
            display: block;
        }}
        .ns-filter-sep {{
            width: 1px;
            height: 22px;
            background: #2a3444;
        }}
        .ns-filter-link div[data-testid="stButton"] {{
            width: 100%;
        }}
        .ns-filter-link button {{
            min-width: 28px;
            height: 22px;
            padding: 0 0.5rem;
            border-radius: 4px;
            border: 1px solid #2a3444;
            color: {COLORS["text_muted"]};
            font-size: 0.76rem;
            background: transparent;
            box-shadow: none;
            line-height: 1;
        }}
        .ns-filter-link.active button {{
            color: {COLORS["cyan"]};
            border-color: {COLORS["cyan"]};
            background: rgba(0, 212, 255, 0.14);
            font-weight: 600;
        }}
        .ns-filter-link button:hover {{
            border-color: #3a4658;
            color: {COLORS["text_body"]};
        }}
        .ns-filter-link.active button:hover {{
            border-color: {COLORS["cyan"]};
            color: {COLORS["cyan"]};
            background: rgba(0, 212, 255, 0.18);
        }}
        .ns-run-link button {{
            min-width: 120px;
        }}
        .ns-run-select label {{
            display: none !important;
        }}
        .ns-run-select div[data-baseweb="select"] > div {{
            min-height: 28px;
            border-radius: 4px;
            border-color: #2a3444;
            background: transparent;
            box-shadow: none;
        }}
        .ns-run-select div[data-baseweb="select"] span {{
            color: {COLORS["text_body"]};
            font-size: 0.78rem;
        }}
        .ns-kpi-card {{
            background: linear-gradient(90deg, rgba(17, 22, 32, 1) 0%, rgba(17, 22, 32, 1) 76%, rgba(0, 212, 255, 0.08) 100%);
            border: 1px solid {COLORS["border"]};
            border-radius: 10px;
            padding: 0.95rem 0.95rem 0.9rem 0.95rem;
            min-height: 88px;
        }}
        .ns-kpi-spacer {{
            height: 0.8rem;
        }}
        .ns-kpi-label {{
            color: {COLORS["text_muted"]};
            font-size: 0.72rem;
            letter-spacing: 0.14em;
        }}
        .ns-kpi-value {{
            margin-top: 0.58rem;
            font-size: 1.95rem;
            font-weight: 700;
            line-height: 1;
        }}
        .ns-kpi-delta {{
            margin-top: 0.55rem;
            font-size: 0.82rem;
        }}
        .ns-chip {{
            display: inline-block;
            padding: 0.18rem 0.56rem;
            border-radius: 6px;
            font-size: 0.74rem;
            font-weight: 600;
            border: 1px solid currentColor;
            white-space: nowrap;
        }}
        .ns-probe-shell {{
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 0.9rem;
        }}
        div[data-testid="stVerticalBlockBorderWrapper"] {{
            background:
                radial-gradient(circle at top right, rgba(0, 212, 255, 0.08), transparent 28%),
                linear-gradient(180deg, rgba(255, 255, 255, 0.02) 0%, rgba(255, 255, 255, 0.01) 100%),
                {COLORS["card"]};
            border: 1px solid {COLORS["border"]};
            border-radius: 18px;
            box-shadow: 0 0 0 1px rgba(0, 212, 255, 0.02), 0 12px 40px rgba(0, 0, 0, 0.22);
            padding: 0.25rem 0.5rem 0.45rem 0.5rem;
            height: 100%;
        }}
        div[data-testid="stVerticalBlockBorderWrapper"]:has(.ns-panel-alerts) {{
            min-height: 332px;
        }}
        div[data-testid="stVerticalBlockBorderWrapper"]:has(.ns-panel-threat) {{
            min-height: 332px;
        }}
        div[data-testid="stVerticalBlockBorderWrapper"]:has(.ns-panel-stream) {{
            min-height: 308px;
        }}
        div[data-testid="stVerticalBlockBorderWrapper"]:has(.ns-panel-protocol) {{
            min-height: 308px;
        }}
        div[data-testid="stVerticalBlockBorderWrapper"]:has(.ns-panel-probes) {{
            min-height: 150px;
        }}
        .ns-panel-head {{
            padding: 0.2rem 0 0.7rem 0;
            margin-bottom: 0.4rem;
            border-bottom: 1px solid rgba(30, 38, 51, 0.65);
        }}
        .ns-panel-head h3 {{
            margin: 0;
            font-size: 1.12rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.02em;
        }}
        .ns-panel-head p {{
            margin: 0.45rem 0 0 0;
            color: {COLORS["text_muted"]};
            font-size: 0.84rem;
        }}
        .ns-panel-body {{
            display: flex;
            flex-direction: column;
            height: calc(100% - 3.5rem);
        }}
        .ns-panel-body.compact {{
            height: calc(100% - 3.1rem);
        }}
        .ns-threat-legend {{
            margin-top: auto;
        }}
        @media (max-width: 1100px) {{
            .ns-filter-row {{
                gap: 0.8rem 1.2rem;
            }}
            .ns-probe-shell {{
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }}
            div[data-testid="stVerticalBlockBorderWrapper"]:has(.ns-panel-alerts),
            div[data-testid="stVerticalBlockBorderWrapper"]:has(.ns-panel-threat),
            div[data-testid="stVerticalBlockBorderWrapper"]:has(.ns-panel-stream),
            div[data-testid="stVerticalBlockBorderWrapper"]:has(.ns-panel-protocol),
            div[data-testid="stVerticalBlockBorderWrapper"]:has(.ns-panel-probes) {{
                min-height: auto;
            }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _panel_header(title: str, subtitle: str, panel_class: str) -> None:
    st.markdown(
        f"""
        <div class="ns-panel-head {panel_class}">
            <h3>{html.escape(title)}</h3>
            <p>{html.escape(subtitle)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _status_chip(value: str) -> tuple[str, str]:
    mapping = {
        "OPEN": (COLORS["red"], "rgba(239, 68, 68, 0.10)"),
        "REVIEW": (COLORS["amber"], "rgba(245, 158, 11, 0.10)"),
        "CLOSED": (COLORS["green"], "rgba(16, 185, 129, 0.10)"),
    }
    return mapping.get(value, (COLORS["text_muted"], "rgba(107, 127, 150, 0.10)"))


def _attack_chip(value: str) -> tuple[str, str]:
    attack = value.lower()
    if "benign" in attack:
        return COLORS["green"], "rgba(16, 185, 129, 0.10)"
    if "port" in attack:
        return COLORS["amber"], "rgba(245, 158, 11, 0.10)"
    return COLORS["red"], "rgba(239, 68, 68, 0.10)"


def _render_metric_card(label: str, value: str, delta: str, color: str) -> None:
    delta_color = COLORS["green"] if label in {"FLOWS ANALYSED", "ROC-AUC (EBPF)"} else color
    st.markdown(
        f"""
        <div class="ns-kpi-card">
            <div class="ns-kpi-label">{html.escape(label)}</div>
            <div class="ns-kpi-value" style="color:{color};">{html.escape(value)}</div>
            <div class="ns-kpi-delta" style="color:{delta_color};">{html.escape(delta)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_alert_table() -> None:
    alerts = get_dashboard_alerts()
    critical_count = int((alerts["status"] == "OPEN").sum())
    with st.container(border=True):
        _panel_header("Recent Alerts", "Last 50 anomaly events - sorted by score desc", "ns-panel-alerts")
        st.markdown('<div class="ns-panel-body">', unsafe_allow_html=True)
        st.markdown(
            f"""
            <div style="display:flex; justify-content:flex-end; margin-bottom:0.45rem;">
                <div style="
                    color:{COLORS["red"]};
                    border:1px solid rgba(239,68,68,0.32);
                    background:rgba(239,68,68,0.08);
                    border-radius:999px;
                    padding:0.25rem 0.58rem;
                    font-size:0.72rem;
                    font-weight:600;
                ">{critical_count} CRITICAL</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        headers = st.columns([0.9, 1.5, 1.45, 1.1, 0.75, 0.75, 0.85, 0.9], gap="small")
        for col, label in zip(headers, ["TIME", "SRC IP", "DST", "ATTACK", "SCORE", "MODEL", "RUN", "STATUS"]):
            col.markdown(
                f"<div style='color:{COLORS['text_muted']}; font-size:0.71rem; letter-spacing:0.1em; padding-bottom:0.42rem; border-bottom:1px solid {COLORS['border']};'>{label}</div>",
                unsafe_allow_html=True,
            )
        for row_idx, (_, row) in enumerate(alerts.iterrows()):
            attack_color, attack_bg = _attack_chip(str(row["attack"]))
            status_color, status_bg = _status_chip(str(row["status"]))
            score_color = COLORS["green"] if float(row["score"]) < 0.2 else COLORS["amber"] if float(row["score"]) < 0.9 else COLORS["red"]
            row_cols = st.columns([0.9, 1.5, 1.45, 1.1, 0.75, 0.75, 0.85, 0.9], gap="small")
            row_cols[0].markdown(f"<div style='padding-top:0.52rem;'>{html.escape(str(row['time']))}</div>", unsafe_allow_html=True)
            row_cols[1].markdown(f"<div style='padding-top:0.52rem; color:{COLORS['cyan']};'>{html.escape(str(row['src_ip']))}</div>", unsafe_allow_html=True)
            row_cols[2].markdown(f"<div style='padding-top:0.52rem;'>{html.escape(str(row['dst']))}</div>", unsafe_allow_html=True)
            row_cols[3].markdown(
                f"<div style='padding-top:0.36rem;'><span class='ns-chip' style='color:{attack_color}; background:{attack_bg};'>{html.escape(str(row['attack']))}</span></div>",
                unsafe_allow_html=True,
            )
            row_cols[4].markdown(f"<div style='padding-top:0.52rem; color:{score_color};'>{row['score']:.2f}</div>", unsafe_allow_html=True)
            row_cols[5].markdown(f"<div style='padding-top:0.52rem; color:{COLORS['purple']};'>{html.escape(str(row['model']))}</div>", unsafe_allow_html=True)
            row_cols[6].markdown(f"<div style='padding-top:0.52rem;'>{html.escape(str(row['run']))}</div>", unsafe_allow_html=True)
            row_cols[7].markdown(
                f"<div style='padding-top:0.36rem;'><span class='ns-chip' style='color:{status_color}; background:{status_bg};'>{html.escape(str(row['status']))}</span></div>",
                unsafe_allow_html=True,
            )
            if row_idx < len(alerts) - 1:
                st.markdown(f"<div style='border-top:1px solid rgba(30, 38, 51, 0.32); margin-top:0.35rem;'></div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)


def _render_live_stream() -> None:
    stream = get_live_event_stream()
    with st.container(border=True):
        _panel_header("Live Event Stream", "Real-time classification - newest first - auto-scroll", "ns-panel-stream")
        st.markdown('<div class="ns-panel-body compact">', unsafe_allow_html=True)
        for row_idx, (_, row) in enumerate(stream.iterrows()):
            attack_color, attack_bg = _attack_chip(str(row["classification"]))
            score_color = COLORS["green"] if row["score"] < 0.2 else COLORS["amber"] if row["score"] < 0.9 else COLORS["red"]
            cols = st.columns([0.8, 1.4, 0.55, 0.5, 1.2], gap="small")
            cols[0].markdown(f"<div style='color:{COLORS['text_muted']}; padding-top:0.24rem;'>{html.escape(str(row['time']))}</div>", unsafe_allow_html=True)
            cols[1].markdown(f"<div style='color:{COLORS['cyan']}; padding-top:0.24rem;'>{html.escape(str(row['src_ip']))}</div>", unsafe_allow_html=True)
            cols[2].markdown(f"<div style='color:{COLORS['text_muted']}; padding-top:0.24rem;'>{html.escape(str(row['proto']))}</div>", unsafe_allow_html=True)
            cols[3].markdown(f"<div style='color:{score_color}; padding-top:0.24rem; font-weight:600;'>{row['score']:.2f}</div>", unsafe_allow_html=True)
            cols[4].markdown(
                f"<div><span class='ns-chip' style='color:{attack_color}; background:{attack_bg};'>{html.escape(str(row['classification']))}</span></div>",
                unsafe_allow_html=True,
            )
            if row_idx < len(stream) - 1:
                st.markdown(f"<div style='border-top:1px solid rgba(30, 38, 51, 0.32); margin-top:0.32rem;'></div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)


def _render_probe_grid() -> None:
    st.markdown('<div class="ns-probe-shell">', unsafe_allow_html=True)
    probe_cols = st.columns(4, gap="medium")
    for col, probe in zip(probe_cols, get_probe_status_snapshot()):
        with col:
            probe_card(probe["name"], probe["status"], probe["rate"], probe["color"])
    st.markdown("</div>", unsafe_allow_html=True)

def _current_filters() -> tuple[str, str, str]:
    query = st.query_params
    time_range = str(query.get("time", "1h"))
    model = str(query.get("model", "ebpf"))
    run = str(query.get("run", "RUN-043"))
    return time_range, model, run


def _apply_filters(time_range: str, model: str, run: str) -> None:
    st.query_params["time"] = time_range
    st.query_params["model"] = model
    st.query_params["run"] = run
    st.rerun()


def _render_filter_bar() -> tuple[str, str, str]:
    time_range, model, run = _current_filters()
    time_options = ["5m", "1h", "6h", "24h", "7d"]
    model_options = [("baseline", "Baseline IF"), ("ebpf", "eBPF-Enhanced"), ("both", "Both")]
    run_options = ["RUN-043", "RUN-042", "RUN-041"]
    st.markdown('<div class="ns-filter-shell">', unsafe_allow_html=True)
    row = st.columns([1.8, 0.04, 1.55, 0.04, 0.95], gap="small")
    with row[0]:
        st.markdown('<div class="ns-filter-group"><span class="ns-filter-label">Time Range</span></div>', unsafe_allow_html=True)
        btn_cols = st.columns(len(time_options), gap="small")
        for col, option in zip(btn_cols, time_options):
            with col:
                st.markdown(f'<div class="ns-filter-link{" active" if option == time_range else ""}">', unsafe_allow_html=True)
                if st.button(option, key=f"dashboard_time_{option}", width="stretch"):
                    _apply_filters(option, model, run)
                st.markdown("</div>", unsafe_allow_html=True)
    with row[1]:
        st.markdown('<div class="ns-filter-sep"></div>', unsafe_allow_html=True)
    with row[2]:
        st.markdown('<div class="ns-filter-group"><span class="ns-filter-label">Model</span></div>', unsafe_allow_html=True)
        btn_cols = st.columns(len(model_options), gap="small")
        for col, (model_key, label) in zip(btn_cols, model_options):
            with col:
                st.markdown(f'<div class="ns-filter-link{" active" if model_key == model else ""}">', unsafe_allow_html=True)
                if st.button(label, key=f"dashboard_model_{model_key}", width="stretch"):
                    _apply_filters(time_range, model_key, run)
                st.markdown("</div>", unsafe_allow_html=True)
    with row[3]:
        st.markdown('<div class="ns-filter-sep"></div>', unsafe_allow_html=True)
    with row[4]:
        st.markdown('<div class="ns-filter-group"><span class="ns-filter-label">Run</span></div>', unsafe_allow_html=True)
        st.markdown('<div class="ns-run-select">', unsafe_allow_html=True)
        selected_run = st.selectbox(
            "Run",
            run_options,
            index=run_options.index(run) if run in run_options else 0,
            key="dashboard_run_select",
            label_visibility="collapsed",
        )
        st.markdown("</div>", unsafe_allow_html=True)
        if selected_run != run:
            _apply_filters(time_range, model, selected_run)
    st.markdown("</div>", unsafe_allow_html=True)
    return time_range, model, run


_inject_dashboard_css()
render_app_sidebar("pages/dashboard.py")

st.markdown(
    f"""
    <div class="ns-dashboard-top">
        <div class="ns-dashboard-title">
            <div>
                <h1>Dashboard</h1>
                <p>At-a-glance KPIs · Recent alerts · Threat distribution · Probe health</p>
            </div>
            <div class="ns-status-line">Status: <span style="color:{COLORS["green"]};">eBPF Active</span> · eth0</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

_render_filter_bar()
kpi_cols = st.columns(4, gap="medium")
for col, metric in zip(kpi_cols, get_dashboard_kpis()):
    with col:
        _render_metric_card(metric["label"], metric["value"], metric["delta"], metric["color"])
st.markdown('<div class="ns-kpi-spacer"></div>', unsafe_allow_html=True)

top_left, top_right = st.columns([2.72, 0.78], gap="small")
with top_left:
    _render_alert_table()
with top_right:
    threat_df = get_threat_distribution_snapshot()
    with st.container(border=True):
        _panel_header("Threat Distribution", "By attack family · current window", "ns-panel-threat")
        st.markdown('<div class="ns-panel-body compact">', unsafe_allow_html=True)
        figure = donut_chart(
            labels=threat_df["attack"],
            values=threat_df["alerts"],
            colors=threat_df["color"].tolist(),
            height=255,
        )
        figure.update_layout(
            margin={"l": 10, "r": 10, "t": 10, "b": 10},
            annotations=[
                {
                    "text": "348",
                    "showarrow": False,
                    "x": 0.5,
                    "y": 0.54,
                    "font": {"color": COLORS["text_body"], "size": 15},
                },
                {
                    "text": "ALERTS",
                    "showarrow": False,
                    "x": 0.5,
                    "y": 0.44,
                    "font": {"color": COLORS["text_muted"], "size": 9},
                }
            ],
        )
        st.plotly_chart(figure, width="stretch", config={"displayModeBar": False})
        st.markdown('<div class="ns-threat-legend">', unsafe_allow_html=True)
        for _, row in threat_df.iterrows():
            st.markdown(
                f"""
                <div style='display:flex; justify-content:space-between; padding:0.22rem 0;'>
                    <div style='display:flex; align-items:center; gap:0.52rem; color:{COLORS["text_muted"]};'>
                        <span style='width:0.55rem; height:0.55rem; border-radius:999px; background:{row["color"]}; display:inline-block;'></span>
                        <span>{row["attack"]}</span>
                    </div>
                    <div style='color:{row["color"]};'>{int(row["share"] * 100)}%</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        st.markdown("</div></div>", unsafe_allow_html=True)

mid_left, mid_right = st.columns([1.0, 1.0], gap="small")
with mid_left:
    _render_live_stream()
with mid_right:
    protocol_df = get_protocol_breakdown_snapshot()
    with st.container(border=True):
        _panel_header("Protocol Breakdown", "Traffic mix · current window", "ns-panel-protocol")
        st.markdown('<div class="ns-panel-body compact">', unsafe_allow_html=True)
        protocol_chart = horizontal_bar(
            y=protocol_df["protocol"],
            x=protocol_df["share"],
            colors=protocol_df["color"].tolist(),
            height=210,
            xaxis_title="Traffic Share (%)",
        )
        protocol_chart.update_layout(margin={"l": 24, "r": 20, "t": 10, "b": 10}, showlegend=False)
        protocol_chart.update_xaxes(range=[0, 100], ticksuffix="%", showgrid=False, showticklabels=False, title="")
        protocol_chart.update_yaxes(showgrid=False, title="")
        st.plotly_chart(protocol_chart, width="stretch", config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

with st.container(border=True):
    _panel_header("eBPF Probe Status", "Active kernel probes · health & event rate", "ns-panel-probes")
    st.markdown('<div class="ns-panel-body compact">', unsafe_allow_html=True)
    _render_probe_grid()
    st.markdown("</div>", unsafe_allow_html=True)
