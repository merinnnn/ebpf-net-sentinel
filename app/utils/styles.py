from __future__ import annotations

from pathlib import Path

import streamlit as st


COLORS: dict[str, str] = {
    "background": "#0a0d12",
    "sidebar": "#111620",
    "card": "#111620",
    "surface": "#161d2a",
    "border": "#1e2633",
    "text_muted": "#6b7f96",
    "text_body": "#c8d4e3",
    "cyan": "#00d4ff",
    "purple": "#7c3aed",
    "green": "#10b981",
    "red": "#ef4444",
    "amber": "#f59e0b",
}

NAV_SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [
    ("Detection", [("pages/dashboard.py", "Dashboard"), ("pages/live_monitor.py", "Live Monitor")]),
    (
        "Experiments",
        [
            ("pages/compare_models.py", "Compare Models"),
            ("pages/attack_breakdown.py", "Attack Breakdown"),
            ("pages/explainability.py", "Explainability"),
        ],
    ),
    ("System", [("pages/cost_performance.py", "Cost & Perf."), ("pages/runs.py", "Runs")]),
    ("Tools", [("pages/model_testing.py", "Model Testing"), ("pages/dataset_explorer.py", "Dataset Explorer")]),
]


PLOTLY_LAYOUT: dict = {
    "paper_bgcolor": COLORS["background"],
    "plot_bgcolor": COLORS["sidebar"],
    "font": {
        "family": "JetBrains Mono, monospace",
        "color": COLORS["text_body"],
        "size": 12,
    },
    "margin": {"l": 32, "r": 24, "t": 40, "b": 32},
    "legend": {
        "orientation": "h",
        "yanchor": "bottom",
        "y": 1.02,
        "xanchor": "right",
        "x": 1,
        "font": {"size": 11},
    },
    "xaxis": {
        "gridcolor": COLORS["border"],
        "linecolor": COLORS["border"],
        "zerolinecolor": COLORS["border"],
        "tickfont": {"color": COLORS["text_muted"]},
        "title": {"font": {"color": COLORS["text_body"]}},
    },
    "yaxis": {
        "gridcolor": COLORS["border"],
        "linecolor": COLORS["border"],
        "zerolinecolor": COLORS["border"],
        "tickfont": {"color": COLORS["text_muted"]},
        "title": {"font": {"color": COLORS["text_body"]}},
    },
}


def inject_css() -> None:
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');

        :root {{
            --bg: {COLORS["background"]};
            --sidebar: {COLORS["sidebar"]};
            --card: {COLORS["card"]};
            --surface: {COLORS["surface"]};
            --border: {COLORS["border"]};
            --muted: {COLORS["text_muted"]};
            --text: {COLORS["text_body"]};
            --cyan: {COLORS["cyan"]};
            --purple: {COLORS["purple"]};
            --green: {COLORS["green"]};
            --red: {COLORS["red"]};
            --amber: {COLORS["amber"]};
        }}

        html, body, [class*="css"], [data-testid="stAppViewContainer"],
        [data-testid="stMarkdownContainer"], [data-testid="stSidebar"] * {{
            font-family: 'JetBrains Mono', monospace;
        }}

        html, body, [data-testid="stAppViewContainer"], .stApp {{
            background: var(--bg);
            color: var(--text);
        }}

        [data-testid="stHeader"] {{
            background: rgba(10, 13, 18, 0.85);
            border-bottom: 1px solid var(--border);
        }}

        [data-testid="stSidebar"] {{
            background: linear-gradient(180deg, var(--sidebar) 0%, #0d121b 100%);
            border-right: 1px solid var(--border);
        }}

        [data-testid="stSidebar"] > div:first-child {{
            background: transparent;
        }}

        [data-testid="stSidebarUserContent"] {{
            padding-top: 0.15rem;
        }}

        [data-testid="stSidebarNav"] {{
            display: none;
        }}

        [data-testid="stSidebarCollapseButton"] {{
            display: flex;
            justify-content: center;
            align-items: center;
            width: 2rem;
            height: 2rem;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: rgba(17, 22, 32, 0.86);
            color: var(--muted);
            top: 0.7rem;
            right: 0.85rem;
        }}

        [data-testid="stSidebarCollapseButton"]:hover {{
            color: var(--cyan);
            border-color: rgba(0, 212, 255, 0.32);
            background: rgba(0, 212, 255, 0.08);
        }}

        [data-testid="collapsedControl"] {{
            display: flex !important;
            top: 0.8rem;
            left: 0.75rem;
        }}

        [data-testid="collapsedControl"] button {{
            display: flex;
            align-items: center;
            justify-content: center;
            width: 2.1rem;
            height: 2.1rem;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: rgba(17, 22, 32, 0.94);
            color: var(--muted);
        }}

        [data-testid="collapsedControl"] button:hover {{
            color: var(--cyan);
            border-color: rgba(0, 212, 255, 0.32);
            background: rgba(0, 212, 255, 0.08);
        }}

        [data-testid="stToolbar"] {{
            right: 1rem;
        }}

        .block-container {{
            padding-top: 1.5rem;
            padding-bottom: 2rem;
            max-width: 1440px;
        }}

        h1, h2, h3, h4, h5, h6, p, span, label, div {{
            color: var(--text);
        }}

        .ns-page-header {{
            padding: 0 0 1.25rem 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1.25rem;
        }}

        .ns-page-header h1 {{
            margin: 0;
            font-size: 2rem;
            line-height: 1.1;
            letter-spacing: -0.02em;
        }}

        .ns-page-header p {{
            margin: 0.5rem 0 0 0;
            color: var(--muted);
            max-width: 72rem;
        }}

        .ns-panel {{
            background:
                radial-gradient(circle at top right, rgba(0, 212, 255, 0.08), transparent 28%),
                linear-gradient(180deg, rgba(255, 255, 255, 0.02) 0%, rgba(255, 255, 255, 0.01) 100%),
                var(--card);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 1rem 1rem 1.1rem 1rem;
            box-shadow: 0 0 0 1px rgba(0, 212, 255, 0.02), 0 12px 40px rgba(0, 0, 0, 0.22);
            margin-bottom: 1rem;
        }}

        .ns-panel-header {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 1rem;
            margin-bottom: 0.9rem;
        }}

        .ns-panel-title {{
            margin: 0;
            font-size: 0.96rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }}

        .ns-panel-subtitle {{
            margin: 0.3rem 0 0 0;
            font-size: 0.83rem;
            color: var(--muted);
        }}

        .ns-placeholder {{
            border: 1px dashed rgba(107, 127, 150, 0.65);
            border-radius: 14px;
            padding: 1rem;
            background:
                linear-gradient(180deg, rgba(22, 29, 42, 0.65) 0%, rgba(17, 22, 32, 0.45) 100%);
            min-height: 160px;
        }}

        .ns-placeholder h4 {{
            margin: 0 0 0.45rem 0;
            font-size: 0.95rem;
            color: var(--text);
        }}

        .ns-placeholder p {{
            margin: 0;
            color: var(--muted);
            line-height: 1.6;
        }}

        .ns-filter-bar {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
            padding: 0.9rem 1rem;
            margin-bottom: 1rem;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 18px;
        }}

        .ns-probe-card {{
            position: relative;
            background: linear-gradient(180deg, rgba(22, 29, 42, 0.95) 0%, rgba(17, 22, 32, 0.95) 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 0.95rem 1rem;
            overflow: hidden;
        }}

        .ns-probe-card::before {{
            content: "";
            position: absolute;
            inset: 0 auto 0 0;
            width: 4px;
            background: var(--probe-color, var(--cyan));
        }}

        .ns-probe-top {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            margin-bottom: 0.55rem;
        }}

        .ns-probe-name {{
            font-size: 0.94rem;
            font-weight: 600;
        }}

        .ns-probe-status {{
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            color: var(--muted);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.08em;
        }}

        .ns-probe-status::before {{
            content: "";
            width: 0.55rem;
            height: 0.55rem;
            border-radius: 999px;
            background: var(--probe-color, var(--cyan));
            box-shadow: 0 0 12px var(--probe-color, var(--cyan));
        }}

        .ns-probe-rate {{
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--text);
        }}

        .ns-sidebar-brand {{
            color: var(--cyan);
            font-size: 1.55rem;
            font-weight: 700;
            margin: 0.55rem 0 0.15rem 0;
        }}

        .ns-sidebar-tag {{
            color: var(--muted);
            font-size: 0.88rem;
            margin-bottom: 0.85rem;
        }}

        .ns-sidebar-section {{
            color: var(--muted);
            font-size: 0.74rem;
            letter-spacing: 0.18em;
            text-transform: uppercase;
            margin: 1rem 0 0.3rem 0;
        }}

        .ns-sidebar-divider {{
            height: 1px;
            background: var(--border);
            margin: 0.45rem -1rem 0.9rem -1rem;
        }}

        .ns-sidebar-link {{
            display: block;
            margin: 0 -1rem 0.06rem -1rem;
        }}

        [data-testid="stSidebar"] .ns-sidebar-link div[data-testid="stButton"] {{
            width: 100%;
        }}

        [data-testid="stSidebar"] .ns-sidebar-link button {{
            display: flex;
            align-items: center;
            justify-content: flex-start;
            width: 100%;
            min-height: 32px;
            padding: 0 0.95rem;
            margin: 0;
            border-radius: 0 !important;
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
            color: var(--muted) !important;
            font-size: 0.94rem;
            letter-spacing: 0.01em;
            line-height: 1;
            outline: none !important;
            text-decoration: none !important;
            transition: background-color 120ms ease, color 120ms ease;
        }}

        [data-testid="stSidebar"] .ns-sidebar-link button p,
        [data-testid="stSidebar"] .ns-sidebar-link button span {{
            color: inherit !important;
            margin: 0 !important;
            line-height: 1 !important;
        }}

        [data-testid="stSidebar"] .ns-sidebar-link button::before {{
            content: "●";
            font-size: 0.9rem;
            line-height: 1;
            margin-right: 0.75rem;
            color: currentColor;
        }}

        [data-testid="stSidebar"] .ns-sidebar-link.available button {{
            color: var(--text) !important;
        }}

        [data-testid="stSidebar"] .ns-sidebar-link.available button:hover {{
            color: var(--text) !important;
            background: rgba(255, 255, 255, 0.02) !important;
        }}

        [data-testid="stSidebar"] .ns-sidebar-link.active button {{
            color: var(--cyan) !important;
            background: rgba(0, 212, 255, 0.10) !important;
            border-left: 2px solid var(--cyan) !important;
            padding-left: calc(0.95rem - 2px);
        }}

        [data-testid="stSidebar"] .ns-sidebar-link button:disabled {{
            opacity: 1 !important;
            cursor: default !important;
        }}

        [data-testid="stSidebar"] .ns-sidebar-link.muted button {{
            color: rgba(107, 127, 150, 0.78) !important;
        }}

        [data-testid="stSidebar"] .ns-sidebar-link.muted button:hover,
        [data-testid="stSidebar"] .ns-sidebar-link.muted button:disabled:hover {{
            background: transparent !important;
            color: rgba(107, 127, 150, 0.78) !important;
        }}

        .stSelectbox label, .stMultiSelect label, .stSlider label, .stRadio label,
        .stTextInput label, .stNumberInput label {{
            color: var(--muted) !important;
            font-size: 0.78rem !important;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }}

        .stSelectbox > div > div, .stMultiSelect > div > div, .stTextInput > div > div > input,
        .stNumberInput input, .stDateInput input {{
            background: var(--surface);
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 12px;
        }}

        .stSlider [data-baseweb="slider"] {{
            padding-top: 0.25rem;
        }}

        .stButton > button, .stDownloadButton > button {{
            background: var(--surface);
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 10px;
            box-shadow: none;
        }}

        .stButton > button:hover, .stDownloadButton > button:hover {{
            border-color: rgba(0, 212, 255, 0.28);
            color: var(--text);
        }}

        .stDataFrame, [data-testid="stTable"] {{
            border: 1px solid var(--border);
            border-radius: 14px;
            overflow: hidden;
        }}

        div[data-baseweb="select"] > div {{
            background: var(--surface);
            border-color: var(--border);
        }}

        [data-testid="stMetric"] {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 0.75rem 0.9rem;
        }}

        [data-testid="stMetricLabel"] {{
            color: var(--muted);
        }}

        [data-testid="stMetricValue"] {{
            color: var(--text);
        }}

        [data-testid="stExpander"] {{
            border: 1px solid var(--border);
            border-radius: 14px;
            background: var(--card);
        }}

        .stTabs [data-baseweb="tab-list"] {{
            gap: 0.35rem;
        }}

        .stTabs [data-baseweb="tab"] {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--muted);
        }}

        .stTabs [aria-selected="true"] {{
            color: var(--text);
            border-color: rgba(0, 212, 255, 0.35);
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def page_header(title: str, subtitle: str) -> None:
    st.markdown(
        f"""
        <section class="ns-page-header">
            <h1>{title}</h1>
            <p>{subtitle}</p>
        </section>
        """,
        unsafe_allow_html=True,
    )


def panel(title: str, subtitle: str = "") -> None:
    subtitle_html = f'<p class="ns-panel-subtitle">{subtitle}</p>' if subtitle else ""
    st.markdown(
        f"""
        <section class="ns-panel">
            <div class="ns-panel-header">
                <div>
                    <h3 class="ns-panel-title">{title}</h3>
                    {subtitle_html}
                </div>
            </div>
        """,
        unsafe_allow_html=True,
    )


def close_panel() -> None:
    st.markdown("</section>", unsafe_allow_html=True)


def placeholder(title: str, body: str) -> None:
    st.markdown(
        f"""
        <div class="ns-placeholder">
            <h4>{title}</h4>
            <p>{body}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def filter_bar(
    show_time: bool,
    show_model: bool,
    show_run: bool,
) -> tuple[str | None, str | None, str | None]:
    st.markdown('<div class="ns-filter-bar">', unsafe_allow_html=True)
    time_range = None
    model_sel = None
    run_sel = None

    columns = st.columns(sum([show_time, show_model, show_run]) or 1)
    col_idx = 0

    if show_time:
        with columns[col_idx]:
            time_range = st.selectbox(
                "Time Range",
                ["5m", "1h", "6h", "24h", "7d"],
                index=1,
                key="ns_filter_time",
            )
        col_idx += 1

    if show_model:
        with columns[col_idx]:
            model_sel = st.selectbox(
                "Model",
                ["Baseline IF", "eBPF-Enhanced", "Both"],
                index=1,
                key="ns_filter_model",
            )
        col_idx += 1

    if show_run:
        with columns[col_idx]:
            run_sel = st.selectbox(
                "Run",
                ["RUN-043", "RUN-042", "RUN-041", "RUN-040"],
                index=0,
                key="ns_filter_run",
            )

    st.markdown("</div>", unsafe_allow_html=True)
    return time_range, model_sel, run_sel


def probe_card(name: str, status: str, rate: str, color: str) -> None:
    st.markdown(
        f"""
        <div class="ns-probe-card" style="--probe-color: {color};">
            <div class="ns-probe-top">
                <div class="ns-probe-name">{name}</div>
                <div class="ns-probe-status">{status}</div>
            </div>
            <div class="ns-probe-rate">{rate}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_app_sidebar(active_page: str) -> None:
    st.sidebar.markdown(
        """
        <div class="ns-sidebar-brand">NetSentinel</div>
        <div class="ns-sidebar-tag">eBPF ML Detection</div>
        <div class="ns-sidebar-divider"></div>
        """,
        unsafe_allow_html=True,
    )

    for section, items in NAV_SECTIONS:
        st.sidebar.markdown(f'<div class="ns-sidebar-section">{section}</div>', unsafe_allow_html=True)
        for target, label in items:
            page_exists = (Path(__file__).resolve().parents[1] / target).exists()
            is_active = target == active_page
            row_class = "ns-sidebar-link"
            if is_active:
                row_class += " active"
            elif page_exists:
                row_class += " available"
            else:
                row_class += " muted"

            st.sidebar.markdown(f'<div class="{row_class}">', unsafe_allow_html=True)
            clicked = st.sidebar.button(
                label,
                key=f"nav::{active_page}::{target}",
                width="stretch",
                disabled=is_active or not page_exists,
            )
            st.sidebar.markdown("</div>", unsafe_allow_html=True)

            if clicked and not is_active and page_exists:
                st.switch_page(target)
