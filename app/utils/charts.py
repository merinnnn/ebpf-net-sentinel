from __future__ import annotations

from typing import Iterable

import pandas as pd
import plotly.graph_objects as go

from utils.styles import COLORS, PLOTLY_LAYOUT

def _base_figure(height: int, **overrides: object) -> go.Figure:
    figure = go.Figure()
    layout = dict(PLOTLY_LAYOUT)
    layout.update(
        {
            "height": height,
            "hovermode": "x unified",
            "bargap": 0.18,
            "dragmode": False,
        }
    )
    layout.update(overrides)
    figure.update_layout(**layout)
    return figure

def _style_axes(figure: go.Figure, xaxis_title: str = "", yaxis_title: str = "") -> go.Figure:
    figure.update_xaxes(
        title=xaxis_title,
        showgrid=True,
        gridcolor=COLORS["border"],
        linecolor=COLORS["border"],
        zerolinecolor=COLORS["border"],
        tickfont={"color": COLORS["text_muted"]},
        title_font={"color": COLORS["text_body"]},
    )
    figure.update_yaxes(
        title=yaxis_title,
        showgrid=True,
        gridcolor=COLORS["border"],
        linecolor=COLORS["border"],
        zerolinecolor=COLORS["border"],
        tickfont={"color": COLORS["text_muted"]},
        title_font={"color": COLORS["text_body"]},
    )
    return figure

def roc_chart(
    fpr: Iterable[float],
    tpr_base: Iterable[float],
    tpr_ebpf: Iterable[float],
    run_base: str,
    run_ebpf: str,
    height: int,
) -> go.Figure:
    figure = _base_figure(height, hovermode="closest")
    figure.add_trace(
        go.Scatter(
            x=list(fpr),
            y=list(tpr_base),
            mode="lines",
            name=run_base,
            line={"color": COLORS["amber"], "width": 3},
        )
    )
    figure.add_trace(
        go.Scatter(
            x=list(fpr),
            y=list(tpr_ebpf),
            mode="lines",
            name=run_ebpf,
            line={"color": COLORS["cyan"], "width": 3},
        )
    )
    figure.add_trace(
        go.Scatter(
            x=[0, 1],
            y=[0, 1],
            mode="lines",
            name="Chance",
            line={"color": COLORS["text_muted"], "width": 1.2, "dash": "dash"},
        )
    )
    figure.update_xaxes(range=[0, 1], tickformat=".0%")
    figure.update_yaxes(range=[0, 1], tickformat=".0%")
    return _style_axes(figure, "False Positive Rate", "True Positive Rate")

def radar_chart(
    base_vals: Iterable[float],
    ebpf_vals: Iterable[float],
    categories: Iterable[str],
    run_base: str,
    run_ebpf: str,
    height: int,
) -> go.Figure:
    labels = list(categories)
    baseline_values = list(base_vals)
    ebpf_values = list(ebpf_vals)
    if labels:
        labels = labels + [labels[0]]
        baseline_values = baseline_values + [baseline_values[0]]
        ebpf_values = ebpf_values + [ebpf_values[0]]

    figure = _base_figure(height, polar={"bgcolor": COLORS["sidebar"]}, hovermode="closest")
    figure.add_trace(
        go.Scatterpolar(
            r=baseline_values,
            theta=labels,
            fill="toself",
            name=run_base,
            line={"color": COLORS["purple"], "width": 2},
            fillcolor="rgba(124, 58, 237, 0.20)",
        )
    )
    figure.add_trace(
        go.Scatterpolar(
            r=ebpf_values,
            theta=labels,
            fill="toself",
            name=run_ebpf,
            line={"color": COLORS["cyan"], "width": 2},
            fillcolor="rgba(0, 212, 255, 0.20)",
        )
    )
    figure.update_layout(
        polar={
            "radialaxis": {
                "visible": True,
                "range": [0, 1],
                "gridcolor": COLORS["border"],
                "linecolor": COLORS["border"],
                "tickfont": {"color": COLORS["text_muted"]},
            },
            "angularaxis": {
                "gridcolor": COLORS["border"],
                "linecolor": COLORS["border"],
                "tickfont": {"color": COLORS["text_body"]},
            },
            "bgcolor": COLORS["sidebar"],
        }
    )
    return figure

def confusion_heatmap(
    tn: int,
    fp: int,
    fn: int,
    tp: int,
    label: str,
    color: str,
    height: int,
) -> go.Figure:
    figure = _base_figure(height, hovermode="closest")
    z = [[tn, fp], [fn, tp]]
    figure.add_trace(
        go.Heatmap(
            z=z,
            x=["Predicted Benign", "Predicted Attack"],
            y=["Actual Benign", "Actual Attack"],
            colorscale=[
                [0.0, COLORS["surface"]],
                [0.4, color],
                [1.0, COLORS["cyan"] if color != COLORS["cyan"] else "#7ff0ff"],
            ],
            text=[[f"TN<br>{tn:,}", f"FP<br>{fp:,}"], [f"FN<br>{fn:,}", f"TP<br>{tp:,}"]],
            texttemplate="%{text}",
            textfont={"color": COLORS["text_body"], "size": 14},
            showscale=False,
            name=label,
        )
    )
    figure.update_xaxes(side="top")
    figure.update_yaxes(autorange="reversed")
    return _style_axes(figure, "", "")

def grouped_bar(
    df: pd.DataFrame,
    x_col: str,
    y_cols: list[str],
    colors: list[str],
    names: list[str],
    height: int,
    yaxis_title: str,
) -> go.Figure:
    figure = _base_figure(height, barmode="group")
    for idx, y_col in enumerate(y_cols):
        figure.add_trace(
            go.Bar(
                x=df[x_col],
                y=df[y_col],
                name=names[idx] if idx < len(names) else y_col,
                marker={"color": colors[idx] if idx < len(colors) else COLORS["cyan"]},
                offsetgroup=str(idx),
            )
        )
    return _style_axes(figure, "", yaxis_title)

def horizontal_bar(
    y: Iterable[str],
    x: Iterable[float],
    colors: list[str],
    height: int,
    xaxis_title: str,
) -> go.Figure:
    y_values = list(y)
    x_values = list(x)
    bar_colors = colors if colors else [COLORS["cyan"]] * max(len(y_values), 1)

    figure = _base_figure(height, hovermode="y unified")
    figure.add_trace(
        go.Bar(
            x=x_values,
            y=y_values,
            orientation="h",
            marker={"color": bar_colors[: len(y_values)]},
            text=[f"{value:.3f}" if isinstance(value, float) else str(value) for value in x_values],
            textposition="outside",
            cliponaxis=False,
        )
    )
    figure.update_yaxes(autorange="reversed")
    return _style_axes(figure, xaxis_title, "")

def line_chart(
    t: Iterable[object],
    series_dict: dict[str, tuple[Iterable[float], str]],
    height: int,
    yaxis_title: str,
) -> go.Figure:
    time_values = list(t)
    figure = _base_figure(height)
    for name, (values, color) in series_dict.items():
        figure.add_trace(
            go.Scatter(
                x=time_values,
                y=list(values),
                mode="lines",
                name=name,
                line={"color": color, "width": 2.5},
            )
        )
    return _style_axes(figure, "", yaxis_title)

def histogram_overlay(
    series_dict: dict[str, tuple[Iterable[float], str]],
    nbinsx: int,
    height: int,
    xaxis_title: str,
) -> go.Figure:
    figure = _base_figure(height, barmode="overlay", hovermode="closest")
    for name, (values, color) in series_dict.items():
        figure.add_trace(
            go.Histogram(
                x=list(values),
                nbinsx=nbinsx,
                name=name,
                marker={"color": color},
                opacity=0.55,
            )
        )
    return _style_axes(figure, xaxis_title, "Count")

def shap_bar(df: pd.DataFrame, height: int) -> go.Figure:
    frame = df.copy()
    if "feature" not in frame.columns or "importance" not in frame.columns:
        frame = pd.DataFrame({"feature": [], "importance": []})

    if not frame.empty:
        frame = frame.sort_values("importance", ascending=True).tail(12)

    colors = [
        COLORS["cyan"] if str(feature).startswith("ebpf_") else COLORS["purple"]
        for feature in frame.get("feature", [])
    ]
    figure = _base_figure(height, hovermode="y unified")
    figure.add_trace(
        go.Bar(
            x=frame.get("importance", []),
            y=frame.get("feature", []),
            orientation="h",
            marker={"color": colors},
            text=[f"{value:.3f}" for value in frame.get("importance", [])],
            textposition="outside",
            cliponaxis=False,
        )
    )
    figure.update_yaxes(autorange="reversed")
    return _style_axes(figure, "Mean |SHAP|", "")


def donut_chart(
    labels: Iterable[str],
    values: Iterable[float],
    colors: list[str],
    height: int,
    hole: float = 0.68,
) -> go.Figure:
    figure = _base_figure(height, hovermode="closest")
    figure.add_trace(
        go.Pie(
            labels=list(labels),
            values=list(values),
            hole=hole,
            marker={"colors": colors},
            sort=False,
            direction="clockwise",
            textinfo="none",
            hovertemplate="%{label}: %{percent}<extra></extra>",
        )
    )
    figure.update_layout(
        margin={"l": 12, "r": 12, "t": 12, "b": 12},
        showlegend=False,
    )
    return figure


def live_monitor_timeseries_chart(
    t: Iterable[object],
    packets_per_sec: Iterable[float],
    anomaly_score: Iterable[float],
    alert_mask: Iterable[bool],
    height: int,
    threshold: float,
) -> go.Figure:
    time_values = list(t)
    packet_values = list(packets_per_sec)
    score_values = list(anomaly_score)
    alerts = list(alert_mask)

    figure = _base_figure(height, hovermode="x unified")
    figure.add_trace(
        go.Scatter(
            x=time_values,
            y=packet_values,
            mode="lines",
            name="PPS",
            line={"color": COLORS["cyan"], "width": 2.6},
        )
    )
    figure.add_trace(
        go.Scatter(
            x=time_values,
            y=score_values,
            mode="lines",
            name="Anomaly score",
            line={"color": COLORS["red"], "width": 1.8},
            yaxis="y2",
        )
    )

    alert_times = [time_values[idx] for idx, is_alert in enumerate(alerts) if is_alert]
    alert_scores = [score_values[idx] for idx, is_alert in enumerate(alerts) if is_alert]
    if alert_times:
        figure.add_trace(
            go.Scatter(
                x=alert_times,
                y=alert_scores,
                mode="markers",
                name="Alert spike",
                marker={"color": COLORS["amber"], "size": 8, "line": {"color": COLORS["background"], "width": 1}},
                yaxis="y2",
            )
        )
        for timestamp in alert_times:
            figure.add_vline(x=timestamp, line_color="rgba(239, 68, 68, 0.35)", line_width=1, line_dash="dot")

    figure.update_layout(
        margin={"l": 42, "r": 42, "t": 22, "b": 24},
        legend={"orientation": "h", "x": 0, "y": 1.12, "xanchor": "left", "yanchor": "bottom"},
        shapes=[
            {
                "type": "line",
                "xref": "paper",
                "x0": 0,
                "x1": 1,
                "yref": "y2",
                "y0": threshold,
                "y1": threshold,
                "line": {"color": "rgba(245, 158, 11, 0.45)", "width": 1, "dash": "dash"},
            }
        ],
        xaxis={
            "showgrid": True,
            "gridcolor": COLORS["border"],
            "linecolor": COLORS["border"],
            "tickfont": {"color": COLORS["text_muted"]},
            "tickformat": "%H:%M:%S",
            "title": "",
        },
        yaxis={
            "title": "Packets / sec",
            "gridcolor": COLORS["border"],
            "linecolor": COLORS["border"],
            "tickfont": {"color": COLORS["text_muted"]},
            "title_font": {"color": COLORS["text_body"]},
        },
        yaxis2={
            "title": "Anomaly score",
            "overlaying": "y",
            "side": "right",
            "range": [0, 1],
            "tickformat": ".0%",
            "showgrid": False,
            "linecolor": COLORS["border"],
            "tickfont": {"color": COLORS["text_muted"]},
            "title_font": {"color": COLORS["text_body"]},
        },
    )
    return figure

__all__ = [
    "roc_chart",
    "radar_chart",
    "confusion_heatmap",
    "grouped_bar",
    "horizontal_bar",
    "line_chart",
    "histogram_overlay",
    "shap_bar",
    "donut_chart",
    "live_monitor_timeseries_chart",
]
