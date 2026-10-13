"""Summary charts for the report (headless matplotlib).

Three charts that an OT report always wants: a severity bar, a protocol-mix
donut, and a top-talkers bar. All render to PNG on a dark theme matching the
topology diagram.
"""

from __future__ import annotations

from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from ..core.inventory import Inventory
from ..analysis import statistics

_SEV_COLOR = {"Critical": "#d7263d", "High": "#e4572e", "Medium": "#f4a259",
              "Low": "#4c9f70", "Info": "#2e86ab"}
_BG = "#0f1115"
_FG = "#e8eaed"


def _style(ax) -> None:
    ax.set_facecolor(_BG)
    ax.tick_params(colors=_FG, labelsize=8)
    for s in ax.spines.values():
        s.set_color("#2a2f3a")
    ax.title.set_color(_FG)


def severity_chart(findings, out_path: str) -> Optional[str]:
    matrix = statistics.severity_matrix(findings)
    matrix = {k: v for k, v in matrix.items() if v or k in ("Critical", "High")}
    if not matrix:
        return None
    fig, ax = plt.subplots(figsize=(6, 3.2))
    fig.patch.set_facecolor(_BG)
    keys = list(matrix.keys())
    ax.bar(keys, [matrix[k] for k in keys],
           color=[_SEV_COLOR.get(k, "#888") for k in keys])
    ax.set_title("Findings by severity")
    _style(ax)
    for i, k in enumerate(keys):
        ax.text(i, matrix[k], str(matrix[k]), ha="center", va="bottom",
                color=_FG, fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130, facecolor=_BG)
    plt.close(fig)
    return out_path


def protocol_chart(inv: Inventory, out_path: str, top: int = 10) -> Optional[str]:
    dist = statistics.protocol_distribution(inv)
    if not dist:
        return None
    items = list(dist.items())[:top]
    labels = [k for k, _ in items]
    vals = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(5.5, 4))
    fig.patch.set_facecolor(_BG)
    wedges, *_ = ax.pie(vals, labels=None, wedgeprops=dict(width=0.42),
                        colors=plt.cm.twilight([i / max(len(vals), 1)
                                                for i in range(len(vals))]))
    ax.legend(wedges, [f"{l} ({v})" for l, v in items], loc="center left",
              bbox_to_anchor=(0.95, 0.5), fontsize=8, facecolor="#1a1e26",
              edgecolor="#2a2f3a", labelcolor=_FG)
    ax.set_title("Protocol mix", color=_FG)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130, facecolor=_BG)
    plt.close(fig)
    return out_path


def talkers_chart(inv: Inventory, out_path: str, n: int = 10) -> Optional[str]:
    talkers = statistics.top_talkers(inv, n)
    if not talkers:
        return None
    labels = [t["asset"] for t in talkers][::-1]
    vals = [t["bytes"] for t in talkers][::-1]
    fig, ax = plt.subplots(figsize=(6.5, 4))
    fig.patch.set_facecolor(_BG)
    ax.barh(labels, vals, color="#2e86ab")
    ax.set_title("Top talkers (bytes)")
    _style(ax)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130, facecolor=_BG)
    plt.close(fig)
    return out_path
