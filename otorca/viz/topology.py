"""OT network topology diagram generation (networkx + matplotlib).

Builds a directed graph from observed flows, lays assets out by Purdue level
(L0 field devices at the bottom, enterprise at the top — the way an OT engineer
expects to read it), colours nodes by role, and draws control/write edges in red
so unauthorized-command paths jump out. Renders headless (Agg) so it works on a
server or in CI, and also emits a Graphviz DOT file for interactive tools.
"""

from __future__ import annotations

import math
from typing import Optional

import matplotlib
matplotlib.use("Agg")  # headless-safe; must precede pyplot import
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx

from ..core.inventory import Inventory
from ..core.models import Purdue

_ROLE_COLOR = {
    "plc": "#e4572e", "rtu": "#e4572e", "ied": "#f4a259", "io-device": "#f4a259",
    "hmi": "#2e86ab", "scada": "#2e86ab", "opc-server": "#17a398",
    "engineering": "#8661c1", "historian": "#4c9f70", "broker": "#4c9f70",
    "bas": "#4c9f70", "it": "#9aa0a6", "unknown": "#c7ccd1",
}
_CONTROL_PROTOS = {"modbus", "dnp3", "s7comm", "enip", "cip", "iec104",
                   "iec60870_104", "bacnet", "omron", "opcua"}


def build_graph(inv: Inventory) -> nx.DiGraph:
    g = nx.DiGraph()
    for a in inv.assets.values():
        g.add_node(a.key, label=a.display_name, role=a.role,
                   purdue=int(a.purdue), vendor=a.vendor or "",
                   protocols=",".join(sorted(a.protocols)))
    for fl in inv.flows.values():
        if fl.src in g and fl.dst in g:
            control = fl.protocol.split("-")[0] in _CONTROL_PROTOS
            if g.has_edge(fl.src, fl.dst):
                g[fl.src][fl.dst]["weight"] += fl.packets
            else:
                g.add_edge(fl.src, fl.dst, weight=fl.packets,
                           protocol=fl.protocol, control=control)
    return g


# Vertical ordering: enterprise at the top, field devices at the bottom, with
# unclassified assets parked just below L0 so they don't crowd the control bands.
_BAND_Y = {
    int(Purdue.ENTERPRISE): 6, int(Purdue.DMZ): 5, int(Purdue.OPERATIONS): 4,
    int(Purdue.SUPERVISORY): 3, int(Purdue.CONTROL): 2, int(Purdue.PROCESS): 1,
    int(Purdue.UNKNOWN): 0,
}
_BAND_LABEL = {
    6: "L5 Enterprise", 5: "L3.5 DMZ", 4: "L3 Operations", 3: "L2 Supervisory",
    2: "L1 Control", 1: "L0 Process", 0: "Unclassified",
}


def _purdue_layout(inv: Inventory, g: nx.DiGraph) -> tuple[dict, set[int]]:
    """Vertical bands by Purdue level; spread horizontally within a band."""
    bands: dict[int, list[str]] = {}
    for key in g.nodes:
        y = _BAND_Y.get(g.nodes[key]["purdue"], 0)
        bands.setdefault(y, []).append(key)
    pos = {}
    for y, nodes in bands.items():
        n = len(nodes)
        for i, key in enumerate(sorted(nodes)):
            x = (i - (n - 1) / 2.0) * 2.0
            pos[key] = (x, float(y))
    return pos, set(bands.keys())


def render(inv: Inventory, out_path: str, title: str = "OT-ORCA Network Topology",
           max_nodes: int = 120) -> Optional[str]:
    """Render the topology to ``out_path`` (PNG/SVG by extension). Returns path."""
    inv.classify_purdue()  # idempotent; ensures bands are correct standalone
    g = build_graph(inv)
    if g.number_of_nodes() == 0:
        return None
    # Cap for readability: keep the busiest nodes.
    if g.number_of_nodes() > max_nodes:
        busiest = sorted(g.nodes, key=lambda k: -(inv.assets[k].packets
                         if k in inv.assets else 0))[:max_nodes]
        g = g.subgraph(busiest).copy()

    pos, used_bands = _purdue_layout(inv, g)
    xs = [p[0] for p in pos.values()] or [0.0]
    x_min, x_max = min(xs), max(xs)
    fig, ax = plt.subplots(figsize=(max(12, g.number_of_nodes() * 0.35), 9))
    fig.patch.set_facecolor("#0f1115")
    ax.set_facecolor("#0f1115")
    ax.set_xlim(x_min - 2.0, x_max + 2.0)
    ax.set_ylim(min(used_bands) - 0.6, max(used_bands) + 0.6)

    # Purdue band separators + labels, aligned to the bands actually in use.
    for y in sorted(used_bands):
        ax.axhline(y - 0.5, color="#2a2f3a", lw=0.8, ls="--", zorder=0)
        ax.text(x_min - 1.9, y, _BAND_LABEL.get(y, ""), color="#6b7280",
                fontsize=10, va="center", ha="left", zorder=0, alpha=0.8)

    sizes = [300 + math.sqrt(max(inv.assets[k].packets, 1)) * 40
             if k in inv.assets else 300 for k in g.nodes]
    colors = [_ROLE_COLOR.get(g.nodes[k]["role"], "#c7ccd1") for k in g.nodes]

    ctrl_edges = [(u, v) for u, v, d in g.edges(data=True) if d.get("control")]
    other_edges = [(u, v) for u, v, d in g.edges(data=True) if not d.get("control")]
    nx.draw_networkx_edges(g, pos, edgelist=other_edges, ax=ax,
                           edge_color="#3d4454", width=1.0, alpha=0.6,
                           arrows=True, arrowsize=8, connectionstyle="arc3,rad=0.06")
    nx.draw_networkx_edges(g, pos, edgelist=ctrl_edges, ax=ax,
                           edge_color="#e4572e", width=1.8, alpha=0.9,
                           arrows=True, arrowsize=12, connectionstyle="arc3,rad=0.06")
    nx.draw_networkx_nodes(g, pos, node_size=sizes, node_color=colors,
                           edgecolors="#11141a", linewidths=1.2, ax=ax)
    labels = {k: g.nodes[k]["label"] for k in g.nodes}
    nx.draw_networkx_labels(g, pos, labels=labels, font_size=7,
                            font_color="#e8eaed", ax=ax)

    legend = [mpatches.Patch(color=c, label=r)
              for r, c in _ROLE_COLOR.items()
              if any(g.nodes[k]["role"] == r for k in g.nodes)]
    legend.append(mpatches.Patch(color="#e4572e", label="control/write flow"))
    ax.legend(handles=legend, loc="upper right", fontsize=8,
              facecolor="#1a1e26", edgecolor="#2a2f3a", labelcolor="#e8eaed")
    ax.set_title(title, color="#e8eaed", fontsize=14, pad=14)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(out_path, dpi=130, facecolor=fig.get_facecolor())
    plt.close(fig)
    return out_path


def export_dot(inv: Inventory, out_path: str) -> Optional[str]:
    """Write a Graphviz DOT file for interactive exploration (Gephi, xdot…)."""
    g = build_graph(inv)
    if g.number_of_nodes() == 0:
        return None
    try:
        nx.nx_pydot.write_dot(g, out_path)
    except Exception:
        # pydot not installed — write a minimal DOT ourselves.
        with open(out_path, "w") as fh:
            fh.write("digraph otorca {\n")
            for k in g.nodes:
                lbl = g.nodes[k]["label"].replace('"', "'")
                fh.write(f'  "{k}" [label="{lbl}"];\n')
            for u, v, d in g.edges(data=True):
                fh.write(f'  "{u}" -> "{v}" [label="{d.get("protocol","")}"];\n')
            fh.write("}\n")
    return out_path
