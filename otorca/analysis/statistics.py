"""Traffic statistics and anomaly scoring with numpy.

Passive OT traffic is highly periodic (polling loops run at fixed intervals), so
simple statistical measures are surprisingly powerful: a talker whose inter-
packet timing suddenly changes, or a new high-volume flow, is worth surfacing.
This module computes per-asset/flow aggregates and a few lightweight anomaly
scores that feed both the report and the charts.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from ..core.inventory import Inventory


def protocol_distribution(inv: Inventory) -> dict[str, int]:
    return dict(sorted(inv.protocol_counts.items(), key=lambda kv: -kv[1]))


def top_talkers(inv: Inventory, n: int = 10) -> list[dict[str, Any]]:
    assets = sorted(inv.assets.values(), key=lambda a: -a.bytes)[:n]
    return [{"asset": a.display_name, "ip": a.ip, "role": a.role,
             "packets": a.packets, "bytes": a.bytes} for a in assets]


def top_flows(inv: Inventory, n: int = 15) -> list[dict[str, Any]]:
    flows = sorted(inv.flows.values(), key=lambda f: -f.packets)[:n]
    return [{"src": f.src, "dst": f.dst, "protocol": f.protocol,
             "dport": f.dport, "packets": f.packets,
             "ops": dict(sorted(f.func_codes.items(), key=lambda kv: -kv[1]))}
            for f in flows]


def role_breakdown(inv: Inventory) -> dict[str, int]:
    counts: dict[str, int] = {}
    for a in inv.assets.values():
        counts[a.role] = counts.get(a.role, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def severity_matrix(findings) -> dict[str, int]:
    from ..core.models import Severity
    out = {s.label: 0 for s in reversed(list(Severity))}
    for f in findings:
        out[f.severity.label] += f.count
    return out


def periodicity_scores(inv: Inventory, timestamps_by_flow: dict) -> list[dict]:
    """Score how periodic each flow is (coefficient of variation of intervals).

    A low CV => metronomic polling (normal OT). A high CV or a sudden change =>
    worth a human look. ``timestamps_by_flow`` maps a flow key to a list of
    epoch timestamps (collected optionally by the session).
    """
    results = []
    for key, ts in timestamps_by_flow.items():
        if len(ts) < 5:
            continue
        arr = np.asarray(sorted(ts), dtype=float)
        deltas = np.diff(arr)
        if deltas.size == 0 or deltas.mean() == 0:
            continue
        cv = float(deltas.std() / deltas.mean())
        results.append({
            "flow": key,
            "count": int(arr.size),
            "mean_interval_s": round(float(deltas.mean()), 4),
            "cv": round(cv, 3),
            "regular": cv < 0.25,
        })
    return sorted(results, key=lambda r: -r["cv"])


def overview(inv: Inventory, findings) -> dict[str, Any]:
    return {
        "summary": inv.summary(),
        "protocol_distribution": protocol_distribution(inv),
        "role_breakdown": role_breakdown(inv),
        "top_talkers": top_talkers(inv),
        "top_flows": top_flows(inv),
        "severity_matrix": severity_matrix(findings),
    }
