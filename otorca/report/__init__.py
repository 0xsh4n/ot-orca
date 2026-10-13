"""Reporting: HTML, JSON and Markdown exporters."""

from __future__ import annotations

import json

from .html_report import write_report, build_html  # noqa: F401


def write_json(result, out_path: str) -> str:
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(result.to_json())
    return out_path


def write_markdown(result, out_path: str, ai_narrative: str = "") -> str:
    d = result.to_dict()
    lines = [f"# OT-ORCA Report — {d['meta'].get('source','')}", ""]
    lines.append(f"- Mode: {d['meta'].get('mode')}  ·  tshark: "
                 f"{d['meta'].get('tshark')}")
    lines.append(f"- Generated: {d['meta'].get('generated')}  ·  Duration: "
                 f"{d['meta'].get('duration_s')}s")
    s = d["summary"]
    lines.append(f"- Assets: {s.get('assets')}  ·  Flows: {s.get('flows')}  ·  "
                 f"Packets: {s.get('packets')}")
    sev = d["stats"].get("severity_matrix", {})
    lines.append(f"- Severity: " + ", ".join(f"{k}={v}" for k, v in sev.items()))
    if ai_narrative:
        lines += ["", "## AI Analyst", "", ai_narrative]
    lines += ["", "## Findings", ""]
    for f in d["findings"]:
        lines.append(f"### [{f['severity']}] {f['rule_id']} — {f['title']}")
        lines.append(f"- **Category:** {f['category']} (confidence "
                     f"{f.get('confidence','medium')}, seen x{f.get('count',1)})")
        lines.append(f"- **Affected:** {', '.join(f['assets'][:10]) or '-'}")
        lines.append(f"- **Description:** {f['description']}")
        lines.append(f"- **Mitigation:** {f['mitigation']}")
        if f["references"]:
            lines.append(f"- **References:** {'; '.join(f['references'])}")
        lines.append("")
    lines += ["## Asset Inventory", ""]
    lines.append("| Name | IP | Role | Purdue | Vendor | Protocols |")
    lines.append("|---|---|---|---|---|---|")
    for a in d["assets"]:
        lines.append(f"| {a.get('display_name','')} | {a.get('ip') or ''} | "
                     f"{a.get('role')} | {a.get('purdue')} | "
                     f"{a.get('vendor') or ''} | {','.join(a.get('protocols',[]))} |")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return out_path
