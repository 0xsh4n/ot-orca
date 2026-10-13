"""Self-contained HTML report generator.

Produces a single ``.html`` file with charts and the topology diagram embedded
as base64 PNGs, so the report can be emailed or archived with no external
assets. Styled to match a professional OT assessment deliverable.
"""

from __future__ import annotations

import base64
import html
import os
import tempfile
from typing import Optional

from ..core.session import ScanResult

_SEV_COLOR = {"Critical": "#d7263d", "High": "#e4572e", "Medium": "#f4a259",
              "Low": "#4c9f70", "Info": "#2e86ab"}


def _img_b64(path: Optional[str]) -> Optional[str]:
    if not path or not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        return base64.b64encode(fh.read()).decode()


def _md_to_html(md: str) -> str:
    """Tiny Markdown subset -> HTML (headings, bold, lists)."""
    out = []
    in_list = False
    for raw in md.splitlines():
        line = html.escape(raw)
        import re
        line = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
        line = re.sub(r"`(.+?)`", r"<code>\1</code>", line)
        if line.startswith("## "):
            if in_list:
                out.append("</ul>"); in_list = False
            out.append(f"<h3>{line[3:]}</h3>")
        elif line.startswith("# "):
            out.append(f"<h2>{line[2:]}</h2>")
        elif re.match(r"^\d+\.\s", line) or line.startswith("- "):
            if not in_list:
                out.append("<ul>"); in_list = True
            content = re.sub(r"^(\d+\.|-)\s", "", line)
            out.append(f"<li>{content}</li>")
        elif line.strip().startswith("&gt;"):
            out.append(f"<blockquote>{line.strip()[4:]}</blockquote>")
        elif line.strip():
            if in_list:
                out.append("</ul>"); in_list = False
            out.append(f"<p>{line}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def build_html(result: ScanResult, topology_png: Optional[str] = None,
               severity_png: Optional[str] = None,
               protocol_png: Optional[str] = None,
               talkers_png: Optional[str] = None,
               ai_narrative: str = "", ai_source: str = "") -> str:
    d = result.to_dict()
    meta, summary, stats = d["meta"], d["summary"], d["stats"]
    findings = d["findings"]
    sev = stats.get("severity_matrix", {})

    def badge(s):
        return (f'<span class="badge" style="background:{_SEV_COLOR.get(s,"#888")}">'
                f'{s}</span>')

    # --- findings table rows
    frows = []
    for f in findings:
        refs = "".join(f'<li>{html.escape(r)}</li>' for r in f["references"])
        ev = "".join(f'<li>{html.escape(e)}</li>' for e in f["evidence"][:8])
        assets = ", ".join(html.escape(a) for a in f["assets"][:10]) or "-"
        frows.append(f"""
        <div class="finding sev-{f['severity'].lower()}">
          <div class="finding-head">
            {badge(f['severity'])}
            <span class="rid">{html.escape(f['rule_id'])}</span>
            <span class="ftitle">{html.escape(f['title'])}</span>
            <span class="count">x{f.get('count',1)}</span>
          </div>
          <div class="finding-body">
            <p class="cat"><b>Category:</b> {html.escape(f['category'])} &nbsp;
               <b>Confidence:</b> {html.escape(f.get('confidence','medium'))}</p>
            <p><b>Affected:</b> {assets}</p>
            <p>{html.escape(f['description'])}</p>
            <p class="mit"><b>Mitigation:</b> {html.escape(f['mitigation'])}</p>
            <details><summary>Evidence &amp; references</summary>
              <b>Evidence</b><ul>{ev or '<li>-</li>'}</ul>
              <b>References</b><ul>{refs}</ul>
            </details>
          </div>
        </div>""")

    # --- asset table
    arows = []
    for a in d["assets"][:400]:
        arows.append(f"""<tr>
          <td>{html.escape(a.get('display_name',''))}</td>
          <td>{html.escape(a.get('ip') or '')}</td>
          <td>{html.escape(a.get('role',''))}</td>
          <td>{html.escape(a.get('purdue',''))}</td>
          <td>{html.escape(a.get('vendor') or '')}</td>
          <td>{html.escape(a.get('product') or '')}</td>
          <td>{html.escape(','.join(a.get('protocols',[])))}</td>
          <td>{a.get('packets',0)}</td></tr>""")

    def img_block(png, title):
        b = _img_b64(png)
        if not b:
            return ""
        return (f'<div class="imgcard"><h3>{title}</h3>'
                f'<img src="data:image/png;base64,{b}"/></div>')

    kpis = f"""
      <div class="kpi"><span>{summary.get('assets',0)}</span>Assets</div>
      <div class="kpi"><span>{summary.get('flows',0)}</span>Flows</div>
      <div class="kpi"><span>{summary.get('packets',0)}</span>Packets</div>
      <div class="kpi crit"><span>{sev.get('Critical',0)}</span>Critical</div>
      <div class="kpi high"><span>{sev.get('High',0)}</span>High</div>
      <div class="kpi med"><span>{sev.get('Medium',0)}</span>Medium</div>"""

    ai_html = (f'<section><h2>AI Analyst</h2>'
               f'<p class="muted">Source: {html.escape(ai_source)}</p>'
               f'<div class="ai">{_md_to_html(ai_narrative)}</div></section>'
               if ai_narrative else "")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OT-ORCA Report — {html.escape(meta.get('source',''))}</title>
<style>
:root{{--bg:#0f1115;--card:#171b22;--line:#262c37;--fg:#e8eaed;--muted:#8a93a3;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);
 font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
header{{padding:28px 32px;border-bottom:1px solid var(--line);
 background:linear-gradient(120deg,#13171f,#0f1115)}}
header h1{{margin:0;font-size:24px;letter-spacing:.5px}}
header .sub{{color:var(--muted);margin-top:6px;font-size:13px}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px 32px}}
section{{margin:26px 0}}
h2{{font-size:18px;border-left:3px solid #e4572e;padding-left:10px}}
.kpis{{display:flex;gap:14px;flex-wrap:wrap}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:10px;
 padding:14px 18px;min-width:110px;text-align:center}}
.kpi span{{display:block;font-size:26px;font-weight:700}}
.kpi.crit span{{color:#d7263d}}.kpi.high span{{color:#e4572e}}
.kpi.med span{{color:#f4a259}}
.grid{{display:flex;gap:18px;flex-wrap:wrap}}
.imgcard{{background:var(--card);border:1px solid var(--line);border-radius:10px;
 padding:14px;flex:1;min-width:320px}}
.imgcard img{{width:100%;border-radius:6px}}
.finding{{background:var(--card);border:1px solid var(--line);
 border-left:4px solid #888;border-radius:8px;margin:12px 0;overflow:hidden}}
.finding.sev-critical{{border-left-color:#d7263d}}
.finding.sev-high{{border-left-color:#e4572e}}
.finding.sev-medium{{border-left-color:#f4a259}}
.finding.sev-low{{border-left-color:#4c9f70}}
.finding.sev-info{{border-left-color:#2e86ab}}
.finding-head{{display:flex;align-items:center;gap:10px;padding:12px 16px;
 background:#1b2029}}
.badge{{color:#fff;padding:2px 10px;border-radius:12px;font-size:11px;
 font-weight:700}}
.rid{{font-family:ui-monospace,monospace;color:var(--muted);font-size:12px}}
.ftitle{{font-weight:600}}.count{{margin-left:auto;color:var(--muted)}}
.finding-body{{padding:10px 16px}}
.finding-body p{{margin:6px 0}}
.mit{{color:#8fd19e}}.cat{{color:var(--muted);font-size:12px}}
details{{margin-top:8px;color:var(--muted)}}
summary{{cursor:pointer}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line)}}
th{{color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--card)}}
.tablewrap{{max-height:460px;overflow:auto;border:1px solid var(--line);
 border-radius:8px;background:var(--card)}}
.muted{{color:var(--muted);font-size:12px}}
.ai{{background:var(--card);border:1px solid var(--line);border-radius:10px;
 padding:4px 18px}}
.ai h3{{color:#e4572e}} code{{background:#11141a;padding:1px 5px;border-radius:4px}}
blockquote{{border-left:3px solid var(--line);margin:8px 0;padding-left:12px;
 color:var(--muted)}}
footer{{color:var(--muted);text-align:center;padding:24px;font-size:12px;
 border-top:1px solid var(--line)}}
</style></head><body>
<header>
  <h1>🐋 OT-ORCA — Passive OT Security Assessment</h1>
  <div class="sub">Source: <b>{html.escape(meta.get('source',''))}</b> ·
   mode: {html.escape(meta.get('mode',''))} ·
   {html.escape(meta.get('tshark',''))} ·
   generated {html.escape(meta.get('generated',''))} ·
   duration {meta.get('duration_s',0)}s</div>
</header>
<div class="wrap">
  <section><div class="kpis">{kpis}</div></section>
  {ai_html}
  <section><h2>Visual Analysis</h2>
    <div class="grid">
      {img_block(topology_png,'Network Topology (by Purdue level)')}
    </div>
    <div class="grid">
      {img_block(severity_png,'Findings by Severity')}
      {img_block(protocol_png,'Protocol Mix')}
      {img_block(talkers_png,'Top Talkers')}
    </div>
  </section>
  <section><h2>Findings ({len(findings)})</h2>
    {''.join(frows) or '<p class="muted">No findings.</p>'}
  </section>
  <section><h2>Asset Inventory ({summary.get('assets',0)})</h2>
    <div class="tablewrap"><table>
      <tr><th>Name</th><th>IP</th><th>Role</th><th>Purdue</th><th>Vendor</th>
          <th>Product</th><th>Protocols</th><th>Pkts</th></tr>
      {''.join(arows)}
    </table></div>
  </section>
</div>
<footer>Generated by OT-ORCA v{html.escape(meta.get('version',''))} ·
 Passive assessment · Findings are indicative and require operator validation.
</footer>
</body></html>"""


def write_report(result: ScanResult, out_html: str, inv=None,
                 ai_narrative: str = "", ai_source: str = "",
                 render_images: bool = True) -> str:
    """Render charts/topology (if ``inv`` given) and write the HTML file."""
    topo = sev = proto = talk = None
    if render_images and inv is not None:
        from ..viz import topology as topo_mod, charts
        tmp = tempfile.mkdtemp(prefix="otorca_")
        try:
            topo = topo_mod.render(inv, os.path.join(tmp, "topo.png"))
        except Exception:
            topo = None
        try:
            sev = charts.severity_chart(
                [_F(f) for f in result.findings], os.path.join(tmp, "sev.png"))
            proto = charts.protocol_chart(inv, os.path.join(tmp, "proto.png"))
            talk = charts.talkers_chart(inv, os.path.join(tmp, "talk.png"))
        except Exception:
            pass
    html_text = build_html(result, topo, sev, proto, talk,
                           ai_narrative, ai_source)
    with open(out_html, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    return out_html


class _F:
    """Adapt a serialized finding dict back to the attribute shape charts expect."""
    def __init__(self, d: dict):
        from ..core.models import Severity
        self.severity = Severity.parse(d["severity"])
        self.count = d.get("count", 1)
