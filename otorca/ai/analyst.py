"""The AI analyst: turns a scan result into an executive narrative.

Given a :class:`ScanResult`, it builds a compact, privacy-conscious prompt
(counts and finding metadata — never raw secret values) and asks the configured
LLM for an executive summary, a prioritized remediation roadmap, and an
attacker's-eye-view. If no backend is available, it returns a solid
deterministic narrative built from the findings themselves, so the report is
always complete.
"""

from __future__ import annotations

from typing import Optional

from .base import AIConfig, AIBackendError, LLMBackend
from .ollama_client import OllamaBackend
from .openai_client import OpenAIBackend


SYSTEM_PROMPT = (
    "You are a senior OT/ICS security consultant writing the analysis section of "
    "a passive network assessment report. You are precise, vendor-neutral, and "
    "map findings to IEC 62443, NIST SP 800-82 and MITRE ATT&CK for ICS. You "
    "never invent devices or findings that are not in the provided data. Output "
    "clean Markdown with these sections: '## Executive Summary', "
    "'## Attack Surface & Likely Adversary Path', '## Prioritized Remediation "
    "Roadmap' (as a numbered list, most urgent first), and '## Residual Risk & "
    "Monitoring Recommendations'. Be concise and actionable."
)


def make_backend(config: AIConfig) -> Optional[LLMBackend]:
    if config.provider == "ollama":
        return OllamaBackend(config)
    if config.provider in ("openai", "openai-compatible", "codex", "lmstudio",
                           "vllm"):
        return OpenAIBackend(config)
    return None


def _build_user_prompt(result) -> str:
    d = result.to_dict() if hasattr(result, "to_dict") else result
    meta = d.get("meta", {})
    summary = d.get("summary", {})
    stats = d.get("stats", {})
    findings = d.get("findings", [])

    lines = []
    lines.append(f"ASSESSMENT SOURCE: {meta.get('source')} (passive capture)")
    lines.append(f"DURATION: {meta.get('duration_s')}s   "
                 f"PACKETS: {summary.get('packets')}   "
                 f"ASSETS: {summary.get('assets')}   "
                 f"FLOWS: {summary.get('flows')}")
    lines.append(f"PROTOCOL MIX: {stats.get('protocol_distribution', {})}")
    lines.append(f"ROLE BREAKDOWN: {stats.get('role_breakdown', {})}")
    lines.append(f"SEVERITY TOTALS: {stats.get('severity_matrix', {})}")
    lines.append("")
    lines.append("FINDINGS (id | severity | title | affected assets | count):")
    for f in findings:
        assets = ", ".join(f.get("assets", [])[:6]) or "-"
        lines.append(f"- {f['rule_id']} | {f['severity']} | {f['title']} | "
                     f"{assets} | x{f.get('count', 1)} | cat={f.get('category')}")
    lines.append("")
    lines.append("Write the analysis now. Do not restate every finding verbatim; "
                 "synthesize, prioritize, and explain business/process impact.")
    return "\n".join(lines)


def deterministic_narrative(result) -> str:
    """Template fallback when no LLM is configured/reachable."""
    d = result.to_dict() if hasattr(result, "to_dict") else result
    findings = d.get("findings", [])
    sev = d.get("stats", {}).get("severity_matrix", {})
    crit = [f for f in findings if f["severity"] == "Critical"]
    high = [f for f in findings if f["severity"] == "High"]

    out = ["## Executive Summary", ""]
    out.append(
        f"A passive assessment of `{d.get('meta', {}).get('source')}` observed "
        f"{d.get('summary', {}).get('assets', 0)} assets exchanging "
        f"{d.get('summary', {}).get('packets', 0)} packets. The rules engine "
        f"raised {len(findings)} findings "
        f"({sev.get('Critical', 0)} critical, {sev.get('High', 0)} high, "
        f"{sev.get('Medium', 0)} medium).")
    if crit:
        out.append("")
        out.append("**Critical issues requiring immediate attention:**")
        for f in crit:
            out.append(f"- {f['title']} — {', '.join(f['assets'][:4])}")
    out += ["", "## Attack Surface & Likely Adversary Path", ""]
    out.append(
        "Unauthenticated control protocols combined with any cleartext "
        "management access give an on-network adversary a direct path from "
        "initial access to manipulation of control. Prioritize closing the "
        "highest-severity command paths and segmenting the control zone.")
    out += ["", "## Prioritized Remediation Roadmap", ""]
    rank = crit + high + [f for f in findings
                          if f["severity"] not in ("Critical", "High")]
    for i, f in enumerate(rank[:12], 1):
        out.append(f"{i}. **{f['title']}** ({f['severity']}) — {f['mitigation']}")
    out += ["", "## Residual Risk & Monitoring Recommendations", ""]
    out.append(
        "Deploy continuous passive OT monitoring, baseline normal command "
        "sources per controller, and alert on any STOP/restart/program-download "
        "function or new master. Re-run this assessment after remediation to "
        "confirm the command paths are closed.")
    return "\n".join(out)


class Analyst:
    def __init__(self, config: AIConfig):
        self.config = config
        self.backend = make_backend(config)

    def status(self) -> str:
        if self.config.provider == "none" or not self.backend:
            return "disabled"
        return "ready" if self.backend.available() else "unreachable"

    def analyze(self, result) -> tuple[str, str]:
        """Return (narrative_markdown, source_label)."""
        if self.config.provider == "none" or not self.backend:
            return deterministic_narrative(result), "deterministic (no AI)"
        if not self.backend.available():
            return (deterministic_narrative(result),
                    f"deterministic (backend {self.backend.name} unreachable)")
        try:
            text = self.backend.chat(SYSTEM_PROMPT, _build_user_prompt(result))
            return text, self.backend.name
        except AIBackendError as exc:
            fb = deterministic_narrative(result)
            return (fb + f"\n\n> _AI analyst unavailable: {exc}_",
                    "deterministic (AI error)")
