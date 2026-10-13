"""
OT-ORCA — Operational Technology Observation, Reconnaissance & Compliance Analyzer.

A strictly *passive* OT/ICS network security scanner and analysis toolkit.

OT-ORCA never transmits a single frame of its own onto the monitored network
when running in its default passive mode. It listens via ``tshark`` (Wireshark's
CLI), reconstructs an asset inventory and protocol conversation map, runs a
rules engine built from a senior OT-pentester's playbook, and produces
severity-rated findings with descriptions and concrete mitigations.

Optional, *clearly opt-in* active helpers (nmap) and AI analysts
(Ollama / OpenAI-compatible / MCP) can enrich the report, but they are never
engaged unless the operator explicitly asks for them.
"""

from .version import __version__, CODENAME

__all__ = ["__version__", "CODENAME"]
