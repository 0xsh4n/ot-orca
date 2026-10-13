"""Optional nmap enrichment — ACTIVE, and strictly opt-in.

OT-ORCA is a passive tool. This module is the one place that can transmit, and
it never runs unless the operator explicitly passes ``--active-nmap`` (CLI) or
ticks the consent box (GUI). Even then it defaults to a *gentle* profile
designed not to disturb fragile OT devices:

  * ``-sT`` connect scan or ``-sV --version-intensity 0`` only on discovered
    ports, never a full SYN sweep of the control range by default.
  * ``-T2`` timing, ``--max-retries 1``, host-timeout, and ``--scan-delay`` to
    avoid hammering PLCs that crash under load.
  * Targets default to assets OT-ORCA already *saw* passively, so the active
    footprint stays within the known conversation set.

Scanning OT devices can still cause faults. The caller is responsible for
authorization; this module refuses to run without an explicit consent flag.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

from ..core.inventory import Inventory


class ConsentRequired(RuntimeError):
    pass


@dataclass
class NmapResult:
    host: str
    ports: list[dict] = field(default_factory=list)
    os_guess: Optional[str] = None


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def targets_from_inventory(inv: Inventory) -> list[str]:
    return sorted({a.ip for a in inv.assets.values()
                   if a.ip and a.is_private})


def build_command(targets: list[str], profile: str = "gentle",
                  ports: Optional[str] = None) -> list[str]:
    exe = shutil.which("nmap") or "nmap"
    cmd = [exe, "-oX", "-", "-n", "-Pn"]
    if profile == "gentle":
        cmd += ["-sT", "-T2", "--max-retries", "1", "--host-timeout", "60s",
                "--scan-delay", "50ms", "-sV", "--version-intensity", "2"]
    elif profile == "discovery":
        cmd += ["-sn"]   # ping/ARP discovery only, no port scan
    else:  # "standard"
        cmd += ["-sS", "-T3", "-sV"]
    if ports:
        cmd += ["-p", ports]
    elif profile != "discovery":
        # Default to common OT + management ports to keep the scan narrow.
        cmd += ["-p", "21,22,23,80,102,443,502,2404,4840,20000,44818,47808,"
                      "1883,8883,9600,161,5900,1911,34962-34964"]
    cmd += targets
    return cmd


def run(targets: list[str], consent: bool = False, profile: str = "gentle",
        ports: Optional[str] = None, timeout: int = 600) -> list[NmapResult]:
    if not consent:
        raise ConsentRequired(
            "nmap is an ACTIVE scan and is disabled by default. Re-run with "
            "explicit consent (--active-nmap) only against assets you are "
            "authorized to probe. OT devices can fault under scanning.")
    if not nmap_available():
        raise RuntimeError("nmap not found on PATH.")
    if not targets:
        return []
    cmd = build_command(targets, profile=profile, ports=ports)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return _parse_xml(proc.stdout)


def _parse_xml(xml_text: str) -> list[NmapResult]:
    results: list[NmapResult] = []
    if not xml_text.strip():
        return results
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return results
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        res = NmapResult(host=addr_el.get("addr", "?"))
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            res.ports.append({
                "port": int(port.get("portid", 0)),
                "proto": port.get("protocol", "tcp"),
                "service": svc.get("name") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
        osmatch = host.find("./os/osmatch")
        if osmatch is not None:
            res.os_guess = osmatch.get("name")
        results.append(res)
    return results


def enrich_inventory(inv: Inventory, results: list[NmapResult]) -> None:
    """Fold nmap findings back into the passive asset inventory."""
    for r in results:
        asset = inv.assets.get(r.host)
        if not asset:
            continue
        for p in r.ports:
            if p["proto"] == "tcp":
                asset.tcp_ports.add(p["port"])
            else:
                asset.udp_ports.add(p["port"])
            if p["product"] and not asset.product:
                asset.product = f"{p['product']} {p['version']}".strip()
        if r.os_guess:
            asset.attributes.setdefault("nmap_os", r.os_guess)
        asset.labels.add("nmap-enriched")
