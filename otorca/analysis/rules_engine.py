"""Rules engine: inventory + events -> severity-rated findings.

Two kinds of rules run:

1. **Event rules** — a direct map from a :class:`ProtocolEvent` ``kind`` to a
   catalog ``rule_id``. These catch command-level behaviour (writes, STOPs,
   cleartext creds) as it happens.
2. **Analytic rules** — functions that reason over the whole inventory at the
   end of a scan (segmentation crossings, ARP anomalies, multiple masters,
   GOOSE stNum continuity, insecure-protocol presence).

All findings are de-duplicated and merged by ``(rule_id, primary asset)`` so a
noisy capture yields one well-evidenced finding per issue, with a count.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Optional

from ..core.inventory import Inventory
from ..core.models import Finding, Severity, ProtocolEvent
from ..findings import catalog
from ..protocols.tables import INSECURE_OT_PROTOCOLS, OT_PORTS


# ProtocolEvent.kind -> catalog rule_id
EVENT_RULES: dict[str, str] = {
    "modbus.write": "OTO-MODBUS-WRITE",
    "modbus.program": "OTO-MODBUS-PROGRAM",
    "s7.stop": "OTO-S7-STOP",
    "s7.program": "OTO-S7-PROGRAM",
    "s7.write": "OTO-S7-WRITE",
    "dnp3.dangerous": "OTO-DNP3-DANGEROUS",
    "dnp3.write": "OTO-DNP3-WRITE",
    "cip.dangerous": "OTO-CIP-DANGEROUS",
    "cip.write": "OTO-CIP-WRITE",
    "iec104.dangerous": "OTO-IEC104-DANGEROUS",
    "iec104.control": "OTO-IEC104-CONTROL",
    "bacnet.dangerous": "OTO-BACNET-DANGEROUS",
    "bacnet.write": "OTO-BACNET-WRITE",
    "omron.dangerous": "OTO-OMRON-DANGEROUS",
    "omron.write": "OTO-OMRON-WRITE",
    "profinet.dcp_set": "OTO-PROFINET-DCPSET",
    "opcua.nosec": "OTO-OPCUA-NOSEC",
    "cleartext.telnet": "OTO-CLEARTEXT-TELNET",
    "cleartext.ftp": "OTO-CLEARTEXT-FTP",
    "cleartext.http_auth": "OTO-CLEARTEXT-HTTP-AUTH",
    "cleartext.tftp": "OTO-TFTP",
    "snmp.default_community": "OTO-SNMP-DEFAULT",
    "snmp.v1v2_cleartext": "OTO-SNMP-V1V2",
    "tls.weak_version": "OTO-TLS-WEAK",
    "mqtt.cleartext_auth": "OTO-MQTT-CLEARTEXT-AUTH",
    "remote.vnc": "OTO-VNC",
    "enip.identity": "OTO-ENIP-IDENTITY",
}

# control/write event kinds, used by the multiple-masters analytic
_COMMAND_KINDS = {
    "modbus.write", "modbus.program", "s7.stop", "s7.program", "s7.write",
    "dnp3.dangerous", "dnp3.write", "cip.dangerous", "cip.write",
    "iec104.dangerous", "iec104.control", "bacnet.dangerous", "bacnet.write",
    "omron.dangerous", "omron.write",
}


class RulesEngine:
    def __init__(self, inv: Inventory):
        self.inv = inv
        self._by_key: dict[tuple, Finding] = {}

    # --- finding construction ------------------------------------------------
    def _add(self, rule_id: str, assets: list[str], evidence: str,
             ts: Optional[float] = None, severity: Optional[Severity] = None,
             confidence: str = "medium") -> None:
        tpl = catalog.get(rule_id)
        primary = assets[0] if assets else "-"
        key = (rule_id, primary)
        f = Finding(
            rule_id=rule_id,
            title=tpl["title"],
            severity=severity or tpl["severity"],
            category=tpl["category"],
            description=tpl["description"],
            mitigation=tpl["mitigation"],
            references=list(tpl["references"]),
            assets=list(assets),
            evidence=[evidence] if evidence else [],
            confidence=confidence,
            first_seen=ts, last_seen=ts,
        )
        if key in self._by_key:
            self._by_key[key].merge(f)
        else:
            self._by_key[key] = f

    # --- main entry ----------------------------------------------------------
    def run(self) -> list[Finding]:
        self.inv.classify_purdue()
        self._event_rules()
        self._insecure_protocols()
        self._it_ot_crossing()
        self._multiple_masters()
        self._arp_anomaly()
        self._goose_continuity()
        self._flat_network()
        self._discovery()
        findings = list(self._by_key.values())
        findings.sort(key=lambda f: (-int(f.severity), -f.count, f.rule_id))
        return findings

    # --- (1) event rules -----------------------------------------------------
    def _event_rules(self) -> None:
        for ev in self.inv.events:
            rule = EVENT_RULES.get(ev.kind)
            if not rule:
                continue
            target = ev.dst or ev.src or "-"
            self._add(rule, [target, ev.src] if ev.src and ev.src != target
                      else [target], ev.summary, ts=ev.ts, confidence="high")

    # --- (2) insecure-by-design protocols present ---------------------------
    def _insecure_protocols(self) -> None:
        seen: dict[str, set[str]] = defaultdict(set)
        for a in self.inv.assets.values():
            for p in a.protocols:
                base = p.split("-")[0]
                if base in INSECURE_OT_PROTOCOLS:
                    seen[base].add(a.display_name)
        for proto, hosts in seen.items():
            note = INSECURE_OT_PROTOCOLS[proto]
            self._add("OTO-PROTO-CLEARTEXT", sorted(hosts),
                      f"{proto.upper()}: {note} Devices: {', '.join(sorted(hosts))}",
                      confidence="high")

    # --- (3) IT/OT boundary crossing ----------------------------------------
    def _it_ot_crossing(self) -> None:
        ot_protos = set(INSECURE_OT_PROTOCOLS) | {"opcua", "enip", "cip"}
        for fl in self.inv.flows.values():
            if fl.protocol.split("-")[0] not in ot_protos:
                continue
            src_ext = self._is_external(fl.src)
            dst_asset = self.inv.assets.get(fl.dst)
            if src_ext and dst_asset and dst_asset.role in (
                    "plc", "rtu", "ied", "io-device"):
                self._add(
                    "OTO-IT-OT-CROSSING", [fl.dst, fl.src],
                    f"External host {fl.src} spoke {fl.protocol} to controller "
                    f"{fl.dst}", confidence="high")

    def _is_external(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        # "External" = globally routable public address. Enterprise/private
        # cross-zone talk needs explicit zone config to judge, so we only flag
        # the unambiguous public case here.
        return addr.is_global

    # --- (4) multiple masters issuing commands ------------------------------
    def _multiple_masters(self) -> None:
        masters: dict[str, set[str]] = defaultdict(set)
        for ev in self.inv.events:
            if ev.kind in _COMMAND_KINDS and ev.src and ev.dst:
                masters[ev.dst].add(ev.src)
        for controller, srcs in masters.items():
            if len(srcs) >= 2:
                self._add("OTO-NEW-MASTER", [controller] + sorted(srcs),
                          f"{len(srcs)} command sources to {controller}: "
                          f"{', '.join(sorted(srcs))}")

    # --- (5) ARP anomaly -----------------------------------------------------
    def _arp_anomaly(self) -> None:
        ip_to_macs: dict[str, set[str]] = defaultdict(set)
        # Prefer explicit ARP claims; fall back to observed asset MACs.
        for ip, macs in self.inv.arp_claims.items():
            ip_to_macs[ip].update(macs)
        for a in self.inv.assets.values():
            if a.ip and a.macs:
                for m in a.macs:
                    ip_to_macs[a.ip].add(m)
        for ip, macs in ip_to_macs.items():
            real = {m for m in macs if m and m != "00:00:00:00:00:00"
                    and not m.startswith("ff:ff:ff")}
            if len(real) >= 2:
                self._add("OTO-ARP-ANOMALY", [ip],
                          f"IP {ip} claimed by {len(real)} MACs: "
                          f"{', '.join(sorted(real))}", confidence="medium")

    # --- (6) GOOSE stNum continuity -----------------------------------------
    def _goose_continuity(self) -> None:
        last_stnum: dict[str, int] = {}
        seen_sim: set[str] = set()
        for ev in self.inv.events:
            if ev.kind != "goose.frame":
                continue
            ref = ev.data.get("ref")
            st = ev.data.get("stnum")
            if ref and isinstance(st, int):
                prev = last_stnum.get(ref)
                if prev is not None and st < prev:
                    self._add("OTO-GOOSE-STNUM-REGRESS", [ev.src or ref],
                              f"GOOSE {ref} stNum regressed {prev} -> {st} "
                              f"(src {ev.src})", ts=ev.ts, confidence="medium")
                last_stnum[ref] = st
            if (ev.data.get("sim") or ev.data.get("ndscom")) and ref not in seen_sim:
                seen_sim.add(ref)
                self._add("OTO-GOOSE-TEST-SIM", [ev.src or ref],
                          f"GOOSE {ref} has simulation/ndsCom flag set",
                          ts=ev.ts, confidence="high")

    # --- (7) flat network ----------------------------------------------------
    def _flat_network(self) -> None:
        subnets: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: {"ot": set(), "it": set()})
        for a in self.inv.assets.values():
            if not a.ip:
                continue
            try:
                net = str(ipaddress.ip_network(a.ip + "/24", strict=False))
            except ValueError:
                continue
            if a.role in ("plc", "rtu", "ied", "io-device"):
                subnets[net]["ot"].add(a.display_name)
            elif a.role in ("it", "unknown") and a.is_private:
                subnets[net]["it"].add(a.display_name)
        for net, groups in subnets.items():
            if groups["ot"] and len(groups["it"]) >= 3:
                self._add("OTO-FLAT-NETWORK", sorted(groups["ot"]),
                          f"Subnet {net} mixes {len(groups['ot'])} controllers "
                          f"with {len(groups['it'])} general hosts")

    # --- (8) discovery protocols ---------------------------------------------
    def _discovery(self) -> None:
        disc_hosts = set()
        for a in self.inv.assets.values():
            if a.protocols & {"profinet", "lldp", "cdp", "mdns"}:
                disc_hosts.add(a.display_name)
            if "profinet" in a.protocols:
                disc_hosts.add(a.display_name)
        if disc_hosts:
            self._add("OTO-UNENCRYPTED-DISCOVERY", sorted(disc_hosts),
                      f"L2 discovery active on: {', '.join(sorted(disc_hosts))}",
                      confidence="low")


def analyze(inv: Inventory) -> list[Finding]:
    return RulesEngine(inv).run()
