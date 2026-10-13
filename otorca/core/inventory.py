"""The live inventory: assets, flows and events accumulated during a scan.

:class:`Inventory` is the mutable state that the capture loop fills and the
analysis layer reads. It owns asset identity resolution (merging MAC/IP/hostname
observations into one :class:`Asset`), flow accounting, and the event log.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from typing import Optional

from . import oui
from .models import Asset, Flow, ProtocolEvent, Purdue
from ..protocols.tables import OT_PORTS


# Role precedence — a device seen both as PLC and engineering stays a PLC.
_ROLE_PRIORITY = {
    "unknown": 0, "it": 1, "broker": 2, "historian": 3, "bas": 3,
    "scada": 4, "hmi": 5, "engineering": 6, "io-device": 6, "ied": 7,
    "rtu": 8, "plc": 9, "opc-server": 4,
}


class Inventory:
    def __init__(self) -> None:
        self.assets: dict[str, Asset] = {}
        self.flows: dict[tuple, Flow] = {}
        self.events: list[ProtocolEvent] = []
        self.packet_count = 0
        self.byte_count = 0
        self.started = time.time()
        self.protocol_counts: dict[str, int] = {}
        self.arp_claims: dict[str, set[str]] = {}   # ip -> set(mac) from ARP
        self._lock = threading.Lock()

    @staticmethod
    def _is_bcast_mcast(mac: Optional[str]) -> bool:
        if not mac:
            return False
        m = mac.lower()
        if m == "ff:ff:ff:ff:ff:ff":
            return True
        try:
            first = int(m.split(":")[0], 16)
            return bool(first & 0x01)  # multicast bit (covers 01:xx, 33:33, etc.)
        except (ValueError, IndexError):
            return False

    # --- asset identity ------------------------------------------------------
    def _asset_for(self, ip: Optional[str], mac: Optional[str] = None,
                   layer2: bool = False) -> Optional[Asset]:
        # Never create a standalone asset for a broadcast/multicast L2 address.
        if not ip and self._is_bcast_mcast(mac):
            return None
        key: Optional[str] = None
        if ip and not layer2:
            key = ip
        elif mac:
            key = f"mac:{mac.lower()}"
        elif ip:
            key = ip
        if not key:
            return None
        asset = self.assets.get(key)
        if asset is None:
            asset = Asset(key=key, ip=ip if (ip and not layer2) else None)
            if mac:
                asset.macs.add(mac.lower())
                v = oui.lookup(mac)
                if v and not asset.vendor:
                    asset.vendor = v
            self.assets[key] = asset
        else:
            if ip and not asset.ip and not layer2:
                asset.ip = ip
            if mac:
                asset.macs.add(mac.lower())
        return asset

    def _bump_role(self, asset: Asset, role_hint: Optional[str]) -> None:
        if not role_hint:
            return
        cur = _ROLE_PRIORITY.get(asset.role, 0)
        new = _ROLE_PRIORITY.get(role_hint, 0)
        if new > cur:
            asset.role = role_hint

    def tag_asset(self, ip: Optional[str], mac: Optional[str] = None,
                  protocol: Optional[str] = None, role_hint: Optional[str] = None,
                  port: Optional[int] = None, proto_tcp: bool = False,
                  proto_udp: bool = False, vendor: Optional[str] = None,
                  product: Optional[str] = None, serial: Optional[str] = None,
                  hostname: Optional[str] = None, layer2: bool = False) -> None:
        """Called by dissectors to enrich an asset. All args optional."""
        asset = self._asset_for(ip, mac, layer2=layer2)
        if asset is None:
            return
        if protocol:
            asset.protocols.add(protocol)
        self._bump_role(asset, role_hint)
        if port:
            (asset.tcp_ports if proto_tcp or not proto_udp else asset.udp_ports).add(port)
        if vendor and not asset.vendor:
            asset.vendor = vendor
        if product and not asset.product:
            asset.product = product
        if serial and not asset.serial:
            asset.serial = serial
        if hostname:
            asset.hostnames.add(hostname)

    def flow(self, src: Optional[str], dst: Optional[str], protocol: str,
             dport: Optional[int] = None, func: Optional[str] = None,
             transport: str = "tcp", nbytes: int = 0) -> None:
        if not src or not dst:
            return
        key = (src, dst, protocol, dport)
        fl = self.flows.get(key)
        if fl is None:
            fl = Flow(src=src, dst=dst, protocol=protocol, dport=dport,
                      transport=transport)
            self.flows[key] = fl
        fl.packets += 1
        fl.bytes += nbytes
        fl.last_seen = time.time()
        if func:
            fl.func_codes[func] = fl.func_codes.get(func, 0) + 1

    # --- the per-packet entry point -----------------------------------------
    def observe(self, row: dict) -> None:
        with self._lock:
            self._observe(row)

    def _observe(self, row: dict) -> None:
        self.packet_count += 1
        try:
            ts = float(row.get("ts") or time.time())
        except ValueError:
            ts = time.time()
        try:
            nbytes = int(row.get("len") or 0)
        except ValueError:
            nbytes = 0
        self.byte_count += nbytes

        stack = row.get("protostack", "")
        if stack:
            top = stack.split(":")[-1]
            self.protocol_counts[top] = self.protocol_counts.get(top, 0) + 1

        ip_src = row.get("ip_src") or row.get("ip6_src")
        ip_dst = row.get("ip_dst") or row.get("ip6_dst")
        mac_src = row.get("eth_src")
        mac_dst = row.get("eth_dst")

        # L3 endpoints
        a = self._asset_for(ip_src, mac_src)
        if a:
            a.touch(ts, nbytes)
            if mac_src:
                a.macs.add(mac_src.lower())
                v = oui.lookup(mac_src)
                if v and not a.vendor:
                    a.vendor = v
        b = self._asset_for(ip_dst, mac_dst)
        if b:
            b.touch(ts, nbytes)

        # Generic port accounting for server side (dst)
        dport = self._int(row.get("tcp_dport")) or self._int(row.get("udp_dport"))
        if b and dport:
            if row.get("tcp_dport"):
                b.tcp_ports.add(dport)
            else:
                b.udp_ports.add(dport)
            svc = OT_PORTS.get(dport)
            if svc:
                b.protocols.add(svc.split("-")[0])

        # ARP claims (ip -> mac) for spoofing/duplicate-IP detection.
        arp_ip, arp_mac = row.get("arp_src_ip"), row.get("arp_src_mac")
        if arp_ip and arp_mac:
            mac_l = arp_mac.lower()
            self.arp_claims.setdefault(arp_ip, set()).add(mac_l)
            # Reconcile identity: fold the MAC into the IP-keyed asset (creating
            # it if needed) rather than keeping a separate MAC-only asset, so a
            # device seen via both L3 and ARP is one node, not two.
            ipa = self._asset_for(arp_ip)
            if ipa:
                ipa.macs.add(mac_l)
                v = oui.lookup(mac_l)
                if v and not ipa.vendor:
                    ipa.vendor = v
            stale = self.assets.pop(f"mac:{mac_l}", None)
            if stale and ipa:
                ipa.protocols |= stale.protocols
                ipa.hostnames |= stale.hostnames

        # Naming signals
        self._apply_names(row, a, b)

        # Hand to protocol dissectors (they append to self.events)
        from ..protocols.dissect import dissect as _dissect
        _dissect(row, ts, self, self.events)

    def _apply_names(self, row, a, b) -> None:
        name = (row.get("dhcp_host") or row.get("nbns_name") or
                row.get("lldp_name") or row.get("cdp_devid"))
        if name and a:
            a.hostnames.add(name.strip())
        # DNS answer mapping is best-effort; we only capture the query name here.

    @staticmethod
    def _int(val) -> Optional[int]:
        if not val:
            return None
        try:
            return int(str(val).split(",")[0])
        except ValueError:
            return None

    # --- Purdue level inference (heuristic) ---------------------------------
    def classify_purdue(self) -> None:
        for asset in self.assets.values():
            # A globally-routable address is enterprise/internet by definition,
            # regardless of what protocol role it was seen playing.
            if asset.ip:
                try:
                    if ipaddress.ip_address(asset.ip).is_global:
                        asset.purdue = Purdue.ENTERPRISE
                        continue
                except ValueError:
                    pass
            if asset.role in ("plc", "rtu", "ied", "io-device"):
                asset.purdue = Purdue.CONTROL
            elif asset.role in ("hmi", "scada", "opc-server"):
                asset.purdue = Purdue.SUPERVISORY
            elif asset.role in ("historian", "broker", "bas"):
                asset.purdue = Purdue.OPERATIONS
            elif asset.role == "engineering":
                asset.purdue = Purdue.SUPERVISORY
            elif asset.ip and not asset.is_private:
                asset.purdue = Purdue.ENTERPRISE
            elif asset.role == "it":
                asset.purdue = Purdue.OPERATIONS
            else:
                asset.purdue = Purdue.UNKNOWN

    # --- snapshots -----------------------------------------------------------
    def summary(self) -> dict:
        return {
            "packets": self.packet_count,
            "bytes": self.byte_count,
            "assets": len(self.assets),
            "flows": len(self.flows),
            "events": len(self.events),
            "duration_s": round(time.time() - self.started, 1),
            "protocol_counts": dict(sorted(
                self.protocol_counts.items(), key=lambda kv: -kv[1])),
        }
