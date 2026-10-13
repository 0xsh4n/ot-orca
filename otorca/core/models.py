"""Core domain model for OT-ORCA.

Everything the analysis and reporting layers consume is one of the dataclasses
defined here: :class:`Asset`, :class:`Flow`, :class:`ProtocolEvent`,
:class:`Finding`, and the :class:`Inventory` that aggregates them.

The model is deliberately protocol-agnostic. Protocol dissectors push normalized
:class:`ProtocolEvent` objects into the inventory; the rules engine reads assets,
flows and events back out. This keeps the OT-specific knowledge in two places
only: the protocol dissectors and the findings catalog/rules.
"""

from __future__ import annotations

import enum
import ipaddress
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class Severity(enum.IntEnum):
    """Ordered severity levels. Higher is worse; ``IntEnum`` so we can sort."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def cvss_band(self) -> str:
        # Indicative only — OT-ORCA findings are environment-aware, not CVSS scores.
        return {
            Severity.INFO: "0.0",
            Severity.LOW: "0.1-3.9",
            Severity.MEDIUM: "4.0-6.9",
            Severity.HIGH: "7.0-8.9",
            Severity.CRITICAL: "9.0-10.0",
        }[self]

    @classmethod
    def parse(cls, value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


# Purdue model reference levels, used to flag boundary-crossing conversations.
class Purdue(enum.IntEnum):
    ENTERPRISE = 5          # L5 enterprise / internet
    DMZ = 35                # L3.5 industrial DMZ
    OPERATIONS = 3          # L3 site operations (historians, MES)
    SUPERVISORY = 2         # L2 SCADA/HMI
    CONTROL = 1             # L1 PLC/RTU/controllers
    PROCESS = 0             # L0 field devices / I/O
    UNKNOWN = 99

    @property
    def label(self) -> str:
        return {
            Purdue.ENTERPRISE: "L5 Enterprise",
            Purdue.DMZ: "L3.5 Industrial DMZ",
            Purdue.OPERATIONS: "L3 Operations",
            Purdue.SUPERVISORY: "L2 Supervisory",
            Purdue.CONTROL: "L1 Control",
            Purdue.PROCESS: "L0 Process",
            Purdue.UNKNOWN: "Unclassified",
        }[self]


@dataclass
class Asset:
    """A host observed on the wire, keyed by IP (or MAC for L2-only devices)."""

    key: str                                   # ip, or "mac:<addr>" when L2-only
    ip: Optional[str] = None
    macs: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    vendor: Optional[str] = None               # from CIP/ENIP identity, OUI, etc.
    product: Optional[str] = None
    serial: Optional[str] = None
    firmware: Optional[str] = None
    role: str = "unknown"                       # plc, hmi, scada, engineering, io, historian, it
    device_class: str = "unknown"               # controller, field-device, workstation...
    purdue: Purdue = Purdue.UNKNOWN
    protocols: set[str] = field(default_factory=set)
    tcp_ports: set[int] = field(default_factory=set)
    udp_ports: set[int] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packets: int = 0
    bytes: int = 0
    labels: set[str] = field(default_factory=set)   # free-form tags from dissectors
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def is_private(self) -> bool:
        if not self.ip:
            return True
        try:
            return ipaddress.ip_address(self.ip).is_private
        except ValueError:
            return False

    @property
    def display_name(self) -> str:
        if self.hostnames:
            return sorted(self.hostnames)[0]
        return self.ip or self.key

    def touch(self, ts: float, nbytes: int = 0) -> None:
        self.last_seen = max(self.last_seen, ts)
        self.first_seen = min(self.first_seen, ts) if self.first_seen else ts
        self.packets += 1
        self.bytes += nbytes

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("macs", "hostnames", "protocols", "labels"):
            d[k] = sorted(d[k])
        d["tcp_ports"] = sorted(self.tcp_ports)
        d["udp_ports"] = sorted(self.udp_ports)
        d["purdue"] = self.purdue.label
        d["is_private"] = self.is_private
        d["display_name"] = self.display_name
        return d


@dataclass
class Flow:
    """A directed conversation between two endpoints over one protocol/port."""

    src: str
    dst: str
    protocol: str
    transport: str = "tcp"              # tcp, udp, l2
    dport: Optional[int] = None
    packets: int = 0
    bytes: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    func_codes: dict[str, int] = field(default_factory=dict)  # observed op -> count

    @property
    def key(self) -> tuple:
        return (self.src, self.dst, self.protocol, self.dport)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProtocolEvent:
    """A single normalized protocol observation of interest.

    Dissectors emit these for anything a rule might care about: a Modbus write,
    an S7 STOP, a GOOSE state change, a cleartext credential, etc. The rules
    engine reads them; the catalog maps ``kind`` to findings.
    """

    ts: float
    protocol: str
    kind: str                           # e.g. "modbus.write", "s7.stop"
    src: Optional[str] = None
    dst: Optional[str] = None
    dport: Optional[int] = None
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A severity-rated security finding with evidence and remediation."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    mitigation: str
    confidence: str = "medium"          # low | medium | high
    assets: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    count: int = 1
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    def merge(self, other: "Finding") -> None:
        self.count += other.count
        for a in other.assets:
            if a not in self.assets:
                self.assets.append(a)
        for e in other.evidence:
            if e not in self.evidence and len(self.evidence) < 50:
                self.evidence.append(e)
        if other.first_seen:
            self.first_seen = min(self.first_seen or other.first_seen, other.first_seen)
        if other.last_seen:
            self.last_seen = max(self.last_seen or other.last_seen, other.last_seen)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["severity_rank"] = int(self.severity)
        return d
