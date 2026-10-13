"""Scan session orchestration.

A :class:`ScanSession` wires the capture engine to the inventory and runs the
rules engine on demand. It supports both blocking (CLI) and threaded (GUI) use,
exposes live progress via a callback, and serialises a complete result bundle
(assets, flows, events, findings, stats) for the reporting layer.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Optional

from .capture import CaptureConfig, LiveCapture, tshark_version
from .inventory import Inventory
from ..analysis import rules_engine, statistics
from ..version import __version__


ProgressCB = Callable[[dict], None]


@dataclass
class ScanResult:
    meta: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    assets: list = field(default_factory=list)
    flows: list = field(default_factory=list)
    events: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "meta": self.meta, "summary": self.summary,
            "assets": self.assets, "flows": self.flows,
            "events": self.events, "findings": self.findings,
            "stats": self.stats,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


class ScanSession:
    def __init__(self, config: CaptureConfig,
                 progress_cb: Optional[ProgressCB] = None,
                 progress_every: int = 100):
        self.config = config
        self.inv = Inventory()
        self.progress_cb = progress_cb
        self.progress_every = progress_every
        self._capture: Optional[LiveCapture] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._flow_ts: dict = defaultdict(list)
        self.error: Optional[str] = None

    # --- control -------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._running.is_set()

    def start_async(self) -> None:
        self._thread = threading.Thread(target=self._run_capture, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._capture:
            self._capture.stop()
        self._running.clear()

    def run_blocking(self) -> None:
        self._run_capture()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    # --- capture loop --------------------------------------------------------
    def _run_capture(self) -> None:
        self._running.set()
        self._capture = LiveCapture(self.config)
        try:
            for row in self._capture:
                if not self._running.is_set():
                    break
                self.inv.observe(row)
                self._record_flow_ts(row)
                if (self.progress_cb and
                        self.inv.packet_count % self.progress_every == 0):
                    self.progress_cb(self.inv.summary())
        except PermissionError as exc:
            self.error = str(exc)
        except Exception as exc:  # pragma: no cover - defensive
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self._running.clear()
            if self.progress_cb:
                self.progress_cb(self.inv.summary())

    def _record_flow_ts(self, row: dict) -> None:
        proto = row.get("protostack", "").split(":")[-1]
        src, dst = row.get("ip_src"), row.get("ip_dst")
        if src and dst:
            try:
                ts = float(row.get("ts") or 0)
            except ValueError:
                return
            key = f"{src}->{dst}/{proto}"
            lst = self._flow_ts[key]
            if len(lst) < 5000:
                lst.append(ts)

    # --- results -------------------------------------------------------------
    def analyze(self) -> list:
        return rules_engine.analyze(self.inv)

    def build_result(self) -> ScanResult:
        findings = self.analyze()
        stats = statistics.overview(self.inv, findings)
        stats["periodicity"] = statistics.periodicity_scores(
            self.inv, self._flow_ts)[:20]
        source = self.config.pcap or f"iface:{self.config.interface}"
        return ScanResult(
            meta={
                "tool": "OT-ORCA",
                "version": __version__,
                "tshark": tshark_version(),
                "source": source,
                "mode": "passive",
                "generated": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "duration_s": round(time.time() - self.inv.started, 1),
            },
            summary=self.inv.summary(),
            assets=[a.to_dict() for a in sorted(
                self.inv.assets.values(), key=lambda a: (-int(a.purdue), a.key))],
            flows=[f.to_dict() for f in sorted(
                self.inv.flows.values(), key=lambda f: -f.packets)],
            events=[e.to_dict() for e in self.inv.events[-2000:]],
            findings=[f.to_dict() for f in findings],
            stats=stats,
        )
