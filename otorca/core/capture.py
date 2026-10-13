"""Passive capture engine — a thin, safe wrapper around tshark.

Design goals:
  * **Passive by default.** The live command uses ``-p`` (no promiscuous-mode
    *change* beyond what the adapter already does) only when asked; by default
    tshark simply reads frames. OT-ORCA itself never crafts or injects packets.
  * **Version-robust.** The requested field list is intersected with the fields
    the local tshark build actually knows (``tshark -G fields``), so an older or
    stripped Wireshark won't abort the capture.
  * **Streaming.** Rows are yielded as they arrive (``-l`` line-buffered), so the
    GUI can update live and long captures don't buffer in memory.

The engine works identically on a live interface (``-i``) or an offline pcap
(``-r``), which makes the whole tool unit-testable without root or hardware.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from collections.abc import Iterator, Iterable
from dataclasses import dataclass
from typing import Optional

from . import fields as F


class TsharkNotFound(RuntimeError):
    pass


@dataclass
class CaptureConfig:
    interface: Optional[str] = None      # e.g. "eth0"  (mutually exclusive w/ pcap)
    pcap: Optional[str] = None           # read offline file instead
    bpf: Optional[str] = None            # optional capture filter (still passive)
    display_filter: Optional[str] = None  # tshark -Y
    packet_limit: int = 0                # 0 = unlimited
    duration: int = 0                    # seconds, 0 = until stopped
    snaplen: int = 0                     # 0 = default
    monitor_mode: bool = False           # 802.11 monitor (wlan)
    promiscuous: bool = True             # listen to all frames on the segment


def find_tshark() -> str:
    exe = shutil.which("tshark")
    if not exe:
        raise TsharkNotFound(
            "tshark was not found on PATH. Install Wireshark/tshark "
            "(e.g. 'sudo apt install tshark' or 'brew install wireshark')."
        )
    return exe


def tshark_version() -> str:
    try:
        out = subprocess.run(
            [find_tshark(), "--version"], capture_output=True, text=True, timeout=10
        ).stdout
        return out.splitlines()[0] if out else "unknown"
    except Exception:
        return "unknown"


_VALID_FIELDS_CACHE: Optional[set[str]] = None


def available_fields() -> set[str]:
    """Return the set of field names this tshark build can extract (cached)."""
    global _VALID_FIELDS_CACHE
    if _VALID_FIELDS_CACHE is not None:
        return _VALID_FIELDS_CACHE
    valid: set[str] = set()
    try:
        proc = subprocess.run(
            [find_tshark(), "-G", "fields"],
            capture_output=True, text=True, timeout=60,
        )
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            # Format: F \t name \t abbrev \t type \t parent \t ...
            if len(parts) >= 3 and parts[0] == "F":
                valid.add(parts[2])
    except Exception:
        valid = set()
    _VALID_FIELDS_CACHE = valid
    return valid


def resolve_fields() -> list[tuple[str, str]]:
    """Intersect the desired field schema with what tshark actually supports."""
    valid = available_fields()
    if not valid:  # couldn't query — trust the schema and let tshark complain
        return list(F.FIELDS)
    return [(fname, alias) for fname, alias in F.FIELDS if fname in valid]


def list_interfaces() -> list[tuple[str, str]]:
    """Return [(name, description), ...] of capture interfaces tshark can see."""
    try:
        proc = subprocess.run(
            [find_tshark(), "-D"], capture_output=True, text=True, timeout=15
        )
    except Exception:
        return []
    out: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        # "1. eth0" or "1. eth0 (Ethernet)"
        line = line.strip()
        if not line or "." not in line:
            continue
        _, rest = line.split(".", 1)
        rest = rest.strip()
        name = rest.split(" ", 1)[0]
        desc = rest[len(name):].strip(" ()") or name
        out.append((name, desc))
    return out


class LiveCapture:
    """Run tshark and yield one ``dict`` per packet (alias -> value)."""

    def __init__(self, config: CaptureConfig):
        self.config = config
        self._proc: Optional[subprocess.Popen] = None
        self._fields = resolve_fields()
        self._stop = threading.Event()

    # --- command construction ------------------------------------------------
    def build_command(self) -> list[str]:
        c = self.config
        cmd = [find_tshark(), "-l", "-n"]  # -n: no name resolution (passive-safe)
        if c.pcap:
            cmd += ["-r", c.pcap]
        else:
            if not c.interface:
                raise ValueError("Either interface or pcap must be set")
            cmd += ["-i", c.interface]
            if not c.promiscuous:
                cmd += ["-p"]
            if c.monitor_mode:
                cmd += ["-I"]
            if c.snaplen:
                cmd += ["-s", str(c.snaplen)]
            if c.duration:
                cmd += ["-a", f"duration:{c.duration}"]
            if c.packet_limit:
                cmd += ["-c", str(c.packet_limit)]
            if c.bpf:
                cmd += ["-f", c.bpf]
        if c.display_filter:
            cmd += ["-Y", c.display_filter]
        cmd += ["-T", "fields",
                "-E", "separator=\t",
                "-E", "occurrence=a",
                "-E", "aggregator=,"]
        for fname, _alias in self._fields:
            cmd += ["-e", fname]
        return cmd

    def stop(self) -> None:
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def __iter__(self) -> Iterator[dict[str, str]]:
        return self.rows()

    def rows(self) -> Iterator[dict[str, str]]:
        cmd = self.build_command()
        aliases = [a for _f, a in self._fields]
        env = dict(os.environ)
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env,
        )
        assert self._proc.stdout is not None
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                line = line.rstrip("\n")
                if not line:
                    continue
                values = line.split("\t")
                # Pad/truncate defensively — tshark always emits one col per -e.
                if len(values) < len(aliases):
                    values += [""] * (len(aliases) - len(values))
                row = {aliases[i]: values[i] for i in range(len(aliases))}
                if any(row.values()):
                    yield row
        finally:
            self._drain_stderr()

    def _drain_stderr(self) -> None:
        if not self._proc:
            return
        try:
            _, err = self._proc.communicate(timeout=5)
        except Exception:
            err = ""
        rc = self._proc.returncode
        if rc not in (0, None) and err and not self._stop.is_set():
            # Surface genuine errors (bad iface, permissions) but not clean stops.
            msg = err.strip().splitlines()[-1] if err.strip() else f"exit {rc}"
            if "You don't have permission" in err or "Couldn't run" in err:
                raise PermissionError(
                    "tshark could not open the interface. On Linux, add your user "
                    "to the 'wireshark' group or give dumpcap capture capabilities. "
                    f"Details: {msg}"
                )


def iter_packets(config: CaptureConfig) -> Iterable[dict[str, str]]:
    """Convenience: iterate packets for a config in the current thread."""
    return LiveCapture(config)
