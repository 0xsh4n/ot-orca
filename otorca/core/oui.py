"""MAC OUI -> vendor lookup.

Prefers Wireshark's bundled ``manuf`` database when present (rich, always
up to date on a Wireshark install), and falls back to a small built-in table of
OT-relevant vendors so the tool still classifies controllers offline.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache

# OT-relevant OUI prefixes (first 3 octets, upper, no separators).
_BUILTIN = {
    "000FAB": "Rockwell/Allen-Bradley",
    "0000BC": "Rockwell/Allen-Bradley",
    "001D9C": "Rockwell Automation",
    "28633E": "Rockwell Automation",
    "001B1B": "Siemens",
    "000E8C": "Siemens",
    "002161": "Siemens",
    "00806D": "Siemens",
    "0001F2": "Schneider Electric",
    "0080F4": "Schneider Electric (Telemecanique)",
    "000569": "Schneider Electric",
    "0010A1": "Schneider Electric",
    "00A07A": "Schneider Electric",
    "0003E0": "Mitsubishi Electric",
    "00264D": "Mitsubishi Electric",
    "0000F4": "Mitsubishi",
    "0000F9": "Omron",
    "001F9A": "Omron",
    "00C0C8": "Omron",
    "0008E1": "Yokogawa",
    "00A098": "Yokogawa",
    "0002A3": "Yokogawa",
    "0000A6": "Emerson/DeltaV",
    "00409D": "Emerson",
    "001013": "Emerson",
    "0001C7": "Honeywell",
    "0040B9": "Honeywell",
    "0017F2": "GE / General Electric",
    "0005F6": "GE Intelligent Platforms",
    "000CCD": "IEC-61850 / Beckhoff-ish",
    "0001A4": "Phoenix Contact",
    "A8740B": "Phoenix Contact",
    "00A025": "Hirschmann",
    "001C06": "Hirschmann/Belden",
    "ECE555": "WAGO",
    "00301B": "WAGO",
    "001401": "B&R Automation",
    "0060FC": "B&R Automation",
    "0030DE": "Wago Kontakttechnik",
    "001B6D": "Moxa",
    "0090E8": "Moxa",
    "00605C": "Moxa",
    "0003B9": "Beckhoff",
    "00013E": "Beckhoff",
    "001B97": "ABB",
    "000C8C": "ABB",
    "005079": "Dell",
    "000C29": "VMware",
    "005056": "VMware",
}

_MANUF_PATHS = [
    "/usr/share/wireshark/manuf",
    "/usr/local/share/wireshark/manuf",
    "/Applications/Wireshark.app/Contents/Resources/share/wireshark/manuf",
    os.path.expanduser("~/.config/wireshark/manuf"),
]


@lru_cache(maxsize=1)
def _manuf_table() -> dict[str, str]:
    for path in _MANUF_PATHS:
        if os.path.isfile(path):
            table: dict[str, str] = {}
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = re.split(r"\s+", line, maxsplit=2)
                        if len(parts) < 2:
                            continue
                        prefix = parts[0].upper().replace(":", "").replace("-", "")
                        if len(prefix) >= 6 and "/" not in prefix:
                            vendor = parts[2] if len(parts) > 2 else parts[1]
                            table[prefix[:6]] = vendor
                return table
            except Exception:
                return {}
    return {}


@lru_cache(maxsize=4096)
def lookup(mac: str) -> str | None:
    if not mac or len(mac) < 8:
        return None
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    if prefix in _BUILTIN:
        return _BUILTIN[prefix]
    return _manuf_table().get(prefix)
