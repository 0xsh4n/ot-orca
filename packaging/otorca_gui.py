"""Frozen-app entry point for the OT-ORCA GUI (PyInstaller target).

This is the single script PyInstaller bundles into the standalone GUI binary
(``otorca-gui`` on Linux, ``otorca-gui.exe`` on Windows). It keeps a tiny
``--version`` fast path so the binary can be smoke-tested without a display.
"""

from __future__ import annotations

import sys


def main() -> int:
    if "--version" in sys.argv or "-V" in sys.argv:
        from otorca.version import __version__
        print(f"OT-ORCA GUI {__version__}")
        return 0
    try:
        from otorca.gui.app import launch
    except Exception as exc:  # pragma: no cover
        sys.stderr.write(f"Failed to start OT-ORCA GUI: {exc}\n")
        return 1
    launch()
    return 0


if __name__ == "__main__":
    sys.exit(main())
