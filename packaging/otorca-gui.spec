# -*- mode: python ; coding: utf-8 -*-
"""Shared PyInstaller spec for the OT-ORCA GUI (Linux + Windows).

Build:  pyinstaller --noconfirm packaging/otorca-gui.spec
Output: dist/otorca-gui       (Linux, one-file)
        dist/otorca-gui.exe   (Windows, one-file, windowed)
"""
import os
import sys
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# SPECPATH is injected by PyInstaller; resolve everything relative to it so the
# spec works no matter what the current working directory is.
HERE = SPECPATH
REPO = os.path.abspath(os.path.join(HERE, ".."))

hiddenimports = []
hiddenimports += collect_submodules("otorca")
# matplotlib Agg backend is what viz/* uses; pull it explicitly.
hiddenimports += ["matplotlib.backends.backend_agg", "numpy", "requests"]

datas = []
datas += collect_data_files("matplotlib", includes=["mpl-data/**"])

a = Analysis(
    [os.path.join(HERE, "otorca_gui.py")],
    pathex=[REPO],          # so the 'otorca' package is importable at build time
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PyQt5", "PyQt6", "PySide2", "PySide6", "pytest", "scapy",
              "IPython", "jupyter", "pandas"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="otorca-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                     # windowed GUI app
    disable_windowed_traceback=False,
    icon=None,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
