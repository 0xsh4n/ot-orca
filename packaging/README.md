# Packaging — standalone OT-ORCA GUI

This directory builds the **GUI-only** standalone apps (no Python install needed
on the target machine). The CLI remains available from the source package /
`pip install`.

| File | Purpose |
|---|---|
| `otorca_gui.py` | Frozen-app entry point (`--version` fast path + `launch()`) |
| `otorca-gui.spec` | Shared PyInstaller spec (Linux + Windows) |
| `build_linux.sh` | Builds the Linux binary **and** a `.deb` |
| `build_windows.ps1` | Builds the Windows `.exe` |
| `assets/` | `.desktop` launcher + app icon |

Everything lands in `../release/`.

## Build locally

### Linux (binary + .deb)
```bash
python3 -m pip install -r ../requirements.txt pyinstaller
./build_linux.sh
# -> release/otorca-gui-<ver>-linux-x86_64
# -> release/ot-orca-gui_<ver>_amd64.deb   (Depends: tshark)
```

### Windows (.exe)
A Windows `.exe` must be built **on Windows** — PyInstaller does not
cross-compile. On a Windows machine with Python 3.9+:
```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
# -> release\otorca-gui-<ver>-windows-x86_64.exe
```

## Build via GitHub Actions (recommended)

Pushing a version tag builds **all** targets and publishes a GitHub Release
automatically (see [`../.github/workflows/release.yml`](../.github/workflows/release.yml)):

```bash
git tag v1.0.0
git push origin v1.0.0
```

Or run the workflow manually from the **Actions** tab (`workflow_dispatch`) to
get the artifacts without publishing a release.

## Notes

- **tshark is a runtime dependency**, not bundled. The `.deb` declares
  `Depends: tshark`; Windows users install Wireshark.
- Binaries are ~90 MB (they bundle Python, numpy, matplotlib, networkx, Tk).
- On Linux, capturing without root needs membership in the `wireshark` group.
