# Build the OT-ORCA GUI for Windows: a standalone .exe via PyInstaller.
#
#   powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
#
# Produces in .\release\ :
#   otorca-gui-<ver>-windows-x86_64.exe
#
# Requirements: Python 3.9+ on PATH. Wireshark (tshark) must be installed
# separately on the target machine for capture to work.
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")
$root = (Get-Location).Path

Write-Host "==> Installing build dependencies"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller

$ver = (python -c "import otorca.version as v; print(v.__version__)").Trim()
Write-Host "==> OT-ORCA $ver - building Windows GUI"

if (Test-Path dist) { Remove-Item -Recurse -Force dist }
if (Test-Path build\pyi) { Remove-Item -Recurse -Force build\pyi }

pyinstaller --noconfirm --distpath dist --workpath build\pyi `
    packaging\otorca-gui.spec

New-Item -ItemType Directory -Force -Path release | Out-Null
$out = "release\otorca-gui-$ver-windows-x86_64.exe"
Copy-Item dist\otorca-gui.exe $out -Force

Write-Host ""
Write-Host "==> Done: $out"
Get-Item $out | Format-List Name, Length
