#!/usr/bin/env bash
# Build the OT-ORCA GUI for Linux: a standalone PyInstaller binary and a .deb.
#
#   ./packaging/build_linux.sh
#
# Produces in ./release/ :
#   otorca-gui-<ver>-linux-x86_64        (standalone executable)
#   ot-orca-gui_<ver>_amd64.deb          (Debian/Ubuntu/Kali package)
#
# Runtime dependency: tshark (the .deb declares it via Depends:).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
VER="$(python3 -c 'import otorca.version as v; print(v.__version__)')"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
REL="$ROOT/release"
mkdir -p "$REL"

echo "==> OT-ORCA $VER — building Linux GUI ($ARCH)"

# 1) Freeze the GUI ---------------------------------------------------------
echo "==> PyInstaller"
rm -rf build/pyi dist
pyinstaller --noconfirm --distpath dist --workpath build/pyi \
    packaging/otorca-gui.spec
test -f dist/otorca-gui
cp dist/otorca-gui "$REL/otorca-gui-${VER}-linux-x86_64"
chmod +x "$REL/otorca-gui-${VER}-linux-x86_64"

# 2) Assemble the .deb tree -------------------------------------------------
echo "==> Packaging .deb"
PKG="ot-orca-gui"
STAGE="build/deb/${PKG}_${VER}_${ARCH}"
rm -rf "$STAGE"
install -d "$STAGE/DEBIAN"
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/share/applications"
install -d "$STAGE/usr/share/icons/hicolor/256x256/apps"
install -d "$STAGE/usr/share/doc/${PKG}"

install -m0755 dist/otorca-gui                       "$STAGE/usr/bin/otorca-gui"
install -m0644 packaging/assets/otorca-gui.desktop   "$STAGE/usr/share/applications/otorca-gui.desktop"
install -m0644 packaging/assets/otorca-gui.png       "$STAGE/usr/share/icons/hicolor/256x256/apps/otorca-gui.png"
install -m0644 README.md                             "$STAGE/usr/share/doc/${PKG}/README.md"
install -m0644 LICENSE                                "$STAGE/usr/share/doc/${PKG}/copyright"

INSTALLED_KB="$(du -ks "$STAGE/usr" | cut -f1)"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VER}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: tshark
Recommends: nmap
Installed-Size: ${INSTALLED_KB}
Maintainer: OT-ORCA contributors <noreply@ot-orca.local>
Homepage: https://github.com/yourorg/ot-orca
Description: Passive OT/ICS network security scanner (GUI)
 OT-ORCA (Operational Technology Observation, Reconnaissance & Compliance
 Analyzer) is a strictly passive OT/ICS network security scanner. It listens
 via tshark, builds an asset inventory and protocol map, runs a rules engine
 of ICS detections, and reports severity-rated findings with mitigations plus
 a Purdue-model network topology diagram.
 .
 This package installs the cross-platform graphical interface as a standalone
 application. tshark is required at runtime; to capture without root, add your
 user to the 'wireshark' group.
EOF

# Allow non-root capture reminder after install.
cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
echo "OT-ORCA GUI installed. tshark is required; to capture as a non-root"
echo "user: sudo usermod -aG wireshark \"\$USER\" then log out and back in."
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

DEB="$REL/${PKG}_${VER}_${ARCH}.deb"
fakeroot dpkg-deb --build "$STAGE" "$DEB"

echo
echo "==> Done. Artifacts in release/:"
ls -lh "$REL"
echo
echo "Verify:  dpkg-deb --info \"$DEB\""
