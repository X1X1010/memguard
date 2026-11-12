#!/usr/bin/env bash
# Build a Debian package from the release binaries: dist/memguard_<version>_arm64.deb
# Usage: ./packaging/build-deb.sh   (after cargo build --release)
#   MAINTAINER="Name <email>" HOMEPAGE=https://... override the control fields.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
ARCH=$(dpkg --print-architecture)
MAINTAINER="${MAINTAINER:-X1X1010 <X1X1010@users.noreply.github.com>}"
HOMEPAGE="${HOMEPAGE:-https://github.com/X1X1010/memguard}"
BIN="$ROOT/target/release"
[ -x "$BIN/memguard" ] && [ -x "$BIN/memguard-hog" ] || { echo "build first: cargo build --release"; exit 1; }
PKG="memguard_${VERSION}_${ARCH}"
D="$ROOT/dist/$PKG"
rm -rf "$D"; mkdir -p "$D/DEBIAN" "$D/usr/sbin" "$D/usr/bin" "$D/usr/lib/systemd/system" "$D/etc/memguard" \
  "$D/usr/share/doc/memguard" "$D/usr/share/memguard/skills" "$D/usr/share/memguard/scripts"
install -m 0755 "$BIN/memguard" "$D/usr/sbin/memguard"
install -m 0755 "$BIN/memguard-hog" "$D/usr/sbin/memguard-hog"
ln -s ../sbin/memguard "$D/usr/bin/memguard"
ln -s ../sbin/memguard-hog "$D/usr/bin/memguard-hog"
sed 's#/usr/local/sbin/memguard#/usr/sbin/memguard#; s#/usr/local/share/doc/memguard#/usr/share/doc/memguard#' \
  "$ROOT/packaging/memguard.service" > "$D/usr/lib/systemd/system/memguard.service"
chmod 0644 "$D/usr/lib/systemd/system/memguard.service"
install -m 0644 "$ROOT/packaging/memguard.conf" "$D/etc/memguard/memguard.conf"
install -m 0644 "$ROOT/README.md" "$D/usr/share/doc/memguard/README.md"
install -m 0644 "$ROOT/packaging/90-memguard-sysctl.conf" "$D/usr/share/doc/memguard/90-memguard-sysctl.conf.example"
install -m 0755 "$ROOT/scripts/safe-test.sh" "$D/usr/share/memguard/scripts/safe-test.sh"
cp -r "$ROOT/skills/memguard" "$D/usr/share/memguard/skills/"
{ echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"; echo "Upstream-Name: memguard"; echo "Source: $HOMEPAGE"; echo; echo "Files: *"; echo "Copyright: 2026 Yicheng Chen"; echo "License: MIT"; sed 's/^/ /; s/^ $/ ./' "$ROOT/LICENSE" | tail -n +3; } > "$D/usr/share/doc/memguard/copyright"
cat > "$D/DEBIAN/control" <<CTRL
Package: memguard
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Maintainer: $MAINTAINER
Homepage: $HOMEPAGE
Depends: systemd (>= 245), libc6 (>= 2.34)
Description: memory watchdog for NVIDIA GB10 (DGX Spark) unified memory
 On GB10 every cudaMalloc is system RAM that the kernel cannot attribute
 to a process, so a runaway GPU job freezes the whole machine instead of
 getting a CUDA out-of-memory error. memguard watches MemAvailable and
 memory pressure at 50 ms, attributes GPU memory per process through NVML,
 keeps free headroom, and kills the offending job before the freeze.
 It also runs single jobs under GPU/RAM budgets (memguard run).
CTRL
echo "/etc/memguard/memguard.conf" > "$D/DEBIAN/conffiles"
cat > "$D/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ -z "$2" ]; then
        systemctl enable memguard.service >/dev/null 2>&1 || true
    fi
    if ! systemctl restart memguard.service >/dev/null 2>&1; then
        echo "memguard: service did not start; see 'journalctl -u memguard' (systemd-oomd/earlyoom active?)"
    fi
    echo "memguard: run 'memguard doctor' and 'memguard status' to verify; config in /etc/memguard/memguard.conf"
fi
POST
cat > "$D/DEBIAN/prerm" <<'PRE'
#!/bin/sh
set -e
if [ "$1" = "remove" ]; then
    systemctl disable --now memguard.service >/dev/null 2>&1 || true
fi
PRE
cat > "$D/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
if [ "$1" = "purge" ]; then
    rm -rf /etc/memguard /run/memguard
fi
POSTRM
chmod 0755 "$D/DEBIAN/postinst" "$D/DEBIAN/prerm" "$D/DEBIAN/postrm"
find "$D" -type d -exec chmod 0755 {} +
chmod 0644 "$D/usr/share/doc/memguard/copyright"
dpkg-deb --build --root-owner-group "$D" "$ROOT/dist/$PKG.deb" >/dev/null
rm -rf "$D"
echo "built $ROOT/dist/$PKG.deb"
