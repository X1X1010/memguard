#!/usr/bin/env bash
# Install memguard system-wide. Usage: sudo ./packaging/install.sh [--sysctl] [--no-enable]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SYSCTL=0; ENABLE=1
for a in "$@"; do
  case "$a" in
    --sysctl) SYSCTL=1 ;;
    --no-enable) ENABLE=0 ;;
    *) echo "unknown option $a"; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0 $*"; exit 1; }
# Source checkout (target/release) or extracted release tarball (bin/)
BIN="$ROOT/target/release"
[ -x "$BIN/memguard" ] || BIN="$ROOT/bin"
[ -x "$BIN/memguard" ] && [ -x "$BIN/memguard-hog" ] || { echo "no binaries: run 'cargo build --release' or extract a release tarball"; exit 1; }
# Validate before replacing an installed daemon or its unit.
CONFIG=/etc/memguard/memguard.conf
[ -e "$CONFIG" ] || CONFIG="$ROOT/packaging/memguard.conf"
"$BIN/memguard" check-config --config "$CONFIG" --quiet >/dev/null

install -d -m 0755 /usr/local/sbin /usr/local/bin /etc/memguard /usr/local/share/doc/memguard
install -m 0755 "$BIN/memguard" /usr/local/sbin/memguard.new
mv -f /usr/local/sbin/memguard.new /usr/local/sbin/memguard
install -m 0755 "$BIN/memguard-hog" /usr/local/sbin/memguard-hog.new
mv -f /usr/local/sbin/memguard-hog.new /usr/local/sbin/memguard-hog
ln -sf /usr/local/sbin/memguard /usr/local/bin/memguard
ln -sf /usr/local/sbin/memguard-hog /usr/local/bin/memguard-hog
[ -e /etc/memguard/memguard.conf ] || install -m 0644 "$ROOT/packaging/memguard.conf" /etc/memguard/memguard.conf
install -m 0644 "$ROOT/packaging/memguard.service" /etc/systemd/system/memguard.service
[ -e "$ROOT/README.md" ] && install -m 0644 "$ROOT/README.md" /usr/local/share/doc/memguard/README.md
if [ "$SYSCTL" = 1 ]; then
  install -m 0644 "$ROOT/packaging/90-memguard-sysctl.conf" /etc/sysctl.d/90-memguard.conf
  sysctl -q -p /etc/sysctl.d/90-memguard.conf
  echo "applied /etc/sysctl.d/90-memguard.conf"
fi
systemctl daemon-reload
/usr/local/sbin/memguard check-config --quiet >/dev/null
if [ "$ENABLE" = 1 ]; then
  systemctl enable memguard.service
  systemctl restart memguard.service
  sleep 1.5
  systemctl --no-pager --lines=8 status memguard.service
else
  echo "installed; enable with: systemctl enable --now memguard.service"
fi
echo
echo "next: memguard status | memguard doctor | journalctl -fu memguard"
