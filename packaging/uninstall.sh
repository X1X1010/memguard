#!/usr/bin/env bash
# Remove memguard. Usage: sudo ./packaging/uninstall.sh [--purge]   (--purge also removes /etc/memguard)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
systemctl disable --now memguard.service 2>/dev/null || true
rm -f /etc/systemd/system/memguard.service /etc/sysctl.d/90-memguard.conf
rm -f /usr/local/bin/memguard /usr/local/bin/memguard-hog /usr/local/sbin/memguard /usr/local/sbin/memguard-hog
rm -rf /usr/local/share/doc/memguard /run/memguard
[ "${1:-}" = "--purge" ] && rm -rf /etc/memguard
systemctl daemon-reload
echo "memguard removed${1:+ ($1)}"
