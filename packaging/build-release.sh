#!/usr/bin/env bash
# Build a prebuilt-binary tarball: dist/memguard-<version>-<arch>.tar.gz
# Users extract it and run: sudo ./packaging/install.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
ARCH=$(uname -m)
BIN="$ROOT/target/release"
[ -x "$BIN/memguard" ] && [ -x "$BIN/memguard-hog" ] || { echo "build first: cargo build --release"; exit 1; }
NAME="memguard-${VERSION}-${ARCH}"
S="$ROOT/dist/$NAME"
rm -rf "$S"; mkdir -p "$S/bin" "$S/packaging" "$S/scripts" "$S/skills"
install -m 0755 "$BIN/memguard" "$BIN/memguard-hog" "$S/bin/"
install -m 0644 "$ROOT/packaging/memguard.service" "$ROOT/packaging/memguard.conf" "$ROOT/packaging/90-memguard-sysctl.conf" "$S/packaging/"
install -m 0755 "$ROOT/packaging/install.sh" "$ROOT/packaging/uninstall.sh" "$S/packaging/"
install -m 0755 "$ROOT/scripts/safe-test.sh" "$S/scripts/"
cp -r "$ROOT/skills/memguard" "$S/skills/"
install -m 0644 "$ROOT/README.md" "$ROOT/LICENSE" "$S/"
tar -C "$ROOT/dist" -czf "$ROOT/dist/$NAME.tar.gz" "$NAME"
rm -rf "$S"
sha256sum "$ROOT/dist/$NAME.tar.gz" "$ROOT"/dist/*.deb 2>/dev/null | sed "s#$ROOT/dist/##" > "$ROOT/dist/SHA256SUMS"
echo "built $ROOT/dist/$NAME.tar.gz"
