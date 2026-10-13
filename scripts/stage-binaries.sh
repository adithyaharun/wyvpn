#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  echo "Usage: scripts/stage-binaries.sh [<target-triple>|universal-apple-darwin]" >&2
  echo "Builds wyvpnd and wyvpn-cli in release mode into $TAURI_DIR/binaries (default: host triple)." >&2
}

case "${1:-}" in
  -h | --help) usage; exit 0 ;;
esac
[ $# -le 1 ] || { usage; exit 2; }

TARGET="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
BIN_DIR="$TAURI_DIR/binaries"
BINS=(wyvpnd wyvpn-cli)
EXT=""
[[ "$TARGET" == *windows* ]] && EXT=".exe"

if [[ "$TARGET" == *apple-darwin && -z "${WYVPN_TEAM_ID:-}" && -z "${WYVPN_OPENVPN_SHA256:-}" ]]; then
  say "warning: WYVPN_TEAM_ID and WYVPN_OPENVPN_SHA256 are unset; the daemon cannot verify the bundled OpenVPN"
fi
if [[ "$TARGET" == *windows* && -z "${WYVPN_PUBLISHER:-}" ]]; then
  say "warning: WYVPN_PUBLISHER is unset; the daemon trusts only the OpenVPN publisher"
fi

build() {
  say "building ${BINS[*]} for $1"
  cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked \
    -p wyvpn-daemon -p wyvpn-cli --target "$1"
}

stage() {
  local triple="$1" bin
  for bin in "${BINS[@]}"; do
    install -m 755 "$TARGET_DIR/$triple/release/$bin$EXT" "$BIN_DIR/$bin-$triple$EXT"
  done
}

mkdir -p "$BIN_DIR"
if [ "$TARGET" = universal-apple-darwin ]; then
  # tauri-build looks up the per-arch names; the bundler looks up the universal one.
  for triple in aarch64-apple-darwin x86_64-apple-darwin; do
    build "$triple"
    stage "$triple"
  done
  for bin in "${BINS[@]}"; do
    lipo -create \
      "$BIN_DIR/$bin-aarch64-apple-darwin" "$BIN_DIR/$bin-x86_64-apple-darwin" \
      -output "$BIN_DIR/$bin-universal-apple-darwin"
  done
else
  build "$TARGET"
  stage "$TARGET"
fi

say "staged:"
find "$BIN_DIR" -type f -name "*-$TARGET$EXT" -exec ls -l {} + >&2
