#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/package.sh <macos|windows|linux>

Stages OpenVPN (macOS build, Windows fetch), wyvpnd and wyvpn-cli, the license
notice, runs `tauri build` with the release config overlays and copies the
installers into target/packaging/dist. On macOS it also signs (see
scripts/macos-sign-notarize.sh). A staged OpenVPN matching
packaging/openvpn/VERSION is reused.
EOF
}

case "${1:-}" in
  macos) TRIPLE=universal-apple-darwin BUNDLES=app ;;
  windows) TRIPLE=x86_64-pc-windows-msvc BUNDLES=msi ;;
  linux) TRIPLE=x86_64-unknown-linux-gnu BUNDLES=deb,rpm ;;
  -h | --help) usage; exit 0 ;;
  *) usage; exit 2 ;;
esac
PLATFORM="$1"
DIST="$PACKAGING_DIR/dist"
BUNDLE_DIR="$TARGET_DIR/$TRIPLE/release/bundle"
load_openvpn_pins

staged_openvpn() {
  [ -f "$1/COPYING" ] && [ "$(cat "$1/VERSION" 2>/dev/null)" = "$OPENVPN_VERSION" ]
}

case "$PLATFORM" in
  macos)
    dir="$TAURI_DIR/resources/openvpn-macos"
    if ! staged_openvpn "$dir" || [ ! -f "$dir/openvpn" ]; then
      "$ROOT/scripts/build-openvpn-macos.sh"
    fi
    if [ -z "${WYVPN_TEAM_ID:-}" ] && [ -z "${APPLE_SIGNING_IDENTITY:-}" ]; then
      codesign --force --options runtime --timestamp=none --sign - \
        --identifier com.aprdth.wyvpn.openvpn "$dir/openvpn"
      WYVPN_OPENVPN_SHA256="$(sha256_of "$dir/openvpn")"
      export WYVPN_OPENVPN_SHA256
      say "unsigned build: pinning OpenVPN SHA-256 $WYVPN_OPENVPN_SHA256"
    fi
    ;;
  windows)
    dir="$TAURI_DIR/resources/openvpn-windows"
    if ! staged_openvpn "$dir"; then
      ps=powershell
      command -v pwsh >/dev/null 2>&1 && ps=pwsh
      "$ps" -NoProfile -ExecutionPolicy Bypass -File "$ROOT/scripts/fetch-openvpn-windows.ps1"
    fi
    ;;
esac

"$ROOT/scripts/stage-binaries.sh" "$TRIPLE"
"$ROOT/scripts/gen-licenses.sh"

CONFIGS=(--config "$TAURI_DIR/tauri.release.conf.json")
[ -f "$TAURI_DIR/tauri.release.$PLATFORM.conf.json" ] \
  && CONFIGS+=(--config "$TAURI_DIR/tauri.release.$PLATFORM.conf.json")
EXTRA=()
[ "$PLATFORM" = macos ] && EXTRA=(--no-sign)

rm -rf "$BUNDLE_DIR" "$DIST"
# Signing and notarization run in our own script, not in the Tauri bundler.
(cd "$ROOT/apps/desktop" && env -u APPLE_SIGNING_IDENTITY -u APPLE_CERTIFICATE -u APPLE_API_KEY \
  -u APPLE_API_ISSUER -u APPLE_API_KEY_PATH -u APPLE_ID -u APPLE_PASSWORD \
  bun run tauri build --ci --target "$TRIPLE" --bundles "$BUNDLES" \
  "${CONFIGS[@]}" ${EXTRA[@]+"${EXTRA[@]}"})

mkdir -p "$DIST"
case "$PLATFORM" in
  macos) "$ROOT/scripts/macos-sign-notarize.sh" "$BUNDLE_DIR/macos/WyVPN.app" "$DIST" >/dev/null ;;
  windows) cp "$BUNDLE_DIR"/msi/*.msi "$DIST/" ;;
  linux) cp "$BUNDLE_DIR"/deb/*.deb "$BUNDLE_DIR"/rpm/*.rpm "$DIST/" ;;
esac

say "installers in $DIST:"
ls -l "$DIST" >&2
