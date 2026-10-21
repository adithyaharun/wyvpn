#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/package.sh <macos|windows|linux> [--check-config] [--config <overlay.json>]...

Stages OpenVPN (macOS build, Windows fetch), Wintun (Windows fetch), wyvpnd and
wyvpn-cli, the license notice, runs `tauri build` with the release config
overlays and copies the installers into target/packaging/dist. On macOS it also
signs (see scripts/macos-sign-notarize.sh) and packs the stapled app as the
updater archive. Local builds with TAURI_SIGNING_PRIVATE_KEY also sign that
archive; in CI the updater-sign job does. A staged OpenVPN or Wintun matching
packaging/openvpn/VERSION or packaging/wintun/VERSION is reused.

Extra --config overlays are merged after the release overlays. The merged config
must keep the committed updater endpoint and pubkey and must not allow insecure
transport. --check-config only runs that check.
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
shift
OVERLAYS=()
CHECK_ONLY=false
while [ $# -gt 0 ]; do
  case "$1" in
    --config)
      [ -f "${2:-}" ] || die "--config needs an existing JSON file"
      OVERLAYS+=("$(abs_path "$2")")
      shift 2
      ;;
    --check-config) CHECK_ONLY=true; shift ;;
    *) usage; exit 2 ;;
  esac
done
[ -z "${TAURI_CONFIG:-}" ] || die "TAURI_CONFIG is not supported here; pass --config <file>"

UPDATER_KEY="${TAURI_SIGNING_PRIVATE_KEY:-}"
UPDATER_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD TAURI_SIGNING_PRIVATE_KEY_PATH \
  TAURI_PRIVATE_KEY TAURI_PRIVATE_KEY_PATH TAURI_PRIVATE_KEY_PASSWORD
if [ -n "$UPDATER_KEY" ] && [ "${GITHUB_ACTIONS:-}" = true ]; then
  die "the updater key must not reach build jobs; the updater-sign job signs in CI"
fi

CONFIGS=("$TAURI_DIR/tauri.release.conf.json")
[ -f "$TAURI_DIR/tauri.release.$PLATFORM.conf.json" ] \
  && CONFIGS+=("$TAURI_DIR/tauri.release.$PLATFORM.conf.json")
CONFIGS+=(${OVERLAYS[@]+"${OVERLAYS[@]}"})

GUARD=release
if [ "${WYVPN_UPDATER_E2E:-}" = 1 ]; then
  [ -z "${CI:-}" ] || die "updater test builds are local only"
  for overlay in ${OVERLAYS[@]+"${OVERLAYS[@]}"}; do
    case "$overlay" in
      "$UPDATER_TEST_DIR"/*) ;;
      *) die "updater test overlays must live in $UPDATER_TEST_DIR" ;;
    esac
  done
  GUARD=e2e
fi
command -v jq >/dev/null 2>&1 || die "jq is required"
MERGED="$(merged_tauri_config "$PLATFORM" "${CONFIGS[@]}")"
check_release_config "$MERGED" "$GUARD"
APP_VERSION="$(jq -r '.version // empty' <<<"$MERGED")"
[ -n "$APP_VERSION" ] || APP_VERSION="$(workspace_version)"
if $CHECK_ONLY; then
  say "$GUARD config check passed for $PLATFORM ($APP_VERSION)"
  exit 0
fi

DIST="$PACKAGING_DIR/dist"
BUNDLE_DIR="$TARGET_DIR/$TRIPLE/release/bundle"
load_openvpn_pins

staged_openvpn() {
  [ -f "$1/COPYING" ] && [ "$(cat "$1/VERSION" 2>/dev/null)" = "$OPENVPN_VERSION" ]
}

staged_wintun() {
  [ -f "$1/LICENSE.txt" ] && [ -f "$1/wintun.dll" ] \
    && [ "$(cat "$1/VERSION" 2>/dev/null)" = "$WINTUN_VERSION" ] \
    && [ "$(sha256_of "$1/wintun.dll")" = "$WINTUN_DLL_SHA256" ]
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
    ps=powershell
    command -v pwsh >/dev/null 2>&1 && ps=pwsh
    if ! staged_openvpn "$TAURI_DIR/resources/openvpn-windows"; then
      "$ps" -NoProfile -ExecutionPolicy Bypass -File "$ROOT/scripts/fetch-openvpn-windows.ps1"
    fi
    load_wintun_pins
    if ! staged_wintun "$TAURI_DIR/resources/wintun-windows"; then
      "$ps" -NoProfile -ExecutionPolicy Bypass -File "$ROOT/scripts/fetch-wintun-windows.ps1"
    fi
    ;;
esac

"$ROOT/scripts/stage-binaries.sh" "$TRIPLE"
"$ROOT/scripts/gen-licenses.sh"

CONFIG_ARGS=()
for config in "${CONFIGS[@]}"; do
  CONFIG_ARGS+=(--config "$config")
done
EXTRA=()
[ "$PLATFORM" = macos ] && EXTRA=(--no-sign)

rm -rf "$BUNDLE_DIR" "$DIST"
# Signing and notarization run in our own script, not in the Tauri bundler.
(cd "$ROOT/apps/desktop" && env -u APPLE_SIGNING_IDENTITY -u APPLE_CERTIFICATE -u APPLE_API_KEY \
  -u APPLE_API_ISSUER -u APPLE_API_KEY_PATH -u APPLE_ID -u APPLE_PASSWORD \
  bun run tauri build --ci --target "$TRIPLE" --bundles "$BUNDLES" \
  "${CONFIG_ARGS[@]}" ${EXTRA[@]+"${EXTRA[@]}"})

macos_updater_archive() {
  local dmgs suffix archive
  dmgs=("$DIST"/WyVPN_*_universal*.dmg)
  if [ ${#dmgs[@]} -ne 1 ] || [ ! -f "${dmgs[0]}" ]; then
    die "expected one .dmg in $DIST"
  fi
  suffix="$(basename "${dmgs[0]}" .dmg)"
  suffix="${suffix#WyVPN_*_universal}"
  archive="$DIST/WyVPN_${APP_VERSION}_universal${suffix}.app.tar.gz"
  COPYFILE_DISABLE=1 tar --no-xattrs -C "$BUNDLE_DIR/macos" -czf "$archive" WyVPN.app
  if [ -z "$UPDATER_KEY" ]; then
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
      say "$(basename "$archive") is left for the updater-sign job"
    else
      warn "TAURI_SIGNING_PRIVATE_KEY unset; $(basename "$archive") has no updater signature"
    fi
    return
  fi
  TAURI_SIGNING_PRIVATE_KEY="$UPDATER_KEY" TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$UPDATER_KEY_PASSWORD" \
    "$ROOT/scripts/updater-sign.sh" --app-version "$APP_VERSION" "$archive"
}

mkdir -p "$DIST"
case "$PLATFORM" in
  macos)
    "$ROOT/scripts/macos-sign-notarize.sh" "$BUNDLE_DIR/macos/WyVPN.app" "$DIST" >/dev/null
    macos_updater_archive
    ;;
  windows) cp "$BUNDLE_DIR"/msi/*.msi "$DIST/" ;;
  linux) cp "$BUNDLE_DIR"/deb/*.deb "$BUNDLE_DIR"/rpm/*.rpm "$DIST/" ;;
esac

say "installers in $DIST:"
ls -l "$DIST" >&2
