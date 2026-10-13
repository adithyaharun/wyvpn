#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/macos-sign-notarize.sh <WyVPN.app> [out-dir]

Signs the inner binaries and the app, builds and signs the .dmg, then notarizes
and staples both. Prints the .dmg path.

  APPLE_SIGNING_IDENTITY   Developer ID Application identity in the keychain
  APPLE_API_KEY, APPLE_API_ISSUER, APPLE_API_KEY_PATH   notarytool API key
  APPLE_ID, APPLE_PASSWORD, APPLE_TEAM_ID               or Apple ID credentials

Without an identity the app is ad-hoc signed and the .dmg is named *-unsigned.
The bundled openvpn is left as is then: its checksum is pinned in wyvpnd.
With an identity but no notary credentials it is named *-unnotarized.
EOF
}

case "${1:-}" in
  -h | --help) usage; exit 0 ;;
  "") usage; exit 2 ;;
esac
[ "$(uname -s)" = Darwin ] || die "macOS only"

APP="${1%/}"
OUT_DIR="${2:-$(dirname "$APP")}"
[ -d "$APP/Contents/MacOS" ] || die "$APP is not an app bundle"
ENTITLEMENTS="$ROOT/packaging/macos/entitlements.plist"
VERSION="$(workspace_version)"
IDENTITY="${APPLE_SIGNING_IDENTITY:-}"
SUFFIX=""

if [ -z "$IDENTITY" ]; then
  say "APPLE_SIGNING_IDENTITY unset; ad-hoc signing"
  IDENTITY="-"
  TIMESTAMP=(--timestamp=none)
  SUFFIX="-unsigned"
else
  TIMESTAMP=(--timestamp)
fi

NOTARY=()
if [ "$IDENTITY" != "-" ]; then
  if [ -n "${APPLE_API_KEY:-}" ] && [ -n "${APPLE_API_ISSUER:-}" ] && [ -n "${APPLE_API_KEY_PATH:-}" ]; then
    NOTARY=(--key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER")
  elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_PASSWORD:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ]; then
    NOTARY=(--apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID")
  else
    say "no notarization credentials; skipping notarization"
    SUFFIX="-unnotarized"
  fi
fi

sign() {
  codesign --force --options runtime "${TIMESTAMP[@]}" --sign "$IDENTITY" "$@"
}

notarize() {
  local file="$1" result status id
  say "notarizing $(basename "$file")"
  result="$(xcrun notarytool submit "$file" "${NOTARY[@]}" --wait --timeout 2h --output-format json)" || true
  status="$(jq -r '.status // empty' <<<"$result" 2>/dev/null || true)"
  id="$(jq -r '.id // empty' <<<"$result" 2>/dev/null || true)"
  if [ "$status" != Accepted ]; then
    [ -z "$id" ] || xcrun notarytool log "$id" "${NOTARY[@]}" >&2 || true
    die "notarization of $file returned $status"
  fi
}

# Explicit identifiers: --force would otherwise keep the linker's hashed ad-hoc identifier.
for entry in \
  Contents/Resources/openvpn/openvpn=com.aprdth.wyvpn.openvpn \
  Contents/MacOS/wyvpnd=com.aprdth.wyvpn.daemon \
  Contents/MacOS/wyvpn-cli=com.aprdth.wyvpn.cli; do
  inner="${entry%%=*}"
  [ -f "$APP/$inner" ] || die "missing $APP/$inner"
  if [ "$IDENTITY" = "-" ] && [ "$inner" = Contents/Resources/openvpn/openvpn ]; then
    continue
  fi
  say "signing $inner"
  sign --identifier "${entry#*=}" "$APP/$inner"
done
say "signing $(basename "$APP")"
sign --entitlements "$ENTITLEMENTS" "$APP"
codesign --verify --strict --deep --verbose=2 "$APP"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ ${#NOTARY[@]} -gt 0 ]; then
  ditto -c -k --keepParent "$APP" "$WORK/app.zip"
  notarize "$WORK/app.zip"
  xcrun stapler staple "$APP"
fi

mkdir -p "$OUT_DIR" "$WORK/dmg"
DMG="$OUT_DIR/WyVPN_${VERSION}_universal${SUFFIX}.dmg"
ditto "$APP" "$WORK/dmg/$(basename "$APP")"
ln -s /Applications "$WORK/dmg/Applications"
hdiutil create -volname WyVPN -srcfolder "$WORK/dmg" -fs HFS+ -format UDZO -ov "$DMG" >&2

if [ "$IDENTITY" != "-" ]; then
  codesign --force "${TIMESTAMP[@]}" --sign "$IDENTITY" "$DMG"
fi
if [ ${#NOTARY[@]} -gt 0 ]; then
  notarize "$DMG"
  xcrun stapler staple "$DMG"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
fi

echo "$DMG"
