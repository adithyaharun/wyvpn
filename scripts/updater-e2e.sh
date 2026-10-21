#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PORT=8787

usage() {
  cat >&2 <<EOF
Usage: scripts/updater-e2e.sh

Local end-to-end test of the in-app updater on macOS. Builds two ad-hoc signed
release bundles with a test overlay (a throwaway key pair, the feed at
http://127.0.0.1:$PORT/latest.json and insecure transport allowed):

  A  the current version, to install by hand
  B  the next patch version with -test.1, served as the update

Everything lands in target/updater-test/, which each run replaces. The real
updater key and the Apple signing settings are never used.
EOF
}

case "${1:-}" in
  -h | --help) usage; exit 0 ;;
  "") ;;
  *) usage; exit 2 ;;
esac
[ "$(uname -s)" = Darwin ] || die "macOS only"
[ -z "${CI:-}" ] || die "local only"
for tool in bun jq openssl python3; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

for var in TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD TAURI_SIGNING_PRIVATE_KEY_PATH \
  TAURI_PRIVATE_KEY TAURI_PRIVATE_KEY_PATH TAURI_PRIVATE_KEY_PASSWORD TAURI_CONFIG \
  APPLE_SIGNING_IDENTITY APPLE_CERTIFICATE APPLE_API_KEY APPLE_API_ISSUER APPLE_API_KEY_PATH \
  APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID WYVPN_TEAM_ID; do
  unset "$var"
done

CURRENT="$(workspace_version)"
[[ "$CURRENT" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || die "workspace version $CURRENT is not a plain release"
# <current>-test.1 would sort below <current>, so B bumps the patch.
NEXT="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))-test.1"

DIR="$UPDATER_TEST_DIR"
case "$DIR" in
  */updater-test) ;;
  *) die "unexpected test directory $DIR" ;;
esac
rm -rf "$DIR"
mkdir -p "$DIR/key" "$DIR/a" "$DIR/b" "$DIR/feed"
chmod 700 "$DIR/key"

say "generating a throwaway updater key in $DIR/key"
PASSWORD="$(openssl rand -hex 16)"
(cd "$ROOT/apps/desktop" && bun run tauri signer generate --ci -p "$PASSWORD" -w "$DIR/key/updater.key" \
  </dev/null >/dev/null 2>&1) || die "tauri signer generate failed"
PUBKEY="$(cat "$DIR/key/updater.key.pub")"
[ "$PUBKEY" != "$(jq -r .plugins.updater.pubkey "$TAURI_DIR/tauri.conf.json")" ] || die "throwaway key equals the release key"

overlay() {
  jq -n --arg pubkey "$PUBKEY" --arg endpoint "http://127.0.0.1:$PORT/latest.json" --arg version "${1:-}" '
    {plugins: {updater: {pubkey: $pubkey, endpoints: [$endpoint], dangerousInsecureTransportProtocol: true}}}
    + (if $version == "" then {} else {version: $version} end)'
}
overlay >"$DIR/overlay-a.json"
overlay "$NEXT" >"$DIR/overlay-b.json"

build() {
  say "building $1 ($2)"
  WYVPN_UPDATER_E2E=1 TAURI_SIGNING_PRIVATE_KEY="$(cat "$DIR/key/updater.key")" \
    TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$PASSWORD" \
    "$ROOT/scripts/package.sh" macos --config "$DIR/overlay-$1.json"
  cp -R "$PACKAGING_DIR/dist/." "$DIR/$1/"
}
build a "$CURRENT"
build b "$NEXT"

shopt -s nullglob
dmgs=("$DIR"/a/*.dmg)
archives=("$DIR"/b/WyVPN_"$NEXT"_universal*.app.tar.gz)
shopt -u nullglob
[ ${#dmgs[@]} -eq 1 ] || die "expected one .dmg in $DIR/a"
[ ${#archives[@]} -eq 1 ] || die "expected one updater archive in $DIR/b"
cp "${archives[0]}" "${archives[0]}.sig" "$DIR/feed/"
"$ROOT/scripts/updater-manifest.sh" --only macos --base-url "http://127.0.0.1:$PORT" \
  --notes "Test update from $CURRENT to $NEXT." "$DIR/feed" "$NEXT" >/dev/null
ARCHIVE="$DIR/feed/$(basename "${archives[0]}")"

cat >&2 <<EOF

Feed ready in $DIR/feed. Next steps:

1. Install A over your current WyVPN: open ${dmgs[0]}
   and drag WyVPN to Applications. Approve the service if asked.
2. Serve the feed (leave it running):
     python3 -m http.server $PORT --bind 127.0.0.1 --directory "$DIR/feed"
3. In A, connect a profile, then choose Check for Updates… in the tray.
   The prompt shows $NEXT with the VPN warning. Click Install: the VPN
   disconnects, the download shows progress, and WyVPN relaunches as $NEXT.
4. Failure cases (reinstall A first):
     corrupt archive:  cp "$ARCHIVE" "$ARCHIVE.orig" && printf x >>"$ARCHIVE"
     corrupt .sig:     cp "$ARCHIVE.sig" "$ARCHIVE.sig.orig" && printf 'AAAA' >"$ARCHIVE.sig" &&
                       "$ROOT/scripts/updater-manifest.sh" --only macos --base-url http://127.0.0.1:$PORT "$DIR/feed" "$NEXT"
   Each must show an error and leave A installed.
5. With "Check for updates automatically" off, relaunch A: the server log must
   show no request.

A and B trust only the throwaway key. Install a release build afterwards to get
real updates again.
EOF
