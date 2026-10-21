#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

unset GITHUB_ACTIONS
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAILED=0
V=1.2.3
GH="$REPOSITORY_URL/releases/download/v$V"

pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; FAILED=1; }
check() {
  local name="$1"
  shift
  if "$@"; then pass "$name"; else fail "$name"; fi
}

fixture() {
  local dir="$WORK/$1"
  shift
  mkdir -p "$dir"
  touch "$dir/WyVPN_${V}_universal.dmg" "$dir/wyvpn_${V}_amd64.deb"
  local f
  for f in "$@"; do
    case "$f" in
      *.sig) printf 'sig-of-%s' "$f" | base64 >"$dir/$f" ;;
      *) printf 'payload %s' "$f" >"$dir/$f" ;;
    esac
  done
  printf '%s' "$dir"
}

manifest() {
  "$ROOT/scripts/updater-manifest.sh" "$@" >"$WORK/out" 2>"$WORK/err"
}

field() {
  jq -r "$1" "$2"
}

mac="WyVPN_${V}_universal.app.tar.gz"
msi="WyVPN_${V}_x64_en-US.msi"

dir="$(fixture full "$mac" "$mac.sig" "$msi" "$msi.sig")"
check "full manifest is written" manifest "$dir" "$V"
m="$dir/latest.json"
check "full manifest has three platforms" \
  [ "$(field '.platforms | keys | join(",")' "$m")" = "darwin-aarch64,darwin-x86_64,windows-x86_64" ]
check "both macOS keys use the universal archive" \
  [ "$(field '.platforms["darwin-aarch64"].url' "$m")" = "$GH/$mac" ]
check "darwin-x86_64 matches darwin-aarch64" \
  [ "$(field '.platforms["darwin-x86_64"] == .platforms["darwin-aarch64"]' "$m")" = true ]
check "windows url points at the MSI" [ "$(field '.platforms["windows-x86_64"].url' "$m")" = "$GH/$msi" ]
check "signature is the .sig content" \
  [ "$(field '.platforms["windows-x86_64"].signature' "$m")" = "$(tr -d '\r\n' <"$dir/$msi.sig")" ]
check "version, notes and pub_date are set" \
  [ "$(field '[.version, .notes, (.pub_date | test("^[0-9-]{10}T[0-9:]{8}Z$"))] | map(tostring) | join("|")' "$m")" \
    = "$V|WyVPN $V|true" ]

dir="$(fixture none "$mac" "$msi")"
check "no signatures exits 0" manifest "$dir" "$V"
check "no signatures writes no manifest" [ ! -e "$dir/latest.json" ]
check "no signatures warns" grep -q "no updater signatures" "$WORK/err"

dir="$(fixture partial "$mac" "$mac.sig" "$msi")"
check "only the macOS signature fails" bash -c '! "$@" 2>/dev/null' _ "$ROOT/scripts/updater-manifest.sh" "$dir" "$V"
manifest "$dir" "$V" || true
check "partial failure names the missing .sig" grep -q "$msi.sig" "$WORK/err"
check "partial failure writes no manifest" [ ! -e "$dir/latest.json" ]

dir="$(fixture no-msi "$mac" "$mac.sig")"
manifest "$dir" "$V" || true
check "a missing MSI is named" grep -q "no MSI for $V" "$WORK/err"

umac="WyVPN_${V}_universal-unsigned.app.tar.gz"
umsi="WyVPN_${V}_x64_en-US-unsigned.msi"
dir="$(fixture unsigned "$umac" "$umac.sig" "$umsi" "$umsi.sig")"
check "unsigned installers are listed" manifest "$dir" "$V"
check "-unsigned macOS name is kept" [ "$(field '.platforms["darwin-x86_64"].url' "$dir/latest.json")" = "$GH/$umac" ]
check "-unsigned MSI name is kept" [ "$(field '.platforms["windows-x86_64"].url' "$dir/latest.json")" = "$GH/$umsi" ]

dir="$(fixture orphan "$mac" "$mac.sig" "$msi" "$msi.sig" "other.msi.sig")"
check "a .sig without its file fails" bash -c '! "$@" 2>/dev/null' _ "$ROOT/scripts/updater-manifest.sh" "$dir" "$V"

dir="$(fixture only "$mac" "$mac.sig")"
check "--only macos writes a macOS manifest" \
  manifest --only macos --base-url http://127.0.0.1:8787/ --notes "test" "$dir" "$V"
check "--base-url is used" \
  [ "$(field '.platforms["darwin-aarch64"].url' "$dir/latest.json")" = "http://127.0.0.1:8787/$mac" ]
check "--only macos has no Windows key" [ "$(field '.platforms | has("windows-x86_64")' "$dir/latest.json")" = false ]

check "an invalid version fails" bash -c '! "$@" 2>/dev/null' _ "$ROOT/scripts/updater-manifest.sh" "$WORK/full" "1.2"

m="$WORK/full/latest.json"
printf 'Fixes\r\n- one\r\n' | "$ROOT/scripts/updater-manifest.sh" --publish "$m" "$V" 2026-10-21T04:31:00Z 2>/dev/null
check "publish copies the notes" [ "$(field .notes "$m")" = $'Fixes\n- one' ]
check "publish sets pub_date" [ "$(field .pub_date "$m")" = 2026-10-21T04:31:00Z ]
check "publish keeps the signatures" [ "$(field '.platforms | length' "$m")" = 3 ]
printf '' | "$ROOT/scripts/updater-manifest.sh" --publish "$m" "$V" 2026-10-21T05:00:00Z 2>/dev/null
check "publish with an empty body falls back" [ "$(field .notes "$m")" = "WyVPN $V" ]
printf '### Fixed\r\n\r\n- one\r\n- a --- b\r\n\r\n---\r\n\r\nChecksums are in SHA256SUMS.\r\n\r\n---\r\nmore\r\n' \
  | "$ROOT/scripts/updater-manifest.sh" --publish "$m" "$V" 2026-10-21T05:00:00Z 2>/dev/null
check "publish drops the body footer after the first --- line" \
  [ "$(field .notes "$m")" = $'### Fixed\n\n- one\n- a --- b' ]
printf -- '---\nChecksums are in SHA256SUMS.\n' \
  | "$ROOT/scripts/updater-manifest.sh" --publish "$m" "$V" 2026-10-21T05:00:00Z 2>/dev/null
check "publish with only a footer falls back" [ "$(field .notes "$m")" = "WyVPN $V" ]
check "publish refuses another version" \
  bash -c '! printf x | "$@" 2>/dev/null' _ "$ROOT/scripts/updater-manifest.sh" --publish "$m" 9.9.9 2026-10-21T05:00:00Z

touch "$WORK/file.msi"
check "updater-sign.sh without a key exits 0" \
  env -u TAURI_SIGNING_PRIVATE_KEY "$ROOT/scripts/updater-sign.sh" "$WORK/file.msi" 2>"$WORK/err"
check "updater-sign.sh without a key warns" grep -q "TAURI_SIGNING_PRIVATE_KEY unset" "$WORK/err"
check "updater-sign.sh without a key writes no .sig" [ ! -e "$WORK/file.msi.sig" ]

pubkey="$(jq -r .plugins.updater.pubkey "$TAURI_DIR/tauri.conf.json")"
overlay() {
  printf '%s' "$2" >"$WORK/$1.json"
  printf '%s' "$WORK/$1.json"
}
refused() {
  local out
  if out="$("$ROOT/scripts/package.sh" linux --check-config --config "$1" 2>&1)"; then
    return 1
  fi
  grep -q "refusing this Tauri config: .*$2" <<<"$out"
}
check "guard rejects insecure transport" refused \
  "$(overlay insecure '{"plugins":{"updater":{"dangerousInsecureTransportProtocol":true}}}')" dangerousInsecure
check "guard rejects invalid certificates" refused \
  "$(overlay certs '{"plugins":{"updater":{"dangerousAcceptInvalidCerts":true}}}')" dangerousAcceptInvalidCerts
check "guard rejects the kebab-case alias" refused \
  "$(overlay kebab '{"plugins":{"updater":{"dangerous-insecure-transport-protocol":true}}}')" dangerous-insecure
check "guard rejects downgrades" refused \
  "$(overlay downgrade '{"plugins":{"updater":{"allowDowngrades":true}}}')" allowDowngrades
check "guard rejects a foreign endpoint" refused \
  "$(overlay endpoint '{"plugins":{"updater":{"endpoints":["https://example.com/latest.json"]}}}')" endpoints
extra="$(jq -nc --arg e "$UPDATER_ENDPOINT" '{plugins: {updater: {endpoints: [$e, "https://example.com/l.json"]}}}')"
check "guard rejects an extra endpoint" refused "$(overlay extra "$extra")" endpoints
check "guard rejects a removed endpoint list" refused \
  "$(overlay removed '{"plugins":{"updater":{"endpoints":null}}}')" endpoints
check "guard rejects another pubkey" refused "$(overlay pubkey '{"plugins":{"updater":{"pubkey":"b3RoZXI="}}}')" pubkey
check "guard rejects requireSignedVersion off" refused \
  "$(overlay unsigned-version '{"plugins":{"updater":{"requireSignedVersion":false}}}')" requireSignedVersion
check "guard rejects the requireSignedVersion alias" refused \
  "$(overlay alias-version '{"plugins":{"updater":{"require-signed-version":false}}}')" require-signed-version
check "guard rejects installer arguments" refused \
  "$(overlay installer-args '{"plugins":{"updater":{"windows":{"installerArgs":["/qn"]}}}}')" installerArgs
check "guard rejects the installer-args alias" refused \
  "$(overlay installer-alias '{"plugins":{"updater":{"windows":{"installer-args":["/qn"]}}}}')" installerArgs
check "guard accepts empty installer arguments" \
  bash -c '"$@" >/dev/null 2>&1' _ "$ROOT/scripts/package.sh" linux --check-config \
  --config "$(overlay installer-empty '{"plugins":{"updater":{"windows":{"installerArgs":[]}}}}')"
check "package.sh refuses the updater key in CI" \
  bash -c '! GITHUB_ACTIONS=true TAURI_SIGNING_PRIVATE_KEY=x "$@" >/dev/null 2>&1' _ "$ROOT/scripts/package.sh" linux --check-config
check "TAURI_CLI_VERSION matches bun.lock" \
  grep -qF "\"@tauri-apps/cli@$TAURI_CLI_VERSION\"" "$ROOT/bun.lock"
pinned_integrity() {
  local sri
  sri="$(lock_integrity "$1")" || return 1
  [[ "$sri" =~ ^sha512-[A-Za-z0-9+/]{86}==$ ]]
}
for pkg in cli cli-linux-x64-gnu "cli-$(tauri_cli_platform)"; do
  check "bun.lock pins the sha512 of @tauri-apps/$pkg@$TAURI_CLI_VERSION" \
    pinned_integrity "@tauri-apps/$pkg@$TAURI_CLI_VERSION"
done

mkdir -p "$WORK/registry/@tauri-apps/cli/-" "$WORK/pinned"
printf 'tampered' >"$WORK/registry/@tauri-apps/cli/-/cli-$TAURI_CLI_VERSION.tgz"
touch "$WORK/pinned/WyVPN_${V}_universal.app.tar.gz"
pinned_tampered() {
  ! WYVPN_NPM_REGISTRY="file://$WORK/registry" TAURI_SIGNING_PRIVATE_KEY=not-a-key \
    "$ROOT/scripts/updater-sign.sh" --pinned-cli "$WORK/pinned/WyVPN_${V}_universal.app.tar.gz" 2>"$WORK/err"
}
check "a tampered pinned CLI fails" pinned_tampered
check "the failure names the integrity mismatch" grep -q "integrity mismatch for @tauri-apps/cli@" "$WORK/err"
check "a tampered pinned CLI signs nothing" [ ! -e "$WORK/pinned/WyVPN_${V}_universal.app.tar.gz.sig" ]

for name in "WyVPN_${V}_universal-unsigned.app.tar.gz" "WyVPN_${V}_universal-unnotarized.app.tar.gz" \
  "WyVPN_${V}_x64_en-US-unsigned.msi"; do
  touch "$WORK/pinned/$name"
  check "--require-signed refuses $name" \
    bash -c '! TAURI_SIGNING_PRIVATE_KEY=not-a-key "$@" 2>/dev/null' _ \
    "$ROOT/scripts/updater-sign.sh" --require-signed "$WORK/pinned/$name"
done
touch "$WORK/pinned/WyVPN_${V}_x64_en-US.msi"
no_key() {
  local expect="$1"
  shift
  env -u TAURI_SIGNING_PRIVATE_KEY "$@" "$ROOT/scripts/updater-sign.sh" "${SIGN_ARGS[@]}" \
    "$WORK/pinned/WyVPN_${V}_universal.app.tar.gz" "$WORK/pinned/WyVPN_${V}_x64_en-US.msi" >"$WORK/err" 2>&1
  local rc=$?
  if [ "$expect" = fail ]; then
    [ "$rc" != 0 ] && grep -q "the release needs updater signatures" "$WORK/err"
  else
    [ "$rc" = 0 ] && grep -q "no updater signature" "$WORK/err"
  fi
}
SIGN_ARGS=(--require-signed)
check "--require-signed passes signed names and then fails without a key" no_key fail
SIGN_ARGS=(--pinned-cli)
check "--pinned-cli in GitHub Actions fails without a key" no_key fail GITHUB_ACTIONS=true
check "--pinned-cli locally warns without a key" no_key ok
SIGN_ARGS=(--app-version "$V")
check "a plain run in GitHub Actions warns without a key" no_key ok GITHUB_ACTIONS=true
check "updater-sign.sh captures the key before parsing arguments" \
  [ "$(grep -n '^KEY=' "$ROOT/scripts/updater-sign.sh" | cut -d: -f1)" \
    -lt "$(grep -n '^while ' "$ROOT/scripts/updater-sign.sh" | head -n 1 | cut -d: -f1)" ]
require_signed_message() {
  ! TAURI_SIGNING_PRIVATE_KEY=not-a-key "$ROOT/scripts/updater-sign.sh" --require-signed \
    "$WORK/pinned/WyVPN_${V}_x64_en-US-unsigned.msi" 2>"$WORK/err" \
    && grep -q "not code-signed or notarized" "$WORK/err"
}
check "--require-signed explains the refusal" require_signed_message

tag_ok() { (check_tag_version "$1") >/dev/null 2>&1; }
check "the tag check accepts v<workspace version>" tag_ok "v$(workspace_version)"
tag_refused() { ! tag_ok "$1"; }
check "the tag check refuses another tag" tag_refused v0.0.0-nope
check "guard rejects TAURI_CONFIG" \
  bash -c '! TAURI_CONFIG="{}" "$@" >/dev/null 2>&1' _ "$ROOT/scripts/package.sh" linux --check-config
check "test overlays are refused in CI" \
  bash -c '! CI=true WYVPN_UPDATER_E2E=1 "$@" >/dev/null 2>&1' _ "$ROOT/scripts/package.sh" linux --check-config --config "$WORK/insecure.json"
check "test overlays outside the test dir are refused" \
  bash -c '! env -u CI WYVPN_UPDATER_E2E=1 "$@" >/dev/null 2>&1' _ "$ROOT/scripts/package.sh" linux --check-config --config "$WORK/insecure.json"
check "package.sh --check-config passes without overlays" \
  bash -c '"$@" >/dev/null 2>&1' _ "$ROOT/scripts/package.sh" linux --check-config

guard_ok() { (check_release_config "$@") 2>/dev/null; }
for platform in macos windows linux; do
  configs=("$TAURI_DIR/tauri.release.conf.json")
  [ -f "$TAURI_DIR/tauri.release.$platform.conf.json" ] && configs+=("$TAURI_DIR/tauri.release.$platform.conf.json")
  check "committed $platform release config passes the guard" \
    guard_ok "$(merged_tauri_config "$platform" "${configs[@]}")"
done
check "the committed pubkey is set" [ -n "$pubkey" ]

e2e="$(jq -c --arg k "$(printf 'throwaway' | base64)" \
  '.plugins.updater += {pubkey: $k, endpoints: ["http://127.0.0.1:8787/latest.json"], dangerousInsecureTransportProtocol: true}' \
  "$TAURI_DIR/tauri.conf.json")"
check "test mode accepts a loopback overlay" guard_ok "$e2e" e2e
guard_refuses() { ! guard_ok "$@"; }
check "test mode still requires requireSignedVersion" guard_refuses \
  "$(jq -c '.plugins.updater.requireSignedVersion = false' <<<"$e2e")" e2e
check "test mode rejects the committed pubkey" guard_refuses \
  "$(jq -c '.plugins.updater.endpoints = ["http://127.0.0.1:8787/latest.json"]' "$TAURI_DIR/tauri.conf.json")" e2e

[ "$FAILED" = 0 ] || die "updater script tests failed"
say "all updater script tests passed"
