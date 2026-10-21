# shellcheck shell=bash disable=SC2034
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAURI_DIR="$ROOT/apps/desktop/src-tauri"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
PACKAGING_DIR="$TARGET_DIR/packaging"

say() { printf '\033[1m[%s]\033[0m %s\n' "${0##*/}" "$*" >&2; }
die() { printf '\033[31m[%s]\033[0m %s\n' "${0##*/}" "$*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

fetch_verified() {
  local url="$1" sha="$2" dest="$3" got
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "missing or placeholder SHA-256 for $url"
  if [ ! -f "$dest" ] || [ "$(sha256_of "$dest")" != "$sha" ]; then
    say "downloading $url"
    mkdir -p "$(dirname "$dest")"
    curl -fsSL --retry 3 -o "$dest.part" "$url"
    mv -f "$dest.part" "$dest"
  fi
  got="$(sha256_of "$dest")"
  if [ "$got" != "$sha" ]; then
    rm -f "$dest"
    die "SHA-256 mismatch for $url: expected $sha, got $got"
  fi
}

load_openvpn_pins() {
  # shellcheck disable=SC1091
  source "$ROOT/packaging/openvpn/VERSION"
  local key
  for key in OPENVPN_VERSION OPENVPN_SOURCE_URL OPENVPN_SOURCE_SHA256; do
    [ -n "${!key:-}" ] || die "$key missing from packaging/openvpn/VERSION"
  done
}

load_wintun_pins() {
  # shellcheck disable=SC1091
  source "$ROOT/packaging/wintun/VERSION"
  local key
  for key in WINTUN_VERSION WINTUN_DLL_SHA256; do
    [ -n "${!key:-}" ] || die "$key missing from packaging/wintun/VERSION"
  done
}

workspace_version() {
  awk '
    /^\[workspace\.package\]/ { f = 1; next }
    /^\[/ { f = 0 }
    f && /^version[[:space:]]*=/ { gsub(/.*=[[:space:]]*"|".*/, ""); print; exit }
  ' "$ROOT/Cargo.toml"
}

REPOSITORY_URL="https://github.com/adithyaharun/wyvpn"
UPDATER_ENDPOINT="$REPOSITORY_URL/releases/latest/download/latest.json"
UPDATER_TEST_DIR="$TARGET_DIR/updater-test"
TAURI_CLI_VERSION=2.12.2

warn() {
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    printf '::warning::%s\n' "$*"
  else
    printf '\033[33m[%s]\033[0m %s\n' "${0##*/}" "$*" >&2
  fi
}

abs_path() {
  printf '%s/%s\n' "$(cd "$(dirname "$1")" && pwd)" "$(basename "$1")"
}

# Tauri merges the platform file and each --config overlay as RFC 7396 merge patches.
merged_tauri_config() {
  local platform="$1"
  shift
  local files=("$TAURI_DIR/tauri.conf.json")
  [ -f "$TAURI_DIR/tauri.$platform.conf.json" ] && files+=("$TAURI_DIR/tauri.$platform.conf.json")
  jq -cs '
    def patch($p):
      if ($p | type) == "object" then
        reduce ($p | to_entries[]) as $e (if type == "object" then . else {} end;
          if $e.value == null then del(.[$e.key]) else .[$e.key] |= patch($e.value) end)
      else $p end;
    reduce .[1:][] as $o (.[0]; patch($o))
  ' "${files[@]}" "$@"
}

check_release_config() {
  local merged="$1" mode="${2:-release}" committed args problems
  committed="$(jq -r '.plugins.updater.pubkey // empty' "$TAURI_DIR/tauri.conf.json")"
  [ -n "$committed" ] || die "tauri.conf.json has no plugins.updater.pubkey"
  args="$(jq -c '.plugins.updater.windows.installerArgs // []' "$TAURI_DIR/tauri.conf.json")"
  problems="$(jq -r --arg endpoint "$UPDATER_ENDPOINT" --arg pubkey "$committed" --arg mode "$mode" \
    --argjson args "$args" '
    def normalized: ascii_downcase | gsub("-"; "");
    (.plugins.updater // {}) as $u
    | (if $u.requireSignedVersion != true
        then "plugins.updater.requireSignedVersion is not true" else empty end),
      ($u | keys[] | select(normalized == "requiresignedversion" and . != "requireSignedVersion")
        | "plugins.updater.\(.) is not allowed"),
      if $mode == "e2e" then
        (if ($u.endpoints // []) | (length == 0 or any(.[]; startswith("http://127.0.0.1:") | not))
          then "test endpoints must be on http://127.0.0.1" else empty end),
        (if ($u.pubkey // "") == "" or $u.pubkey == $pubkey
          then "test builds need a throwaway pubkey" else empty end)
      else
        ($u | to_entries[]
          | select(.key | ascii_downcase | gsub("-"; "") | startswith("dangerous") or . == "allowdowngrades")
          | select(.value != false and .value != null)
          | "plugins.updater.\(.key) is set"),
        (if $u.endpoints != [$endpoint]
          then "plugins.updater.endpoints is not [\"\($endpoint)\"]" else empty end),
        (if $u.pubkey != $pubkey
          then "plugins.updater.pubkey differs from tauri.conf.json" else empty end),
        ([$u.windows // {} | to_entries[] | select(.key | normalized == "installerargs")] as $set
          | if ($set | length) > 1 or ($set | any(.value != null and .value != [] and .value != $args))
            then "plugins.updater.windows.installerArgs differs from tauri.conf.json" else empty end)
      end
  ' <<<"$merged")"
  [ -z "$problems" ] || die "refusing this Tauri config: $(printf '%s' "$problems" | paste -sd ';' - | sed 's/;/; /g')"
}

check_tag_version() {
  local version
  version="$(workspace_version)"
  [ "$1" = "v$version" ] && return 0
  [ "${GITHUB_ACTIONS:-}" != true ] || printf '::error::tag %s does not match version %s\n' "$1" "$version"
  die "tag $1 does not match version $version"
}

lock_integrity() {
  local lines
  lines="$(grep -F "[\"$1\"," "$ROOT/bun.lock" || true)"
  if [ -z "$lines" ] || [ "$(printf '%s\n' "$lines" | wc -l | tr -d ' ')" != 1 ]; then
    return 1
  fi
  printf '%s\n' "$lines" | grep -oE 'sha512-[A-Za-z0-9+/]+={0,2}' | tail -n 1
}

tauri_cli_platform() {
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) echo linux-x64-gnu ;;
    Linux-aarch64) echo linux-arm64-gnu ;;
    Darwin-arm64) echo darwin-arm64 ;;
    Darwin-x86_64) echo darwin-x64 ;;
    *) die "no pinned Tauri CLI for $(uname -s) $(uname -m)" ;;
  esac
}

install_pinned_tauri_cli() {
  local dir="$1" registry="${WYVPN_NPM_REGISTRY:-https://registry.npmjs.org}" platform name pkg tgz want got
  platform="$(tauri_cli_platform)"
  for name in cli "cli-$platform"; do
    pkg="@tauri-apps/$name"
    want="$(lock_integrity "$pkg@$TAURI_CLI_VERSION")" || die "no single $pkg@$TAURI_CLI_VERSION entry in bun.lock"
    [ -n "$want" ] || die "no sha512 integrity for $pkg@$TAURI_CLI_VERSION in bun.lock"
    tgz="$dir/$name.tgz"
    curl -fsSL --retry 3 -o "$tgz" "$registry/$pkg/-/$name-$TAURI_CLI_VERSION.tgz" \
      || die "could not download $pkg@$TAURI_CLI_VERSION"
    got="sha512-$(openssl dgst -sha512 -binary "$tgz" | openssl base64 -A)"
    [ "$got" = "$want" ] || die "integrity mismatch for $pkg@$TAURI_CLI_VERSION: bun.lock has $want, got $got"
    mkdir -p "$dir/node_modules/$pkg"
    tar -xzf "$tgz" -C "$dir/node_modules/$pkg" --strip-components 1
  done
}
