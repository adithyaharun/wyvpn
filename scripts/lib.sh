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

workspace_version() {
  awk '
    /^\[workspace\.package\]/ { f = 1; next }
    /^\[/ { f = 0 }
    f && /^version[[:space:]]*=/ { gsub(/.*=[[:space:]]*"|".*/, ""); print; exit }
  ' "$ROOT/Cargo.toml"
}
