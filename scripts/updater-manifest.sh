#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/updater-manifest.sh [options] <dist> <version>
       scripts/updater-manifest.sh --publish <latest.json> <version> <pub_date> <notes-file

Writes <dist>/latest.json for the in-app updater from the macOS archive
WyVPN_<version>_universal*.app.tar.gz, the Windows WyVPN_<version>_*.msi and
their .sig files. Both macOS keys point to the universal archive. With no .sig
it warns and writes nothing; with only one platform signed it fails.

  --base-url <url>        asset URL prefix (default: the GitHub release download URL of v<version>)
  --notes <text>          release notes (default: "WyVPN <version>")
  --only <macos|windows>  expect only this platform (local tests)

--publish replaces the notes with stdin up to the first line that is exactly
"---" (the release body footer) and sets pub_date, for a published release.
EOF
}

SEMVER='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'

validate() {
  jq -e '
    def filled: type == "string" and length > 0;
    (.version | filled)
    and (.notes | filled)
    and (.pub_date | type == "string"
      and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$"))
    and (.platforms | type == "object" and length > 0)
    and all(.platforms[]; (.url | filled and startswith("http")) and (.signature | filled))
  ' "$1" >/dev/null || die "$1 is not a complete update manifest"
}

check_version() {
  [[ "$1" =~ $SEMVER ]] || die "not a semver version: $1"
}

publish() {
  local file="$1" version="$2" pub_date="$3" notes
  [ -f "$file" ] || die "no such file: $file"
  check_version "$version"
  jq -e --arg version "$version" '.version == $version' "$file" >/dev/null \
    || die "$file is not the manifest of $version"
  notes="$(cat)"
  notes="${notes//$'\r'/}"
  notes="$(printf '%s\n' "$notes" | awk '$0 == "---" { exit } { print }')"
  [ -n "${notes//[[:space:]]/}" ] || notes="WyVPN $version"
  jq --arg notes "$notes" --arg pub_date "$pub_date" '.notes = $notes | .pub_date = $pub_date' \
    "$file" >"$file.tmp"
  validate "$file.tmp"
  mv -f "$file.tmp" "$file"
  say "set notes and pub_date $pub_date in $file"
}

if [ "${1:-}" = --publish ]; then
  [ $# -eq 4 ] || { usage; exit 2; }
  publish "$2" "$3" "$4"
  exit 0
fi

BASE_URL="" NOTES="" ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --base-url) BASE_URL="${2:?--base-url needs a value}"; shift 2 ;;
    --notes) NOTES="${2:?--notes needs a value}"; shift 2 ;;
    --only)
      case "${2:-}" in macos | windows) ONLY="$2" ;; *) usage; exit 2 ;; esac
      shift 2
      ;;
    -h | --help) usage; exit 0 ;;
    -*) usage; exit 2 ;;
    *) break ;;
  esac
done
[ $# -eq 2 ] || { usage; exit 2; }
DIST="${1%/}"
VERSION="$2"
[ -d "$DIST" ] || die "no such directory: $DIST"
check_version "$VERSION"
BASE_URL="${BASE_URL:-$REPOSITORY_URL/releases/download/v$VERSION}"
BASE_URL="${BASE_URL%/}"
NOTES="${NOTES:-WyVPN $VERSION}"
OUT="$DIST/latest.json"
rm -f "$OUT"

shopt -s nullglob
MAC=("$DIST/WyVPN_${VERSION}_universal"*.app.tar.gz)
WIN=("$DIST/WyVPN_${VERSION}_"*.msi)
SIGS=("$DIST"/*.sig)
shopt -u nullglob
[ ${#MAC[@]} -le 1 ] || die "more than one macOS updater archive in $DIST"
[ ${#WIN[@]} -le 1 ] || die "more than one MSI in $DIST"
for sig in ${SIGS[@]+"${SIGS[@]}"}; do
  [ -f "${sig%.sig}" ] || die "$sig has no matching file"
done

signed() {
  [ $# -eq 1 ] && [ -s "$1.sig" ]
}
missing() {
  if [ $# -eq 2 ]; then echo "$2.sig"; else echo "$1"; fi
}

mac_signed=false win_signed=false
signed ${MAC[@]+"${MAC[@]}"} && mac_signed=true
signed ${WIN[@]+"${WIN[@]}"} && win_signed=true

case "$ONLY" in
  macos)
    $mac_signed || die "missing updater signature: $(missing "no macOS archive for $VERSION" ${MAC[@]+"${MAC[@]}"})"
    win_signed=false
    ;;
  windows)
    $win_signed || die "missing updater signature: $(missing "no MSI for $VERSION" ${WIN[@]+"${WIN[@]}"})"
    mac_signed=false
    ;;
  *)
    if ! $mac_signed && ! $win_signed; then
      warn "no updater signatures in $DIST; not writing latest.json"
      exit 0
    fi
    $mac_signed || die "missing updater signature: $(missing "no macOS archive for $VERSION" ${MAC[@]+"${MAC[@]}"})"
    $win_signed || die "missing updater signature: $(missing "no MSI for $VERSION" ${WIN[@]+"${WIN[@]}"})"
    ;;
esac

entry() {
  local name
  name="$(basename "$1")"
  jq -n --arg url "$BASE_URL/$(jq -rn --arg name "$name" '$name | @uri')" \
    --arg signature "$(tr -d '\r\n' <"$1.sig")" '{signature: $signature, url: $url}'
}

platforms='{}'
if $mac_signed; then
  platforms="$(jq -c --argjson e "$(entry "${MAC[0]}")" '. + {"darwin-aarch64": $e, "darwin-x86_64": $e}' <<<"$platforms")"
fi
if $win_signed; then
  platforms="$(jq -c --argjson e "$(entry "${WIN[0]}")" '. + {"windows-x86_64": $e}' <<<"$platforms")"
fi

jq -n --arg version "$VERSION" --arg notes "$NOTES" --arg pub_date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson platforms "$platforms" \
  '{version: $version, notes: $notes, pub_date: $pub_date, platforms: $platforms}' >"$OUT.tmp"
validate "$OUT.tmp"
mv -f "$OUT.tmp" "$OUT"
say "wrote $OUT"
echo "$OUT"
