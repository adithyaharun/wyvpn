#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_openvpn_pins

warn() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::warning::$*"; else say "warning: $*"; fi
}

HEADERS=(-H "Accept: application/vnd.github+json")
[ -n "${GITHUB_TOKEN:-}" ] && HEADERS+=(-H "Authorization: Bearer $GITHUB_TOKEN")

if ! releases="$(curl -fsSL "${HEADERS[@]}" "https://api.github.com/repos/OpenVPN/openvpn/releases?per_page=100")"; then
  warn "could not query OpenVPN releases"
  exit 0
fi
latest="$(jq -r '.[] | select(.prerelease | not) | .tag_name' <<<"$releases" \
  | sed -n 's/^v\(2\.6\.[0-9][0-9]*\)$/\1/p' | sort -t. -k3,3n | tail -n 1)"

pinned_patch="${OPENVPN_VERSION##*.}"
latest_patch="${latest##*.}"
if [ -n "$latest" ] && [ "$latest_patch" -gt "$pinned_patch" ]; then
  warn "OpenVPN $latest is available; packaging/openvpn/VERSION pins $OPENVPN_VERSION"
else
  say "OpenVPN $OPENVPN_VERSION is the latest 2.6.x"
fi
