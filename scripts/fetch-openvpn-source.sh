#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ $# -eq 1 ] || { echo "Usage: scripts/fetch-openvpn-source.sh <out-dir>" >&2; exit 2; }
load_openvpn_pins
OUT="$1"
mkdir -p "$OUT"
fetch_verified "$OPENVPN_SOURCE_URL" "$OPENVPN_SOURCE_SHA256" "$OUT/openvpn-$OPENVPN_VERSION.tar.gz"
# LZO is GPL-2.0 and statically linked into the macOS build.
fetch_verified "$LZO_URL" "$LZO_SHA256" "$OUT/lzo-$LZO_VERSION.tar.gz"
