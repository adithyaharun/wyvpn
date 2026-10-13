#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

OUT="$TAURI_DIR/resources/THIRD_PARTY_LICENSES"
command -v cargo-about >/dev/null 2>&1 \
  || die "cargo-about not found; run: cargo install cargo-about --locked --features cli"
command -v bun >/dev/null 2>&1 || die "bun not found"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ABOUT_ARGS=(--workspace --fail --locked)
[ "${WYVPN_LICENSES_OFFLINE:-0}" = 1 ] && ABOUT_ARGS+=(--offline)

say "Rust licenses (cargo about)"
cargo about generate "${ABOUT_ARGS[@]}" \
  --manifest-path "$ROOT/Cargo.toml" --config "$ROOT/about.toml" \
  -o "$WORK/rust.txt" "$ROOT/packaging/licenses/about.hbs"

say "JavaScript licenses"
bun "$ROOT/scripts/js-licenses.ts" >"$WORK/js.txt"

rule() { printf '%s\n' "================================================================================"; }

{
  echo "WyVPN $(workspace_version) third-party licenses"
  echo
  echo "WyVPN is licensed under the MIT license. It includes or is built with the"
  echo "third-party software listed below, each under its own license."
  echo
  for dir in "$TAURI_DIR"/resources/openvpn-macos "$TAURI_DIR"/resources/openvpn-windows; do
    [ -f "$dir/COPYING" ] || continue
    rule
    echo "OpenVPN $(cat "$dir/VERSION" 2>/dev/null || echo)"
    echo
    echo "Bundled unmodified under GPL-2.0. The exact corresponding source is published"
    echo "with each WyVPN release on GitHub as openvpn-<version>.tar.gz."
    echo
    cat "$dir/COPYING"
    echo
    cat "$dir/LICENSE"
    echo
    for extra in "$dir"/third-party/*; do
      [ -f "$extra" ] || continue
      rule
      echo "$(basename "$extra" .txt), statically linked into OpenVPN"
      echo
      cat "$extra"
      echo
    done
  done
  rule
  cat "$WORK/rust.txt"
  rule
  cat "$WORK/js.txt"
} >"$WORK/THIRD_PARTY_LICENSES"

mkdir -p "$(dirname "$OUT")"
mv -f "$WORK/THIRD_PARTY_LICENSES" "$OUT"
say "wrote $OUT ($(wc -c <"$OUT" | tr -d ' ') bytes)"
