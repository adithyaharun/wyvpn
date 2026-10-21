#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
KEY="${TAURI_SIGNING_PRIVATE_KEY:-}"
KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"
unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD TAURI_SIGNING_PRIVATE_KEY_PATH \
  TAURI_PRIVATE_KEY TAURI_PRIVATE_KEY_PATH TAURI_PRIVATE_KEY_PASSWORD NAPI_RS_NATIVE_LIBRARY_PATH

usage() {
  cat >&2 <<'EOF'
Usage: scripts/updater-sign.sh [--app-version <version>] [--pinned-cli] [--require-signed] <file>...

Signs each file for the in-app updater with `tauri signer sign` and writes
<file>.sig. The signature is bound to --app-version (default: the workspace
version).

  --pinned-cli      download @tauri-apps/cli at TAURI_CLI_VERSION (scripts/lib.sh)
                    into an empty directory and check both tarballs against the
                    sha512 integrity in bun.lock, instead of using
                    apps/desktop/node_modules
  --require-signed  refuse files named *-unsigned* or *-unnotarized*

  TAURI_SIGNING_PRIVATE_KEY            private key contents (not a path)
  TAURI_SIGNING_PRIVATE_KEY_PASSWORD   its password

Without TAURI_SIGNING_PRIVATE_KEY it prints a warning and exits 0, except with
--require-signed or with --pinned-cli in GitHub Actions, where it fails. The key
is exported only to the signer process.
EOF
}

APP_VERSION=""
PINNED=false
REQUIRE_SIGNED=false
while [ $# -gt 0 ]; do
  case "$1" in
    --app-version) APP_VERSION="${2:?--app-version needs a value}"; shift 2 ;;
    --pinned-cli) PINNED=true; shift ;;
    --require-signed) REQUIRE_SIGNED=true; shift ;;
    -h | --help) usage; exit 0 ;;
    --) shift; break ;;
    -*) usage; exit 2 ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { usage; exit 2; }
[ -n "$APP_VERSION" ] || APP_VERSION="$(workspace_version)"

for file in "$@"; do
  [ -f "$file" ] || die "no such file: $file"
  if $REQUIRE_SIGNED; then
    case "$(basename "$file")" in
      *-unsigned* | *-unnotarized*)
        die "$(basename "$file") is not code-signed or notarized, and REQUIRE_SIGNED_UPDATES is on; fix the signing secrets or turn the variable off" ;;
    esac
  fi
done

if [ -z "$KEY" ]; then
  if $REQUIRE_SIGNED || { $PINNED && [ "${GITHUB_ACTIONS:-}" = true ]; }; then
    die "TAURI_SIGNING_PRIVATE_KEY unset; the release needs updater signatures for: $*"
  fi
  warn "TAURI_SIGNING_PRIVATE_KEY unset; no updater signature for: $*"
  exit 0
fi

if $PINNED; then
  SIGNER_DIR="$(mktemp -d)"
  trap 'rm -rf "$SIGNER_DIR"' EXIT
  install_pinned_tauri_cli "$SIGNER_DIR"
  RUNTIME="$(command -v node || command -v bun || true)"
  [ -n "$RUNTIME" ] || die "node or bun is required"
fi
signer() {
  if $PINNED; then
    (cd "$SIGNER_DIR" && TAURI_SIGNING_PRIVATE_KEY="$KEY" TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$KEY_PASSWORD" \
      "$RUNTIME" "$SIGNER_DIR/node_modules/@tauri-apps/cli/tauri.js" signer sign "$@")
  else
    (cd "$ROOT/apps/desktop" && TAURI_SIGNING_PRIVATE_KEY="$KEY" TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$KEY_PASSWORD" \
      bun run tauri signer sign "$@")
  fi
}

for file in "$@"; do
  path="$(abs_path "$file")"
  command -v cygpath >/dev/null 2>&1 && path="$(cygpath -m "$path")"
  rm -f "$file.sig"
  signer --app-version "$APP_VERSION" "$path" </dev/null >/dev/null || die "tauri signer sign failed for $file"
  [ -s "$file.sig" ] || die "tauri signer sign wrote no $file.sig"
  say "signed $(basename "$file") for the updater ($APP_VERSION)"
done
