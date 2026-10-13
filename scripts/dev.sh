#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage: scripts/dev.sh [--no-app] [--fresh]

Builds wyvpnd and wyvpn-cli, installs root-owned dev copies, runs the daemon as
root and the desktop app in one terminal. Ctrl-C stops both.

  --no-app   run only the daemon (use the CLI with `bun run cli -- <args>`)
  --fresh    delete the dev data dir (profiles, secrets) before starting

Dev only: on macOS the root copy of Homebrew's openvpn still loads Homebrew
libraries your user can modify, so do not use this on a shared machine.
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOCKET="${WYVPN_SOCKET:-/tmp/wyvpn.sock}"
DATA_DIR="${WYVPN_DATA_DIR:-/tmp/wyvpn-data}"
BIN_DIR=/opt/wyvpn-dev/bin
STATE_DIR="${TMPDIR:-/tmp}"
STATE_DIR="${STATE_DIR%/}/wyvpn-dev-$(id -u)"
LOG="$STATE_DIR/wyvpnd.log"
PIDFILE="$STATE_DIR/wyvpnd.pid"
RUN_APP=1
FRESH=0

for arg in "$@"; do
  case "$arg" in
    --no-app) RUN_APP=0 ;;
    --fresh) FRESH=1 ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

say() { printf '\033[1m[dev]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[dev]\033[0m %s\n' "$*" >&2; exit 1; }
prefix() { awk -v tag="$1" '{ print tag " " $0; fflush() }'; }
cli() { WYVPN_SOCKET="$SOCKET" "$ROOT/target/debug/wyvpn-cli" "$@"; }

case "$DATA_DIR" in
  *..*) die "WYVPN_DATA_DIR must not contain '..'" ;;
  /tmp/?* | /private/tmp/?*) ;;
  *) die "WYVPN_DATA_DIR must be under /tmp for dev runs" ;;
esac
mkdir -p "$STATE_DIR"
[ -O "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] || die "$STATE_DIR is not a directory you own"
chmod 700 "$STATE_DIR"

install_root_copy() {
  local src="$1" dest="$2"
  if ! sudo cmp -s "$src" "$dest" 2>/dev/null; then
    sudo install -o root -g 0 -m 755 "$src" "$dest"
    say "installed $dest"
  fi
}

say "building wyvpnd and wyvpn-cli"
cargo build --manifest-path "$ROOT/Cargo.toml" -p wyvpn-daemon -p wyvpn-cli

if cli status >/dev/null 2>&1; then
  pgrep -lf 'wyvpnd( |$)' | grep -v '^[0-9]* sudo' >&2 || true
  die "a daemon is already serving $SOCKET; stop it with: sudo kill -TERM <pid>"
fi

say "sudo is needed to run the daemon as root"
sudo -v
while sudo -n true 2>/dev/null; do sleep 50; done &
KEEPALIVE=$!

DAEMON_PID=""
cleanup() {
  trap - EXIT INT TERM
  if [ -n "$DAEMON_PID" ]; then
    local pid
    pid="$(sudo cat "$PIDFILE" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      say "stopping wyvpnd (restores DNS, stops tunnels)"
      sudo kill -TERM "$pid" 2>/dev/null || true
      for _ in $(seq 1 30); do
        sudo kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
      done
      sudo kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$DAEMON_PID" 2>/dev/null || true
    sudo rm -f -- "$PIDFILE"
  fi
  kill "$KEEPALIVE" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

sudo install -d -o root -g 0 -m 755 /opt/wyvpn-dev "$BIN_DIR"
install_root_copy "$ROOT/target/debug/wyvpnd" "$BIN_DIR/wyvpnd"

OPENVPN_ARGS=()
if [ "$(uname -s)" = Darwin ]; then
  brew_openvpn="$(brew --prefix 2>/dev/null)/sbin/openvpn"
  [ -e "$brew_openvpn" ] || die "OpenVPN not found; run: brew install openvpn"
  install_root_copy "$(realpath "$brew_openvpn")" "$BIN_DIR/openvpn"
  OPENVPN_ARGS=(--openvpn-path "$BIN_DIR/openvpn")
  if otool -L "$BIN_DIR/openvpn" | grep -q "$(brew --prefix)"; then
    say "note: openvpn loads Homebrew libraries your user owns (dev only)"
  fi
fi

if [ "$FRESH" = 1 ]; then
  say "removing $DATA_DIR"
  sudo rm -rf -- "$DATA_DIR"
elif [ -d "$DATA_DIR" ] && [ "$(stat -c %u "$DATA_DIR" 2>/dev/null || stat -f %u "$DATA_DIR")" != 0 ]; then
  rmdir "$DATA_DIR" 2>/dev/null \
    || die "$DATA_DIR is not owned by root; remove it or run with --fresh"
fi

say "starting wyvpnd (log: $LOG)"
sudo sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$PIDFILE" \
  env WYVPN_SOCKET="$SOCKET" WYVPN_DATA_DIR="$DATA_DIR" RUST_LOG="${RUST_LOG:-wyvpnd=debug}" \
  "$BIN_DIR/wyvpnd" ${OPENVPN_ARGS[@]+"${OPENVPN_ARGS[@]}"} 2>&1 | tee "$LOG" | prefix $'\033[36m[daemon]\033[0m' &
DAEMON_PID=$!

for _ in $(seq 1 60); do
  cli status >/dev/null 2>&1 && break
  kill -0 "$DAEMON_PID" 2>/dev/null || die "wyvpnd exited; see $LOG"
  sleep 0.5
done
cli status >/dev/null 2>&1 || die "wyvpnd did not come up on $SOCKET; see $LOG"
say "wyvpnd ready on $SOCKET; CLI: bun run cli -- status"

if [ "$RUN_APP" = 1 ]; then
  say "starting the desktop app"
  WYVPN_SOCKET="$SOCKET" bun run --cwd "$ROOT/apps/desktop" tauri dev 2>&1 | prefix $'\033[35m[app]\033[0m'
else
  wait "$DAEMON_PID"
fi
