# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this is

WyVPN is an alternative VPN connector: a client that talks to existing, unmodified VPN servers of an established open-source product. It imports that product's profiles (`.ovpn`, `.tar` bundles, profile links), syncs them, and runs tunnels.

**Never write the upstream product's name** in docs, comments, specs, notes or commit messages. Call it "the reference client/server" or "the vendor". The only place the literal appears is `packages/core/src/vendor.rs` (`VENDOR_*` constants); refer to those constant names instead.

## Layout

Cargo workspace (edition 2024, MSRV 1.95) plus a Bun workspace for the desktop frontend.

| Path | Crate / package | Role |
|---|---|---|
| `packages/ipc` | `wyvpn-ipc` | Wire types shared by daemon, CLI and app. Socket path constants. |
| `packages/core` | `wyvpn-core` | Profile parsing, import, sync API client, auth, request signing, TLS pinning, `.ovpn` rendering, WireGuard registration. No I/O beyond HTTP. |
| `apps/daemon` | `wyvpn-daemon` (bin `wyvpnd`) | Privileged service. Owns profile storage, OpenVPN processes, routes and DNS. |
| `apps/cli` | `wyvpn-cli` | CLI client; also serves MCP over stdio (`wyvpn-cli mcp [--allow-control]`). |
| `apps/desktop` | `@wyvpn/desktop` + `src-tauri` (`wyvpn-app`, bin `WyVPN`) | Tauri 2 tray app, Svelte 5 / SvelteKit static frontend. |

`apps/desktop/src-tauri` is a workspace member but **not** a default member, so plain `cargo build`/`cargo test` at the root skip it. Use `-p wyvpn-app` or `--workspace`.

## Commands

```bash
bun install                       # frontend deps (needed before any desktop build)

bun run dev                       # build daemon+CLI, run wyvpnd as root via sudo, start desktop app
bun run dev -- --fresh            # same, wiping the dev data dir first
bun run dev:daemon                # daemon only
bun run cli -- status             # CLI against the dev socket (/tmp/wyvpn.sock)
bun run build                     # tauri build (release bundle)

cargo build                       # default members: daemon, CLI, packages
cargo test                        # default members
cargo test -p wyvpn-app           # Tauri backend tests
cargo test -p wyvpn-daemon session::      # tests in one module
cargo test -p wyvpn-core -- ovpn::tests::<test_name> --exact   # single test
cargo clippy --workspace --all-targets
cargo fmt --all

bun run --cwd apps/desktop test   # vitest (jsdom)
bun run --cwd apps/desktop test -- src/lib/reducer.test.ts   # single file
bun run --cwd apps/desktop check  # svelte-check / TypeScript
```

Live tests against a real server are behind a feature flag and read fixtures from the gitignored `.secrets/` dir (`<kind>.link`, `<kind>.tar` or `<kind>.ovpn`; PIN via `WYVPN_TEST_PIN`). Missing fixtures skip, not fail:

```bash
cargo test -p wyvpn-core --features live --test live -- --nocapture
```

On macOS, `scripts/dev.sh` needs `brew install openvpn`; it copies the binary and `wyvpnd` into `/opt/wyvpn-dev/bin` as root. Dev data dir must live under `/tmp` (default `/tmp/wyvpn-data`).

## Architecture

### Process model

```
desktop app (user) ─┐
wyvpn-cli (user)  ──┼─ newline-delimited JSON over socket ─► wyvpnd (root) ─► openvpn child
MCP agent ─ cli mcp ┘                                              │
                                                                   └─► DNS / routes
```

- Socket: `/var/run/wyvpn.sock` (unix, group `admin` on macOS, `wyvpn` elsewhere) or `\\.\pipe\wyvpn` (Windows). Override with `WYVPN_SOCKET`. Data dir override: `WYVPN_DATA_DIR`.
- Protocol in `packages/ipc/src/lib.rs`: `RequestEnvelope {id, request}` → `ResponseEnvelope {id, result|error}`; after `Subscribe`, the server also pushes untagged `EventEnvelope {event}`. `Event` has `#[serde(other)] Unknown` so older clients tolerate new events. Max line 512 KiB (`server.rs`).
- Changing IPC types means updating three consumers: daemon `control.rs`, CLI, and both Tauri `bridge.rs`/`model.rs` and the TS mirror `apps/desktop/src/lib/types.ts` (snake_case; transports serialize as `wire_guard` / `open_vpn`).

### Daemon (`apps/daemon/src`)

- `listener.rs` binds/permissions the socket; `server.rs` handles per-connection framing and event fan-out (broadcast channel); `control.rs::dispatch` maps `Request` to handlers.
- `state.rs` holds profile source, session manager and event publisher. `storage.rs` persists profiles: public record (header + `.ovpn` with secret blocks stripped) and a separate secret record (`key`, `tls-auth`, `tls-crypt`, sync token/secret, TLS pins).
- `session.rs::Manager` owns a single active tunnel slot: claim → optional credentials wait (120 s) → launch → watchdog, stats polling, network probing, reconnect backoff (1/2/5/10/30 s).
- `launcher.rs` defines the `Launcher`/`Running` traits so sessions are testable with fakes; `TunnelLauncher` is the real one using `openvpn/` (binary discovery, process spawn, management-interface client, runtime dir sweep).
- `wyvpnd hook` (hidden subcommand) is invoked by OpenVPN as its up/down script. It forwards `foreign_option_*` env vars to the daemon's DNS listener (`dns/`), which applies DNS per OS (`macos.rs`, `linux.rs`). On startup, `dns::recover` restores DNS left by a crash.
- Transport: WireGuard is preferred when the profile allows it, but the daemon currently stops after registration with `NotImplemented`; OpenVPN is the working path.

### Core (`packages/core/src`)

`#![deny(unsafe_code)]`. Secrets use `Secret`/`Sensitive` with zeroize and redacted `Debug`; an ipc test asserts no summary type serializes a secret-looking field name. Keep that invariant when adding fields. `testdata/` holds expected `.ovpn` render outputs.

### Desktop (`apps/desktop`)

- Rust side (`src-tauri/src`): `bridge.rs` keeps a subscribed daemon connection with backoff/heartbeat and emits `daemon://event`, `daemon://availability`, `daemon://statuses`, `daemon://profiles`. `commands.rs` are the `invoke` handlers; `shell.rs` owns windows/tray glue; `settings.rs` stores app settings in the app config dir.
- Frontend: `src/lib/api.ts` wraps `invoke` (camelCase args) and converts errors to `CommandError`; `reducer.ts` is a pure `applyEvent`; `daemon.svelte.ts` is the store singleton. Seq counters drop stale in-flight fetches when a pushed list arrives.
- Tests mock `@tauri-apps/api/core` with `vi.hoisted` + `vi.mock`.
- Svelte gotchas: whitespace at `{#if}` edges is trimmed (use template literals); use `{@attach}` instead of `autofocus`; name length limits count Unicode scalars, not `maxlength`.

## Planning workflow

`openspec/` (gitignored, local) holds specs and change proposals; `docs/protocol/` (gitignored) is the reverse-engineered wire protocol reference with `client:`/`server:` citations and **UNVERIFIED** markers; `notes/` holds findings. Use the `opsx:*` skills for proposals. OpenSpec rules: proposals under 500 words, tasks split to the smallest unit, Mermaid diagrams in designs, run the linter before marking a task done.
