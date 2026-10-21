# WyVPN

Alternative Pritunl or OpenVPN client, written in Rust for the backend, wrapped in Tauri for the user interface. Available as a graphical desktop interface, command-line interface, and an MCP.

## Motivation

I hate having a VPN client that takes horrendous amount of disk space, and I hope this should be faster because it's written in Rust.

## BEGIN LLM LINE

> Status: early development (0.1.0). OpenVPN tunnels work on macOS and Linux. WireGuard registration is implemented in the core library but the daemon does not bring up WireGuard tunnels yet.

## Features

- Import profiles from `.ovpn` files, `.tar` bundles, or profile links.
- Profile sync with signed requests and TLS certificate pinning.
- PIN prompts for profiles that require one.
- Auto-reconnect with backoff, connection watchdog, and live traffic counters.
- DNS from the server applied per OS, and restored after a crash.
- Per-session log from the daemon and the tunnel.
- Desktop tray app with notifications and launch at login.
- `wyvpn-cli` for scripting, with `--json` output.
- MCP server (`wyvpn-cli mcp`) so AI agents can list profiles, read status, and optionally connect or disconnect.

## Architecture

```
WyVPN desktop app ─┐
wyvpn-cli          ├─ JSON lines over a local socket ─► wyvpnd (root) ─► openvpn
wyvpn-cli mcp      ┘                                       └─► routes, DNS
```

| Component | Path | Description |
|---|---|---|
| `wyvpnd` | `apps/daemon` | Privileged service. Stores profiles and secrets, runs tunnels, manages DNS. |
| `wyvpn-cli` | `apps/cli` | Command-line client and MCP server. |
| WyVPN | `apps/desktop` | Tauri 2 tray app with a Svelte 5 frontend. |
| `wyvpn-core` | `packages/core` | Profile parsing, import, sync, auth, TLS, config rendering. |
| `wyvpn-ipc` | `packages/ipc` | Message types shared by all of the above. |

The daemon listens on `/var/run/wyvpn.sock` (macOS, Linux) or `\\.\pipe\wyvpn` (Windows). Members of the `admin` group (macOS) or `wyvpn` group (Linux) can use it. Profiles are stored in `/Library/Application Support/WyVPN` (macOS), `/var/lib/wyvpn` (Linux), or `%ProgramData%\WyVPN` (Windows).

## Installing

Download the installer for your system from [GitHub Releases](https://github.com/adithyaharun/wyvpn/releases) and check it against `SHA256SUMS` from the same release:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing    # macOS
sha256sum -c SHA256SUMS --ignore-missing        # Linux
```

On Windows, compare the output of `Get-FileHash .\WyVPN_*.msi` with the matching line in `SHA256SUMS`.

Installing takes one administrator prompt. After that, connecting needs no elevation.

### macOS

Requires macOS 13 or later. Works on Apple silicon and Intel. OpenVPN is included, so you do not need Homebrew.

1. Open `WyVPN_<version>_universal.dmg` and drag WyVPN to Applications.
2. Open WyVPN. It registers its background service and asks you to approve it.
3. Click **Open System Settings** and turn on WyVPN under **General › Login Items & Extensions**. The app continues by itself once the service is running.
4. Optional: choose **WyVPN › Install Command Line Tool…** to create `/usr/local/bin/wyvpn-cli`. This needs an administrator account.

To uninstall, choose **WyVPN › Uninstall WyVPN…**. Pick whether to keep or delete your profiles and secrets, then move WyVPN.app to the Trash. Moving the app to the Trash without this step also stops the service, but leaves your profiles in `/Library/Application Support/WyVPN`.

### Windows

Requires Windows 10 22H2 or later, x64.

1. Run `WyVPN_<version>_x64_en-US.msi` and accept the administrator prompt.
2. The installer adds the WyVPN app, the `wyvpnd` service (starts automatically), OpenVPN with its DCO driver, and `wyvpn-cli` on the system `PATH`. Open a new terminal to use `wyvpn-cli`.

To uninstall, use **Settings › Apps › WyVPN**. The uninstaller asks whether to delete your profiles and secrets in `%ProgramData%\WyVPN`; the default keeps them. For a silent uninstall that also deletes them:

```powershell
msiexec /x WyVPN_<version>_x64_en-US.msi /qn REMOVEDATA=1
```

### Linux

Requires x64 and OpenVPN 2.5 or later from your distribution, which the package pulls in.

```bash
sudo apt install ./wyvpn_<version>_amd64.deb      # Ubuntu 22.04+, Debian 12+
sudo dnf install ./wyvpn-<version>-1.x86_64.rpm   # Fedora 40+
```

The package enables and starts `wyvpnd.service` and creates the `wyvpn` group. When you install with `sudo` or `pkexec`, your user is added to the group. Log out and back in before you open WyVPN. If you were not added, run:

```bash
sudo usermod -aG wyvpn "$USER"
```

To uninstall:

```bash
sudo apt remove wyvpn     # keeps profiles in /var/lib/wyvpn
sudo apt purge wyvpn      # also deletes /var/lib/wyvpn
sudo dnf remove wyvpn     # keeps profiles; delete them with: sudo rm -rf /var/lib/wyvpn
```

### Unsigned builds

Current releases are not code-signed yet, so their files have `-unsigned` in the name and the OS warns before the first launch. Check the file against `SHA256SUMS` first, then:

- **macOS:** after dragging WyVPN to Applications, remove the download quarantine, then open it as usual:

  ```bash
  xattr -dr com.apple.quarantine /Applications/WyVPN.app
  ```

  Alternatively, open WyVPN once, then click **Open Anyway** in **System Settings › Privacy & Security**.
- **Windows:** when SmartScreen shows "Windows protected your PC", click **More info**, then **Run anyway**.
- **Linux:** packages are not signed on any release; `apt` and `dnf` install local files without a signature check.

### Building installers

`bun run package:macos`, `bun run package:windows` and `bun run package:linux` build the installer for the current system. See [docs/release.md](docs/release.md) for the steps and the signing setup.

## Requirements

- Rust 1.95 or later
- [Bun](https://bun.sh)
- OpenVPN (`brew install openvpn` on macOS, your distribution's package on Linux)
- Tauri 2 [system dependencies](https://tauri.app/start/prerequisites/) for the desktop app
- Linux tray: `libayatana-appindicator3` or `libappindicator3`

## Development

```bash
bun install
bun run dev
```

`bun run dev` builds the daemon and CLI, asks for `sudo`, runs `wyvpnd` as root on `/tmp/wyvpn.sock` with data in `/tmp/wyvpn-data`, and starts the desktop app. Ctrl-C stops both and restores DNS.

| Command | Description |
|---|---|
| `bun run dev -- --fresh` | Delete dev profiles and secrets before starting. |
| `bun run dev:daemon` | Run the daemon only. |
| `bun run cli -- <args>` | Run the CLI against the dev daemon. |
| `bun run build` | Build the desktop app bundle. |

The dev script is for single-user machines only. On macOS the root copy of Homebrew's OpenVPN still loads libraries your user can modify.

### Tests

```bash
cargo test                          # daemon, CLI, core, ipc
cargo test -p wyvpn-app             # desktop app backend
bun run --cwd apps/desktop test     # desktop frontend
bun run --cwd apps/desktop check    # type check
cargo clippy --workspace --all-targets
```

Tests against a real server need profiles in `.secrets/` (gitignored) and are opt-in:

```bash
WYVPN_TEST_PIN=... cargo test -p wyvpn-core --features live --test live -- --nocapture
```

## CLI

```bash
wyvpn-cli import profile.tar        # or a .ovpn file, a profile link, or "-" for stdin
wyvpn-cli list
wyvpn-cli connect <name-or-id>      # prompts for a PIN if needed; --pin-stdin to pipe it
wyvpn-cli connect <name-or-id> --transport wireguard   # or openvpn; omit for the default (OpenVPN)
wyvpn-cli status
wyvpn-cli disconnect <name-or-id>
wyvpn-cli rename <name-or-id> "New name"   # --reset restores the imported name
wyvpn-cli remove <name-or-id>
```

Add `--json` to any command for machine-readable output. Set `WYVPN_SOCKET` to use a different socket.

### MCP

```bash
wyvpn-cli mcp                   # list_profiles, connection_status
wyvpn-cli mcp --allow-control   # also connect, disconnect
```

Profiles that need a PIN cannot be connected through MCP.

## END LLM LINE

## License

MIT. See [NOTICE.md](NOTICE.md) for trademarks and third-party software.
