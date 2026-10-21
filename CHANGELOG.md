# Changelog

All notable changes to WyVPN are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- WireGuard connections for profiles that offer it, next to OpenVPN, with routes, DNS and keepalive handled by the service. The Windows installer includes the wintun.dll driver that WireGuard needs, and registration works with servers that redirect to a trailing-slash path.
- wyvpn-cli connect --transport chooses OpenVPN or WireGuard. Without it, OpenVPN is used.
- The desktop Connect button has a menu to choose OpenVPN or WireGuard for profiles that offer both.
- wyvpn-cli status --json reports the last WireGuard handshake time.
- In-app updates on macOS and Windows. WyVPN checks for a new version at launch and once a day, shows the release notes, and on Install disconnects the VPN, downloads and verifies the update, installs it and relaunches. On Linux it links to the release page. Earlier versions cannot update themselves, so install this version by hand.
- Check for Updates… in the tray menu, under Settings › Support and in the macOS app menu, and a setting to turn automatic checks off.
- A Repair action for the macOS background service.
- This changelog. Release notes on GitHub and in the update prompt come from it.

### Changed

- Text can be selected only where it is worth copying: inputs, addresses, versions, commands, errors, release notes, the log and licenses.

### Fixed

- Profiles that offer both OpenVPN and WireGuard now connect over OpenVPN by default instead of failing.
- On macOS, after an in-place update the app repairs a background service that failed to restart. macOS then asks for approval again, and the setup screen explains why.
- The status counters no longer leave an empty line below them.

### Security

- Updates are signed, and the app checks the signature, bound to the version, before installing.
- wintun.dll must carry the expected WireGuard LLC signature from a pinned issuer, and is loaded through the same file handle that was checked.
- Registration hosts and the WireGuard configuration sent by the server are validated and size-limited. Invalid routes are skipped.
- WireGuard registration to a server addressed by IP trusts its certificate on first use and pins it. A later certificate change ends the session.
- Registration secrets are wiped from memory after use.

## [0.1.2] - 2026-10-13

### Fixed

- On macOS, the service restarts by itself after the app is replaced, so the new bundled OpenVPN is no longer rejected by the old service.
- On macOS, a notice shows while the service runs a different version than the app.

## [0.1.1] - 2026-10-13

### Fixed

- On macOS, the toolbar lines up with the window buttons in release builds.
- On macOS, WyVPN asks again for background service approval while it is pending, adds an Approve Background Service… tray item, and shows the service as starting instead of not running.
- Double-clicking the title bar no longer causes an error.

## [0.1.0] - 2026-10-13

### Added

- wyvpnd, a background service that runs tunnels, applies DNS and stores profiles and secrets.
- A desktop tray app with notifications and launch at login.
- wyvpn-cli for scripting, with --json output, and an MCP server (wyvpn-cli mcp) for AI agents.
- Profile import from .ovpn files, .tar bundles and profile links.
- Profile sync with signed requests and TLS certificate pinning.
- PIN prompts for profiles that need one.
- OpenVPN tunnels with auto-reconnect, a connection watchdog and live traffic counters.
- Server DNS applied per OS and restored after a crash.
- A per-session log from the service and the tunnel.
- Installers for macOS (.dmg), Windows (.msi) and Linux (.deb, .rpm), with OpenVPN bundled on macOS and Windows.

[Unreleased]: https://github.com/adithyaharun/wyvpn/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/adithyaharun/wyvpn/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/adithyaharun/wyvpn/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/adithyaharun/wyvpn/releases/tag/v0.1.0
