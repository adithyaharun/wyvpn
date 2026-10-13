# Third-party notice

WyVPN is an independent project. It is not affiliated with, endorsed by, or sponsored by OpenVPN Inc., Pritunl, Inc., or the WireGuard project.

- OpenVPN is a registered trademark of OpenVPN Inc. WireGuard is a registered trademark of Jason A. Donenfeld. Pritunl is a trademark of Pritunl, Inc. These names appear only to describe compatibility.
- WyVPN is written independently and does not include source code from those projects.
- The macOS and Windows packages bundle an unmodified OpenVPN build, licensed by its authors under GPL-2.0; its license and copyright notice ship inside those packages. The exact corresponding source is published with each release as `openvpn-<version>.tar.gz`. On Linux, WyVPN uses the OpenVPN package from your distribution.
- WyVPN is built with Tauri, Svelte, Tokio, rustls and other open-source projects, which keep their own licenses. Full license texts ship with each release in `THIRD_PARTY_LICENSES`. `Cargo.lock` and `bun.lock` list every dependency.

Use WyVPN only with VPN servers you are authorized to access. It is provided as is, without warranty of any kind.
