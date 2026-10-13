# Release checklist

Releases are built by `.github/workflows/release.yml` on a `v*` tag. It builds the macOS universal `.dmg`, the Windows x64 `.msi` and the Linux x64 `.deb` and `.rpm`, then creates a **draft** GitHub release with every installer, `SHA256SUMS` and the OpenVPN corresponding source.

## 1. Prepare

- [ ] Bump `workspace.package.version` in the root `Cargo.toml`.
- [ ] Run `bun run version:sync` and commit the updated `tauri.conf.json` and `package.json` files. CI fails with `bun run version:check` if they drift.
- [ ] Check the OpenVPN pin: `scripts/check-openvpn-update.sh`. To move to a newer 2.6.x, update every URL and SHA-256 in `packaging/openvpn/VERSION`. Verify the tarball and MSI against their `.asc` signatures from the OpenVPN security key first.
- [ ] CI is green on `main`.

## 2. Tag

```bash
git tag -s v<version> -m "WyVPN <version>"
git push origin v<version>
```

The release job refuses a tag that does not match the `Cargo.toml` version.

## 3. Secrets and variables

Signing runs only when its secrets exist. Without them the installers are still built but named `*-unsigned` (or `*-unnotarized` on macOS when signed but not notarized). Unsigned builds also leave `WYVPN_TEAM_ID` and `WYVPN_PUBLISHER` unset. On macOS the daemon then checks the bundled OpenVPN against `WYVPN_OPENVPN_SHA256`, the hash of the final ad-hoc-signed binary pinned at build time. On Windows the official OpenVPN binaries keep their own signature, which the daemon accepts.

| Name | Kind | Used for |
|---|---|---|
| `APPLE_CERTIFICATE` | secret | Base64 `.p12` with the Developer ID Application certificate and key |
| `APPLE_CERTIFICATE_PASSWORD` | secret | Password of that `.p12` |
| `APPLE_SIGNING_IDENTITY` | secret | e.g. `Developer ID Application: Name (TEAMID)` |
| `APPLE_TEAM_ID` | variable (or secret) | Team ID; compiled into `wyvpnd` as `WYVPN_TEAM_ID` to verify the bundled OpenVPN, only when the Apple signing secrets are set |
| `APPLE_API_KEY`, `APPLE_API_ISSUER`, `APPLE_API_KEY_P8` | secrets | App Store Connect API key ID, issuer ID and `.p8` contents for `notarytool` |
| `APPLE_ID`, `APPLE_PASSWORD` | secrets | Alternative to the API key: Apple ID and app-specific password |
| `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD` | secrets | Base64 `.pfx` Authenticode certificate for `scripts/windows-sign.ps1` |
| `WINDOWS_TIMESTAMP_URL` | variable (optional) | RFC 3161 timestamp server; defaults to DigiCert, or Microsoft for Trusted Signing |
| `AZURE_TRUSTED_SIGNING_ENDPOINT`, `AZURE_TRUSTED_SIGNING_ACCOUNT`, `AZURE_CERTIFICATE_PROFILE`, `AZURE_CODESIGNING_DLIB` | variables | Alternative to the `.pfx`: Azure Trusted Signing |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | secrets | Azure credentials for Trusted Signing |
| `WYVPN_PUBLISHER` | variable | Authenticode subject CN, compiled into `wyvpnd` to verify our signed binaries, only when Windows signing is configured |

On Windows, `tauri build` signs the executables and the MSI through `bundle.windows.signCommand` (`scripts/windows-sign.ps1`); CI only provides the environment. Azure Trusted Signing also needs the Trusted Signing client installed on the runner, with `AZURE_CODESIGNING_DLIB` pointing to its dlib.

Signing keys never live in the repository.

## 4. Verify the draft release

- [ ] Every job passed and the draft lists the `.dmg`, `.msi`, `.deb`, `.rpm`, `SHA256SUMS`, `openvpn-<version>.tar.gz` and `lzo-<version>.tar.gz`.
- [ ] Assets named `-unsigned` or `-unnotarized` are expected until the signing secrets exist. Say so in the release notes and link the README's unsigned-build steps.
- [ ] Checksums: download all assets and run `sha256sum -c SHA256SUMS`, or `shasum -a 256 -c SHA256SUMS` on macOS.
- [ ] OpenVPN source: the SHA-256 of `openvpn-<version>.tar.gz` matches `OPENVPN_SOURCE_SHA256` in `packaging/openvpn/VERSION`.
- [ ] macOS:
  - `spctl --assess --type open --context context:primary-signature -v WyVPN_*.dmg`
  - After copying the app to `/Applications`, `spctl -a -vv /Applications/WyVPN.app` reports `Notarized Developer ID`.
  - `codesign -dv --verbose=4` on `Contents/MacOS/wyvpnd`, `Contents/MacOS/wyvpn-cli` and `Contents/Resources/openvpn/openvpn` shows our Team ID and the `runtime` flag.
  - `xcrun stapler validate` passes on the `.dmg` and the app.
- [ ] Windows: `Get-AuthenticodeSignature` reports `Valid` with our publisher for the `.msi`, `WyVPN.exe`, `wyvpnd.exe` and `wyvpn-cli.exe`. `openvpn\openvpn.exe` keeps the OpenVPN Inc. signature.

## 5. Smoke-test the installers

On a clean machine or VM for each OS: install, approve or start the service, import a profile, connect, reboot, check that the daemon is back, disconnect, uninstall.

- [ ] macOS 13 or later, on both Apple silicon and Intel if possible. Approve the background item in System Settings. Use Install CLI, then run `wyvpn-cli --version`.
- [ ] Windows 10 22H2 or Windows 11. The installer offers no folder choice and installs to `C:\Program Files\WyVPN`. Check that the `wyvpnd` service is running and that `wyvpn-cli --version` works in a new terminal.
- [ ] Ubuntu 22.04 (OpenVPN 2.5), Ubuntu 24.04 or Debian 12 (`.deb`) and Fedora 40 (`.rpm`). Check that `systemctl status wyvpnd` is active and that you are in the `wyvpn` group. Remove the package (without purging), reinstall it, and check that `systemctl is-enabled wyvpnd` reports `enabled`.
- [ ] The About window shows the third-party licenses and the OpenVPN source location.

The Linux packages need OpenVPN 2.5 or later, so Ubuntu 22.04 (2.5.11) is the oldest supported Ubuntu. The Linux job builds on `ubuntu-22.04` so the binaries need only glibc 2.35.

## 6. Publish

- [ ] Edit the draft release notes and publish.

## Local builds

```bash
cargo install cargo-about --locked --features cli
bun install
bun run package:macos      # or package:windows (Git Bash) / package:linux
```

The installers land in `target/packaging/dist`. The packaging scripts stage files that `tauri build` needs only for release bundles:

- `scripts/stage-binaries.sh` puts the sidecars in `apps/desktop/src-tauri/binaries/`.
- `scripts/build-openvpn-macos.sh` and `scripts/fetch-openvpn-windows.ps1` stage OpenVPN in `apps/desktop/src-tauri/resources/openvpn-*`.
- `scripts/gen-licenses.sh` writes `apps/desktop/src-tauri/resources/THIRD_PARTY_LICENSES`.

These files are referenced from the `tauri.release*.conf.json` overlays, which only `scripts/package.sh` passes to `tauri build`. That way `tauri dev`, `cargo check -p wyvpn-app` and a plain `bun run build` work without them on every OS. A plain `bun run build` produces a bundle without the daemon, the CLI or OpenVPN, so it is not something to ship.

Set `WYVPN_LICENSES_OFFLINE=1` to make `cargo about` use only local crate files, which is faster. In that mode, crates that ship without a license file get the generic license text.
