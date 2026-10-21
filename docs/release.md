# Release checklist

Releases are built by `.github/workflows/release.yml` on a `v*` tag. It builds the macOS universal `.dmg`, the Windows x64 `.msi` and the Linux x64 `.deb` and `.rpm`, then creates a **draft** GitHub release with every installer, `SHA256SUMS` and the OpenVPN corresponding source. With the updater key it also attaches the in-app updater files: the macOS `.app.tar.gz`, the `.sig` signatures and `latest.json` (see [Updater](#4-updater)).

## 1. Prepare

- [ ] Bump `workspace.package.version` in the root `Cargo.toml`.
- [ ] Run `bun run version:sync` and commit the updated `tauri.conf.json` and `package.json` files. CI fails with `bun run version:check` if they drift.
- [ ] Check the OpenVPN pin: `scripts/check-openvpn-update.sh`. To move to a newer 2.6.x, update every URL and SHA-256 in `packaging/openvpn/VERSION`. Verify the tarball and MSI against their `.asc` signatures from the OpenVPN security key first.
- [ ] To move to a newer Wintun, update `packaging/wintun/VERSION`: the zip URL and SHA-256 (compare with the hash on wintun.net), the SHA-256 of `wintun/bin/amd64/wintun.dll` from that zip, and the signer pins. The publisher, issuer and issuer SHA-256 must match the pin in `apps/daemon/src/openvpn/signature.rs`; CI checks this.
- [ ] CI is green on `main`.

## 2. Tag

```bash
git tag -s v<version> -m "WyVPN <version>"
git push origin v<version>
```

The release job refuses a tag that does not match the `Cargo.toml` version.

The run then pauses at the `updater-sign` job until you approve its `updater-signing` deployment: open the run in the Actions tab, choose **Review deployments**, tick `updater-signing` and approve. The `release` job, and with it the draft, waits for this step. A rejected or expired approval fails the run without a draft.

## 3. Secrets and variables

Signing runs only when its secrets exist. Without them the installers are still built but named `*-unsigned` (or `*-unnotarized` on macOS when signed but not notarized). Unsigned builds also leave `WYVPN_TEAM_ID` and `WYVPN_PUBLISHER` unset. On macOS the daemon then checks the bundled OpenVPN against `WYVPN_OPENVPN_SHA256`, the hash of the final ad-hoc-signed binary pinned at build time. On Windows the official OpenVPN binaries and `wintun.dll` keep their own signatures, which the daemon accepts.

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
| `REQUIRE_SIGNED_UPDATES` | variable (optional) | `true` makes the `updater-sign` job fail on any `-unsigned` or `-unnotarized` installer, so a release with broken code signing never reaches the updater. Set it once the Apple and Windows signing secrets exist |
| `TAURI_SIGNING_PRIVATE_KEY` | environment secret (`updater-signing`) | Updater private key, the contents of `~/.tauri/wyvpn.key` (not a path). Only the "Sign updater files" step of the `updater-sign` job receives it |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | environment secret (`updater-signing`) | Password of that key |

On Windows, `tauri build` signs the executables and the MSI through `bundle.windows.signCommand` (`scripts/windows-sign.ps1`); CI only provides the environment. Azure Trusted Signing also needs the Trusted Signing client installed on the runner, with `AZURE_CODESIGNING_DLIB` pointing to its dlib.

Signing keys never live in the repository. The updater public key is the one exception: it is committed in `apps/desktop/src-tauri/tauri.conf.json` under `plugins.updater.pubkey`.

## 4. Updater

The desktop app checks `https://github.com/adithyaharun/wyvpn/releases/latest/download/latest.json`. macOS and Windows download and install the file it names after verifying its minisign signature against the committed public key. Linux only shows that a version is available.

### Key pair

Create the key pair once, on a trusted machine:

```bash
bunx tauri signer generate -w ~/.tauri/wyvpn.key
```

1. Choose a strong password. The command writes `~/.tauri/wyvpn.key` (private, encrypted with the password) and `~/.tauri/wyvpn.key.pub`.
2. Put the contents of `wyvpn.key.pub` in `plugins.updater.pubkey` in `apps/desktop/src-tauri/tauri.conf.json` and commit it.
3. Keep an offline backup of `wyvpn.key` and its password, for example in a password manager and on an encrypted drive. Without them no installed app can be updated again.
4. Add both as secrets of the `updater-signing` environment (**Settings › Environments › updater-signing**), not as repository secrets:

   ```bash
   gh secret set TAURI_SIGNING_PRIVATE_KEY --env updater-signing <~/.tauri/wyvpn.key
   gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD --env updater-signing
   ```

   The second command prompts for the password, so it does not end up in your shell history. The environment allows deployments only from tags matching `v*` and needs the repository owner's approval, so a branch, a pull request or an unapproved run cannot read the key. Delete any repository-level secrets with these names.

### Updater files

`bundle.createUpdaterArtifacts` stays off. Tauri would sign its archive before our code signing, so the archive would not match the app we ship. We sign the final files ourselves with `scripts/updater-sign.sh`, which runs `tauri signer sign` and binds each signature to the release version:

- macOS job: after `scripts/macos-sign-notarize.sh` has signed, notarized and stapled `WyVPN.app`, `scripts/package.sh` packs it as `WyVPN_<version>_universal<suffix>.app.tar.gz`, with `WyVPN.app` at the root, and uploads it as the `macos-updater` artifact. `<suffix>` matches the `.dmg` (`-unsigned`, `-unnotarized` or empty).
- Windows job: the MSI artifact is the final file, after "Sign MSI" and "Label unsigned", `-unsigned` name included.
- `updater-sign` job: on a fresh runner, in the `updater-signing` environment, it checks out only `scripts/`, `Cargo.toml` and `bun.lock`, checks that the tag matches the workspace version, downloads only those two artifacts, and signs both with `scripts/updater-sign.sh --pinned-cli`. That downloads `@tauri-apps/cli` and its Linux x64 binding at `TAURI_CLI_VERSION` (`scripts/lib.sh`) into an empty directory and refuses them unless their SHA-512 matches the integrity recorded in `bun.lock`, before the key is exported to anything. No repository build code or dependency install runs next to the key. The job uploads only the `.sig` files.

The build jobs never see the key, and `scripts/package.sh` exits with an error if it finds the key in CI. Local release builds can still sign: with `TAURI_SIGNING_PRIVATE_KEY` set, `scripts/package.sh` signs the macOS archive itself, and `scripts/updater-sign.sh <file>` signs an MSI.
- Release job: `scripts/updater-manifest.sh dist <version>` writes `latest.json`. `SHA256SUMS` covers the archive and the `.sig` files but not `latest.json`, because the publish step rewrites it.

Unsigned and unnotarized installers are listed in the feed too. The minisign signature still proves they came from our CI. Once the code signing secrets exist, set the repository variable `REQUIRE_SIGNED_UPDATES` to `true` (`gh variable set REQUIRE_SIGNED_UPDATES --body true`). Without it, a release whose Apple or Windows signing silently failed (an expired certificate, a missing secret) would update signed installs to unsigned builds. With it, the `updater-sign` job fails with an error naming the file, and no draft is created.

`latest.json`:

```json
{
  "version": "0.2.0",
  "notes": "Release notes from the published release",
  "pub_date": "2026-10-21T04:31:00Z",
  "platforms": {
    "darwin-aarch64": { "url": "https://github.com/adithyaharun/wyvpn/releases/download/v0.2.0/WyVPN_0.2.0_universal.app.tar.gz", "signature": "<contents of the .app.tar.gz.sig>" },
    "darwin-x86_64": { "url": "https://github.com/adithyaharun/wyvpn/releases/download/v0.2.0/WyVPN_0.2.0_universal.app.tar.gz", "signature": "<same>" },
    "windows-x86_64": { "url": "https://github.com/adithyaharun/wyvpn/releases/download/v0.2.0/WyVPN_0.2.0_x64_en-US.msi", "signature": "<contents of the .msi.sig>" }
  }
}
```

Both macOS keys point to the universal archive. The release job fails when only one platform has a signature, so a feed never breaks updates on one OS.

### Builds without the key

Without `TAURI_SIGNING_PRIVATE_KEY` (local builds, forks, a missing secret) the installers are still built. `scripts/package.sh` still writes the macOS archive but no `.sig`, and warns on local builds. In CI a tagged release cannot go out without the key: `updater-sign.sh --pinned-cli` fails in GitHub Actions when the key is missing (as does `--require-signed` anywhere), so the run stops at the `updater-sign` job and creates no draft. The build jobs still finish, so their installers stay available as run artifacts, for example on a fork without the secret. A release published without `latest.json` is invisible to the updater, and while it is the latest release, update checks fail because `releases/latest/download/latest.json` returns 404.

`scripts/package.sh` also refuses a merged Tauri config that allows insecure transport or invalid certificates, allows downgrades, turns off `requireSignedVersion` (or spells it differently), changes the updater endpoint or public key, or sets Windows `installerArgs` other than the committed ones. Check an overlay with `scripts/package.sh <os> --check-config --config <overlay.json>`.

### Draft and publish

`releases/latest/download/latest.json` serves only the newest **published** release that is not a prerelease. Clients do not see a draft, so you can check it at leisure. When you publish, the "Update feed" workflow (`.github/workflows/update-feed.yml`) copies the release body into `notes`, sets `pub_date` to the publish time and uploads `latest.json` again. For about a minute after publishing, clients may see the draft placeholder notes; the version and signatures are already final. Editing the notes later does not update `latest.json`; run the workflow again with `gh workflow run update-feed.yml -f tag=v<version>`.

### First updater release

Versions without **Check for Updates…** cannot update themselves. The first release with the updater must be installed by hand; say so in its release notes. The release after it is the first one delivered by the updater.

### Key rotation

To replace the key while the old one is still available:

1. Generate a new pair, for example `~/.tauri/wyvpn-2.key`, and back it up.
2. Release N: commit the new public key in `tauri.conf.json`, but keep the **old** private key in the `updater-signing` environment secrets. Installed apps verify N with the old key, and N trusts the new key.
3. After N is published, replace both environment secrets with the new key and password. Release N+1 and later are signed with the new key.

Users who skip N and are offered N+1 directly fail the signature check; they must install N or later by hand. Keep N as the latest release for a while before releasing N+1 to reduce that.

If the private key leaks, rotate the same way at once. Until N is out, anyone with the key could sign an update that installed apps accept, but they still need to serve it from our GitHub release.

### Losing the key

If the private key or its password is lost, no installed app can be updated again: the public key is compiled in and the signature check cannot be turned off. Generate a new pair, commit the new public key, and release. Every user must install that release by hand. Say so prominently in the release notes and the README.

## 5. Verify the draft release

- [ ] Every job passed and the draft lists the `.dmg`, `.msi`, `.deb`, `.rpm`, `SHA256SUMS`, `openvpn-<version>.tar.gz` and `lzo-<version>.tar.gz`.
- [ ] Assets named `-unsigned` or `-unnotarized` are expected until the signing secrets exist; with `REQUIRE_SIGNED_UPDATES=true` the run fails instead. Say so in the release notes and link the README's unsigned-build steps.
- [ ] Checksums: download all assets and run `sha256sum -c SHA256SUMS`, or `shasum -a 256 -c SHA256SUMS` on macOS.
- [ ] OpenVPN source: the SHA-256 of `openvpn-<version>.tar.gz` matches `OPENVPN_SOURCE_SHA256` in `packaging/openvpn/VERSION`.
- [ ] macOS:
  - `spctl --assess --type open --context context:primary-signature -v WyVPN_*.dmg`
  - After copying the app to `/Applications`, `spctl -a -vv /Applications/WyVPN.app` reports `Notarized Developer ID`.
  - `codesign -dv --verbose=4` on `Contents/MacOS/wyvpnd`, `Contents/MacOS/wyvpn-cli` and `Contents/Resources/openvpn/openvpn` shows our Team ID and the `runtime` flag.
  - `xcrun stapler validate` passes on the `.dmg` and the app.
- [ ] Windows: `Get-AuthenticodeSignature` reports `Valid` with our publisher for the `.msi`, `WyVPN.exe`, `wyvpnd.exe` and `wyvpn-cli.exe`. `openvpn\openvpn.exe` keeps the OpenVPN Inc. signature, and `wintun.dll` (next to `wyvpnd.exe`) keeps the WireGuard LLC signature; the release job checks the latter with `scripts/check-windows-msi.ps1`.
- [ ] Updater files: the draft lists `latest.json`, `WyVPN_<version>_universal*.app.tar.gz` with its `.sig`, and the `.msi.sig`. A run without the key fails at `updater-sign` and makes no draft.
- [ ] Updater archive (macOS): it contains the shipped app.

  ```bash
  mkdir check && tar -xzf WyVPN_*_universal*.app.tar.gz -C check
  codesign --verify --strict --deep --verbose=2 check/WyVPN.app
  xcrun stapler validate check/WyVPN.app    # notarized builds only
  ```
- [ ] Updater signatures: each `.sig` is a base64-encoded minisign signature. Check the archive and the MSI with [minisign](https://jedisct1.github.io/minisign/) and the committed public key:

  ```bash
  jq -r .plugins.updater.pubkey apps/desktop/src-tauri/tauri.conf.json | base64 -d >updater.pub
  for f in WyVPN_*.app.tar.gz WyVPN_*.msi; do
    base64 -d <"$f.sig" >"$f.minisig"
    minisign -V -p updater.pub -m "$f" -x "$f.minisig"
  done
  ```

  Each check prints `Signature and comment signature verified` and a trusted comment ending in `version:<version>`. The updater rejects a signature whose version differs from `latest.json`.
- [ ] `latest.json` (`gh release download v<version> -p latest.json`): `version` is the release version, the three platform URLs point to `releases/download/v<version>/` and name files in the draft, and each `signature` equals the matching `.sig` file.

## 6. Smoke-test the installers

On a clean machine or VM for each OS: install, approve or start the service, import a profile, connect, reboot, check that the daemon is back, disconnect, uninstall.

- [ ] macOS 13 or later, on both Apple silicon and Intel if possible. Approve the background item in System Settings. Use Install CLI, then run `wyvpn-cli --version`.
- [ ] Windows 10 22H2 or Windows 11. The installer offers no folder choice and installs to `C:\Program Files\WyVPN`. Check that the `wyvpnd` service is running and that `wyvpn-cli --version` works in a new terminal.
- [ ] Ubuntu 22.04 (OpenVPN 2.5), Ubuntu 24.04 or Debian 12 (`.deb`) and Fedora 40 (`.rpm`). Check that `systemctl status wyvpnd` is active and that you are in the `wyvpn` group. Remove the package (without purging), reinstall it, and check that `systemctl is-enabled wyvpnd` reports `enabled`.
- [ ] The About window shows the third-party licenses and the OpenVPN source location.

The Linux packages need OpenVPN 2.5 or later, so Ubuntu 22.04 (2.5.11) is the oldest supported Ubuntu. The Linux job builds on `ubuntu-22.04` so the binaries need only glibc 2.35.

## 7. Publish

- [ ] Edit the draft release notes and publish. These notes are what the update prompt shows.
- [ ] The "Update feed" workflow passed, and `curl -sL https://github.com/adithyaharun/wyvpn/releases/latest/download/latest.json | jq '.version, .notes'` shows the new version and the published notes.
- [ ] On a machine with the previous release, **Check for Updates…** offers the new version.

## Local builds

```bash
cargo install cargo-about --locked --features cli
bun install
bun run package:macos      # or package:windows (Git Bash) / package:linux
```

The installers land in `target/packaging/dist`. The packaging scripts stage files that `tauri build` needs only for release bundles:

- `scripts/stage-binaries.sh` puts the sidecars in `apps/desktop/src-tauri/binaries/`.
- `scripts/build-openvpn-macos.sh` and `scripts/fetch-openvpn-windows.ps1` stage OpenVPN in `apps/desktop/src-tauri/resources/openvpn-*`. On Windows the fetch script needs `7z` on `PATH` (preinstalled on GitHub runners) to unpack the ovpn-dco driver from the MSI.
- `scripts/fetch-wintun-windows.ps1` checks the Wintun zip and `wintun.dll` against `packaging/wintun/VERSION`, checks the WireGuard LLC signature, and stages the DLL and its license in `apps/desktop/src-tauri/resources/wintun-windows`.
- `scripts/gen-licenses.sh` writes `apps/desktop/src-tauri/resources/THIRD_PARTY_LICENSES`.

These files are referenced from the `tauri.release*.conf.json` overlays, which only `scripts/package.sh` passes to `tauri build`. That way `tauri dev`, `cargo check -p wyvpn-app` and a plain `bun run build` work without them on every OS. A plain `bun run build` produces a bundle without the daemon, the CLI or OpenVPN, so it is not something to ship.

Set `WYVPN_LICENSES_OFFLINE=1` to make `cargo about` use only local crate files, which is faster. In that mode, crates that ship without a license file get the generic license text.

### Updater end-to-end test

`scripts/updater-e2e.sh` tests the update path on a Mac without the real key or GitHub:

```bash
scripts/updater-e2e.sh
```

It generates a throwaway key pair in `target/updater-test/key`, writes a test overlay (the throwaway public key, the feed `http://127.0.0.1:8787/latest.json` and `dangerousInsecureTransportProtocol`), and builds two ad-hoc signed bundles through `scripts/package.sh`: A at the current version and B at the next patch version with `-test.1`. It signs B's archive with the throwaway key and writes a loopback `latest.json` into `target/updater-test/feed`, then prints the steps: install A, serve the feed with `python3 -m http.server 8787 --bind 127.0.0.1`, update while connected, and try a corrupted archive and `.sig`.

`scripts/package.sh` accepts the test overlay only from this script: it needs `WYVPN_UPDATER_E2E=1`, refuses it in CI, and requires a loopback endpoint, a public key other than the committed one, and an overlay inside `target/updater-test`. The script unsets `TAURI_SIGNING_*` and the Apple signing variables, so the real key in `~/.tauri` is never read. A and B trust only the throwaway key, so install a release build afterwards.

For the daemon upgrade path, build B from a scratch worktree with a real version bump (`bun run version:sync`) and check that the daemon reports the new version after the update.

`scripts/test-updater.sh` runs in CI and covers `updater-manifest.sh` with fixture folders, `updater-sign.sh` without a key, with `--require-signed` and with a tampered pinned CLI, the tag check, the `bun.lock` integrity pins, and the config guard.
