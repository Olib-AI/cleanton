# Cleanton Packaging

This directory contains macOS packaging scaffolding for local smoke checks and
direct-download release builds. It intentionally does not contain signing identities,
notarization credentials, provisioning profiles, or fake placeholders for those values.

Every packaging run recreates `packaging/dist/` from scratch so stale app bundles,
archives, and checksums do not leak into later builds. The directory is ignored by git.

## Local unsigned artifacts

Run:

```sh
./packaging/build-macos.sh
```

The script targets macOS **arm64 only** (it fails fast on any other arch), builds the real
workspace binaries, strips local symbols, ad-hoc signs them, and writes outputs to
`packaging/dist/`:

- `cleanton-cli-macos-arm64.tar.gz` contains the `cleanton` CLI binary.
- `Cleanton.app/` is a macOS app bundle containing:
  - `Contents/Info.plist` (bundle id, version, `LSMinimumSystemVersion`, and TCC purpose
    strings for Desktop/Documents/Downloads/removable/network volumes)
  - `Contents/MacOS/Cleanton`
  - `Contents/Resources/Cleanton.icns`
  - `Contents/PkgInfo`
- `cleanton-app-macos-arm64.tar.gz` contains the `Cleanton.app` bundle.
- `SHA256SUMS` contains relative-path checksums for the two archives.

Both the CLI binary and the app bundle are **ad-hoc signed** (`codesign --sign -`) so they
launch on the local arm64 machine after stripping. Ad-hoc signing is **not** a substitute for
distribution signing: Gatekeeper will still reject these artifacts (`"cannot be opened"` /
quarantine) because they carry no Developer ID signature and are not notarized or stapled.
That is expected for unsigned builds — the signed path below stays gated on Apple secrets.

These archives are useful for CI smoke checks and developer-local testing. They are not a
production distribution format because direct-download macOS artifacts must be Developer ID
signed, hardened-runtime enabled where applicable, notarized, and stapled before public release.
See `doc/PLATFORM.md` section 3 and the M9 release gate in `doc/IMPLEMENTATION_PLAN.md`.

## Signed and Notarized Artifacts

Set the Apple release credentials in the environment. Cleanton uses the same variable
names as the Olib Browser light release:

- `APPLE_CERTIFICATE_B64`
  - Base64-encoded Developer ID Application `.p12`.
- `APPLE_CERTIFICATE_PASSWORD`
  - Password for the `.p12`.
- `APPLE_ID`
  - Apple developer account email.
- `APPLE_APP_PASSWORD`
  - App-specific password from appleid.apple.com.
- `APPLE_TEAM_ID`
  - 10-character Apple team id.

Optional:

- `APPLE_KEYCHAIN_NAME`
  - Temporary keychain filename. Defaults to `cleanton-build.keychain`.
- `APPLE_KEYCHAIN_PASS`
  - Temporary keychain password. Defaults to a random value.

Run:

```sh
./packaging/build-macos.sh --notarize
```

The build script still creates the CLI archive, app bundle, app archive, and `SHA256SUMS`
under `packaging/dist/`, but the app bundle is signed and notarized before the app archive
is generated.

The notarization script:

1. Validates required commands and Apple credential variables.
2. Imports the Developer ID Application certificate into a temporary keychain.
3. Signs `Cleanton.app` with hardened runtime.
4. Verifies the code signature.
5. Submits a temporary zip to Apple's notary service.
6. Staples the notarization ticket.
7. Validates the staple and runs Gatekeeper assessment.
8. Deletes the temporary zip and keychain on exit.

Public direct-download macOS releases should be produced with this flow, then published
from the generated files in `packaging/dist/`.

## Production release work still required

- Decide whether the GUI release channel ships the `.app` tarball, a DMG, or both.
- Add/verify GitHub release automation that provides the Apple secrets above before public release.
- Add a Homebrew formula or tap for the CLI release channel.
- Add release QA that verifies quarantine/Gatekeeper behavior on a fresh macOS machine.
