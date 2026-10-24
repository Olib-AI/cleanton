# Installation

Cleanton runs on macOS with Apple Silicon (arm64).

## The app

### Homebrew

```sh
brew tap olib-ai/tap
brew trust olib-ai/tap
brew install --cask cleanton
```

`brew trust` is a one-time step. Homebrew 6 refuses casks from a third-party tap until you trust it. Later, `brew upgrade --cask cleanton` moves you to the newest release.

### Direct download

1. Download `cleanton-app-macos-arm64.tar.gz` from the [latest release](https://github.com/Olib-AI/cleanton/releases/latest).
2. Double-click the tarball to extract `Cleanton.app`.
3. Move `Cleanton.app` to your Applications folder.
4. Open it.

The app is signed with the Olib AI Apple Developer ID and notarized by Apple. It opens without a right-click override and without a quarantine warning.

## The command-line tool

The quickest path is the installer script:

```sh
curl -fsSL https://raw.githubusercontent.com/Olib-AI/cleanton/main/scripts/install.sh | sh
```

It downloads the latest CLI tarball, installs it to `~/.cleanton/`, clears the macOS quarantine flag, and adds a `cleanton` shim to `~/.local/bin`. If `~/.local/bin` is not on your `PATH`, the script prints the line to add to your shell profile.

### Manual CLI install

1. Download `cleanton-cli-macos-arm64.tar.gz` from the [latest release](https://github.com/Olib-AI/cleanton/releases/latest).
2. Extract it: `tar -xzf cleanton-cli-macos-arm64.tar.gz`
3. Clear the quarantine flag once: `xattr -d com.apple.quarantine ./cleanton`
4. Move it somewhere on your `PATH`, for example: `mv ./cleanton ~/.local/bin/`

The quarantine step is needed only for the standalone CLI, because it is distributed on its own rather than inside the notarized app bundle. The app does not need it.

## Verifying the download

Each release includes a `SHA256SUMS` file. To check a download:

```sh
shasum -a 256 -c SHA256SUMS
```

Run it in the folder that holds the downloaded tarballs.

## Uninstalling

- App (Homebrew): `brew uninstall --cask cleanton`. Add `--zap` to also remove Cleanton's own settings, logs, and security baseline under `~/.config/cleanton`.
- App (direct download): move `Cleanton.app` to the Trash, and remove `~/.config/cleanton` if you want its settings gone too.
- CLI: remove `~/.cleanton/` and the `~/.local/bin/cleanton` shim.
