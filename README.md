<div align="center">
  <img src="web/assets/logo.png" alt="Cleanton" width="120" height="120"/>

  # Cleanton

  **Reclaim disk space, and check your packages for supply-chain attacks.**

  A native macOS app that finds the space your tools leave behind, uninstalls apps along with everything they scatter on disk, and scans your installed packages for the kind of malicious code that has been showing up in npm and pip. You review everything first. What gets removed goes to the Trash, so a mistake is recoverable.

  [![Latest release](https://img.shields.io/github/v/release/Olib-AI/cleanton?label=download&style=flat-square&color=2F6FEB)](https://github.com/Olib-AI/cleanton/releases/latest)
  [![Platform](https://img.shields.io/badge/platform-macOS%20arm64-2F6FEB?style=flat-square)](https://github.com/Olib-AI/cleanton/releases)
  [![CI](https://github.com/Olib-AI/cleanton/actions/workflows/ci.yml/badge.svg)](https://github.com/Olib-AI/cleanton/actions/workflows/ci.yml)
  [![Security audit](https://github.com/Olib-AI/cleanton/actions/workflows/security.yml/badge.svg)](https://github.com/Olib-AI/cleanton/actions/workflows/security.yml)
  [![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-2F6FEB?style=flat-square)](LICENSE)

  [Download](https://github.com/Olib-AI/cleanton/releases/latest) · [Install](#install) · [Building from source](#building-from-source) · [Docs](docs/) · [Safety](docs/safety.md) · [olib.ai](https://www.olib.ai)
</div>

---

## Read this first

Cleanton removes files from your disk. You decide what goes, but you are responsible for the result.

- Cleanton moves removed items to the **Trash by default**. You can recover them from the Trash until you empty it.
- Some actions can free a large amount of data at once. A full developer machine can have tens of gigabytes in build caches.
- Always read the plan before you run it. Cleanton shows every item and its size, and lets you select or skip individual entries.
- Back up anything you cannot lose. Cleanton targets caches and rebuildable artifacts, but you are the one who confirms the final list.
- The suggestions for large folders and re-clonable repositories are for review only. Cleanton never removes those for you.
- The security scan only reports. It never removes, quarantines, or changes a package.

If you are not sure what an item is, skip it. Nothing is removed until you confirm.

---

## What Cleanton does

Cleanton does two jobs, and shows you everything before it acts.

1. **Frees disk space** that developer tools, apps, and macOS leave behind.
2. **Checks your installed packages** for supply-chain attacks and tells you when something looks wrong.

It ships as a native macOS app and a command-line tool that share the same engine.

---

## Free up space

Cleanton knows where the space hides and groups what it finds so you can act fast.

- **Rust**: `target` directories, the Cargo registry cache, incremental and sccache data
- **Node**: `node_modules`, npm and Yarn and pnpm and Bun and Deno caches, framework and deploy caches, and downloaded test browsers (Playwright, Puppeteer, Cypress)
- **JVM and Android**: Gradle caches and build outputs, the Maven repository, and Android Studio caches
- **Swift**: Xcode DerivedData, Swift Package Manager, CocoaPods, and Carthage
- **Python**: virtual environments and pip, uv, Poetry, and Conda caches
- **Go, Ruby, PHP, .NET, Dart and Flutter, Elixir, Haskell, Zig, and more**: the build and dependency caches for each
- **IDEs and editors**: JetBrains, VS Code, and Zed caches
- **Everyday apps**: caches from Chrome and other browsers, Adobe media caches, Steam shader caches, Zoom, and old iPhone and iPad backups
- **Docker**: dangling images, build cache, unused volumes
- **Machine learning and AI tools**: model and checkpoint caches, Ollama and LM Studio models, and the caches left by Claude Code, Cursor, Copilot, and other assistants
- **System**: Homebrew and Xcode caches, old logs, crash reports, and local Time Machine snapshots

Local Time Machine snapshots deserve a note. macOS keeps them on your startup disk and they can quietly hold many gigabytes. Because macOS manages them, Cleanton removes them with Apple's own tool after you confirm, and unlike everything else they do not go to the Trash. Cleanton says so plainly before you act.

Then it helps you deal with the rest, and never removes any of it on its own:

- **Applications**: pick an installed app and Cleanton finds everything it leaves behind, the bundle plus its application support, caches, preferences, saved state, logs, containers, launch agents, helpers, and home-directory data like `~/.ollama`. Review each item and move it to the Trash. If the app came from a Homebrew cask, Cleanton removes it through Homebrew too. Remove an app in the Finder and Cleanton notices, then offers to clean up what it left.
- **Suggestions**: duplicate files, large folders, re-clonable git repositories (a remote and no local changes), macOS screenshots and screen recordings, and old installers left in Downloads. Surfaced for review only; never deleted automatically.
- **Packages**: review npm, pip, Homebrew, and MacPorts packages. See what depends on what, and clean up packages you do not use without breaking the ones you keep.
- **Services**: inspect `launchd` and Homebrew services, disable startup items you do not need, and keep system services protected.

---

## Supply-chain security scan

Developer machines hold tokens, keys, credentials, and source code. Attackers know this, and attacks that hide inside legitimate package managers (npm, pip, and editor plugins) have become common.

Cleanton includes a **static supply-chain scanner** that runs entirely on your machine. It makes zero network requests and does not execute the packages it inspects.

- **Lifecycle scripts and hooks**: flags install scripts (`postinstall`, `preinstall`, setup hooks) that run system shells, spawn processes, or download secondary payloads
- **Credential access and exfiltration**: looks for reads from `~/.aws`, `~/.ssh`, `~/.npmrc`, `~/.git-credentials`, environment variables like `GITHUB_TOKEN`, and patterns that send them over the wire
- **Known-malware signatures**: includes a hash and pattern database covering documented supply-chain incidents
- **Obfuscation**: detects base64-encoded eval chains, hex decoding loops, and encrypted payload drops designed to hide from simple string searches
- **Baseline tracking**: the first scan creates a local baseline of your packages. Subsequent scans only alert you when packages change, reducing notification noise. A package that changes on disk without a new version number is treated as a strong warning, because that is how a compromised update hides.

When Cleanton flags something, it shows you where it is and gives you the exact command to remove or reinstall it yourself. It never touches your packages. You stay in control.

---

## Screenshots

| | |
|---|---|
| **Dashboard.** Scan your home folder and see reclaimable space by category. | **Results.** Review every group and item, with sizes and a safety rating, then select what to remove. |
| <img src="web/assets/screenshots/dashboard.png" alt="Cleanton Dashboard" width="420"/> | <img src="web/assets/screenshots/results.png" alt="Cleanton Results" width="420"/> |
| **Packages.** Review npm, pip, Homebrew, and MacPorts packages, with dependency-aware removal and codebase-usage warnings. | **Services.** See launchd and Homebrew services and startup items, disable or remove the ones you do not want, with system services locked. |
| <img src="web/assets/screenshots/packages.png" alt="Cleanton Packages" width="420"/> | <img src="web/assets/screenshots/services.png" alt="Cleanton Services" width="420"/> |

---

## Install

Cleanton is a macOS app for Apple Silicon (arm64).

### The app

**Homebrew (recommended)**

```sh
brew tap olib-ai/tap
brew trust olib-ai/tap
brew install --cask cleanton
```

`brew trust` is a one-time step: Homebrew refuses casks from a third-party tap until you trust it. Update later with `brew upgrade --cask cleanton`.

**Direct download**

1. Download `cleanton-app-macos-arm64.tar.gz` from the [latest release](https://github.com/Olib-AI/cleanton/releases/latest).
2. Extract it and move `Cleanton.app` to your `/Applications` folder.
3. Open it. The app is signed with our Apple Developer ID and notarized by Apple, so it opens without a Gatekeeper override.

### The command-line tool

```sh
curl -fsSL https://raw.githubusercontent.com/Olib-AI/cleanton/main/scripts/install.sh | sh
```

The script downloads the latest CLI tarball, installs it to `~/.cleanton/`, and adds a `cleanton` shim to `~/.local/bin`.

---

## Using it

Open the app and pick a scan root (your home folder by default). Run a scan, review the grouped results, select what you want to remove, and confirm. Removed items go to the Trash. The Security tab scans your installed packages, and the first scan learns what is normal for your machine.

The command-line tool mirrors the app:

```sh
# show what is reclaimable, grouped, without removing anything
cleanton plan

# run the plan after you have reviewed it (items go to the Trash)
cleanton clean --yes

# scan installed packages for supply-chain threats (reports only)
cleanton security
```

Run `cleanton --help` for the full list of commands.

See [docs/usage.md](docs/usage.md) for the app walkthrough and the complete CLI reference, and [docs/safety.md](docs/safety.md) for exactly how Cleanton decides what is safe to remove.

---

## Building from source

### Workspace layout

Rust workspace, edition 2024, resolver 3, pinned to **Rust 1.99.1**.

| Crate | Role |
|---|---|
| `cleanton-antivirus` | Vendored static malware + supply-chain scanner (multi-engine; pure/static, zero network calls). Backs the Security tab and `cleanton security`. |
| `cleanton-common` | Shared config, plan, result, and error types. |
| `cleanton-scanner` | Filesystem scanner and the audited macOS capacity FFI (`statfs`/`pathconf`). |
| `cleanton-recipes` | TOML recipe registry (over 130 built-in recipes for Rust, Node, Swift, Python, JVM, Docker, AI/ML, and more). |
| `cleanton-engine` | Orchestration: `analyze_full`, the planner, the trash-based executor, Docker, the suggestions engine, and the read-only `security` supply-chain scan. |
| `cleanton-packages` | Package-manager facade: Homebrew, npm, pip, MacPorts. Keep-set removal, codebase-usage scan. |
| `cleanton-services` | `launchd` and Homebrew service inventory and gated enable/disable. |
| `cleanton-ml` | Safety-constrained ONNX ML advisory (pure-Rust `tract`, never widens what is removable). |
| `cleanton-ui` | ratatui terminal UI used by the CLI's interactive mode. |
| `cleanton-app` | Native Slint GUI app. Canonical product UI. |
| `cleanton-cli` | clap CLI: subcommands (`plan`, `clean`, `security`) plus the interactive TUI launcher. |

### Development commands

```sh
# Run GUI app
cargo run -p cleanton-app

# Run CLI interactive mode
cargo run -p cleanton-cli

# Run formatting checks
cargo fmt --check

# Run strict clippy
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run all workspace unit and integration tests
cargo test --workspace --all-features

# Run RustSec dependency audit
./scripts/audit.sh

# Build release package locally (unsigned)
./packaging/build-macos.sh
```

---

## Safety model

Cleanton is a deleter, so its safety invariants are enforced at compile time and in CI:

- **Trash by default.** Removal goes through the `cleanton-engine` executor, which moves to the macOS Trash via Finder IPC so that "Put Back" works.
- **Review before action.** A scan never deletes anything. The user explicitly reviews and confirms the plan.
- **Suggestions are review-only.** Large folders, re-clonable git repositories, and screen recordings are never automatically deleted.
- **Zero panics.** Production crates deny `unwrap`, `expect`, `panic`, and slice indexing via Clippy workspace lints.
- **Static security scanning.** The security engine only inspects; it never executes code or modifies packages.

---

## License

Cleanton is open-source software dual-licensed under either:

* [MIT License](LICENSE)
* [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
