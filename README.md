<div align="center">
  <img src="web/assets/logo.png" alt="Cleanton" width="120" height="120"/>

  # Cleanton

  **Reclaim disk space, and check your packages for supply-chain attacks.**

  A native macOS app that finds the space your tools leave behind, uninstalls apps along with everything they scatter on disk, and scans your installed packages for the kind of malicious code that has been showing up in npm and pip. You review everything first. What gets removed goes to the Trash, so a mistake is recoverable.

  [![Latest release](https://img.shields.io/github/v/release/Olib-AI/cleanton?label=download&style=flat-square&color=2F6FEB)](https://github.com/Olib-AI/cleanton/releases/latest)
  [![Platform](https://img.shields.io/badge/platform-macOS%20arm64-2F6FEB?style=flat-square)](https://github.com/Olib-AI/cleanton/releases)
  [![Notarized](https://img.shields.io/badge/Apple-notarized-2F6FEB?style=flat-square)](#is-it-safe-to-run)
  [![License](https://img.shields.io/badge/license-proprietary-6B7785?style=flat-square)](LICENSE)

  [Download](https://github.com/Olib-AI/cleanton/releases/latest) · [Install](#install) · [Docs](docs/) · [Safety](docs/safety.md) · [olib.ai](https://www.olib.ai)
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
- **Suggestions**: duplicate files, large folders, re-clonable git repositories (a remote and no local changes), macOS screenshots and screen recordings, and old installers left in Downloads. Surfaced for review, never removed for you.
- **Packages**: review and clean npm, pip, Homebrew, and MacPorts packages, with dependency-aware removal and a warning when a package is referenced by one of your codebases.
- **Services**: see launchd and Homebrew services and startup items, and disable or remove the ones you do not want, with system services locked as protected.

---

## Check your packages for supply-chain attacks

Attackers have been slipping malicious code into popular npm and pip packages, and into editor extensions. Some steal your tokens during install. Some reach out to servers they should not. Some copy a trusted name one letter off. The newest ones spread on their own, republishing themselves through any account they can reach.

Cleanton scans the packages installed on your Mac and looks for those signs. It reads the code without running it, so scanning is safe.

The first scan records what you already have as trusted. After that, Cleanton only speaks up about what is new or has changed, so a normal toolchain stays quiet instead of drowning you in noise. A package that changes on disk without a new version number is treated as a strong warning, because that is how a compromised update hides.

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

1. Download `cleanton-app-macos-arm64.tar.gz` from the [latest release](https://github.com/Olib-AI/cleanton/releases/latest).
2. Extract it and move `Cleanton.app` to your Applications folder.
3. Open it. The app is signed with our Apple Developer ID and notarized by Apple, so it opens without a Gatekeeper override.

### The command-line tool

```sh
curl -fsSL https://raw.githubusercontent.com/Olib-AI/cleanton/main/scripts/install.sh | sh
```

The script downloads the latest CLI tarball, installs it to `~/.cleanton/`, and adds a `cleanton` shim to `~/.local/bin`.

> **Note on the CLI binary.** The command-line tool is signed, but it is distributed on its own rather than inside the notarized app bundle, so macOS will quarantine it the first time you download it directly. The installer script clears that flag for you. If you download the CLI tarball by hand, run `xattr -d com.apple.quarantine ./cleanton` once before the first launch, or open it once through the app bundle, which is notarized. The Cleanton app itself never needs this step.

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

## Is it safe to run?

Cleanton is built to be careful:

- **Trash by default.** Removed items are recoverable from the Trash. Permanent deletion is never the default.
- **Review before action.** Every scan shows the full list with sizes. You confirm the final selection.
- **Conservative targets.** Cleanton aims at caches and rebuildable artifacts. Large folders and re-clonable repositories are surfaced as suggestions only, never removed automatically.
- **The security scan only reports.** It reads package code without running it, and never removes or changes anything.
- **Signed and notarized.** The app is signed with the Olib AI Developer ID and notarized by Apple.

That said, only you know your machine. Read [the safety guide](docs/safety.md) and the plan before you run anything.

---

## License

Cleanton is proprietary software, free to download and use. The source code is not public. You may not redistribute, resell, or reverse engineer the binaries. See [LICENSE](LICENSE) for the full terms.

---

## Links

- [Releases](https://github.com/Olib-AI/cleanton/releases) for downloads
- [Docs](docs/) for install, usage, and safety
- [Issues](https://github.com/Olib-AI/cleanton/issues) for bugs and requests
- [olib.ai](https://www.olib.ai) and [hello@olib.ai](mailto:hello@olib.ai)

<div align="center">
  <sub>Built by <a href="https://www.olib.ai">Olib AI</a></sub>
</div>
