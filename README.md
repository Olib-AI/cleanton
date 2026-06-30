# Cleanton (source)

Native macOS disk cleaner for developers. This is the private source workspace.
The public, closed-source distribution lives at
[github.com/Olib-AI/cleanton](https://github.com/Olib-AI/cleanton) (binaries,
docs, and website only). Do not publish source from here.

Cleanton ships two front ends over one engine:

- a native GUI app (Slint), and
- a command-line tool with an interactive terminal UI (ratatui).

Both reclaim disk space from developer build caches and artifacts, move removed
items to the Trash by default, and require the user to review and confirm before
anything is removed.

## Workspace layout

Rust workspace, edition 2024, resolver 3, MSRV 1.96.

| Crate | Role |
|---|---|
| `cleanton-common` | Shared config, plan, result, and error types. |
| `cleanton-scanner` | Filesystem scanner and the audited macOS capacity FFI (`statfs`/`pathconf`). |
| `cleanton-recipes` | TOML recipe registry (about 70 built-in recipes for Rust, Node, Swift, Python, and more). |
| `cleanton-engine` | Orchestration: `analyze_full`, the planner, the trash-based executor, Docker, and the suggestions engine. |
| `cleanton-packages` | Package-manager facade: Homebrew, npm, pip, MacPorts. Keep-set removal, codebase-usage scan. |
| `cleanton-services` | launchd and Homebrew service inventory and gated enable/disable. |
| `cleanton-ml` | Safety-constrained ML advisory (never widens what is removable). |
| `cleanton-ui` | ratatui terminal UI used by the CLI's interactive mode. |
| `cleanton-app` | Slint GUI app. This is the source of truth for the product UI. |
| `cleanton-cli` | clap CLI. Subcommands plus the interactive TUI launcher. |

The Slint app is the canonical UI. When a screen or feature changes there, the
TUI in `cleanton-ui` is expected to follow.

## Build and run

```sh
# GUI app
cargo run -p cleanton-app

# CLI: interactive TUI (no subcommand)
cargo run -p cleanton-cli

# CLI: show a plan without removing anything
cargo run -p cleanton-cli -- plan

# CLI: apply a reviewed plan (items go to the Trash)
cargo run -p cleanton-cli -- plan --apply
```

## Checks

These mirror the CI gates in `.github/workflows/ci.yml`. Run them before
considering a change done.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Safety model

Cleanton is a deleter, so the lint policy is strict (see `CLAUDE.md`). The core
invariants:

- Removal goes through the `cleanton-engine` executor, which moves to the Trash
  by default. Raw `std::fs::remove_*` and `std::process::Command::new` are
  denied by `clippy.toml` outside the audited adapters.
- A scan never removes anything. The user reviews the plan and confirms.
- Suggestions (large folders, re-clonable repos) are review-only and are never
  auto-removed.

## Packaging and release

```sh
# unsigned local build (CI and smoke testing)
./packaging/build-macos.sh

# signed, notarized, stapled release artifacts
./packaging/build-macos.sh --notarize
```

Notarization needs the Apple Developer credentials described in
`packaging/notarize-macos.sh`. The resulting `Cleanton.app` and CLI tarballs are
what get attached to a release in the distribution repo.

## Conventions

See [`CLAUDE.md`](CLAUDE.md) for how to work in this repo, including the lint
rules, the safety boundaries, and the commit policy.
