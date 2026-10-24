# Contributing to Cleanton

Thank you for your interest in contributing to Cleanton!

Cleanton is an open-source native macOS disk cleaner and supply-chain package auditor for developers. We welcome issues, bug reports, recipe additions, and pull requests.

## How to Help

- **Bug reports & fixes.** Open an [issue](https://github.com/Olib-AI/cleanton/issues) with your macOS version, Cleanton version, and reproducible steps.
- **Recipes.** Recipes live in `recipes/*.toml`. If there is a build tool, package manager, or framework cache that Cleanton should clean, PRs adding or refining recipes are warmly welcome.
- **Feature suggestions & improvements.** Share workflows, ideas, or feedback.
- **Documentation.** Fixes and expansions in `docs/` or READMEs are always appreciated.

For security vulnerabilities, please refer to [SECURITY.md](SECURITY.md) and report privately.

---

## Development Setup

### Prerequisites

- **macOS** (Apple Silicon arm64 recommended; macOS 13+)
- **Rust 1.99.1** (channel pinned in `rust-toolchain.toml`, install via `rustup`)
- **cargo-audit** (`cargo install cargo-audit --locked`)

### Build & Run

```sh
# Run the Slint native GUI app
cargo run -p cleanton-app

# Run the CLI interactive terminal UI
cargo run -p cleanton-cli

# Run a CLI dry-run plan
cargo run -p cleanton-cli -- plan

# Apply a plan (moves items to Trash)
cargo run -p cleanton-cli -- plan --apply
```

### Pre-commit Checks & CI Gates

Every pull request must pass the automated gates:

```sh
# Check formatting
cargo fmt --check

# Strict Clippy checks
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Workspace tests
cargo test --workspace --all-features

# Security audit
./scripts/audit.sh
```

---

## Safety Model & Invariants

Cleanton is a deleter. The codebase follows strict safety guarantees:

1. **Trash by default.** All deletions go through the `cleanton-engine` executor, moving items to the macOS Trash via Finder IPC so that "Put Back" remains functional. Raw filesystem deletions (`remove_dir_all`, `remove_file`) are prohibited outside audited, explicit adapters.
2. **Review first.** Scans never delete files. The user explicitly reviews and confirms the plan.
3. **No panic in production code.** Clippy denies `unwrap`, `expect`, `panic`, `indexing_slicing`, `todo`, and `unimplemented` across workspace crates.
4. **Purely offline security scanner.** The `cleanton-antivirus` engine is pure Rust, runs statically with zero network calls, and only reports findings; it never deletes or modifies scanned packages.

---

## License

By contributing to Cleanton, you agree that your contributions will be licensed under the project's dual [MIT](LICENSE) or [Apache-2.0](LICENSE-APACHE) license.
