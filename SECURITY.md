# Security Policy

Cleanton removes files from disk and scans installed developer packages for supply-chain attacks. Safety and reliability are our highest priorities.

## Reporting a Vulnerability

Please report security issues privately by emailing **security@olib.ai** with:

- Description of the vulnerability and potential impact
- Steps or proof-of-concept to reproduce
- Platform details (`uname -a`, macOS version, and Cleanton version)
- Affected components (GUI app, CLI, engine, or package scanner)

We acknowledge receipt within 2 business days and aim to patch confirmed vulnerabilities within 14 days. Please do not file public GitHub issues for unpatched vulnerabilities.

## Scope

**In scope:**
- Any scenario where Cleanton deletes, moves, or modifies a file or directory outside the user-reviewed and confirmed plan.
- Path traversal or sandbox escape vulnerabilities in archive scanning (`cleanton-antivirus`).
- Logic bypasses in safety gates (`DEFAULT_PROTECTED`, sensitive path basenames, or eligibility filters).
- False negative evasion in critical supply-chain detection signatures.

**Out of scope:**
- Reclaiming disk space from items explicitly reviewed and confirmed by the user.
- Normal cache invalidation effects of external tools whose caches were removed.

## Toolchain & Dependency Auditing

- **Toolchain.** The repository is pinned to Rust **1.99.1** via `rust-toolchain.toml`, and declared in `Cargo.toml` (`rust-version = "1.99.1"`).
- **Audit.** `cargo audit` runs in CI on every push, pull request, and daily against the live RustSec advisory database (`.cargo/audit.toml`). Run locally with `./scripts/audit.sh`.
- **Ignore Policy.** Advisories in `.cargo/audit.toml` are only permitted when verified unreachable (e.g. archive extraction functions in `zip` where the codebase only reads files in-memory and never calls `extract()`). Every ignore records owner and justification.
