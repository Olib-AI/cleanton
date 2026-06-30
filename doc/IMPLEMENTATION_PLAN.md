# Cleanton — Implementation Plan and Release Gates

> This document turns the architecture into buildable milestones with explicit blockers.
> Cleanton is a disk cleaner, so a feature is not done until its safety behavior is testable.

---

## 1. Product Contract

Cleanton helps macOS developers find and remove regenerable local waste. It must be fast and pleasant, but the core promise is restraint: when unsure, keep the data.

### Non-Negotiable Invariants

1. Dry-run is the default for headless cleanup.
2. No filesystem mutation happens before a validated plan and explicit confirmation.
3. Protected paths cannot be overridden by recipes, config, ML, or `--force`.
4. Symlinks are never followed for deletion.
5. Missing or permission-denied scan context lowers confidence; it never makes a target safer.
6. Every execution attempt is logged, including skipped and failed actions.
7. ML is optional, local-only in the shipped app, and annotation-only.
8. The app must run as the current user; privileged service changes are isolated and separately confirmed.
9. Trash is preferred over permanent delete. Permanent delete is reserved for explicitly reviewed `aggressive` recipes whose targets are small, tool-owned, regenerable, and bounded by the hard aggressive-action size limit.
10. Cloud, external, network, and Time Machine volumes are excluded by default.
11. Space accounting is honest: `reclaimable`, `moved_to_trash`, and `freed` are reported as distinct quantities. Trashed bytes are never counted as freed, and APFS snapshot/purgeable/clone/hardlink effects are disclosed, never hidden ([PLATFORM.md](./PLATFORM.md) §1).
12. `.gitignore` is a regenerability signal only; the scanner still traverses ignored directories — that is where the cleanable waste lives ([CRATES.md](./CRATES.md) §2.2).
13. Protected-path checks are Unicode-normalized, case-folded per volume, and firmlink-aware before comparison ([SAFETY.md](./SAFETY.md) Layer 1, [PLATFORM.md](./PLATFORM.md) §4).

---

## 2. Milestones

### M0 — Documentation Freeze

Deliverables:

- Architecture, safety, crate, recipe, UI, icon, ML, and implementation docs agree with each other.
- Recipe acceptance rules are documented.
- Known unsafe broad patterns are removed or downgraded.

Exit gate:

- A reviewer can trace every planned destructive path through safety validation, plan review, and logging.

### M1 — Workspace Skeleton

Deliverables:

- Cargo workspace with the planned crates, `rust-toolchain.toml` pinned to **1.96.0** (stable), `rust-version = "1.96.0"` and `edition = "2024"` set workspace-wide.
- Workspace lint table and `clippy.toml` disallowed-methods choke-point in place ([ARCHITECTURE.md](./ARCHITECTURE.md) §7.0); `unsafe_code = "forbid"` except the documented FFI crates.
- Shared types, config schema, errors, and protected path checks.
- CI with `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo audit`, and macOS release-binary build checks.

Exit gate:

- Protected path tests pass on macOS and Linux CI.
- `clippy -D warnings` is green; the toolchain pin builds identically on a clean runner.
- Raw `std::fs::remove_*` / `Command::new` appear in **no** crate except `cleanton-engine::executor` and `cleanton-services` (enforced by `clippy.toml`).
- No crate performs deletion yet.

### M2 — Read-Only Scanner

Deliverables:

- Parallel scanner with permission-error reporting.
- Project root detection.
- Logical and allocated-size collection where available.
- Cloud, external, network, and protected-root exclusions.

Exit gate:

- Fixture scans are deterministic.
- Running against a real home directory cannot mutate the filesystem.
- Permission-denied paths appear in JSON/UI data.

### M3 — Recipe Engine

Deliverables:

- TOML parser, strict schema validation, recipe registry, self-tests.
- Built-in recipe fixtures.
- Conflict resolution and deduplication rules.

Exit gate:

- Every built-in recipe has match and non-match fixtures.
- Fuzz/mutation tests reject broad or protected-path recipes.
- No recipe can match credential or user-document fixtures.

### M4 — Planner

Deliverables:

- Cleanup plan builder with safety levels, grouping, size guards, and stale-plan timeout.
- Metadata fingerprints for execution-time revalidation.
- JSON output for scan and plan.

Exit gate:

- Plans are stable snapshots and cannot be executed after stale metadata is detected.
- Incomplete scans are marked as incomplete in the plan.

### M5 — Executor

Deliverables:

- Trash execution.
- Permanent delete only for explicitly approved `aggressive` recipes.
- Execution log and partial-success reporting.
- Cancellation support.

Exit gate:

- Symlink swap, path replacement, protected path, read-only directory, and concurrent modification tests pass.
- Missing targets are skipped, not fatal.
- Permanent delete cannot be reached by `safe` or `cautious` recipes.

### M6 — TUI and CLI

Deliverables:

- CLI commands for scan, plan, clean, recipe validation, and config.
- TUI screens for scan progress, results, plan review, execution, and settings.
- Accessible keyboard navigation and degraded icon modes.

Exit gate:

- Every destructive TUI action requires visible confirmation.
- The CLI has predictable exit codes and machine-readable JSON.

### M7 — macOS Services

Deliverables:

- Read-only service discovery for launchd and Homebrew.
- User-level start/stop/disable controls.
- Backup and rollback for user-owned plist cleanup.

Exit gate:

- `com.apple.*`, `/System/Library`, and root-owned system services are immutable.
- System-domain changes return structured privilege errors unless separately confirmed through the approved elevation path.

### M8 — Optional ML

Deliverables:

- Feature extraction parity tests between Python and Rust.
- ONNX inference behind a Cargo feature.
- Model evaluation gate and golden safety set.

Exit gate:

- ML cannot create executable actions.
- Golden safety false-positive rate is zero.
- Disabling the feature removes ONNX runtime requirements.

### M9 — Packaging

Deliverables:

- Signed/notarized macOS artifacts as appropriate for release channel.
- Homebrew formula or tap.
- First-run permission guidance.
- CI-produced unsigned app/CLI archives are allowed only as smoke-test artifacts; production direct-download artifacts must be signed, notarized, and stapled.

Exit gate:

- Fresh macOS install can run scan without Full Disk Access and explains missing permissions.
- Release artifacts contain no private training data, full icon packs, credentials, or local paths.

---

## 3. Risk Register

| Risk | Severity | Mitigation |
|---|---:|---|
| Broad recipe deletes user-authored data | Critical | Strict schema, context proof, protected fixtures, mutation tests |
| Agent/AI tool cleanup removes auth or conversation history | Critical | Tool recipes match only known cache/log subdirectories and default to cautious |
| APFS size estimates overpromise freed space | Medium | Report logical and estimated reclaimable size separately |
| Full Disk Access missing hides important context | Medium | Mark scan incomplete and lower confidence |
| Docker volume cleanup removes databases | Critical | Aggressive, double confirmation, API-based inspection |
| Launchd mutation disables system service | Critical | Immutable system labels/paths and structured privilege handling |
| ML false positive | Critical | Annotation-only model, keep-biased training, golden safety gate |
| Trash fallback silently becomes permanent delete | Critical | Permanent-delete fallback is forbidden |
| License issue with embedded icons | High | Curated assets only and release-time license review |
| Scanner skips ignored dirs and finds nothing to clean | High | `.gitignore` used as signal, not filter; fixture asserts `target/`/`node_modules/` are entered (PLATFORM §8 / CRATES §2.2) |
| "Freed" counter overstates results (trash, snapshots, clones, hardlinks) | High | Separate reclaimable/moved/freed; snapshot + purgeable disclosure; inode-deduped sizing (PLATFORM §1) |
| Protected path bypassed via case/Unicode/firmlink | Critical | Normalize + case-fold + firmlink-equivalence in comparator; bypass fixtures (SAFETY Layer 1) |
| Docker prune reported as host space freed but VM image doesn't shrink | Medium | Report "inside the VM"; detect OrbStack/Colima/Podman sockets (PLATFORM §5) |
| FDA guidance points at the wrong target for CLI users | Medium | Detect host context; deep-link to Settings; name the terminal, not the binary (PLATFORM §2) |
| Direct-download binary blocked by Gatekeeper / not notarized | Medium | Hardened Runtime + Developer ID + notarize + staple; Homebrew bottle path (PLATFORM §3) |

---

## 4. Definition of Done

A cleanup feature is complete only when all are true:

1. It has docs, recipe fixtures, unit tests, and integration tests.
2. It behaves correctly with protected paths, symlinks, permission errors, cloud roots, and stale metadata.
3. It has JSON output suitable for automation.
4. It logs all attempted actions.
5. It has a manual QA checklist entry.
6. It defaults to the least destructive reasonable behavior.

---

## 5. First Implementation Recommendation

Build in this order:

1. `cleanton-common` safety primitives.
2. `cleanton-scanner` read-only scan.
3. `cleanton-recipes` parser and validation.
4. `cleanton-engine` planner with no executor.
5. CLI JSON output.
6. Trash-only executor.
7. TUI.
8. Services.
9. ML.

This order keeps destructive behavior out of the product until the scanner, recipes, safety model, and plan format are already testable.
