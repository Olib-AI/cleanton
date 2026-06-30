# Cleanton — Safety Model

> This document details every layer of protection that prevents cleanton from
> causing data loss. Safety is the #1 priority — above features, performance, and aesthetics.

---

## 1. Threat Model

| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Delete wrong files via bad recipe pattern | Medium | **Critical** | Recipe validation, self-tests, protected paths |
| Delete protected system files | Low | **Critical** | Hardcoded protected path list |
| Symlink traversal attack | Low | High | Never follow symlinks during deletion |
| Race condition (TOCTOU) | Low | High | Pre-execution metadata revalidation, symlink-safe deletion APIs, NotFound-as-skip behavior |
| User error (confirm wrong plan) | Medium | Medium | Dry-run default, size guards, double confirm for aggressive |
| Corrupt scan data leads to bad plan | Very Low | High | Plan validation before execution |
| ML model misclassification | Medium | Medium | Confidence threshold, cautious-by-default |
| macOS privacy denial hides context | Medium | Medium | Permission errors surfaced in plan; never infer safety from incomplete scans |
| Cloud-synced placeholder deletion | Medium | High | Cloud roots excluded by default; cloud providers are cautious and require explicit opt-in |
| Active process writes into target during cleanup | Medium | Medium | Liveness checks where possible, execution-time metadata recheck, partial failure logging |

---

## 2. Defense Layers

### Layer 1: Protected Paths (Hardcoded)

These paths can **never** be deleted, regardless of any recipe, user config, or ML output:

```
/System/                    # macOS system
/Library/                   # System library
/usr/                       # Unix system
/bin/                       # System binaries
/sbin/                      # System admin binaries
/private/                   # macOS private directories, including /private/var
/etc/                       # System config
/var/                       # System variable data
/Applications/              # Installed apps
~/.ssh/                     # SSH keys
~/.gnupg/                   # GPG keys
~/.aws/                     # Cloud credentials
~/.azure/                   # Cloud credentials
~/.config/gcloud/           # Cloud credentials
~/.kube/                    # Kubernetes credentials
~/.config/cleanton/         # Own configuration
~/.docker/config.json       # Registry credentials
~/.npmrc                    # Registry tokens
~/.pypirc                   # Package registry tokens
~/.netrc                    # Machine credentials
~/Library/Keychains/        # Keychain data
~/Library/Mail/             # Email data
~/Library/Messages/         # Messages database and attachments
~/Library/Containers/       # Sandboxed app containers
~/Library/Group Containers/ # Shared app containers
~/Desktop/                  # User desktop
~/Documents/                # User documents
~/Downloads/                # User downloads
~/Pictures/                 # User photos
~/Music/                    # User music
~/Movies/                   # User movies
```

**Implementation**: `ProtectedPaths::is_protected()` is called during recipe validation, planning, and immediately before **every** deletion.
Even if a recipe somehow matches a protected path, the executor will refuse and log a warning.

Path comparison must normalize `~`, collapse `.` and `..`, resolve symlinks where the path exists, and perform boundary-aware ancestor checks. String-prefix checks are forbidden because `/Users/alice/Documents-old` is not inside `/Users/alice/Documents`.

Three macOS-specific normalizations are **mandatory** (omitting any of them is a bypass; see [PLATFORM.md](./PLATFORM.md) §4):

1. **Unicode normalization** — normalize both sides to the same form (e.g. NFC) before comparing. APFS preserves bytes but compares normalized, so a composed-vs-decomposed accented path (`é` as one codepoint vs `e` + combining mark) must not defeat a protected-path check.
2. **Case folding on case-insensitive volumes** — default APFS is case-insensitive/case-preserving, so `~/Library/KEYCHAINS` *is* `~/Library/Keychains`. Compare case-insensitively when the target volume reports case-insensitive (`pathconf(_PC_CASE_SENSITIVE)` / `VOL_CAP_FMT_CASE_SENSITIVE`), case-sensitively otherwise.
3. **Firmlink/synthetic-symlink equivalence** — `/var` → `/private/var`, `/etc` → `/private/etc`, `/tmp` → `/private/tmp`, and System/Data firmlinks mean a path can canonicalize across the boundary. A protection written for `/private/var` must also catch a `/var/...` target. Canonicalize both forms and apply the check to each.

### Layer 2: Recipe Validation

Every recipe goes through validation before it can be used:

1. **Schema validation** — all required fields present, correct types
2. **Pattern validation** — glob patterns compile successfully
3. **Self-test execution** — `[test]` section's `should_match` and `should_not_match` are verified
4. **Protected path check** — recipe patterns are tested against protected paths; any match = recipe rejected
5. **Breadth check** — recipes that match too broadly (e.g., `**/*`) are rejected
6. **Context proof** — project artifact recipes must require local evidence such as `Cargo.toml`, `package.json`, `pyvenv.cfg`, `Package.swift`, lockfiles, or known cache directory names
7. **Secret guard** — any pattern that can match credentials, keychains, tokens, shell history, password-store data, or agent conversation history is rejected

### Layer 3: Safety Levels

| Level | UI Treatment | Confirmation | Restrictions |
|---|---|---|---|
| `safe` | Green badge ✅ | Single "Execute" confirmation | Must be regenerable and supported by context proof |
| `cautious` | Yellow badge ⚠️ | Per-item confirmation in UI | Must show full path list |
| `aggressive` | Red badge 🔴 | Double confirmation + forced dry-run first | Size limit: max 5GB per action; only level allowed to use permanent delete |

### Layer 4: Dry-Run Default

- **TUI mode**: Shows full plan before any execution; user must explicitly press `x` then confirm
- **CLI mode**: `cleanton clean` defaults to `--dry-run`; must pass `--yes` to actually execute
- **JSON mode**: `cleanton scan --json` never executes anything

### Layer 5: Size Guards

| Guard | Default | Override |
|---|---|---|
| Max total per run | 50 GB | `--force` flag |
| Max single item | 20 GB | Per-item confirmation |
| Aggressive recipe max | 5 GB per action | Cannot be overridden |

### Layer 6: Trash Preferred

The default `action_type` is `trash`, not `delete`:

- `trash` → moves to macOS Trash (recoverable via Finder → Empty Trash)
- `delete` → permanent removal. This is reserved for explicitly approved `aggressive` recipes for truly ephemeral, tool-owned caches and remains blocked for `safe` and `cautious` recipes.
- `archive` → compress to `~/.config/cleanton/archive/` before removal. Note: archiving onto the **same APFS volume** reclaims little space and adds risk; `archive` is only meaningful when the destination is a different volume, and is disabled by default.

### Layer 7: Execution Logging

Every execution writes a detailed log:

```toml
# ~/.config/cleanton/logs/2026-06-28_18-30-00.toml

[execution]
timestamp = "2026-06-28T18:30:00-04:00"
duration_seconds = 12.4
total_actions = 14
successful = 13
failed = 1
total_freed_bytes = 47_300_000_000

[[actions]]
path = "/Users/user/projects/my-app/target"
action = "trash"
recipe = "rust-target-dirs"
size_bytes = 2_300_000_000
result = "success"
trash_location = "~/.Trash/target-20260628-183001"

[[actions]]
path = "/Users/user/projects/web/node_modules"
action = "trash"
recipe = "node-modules"
size_bytes = 891_000_000
result = "success"
trash_location = "~/.Trash/node_modules-20260628-183005"
```

Logs must avoid storing secret file contents. Paths are allowed because the user needs forensic traceability, but future telemetry or support bundles must redact usernames and known secret-bearing path segments by default.

Logs themselves must not become an unbounded leak: rotate by count/age (keep the last N runs and/or M days, configurable) and prune older logs. Because `~/.config/cleanton/` is a protected path, Cleanton never cleans its own logs via a recipe — rotation is the engine's own responsibility, performed on startup.

Each `[[actions]]` entry records its action `type` and, for `trash`, makes explicit that the bytes are **moved to Trash, not freed** (see [PLATFORM.md](./PLATFORM.md) §1.1). Run totals separate `moved_to_trash_bytes` from `freed_bytes`; only permanent deletes contribute to `freed_bytes`.

### Layer 8: Symlink Safety

1. Scanner records symlink targets but **never traverses** them
2. Executor can delete symlinks themselves (the link, not the target)
3. If a deletion target turns out to be a symlink at execution time (wasn't during scan), abort that action
4. Log warning for any symlink encountered during deletion
5. Re-stat the target immediately before action and compare kind, device, inode/file ID where available, and canonical parent against the scan-time record

### Layer 9: ML Guardrails

When the ML model is enabled:

1. **Confidence threshold** — only act on predictions with confidence ≥ 0.85 (configurable)
2. **Never auto-execute ML results** — always present for user review
3. **Label bias** — model is trained with bias toward `Keep` (false negatives > false positives)
4. **No ML for aggressive** — ML cannot recommend `aggressive` safety level actions
5. **No ML-created execution** — ML can only annotate ambiguous findings. It cannot create a cleanable action without a recipe or explicit user selection.

### Layer 10: Service Control Guards

When managing macOS services via `cleanton-services`:

1. **System Service Immunity** — any launchd service with label starting with `com.apple.` or located in `/System/Library/` is strictly immutable. The CLI/UI must display them as read-only and refuse modification commands.
2. **Elevated Privilege Isolation** — Cleanton must **never** be run as `root` (sudo) globally. For operations requiring root privileges (like starting/stopping System LaunchDaemons in `/Library/LaunchDaemons`), Cleanton will isolate elevation to targeted subprocesses using standard macOS authorization APIs (`osascript` GUI admin prompt) or prompt the user for password verification.
3. **Backup before Deletion** — before deleting an orphaned plist file, a backup copy is automatically created under `~/.config/cleanton/backups/services/` to allow full rollback capabilities if needed.
4. **Dependency Warn-on-Stop** — stopping critical local development infrastructure (e.g. database daemons like Redis/PostgreSQL or Docker) requires a warning modal indicating that local development projects may be disrupted.

### Layer 11: macOS Privacy and Volume Guards

1. Permission-denied directories remain visible as scan warnings and reduce confidence in any parent summary.
2. Cloud-synced roots (`~/Library/Mobile Documents`, iCloud Drive, Dropbox, Google Drive, OneDrive, Box) are excluded from bulk actions by default.
3. External, network, and Time Machine volumes are excluded unless passed explicitly via `--root` or enabled in config.
4. Trash actions must detect cross-volume behavior. If moving to Trash would copy large data across volumes or fail, the action becomes a confirmation-required error instead of falling back to permanent delete.
5. Size reporting must distinguish logical bytes from estimated reclaimable bytes on APFS.

### Layer 12: Active-Use Guards

1. Do not clean a directory that contains a lockfile or pidfile for a currently running process unless the recipe explicitly knows how to validate it.
2. Docker, Homebrew services, simulators, package managers, and model servers are queried through their APIs/CLIs when available before deleting associated state.
3. Recently modified items default to keep unless a recipe has a strong reason and a documented minimum age.
4. If execution partially succeeds, the result is `partial_success`; the UI and JSON output must never report a full reclaimed total.

---

## 3. Incident Response

If a user reports data loss:

1. Check execution log at `~/.config/cleanton/logs/`
2. Check macOS Trash for recoverable items
3. The log contains exact paths, timestamps, and recipe IDs for forensic analysis
4. If the issue is a recipe bug, the recipe's `[test]` section should be updated to prevent recurrence

---

## 4. Testing Safety

### Automated Tests

| Test Type | What It Verifies |
|---|---|
| Protected path unit tests | Every hardcoded protected path is actually protected |
| Recipe self-tests | Every recipe's `should_match` / `should_not_match` pass |
| Protected path recipe tests | No recipe pattern matches any protected path |
| Fixture directory tests | Full pipeline on known fixture → expected actions |
| Mutation tests | Corrupted recipe → rejected, not executed |

### Manual QA Checklist

Before any release:

- [ ] Run `cleanton scan --dry-run` on a real home directory — inspect every proposed action
- [ ] Verify protected paths cannot be deleted even with a crafted recipe
- [ ] Verify `--force` is required for > 50 GB
- [ ] Verify aggressive recipes show double confirmation
- [ ] Verify execution log is written correctly
- [ ] Verify Trash integration works (items appear in Finder Trash)
- [ ] Test with symlinks pointing to important directories
- [ ] Test with read-only directories (should skip gracefully)
- [ ] Test permission-denied directories without Full Disk Access
- [ ] Test iCloud Drive and external volume roots remain excluded by default
- [ ] Test APFS clone/sparse-file size reporting does not overpromise reclaimed bytes
- [ ] Test active Docker/Homebrew services are detected before service-related cleanup
