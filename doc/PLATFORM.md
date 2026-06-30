# Cleanton — macOS Platform Realities (2026)

> This document captures the macOS- and APFS-specific truths that a disk cleaner must
> respect to be correct, honest, and safe. The other docs describe *what* Cleanton does;
> this one describes the *ground it stands on*. Several items here are subtle enough to
> silently break the core promise ("free up space, lose nothing") if ignored, so each is
> treated as a first-class requirement.
>
> Target platform: **macOS Tahoe 26** (Apple's year-based versioning, "Liquid Glass" era)
> on **Apple Silicon** (M-series) primarily, with Intel as a secondary target. APFS is the
> only supported on-disk format.

---

## 1. "Freed" vs "Reclaimable": The Honesty Problem

This is the single most important correctness issue in the product, because the entire UI
is built around a freed-space counter.

### 1.1 Trash does not free space

`trash` (the default and preferred action) moves items to `~/.Trash` (or a per-volume
`.Trashes`). **No space is reclaimed until the user empties the Trash.** A counter that
says "Freed 47.3 GB" immediately after trashing is factually wrong; the bytes still occupy
the disk.

**Requirement**: The UI and JSON output must distinguish:

| Term | Meaning |
|---|---|
| **Reclaimable** | Bytes the plan *targets*. Shown during scan/plan. |
| **Moved to Trash** | Bytes relocated to Trash by a `trash` action — *not yet freed*. |
| **Freed** | Bytes actually returned to free space — only `delete` actions, or after the user empties Trash. |

The execution screen (`UI_DESIGN.md` §3.4) must label the live counter **"Moved to Trash"**
for trash actions and **"Freed"** only for permanent deletes, and should offer an explicit
**"Empty Trash now"** affordance (with its own confirmation) so the user can realize the
space. Cleanton must never empty the Trash automatically.

### 1.2 APFS snapshots pin "deleted" space

macOS keeps **local APFS snapshots** (Time Machine local snapshots, plus snapshots taken by
Software Update and some backup tools). A file referenced by a snapshot continues to occupy
disk **even after it is deleted and the Trash is emptied** — the space becomes *purgeable*,
not free, until the snapshot expires (local TM snapshots are normally evicted within ~24h or
under space pressure).

**Requirement**: When reporting results, Cleanton must not promise that deleted bytes are
immediately available. If `tmutil listlocalsnapshots /` shows snapshots, surface a note:
"≈N GB may remain held by local snapshots and free up automatically within ~24 hours."
Cleanton must **never** delete snapshots itself.

### 1.3 Purgeable space distorts disk-usage readouts

The Dashboard "Disk Usage: 487 GB / 1 TB" figure is misleading if taken from a naïve
`statvfs`/`f_bavail`. macOS reports large amounts of **purgeable** space (caches, snapshots,
re-downloadable content) that Finder hides from "Available".

**Requirement**: Compute capacity using the URL resource keys
`volumeAvailableCapacityForImportantUsageKey` (what the user can really use) and
`volumeTotalCapacityKey`, not raw `statvfs`. Where Cleanton cannot call those APIs directly
from Rust, document the FFI/`statfs` approximation and label the number as approximate.
Show purgeable separately rather than folding it into "free".

### 1.4 APFS clones and sparse files

APFS supports **clones** (copy-on-write file copies that share blocks) and **sparse files**.
Two consequences:

1. Summing logical file sizes **overestimates** reclaimable space when blocks are shared
   (clones) and **overestimates** for sparse files (logical size ≫ allocated blocks).
2. Deleting one clone frees only the blocks unique to it.

**Requirement**: The scanner records both **logical bytes** and **allocated blocks**
(`st_blocks`) per `CRATES.md` §2.5. Reclaimable estimates use allocated blocks and are always
presented as estimates ("≈"). The plan must never present an exact freed total before
execution (already an invariant in `IMPLEMENTATION_PLAN.md`).

### 1.5 Hardlinks: inode de-duplication

`pnpm`, `bun`, Time Machine, and content-addressable stores use **hardlinks**. A file with
link count > 1 is counted once per path by a naïve walk, inflating the reclaimable total, and
deleting one path frees **zero** bytes until the last link is gone.

**Requirement**: Size aggregation (`cleanton-scanner` `aggregator.rs`) must de-duplicate by
`(device, inode)`; bytes from a multiply-linked inode are counted once. The metadata schema
already captures device + inode (`CRATES.md` §2.5) — the aggregator must actually use it.
This is also why the pnpm/bun global stores are `cautious`: project `node_modules` are
hardlink farms into the store.

---

## 2. Permissions, TCC, and First-Run UX

### 2.1 Full Disk Access attaches to the *host*, not the abstract "app"

This is the most common source of "it works for me but not the user" confusion for a
terminal tool:

- When Cleanton runs as a **Homebrew CLI / TUI**, the TCC grant (Full Disk Access, and access
  to `Desktop`/`Documents`/`Downloads`) is evaluated against the **terminal emulator** hosting
  it (Terminal.app, iTerm2, Ghostty, WezTerm, …), *not* against the `cleanton` binary. The
  user must grant FDA to **their terminal**.
- When Cleanton runs as a distributed, signed **`.app`**, the grant attaches to the app's code
  signature / bundle ID.

**Requirement**: First-run guidance (`IMPLEMENTATION_PLAN.md` M9) must detect the execution
context and give the *correct* instruction. For the CLI, it must name the host terminal and
deep-link to **System Settings → Privacy & Security → Full Disk Access**
(`x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`). Telling a CLI
user to "add Cleanton to Full Disk Access" is wrong and will not work.

### 2.2 Degraded mode is the default, not the exception

Most home directories are *partly* readable without FDA. `~/Library` subtrees, `Desktop`,
`Documents`, `Downloads`, and Removable/Network volumes raise TCC denials. Per existing
invariants, permission errors are first-class results, not crashes, and **never** raise a
target's safety. This doc adds one clarification:

**Requirement**: The scan summary must state coverage explicitly — e.g. "Scanned 412k files;
**3 locations skipped** (no permission): `~/Library/Mail`, …". A confident-looking total over
an incomplete scan is a trust failure.

### 2.3 macOS Tahoe 26 specifics

- The Tahoe redesign ("Liquid Glass") changes **System Settings** layout/labels; first-run
  copy and screenshots must target Tahoe's Settings, and the deep-link URL scheme above is the
  stable way to send users there.
- Tahoe continues the trend of **recurring TCC re-consent** prompts for some categories. Any
  capability Cleanton relies on must tolerate a permission being revoked between runs.
- Apple Intelligence / system ML caches under macOS control are **out of scope** and must be
  treated as OS-managed (never cleaned), consistent with "What Cleanton Is NOT".

---

## 3. Distribution: Gatekeeper, Quarantine, Notarization

A correct safety story does not help if users can't run the binary, or run a tampered one.

| Channel | Quarantine / Gatekeeper behavior | Requirement |
|---|---|---|
| **Homebrew formula/bottle** | Bottles installed by Homebrew are **not** quarantined; no Gatekeeper prompt. Preferred channel for the CLI. | Ship a tap/formula; the binary still must be signed + notarized so ad-hoc downloads also work. |
| **Direct download (`.tar.gz`/`.dmg` via browser/curl)** | Gets the `com.apple.quarantine` xattr; unsigned/un-notarized binaries are blocked ("cannot be opened"). | **Hardened Runtime + Developer ID signature + notarization + stapling** are mandatory for any non-Homebrew artifact. |
| **`.app` bundle (DMG)** | Same as above, plus first-launch Gatekeeper dialog. | Notarize and staple the `.app`; DMG itself should be signed. |

**Notes for implementation**:
- A non-sandboxed CLI needs **no entitlements** to read user files (FDA is granted to the
  host), but **Hardened Runtime is required for notarization**. If the `ml` feature ships ONNX
  Runtime as a dynamic library, it must be signed and either bundled or the binary needs the
  `com.apple.security.cs.disable-library-validation` entitlement — prefer signing/bundling over
  disabling validation.
- Release artifacts must contain **no** training data, full FontAwesome packs, credentials, or
  developer-local paths (already an M9 exit gate; restated here because notarization uploads the
  artifact to Apple).
- Tooling: `cargo-dist` has been **renamed to `dist`** (still maintained, standalone CLI) — see
  `ARCHITECTURE.md` §7.2. Verify current `dist` macOS signing/notarization support at
  implementation time rather than assuming the 2024 behavior.

---

## 4. Path Safety on Real macOS Filesystems

`SAFETY.md` Layer 1 requires boundary-aware ancestor checks with `~` expansion, `.`/`..`
collapse, and symlink resolution. Real APFS adds three traps that a string-prefix or
naïvely-canonicalized check will miss:

### 4.1 Case-insensitivity (default APFS)

Default APFS (`APFS`, not `APFS (Case-sensitive)`) is **case-insensitive, case-preserving**.
`~/Library/KEYCHAINS` resolves to the protected `~/Library/Keychains`. A case-sensitive
protected-path comparison can be bypassed.

**Requirement**: Protected-path and recipe-exclusion comparisons must perform
**case-insensitive** matching *when the target volume is case-insensitive*, and case-sensitive
matching on case-sensitive volumes. Detect per-volume (`pathconf(_PC_CASE_SENSITIVE)` or the
volume's `VOL_CAP_FMT_CASE_SENSITIVE` capability) rather than assuming one mode.

### 4.2 Unicode normalization (NFD/NFC)

macOS paths can carry either Unicode normalization form; APFS preserves bytes but compares
normalized. A protected directory named with composed vs. decomposed characters (e.g. an
accented username or folder) can defeat a byte-for-byte comparison.

**Requirement**: Normalize both sides (e.g. to NFC) before comparing protected paths and
recipe excludes. This is currently absent from `SAFETY.md` Layer 1 and is added there.

### 4.3 Firmlinks and the synthetic root

macOS uses a read-only **System** volume and a writable **Data** volume joined by
**firmlinks** (`/Users`, `/Applications`, `/private/var`, …), and synthesized symlinks
(`/var` → `/private/var`, `/etc` → `/private/etc`, `/tmp` → `/private/tmp`). Canonicalizing a
path can therefore relocate it across the System/Data boundary.

**Requirement**: After canonicalization, protected-path checks must hold for **both** the
pre- and post-firmlink forms. The hardcoded denylist already lists `/private`, `/var`, and
`/etc`; the comparator must treat `/var/...` and `/private/var/...` as equivalent (canonicalize
both, compare boundary-aware) so a `/var/...` target can't slip past a check written for
`/private/var`.

### 4.4 `~/Library/Containers` reachability

Sandboxed apps store their data — **including caches** — under
`~/Library/Containers/<bundle-id>/Data/Library/Caches`. That whole subtree is a protected path.
Consequence: Cleanton **cannot and must not** reach into sandboxed-app caches. Recipes that
think they target `~/Library/Caches/<id>` will simply miss sandboxed apps. This is the correct,
conservative behavior and must be documented so the recipe coverage isn't mistaken for a bug.

---

## 5. Container Runtimes (2026)

`bollard` speaks the Docker Engine API over a socket, but in 2026 "Docker" on a Mac is a
plurality of runtimes, each with different data locations and space semantics. The single most
important fact:

> **Pruning inside the VM does not shrink the host disk image.** Docker Desktop, Colima,
> Podman-machine, and Lima all run Linux in a VM backed by a **sparse disk image** on the Mac.
> `docker system prune` frees space *inside* the VM, but the host-side image file
> (`Docker.raw`, `*.qcow2`, etc.) does **not** auto-shrink. Reclaiming host space requires a
> separate compaction step.

| Runtime | API socket (typical) | Host-side data | Shrink mechanism |
|---|---|---|---|
| **Docker Desktop** | `~/.docker/run/docker.sock` / `/var/run/docker.sock` | `~/Library/Containers/com.docker.docker/Data/...` (`Docker.raw`) | Desktop UI "clean up", or recreate the VM; not via prune alone |
| **OrbStack** | `~/.orbstack/run/docker.sock` | `~/.orbstack/` | Auto-shrinks on TRIM; far less of a problem |
| **Colima** | `~/.colima/default/docker.sock` | `~/.colima/` (qcow2) | `colima stop && qemu-img convert`/`colima delete` |
| **Podman** | `podman machine` socket | `~/.local/share/containers/` | `podman machine` reset/compaction |
| **Rancher Desktop** | moby/containerd socket | app data dir | app-managed |

**Requirements**:
1. Detect the active runtime and **connect to whichever socket exists** (env `DOCKER_HOST`
   first, then the known socket paths above), rather than assuming Docker Desktop.
2. After an API prune, report it honestly: "Freed X GB **inside the VM**. The macOS disk image
   may not shrink until the runtime compacts it." Never count VM-internal prune bytes as host
   "Freed".
3. Volumes remain `aggressive` (may hold databases) and require API-based inspection
   (`SAFETY.md` Layer 12 / risk register).
4. If no runtime/socket is present, Docker recipes are simply inert — not an error.

---

## 6. Homebrew Prefix & Tool Discovery

- **Apple Silicon** Homebrew lives at `/opt/homebrew`; **Intel** at `/usr/local`. Never
  hardcode one. Resolve via `brew --prefix` / `brew --cache`, or check both.
- The download cache is `$(brew --cache)` (commonly `~/Library/Caches/Homebrew`), but the path
  is configurable via `HOMEBREW_CACHE`. Recipes should prefer asking `brew` over globbing a
  fixed path when `brew` is on `PATH`.
- Homebrew Services state should be read via `brew services list --json` (machine-readable),
  falling back to plist inspection (`CRATES.md` §8.2). The `homebrew.mxcl.*` label prefix
  identifies brew-managed launch agents.

---

## 7. Apple Silicon & Local AI (2026)

Modern Mac dev machines are dominated by local AI workloads, which are the largest disk
consumers Cleanton will see (tens to hundreds of GB):

- **MLX** (Apple's array framework) caches models under the Hugging Face hub
  (`~/.cache/huggingface/hub`) and project-local dirs; MLX-community weights are `.safetensors`.
- **Ollama** (`~/.ollama/models`), **LM Studio** (`~/.lmstudio/models`, legacy
  `~/.cache/lm-studio/models`), **llama.cpp**/GGUF model dirs, **vLLM** (`~/.cache/vllm`).
- These are **`cautious`** by default: a 4–70 GB model is expensive to re-download and the user
  likely chose it deliberately. Size-rank them high in the UI but never auto-select.

See `RECIPES.md` category `ml` for the concrete recipes; this section is the rationale for
their conservative defaults.

---

## 8. Concurrency Model Clarification

`ARCHITECTURE.md` §4.4 states the engine runs on `tokio` while the scanner uses `rayon`/`jwalk`.
Running a `rayon` parallel walk **directly inside an async task blocks the tokio reactor**.

**Requirement**: Filesystem walking and sizing (CPU/IO-bound, `rayon`-driven) must run via
`tokio::task::spawn_blocking` (or a dedicated thread that owns the `rayon` pool), communicating
progress back through the `mpsc` channel. `tokio` is justified primarily by `bollard`'s async
Docker API and the channel-driven UI; the scanner itself should not assume it is running on an
async worker thread.

---

## 9. Platform Checklist (add to release QA)

- [ ] Live counter reads "Moved to Trash" for trash actions, "Freed" only for deletes.
- [ ] Local-snapshot note shown when `tmutil listlocalsnapshots /` is non-empty.
- [ ] Disk-usage figure uses important-usage capacity, not raw `statvfs`; purgeable shown apart.
- [ ] Size totals de-duplicate hardlinked inodes (verify with a pnpm/bun project fixture).
- [ ] Reclaimable totals use allocated blocks; clones/sparse files don't overpromise.
- [ ] First-run FDA guidance names the host terminal (CLI) or the bundle (`.app`) correctly.
- [ ] Protected-path comparison passes case-insensitive and NFD/NFC bypass fixtures.
- [ ] `/var/...` target is caught by the `/private/var` protection (firmlink equivalence).
- [ ] Docker prune reports "inside the VM"; never counted as host freed space.
- [ ] Works against OrbStack/Colima/Podman sockets, not only Docker Desktop.
- [ ] Homebrew cache resolved on both `/opt/homebrew` and `/usr/local`.
- [ ] Direct-download artifact is signed, notarized, and stapled; Homebrew bottle installs clean.
