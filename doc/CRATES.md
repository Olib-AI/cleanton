# Cleanton — Crate Reference

> Detailed specifications for each crate in the workspace.
> For the high-level overview, see [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## 1. `cleanton-common` — Shared Foundation

**Path**: `crates/cleanton-common/`
**Type**: Library crate
**Dependencies**: Minimal — `serde`, `thiserror`, `tracing`, `chrono`, `humansize`, `directories`

### 1.1 Modules

```
cleanton-common/
├── src/
│   ├── lib.rs              # Re-exports
│   ├── types.rs            # Core data types (FileEntry, ScanResult, etc.)
│   ├── error.rs            # CleantonError enum
│   ├── config.rs           # CleantonConfig + deserialization
│   ├── safety.rs           # ProtectedPaths + validation
│   ├── paths.rs            # Path utilities (expand ~, canonicalize, etc.)
│   └── display.rs          # Display implementations, human-readable sizes
└── Cargo.toml
```

### 1.2 Key Rules

1. **No mutating filesystem I/O** — this crate defines types and pure validation helpers. Read-only path normalization helpers are allowed only when needed by safety code.
2. **No async** — all types are `Send + Sync` but the crate itself does not depend on `tokio`
3. **Serialization** — all public types derive `Serialize, Deserialize` for JSON output mode
4. **Error philosophy** — use `thiserror` for all error types; every variant must carry enough context for a human-readable error message

### 1.3 Protected Paths Implementation

```rust
/// Paths that must NEVER be touched, regardless of recipe or user config.
pub const HARDCODED_PROTECTED: &[&str] = &[
    "/System",
    "/Library",
    "/usr",
    "/bin",
    "/sbin",
    "/private",
    "/etc",
    "/var",
    "/Applications",
];

/// Per-user paths that should never be touched
pub const USER_PROTECTED: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".config/cleanton",
    ".kube",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "Library/Keychains",
    "Library/Mail",
    "Library/Messages",
    "Library/Containers",
    "Library/Group Containers",
    "Desktop",
    "Documents",
    "Downloads",
    "Pictures",
    "Music",
    "Movies",
];

pub struct ProtectedPaths {
    hardcoded: Vec<PathBuf>,
    user_configured: Vec<PathBuf>,
}

impl ProtectedPaths {
    /// Returns true if the given path is protected and must not be deleted
    pub fn is_protected(&self, path: &Path) -> bool;

    /// Returns true if any ancestor of the given path is protected
    pub fn has_protected_ancestor(&self, path: &Path) -> bool;
}
```

---

## 2. `cleanton-scanner` — Filesystem Walker

**Path**: `crates/cleanton-scanner/`
**Type**: Library crate
**Dependencies**: `cleanton-common`, `jwalk`, `walkdir`, `ignore`, `rayon`, `tokio` (only for progress channels if the async API is retained)

### 2.1 Modules

```
cleanton-scanner/
├── src/
│   ├── lib.rs              # Public API: scan(), ScanOptions
│   ├── walker.rs           # Parallel directory walker (jwalk wrapper)
│   ├── project.rs          # Project root detection logic
│   ├── metadata.rs         # File metadata collection & enrichment
│   ├── aggregator.rs       # Size aggregation per directory
│   ├── filter.rs           # Pre-scan exclusion filters
│   └── progress.rs         # Progress reporting (via callback/channel)
└── Cargo.toml
```

### 2.2 Key Rules

1. **Never modify the filesystem** — scan is 100% read-only
2. **Never follow symlinks** — record symlink targets but do not traverse them
3. **`.gitignore` is a *signal*, never a traversal filter.** This is a correctness trap: the
   directories Cleanton targets (`target/`, `node_modules/`, `__pycache__/`, `.next/`, …) are
   *exactly* the ones listed in `.gitignore`. Using the `ignore` crate's default behavior would
   **skip the very waste we are looking for**. Therefore the walker must traverse ignored paths,
   and "ignored by git" is recorded per-entry as a *regenerability hint* (and an ML feature,
   `has_gitignore`), not as a reason to prune the walk. The `respect_gitignore` option only
   controls whether this hint is computed, **not** whether ignored dirs are entered.
4. **De-duplicate hardlinked inodes when aggregating size** — count bytes from a multiply-linked
   `(device, inode)` once, or pnpm/bun stores and Time Machine links inflate the reclaimable
   total (see [PLATFORM.md](./PLATFORM.md) §1.5).
5. **Report progress** — emit progress events at regular intervals (every 1000 files or 100ms, whichever comes first)
6. **Handle permission errors gracefully** — log and skip, never crash

### 2.3 Public API

```rust
pub struct ScanOptions {
    pub roots: Vec<PathBuf>,
    pub max_depth: usize,
    pub follow_symlinks: bool,      // scan-only metadata option; executor never follows symlinks
    pub respect_gitignore: bool,
    pub exclude_patterns: Vec<String>,
    pub exclude_cloud_roots: bool,
    pub exclude_external_volumes: bool,
    pub parallel_threads: usize,    // 0 = auto
}

pub struct ScanResult {
    pub entries: Vec<FileEntry>,
    pub project_roots: Vec<ProjectRoot>,
    pub total_files: u64,
    pub total_dirs: u64,
    pub total_bytes: u64,
    pub duration: Duration,
    pub errors: Vec<ScanError>,     // Permission denied, etc.
    pub incomplete: bool,           // True when permissions or volume guards skipped paths
}

pub struct ProjectRoot {
    pub path: PathBuf,
    pub ecosystem: Ecosystem,       // Rust, Node, Python, Swift, etc.
    pub artifact_dirs: Vec<PathBuf>,// Known cleanable directories within this project
    pub total_size: u64,
    pub artifact_size: u64,
}

/// Main entry point — runs a parallel scan and returns results
pub async fn scan(
    options: ScanOptions,
    progress_tx: tokio::sync::mpsc::Sender<ScanProgress>,
) -> Result<ScanResult, CleantonError>;
```

### 2.4 Project Root Detection

The scanner performs a two-pass approach:

1. **Pass 1 (Fast)**: Walk directories and collect marker files (`Cargo.toml`, `package.json`, etc.)
2. **Pass 2 (Targeted)**: For each detected project root, calculate artifact sizes within known cleanable subdirectories

This avoids the cost of traversing every file in every `node_modules/` — instead, we detect the project root and calculate `node_modules/` size directly.

### 2.5 Metadata Requirements

The scanner must collect enough metadata for safe execution-time revalidation:

| Metadata | Purpose |
|---|---|
| File kind | Detect file/directory/symlink swaps between scan and execution |
| Device and inode/file ID when available | Detect replacement of a target path |
| Logical bytes and allocated blocks | Avoid overpromising reclaimed space on APFS clones/sparse files |
| Modified time | Enforce minimum-age recipes |
| Canonical parent where available | Validate protected ancestors and symlink boundaries |
| Permission error records | Make incomplete scans visible in UI/JSON |

---

## 3. `cleanton-recipes` — Rule Engine

**Path**: `crates/cleanton-recipes/`
**Type**: Library crate
**Dependencies**: `cleanton-common`, `serde`, `toml`, `glob`, `regex`

### 3.1 Modules

```
cleanton-recipes/
├── src/
│   ├── lib.rs              # Public API: load_recipes(), RecipeSet
│   ├── parser.rs           # TOML recipe file parser
│   ├── validator.rs        # Recipe validation (catch bad globs, missing fields)
│   ├── matcher.rs          # Match engine: recipe × file entry → CleanupAction
│   ├── registry.rs         # Recipe registry: built-in + user recipes merged
│   └── builtin.rs          # Embedded built-in recipes (include_str!)
├── Cargo.toml
└── tests/
    ├── fixtures/           # Test recipe files
    └── matcher_tests.rs
```

### 3.2 Key Rules

1. **Built-in recipes are embedded** — compiled into the binary via `include_str!()` so the app works without external recipe files
2. **User recipes override** — if a user recipe has the same `id` as a built-in, the user recipe wins
3. **Validation is strict** — invalid recipe files produce clear errors, never silently ignored
4. **Glob patterns are tested** — every recipe must include at least one test case in its definition
5. **No regex in patterns** — recipes use glob syntax only for safety and readability; regex is reserved for internal implementation

### 3.3 Recipe Schema (Full)

```toml
[recipe]
id = "unique-recipe-id"            # Required, kebab-case
name = "Human-Readable Name"       # Required
description = "What this cleans"    # Required
category = "rust"                   # Required: rust|swift|node|python|go|jvm-android|dart-flutter|docker|ml|ai-tools|editors|apps|system
icon = "fa-crate"                   # FA icon identifier
safety_level = "safe"               # Required: safe|cautious|aggressive
enabled = true                      # Default: true
priority = 50                       # 0-100, higher = shown first

[match]
# At least one match criterion is required
directory_name = "target"           # Match directories by exact name
file_name = "*.ckpt"               # Match files by glob
file_extension = [".pyc", ".pyo"]  # Match by extension(s)
path_glob = "**/DerivedData/**"    # Full path glob
parent_must_contain = ["Cargo.toml"] # Parent dir must contain these files
min_size_mb = 10                    # Only match if total size > N MB
min_age_days = 7                    # Only match if not modified for N days

[match.exclude]
paths = ["**/target/release/*.app"] # Never match these patterns
names = [".gitkeep"]               # Never match these file names

[action]
type = "trash"                      # trash|delete|archive
prompt = "Remove {size} of {name} from {project}?"
group = true                        # Group all matches under one action

[test]
# Self-test: paths that SHOULD match this recipe
should_match = [
    "projects/my-app/target/debug/build/",
    "projects/my-app/target/debug/deps/",
]
# Self-test: paths that MUST NOT match
should_not_match = [
    "projects/my-app/target/release/my-app",
    "projects/my-app/src/",
]
```

### 3.4 Match Semantics (Normative)

The schema above is ambiguous without an explicit boolean contract. The matcher MUST implement:

1. **Across fields: AND.** All present `[match]` criteria must hold for an entry to match.
   `directory_name = "target"` **and** `parent_must_contain = ["Cargo.toml"]` **and**
   `min_size_mb = 10` means *named `target`, has a sibling `Cargo.toml`, and ≥ 10 MB*.
2. **Within a list field: OR.** `file_extension = [".pyc", ".pyo"]` matches either extension.
3. **`[match.exclude]` wins over `[match]`.** Any exclude hit removes the entry, unconditionally.
4. **`min_age_days` uses the newest mtime within the subtree**, not the directory's own mtime.
   A `target/` dir's mtime updates on every build; "untouched for 30 days" must mean *no file
   inside* changed in 30 days. Recipes that size a whole directory therefore age on the
   most-recently-modified descendant.
5. **`min_size_mb` uses hardlink-deduped allocated size** (PLATFORM.md §1.5), the same figure
   shown to the user — never the naïve logical sum.
6. **Empty `[match]` is rejected at validation** (no "match everything"), reinforcing the
   breadth check in SAFETY.md Layer 2.

Each recipe's `[test]` `should_match` / `should_not_match` fixtures must exercise these
semantics (e.g. a fixture that matches the name but fails `parent_must_contain`).

### 3.5 Built-In Recipe List

See [RECIPES.md](./RECIPES.md) for the complete list with examples.

---

## 4. `cleanton-engine` — Core Pipeline

**Path**: `crates/cleanton-engine/`
**Type**: Library crate
**Dependencies**: `cleanton-common`, `cleanton-scanner`, `cleanton-recipes`, `cleanton-ml`, `tokio`, `trash`

### 4.1 Modules

```
cleanton-engine/
├── src/
│   ├── lib.rs              # Re-exports
│   ├── orchestrator.rs     # Top-level pipeline: scan → analyze → plan → execute
│   ├── analyzer.rs         # Match results against recipes + ML
│   ├── planner.rs          # Build CleanupPlan from analysis
│   ├── executor.rs         # Execute the plan (trash/delete/archive)
│   ├── events.rs           # EngineEvent enum and channel types
│   ├── docker.rs           # Docker-specific cleanup (via bollard)
│   └── rollback.rs         # Execution log for potential rollback
└── Cargo.toml
```

### 4.2 Key Rules

1. **Pipeline is uni-directional** — `scan → analyze → plan → execute`, no step can be skipped
2. **Events are non-blocking** — the engine never blocks waiting for the UI to consume events
3. **Executor is idempotent** — re-running the same plan on the same filesystem is safe; missing targets are skipped and logged as already gone
4. **Docker cleanup is special** — uses the Docker Engine API (`bollard`), not filesystem operations
5. **Every deletion is logged** — `~/.config/cleanton/logs/YYYY-MM-DD_HH-MM-SS.toml` contains every action attempted, skipped, failed, or completed
6. **Plans are immutable** — a plan contains scan-time metadata fingerprints and must be revalidated before execution; stale plans cannot be executed after a configurable timeout

### 4.3 Orchestrator API

```rust
pub struct Orchestrator {
    config: CleantonConfig,
    recipes: RecipeSet,
    ml_engine: Option<MlEngine>,
}

impl Orchestrator {
    pub fn new(config: CleantonConfig) -> Result<Self, CleantonError>;

    /// Run the full pipeline, emitting events to the provided channel
    pub async fn run(
        &self,
        options: ScanOptions,
        event_tx: mpsc::Sender<EngineEvent>,
    ) -> Result<PipelineResult, CleantonError>;

    /// Run scan only (no cleanup)
    pub async fn scan_only(
        &self,
        options: ScanOptions,
        event_tx: mpsc::Sender<EngineEvent>,
    ) -> Result<ScanResult, CleantonError>;

    /// Execute a pre-built plan
    pub async fn execute_plan(
        &self,
        plan: CleanupPlan,
        event_tx: mpsc::Sender<EngineEvent>,
    ) -> Result<ExecutionResult, CleantonError>;
}
```

### 4.4 Docker Cleanup Module

Docker cleanup operates differently from filesystem cleanup:

```rust
pub struct DockerCleaner {
    client: bollard::Docker,
}

impl DockerCleaner {
    /// List all cleanable Docker resources
    pub async fn analyze(&self) -> Result<DockerAnalysis, CleantonError>;

    /// Execute Docker cleanup
    pub async fn clean(&self, plan: DockerCleanupPlan) -> Result<DockerCleanupResult, CleantonError>;
}

pub struct DockerAnalysis {
    pub dangling_images: Vec<ImageInfo>,
    pub stopped_containers: Vec<ContainerInfo>,
    pub unused_volumes: Vec<VolumeInfo>,
    pub build_cache: BuildCacheInfo,
    pub total_reclaimable: u64,
}
```

---

## 5. `cleanton-ml` — ML Classification (Optional)

**Path**: `crates/cleanton-ml/`
**Type**: Library crate (behind `ml` Cargo feature)
**Dependencies**: `cleanton-common`, `ort`, `ndarray`

### 5.1 Modules

```
cleanton-ml/
├── src/
│   ├── lib.rs              # Public API: MlEngine, classify()
│   ├── features.rs         # Feature extraction from FileEntry
│   ├── inference.rs        # ONNX session management and inference
│   ├── labels.rs           # Classification label definitions
│   └── fallback.rs         # Heuristic fallback when ONNX unavailable
├── models/
│   └── file_classifier_v2.onnx  # Pre-trained model (embedded, ~83 KB)
├── training/               # Python training scripts (not compiled)
│   ├── train.py
│   ├── export_onnx.py
│   └── requirements.txt
└── Cargo.toml
```

### 5.2 Key Rules

1. **Entirely optional** — controlled by Cargo feature flag `ml`; when disabled, all types are no-ops
2. **Graceful degradation** — if ONNX runtime fails to initialize, log warning and fall back to heuristics
3. **Small model** — model must be < 5MB to be embedded in the binary
4. **No network access** — all shipped-app inference is local, no telemetry, no cloud calls
5. **Deterministic** — same input always produces same output (no randomness in inference)

### 5.3 Feature Vector Design

The ML model takes structured features, NOT raw file content. The **canonical 12-feature
schema is defined once** in [ML_PIPELINE.md](./ML_PIPELINE.md) §3.1; the Rust extractor here and
the Python extractor in `training/features.py` must produce byte-identical vectors (zero-drift,
enforced by the M8 parity tests). The schema is reproduced here for convenience — if the two ever
disagree, ML_PIPELINE.md wins:

| Idx | Feature | Type | Description |
|---|---|---|---|
| 0 | `extension_id` | u8 | Encoded file extension (0-255 categories) |
| 1 | `size_log10` | f32 | log10(file_size_bytes + 1) |
| 2 | `age_days` | f32 | Days since last modification (min-max scaled) |
| 3 | `depth` | u8 | Path depth from scan root |
| 4 | `parent_id` | u8 | Encoded parent directory name |
| 5 | `has_gitignore` | f32 | `.gitignore` present in the directory hierarchy |
| 6 | `has_lockfile` | f32 | Package lockfile present (`Cargo.lock`, `package-lock.json`, …) |
| 7 | `is_hidden` | f32 | Name starts with `.` |
| 8 | `sibling_count` | f32 | log10(files in same directory + 1) |
| 9 | `in_build_dir` | f32 | Inside a known build dir (`build/`, `dist/`, `out/`, …) |
| 10 | `is_source_ext` | f32 | Extension is source code (`.rs`, `.swift`, `.ts`, `.py`, …) |
| 11 | `in_cache_dir` | f32 | Directory name contains "cache"/"tmp" |

### 5.4 Public API

```rust
pub struct MlEngine {
    session: ort::Session,
}

pub struct MlClassification {
    pub label: CleanupLabel,
    pub confidence: f32,        // 0.0 - 1.0
}

pub enum CleanupLabel {
    SafeToRemove,
    LikelyJunk,
    Uncertain,
    Keep,
}

impl MlEngine {
    pub fn new() -> Result<Self, CleantonError>;
    pub fn classify(&self, entry: &FileEntry, context: &FileContext) -> Result<MlClassification, CleantonError>;
    pub fn classify_batch(&self, entries: &[(&FileEntry, &FileContext)]) -> Result<Vec<MlClassification>, CleantonError>;
}
```

---

## 6A. `cleanton-app` — Native GUI (Slint)

**Path**: `crates/cleanton-app/`
**Type**: Binary crate (the primary desktop application)
**Dependencies**: `cleanton-common`, `cleanton-engine`, `cleanton-scanner`, `cleanton-recipes`, `cleanton-services`, `slint`, `tokio`, `tracing-subscriber`
**Build-Dependencies**: `slint-build`

### 6A.1 Modules

```
cleanton-app/
├── build.rs                # Compiles .slint markup into Rust types
├── src/
│   └── main.rs             # Slint app entry point, callback wiring
└── ui/
    ├── app.slint            # Main window: sidebar + 5 screens
    ├── theme.slint          # Design tokens (palette, typography, spacing, radii, durations)
    └── widgets.slint        # Reusable components (GlassCard, Badge, ProgressBar, StatCard, etc.)
```

### 6A.2 Key Rules

1. **SwiftUI-inspired** — the UI uses Slint's declarative markup language which compiles to native GPU-accelerated rendering. No web views, no Electron.
2. **Reactive globals** — `AppState` and `AppCallbacks` are Slint globals exposed to Rust for two-way data binding (scan progress, cleaning status, settings).
3. **Background work** — all engine calls (scan, clean) run on `std::thread::spawn` + Tokio runtime. Progress updates are pushed to the Slint event loop via `upgrade_in_event_loop`.
4. **Dark theme** — the default palette matches the existing Cleanton color system (deep midnight base, indigo/violet accents, emerald/amber/rose semantic colors).
5. **Design tokens** — all sizes, spacings, radii, and animation durations are defined in `theme.slint` and referenced everywhere. No hardcoded values in component files.
6. **macOS Cupertino style** — when built with `SLINT_STYLE=cupertino`, Slint uses native macOS widget rendering. The app adapts automatically.

### 6A.3 Screens

| Screen | Purpose |
|---|---|
| Dashboard | Hero disk usage bar, 6 category stat cards (Rust, Swift, Node, Python, Docker, ML), quick-action buttons |
| Scanner | Real-time progress bar, file/dir/size counters, start/cancel controls |
| Results | File tree with checkboxes, safety badges, size column, "Clean Selected" button |
| Services | launchd/brew service list with status badges, start/stop/restart/enable/disable controls |
| Settings | Configuration viewer/editor (scan root, depth, cloud/volume exclusions, ML toggle) |

---

## 6B. `cleanton-ui` — Terminal User Interface (Fallback)

**Path**: `crates/cleanton-ui/`
**Type**: Library crate
**Dependencies**: `cleanton-common`, `cleanton-engine`, `ratatui`, `crossterm`, `tui-big-text`, `resvg` (optional)

### 6.1 Modules

```
cleanton-ui/
├── src/
│   ├── lib.rs              # Public API: run_tui()
│   ├── app.rs              # App state machine
│   ├── event.rs            # Terminal event handling (key, mouse, resize)
│   ├── screens/
│   │   ├── mod.rs
│   │   ├── dashboard.rs    # Main dashboard with donut chart
│   │   ├── scanner.rs      # Live scan progress screen
│   │   ├── results.rs      # Tree view of results
│   │   ├── plan.rs         # Plan review & confirmation
│   │   ├── execution.rs    # Execution progress
│   │   └── settings.rs     # Configuration screen
│   ├── widgets/
│   │   ├── mod.rs
│   │   ├── donut_chart.rs  # Animated donut/pie chart
│   │   ├── file_tree.rs    # Collapsible file tree
│   │   ├── size_bar.rs     # Proportional size indicator
│   │   ├── progress.rs     # Animated progress bar
│   │   ├── badge.rs        # Safety/confidence badges
│   │   ├── icon.rs         # FA icon rendering widget
│   │   ├── counter.rs      # Animated number counter
│   │   └── sparkline.rs    # Mini sparkline chart
│   ├── icons/
│   │   ├── mod.rs
│   │   ├── nerd_font.rs    # Nerd Font codepoint mappings
│   │   └── renderer.rs     # SVG → halfblock icon renderer
│   ├── theme.rs            # Color palette, styles
│   └── animation.rs        # Animation tick system, easing functions
└── Cargo.toml
```

### 6.2 Key Rules

1. **Immediate mode** — ratatui is immediate-mode; render the entire UI on every frame based on current state
2. **30 FPS default, 60 FPS optional** — animation tick defaults to ~33ms and may rise to ~16ms on capable terminals
3. **No blocking** — UI thread never blocks on engine operations; everything is async via channels
4. **Graceful terminal** — always restore terminal state on panic (use `color-eyre` panic hook)
5. **Keyboard-first** — all actions accessible via keyboard; mouse is optional enhancement

### 6.3 Theme System

```rust
pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub accent: Color,
    pub success: Color,
    pub warning: Color,
    pub danger: Color,
    pub muted: Color,
    pub border: Color,
    pub highlight: Color,
    pub gradient: (Color, Color),   // For animated gradients
}

pub const DARK_THEME: Theme = Theme {
    bg: Color::Rgb(15, 15, 25),         // Deep midnight blue
    fg: Color::Rgb(220, 220, 235),      // Soft white
    accent: Color::Rgb(99, 102, 241),   // Indigo
    success: Color::Rgb(34, 197, 94),   // Emerald
    warning: Color::Rgb(250, 204, 21),  // Amber
    danger: Color::Rgb(239, 68, 68),    // Rose
    muted: Color::Rgb(100, 100, 130),   // Slate
    border: Color::Rgb(55, 55, 85),     // Subtle border
    highlight: Color::Rgb(139, 92, 246),// Violet
    gradient: (
        Color::Rgb(99, 102, 241),       // Indigo start
        Color::Rgb(168, 85, 247),       // Purple end
    ),
};
```

### 6.4 Animation System

```rust
pub struct AnimationState {
    pub tick: u64,
    pub fps: u8,
    pub easing: EasingFunction,
}

pub enum EasingFunction {
    Linear,
    EaseInOut,
    EaseOutCubic,
    Spring { stiffness: f32, damping: f32 },
}

/// Animated value that interpolates from current to target
pub struct AnimatedValue<T: Interpolatable> {
    current: T,
    target: T,
    velocity: f32,
    easing: EasingFunction,
}
```

### 6.5 Screen Navigation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │Dashboard │  │ Scanner  │  │ Results  │  │ Services │  │   Settings   │   │
│  │  (Tab 1) │  │ (Tab 2)  │  │ (Tab 3)  │  │  (Tab 4) │  │   (Tab 5)    │   │
│  └────┬─────┘  └────┬─────┘  └─────┬────┘  └────┬─────┘  └──────────────┘   │
│       │              │              │           │                           │
│       │         [Enter/Space]  [Enter on item]  │                           │
│       │              │              │       [s/r/d/x]                       │
│       │              ▼              ▼           ▼                           │
│       │         ┌──────────┐  ┌──────────┐  ┌──────────┐                    │
│       │         │Plan View │  │  Detail  │  │  Action  │                    │
│       │         │ (Modal)  │  │  (Modal) │  │  (Confirm│                    │
│       │         └────┬─────┘  └──────────┘  └──────────┘                    │
│       │              │                                                      │
│       │         [Confirm]                                                   │
│       │              │                                       │
│       │              ▼                                       │
│       │         ┌──────────┐                                 │
│       │         │Execution │                                 │
│       │         │(Progress)│                                 │
│       │         └──────────┘                                 │
│       │                                                      │
│  [q] Quit    [Tab] Switch    [?] Help    [/] Search          │
└──────────────────────────────────────────────────────────────┘
```

---

## 7. `cleanton-cli` — Binary Entry Point

**Path**: `crates/cleanton-cli/`
**Type**: Binary crate
**Dependencies**: `cleanton-common`, `cleanton-engine`, `cleanton-ui`, `clap`, `tracing-subscriber`, `color-eyre`, `tokio`

### 7.1 Modules

```
cleanton-cli/
├── src/
│   ├── main.rs             # Entry point, panic hooks, runtime setup
│   ├── args.rs             # CLI argument definitions (clap derive)
│   ├── commands/
│   │   ├── mod.rs
│   │   ├── interactive.rs  # Launch TUI mode
│   │   ├── scan.rs         # Headless scan command
│   │   ├── clean.rs        # Headless cleanup command
│   │   ├── recipes.rs      # Recipe management commands
│   │   └── config.rs       # Config display/edit commands
│   ├── output.rs           # Output formatting (table, JSON, plain)
│   └── logging.rs          # tracing subscriber setup
└── Cargo.toml
```

### 7.2 Key Rules

1. **TUI is default** — running `cleanton` with no arguments launches the interactive TUI
2. **Headless is explicit** — `cleanton scan` / `cleanton clean` run without TUI
3. **Exit codes** — 0 = success, 1 = error, 2 = nothing to clean, 3 = user cancelled, 4 = scan incomplete (permissions); these are part of the public contract and must not be renumbered
4. **Versioned JSON** — every `--json` payload carries a top-level `schema_version` (integer, starts at 1). Breaking shape changes bump it; consumers can pin. A documented JSON Schema lives under `doc/schemas/`. This is what makes Cleanton safe to script in CI.
5. **JSON is total** — machine output distinguishes `reclaimable`, `moved_to_trash`, and `freed` byte counts separately (never a single conflated "freed"; see [PLATFORM.md](./PLATFORM.md) §1) and includes the `incomplete` scan flag.
6. **Logging** — `CLEANTON_LOG` env var controls log level (like `RUST_LOG`)
7. **No telemetry** — the binary never phones home

---

## 8. `cleanton-services` — macOS Services Manager

**Path**: `crates/cleanton-services/`
**Type**: Library crate
**Dependencies**: `cleanton-common`, `plist` (for parsing plist files), `serde`, `tokio`, `tracing`, `libc` (for unix system calls)

### 8.1 Modules

```
cleanton-services/
├── src/
│   ├── lib.rs              # Re-exports (ServiceManager, Service, etc.)
│   ├── types.rs            # Data models for services
│   ├── launchd.rs          # plist parsing & launchctl bindings
│   ├── brew.rs             # Homebrew Services CLI interaction
│   ├── safety.rs           # System-critical service protection
│   └── manager.rs          # Coordinator orchestrating status & actions
└── Cargo.toml
```

### 8.2 Key Rules

1. **System Service Protection** — services matching system paths (e.g., `/System/Library/Launch*`) or prefix `com.apple.` are immutable. The manager must refuse to stop or modify them.
2. **Launchctl bootstrap/bootout API** — prefer modern `launchctl bootstrap gui/<uid>` and `launchctl bootout gui/<uid>` over legacy `launchctl load/unload`.
3. **Homebrew services parsing** — run `brew services list --json` (if available) or execute and parse the stdout cleanly. Fall back to reading Homebrew launch agent plists directly for faster performance.
4. **Root elevation handling** — if a service requires root (LaunchDaemons), detect privilege levels and return a structured error `CleantonError::RootPrivilegesRequired` rather than executing a failing command.
5. **No system-wide mutations without warning** — any service stop/disable operation triggers a cautious/aggressive warning flag.
6. **No parsing unstable status text when avoidable** — prefer plist files, `launchctl print` only for human diagnostics, and Homebrew JSON output for machine-readable state.

### 8.3 Core Structs & APIs

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,                 // e.g. "com.redis.redis-server"
    pub name: String,               // e.g. "redis-server" or "redis"
    pub service_type: ServiceType,  // LaunchAgent | LaunchDaemon | BrewService
    pub status: ServiceStatus,      // Running | Stopped | Unknown
    pub plist_path: PathBuf,        // Path to the service .plist file
    pub program: Option<PathBuf>,   // Executable path
    pub program_arguments: Vec<String>,
    pub run_at_load: bool,          // Does it start on boot?
    pub label: String,
    pub user_id: Option<u32>,       // User ID owner
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    UserLaunchAgent,       // ~/Library/LaunchAgents
    SystemLaunchAgent,     // /Library/LaunchAgents
    SystemLaunchDaemon,    // /Library/LaunchDaemons
    BrewService,           // Managed by brew services
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    Running { pid: u32, cpu_percent: Option<f32>, memory_bytes: Option<u64> },
    Stopped,
    Loaded,
    Error(String),
}

pub struct ServiceManager {
    config: CleantonConfig,
    safety_blocklist: Vec<String>,
}

impl ServiceManager {
    pub fn new(config: CleantonConfig) -> Self;

    /// List all background services (launchd and brew services)
    pub async fn list_services(&self) -> Result<Vec<Service>, CleantonError>;

    /// Check status of a specific service
    pub async fn get_status(&self, service_id: &str) -> Result<ServiceStatus, CleantonError>;

    /// Start a service
    pub async fn start_service(&self, service_id: &str) -> Result<(), CleantonError>;

    /// Stop a service
    pub async fn stop_service(&self, service_id: &str) -> Result<(), CleantonError>;

    /// Restart a service
    pub async fn restart_service(&self, service_id: &str) -> Result<(), CleantonError>;

    /// Enable a service (set run_at_load = true or bootstrap)
    pub async fn enable_service(&self, service_id: &str) -> Result<(), CleantonError>;

    /// Disable a service (set run_at_load = false or bootout)
    pub async fn disable_service(&self, service_id: &str) -> Result<(), CleantonError>;

    /// Delete orphaned launch agent plist file (if executable is missing)
    pub async fn delete_orphaned_plist(&self, service_id: &str) -> Result<(), CleantonError>;
}
```

---

## 8B. `cleanton-antivirus` — Static Supply-Chain Scanner

**Path**: `crates/cleanton-antivirus/`
**Type**: Library crate (vendored from the rusted-batata workspace's `rb-antivirus`; keep diffs against upstream minimal — it deliberately does NOT opt into the workspace lints)
**Dependencies**: `serde`, `regex`, `sha2`/`sha1`/`md-5`, `flate2`, `tar`, `zip`, `walkdir`, `unicode-normalization`

A general-purpose, multi-engine **static** malware and supply-chain scanner. It
loads a target (file, directory tree, or archive such as an npm `.tgz`) into an
in-memory `FileUnit` set, runs every `DetectionEngine` over it (signatures,
rules, entropy, IOC, script behavior, binary indicators, supply-chain,
typosquat, worm propagation), and aggregates the `Finding`s into a scored
`ScanReport` with a `Verdict` (`Clean` / `Suspicious` / `Malicious`).

Key properties:

1. **Pure/static** — no network access, no execution of scanned code; bounded
   memory with zip-bomb, file-size, and archive-depth limits (`ScanConfig`).
2. **Entry point** — the `Scanner` facade: `Scanner::with_default_engines(ScanConfig::default()).scan_path(&dir)`.
3. **Findings** carry `Severity` (Info..Critical), `Confidence`, a
   `ThreatCategory` (install script, exfiltration, credential access,
   typosquatting, dependency confusion, …), and a sanitized evidence snippet.

### 8B.1 The `security` module in `cleanton-engine`

`crates/cleanton-engine/src/security.rs` builds Cleanton's **Security** feature
on top of this crate: a read-only supply-chain scan of installed packages.

- **Target discovery** (filesystem only — never spawns `npm`/`pip`/`node`):
  global `node_modules` trees (`/opt/homebrew/lib`, `/usr/local/lib`,
  `~/.npm-global`, pnpm `~/Library/pnpm/global/*/node_modules`,
  `~/.bun/install/global`, `~/.yarn/global`), Python site-packages
  (`~/Library/Python/*/lib/python*/site-packages`, pipx venvs, uv tools),
  VS Code/Cursor extensions, and — via project roots — project `node_modules`
  and virtualenv `site-packages` trees. Absent locations are skipped silently.
- **Orchestration** — each top-level package is one `Scanner` run so findings
  attribute to a package; identical resolved paths are scanned once; a bounded
  worker pool (≤4 threads) with progress callbacks and `AtomicBool`
  cancellation.
- **Report** — `SecurityReport` (serde-serializable): targets, packages
  scanned, duration, flagged packages sorted worst-first (name/version from
  the manifest, path, verdict, score, top findings), and summary counts by
  verdict/severity. `summary_message()` and `PackageReport::finding_lines()`
  are the shared copy rendered identically by the CLI, the Slint app, and the
  TUI.
- **Policy** — detection + notification ONLY. No `CleanupAction` is ever
  produced from security findings; the report shows paths so the user can act
  manually with their package manager.

### 8B.2 CLI

`cleanton security` scans the discovered global/extension targets (add project
trees with `--root <path>`; `--json` emits the full `SecurityReport`).
Exit codes: `0` clean, `3` suspicious findings, `5` malicious findings
(distinct from `plan`/`clean`'s `2` = empty plan and `4` = incomplete scan).

Both UIs surface the same scan as a **Security** tab (Slint screen index 6;
TUI tab `[6]`), with idle → progress → results states and no destructive
affordance.

---

## 9. Cargo Feature Flags

| Feature | Default | Crates Affected | Description |
|---|---|---|---|
| `ml` | `false` | `cleanton-ml`, `cleanton-engine` | Enable ONNX-based ML classification |
| `docker` | `true` | `cleanton-engine` | Enable Docker cleanup via bollard |
| `icons-svg` | `false` | `cleanton-ui` | Enable SVG→halfblock icon rendering (requires `resvg`) |
| `nerd-font` | `true` | `cleanton-ui` | Use Nerd Font glyph codepoints for icons |

---

## 10. Testing Strategy

| Level | Location | Coverage |
|---|---|---|
| **Unit** | Each crate's `tests/` module | Type construction, path matching, recipe parsing |
| **Integration** | `tests/` at workspace root | Full pipeline with fixture directories |
| **Fixture dirs** | `tests/fixtures/` | Fake project trees with known sizes |
| **Recipe tests** | Embedded in recipe TOML (`[test]` section) | Self-testing recipes |
| **Snapshot tests** | `cleanton-ui` | TUI rendering snapshots via `insta` |
| **Property tests** | `cleanton-scanner`, `cleanton-recipes` | Fuzz matching logic via `proptest` |
