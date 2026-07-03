//! Review-only disk-cleanup *suggestions*: content-based duplicate file sets and
//! large file/folder candidates.
//!
//! Nothing in this module mutates the filesystem or produces executable
//! [`cleanton_common::CleanupAction`]s. It is a purely advisory, read-only pass
//! over an in-memory [`ScanResult`] whose results are surfaced to the user for
//! manual review. Every I/O error encountered while hashing a candidate is
//! swallowed (the offending file is skipped) so a suggestion pass can never fail
//! a scan.
//!
//! The hashing pipeline is deliberately staged to stay responsive on large home
//! directories:
//! 1. bucket candidates by exact logical size (a unique size cannot be a dup);
//! 2. within each size bucket, group by a cheap 4 KiB prefix signature;
//! 3. only the survivors get a full streaming content hash, processed
//!    largest-size-first and bounded by a byte/file budget.

use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    ffi::OsStr,
    fs::File,
    hash::Hasher,
    io::{ErrorKind, Read},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use cleanton_common::{FileKind, ScanResult};
use serde::{Deserialize, Serialize};

/// Minimum logical size for a file to be considered for duplicate detection
/// (1 MiB). Smaller files are cheap to keep and noisy to report.
pub const MIN_DUP_BYTES: u64 = 1_048_576;
/// Minimum logical size for a standalone large-file suggestion (1 GiB).
pub const LARGE_FILE_MIN: u64 = 1_073_741_824;
/// Minimum subtree size for a large-folder suggestion (1 GiB).
pub const LARGE_DIR_MIN: u64 = 1_073_741_824;
/// Minimum subtree size for a directory to be considered a re-downloadable
/// ("reclaimable") git repository suggestion (2 GiB). Higher than
/// [`LARGE_DIR_MIN`] because spawning `git` per candidate is comparatively
/// expensive, so only genuinely large checkouts are probed.
pub const LARGE_REPO_MIN: u64 = 2 * 1_073_741_824;
/// Hard ceiling on the number of large directories given a read-only `git`
/// probe, so a deeply nested tree (e.g. a gclient checkout with dozens of
/// vendored repos) can never spawn an unbounded number of subprocesses.
pub const MAX_REPO_PROBES: usize = 64;
/// Hard ceiling on bytes streamed through the full-content hasher (8 GiB).
pub const MAX_HASH_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Hard ceiling on the number of files given a full-content hash.
pub const MAX_HASH_FILES: usize = 5_000;
/// Maximum number of paths retained per reported [`DuplicateSet`].
pub const MAX_PATHS_PER_SET: usize = 20;
/// Maximum number of [`DuplicateSet`]s reported.
pub const MAX_DUP_SETS: usize = 100;
/// Maximum number of [`LargeItem`]s reported.
pub const MAX_LARGE_ITEMS: usize = 100;
/// Prefix length, in bytes, used for the cheap pre-hash signature (4 KiB).
pub const SIGNATURE_PREFIX: usize = 4_096;
/// Streaming chunk size, in bytes, for the full-content hash (64 KiB).
pub const CHUNK_BYTES: usize = 64 * 1024;
/// Wall-clock ceiling for a single read-only `git` invocation. A `git status`
/// on a multi-million-file checkout can be slow; on timeout the child is killed
/// and the repo is annotated "couldn't verify changes" rather than hanging.
const GIT_PROBE_TIMEOUT: Duration = Duration::from_secs(8);
/// Wall-clock ceiling for a single `du -sk` invocation used to measure a
/// directory suggestion's true on-disk size. More generous than
/// [`GIT_PROBE_TIMEOUT`] because `du` over a multi-million-file checkout is
/// slower than `git status`; on timeout the floor (depth-limited) size is kept.
const DU_TIMEOUT: Duration = Duration::from_secs(30);
/// Poll cadence while waiting for a spawned child process to exit.
const SUBPROCESS_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Top-level directories under `$HOME` whose contents are eligible for
/// suggestions. Everything else is ignored.
const USER_DATA_ROOTS: &[&str] = &[
    "Downloads",
    "Documents",
    "Desktop",
    "Pictures",
    "Movies",
    "Music",
];

/// Path components that disqualify a candidate outright. Matched
/// case-sensitively against each `Normal` path component, this covers three
/// classes that must never be surfaced for reclaim:
/// 1. build artifacts / caches / VCS metadata / dependency trees, the macOS
///    `Library`, trash, etc. (already covered by the cleanup plan or noise);
/// 2. tool / SDK / package- and version-manager homes (`.pyenv`, `.nvm`, `go`,
///    `homebrew`, conda installs, …) — large and nominally "reinstallable", but
///    deleting them breaks the user's toolchain; e.g. `.pyenv` is itself a git
///    clone with a remote, so without this it would masquerade as a re-clonable
///    repo while actually holding the user's installed Python versions.
const SKIP_COMPONENTS: &[&str] = &[
    // Build artifacts, caches, VCS metadata, dependency trees, OS dirs.
    "node_modules",
    "target",
    ".cache",
    "Caches",
    ".git",
    "build",
    "dist",
    ".venv",
    "venv",
    "__pycache__",
    "Library",
    ".Trash",
    "vendor",
    ".next",
    ".turbo",
    // Tool / SDK / package- & version-manager homes. Large but NOT junk:
    // removing them breaks the toolchain, so keep them out of every suggestion.
    ".pyenv",
    ".nvm",
    ".rbenv",
    ".nodenv",
    ".jenv",
    ".goenv",
    ".asdf",
    ".sdkman",
    ".rustup",
    ".cargo",
    ".rvm",
    ".gem",
    ".npm",
    ".yarn",
    ".bun",
    ".deno",
    ".pixi",
    ".conda",
    "miniconda3",
    "anaconda3",
    "mambaforge",
    ".gradle",
    ".m2",
    ".local",
    "go",
    "homebrew",
    ".linuxbrew",
    ".ghcup",
    ".cabal",
    ".stack",
    ".opam",
    ".nimble",
];

/// A set of byte-for-byte identical files (same full content hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateSet {
    /// Size of a single copy, in bytes.
    pub file_bytes: u64,
    /// Number of identical copies discovered (always `>= 2`).
    pub count: usize,
    /// Bytes reclaimable by collapsing the set to one copy: `(count - 1) * file_bytes`.
    pub reclaimable_bytes: u64,
    /// The copies, sorted lexicographically and capped at [`MAX_PATHS_PER_SET`].
    /// `count` still reflects the true total even when this list is truncated.
    pub paths: Vec<PathBuf>,
}

/// A single large file or folder surfaced for review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LargeItem {
    /// Absolute path of the item.
    pub path: PathBuf,
    /// Logical size in bytes: the file's own size, or a folder's subtree total.
    pub bytes: u64,
    /// `true` for a folder (subtree) suggestion, `false` for a standalone file.
    pub is_dir: bool,
    /// `true` when this folder is a re-downloadable git checkout (a clone with a
    /// configured remote): deleting it loses nothing that cannot be re-fetched.
    /// Always `false` for plain large files and plain large folders.
    ///
    /// Defaulted on deserialization so older persisted [`Suggestions`] remain
    /// readable.
    #[serde(default)]
    pub redownloadable: bool,
    /// Human-readable annotation for the suggestion, e.g.
    /// `"git · github.com/torvalds · clean — re-clonable"`. Empty for plain
    /// large files and plain large folders. Defaulted on deserialization for
    /// backward compatibility.
    #[serde(default)]
    pub note: String,
}

/// The full set of review-only suggestions produced from a single scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suggestions {
    /// Duplicate sets, sorted by `reclaimable_bytes` descending, capped at [`MAX_DUP_SETS`].
    pub duplicates: Vec<DuplicateSet>,
    /// Sum of `reclaimable_bytes` across the reported [`Self::duplicates`].
    pub duplicate_reclaimable: u64,
    /// Large files and folders, sorted by `bytes` descending, capped at [`MAX_LARGE_ITEMS`].
    pub large_items: Vec<LargeItem>,
    /// macOS screenshots and screen recordings (`note` is `"screenshot"` or
    /// `"screen recording"`), sorted by `bytes` descending, capped at
    /// [`MAX_LARGE_ITEMS`]. Defaulted on deserialization for backward
    /// compatibility with older persisted [`Suggestions`].
    #[serde(default)]
    pub screenshots: Vec<LargeItem>,
    /// Sum of `bytes` across the reported [`Self::screenshots`].
    #[serde(default)]
    pub screenshot_reclaimable: u64,
    /// Installer images and packages sitting in `~/Downloads` (`note` is
    /// `"installer"`): `.dmg`, `.pkg`, `.mpkg`, `.iso`, `.xip`. Already-installed
    /// or abandoned downloads users are typically comfortable giving up — all
    /// re-downloadable. Sorted by `bytes` descending, capped at
    /// [`Limits::max_large_items`]. Defaulted on deserialization for backward
    /// compatibility with older persisted [`Suggestions`].
    #[serde(default)]
    pub installers: Vec<LargeItem>,
    /// Sum of `bytes` across the reported [`Self::installers`].
    #[serde(default)]
    pub installer_reclaimable: u64,
    /// `true` if the hashing budget was hit and some candidates went un-hashed.
    pub truncated: bool,
}

/// Tunable thresholds and budgets for [`detect_with_limits`].
///
/// [`detect_suggestions`] uses [`Limits::production`]; tests inject tiny values
/// so duplicate/large detection can be exercised without gigabyte fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Minimum file size eligible for duplicate detection.
    pub min_dup_bytes: u64,
    /// Minimum file size for a standalone large-file suggestion.
    pub large_file_min: u64,
    /// Minimum subtree size for a large-folder suggestion.
    pub large_dir_min: u64,
    /// Minimum subtree size for a re-downloadable git-repo suggestion.
    pub large_repo_min: u64,
    /// Ceiling on the number of large dirs given a read-only `git` probe.
    pub max_repo_probes: usize,
    /// Ceiling on bytes streamed through the full-content hasher.
    pub max_hash_bytes: u64,
    /// Ceiling on the number of files given a full-content hash.
    pub max_hash_files: usize,
    /// Maximum number of paths retained per [`DuplicateSet`].
    pub max_paths_per_set: usize,
    /// Maximum number of [`DuplicateSet`]s reported.
    pub max_dup_sets: usize,
    /// Maximum number of [`LargeItem`]s reported.
    pub max_large_items: usize,
    /// Prefix length used for the cheap pre-hash signature.
    pub signature_prefix: usize,
    /// Streaming chunk size for the full-content hash.
    pub chunk_bytes: usize,
}

impl Limits {
    /// The production thresholds backing [`detect_suggestions`].
    #[must_use]
    pub const fn production() -> Self {
        Self {
            min_dup_bytes: MIN_DUP_BYTES,
            large_file_min: LARGE_FILE_MIN,
            large_dir_min: LARGE_DIR_MIN,
            large_repo_min: LARGE_REPO_MIN,
            max_repo_probes: MAX_REPO_PROBES,
            max_hash_bytes: MAX_HASH_BYTES,
            max_hash_files: MAX_HASH_FILES,
            max_paths_per_set: MAX_PATHS_PER_SET,
            max_dup_sets: MAX_DUP_SETS,
            max_large_items: MAX_LARGE_ITEMS,
            signature_prefix: SIGNATURE_PREFIX,
            chunk_bytes: CHUNK_BYTES,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::production()
    }
}

/// Produce review-only suggestions for the given scan using production limits.
///
/// Reads `$HOME` once to scope candidates; if `HOME` is unset there are no
/// eligible user-data directories and an empty [`Suggestions`] is returned.
/// This is synchronous and CPU/IO-bound (it hashes file contents): callers
/// should run it on a background thread.
#[must_use]
pub fn detect_suggestions(scan: &ScanResult) -> Suggestions {
    match std::env::var_os("HOME").map(PathBuf::from) {
        Some(home) => detect_with_limits(scan, &home, &Limits::production()),
        None => Suggestions::default(),
    }
}

/// Core suggestion pass with injectable `home` and `limits` for deterministic
/// testing. See module docs for the staged hashing strategy.
#[must_use]
pub(crate) fn detect_with_limits(scan: &ScanResult, home: &Path, limits: &Limits) -> Suggestions {
    let (duplicates, truncated) = detect_duplicates(scan, home, limits);
    let duplicate_reclaimable = duplicates
        .iter()
        .fold(0u64, |acc, set| acc.saturating_add(set.reclaimable_bytes));
    let large_items = detect_large_items(scan, home, limits);
    let screenshots = detect_screenshots(scan, home, limits);
    let screenshot_reclaimable = screenshots
        .iter()
        .fold(0u64, |acc, item| acc.saturating_add(item.bytes));
    let installers = detect_installers(scan, home, limits);
    let installer_reclaimable = installers
        .iter()
        .fold(0u64, |acc, item| acc.saturating_add(item.bytes));

    Suggestions {
        duplicates,
        duplicate_reclaimable,
        large_items,
        screenshots,
        screenshot_reclaimable,
        installers,
        installer_reclaimable,
        truncated,
    }
}

/// Classify a path as a macOS screenshot or screen recording by its basename,
/// or `None` if it is neither. macOS names screenshots
/// `"Screenshot 2026-01-01 at 10.00.00 AM.png"` (older systems: `"Screen Shot
/// ...png"`) and screen recordings `"Screen Recording 2026-01-01 at ....mov"`.
/// Matched case-insensitively; the leading-word check keeps arbitrary user PNGs
/// and videos out.
fn screenshot_kind(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    let ext = path
        .extension()
        .and_then(OsStr::to_str)
        .map(str::to_ascii_lowercase);
    let is_image = ext.as_deref() == Some("png");
    let is_video = matches!(ext.as_deref(), Some("mov" | "mp4" | "m4v"));
    if is_image && (name.starts_with("screenshot ") || name.starts_with("screen shot ")) {
        return Some("screenshot");
    }
    if is_video && name.starts_with("screen recording ") {
        return Some("screen recording");
    }
    None
}

/// Detect macOS screenshots and screen recordings anywhere under `$HOME` (clear
/// of build/cache/toolchain/media-library paths). Review-only, like every other
/// suggestion. Files keep their exact scan size; sorted largest-first and capped
/// at [`Limits::max_large_items`].
fn detect_screenshots(scan: &ScanResult, home: &Path, limits: &Limits) -> Vec<LargeItem> {
    let mut items: Vec<LargeItem> = Vec::new();
    for entry in &scan.entries {
        if entry.kind != FileKind::File {
            continue;
        }
        if home_rel_len(&entry.path, home).is_none() {
            continue;
        }
        let Some(kind) = screenshot_kind(&entry.path) else {
            continue;
        };
        items.push(LargeItem {
            path: entry.path.clone(),
            bytes: entry.logical_bytes,
            is_dir: false,
            redownloadable: false,
            note: kind.to_owned(),
        });
    }
    items.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    items.truncate(limits.max_large_items);
    items
}

/// Installer/disk-image extensions surfaced by [`detect_installers`]. All are
/// artifacts of a one-time install and re-downloadable from their vendor.
const INSTALLER_EXTENSIONS: &[&str] = &["dmg", "pkg", "mpkg", "iso", "xip"];

/// Detect installer images and packages under `~/Downloads`. Scoped to
/// Downloads on purpose: a `.dmg`/`.iso` kept elsewhere (a VM library, an
/// archive folder) was placed there deliberately, while Downloads is where
/// one-time installers accumulate. Review-only, sorted largest-first, capped at
/// [`Limits::max_large_items`].
fn detect_installers(scan: &ScanResult, home: &Path, limits: &Limits) -> Vec<LargeItem> {
    let downloads = home.join("Downloads");
    let mut items: Vec<LargeItem> = Vec::new();
    for entry in &scan.entries {
        if entry.kind != FileKind::File || !entry.path.starts_with(&downloads) {
            continue;
        }
        let is_installer = entry
            .path
            .extension()
            .and_then(OsStr::to_str)
            .map(str::to_ascii_lowercase)
            .is_some_and(|ext| INSTALLER_EXTENSIONS.contains(&ext.as_str()));
        if !is_installer {
            continue;
        }
        items.push(LargeItem {
            path: entry.path.clone(),
            bytes: entry.logical_bytes,
            is_dir: false,
            redownloadable: true,
            note: "installer".to_owned(),
        });
    }
    items.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    items.truncate(limits.max_large_items);
    items
}

/// Filename suffixes of macOS media-library *bundles* (Photos, Music, TV,
/// iMovie, Final Cut). These are opaque databases whose loose internal files
/// (originals, renders, thumbnails) must never be surfaced as duplicate or
/// large-file suggestions — reclaiming inside them corrupts the library. A
/// component whose name ends in one of these is treated exactly like a
/// [`SKIP_COMPONENTS`] entry.
const MEDIA_LIBRARY_SUFFIXES: &[&str] = &[
    ".photoslibrary",
    ".photolibrary",
    ".aplibrary",
    ".musiclibrary",
    ".tvlibrary",
    ".imovielibrary",
    ".theater",
    ".fcpbundle",
];

/// True when a path component is a media-library bundle (see
/// [`MEDIA_LIBRARY_SUFFIXES`]), matched case-insensitively on the suffix.
fn is_media_library_component(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        let lower = name.to_ascii_lowercase();
        MEDIA_LIBRARY_SUFFIXES
            .iter()
            .any(|suffix| lower.ends_with(suffix))
    })
}

/// Number of `Normal` components of `path` relative to `home`, or `None` if
/// `path` is not an eligible user-data path (outside home, wrong top-level dir,
/// or containing a skip component / non-normal component).
fn user_data_rel_len(path: &Path, home: &Path) -> Option<usize> {
    let rel = path.strip_prefix(home).ok()?;
    let mut count = 0usize;
    let mut first: Option<&OsStr> = None;
    for component in rel.components() {
        match component {
            Component::Normal(name) => {
                if SKIP_COMPONENTS.iter().any(|skip| name == OsStr::new(skip))
                    || is_media_library_component(name)
                {
                    return None;
                }
                if first.is_none() {
                    first = Some(name);
                }
                count = count.saturating_add(1);
            }
            // Any `.`/`..`/root/prefix component means this isn't a clean
            // descendant of a user-data root; reject conservatively.
            _ => return None,
        }
    }
    let first = first?;
    if USER_DATA_ROOTS.iter().any(|root| first == OsStr::new(root)) {
        Some(count)
    } else {
        None
    }
}

/// Number of `Normal` components of `path` relative to `home`, or `None` if
/// `path` is outside `home`, contains a build/cache/recipe [`SKIP_COMPONENTS`]
/// entry, or has any non-`Normal` component.
///
/// Unlike [`user_data_rel_len`], this does **not** require the top-level
/// component to be a user-data root: it accepts any clean descendant of `home`
/// (e.g. `~/GitHub/...`). It is the scope gate for re-downloadable git-repo
/// suggestions, which can live anywhere under the home directory.
fn home_rel_len(path: &Path, home: &Path) -> Option<usize> {
    let rel = path.strip_prefix(home).ok()?;
    let mut count = 0usize;
    for component in rel.components() {
        match component {
            Component::Normal(name) => {
                if SKIP_COMPONENTS.iter().any(|skip| name == OsStr::new(skip))
                    || is_media_library_component(name)
                {
                    return None;
                }
                count = count.saturating_add(1);
            }
            // `.`/`..`/root/prefix means this isn't a clean descendant of home.
            _ => return None,
        }
    }
    Some(count)
}

/// Detect content-identical file sets. Returns the (sorted, capped) sets and
/// whether the hashing budget was hit before all candidates were processed.
fn detect_duplicates(scan: &ScanResult, home: &Path, limits: &Limits) -> (Vec<DuplicateSet>, bool) {
    // Bucket eligible files by exact logical size: a size seen only once cannot
    // be a duplicate, so single-occupant buckets are discarded.
    let mut by_size: HashMap<u64, Vec<&Path>> = HashMap::new();
    for entry in &scan.entries {
        if entry.kind != FileKind::File || entry.logical_bytes < limits.min_dup_bytes {
            continue;
        }
        // Duplicates are reported anywhere under $HOME that is not a build
        // cache / VCS / toolchain / media-library path (see `home_rel_len` +
        // SKIP_COMPONENTS). This is broader than the large-file scope (the six
        // user-data roots) on purpose: a developer's real duplicates routinely
        // live in `~/dev`, `~/Code`, `~/GitHub`, download folders, etc.
        if home_rel_len(&entry.path, home).is_none() {
            continue;
        }
        by_size
            .entry(entry.logical_bytes)
            .or_default()
            .push(entry.path.as_path());
    }

    // Process the largest sizes first so the biggest reclaim is found before any
    // budget is exhausted.
    let mut sizes: Vec<u64> = by_size
        .iter()
        .filter_map(|(size, files)| (files.len() >= 2).then_some(*size))
        .collect();
    sizes.sort_unstable_by(|a, b| b.cmp(a));

    let mut sets: Vec<DuplicateSet> = Vec::new();
    let mut bytes_hashed: u64 = 0;
    let mut files_hashed: usize = 0;
    let mut truncated = false;

    'sizes: for size in sizes {
        let Some(files) = by_size.get(&size) else {
            continue;
        };

        // Cheap pre-hash: group by a 4 KiB prefix signature to avoid fully
        // hashing files that obviously differ. Prefix reads are not budgeted.
        let mut by_prefix: HashMap<u64, Vec<&Path>> = HashMap::new();
        for &path in files {
            if let Some(prefix) = prefix_hash(path, limits.signature_prefix) {
                by_prefix.entry(prefix).or_default().push(path);
            }
        }

        for group in by_prefix.into_values() {
            if group.len() < 2 {
                continue;
            }
            let mut by_full: HashMap<u64, Vec<&Path>> = HashMap::new();
            let mut budget_hit = false;
            for path in group {
                if bytes_hashed >= limits.max_hash_bytes || files_hashed >= limits.max_hash_files {
                    truncated = true;
                    budget_hit = true;
                    break;
                }
                if let Some(full) = full_hash(path, limits.chunk_bytes) {
                    bytes_hashed = bytes_hashed.saturating_add(size);
                    files_hashed = files_hashed.saturating_add(1);
                    by_full.entry(full).or_default().push(path);
                }
            }
            for dups in by_full.into_values() {
                if dups.len() >= 2 {
                    sets.push(make_set(size, dups, limits.max_paths_per_set));
                }
            }
            if budget_hit {
                break 'sizes;
            }
        }
    }

    sets.sort_by(|a, b| {
        b.reclaimable_bytes
            .cmp(&a.reclaimable_bytes)
            .then_with(|| b.file_bytes.cmp(&a.file_bytes))
            .then_with(|| a.paths.cmp(&b.paths))
    });
    sets.truncate(limits.max_dup_sets);
    (sets, truncated)
}

/// Build a [`DuplicateSet`] from a confirmed group of identical files.
fn make_set(size: u64, mut paths: Vec<&Path>, max_paths: usize) -> DuplicateSet {
    let count = paths.len();
    paths.sort_unstable();
    let extra = u64::try_from(count.saturating_sub(1)).unwrap_or(u64::MAX);
    let reclaimable_bytes = extra.saturating_mul(size);
    let kept = paths
        .into_iter()
        .take(max_paths)
        .map(Path::to_path_buf)
        .collect();
    DuplicateSet {
        file_bytes: size,
        count,
        reclaimable_bytes,
        paths: kept,
    }
}

/// Read-only git facts about a candidate repository root.
///
/// Gathered by spawning `git` with a timeout (see [`probe_git_repo`]); injected
/// in tests so candidate selection and [`LargeItem`] assembly can be exercised
/// without a real working tree.
#[derive(Debug, Clone)]
struct RepoProbe {
    /// The configured remote URL (`origin`, falling back to any remote), trimmed.
    /// `None`/empty means there is no remote, so the checkout is **not**
    /// re-downloadable and must be skipped.
    remote: Option<String>,
    /// Working-tree cleanliness: `Some(true)` clean, `Some(false)` has local
    /// changes, `None` when `git status` failed or timed out (unverifiable).
    clean: Option<bool>,
}

/// Detect large standalone files, large folders (by subtree size), and
/// re-downloadable git checkouts, merged and sorted by size descending, capped
/// at [`Limits::max_large_items`].
fn detect_large_items(scan: &ScanResult, home: &Path, limits: &Limits) -> Vec<LargeItem> {
    detect_large_items_with_probe(scan, home, limits, &probe_git_repo, &measure_dir_size)
}

/// Core large-item pass with an injectable git `prober` and directory `sizer`
/// for deterministic tests.
///
/// `sizer` returns the true on-disk size of a directory (real `du` in
/// production), or `None` when it could not be measured. Directory suggestions
/// (plain large folders and re-clonable repos) are sized via `sizer` because the
/// scan-derived subtree sum is only a floor: the in-memory [`ScanResult`] is
/// depth-limited, so a deep tree (e.g. a Chromium/gclient checkout) has most of
/// its bytes below the scan depth and would be badly undercounted. Standalone
/// large *files* keep their exact scan `logical_bytes` and are never `sizer`-ed.
fn detect_large_items_with_probe(
    scan: &ScanResult,
    home: &Path,
    limits: &Limits,
    prober: &dyn Fn(&Path) -> RepoProbe,
    sizer: &dyn Fn(&Path) -> Option<u64>,
) -> Vec<LargeItem> {
    let mut items: Vec<LargeItem> = Vec::new();

    // Standalone large files (user-data scoped, unchanged).
    for entry in &scan.entries {
        if entry.kind != FileKind::File || entry.logical_bytes < limits.large_file_min {
            continue;
        }
        if user_data_rel_len(&entry.path, home).is_none() {
            continue;
        }
        items.push(LargeItem {
            path: entry.path.clone(),
            bytes: entry.logical_bytes,
            is_dir: false,
            redownloadable: false,
            note: String::new(),
        });
    }

    // Subtree sizes: propagate each file's bytes up to every scanned ancestor
    // directory, mirroring the in-memory ancestor walk in `analyzer.rs`.
    // O(entries × depth) over in-memory data; no extra disk walks.
    let dirs: HashSet<&Path> = scan
        .entries
        .iter()
        .filter(|entry| entry.kind == FileKind::Directory)
        .map(|entry| entry.path.as_path())
        .collect();

    let mut subtree: HashMap<&Path, u64> = HashMap::with_capacity(dirs.len());
    for entry in &scan.entries {
        if entry.kind != FileKind::File {
            continue;
        }
        for ancestor in entry.path.ancestors() {
            if !dirs.contains(ancestor) {
                continue;
            }
            subtree
                .entry(ancestor)
                .and_modify(|total| *total = total.saturating_add(entry.logical_bytes))
                .or_insert(entry.logical_bytes);
        }
    }

    // Large user-data folders (existing behavior): excluding the user-data roots
    // themselves (rel len 1), which are trivially large; only subfolders are
    // interesting. These are plain folders, not re-downloadable.
    for (&dir, &bytes) in &subtree {
        if bytes < limits.large_dir_min {
            continue;
        }
        if matches!(user_data_rel_len(dir, home), Some(len) if len >= 2) {
            items.push(LargeItem {
                path: dir.to_path_buf(),
                bytes,
                is_dir: true,
                redownloadable: false,
                note: String::new(),
            });
        }
    }

    items.extend(reclaimable_repos(scan, home, limits, &subtree, prober));

    // Dedupe by path (a re-downloadable repo under a user-data root could match
    // both passes): keep the re-downloadable entry, which carries the richer
    // annotation. Sort by path then redownloadable-desc so the kept first of
    // each run is the annotated one.
    items.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| b.redownloadable.cmp(&a.redownloadable))
    });
    items.dedup_by(|a, b| a.path == b.path);

    // Replace each directory's depth-limited floor with its true on-disk size.
    // On measurement failure keep the floor and flag the size as approximate so
    // the UI (which renders `note`) can signal the undercount.
    for item in &mut items {
        if !item.is_dir {
            continue;
        }
        if let Some(measured) = sizer(&item.path) {
            item.bytes = measured;
        } else if item.note.is_empty() {
            "size approx (depth-limited)".clone_into(&mut item.note);
        } else {
            item.note.push_str(" · size approx");
        }
    }

    items.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    items.truncate(limits.max_large_items);
    items
}

/// Identify large git checkouts that are re-downloadable (a clone with a
/// configured remote) and turn them into annotated [`LargeItem`]s.
///
/// A directory qualifies when it is a git repository root (holds a `.git`
/// child), its subtree is at least [`Limits::large_repo_min`], and it sits under
/// `home` clear of any [`SKIP_COMPONENTS`]. At most [`Limits::max_repo_probes`]
/// of the largest such roots are probed, bounding subprocess cost on deeply
/// nested trees (e.g. gclient/Chromium checkouts whose real repo roots are
/// nested directories like `.../chromium/src`).
///
/// Classification is review-only: a present remote always yields a suggestion;
/// the working-tree state only changes the annotation.
fn reclaimable_repos(
    scan: &ScanResult,
    home: &Path,
    limits: &Limits,
    subtree: &HashMap<&Path, u64>,
    prober: &dyn Fn(&Path) -> RepoProbe,
) -> Vec<LargeItem> {
    // Repo roots discovered from the in-memory scan: any dir with a `.git` child.
    // The scanner records `.git` entries (it never prunes them), so this needs no
    // filesystem access for the common case.
    let mut repo_roots: HashSet<&Path> = HashSet::new();
    for entry in &scan.entries {
        if entry.path.file_name() == Some(OsStr::new(".git"))
            && let Some(parent) = entry.path.parent()
        {
            repo_roots.insert(parent);
        }
    }

    // Large, in-scope candidate directories, largest first.
    let mut candidates: Vec<(&Path, u64)> = subtree
        .iter()
        .filter_map(|(&dir, &bytes)| {
            (bytes >= limits.large_repo_min
                && matches!(home_rel_len(dir, home), Some(len) if len >= 1))
            .then_some((dir, bytes))
        })
        .collect();
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));

    let mut out: Vec<LargeItem> = Vec::new();
    let mut probe_budget = limits.max_repo_probes;
    for (dir, bytes) in candidates {
        if probe_budget == 0 {
            break;
        }
        // Confirm it is a repo root: prefer the scan signal; only touch the
        // filesystem (one `stat`) as a fallback for the handful of large dirs
        // whose `.git` did not surface in the scan.
        if !repo_roots.contains(dir) && !dir.join(".git").exists() {
            continue;
        }
        probe_budget = probe_budget.saturating_sub(1);
        if let Some(item) = classify_repo(dir, bytes, &prober(dir)) {
            out.push(item);
        }
    }
    out
}

/// Turn a probed repo into a review-only [`LargeItem`], or `None` when it has no
/// remote (and is therefore not re-downloadable).
fn classify_repo(dir: &Path, bytes: u64, probe: &RepoProbe) -> Option<LargeItem> {
    let remote = probe
        .remote
        .as_deref()
        .map(str::trim)
        .filter(|remote| !remote.is_empty())?;
    let label = summarize_remote(remote);
    let note = match probe.clean {
        Some(true) => format!("git · {label} · clean — re-clonable"),
        Some(false) => format!("git · {label} · has local changes — review"),
        None => format!("git · {label} · couldn't verify changes"),
    };
    Some(LargeItem {
        path: dir.to_path_buf(),
        bytes,
        is_dir: true,
        redownloadable: true,
        note,
    })
}

/// Reduce a git remote URL to a compact `host/owner` label for display, e.g.
/// `https://github.com/torvalds/linux.git` and `git@github.com:torvalds/linux`
/// both become `github.com/torvalds`.
fn summarize_remote(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches(".git");
    // Drop a `scheme://` prefix if present.
    let after_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    // Drop a `user@` prefix (scp-like `git@host:owner/repo`).
    let after_user = after_scheme
        .split_once('@')
        .map_or(after_scheme, |(_, rest)| rest);
    // Normalize the scp `host:owner` separator to a path separator.
    let normalized = after_user.replacen(':', "/", 1);
    let (host, owner) = {
        let mut parts = normalized.split('/').filter(|part| !part.is_empty());
        (
            parts.next().map(str::to_owned),
            parts.next().map(str::to_owned),
        )
    };
    match (host, owner) {
        (Some(host), Some(owner)) => format!("{host}/{owner}"),
        (Some(host), None) => host,
        _ => normalized,
    }
}

/// Probe a repository root with read-only `git` calls (bounded by
/// [`GIT_PROBE_TIMEOUT`]). Never mutates the repository.
fn probe_git_repo(dir: &Path) -> RepoProbe {
    let remote = run_git(dir, &["config", "--get", "remote.origin.url"])
        .map(|out| out.trim().to_owned())
        .filter(|out| !out.is_empty());

    // Only inspect the working tree when there is a remote; otherwise the repo is
    // not re-downloadable and the (potentially slow) status call is pointless.
    let clean = if remote.is_some() {
        run_git(dir, &["status", "--porcelain", "--untracked-files=no"])
            .map(|out| out.trim().is_empty())
    } else {
        None
    };

    RepoProbe { remote, clean }
}

/// Run `git -C <dir> <args>` read-only, requiring a zero exit status.
fn run_git(dir: &Path, args: &[&str]) -> Option<String> {
    let mut full: Vec<&OsStr> = Vec::with_capacity(args.len().saturating_add(2));
    full.push(OsStr::new("-C"));
    full.push(dir.as_os_str());
    full.extend(args.iter().copied().map(OsStr::new));
    run_capture("git", &full, GIT_PROBE_TIMEOUT, true)
}

/// Measure a directory's true on-disk size with `du -sk <path>` (read-only).
/// Returns the size in bytes, or `None` on failure/timeout so the caller can
/// fall back to the depth-limited floor.
fn measure_dir_size(path: &Path) -> Option<u64> {
    // `-k` (1024-byte units) is portable on macOS/BSD and Linux; `-s` prints a
    // single summary line. Avoid `-h` (human units are unparseable). `du` exits
    // non-zero when it cannot read some entries but still prints the summary, so
    // we do *not* require success and instead parse whatever total it reports.
    let args: [&OsStr; 2] = [OsStr::new("-sk"), path.as_os_str()];
    let out = run_capture("du", &args, DU_TIMEOUT, false)?;
    parse_du_kib(&out)
}

/// Parse `du -k` output ("<kbytes>\t<path>") into bytes. Returns `None` when the
/// leading token is not a non-negative integer.
fn parse_du_kib(out: &str) -> Option<u64> {
    let kib: u64 = out.split_whitespace().next()?.parse().ok()?;
    Some(kib.saturating_mul(1024))
}

/// Run `program` with `args`, capturing stdout, bounded by `timeout`. Returns
/// `None` on spawn failure, timeout (the child is killed), or — when
/// `require_success` is set — a non-zero exit status. stdout is drained on a
/// helper thread so large output cannot deadlock by filling the OS pipe buffer
/// while the parent polls for exit. Read-only by construction: callers only ever
/// pass non-mutating commands (`git config`/`git status`, `du`).
fn run_capture(
    program: &str,
    args: &[&OsStr],
    timeout: Duration,
    require_success: bool,
) -> Option<String> {
    // `Command::new` is lint-disallowed because subprocess execution is normally
    // confined to executor adapters with explicit safety review. This is a
    // narrow, audited exception: strictly read-only queries (`git config`/`git
    // status`, `du -sk`) used only to classify and size large directories. None
    // of these commands mutate the filesystem.
    #[allow(clippy::disallowed_methods)]
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut handle = stdout;
        let _ = handle.read_to_string(&mut buf);
        buf
    });

    // `checked_add` only returns `None` on (practically impossible) clock
    // overflow; treat that as "already past the deadline" so we never busy-loop.
    let deadline = Instant::now().checked_add(timeout);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = reader.join().unwrap_or_default();
                return (!require_success || status.success()).then_some(out);
            }
            Ok(None) => {
                if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return None;
                }
                std::thread::sleep(SUBPROCESS_POLL_INTERVAL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = reader.join();
                return None;
            }
        }
    }
}

/// Hash up to `prefix_len` leading bytes of `path`. Returns `None` on any I/O
/// error so the caller skips the file silently.
fn prefix_hash(path: &Path, prefix_len: usize) -> Option<u64> {
    let mut file = File::open(path).ok()?;
    let mut buf = vec![0u8; prefix_len];
    let mut filled = 0usize;
    while filled < prefix_len {
        let dst = buf.get_mut(filled..)?;
        match file.read(dst) {
            Ok(0) => break,
            Ok(read) => filled = filled.saturating_add(read),
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    let mut hasher = DefaultHasher::new();
    hasher.write(buf.get(..filled)?);
    Some(hasher.finish())
}

/// Stream `path` in `chunk` byte chunks and return its full-content hash.
/// Returns `None` on any I/O error so the caller skips the file silently.
fn full_hash(path: &Path, chunk: usize) -> Option<u64> {
    let mut file = File::open(path).ok()?;
    let mut hasher = DefaultHasher::new();
    let mut buf = vec![0u8; chunk.max(1)];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => hasher.write(buf.get(..read)?),
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(hasher.finish())
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing into results clearer.
    #![allow(clippy::indexing_slicing)]
    use std::{
        fs,
        path::Path,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use cleanton_common::{FileEntry, FileKind, ScanResult};

    use super::*;

    fn test_limits() -> Limits {
        Limits {
            min_dup_bytes: 16,
            large_file_min: 1_000,
            large_dir_min: 1_000,
            large_repo_min: 1_000,
            max_repo_probes: 64,
            max_hash_bytes: 1 << 30,
            max_hash_files: 1_000,
            max_paths_per_set: 20,
            max_dup_sets: 100,
            max_large_items: 100,
            signature_prefix: 4_096,
            chunk_bytes: 64 * 1024,
        }
    }

    fn write_file(path: &Path, contents: &[u8]) -> u64 {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, contents).expect("write fixture file");
        contents.len() as u64
    }

    fn file_entry(path: &Path, bytes: u64) -> FileEntry {
        FileEntry {
            path: path.to_path_buf(),
            kind: FileKind::File,
            logical_bytes: bytes,
            allocated_bytes: bytes,
            modified: None,
            depth: 0,
            device_id: None,
            inode: None,
            hardlink_count: None,
            symlink_target: None,
            ignored_by_git: false,
        }
    }

    fn dir_entry(path: &Path) -> FileEntry {
        FileEntry {
            path: path.to_path_buf(),
            kind: FileKind::Directory,
            logical_bytes: 0,
            allocated_bytes: 0,
            modified: None,
            depth: 0,
            device_id: None,
            inode: None,
            hardlink_count: None,
            symlink_target: None,
            ignored_by_git: false,
        }
    }

    fn scan_of(entries: Vec<FileEntry>) -> ScanResult {
        ScanResult {
            entries,
            project_roots: Vec::new(),
            total_files: 0,
            total_dirs: 0,
            logical_bytes: 0,
            allocated_bytes: 0,
            duration: Duration::ZERO,
            errors: Vec::new(),
            incomplete: false,
        }
    }

    #[test]
    fn identical_files_form_a_single_duplicate_set() {
        let home = tempfile::tempdir().expect("home tempdir");
        let docs = home.path().join("Documents");
        let a = docs.join("a.bin");
        let b = docs.join("b.bin");
        let payload = vec![0xABu8; 4_096];
        let size = write_file(&a, &payload);
        write_file(&b, &payload);

        let scan = scan_of(vec![file_entry(&a, size), file_entry(&b, size)]);
        let result = detect_with_limits(&scan, home.path(), &test_limits());

        assert_eq!(result.duplicates.len(), 1);
        let set = &result.duplicates[0];
        assert_eq!(set.count, 2);
        assert_eq!(set.file_bytes, size);
        assert_eq!(set.reclaimable_bytes, size);
        assert_eq!(set.paths, vec![a.clone(), b.clone()]);
        assert_eq!(result.duplicate_reclaimable, size);
        assert!(!result.truncated);
    }

    #[test]
    fn duplicates_are_found_outside_the_six_user_data_roots() {
        // A developer's real duplicates often live in project folders, not the
        // Downloads/Documents/... roots. `home_rel_len` scoping must surface them.
        let home = tempfile::tempdir().expect("home tempdir");
        let a = home.path().join("dev").join("proj").join("a.bin");
        let b = home.path().join("Code").join("b.bin");
        let payload = vec![0xC3u8; 4_096];
        let size = write_file(&a, &payload);
        write_file(&b, &payload);

        let scan = scan_of(vec![file_entry(&a, size), file_entry(&b, size)]);
        let result = detect_with_limits(&scan, home.path(), &test_limits());

        assert_eq!(result.duplicates.len(), 1);
        assert_eq!(result.duplicates[0].count, 2);
    }

    #[test]
    fn files_inside_a_photo_library_bundle_are_not_candidates() {
        let home = tempfile::tempdir().expect("home tempdir");
        let lib = home
            .path()
            .join("Pictures")
            .join("Photos Library.photoslibrary")
            .join("originals");
        let a = lib.join("a.bin");
        let b = lib.join("b.bin");
        let payload = vec![0x2Bu8; 4_096];
        let size = write_file(&a, &payload);
        write_file(&b, &payload);

        let scan = scan_of(vec![file_entry(&a, size), file_entry(&b, size)]);
        let result = detect_with_limits(&scan, home.path(), &test_limits());

        assert!(result.duplicates.is_empty());
        assert!(result.large_items.is_empty());
    }

    #[test]
    fn screenshots_and_recordings_are_detected() {
        let home = tempfile::tempdir().expect("home tempdir");
        let shot = home
            .path()
            .join("Desktop")
            .join("Screenshot 2026-01-01 at 10.00.00 AM.png");
        let rec = home
            .path()
            .join("Desktop")
            .join("Screen Recording 2026-01-01 at 10.00.00 AM.mov");
        let ordinary = home.path().join("Desktop").join("diagram.png");
        let shot_size = write_file(&shot, &vec![0x10u8; 4_096]);
        let rec_size = write_file(&rec, &vec![0x11u8; 8_192]);
        write_file(&ordinary, &vec![0x12u8; 2_048]);

        let scan = scan_of(vec![
            file_entry(&shot, shot_size),
            file_entry(&rec, rec_size),
            file_entry(&ordinary, 2_048),
        ]);
        let result = detect_with_limits(&scan, home.path(), &test_limits());

        assert_eq!(result.screenshots.len(), 2);
        // Largest first: the recording (8 KiB) precedes the screenshot (4 KiB).
        assert_eq!(result.screenshots[0].path, rec);
        assert_eq!(result.screenshots[0].note, "screen recording");
        assert_eq!(result.screenshots[1].path, shot);
        assert_eq!(result.screenshots[1].note, "screenshot");
        assert_eq!(result.screenshot_reclaimable, shot_size + rec_size);
        // An ordinary PNG that is not a screenshot must be ignored.
        assert!(result.screenshots.iter().all(|item| item.path != ordinary));
    }

    #[test]
    fn installers_in_downloads_are_detected() {
        let home = tempfile::tempdir().expect("home tempdir");
        let downloads = home.path().join("Downloads");
        let dmg = downloads.join("SomeApp-4.2.1.dmg");
        let pkg = downloads.join("Tool Installer.PKG");
        let doc = downloads.join("notes.pdf");
        let elsewhere = home.path().join("VMs").join("linux.iso");
        let dmg_size = write_file(&dmg, &vec![0x20u8; 8_192]);
        let pkg_size = write_file(&pkg, &vec![0x21u8; 4_096]);
        write_file(&doc, &vec![0x22u8; 2_048]);
        let iso_size = write_file(&elsewhere, &vec![0x23u8; 8_192]);

        let scan = scan_of(vec![
            file_entry(&dmg, dmg_size),
            file_entry(&pkg, pkg_size),
            file_entry(&doc, 2_048),
            file_entry(&elsewhere, iso_size),
        ]);
        let result = detect_with_limits(&scan, home.path(), &test_limits());

        // Largest first; extension matched case-insensitively.
        assert_eq!(result.installers.len(), 2);
        assert_eq!(result.installers[0].path, dmg);
        assert_eq!(result.installers[1].path, pkg);
        assert!(
            result
                .installers
                .iter()
                .all(|item| item.note == "installer")
        );
        assert!(result.installers.iter().all(|item| item.redownloadable));
        assert_eq!(result.installer_reclaimable, dmg_size + pkg_size);
        // A PDF in Downloads and an ISO kept outside Downloads are not surfaced.
        assert!(result.installers.iter().all(|item| item.path != doc));
        assert!(result.installers.iter().all(|item| item.path != elsewhere));
    }

    #[test]
    fn same_size_different_content_is_not_a_duplicate() {
        let home = tempfile::tempdir().expect("home tempdir");
        let docs = home.path().join("Documents");
        let a = docs.join("a.bin");
        let b = docs.join("b.bin");
        let size = write_file(&a, &vec![0x11u8; 4_096]);
        write_file(&b, &vec![0x22u8; 4_096]);

        let scan = scan_of(vec![file_entry(&a, size), file_entry(&b, size)]);
        let result = detect_with_limits(&scan, home.path(), &test_limits());

        assert!(result.duplicates.is_empty());
        assert_eq!(result.duplicate_reclaimable, 0);
    }

    #[test]
    fn files_in_skipped_components_are_not_candidates() {
        let home = tempfile::tempdir().expect("home tempdir");
        let nm = home.path().join("Documents").join("node_modules");
        let a = nm.join("a.bin");
        let b = nm.join("b.bin");
        let payload = vec![0x7Fu8; 4_096];
        let size = write_file(&a, &payload);
        write_file(&b, &payload);

        let scan = scan_of(vec![file_entry(&a, size), file_entry(&b, size)]);
        let result = detect_with_limits(&scan, home.path(), &test_limits());

        assert!(result.duplicates.is_empty());
        assert!(result.large_items.is_empty());
    }

    #[test]
    fn outside_user_data_root_is_not_a_candidate() {
        let home = tempfile::tempdir().expect("home tempdir");
        // `Library` is both a non-user-data root and a skip component.
        let dir = home.path().join("Library");
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        let payload = vec![0x5Au8; 4_096];
        let size = write_file(&a, &payload);
        write_file(&b, &payload);

        let scan = scan_of(vec![file_entry(&a, size), file_entry(&b, size)]);
        let result = detect_with_limits(&scan, home.path(), &test_limits());

        assert!(result.duplicates.is_empty());
    }

    #[test]
    fn large_file_and_large_folder_are_detected() {
        let home = tempfile::tempdir().expect("home tempdir");
        let docs = home.path().join("Documents");
        let big_dir = docs.join("big");

        // A standalone large file (>= large_file_min = 1000).
        let big_file = docs.join("huge.bin");
        let big_file_size: u64 = 2_048;

        // Two files inside `Documents/big` whose subtree sums >= large_dir_min.
        let inner_a = big_dir.join("part_a.bin");
        let inner_b = big_dir.join("part_b.bin");
        let inner_size: u64 = 800;

        let scan = scan_of(vec![
            dir_entry(&docs),
            dir_entry(&big_dir),
            file_entry(&big_file, big_file_size),
            file_entry(&inner_a, inner_size),
            file_entry(&inner_b, inner_size),
        ]);
        // `big_dir` isn't a repo, so the prober is never consulted; the sizer
        // confirms the scan-derived floor (no real `du` on the tempdir).
        let no_repo = |_: &Path| RepoProbe {
            remote: None,
            clean: None,
        };
        let sizer = |_: &Path| Some(inner_size * 2);
        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &no_repo, &sizer);

        // The standalone large file is reported.
        assert!(
            items
                .iter()
                .any(|item| item.path == big_file && !item.is_dir && item.bytes == big_file_size)
        );

        // `Documents/big` (subtree 1600 >= 1000) is reported as a folder.
        assert!(
            items
                .iter()
                .any(|item| item.path == big_dir && item.is_dir && item.bytes == inner_size * 2)
        );

        // The `Documents` user-data root itself is excluded despite being large.
        assert!(items.iter().all(|item| item.path != docs));
    }

    /// Build a scan with a single large git checkout under `~/GitHub`:
    /// `<home>/GitHub/<name>` holding a `.git` child and one large file.
    fn repo_scan(home: &Path, name: &str, file_bytes: u64) -> (PathBuf, ScanResult) {
        let gh = home.join("GitHub");
        let repo = gh.join(name);
        let git = repo.join(".git");
        let file = repo.join("payload.bin");
        let scan = scan_of(vec![
            dir_entry(&gh),
            dir_entry(&repo),
            dir_entry(&git),
            file_entry(&file, file_bytes),
        ]);
        (repo, scan)
    }

    #[test]
    fn clean_repo_with_remote_is_redownloadable() {
        let home = tempfile::tempdir().expect("home tempdir");
        let (repo, scan) = repo_scan(home.path(), "linux", 4_096);
        let probe = |_: &Path| RepoProbe {
            remote: Some("https://github.com/torvalds/linux.git".to_owned()),
            clean: Some(true),
        };
        // `du` agrees with the scan-derived floor here.
        let sizer = |_: &Path| Some(4_096u64);

        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &probe, &sizer);
        let item = items
            .iter()
            .find(|item| item.path == repo)
            .expect("repo surfaced");
        assert!(item.is_dir);
        assert!(item.redownloadable);
        assert_eq!(item.bytes, 4_096);
        assert_eq!(item.note, "git · github.com/torvalds · clean — re-clonable");
    }

    #[test]
    fn dirty_repo_with_remote_is_annotated_for_review() {
        let home = tempfile::tempdir().expect("home tempdir");
        let (repo, scan) = repo_scan(home.path(), "linux", 4_096);
        let probe = |_: &Path| RepoProbe {
            remote: Some("git@github.com:torvalds/linux.git".to_owned()),
            clean: Some(false),
        };
        let sizer = |_: &Path| Some(4_096u64);

        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &probe, &sizer);
        let item = items
            .iter()
            .find(|item| item.path == repo)
            .expect("repo surfaced");
        assert!(item.redownloadable);
        assert_eq!(
            item.note,
            "git · github.com/torvalds · has local changes — review"
        );
    }

    #[test]
    fn repo_with_unverifiable_status_is_still_suggested() {
        let home = tempfile::tempdir().expect("home tempdir");
        let (repo, scan) = repo_scan(home.path(), "chromium-src", 8_192);
        let probe = |_: &Path| RepoProbe {
            remote: Some("https://chromium.googlesource.com/chromium/src".to_owned()),
            clean: None,
        };
        let sizer = |_: &Path| Some(8_192u64);

        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &probe, &sizer);
        let item = items
            .iter()
            .find(|item| item.path == repo)
            .expect("repo surfaced");
        assert!(item.redownloadable);
        assert_eq!(
            item.note,
            "git · chromium.googlesource.com/chromium · couldn't verify changes"
        );
    }

    #[test]
    fn repo_without_remote_is_not_suggested() {
        let home = tempfile::tempdir().expect("home tempdir");
        let (repo, scan) = repo_scan(home.path(), "local-only", 4_096);
        let probe = |_: &Path| RepoProbe {
            remote: None,
            clean: Some(true),
        };
        let sizer = |_: &Path| Some(4_096u64);

        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &probe, &sizer);
        assert!(items.iter().all(|item| item.path != repo));
    }

    #[test]
    fn repo_below_large_repo_min_is_not_probed() {
        let home = tempfile::tempdir().expect("home tempdir");
        // File (100) is below the repo threshold (1000) → never a candidate.
        let (repo, scan) = repo_scan(home.path(), "tiny", 100);
        let probes = AtomicUsize::new(0);
        let probe = |_: &Path| {
            probes.fetch_add(1, Ordering::SeqCst);
            RepoProbe {
                remote: Some("https://github.com/x/y.git".to_owned()),
                clean: Some(true),
            }
        };
        let sizer = |_: &Path| Some(100u64);

        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &probe, &sizer);
        assert!(items.iter().all(|item| item.path != repo));
        assert_eq!(
            probes.load(Ordering::SeqCst),
            0,
            "no git probe under threshold"
        );
    }

    #[test]
    fn repo_inside_build_cache_component_is_not_reported() {
        let home = tempfile::tempdir().expect("home tempdir");
        // A vendored repo living under a skip component (`node_modules`).
        let nm = home.path().join("GitHub").join("app").join("node_modules");
        let repo = nm.join("dep");
        let git = repo.join(".git");
        let file = repo.join("payload.bin");
        let scan = scan_of(vec![
            dir_entry(&nm),
            dir_entry(&repo),
            dir_entry(&git),
            file_entry(&file, 8_192),
        ]);
        let probe = |_: &Path| RepoProbe {
            remote: Some("https://github.com/x/y.git".to_owned()),
            clean: Some(true),
        };
        let sizer = |_: &Path| Some(8_192u64);

        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &probe, &sizer);
        assert!(
            items.is_empty(),
            "skip-component repos are excluded from scope"
        );
    }

    #[test]
    fn summarize_remote_handles_https_scp_and_googlesource() {
        assert_eq!(
            summarize_remote("https://github.com/torvalds/linux.git"),
            "github.com/torvalds"
        );
        assert_eq!(
            summarize_remote("git@github.com:torvalds/linux.git"),
            "github.com/torvalds"
        );
        assert_eq!(
            summarize_remote("https://chromium.googlesource.com/chromium/src"),
            "chromium.googlesource.com/chromium"
        );
        assert_eq!(summarize_remote("ssh://git@example.com/"), "example.com");
    }

    #[test]
    fn du_size_overrides_scan_derived_floor() {
        let home = tempfile::tempdir().expect("home tempdir");
        // Scan floor is only 4 KiB (depth-limited); `du` reports the true 80 GiB.
        let (repo, scan) = repo_scan(home.path(), "chromium-src", 4_096);
        let probe = |_: &Path| RepoProbe {
            remote: Some("https://chromium.googlesource.com/chromium/src".to_owned()),
            clean: Some(true),
        };
        let measured: u64 = 80 * 1_073_741_824;
        let sizer = move |_: &Path| Some(measured);

        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &probe, &sizer);
        let item = items
            .iter()
            .find(|item| item.path == repo)
            .expect("repo surfaced");
        assert_eq!(item.bytes, measured, "du value replaces the scan floor");
        // A successful measurement must NOT add the approximate marker.
        assert_eq!(
            item.note,
            "git · chromium.googlesource.com/chromium · clean — re-clonable"
        );
    }

    #[test]
    fn du_failure_keeps_floor_and_marks_repo_note_approx() {
        let home = tempfile::tempdir().expect("home tempdir");
        let (repo, scan) = repo_scan(home.path(), "linux", 4_096);
        let probe = |_: &Path| RepoProbe {
            remote: Some("https://github.com/torvalds/linux.git".to_owned()),
            clean: Some(true),
        };
        let sizer = |_: &Path| None; // du failed / timed out.

        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &probe, &sizer);
        let item = items
            .iter()
            .find(|item| item.path == repo)
            .expect("repo surfaced");
        assert_eq!(item.bytes, 4_096, "floor retained on du failure");
        assert_eq!(
            item.note,
            "git · github.com/torvalds · clean — re-clonable · size approx"
        );
    }

    #[test]
    fn du_failure_marks_plain_folder_note_approx() {
        let home = tempfile::tempdir().expect("home tempdir");
        let docs = home.path().join("Documents");
        let big_dir = docs.join("big");
        let inner = big_dir.join("part.bin");
        let scan = scan_of(vec![
            dir_entry(&docs),
            dir_entry(&big_dir),
            file_entry(&inner, 2_048),
        ]);
        let no_repo = |_: &Path| RepoProbe {
            remote: None,
            clean: None,
        };
        let sizer = |_: &Path| None;

        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &no_repo, &sizer);
        let item = items
            .iter()
            .find(|item| item.path == big_dir)
            .expect("folder surfaced");
        assert!(!item.redownloadable);
        assert_eq!(item.bytes, 2_048, "floor retained on du failure");
        assert_eq!(item.note, "size approx (depth-limited)");
    }

    #[test]
    fn parse_du_kib_reads_leading_integer_in_kib() {
        assert_eq!(parse_du_kib("80\t/some/path"), Some(80 * 1024));
        assert_eq!(parse_du_kib("83886080\t/x"), Some(83_886_080 * 1024));
        assert_eq!(parse_du_kib("not-a-number\t/x"), None);
        assert_eq!(parse_du_kib(""), None);
    }

    #[test]
    fn version_manager_home_is_never_suggested() {
        let home = tempfile::tempdir().expect("home tempdir");
        // `~/.pyenv` is itself a git clone with a remote, and holds nested content.
        let pyenv = home.path().join(".pyenv");
        let pyenv_git = pyenv.join(".git");
        let pyenv_file = pyenv.join("payload.bin");
        let version_dir = pyenv.join("versions").join("3.12");
        let version_file = version_dir.join("python.bin");
        let scan = scan_of(vec![
            dir_entry(&pyenv),
            dir_entry(&pyenv_git),
            file_entry(&pyenv_file, 8_192),
            dir_entry(&version_dir),
            file_entry(&version_file, 8_192),
        ]);
        // A real remote and a generous size would otherwise make `.pyenv` a strong
        // re-clonable-repo candidate; the skip component must veto it entirely.
        let probe = |_: &Path| RepoProbe {
            remote: Some("https://github.com/pyenv/pyenv.git".to_owned()),
            clean: Some(true),
        };
        let sizer = |_: &Path| Some(8 * 1_073_741_824u64);

        let items =
            detect_large_items_with_probe(&scan, home.path(), &test_limits(), &probe, &sizer);
        assert!(
            items.is_empty(),
            "version-manager homes are excluded from every suggestion, got {items:?}"
        );
    }
}
