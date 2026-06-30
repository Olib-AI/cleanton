use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use cleanton_common::{
    CleantonError, FileEntry, FileKind, ProtectedPaths, Result, ScanError, ScanResult, Severity,
    paths::{expand_tilde, is_same_or_descendant},
};
use glob::Pattern;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::metadata::entry_from_metadata;
use crate::project::detect_project_roots_from_entries;

type GitignoreStack = Vec<ignore::gitignore::Gitignore>;

/// Per-entry state carried alongside each walked directory entry.
///
/// The `stat(2)` for every entry is performed on `jwalk`'s parallel worker
/// threads (inside `process_read_dir`) and the resulting [`FileEntry`] is stashed
/// here, so the serial consumer loop never blocks on a syscall. Previously the
/// consumer called `dir_entry.metadata()` itself, serialising hundreds of
/// thousands of `stat` calls onto one thread while the worker pool sat parked.
#[derive(Debug, Clone, Default)]
struct EntryState {
    /// Result of evaluating gitignore rules against this entry (advisory signal).
    ignored: bool,
    /// The fully extracted entry, built on a worker thread. `None` only when the
    /// metadata read failed (see `error`).
    entry: Option<FileEntry>,
    /// A metadata-read failure, captured on the worker thread for the consumer to
    /// record: the IO error kind (for incomplete-scan detection) and message.
    error: Option<(Option<std::io::ErrorKind>, String)>,
}

type WalkClientState = (GitignoreStack, EntryState);
type ScanDirEntry = jwalk::DirEntry<WalkClientState>;
type WalkItem = jwalk::Result<ScanDirEntry>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOptions {
    pub roots: Vec<PathBuf>,
    pub max_depth: usize,
    pub follow_symlinks: bool,
    pub respect_gitignore: bool,
    pub exclude_patterns: Vec<String>,
    pub exclude_cloud_roots: bool,
    pub exclude_external_volumes: bool,
    pub protected_paths: Vec<PathBuf>,
    pub parallel_threads: usize,
    /// Traverse and emit hidden (dot-prefixed) files and directories.
    ///
    /// A disk cleaner must scan hidden locations — that is where caches live
    /// (`~/.cargo`, `~/.cache`, `.venv`, `~/.npm`, ...). Defaults to `true`.
    /// When `false`, jwalk's `skip_hidden` is enabled and dot-entries are pruned.
    pub include_hidden: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            roots: vec![PathBuf::from("~")],
            max_depth: 20,
            follow_symlinks: false,
            respect_gitignore: true,
            exclude_patterns: Vec::new(),
            exclude_cloud_roots: true,
            exclude_external_volumes: true,
            protected_paths: Vec::new(),
            parallel_threads: 0,
            include_hidden: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanProgress {
    pub files_scanned: u64,
    pub dirs_entered: u64,
    pub bytes_seen: u64,
}

pub async fn scan(
    options: ScanOptions,
    progress_tx: mpsc::Sender<ScanProgress>,
) -> Result<ScanResult> {
    tokio::task::spawn_blocking(move || scan_blocking(&options, &progress_tx))
        .await
        .map_err(|err| CleantonError::Scan(format!("scanner task failed: {err}")))?
}

fn load_gitignore(dir: &Path) -> Option<ignore::gitignore::Gitignore> {
    let gitignore_path = dir.join(".gitignore");
    if gitignore_path.is_file() {
        let mut builder = ignore::gitignore::GitignoreBuilder::new(dir);
        let _ = builder.add(&gitignore_path);
        builder.build().ok()
    } else {
        None
    }
}

fn initial_gitignore_stack(root: &Path, respect_gitignore: bool) -> GitignoreStack {
    let mut stack = Vec::new();
    if !respect_gitignore {
        return stack;
    }

    let mut ancestors = Vec::new();
    let mut curr = root;
    while let Some(parent) = curr.parent() {
        ancestors.push(parent.to_path_buf());
        curr = parent;
    }
    ancestors.reverse();

    for ancestor in ancestors {
        if let Some(gi) = load_gitignore(&ancestor) {
            stack.push(gi);
        }
    }

    if let Some(gi) = load_gitignore(root) {
        stack.push(gi);
    }

    stack
}

/// Expensive check that also walks every parent component of `path` through the
/// regex matchers. Call this at most once per directory (for the directory
/// itself), never once per child — `matched_path_or_any_parents` is O(depth)
/// regex work and dominates large scans when run on every entry.
fn dir_ignored(stack: &[ignore::gitignore::Gitignore], path: &Path) -> bool {
    for gitignore in stack.iter().rev() {
        // `matched_path_or_any_parents` asserts that `path` is under the
        // matcher's root. Firmlink aliases (`/var` vs `/private/var`) and the
        // synthetic walk root can leave a stack entry whose root is not a prefix
        // of `path`; skip those rather than panic — they cannot match anyway.
        if path.strip_prefix(gitignore.path()).is_err() {
            continue;
        }
        match gitignore.matched_path_or_any_parents(path, true) {
            ignore::Match::Ignore(_) => return true,
            ignore::Match::Whitelist(_) => return false,
            ignore::Match::None => {}
        }
    }
    false
}

/// Cheap per-child check: matches only `child_path` itself (single level, no
/// parent walk) against the stack, falling back to the parent directory's
/// already-computed ignored state. Equivalent to `matched_path_or_any_parents`
/// on the child — the child's ancestors are exactly the parent directory and
/// above, which `parent_ignored` already accounts for — but without re-walking
/// those ancestors through the regex engine for every entry.
fn child_ignored(
    stack: &[ignore::gitignore::Gitignore],
    parent_ignored: bool,
    child_path: &Path,
    is_dir: bool,
) -> bool {
    for gitignore in stack.iter().rev() {
        match gitignore.matched(child_path, is_dir) {
            ignore::Match::Ignore(_) => return true,
            ignore::Match::Whitelist(_) => return false,
            ignore::Match::None => {}
        }
    }
    parent_ignored
}

struct ReadDirContext {
    root: PathBuf,
    options: ScanOptions,
    protected: ProtectedPaths,
    excluded_roots: Vec<PathBuf>,
    excludes: Vec<Pattern>,
    respect_gitignore: bool,
}

fn scan_blocking(
    options: &ScanOptions,
    progress_tx: &mpsc::Sender<ScanProgress>,
) -> Result<ScanResult> {
    let started = Instant::now();
    let excludes = compile_excludes(&options.exclude_patterns)?;
    let mut result = ScanResult {
        entries: Vec::new(),
        project_roots: Vec::new(),
        total_files: 0,
        total_dirs: 0,
        logical_bytes: 0,
        allocated_bytes: 0,
        duration: Duration::ZERO,
        errors: Vec::new(),
        incomplete: false,
    };

    for root in &options.roots {
        scan_root(root, options, &excludes, progress_tx, &mut result);
    }

    aggregate_directory_sizes(&mut result);
    result.project_roots = detect_project_roots_from_entries(&result.entries);
    result.duration = started.elapsed();
    Ok(result)
}

fn scan_root(
    root: &Path,
    options: &ScanOptions,
    excludes: &[Pattern],
    progress_tx: &mpsc::Sender<ScanProgress>,
    result: &mut ScanResult,
) {
    let root = expand_tilde(root);
    if let Err(source) = fs::symlink_metadata(&root) {
        result.incomplete = true;
        result.errors.push(ScanError {
            path: root,
            severity: Severity::Error,
            message: format!("scan root is not accessible: {source}"),
        });
        return;
    }

    let protected = ProtectedPaths::new(options.protected_paths.clone());
    let excluded_roots = excluded_roots(options);
    let respect_gitignore = options.respect_gitignore;
    let read_dir_context = ReadDirContext {
        root: root.clone(),
        options: options.clone(),
        protected: protected.clone(),
        excluded_roots: excluded_roots.clone(),
        excludes: excludes.to_vec(),
        respect_gitignore,
    };

    let walker = jwalk::WalkDirGeneric::<WalkClientState>::new(&root)
        .max_depth(options.max_depth)
        .follow_links(options.follow_symlinks)
        .skip_hidden(!options.include_hidden)
        .parallelism(scan_parallelism(options))
        .root_read_dir_state(initial_gitignore_stack(&root, respect_gitignore))
        .process_read_dir(move |depth, path, read_dir_state, children| {
            process_scan_dir(depth, path, read_dir_state, children, &read_dir_context);
        });

    for item in walker {
        process_walk_item(item, progress_tx, result);
    }
}

fn scan_parallelism(options: &ScanOptions) -> jwalk::Parallelism {
    if options.parallel_threads == 0 {
        jwalk::Parallelism::RayonDefaultPool {
            busy_timeout: Duration::from_secs(1),
        }
    } else {
        jwalk::Parallelism::RayonNewPool(options.parallel_threads)
    }
}

fn process_scan_dir(
    depth: Option<usize>,
    path: &Path,
    read_dir_state: &mut GitignoreStack,
    children: &mut Vec<WalkItem>,
    context: &ReadDirContext,
) {
    if context.respect_gitignore
        && depth.unwrap_or(0) > 0
        && let Some(gi) = load_gitignore(path)
    {
        read_dir_state.push(gi);
    }

    // Resolve the directory's own ignored state once (the O(depth) parent walk),
    // then reuse it for every child via the cheap single-level check. Without
    // this, every entry re-walked all of its ancestors through the regex engine.
    let parent_ignored = context.respect_gitignore && dir_ignored(read_dir_state, path);

    for child in children.iter_mut().flatten() {
        let child_path = child.path();
        let is_dir = child.file_type.is_dir();
        child.client_state.ignored = context.respect_gitignore
            && child_ignored(read_dir_state, parent_ignored, &child_path, is_dir);
    }

    children.retain(|child_result| match child_result {
        Ok(child) => {
            let child_path = child.path();
            // Pruning (protected roots + cloud/volume/excluded roots) only matters
            // for directories — descending is what we avoid. File leaves are just
            // recorded, and the matcher/executor re-check protection before any
            // cleanup. Restricting the expensive path normalization to directories
            // (a small fraction of entries) keeps large scans fast.
            let prune = child.file_type.is_dir()
                && should_skip_path(
                    &child_path,
                    &context.root,
                    &context.options,
                    &context.protected,
                    &context.excluded_roots,
                );
            let skip = prune || matches_exclude_pattern(&child_path, &context.excludes);
            !skip
        }
        Err(_) => true,
    });

    // Read metadata here, on the worker thread, for the entries that survived
    // pruning — keeping every `stat(2)` off the single-threaded consumer loop.
    for child in children.iter_mut().flatten() {
        populate_entry_state(child);
    }
}

/// Extract an entry's metadata on the current (worker) thread and stash the
/// resulting [`FileEntry`] — or the failure — in its client state.
fn populate_entry_state(child: &mut ScanDirEntry) {
    let path = child.path();
    let depth = child.depth();
    match child.metadata() {
        Ok(metadata) => {
            let mut entry = entry_from_metadata(&path, &metadata, depth);
            entry.ignored_by_git = child.client_state.ignored;
            child.client_state.entry = Some(entry);
        }
        Err(source) => {
            let kind = source.io_error().map(std::io::Error::kind);
            let message = if kind == Some(std::io::ErrorKind::PermissionDenied) {
                "permission denied".to_owned()
            } else {
                source.to_string()
            };
            child.client_state.error = Some((kind, message));
        }
    }
}

fn process_walk_item(
    item: WalkItem,
    progress_tx: &mpsc::Sender<ScanProgress>,
    result: &mut ScanResult,
) {
    match item {
        Ok(dir_entry) => process_dir_entry(dir_entry, progress_tx, result),
        Err(err) => push_walk_error(&err, result),
    }
}

fn process_dir_entry(
    mut dir_entry: ScanDirEntry,
    progress_tx: &mpsc::Sender<ScanProgress>,
    result: &mut ScanResult,
) {
    // Metadata was already extracted on a worker thread in `populate_entry_state`;
    // the consumer just folds the prebuilt entry into the running totals.
    if let Some(entry) = dir_entry.client_state.entry.take() {
        match entry.kind {
            FileKind::File => result.total_files += 1,
            FileKind::Directory => result.total_dirs += 1,
            FileKind::Symlink | FileKind::Other => {}
        }
        result.logical_bytes = result.logical_bytes.saturating_add(entry.logical_bytes);
        result.allocated_bytes = result.allocated_bytes.saturating_add(entry.allocated_bytes);
        result.entries.push(entry);

        send_progress_if_due(progress_tx, result);
    } else if let Some((kind, message)) = dir_entry.client_state.error.take() {
        push_scan_error_message(&dir_entry.path(), kind, message, result);
    }
}

fn send_progress_if_due(progress_tx: &mpsc::Sender<ScanProgress>, result: &ScanResult) {
    if result.entries.len().is_multiple_of(1_000) {
        let _ = progress_tx.try_send(ScanProgress {
            files_scanned: result.total_files,
            dirs_entered: result.total_dirs,
            bytes_seen: result.allocated_bytes,
        });
    }
}

fn push_walk_error(source: &jwalk::Error, result: &mut ScanResult) {
    if let Some(path) = source.path() {
        push_scan_error(path, source, result);
    }
}

fn push_scan_error(path: &Path, source: &jwalk::Error, result: &mut ScanResult) {
    let error_kind = source.io_error().map(std::io::Error::kind);
    let message = if error_kind == Some(std::io::ErrorKind::PermissionDenied) {
        "permission denied".to_owned()
    } else {
        source.to_string()
    };
    push_scan_error_message(path, error_kind, message, result);
}

fn push_scan_error_message(
    path: &Path,
    error_kind: Option<std::io::ErrorKind>,
    message: String,
    result: &mut ScanResult,
) {
    let is_permission_denied =
        error_kind.is_some_and(|kind| kind == std::io::ErrorKind::PermissionDenied);
    if is_permission_denied {
        result.incomplete = true;
    }

    result.errors.push(ScanError {
        path: path.to_path_buf(),
        severity: Severity::Warning,
        message,
    });
}

fn compile_excludes(patterns: &[String]) -> Result<Vec<Pattern>> {
    patterns
        .iter()
        .map(|pattern| {
            Pattern::new(pattern).map_err(|err| {
                CleantonError::Config(format!("invalid exclude pattern {pattern:?}: {err}"))
            })
        })
        .collect()
}

fn matches_exclude_pattern(path: &Path, patterns: &[Pattern]) -> bool {
    patterns.iter().any(|pattern| {
        pattern.matches_path(path)
            || path
                .file_name()
                .is_some_and(|name| pattern.matches(&name.to_string_lossy()))
    })
}

fn should_skip_path(
    path: &Path,
    scan_root: &Path,
    options: &ScanOptions,
    protected: &ProtectedPaths,
    excluded_roots: &[PathBuf],
) -> bool {
    if path == scan_root {
        return false;
    }

    // Bulk hot path: `is_protected_fast` does no filesystem syscalls (entries are
    // already real walked paths), so pruning stays cheap across huge trees.
    if protected.is_protected_fast(path) && !protected.is_protected_fast(scan_root) {
        return true;
    }

    if excluded_roots.iter().any(|excluded| {
        is_same_or_descendant(path, excluded) && !is_same_or_descendant(scan_root, excluded)
    }) {
        return true;
    }

    options.exclude_external_volumes
        && is_same_or_descendant(path, Path::new("/Volumes"))
        && !is_same_or_descendant(scan_root, Path::new("/Volumes"))
}

fn excluded_roots(options: &ScanOptions) -> Vec<PathBuf> {
    if !options.exclude_cloud_roots {
        return Vec::new();
    }

    [
        "~/Library/Mobile Documents",
        "~/Library/CloudStorage",
        "~/Dropbox",
        "~/Google Drive",
        "~/OneDrive",
        "~/Box",
    ]
    .into_iter()
    .map(PathBuf::from)
    .map(|path| expand_tilde(&path))
    .collect()
}

fn aggregate_directory_sizes(result: &mut ScanResult) {
    let dir_paths = result
        .entries
        .iter()
        .filter(|entry| entry.kind == FileKind::Directory)
        .map(|entry| entry.path.clone())
        .collect::<HashSet<_>>();

    let mut totals = dir_paths
        .iter()
        .map(|path| (path.clone(), (0_u64, 0_u64)))
        .collect::<HashMap<_, _>>();

    let mut inode_seen = HashSet::<(u64, u64)>::new();

    // 1. De-duplicate entry sizes for hardlinked inodes first
    for entry in &mut result.entries {
        if entry.kind != FileKind::File {
            continue;
        }
        if let (Some(device), Some(inode)) = (entry.device_id, entry.inode)
            && !inode_seen.insert((device, inode))
        {
            entry.logical_bytes = 0;
            entry.allocated_bytes = 0;
        }
    }

    // 2. Accumulate sizes into parent directories
    for entry in &result.entries {
        if entry.kind != FileKind::File {
            continue;
        }

        for ancestor in ancestors(&entry.path) {
            if let Some((logical, allocated)) = totals.get_mut(ancestor) {
                *logical = logical.saturating_add(entry.logical_bytes);
                *allocated = allocated.saturating_add(entry.allocated_bytes);
            }
        }
    }

    // 3. Update directory entries with their subtree sizes
    for entry in &mut result.entries {
        if let Some((logical, allocated)) = totals.get(&entry.path).copied() {
            entry.logical_bytes = logical;
            entry.allocated_bytes = allocated;
        }
    }

    // 4. Calculate total scan results sizes
    result.logical_bytes = result
        .entries
        .iter()
        .filter(|entry| entry.kind == FileKind::File)
        .map(|entry| entry.logical_bytes)
        .sum();
    result.allocated_bytes = result
        .entries
        .iter()
        .filter(|entry| entry.kind == FileKind::File)
        .map(|entry| entry.allocated_bytes)
        .sum();
}

fn ancestors(path: &Path) -> impl Iterator<Item = &Path> {
    path.ancestors().skip(1)
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing into expected results clearer.
    #![allow(clippy::indexing_slicing)]
    use std::fs;

    use tokio::sync::mpsc;

    use super::*;

    fn empty_scan_result() -> ScanResult {
        ScanResult {
            entries: Vec::new(),
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

    #[tokio::test]
    async fn directory_entries_report_subtree_size() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target");
        fs::create_dir(&target).expect("create target");
        fs::write(target.join("artifact.bin"), [1_u8; 8192]).expect("write artifact");

        let (progress_tx, _progress_rx) = mpsc::channel(1);
        let result = scan(
            ScanOptions {
                roots: vec![temp.path().to_path_buf()],
                max_depth: 10,
                ..ScanOptions::default()
            },
            progress_tx,
        )
        .await
        .expect("scan");

        let target_entry = result
            .entries
            .iter()
            .find(|entry| entry.path == target)
            .expect("target entry");
        assert_eq!(target_entry.logical_bytes, 8192);
        assert!(target_entry.allocated_bytes >= 8192);
    }

    #[tokio::test]
    async fn scan_result_includes_detected_project_roots() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("Cargo.toml"), "[package]\nname=\"test\"")
            .expect("write cargo.toml");
        let target = temp.path().join("target");
        fs::create_dir(&target).expect("create target");
        fs::write(target.join("artifact.bin"), [1_u8; 100]).expect("write artifact");

        let (progress_tx, _progress_rx) = mpsc::channel(1);
        let result = scan(
            ScanOptions {
                roots: vec![temp.path().to_path_buf()],
                max_depth: 10,
                ..ScanOptions::default()
            },
            progress_tx,
        )
        .await
        .expect("scan");

        assert_eq!(result.project_roots.len(), 1);
        let project = &result.project_roots[0];
        assert_eq!(project.path, temp.path());
        assert_eq!(project.ecosystem, cleanton_common::Ecosystem::Rust);
        assert_eq!(project.artifact_dirs, vec![target]);
        assert_eq!(project.artifact_size, 100);
    }

    #[tokio::test]
    async fn exclude_patterns_prune_directory_subtrees() {
        let temp = tempfile::tempdir().expect("tempdir");
        let skipped = temp.path().join(".Trash");
        fs::create_dir(&skipped).expect("create skipped");
        fs::write(skipped.join("large.bin"), [1_u8; 8192]).expect("write skipped");
        fs::write(temp.path().join("kept.bin"), [1_u8; 128]).expect("write kept");

        let (progress_tx, _progress_rx) = mpsc::channel(1);
        let result = scan(
            ScanOptions {
                roots: vec![temp.path().to_path_buf()],
                max_depth: 10,
                exclude_patterns: vec![".Trash".to_owned()],
                ..ScanOptions::default()
            },
            progress_tx,
        )
        .await
        .expect("scan");

        assert!(
            result
                .entries
                .iter()
                .all(|entry| !entry.path.starts_with(&skipped))
        );
        assert!(
            result
                .entries
                .iter()
                .any(|entry| entry.path == temp.path().join("kept.bin"))
        );
    }

    #[test]
    fn protected_roots_are_skipped_when_not_scan_root() {
        let protected = ProtectedPaths::new([PathBuf::from("/Users/example/Documents")]);
        let options = ScanOptions::default();

        assert!(should_skip_path(
            Path::new("/Users/example/Documents/cache"),
            Path::new("/Users/example"),
            &options,
            &protected,
            &[],
        ));
        assert!(!should_skip_path(
            Path::new("/Users/example/Documents/cache"),
            Path::new("/Users/example/Documents"),
            &options,
            &protected,
            &[],
        ));
        assert!(!should_skip_path(
            Path::new("/Users/example/project/target"),
            Path::new("/Users/example"),
            &options,
            &protected,
            &[],
        ));
    }

    #[test]
    fn configured_cloud_roots_are_excluded_by_default() {
        let options = ScanOptions::default();
        let protected = ProtectedPaths::new([]);
        let roots = excluded_roots(&options);

        for root in [
            "~/Library/Mobile Documents",
            "~/Library/CloudStorage",
            "~/Dropbox",
            "~/Google Drive",
            "~/OneDrive",
            "~/Box",
        ] {
            let cloud_root = expand_tilde(Path::new(root));
            assert!(roots.contains(&cloud_root), "{cloud_root:?}");
            assert!(should_skip_path(
                &cloud_root.join("cache.bin"),
                &expand_tilde(Path::new("~")),
                &options,
                &protected,
                &roots,
            ));
        }
    }

    #[tokio::test]
    async fn configured_protected_paths_are_pruned_from_scan() {
        let temp = tempfile::Builder::new()
            .prefix("cleanton-scanner-")
            .tempdir_in(std::env::current_dir().expect("current dir"))
            .expect("tempdir");
        let protected = temp.path().join("protected");
        let kept = temp.path().join("kept");
        fs::create_dir(&protected).expect("create protected");
        fs::create_dir(&kept).expect("create kept");
        fs::write(protected.join("secret-cache.bin"), [1_u8; 4096]).expect("write protected");
        fs::write(kept.join("cache.bin"), [1_u8; 128]).expect("write kept");

        let (progress_tx, _progress_rx) = mpsc::channel(1);
        let result = scan(
            ScanOptions {
                roots: vec![temp.path().to_path_buf()],
                max_depth: 10,
                protected_paths: vec![protected.clone()],
                ..ScanOptions::default()
            },
            progress_tx,
        )
        .await
        .expect("scan");

        assert!(
            result
                .entries
                .iter()
                .all(|entry| !entry.path.starts_with(&protected))
        );
        assert!(
            result
                .entries
                .iter()
                .any(|entry| entry.path == kept.join("cache.bin"))
        );
    }

    #[tokio::test]
    async fn inaccessible_roots_are_reported_as_incomplete_scan_errors() {
        let missing_root = PathBuf::from("definitely-missing-cleanton-scan-root");
        let (progress_tx, _progress_rx) = mpsc::channel(1);
        let result = scan(
            ScanOptions {
                roots: vec![missing_root.clone()],
                ..ScanOptions::default()
            },
            progress_tx,
        )
        .await
        .expect("scan");

        assert!(result.incomplete);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].path, missing_root);
        assert_eq!(result.errors[0].severity, Severity::Error);
        assert!(
            result.errors[0]
                .message
                .contains("scan root is not accessible")
        );
        assert!(result.entries.is_empty());
    }

    #[tokio::test]
    async fn hardlinked_files_are_counted_once() {
        let temp = tempfile::tempdir().expect("tempdir");
        let original = temp.path().join("artifact-a.bin");
        let hardlink = temp.path().join("artifact-b.bin");
        fs::write(&original, [7_u8; 8192]).expect("write original");
        fs::hard_link(&original, &hardlink).expect("create hardlink");

        let (progress_tx, _progress_rx) = mpsc::channel(1);
        let result = scan(
            ScanOptions {
                roots: vec![temp.path().to_path_buf()],
                max_depth: 2,
                ..ScanOptions::default()
            },
            progress_tx,
        )
        .await
        .expect("scan");

        let linked_entries = result
            .entries
            .iter()
            .filter(|entry| entry.path == original || entry.path == hardlink)
            .collect::<Vec<_>>();
        assert_eq!(linked_entries.len(), 2);
        assert_eq!(
            linked_entries
                .iter()
                .filter(|entry| entry.allocated_bytes > 0)
                .count(),
            1
        );
        assert_eq!(result.logical_bytes, 8192);
    }

    #[test]
    fn cloud_root_exclusion_can_be_disabled() {
        let options = ScanOptions {
            exclude_cloud_roots: false,
            ..ScanOptions::default()
        };
        let protected = ProtectedPaths::new([]);
        let roots = excluded_roots(&options);
        let cloud_file = expand_tilde(Path::new("~/Dropbox/cache.bin"));

        assert!(roots.is_empty());
        assert!(!should_skip_path(
            &cloud_file,
            &expand_tilde(Path::new("~")),
            &options,
            &protected,
            &roots,
        ));
    }

    #[test]
    fn configured_cloud_roots_allow_explicit_root_opt_in() {
        let options = ScanOptions::default();
        let protected = ProtectedPaths::new([]);
        let roots = excluded_roots(&options);
        let cloud_root = expand_tilde(Path::new("~/Library/CloudStorage"));
        let nested_root = cloud_root.join("Provider");

        assert!(!should_skip_path(
            &cloud_root.join("cache.bin"),
            &cloud_root,
            &options,
            &protected,
            &roots,
        ));
        assert!(!should_skip_path(
            &nested_root.join("cache.bin"),
            &nested_root,
            &options,
            &protected,
            &roots,
        ));
    }

    #[test]
    fn external_volumes_are_excluded_unless_scan_root_opts_in() {
        let options = ScanOptions::default();
        let protected = ProtectedPaths::new([]);
        let roots = Vec::new();
        let external_root = Path::new("/Volumes/Backup");
        let external_file = external_root.join("cache.bin");

        assert!(should_skip_path(
            &external_file,
            Path::new("/Users/example"),
            &options,
            &protected,
            &roots,
        ));
        assert!(!should_skip_path(
            &external_file,
            external_root,
            &options,
            &protected,
            &roots,
        ));
        assert!(!should_skip_path(
            &external_root.join("Project/cache.bin"),
            &external_root.join("Project"),
            &options,
            &protected,
            &roots,
        ));
    }

    #[test]
    fn external_volume_exclusion_can_be_disabled() {
        let options = ScanOptions {
            exclude_external_volumes: false,
            ..ScanOptions::default()
        };
        let protected = ProtectedPaths::new([]);

        assert!(!should_skip_path(
            Path::new("/Volumes/Backup/cache.bin"),
            Path::new("/Users/example"),
            &options,
            &protected,
            &[],
        ));
    }

    #[test]
    fn permission_denied_errors_mark_scan_incomplete() {
        let mut result = empty_scan_result();
        let unreadable = Path::new("/Users/example/Library/Mail");

        push_scan_error_message(
            unreadable,
            Some(std::io::ErrorKind::PermissionDenied),
            "permission denied".to_owned(),
            &mut result,
        );

        assert!(result.incomplete);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].path, unreadable);
        assert_eq!(result.errors[0].message, "permission denied");
    }

    #[tokio::test]
    async fn respects_gitignore_as_signal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let gitignore_path = temp.path().join(".gitignore");
        fs::write(&gitignore_path, "*.log\nignored_dir/").expect("write gitignore");

        let ignored_dir = temp.path().join("ignored_dir");
        fs::create_dir(&ignored_dir).expect("create ignored_dir");
        fs::write(ignored_dir.join("should_be_ignored.txt"), "content").expect("write file");

        fs::write(temp.path().join("debug.log"), "log").expect("write debug.log");
        fs::write(temp.path().join("kept.txt"), "kept").expect("write kept.txt");

        let (progress_tx, _progress_rx) = mpsc::channel(1);
        let result = scan(
            ScanOptions {
                roots: vec![temp.path().to_path_buf()],
                max_depth: 10,
                respect_gitignore: true,
                ..ScanOptions::default()
            },
            progress_tx,
        )
        .await
        .expect("scan");

        let debug_log_entry = result
            .entries
            .iter()
            .find(|entry| entry.path.file_name().unwrap() == "debug.log")
            .expect("debug.log entry");
        assert!(debug_log_entry.ignored_by_git);

        let kept_txt_entry = result
            .entries
            .iter()
            .find(|entry| entry.path.file_name().unwrap() == "kept.txt")
            .expect("kept.txt entry");
        assert!(!kept_txt_entry.ignored_by_git);

        let ignored_file_entry = result
            .entries
            .iter()
            .find(|entry| entry.path.file_name().unwrap() == "should_be_ignored.txt")
            .expect("should_be_ignored.txt entry");
        assert!(ignored_file_entry.ignored_by_git);
    }
}
