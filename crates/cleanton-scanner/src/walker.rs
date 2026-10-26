use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use cleanton_common::{
    CleantonError, FileEntry, FileKind, ProtectedPaths, Result, ScanError, ScanResult, Severity,
    paths::expand_tilde,
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
    tokio::task::spawn_blocking(move || scan_blocking(&options, &progress_tx, None))
        .await
        .map_err(|err| CleantonError::Scan(format!("scanner task failed: {err}")))?
}

/// Like [`scan`], but stops walking promptly once `cancel` is set. A cancelled
/// scan returns the entries gathered so far with `incomplete = true`, so the
/// analyzer will surface it but the executor will refuse to act on it.
pub async fn scan_with_cancel(
    options: ScanOptions,
    progress_tx: mpsc::Sender<ScanProgress>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<ScanResult> {
    tokio::task::spawn_blocking(move || scan_blocking(&options, &progress_tx, Some(&cancel)))
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

#[derive(Clone)]
struct CompiledExclude {
    pattern: Pattern,
    basename_only: bool,
}

struct ReadDirContext {
    root: PathBuf,
    protected: ProtectedPaths,
    protected_scan_root: bool,
    user_data_roots: ProtectedPaths,
    active_excluded_roots: ProtectedPaths,
    active_external_roots: ProtectedPaths,
    excludes: Vec<CompiledExclude>,
    respect_gitignore: bool,
}

impl ReadDirContext {
    fn new(
        root: PathBuf,
        options: &ScanOptions,
        protected: ProtectedPaths,
        excluded_roots: &[PathBuf],
        excludes: &[CompiledExclude],
    ) -> Self {
        let protected_scan_root = protected.is_protected_fast(&root);
        let user_data_roots = ProtectedPaths::configured_only(home_user_data_roots());

        let active_excluded = excluded_roots
            .iter()
            .filter(|excluded| {
                !ProtectedPaths::configured_only([(*excluded).clone()]).is_protected_fast(&root)
            })
            .cloned()
            .collect::<Vec<_>>();
        let active_excluded_roots = ProtectedPaths::configured_only(active_excluded);

        let active_external = if options.exclude_external_volumes {
            external_volume_roots()
                .into_iter()
                .filter(|ext| {
                    !ProtectedPaths::configured_only([ext.clone()]).is_protected_fast(&root)
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let active_external_roots = ProtectedPaths::configured_only(active_external);

        Self {
            root,
            protected,
            protected_scan_root,
            user_data_roots,
            active_excluded_roots,
            active_external_roots,
            excludes: excludes.to_vec(),
            respect_gitignore: options.respect_gitignore,
        }
    }

    #[inline]
    fn should_prune_dir(&self, path: &Path) -> bool {
        if path == self.root {
            return false;
        }
        if !self.protected_scan_root
            && self.protected.is_protected_fast(path)
            && !self.user_data_roots.is_protected_fast(path)
        {
            return true;
        }
        if self.active_excluded_roots.is_protected_fast(path) {
            return true;
        }
        self.active_external_roots.is_protected_fast(path)
    }
}

fn scan_blocking(
    options: &ScanOptions,
    progress_tx: &mpsc::Sender<ScanProgress>,
    cancel: Option<&std::sync::atomic::AtomicBool>,
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
        scan_root(root, options, &excludes, progress_tx, &mut result, cancel);
        if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
            break;
        }
    }

    aggregate_directory_sizes(&mut result);
    result.project_roots = detect_project_roots_from_entries(&result.entries);
    result.duration = started.elapsed();
    Ok(result)
}

fn scan_root(
    root: &Path,
    options: &ScanOptions,
    excludes: &[CompiledExclude],
    progress_tx: &mpsc::Sender<ScanProgress>,
    result: &mut ScanResult,
    cancel: Option<&std::sync::atomic::AtomicBool>,
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
    let read_dir_context =
        ReadDirContext::new(root.clone(), options, protected, &excluded_roots, excludes);

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
        // Cancellation check on the consumer loop: dropping the jwalk iterator
        // stops the worker pool. A cancelled scan is marked incomplete so the
        // executor refuses to act on the partial inventory.
        if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
            result.incomplete = true;
            result.errors.push(ScanError {
                path: root.clone(),
                severity: Severity::Warning,
                message: "scan cancelled by user".to_owned(),
            });
            return;
        }
        process_walk_item(item, progress_tx, result);
    }
}

/// Worker-pool sizing.
///
/// `parallel_threads == 0` means "automatic". Automatic is deliberately NOT
/// "one worker per core": a scanning tool that saturates every core makes the
/// machine unpleasant to use while it runs, and every in-flight worker also
/// holds its own read-dir batch, so the memory high-water mark grows with the
/// pool size. Half the cores, clamped to 2..=8, keeps a full home scan fast
/// while leaving headroom for the rest of the machine. An explicit
/// `parallel_threads` value from the config is honoured exactly.
fn scan_parallelism(options: &ScanOptions) -> jwalk::Parallelism {
    if options.parallel_threads == 0 {
        let cores = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
        let workers = (cores / 2).clamp(2, 8).min(cores.max(1));
        return jwalk::Parallelism::RayonNewPool(workers);
    }
    jwalk::Parallelism::RayonNewPool(options.parallel_threads)
}

fn process_scan_dir(
    depth: Option<usize>,
    path: &Path,
    read_dir_state: &mut GitignoreStack,
    children: &mut Vec<WalkItem>,
    context: &ReadDirContext,
) {
    // Never descend into `.git` internals: object stores are huge, no recipe
    // may ever target them (deleting inside a repository would corrupt it),
    // and project detection only needs the `.git` entry itself — which the
    // parent directory's pass has already yielded by the time we get here.
    if path.file_name().and_then(|name| name.to_str()) == Some(".git") {
        children.clear();
        return;
    }

    // Check already-listed children for `.gitignore` in memory before touching
    // disk, eliminating hundreds of thousands of `stat(".gitignore")` syscalls.
    let has_local_gitignore = context.respect_gitignore
        && depth.unwrap_or(0) > 0
        && children
            .iter()
            .flatten()
            .any(|child| child.file_name == ".gitignore");
    if has_local_gitignore && let Some(gi) = load_gitignore(path) {
        read_dir_state.push(gi);
    }

    // Prune excluded/protected subtrees FIRST so we never allocate paths,
    // evaluate gitignore regexes, or stat children we are about to drop.
    let has_path_excludes = context.excludes.iter().any(|item| !item.basename_only);
    if !context.excludes.is_empty() || children.iter().flatten().any(|c| c.file_type.is_dir()) {
        children.retain(|child_result| match child_result {
            Ok(child) => {
                if matches_basename_exclude(&child.file_name, &context.excludes) {
                    return false;
                }
                let is_dir = child.file_type.is_dir();
                if !is_dir && !has_path_excludes {
                    return true;
                }
                let child_path = child.path();
                if is_dir && context.should_prune_dir(&child_path) {
                    return false;
                }
                !has_path_excludes || !matches_path_exclude(&child_path, &context.excludes)
            }
            Err(_) => true,
        });
    }

    // Resolve the directory's own ignored state once, then short-circuit
    // per-child regex matching whenever either:
    // - the stack is empty (nothing is ignored), or
    // - the parent directory is already ignored and no `.gitignore` on the
    //   stack contains whitelist (`!pattern`) rules (e.g. inside `node_modules`
    //   or `target`, every descendant is guaranteed ignored without regex runs).
    if context.respect_gitignore && !read_dir_state.is_empty() {
        let parent_ignored = dir_ignored(read_dir_state, path);
        let any_whitelists = read_dir_state.iter().any(|gi| gi.num_whitelists() > 0);
        if parent_ignored && !any_whitelists {
            for child in children.iter_mut().flatten() {
                child.client_state.ignored = true;
            }
        } else {
            for child in children.iter_mut().flatten() {
                let child_path = child.path();
                let is_dir = child.file_type.is_dir();
                child.client_state.ignored =
                    child_ignored(read_dir_state, parent_ignored, &child_path, is_dir);
            }
        }
    }

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

fn compile_excludes(patterns: &[String]) -> Result<Vec<CompiledExclude>> {
    patterns
        .iter()
        .map(|pattern| {
            let compiled = Pattern::new(pattern).map_err(|err| {
                CleantonError::Config(format!("invalid exclude pattern {pattern:?}: {err}"))
            })?;
            let basename_only = !pattern.contains('/') && !pattern.contains('\\');
            Ok(CompiledExclude {
                pattern: compiled,
                basename_only,
            })
        })
        .collect()
}

fn matches_basename_exclude(name: &std::ffi::OsStr, excludes: &[CompiledExclude]) -> bool {
    if excludes.is_empty() {
        return false;
    }
    let lossy = name.to_string_lossy();
    excludes
        .iter()
        .any(|item| item.pattern.matches(lossy.as_ref()))
}

fn matches_path_exclude(path: &Path, excludes: &[CompiledExclude]) -> bool {
    excludes
        .iter()
        .filter(|item| !item.basename_only)
        .any(|item| item.pattern.matches_path(path))
}

#[cfg_attr(not(test), allow(dead_code))]
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

    if protected.is_protected_fast(path)
        && !protected.is_protected_fast(scan_root)
        && !cleanton_common::is_user_data_content_path(path)
    {
        return true;
    }

    if !excluded_roots.is_empty() {
        let excluded_set = ProtectedPaths::configured_only(
            excluded_roots
                .iter()
                .filter(|excluded| {
                    !ProtectedPaths::configured_only([(*excluded).clone()])
                        .is_protected_fast(scan_root)
                })
                .cloned(),
        );
        if excluded_set.is_protected_fast(path) {
            return true;
        }
    }

    if options.exclude_external_volumes {
        let ext_set =
            ProtectedPaths::configured_only(external_volume_roots().into_iter().filter(|ext| {
                !ProtectedPaths::configured_only([ext.clone()]).is_protected_fast(scan_root)
            }));
        if ext_set.is_protected_fast(path) {
            return true;
        }
    }

    false
}

fn home_user_data_roots() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    cleanton_common::USER_DATA_CONTENT_ROOTS
        .iter()
        .map(|rel| home.join(rel))
        .collect()
}

fn external_volume_roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/Volumes"),
        PathBuf::from("/media"),
        PathBuf::from("/mnt"),
        PathBuf::from("/run/media"),
    ]
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

/// Roll per-file sizes up into their ancestor directories.
///
/// Both phases are O(entries): every file is folded into its DIRECT parent once,
/// then the per-directory totals are propagated bottom-up (deepest directory
/// first) in a single ordered pass.
fn aggregate_directory_sizes(result: &mut ScanResult) {
    let approx_files = usize::try_from(result.total_files).unwrap_or(0);
    let approx_dirs = usize::try_from(result.total_dirs).unwrap_or(0);
    let mut inode_seen = HashSet::<(u64, u64)>::with_capacity(approx_files / 2);
    let mut total_logical = 0_u64;
    let mut total_allocated = 0_u64;

    // 1. De-duplicate entry sizes for hardlinked inodes first and accumulate scan totals
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
        total_logical = total_logical.saturating_add(entry.logical_bytes);
        total_allocated = total_allocated.saturating_add(entry.allocated_bytes);
    }

    // 2. Per-directory subtree totals. Borrowed path keys keep this allocation
    //    free beyond the accumulator vectors themselves.
    let (dir_entry_indices, totals) = {
        let entries = &result.entries;
        let mut slot_of: HashMap<&Path, usize> = HashMap::with_capacity(approx_dirs);
        let mut dir_paths: Vec<&Path> = Vec::with_capacity(approx_dirs);
        let mut dir_depths: Vec<usize> = Vec::with_capacity(approx_dirs);
        let mut dir_entry_indices: Vec<usize> = Vec::with_capacity(approx_dirs);
        for (index, entry) in entries.iter().enumerate() {
            if entry.kind != FileKind::Directory || slot_of.contains_key(entry.path.as_path()) {
                continue;
            }
            slot_of.insert(entry.path.as_path(), dir_paths.len());
            dir_paths.push(entry.path.as_path());
            dir_depths.push(entry.depth);
            dir_entry_indices.push(index);
        }

        let mut totals = vec![(0_u64, 0_u64); dir_paths.len()];

        // Direct children only: one lookup per file instead of one per ancestor.
        for entry in entries {
            if entry.kind != FileKind::File {
                continue;
            }
            let Some(parent) = entry.path.parent() else {
                continue;
            };
            let Some(slot) = slot_of.get(parent).copied() else {
                continue;
            };
            if let Some(total) = totals.get_mut(slot) {
                total.0 = total.0.saturating_add(entry.logical_bytes);
                total.1 = total.1.saturating_add(entry.allocated_bytes);
            }
        }

        // Bottom-up: sort by recorded depth (falling back to component count if equal)
        // so child directory subtree totals land in their parent before the parent folds up.
        let mut order: Vec<usize> = (0..dir_paths.len()).collect();
        order.sort_unstable_by_key(|slot| {
            let depth = dir_depths.get(*slot).copied().unwrap_or(0);
            let comp = if depth == 0 {
                dir_paths
                    .get(*slot)
                    .map_or(0, |path| path.components().count())
            } else {
                depth
            };
            std::cmp::Reverse(comp)
        });
        for slot in order {
            let Some(path) = dir_paths.get(slot) else {
                continue;
            };
            let Some(parent) = path.parent() else {
                continue;
            };
            let Some(parent_slot) = slot_of.get(parent).copied() else {
                continue;
            };
            if parent_slot == slot {
                continue;
            }
            let Some((logical, allocated)) = totals.get(slot).copied() else {
                continue;
            };
            if let Some(total) = totals.get_mut(parent_slot) {
                total.0 = total.0.saturating_add(logical);
                total.1 = total.1.saturating_add(allocated);
            }
        }

        (dir_entry_indices, totals)
    };

    // 3. Update directory entries with their subtree sizes
    for (slot, index) in dir_entry_indices.iter().enumerate() {
        let Some(entry) = result.entries.get_mut(*index) else {
            continue;
        };
        if let Some((logical, allocated)) = totals.get(slot).copied() {
            entry.logical_bytes = logical;
            entry.allocated_bytes = allocated;
        }
    }

    // 4. Commit total scan results sizes
    result.logical_bytes = total_logical;
    result.allocated_bytes = total_allocated;
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
    async fn git_internals_are_not_walked_but_project_is_detected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let git = temp.path().join(".git");
        fs::create_dir_all(git.join("objects/pack")).expect("create .git");
        fs::write(git.join("objects/pack/blob.bin"), [1_u8; 8192]).expect("write blob");
        fs::write(temp.path().join("Cargo.toml"), "[package]\nname=\"test\"")
            .expect("write cargo.toml");

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

        // The `.git` directory entry itself may be yielded, but nothing
        // beneath it is ever inventoried.
        assert!(
            result
                .entries
                .iter()
                .all(|entry| entry.path == git || !entry.path.starts_with(&git)),
            ".git internals must not be walked: {:?}",
            result
                .entries
                .iter()
                .filter(|entry| entry.path != git && entry.path.starts_with(&git))
                .map(|entry| &entry.path)
                .collect::<Vec<_>>()
        );
        // Marker-file detection still works: the Rust project at the root
        // is found (the `.git` entry adds a second, Git-ecosystem root for
        // the same path, as before this change).
        assert!(
            result.project_roots.iter().any(|project| {
                project.path == temp.path() && project.ecosystem == cleanton_common::Ecosystem::Rust
            }),
            "expected the Rust project root, got {:?}",
            result.project_roots
        );
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
