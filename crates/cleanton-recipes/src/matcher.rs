use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{LazyLock, RwLock},
    time::{Duration, SystemTime},
};

use cleanton_common::{
    CleanupAction, Confidence, FileEntry, FileKind, ProtectedPaths, RecipeId, paths::expand_tilde,
};
use glob::Pattern;

/// Built once: the default protected-path set. Rebuilding it per entry recomputed
/// (and `canonicalize`d) every protected root, which dominated analysis time on
/// large scans.
static DEFAULT_PROTECTED: LazyLock<ProtectedPaths> = LazyLock::new(ProtectedPaths::defaults);

/// Compiled-glob cache, keyed by pattern string. Compiling a `glob::Pattern`
/// builds a token state machine; the matcher was recompiling every recipe's glob
/// for *every* scanned entry (millions of compilations on a large scan, which the
/// profiler showed dominating post-scan analysis). Recipe globs are a tiny, fixed
/// set, so memoizing the compiled form makes matching a cache read plus a match.
/// `None` records a pattern that failed to compile, preserving the previous
/// "invalid glob never matches" behaviour without retrying the compile.
static GLOB_CACHE: LazyLock<RwLock<HashMap<String, Option<Pattern>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Memoized `~`-expansion of recipe glob patterns, keyed by the raw pattern.
///
/// `expand_tilde` reads `$HOME` and builds a fresh `PathBuf` plus a `String` per
/// call, and the two call sites below run once per (entry, recipe) pair — tens
/// of millions of allocations on a full home scan. Recipes are a fixed set, so
/// the expansion is computed once per pattern and reused.
static EXPANDED_CACHE: LazyLock<RwLock<HashMap<String, String>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Run `f` against `pattern`'s `~`-expanded form, memoizing the expansion.
/// Patterns that do not start with `~` are passed through untouched.
fn with_expanded_pattern<R>(pattern: &str, f: impl FnOnce(&str) -> R) -> R {
    if !pattern.starts_with('~') {
        return f(pattern);
    }
    if let Ok(cache) = EXPANDED_CACHE.read()
        && let Some(expanded) = cache.get(pattern)
    {
        return f(expanded.as_str());
    }
    let expanded = expand_tilde(&PathBuf::from(pattern))
        .to_string_lossy()
        .into_owned();
    let out = f(expanded.as_str());
    if let Ok(mut cache) = EXPANDED_CACHE.write() {
        cache.entry(pattern.to_owned()).or_insert(expanded);
    }
    out
}

/// Run `f` against the compiled form of `pattern`, compiling and caching on first
/// use. Returns `None` when the pattern is invalid (so callers treat it as a
/// non-match, exactly as `Pattern::new(..).is_ok_and(..)` did).
fn with_compiled_glob<R>(pattern: &str, f: impl FnOnce(&Pattern) -> R) -> Option<R> {
    if let Ok(cache) = GLOB_CACHE.read()
        && let Some(slot) = cache.get(pattern)
    {
        return slot.as_ref().map(f);
    }
    let compiled = Pattern::new(pattern).ok();
    let result = compiled.as_ref().map(f);
    if let Ok(mut cache) = GLOB_CACHE.write() {
        cache.entry(pattern.to_owned()).or_insert(compiled);
    }
    result
}

/// Cached equivalent of `Pattern::new(pattern).is_ok_and(|p| p.matches_path(path))`.
fn glob_matches_path(pattern: &str, path: &Path) -> bool {
    with_compiled_glob(pattern, |compiled| compiled.matches_path(path)).unwrap_or(false)
}

/// Cached equivalent of `Pattern::new(pattern).is_ok_and(|p| p.matches(text))`.
fn glob_matches(pattern: &str, text: &str) -> bool {
    with_compiled_glob(pattern, |compiled| compiled.matches(text)).unwrap_or(false)
}

/// True when `spec`'s `pattern` selects `entry`.
///
/// A trailing `/**` selects everything *beneath* a directory but not the
/// directory itself: `**/__pycache__/**` matches `.../__pycache__/m.pyc` but NOT
/// `.../__pycache__`. Recipes written that way mean the directory as a unit --
/// their prompts say "Move {size} of X to Trash" -- so for a DIRECTORY entry we
/// also test the pattern with the trailing `/**` stripped.
///
/// That distinction decides the whole shape of the plan. Without it the
/// directory is never a candidate, so the deepest thing the recipe can select is
/// its children; when those children are files, the plan gets one action per
/// file and the executor trashes them one `trash::delete` at a time. With it the
/// directory itself becomes the candidate, the planner subsumes its contents,
/// and the folder moves in a single Trash operation.
///
/// Two deliberate limits:
///
/// - Only DIRECTORY entries get the stripped form; applying it to files could
///   newly select a plain file that happens to share the directory's name.
/// - Only specs WITHOUT `min_age_days`. An age gate means "reclaim the stale
///   parts of this cache", and a directory is aged by the newest mtime in its
///   whole subtree. Hoisting such a recipe to the cache root would gate the
///   entire cache on its single freshest file, so it would essentially never
///   fire -- `~/Library/Caches/ms-playwright/**` (30 days) stops reclaiming the
///   moment one browser is used. Age-gated recipes therefore keep their existing
///   per-child granularity, where the gate can still pick off the stale
///   subdirectories one whole folder at a time.
fn glob_selects_entry(spec: &crate::MatchSpec, pattern: &str, entry: &FileEntry) -> bool {
    if glob_matches_path(pattern, &entry.path) {
        return true;
    }
    if entry.kind != FileKind::Directory || spec.min_age_days.is_some() {
        return false;
    }
    pattern
        .strip_suffix("/**")
        .is_some_and(|base| glob_matches_path(base, &entry.path))
}

use crate::RecipeDocument;

#[must_use]
pub fn recipe_matches_entry(recipe: &RecipeDocument, entry: &FileEntry) -> bool {
    recipe_matches_entry_with_parent_lookup(recipe, entry, |parent, marker| {
        parent.join(marker).exists()
    })
}

pub(crate) fn recipe_matches_entry_with_parent_lookup(
    recipe: &RecipeDocument,
    entry: &FileEntry,
    parent_contains: impl Fn(&Path, &str) -> bool,
) -> bool {
    // Standalone callers (and tests) get the default subtree-mtime probe, which
    // walks the directory's subtree on demand. Bulk callers should use
    // [`recipe_matches_entry_full`] with a precomputed lookup instead — see
    // [`action_for_entry_with_subtree_mtime`].
    recipe_matches_entry_full(recipe, entry, parent_contains, |dir| {
        get_newest_modified_in_subtree(dir)
    })
}

pub(crate) fn recipe_matches_entry_full(
    recipe: &RecipeDocument,
    entry: &FileEntry,
    parent_contains: impl Fn(&Path, &str) -> bool,
    newest_in_subtree: impl Fn(&Path) -> Option<SystemTime>,
) -> bool {
    // The top-level spec and each `[[match.any_of]]` alternative are full,
    // independent match specs; the recipe matches when any one of them does.
    // (Nested alternatives are rejected by the validator, so only the top-level
    // spec's `any_of` is consulted.)
    let matched = std::iter::once(&recipe.matcher)
        .chain(recipe.matcher.any_of.iter())
        .any(|spec| spec_matches_entry(spec, entry, &parent_contains, &newest_in_subtree));
    if !matched {
        return false;
    }

    // Safety floors, evaluated last so their cost (path normalization for the
    // protected-roots check; basename scan) only falls on the few entries that
    // actually match a recipe's pattern — not on every (entry, recipe) pair.
    // A recipe must never plan an action against a protected path or a
    // credential/auth/secret/settings file, regardless of how broad its glob is.
    if DEFAULT_PROTECTED.is_protected_fast(&entry.path) || is_sensitive_basename(&entry.path) {
        return false;
    }

    true
}

/// Evaluate one match spec's own criteria (selectors, context markers, size and
/// age gates, excludes) against an entry. The recipe-wide safety floors are NOT
/// applied here — [`recipe_matches_entry_full`] enforces them once, after any
/// spec has matched.
fn spec_matches_entry(
    matcher: &crate::MatchSpec,
    entry: &FileEntry,
    parent_contains: &impl Fn(&Path, &str) -> bool,
    newest_in_subtree: &impl Fn(&Path) -> Option<SystemTime>,
) -> bool {
    spec_selects_entry(matcher, entry, parent_contains)
        && spec_gates_pass(matcher, entry, newest_in_subtree)
}

/// The spec's *selectors*: excludes, name/glob/extension patterns, and context
/// markers. These decide WHAT a spec is about, independent of whether the
/// candidate is currently eligible. Split out from [`spec_gates_pass`] so
/// [`directory_gate`] can tell "this recipe does not concern this directory"
/// apart from "this recipe concerns it, but it is not eligible right now".
fn spec_selects_entry(
    matcher: &crate::MatchSpec,
    entry: &FileEntry,
    parent_contains: &impl Fn(&Path, &str) -> bool,
) -> bool {
    if matcher.exclude.names.iter().any(|name| {
        entry
            .path
            .file_name()
            .is_some_and(|candidate| candidate == name.as_str())
    }) {
        return false;
    }

    if matcher.exclude.paths.iter().any(|pattern| {
        with_expanded_pattern(pattern, |expanded| glob_matches_path(expanded, &entry.path))
    }) {
        return false;
    }

    if let Some(directory_name) = &matcher.directory_name
        && (entry.kind != FileKind::Directory
            || entry
                .path
                .file_name()
                .is_none_or(|name| name != directory_name.as_str()))
    {
        return false;
    }

    if let Some(file_name) = &matcher.file_name {
        if entry.kind != FileKind::File {
            return false;
        }
        let Some(name) = entry.path.file_name() else {
            return false;
        };
        if !glob_matches(file_name, &name.to_string_lossy()) {
            return false;
        }
    }

    if let Some(extensions) = &matcher.file_extension {
        if entry.kind != FileKind::File {
            return false;
        }
        let extension = entry
            .path
            .extension()
            .map(|extension| format!(".{}", extension.to_string_lossy()));
        if !extension.is_some_and(|extension| extensions.iter().any(|item| item == &extension)) {
            return false;
        }
    }

    if let Some(path_glob) = &matcher.path_glob
        && !with_expanded_pattern(path_glob, |expanded| {
            glob_selects_entry(matcher, expanded, entry)
        })
    {
        return false;
    }

    if !context_markers_hold(matcher, entry, parent_contains) {
        return false;
    }

    true
}

/// The spec's *eligibility gates*: `min_size_mb` and `min_age_days`. A directory
/// is aged by the newest mtime anywhere in its subtree, so a single recently
/// touched file keeps the whole directory ineligible — deliberately strict,
/// because the recipes that carry an age gate mean "this cache is no longer in
/// use". See [`directory_gate`] for what that strictness implies for the
/// directory's contents.
fn spec_gates_pass(
    matcher: &crate::MatchSpec,
    entry: &FileEntry,
    newest_in_subtree: &impl Fn(&Path) -> Option<SystemTime>,
) -> bool {
    if let Some(min_size_mb) = matcher.min_size_mb
        && entry.allocated_bytes < min_size_mb.saturating_mul(1_048_576)
    {
        return false;
    }

    if let Some(min_age_days) = matcher.min_age_days {
        let modified = if entry.kind == FileKind::Directory {
            newest_in_subtree(&entry.path).or(entry.modified)
        } else {
            entry.modified
        };
        if !is_old_enough(modified, min_age_days) {
            return false;
        }
    }

    true
}

/// True when any of the recipe's specs carries an eligibility gate. Recipes
/// without one can never produce [`DirectoryGate::GateFailed`], so bulk callers
/// skip them entirely when building the suppression set.
#[must_use]
pub fn recipe_has_gates(recipe: &RecipeDocument) -> bool {
    std::iter::once(&recipe.matcher)
        .chain(recipe.matcher.any_of.iter())
        .any(|spec| spec.min_size_mb.is_some() || spec.min_age_days.is_some())
}

/// How a recipe relates to a *directory* it was evaluated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryGate {
    /// A spec selected the directory and its gates passed: the directory itself
    /// is a candidate, and the planner will subsume its contents into it.
    Matched,
    /// A spec selected the directory but an eligibility gate failed. The recipe
    /// is *about* this directory as a unit, and the unit is not eligible — so
    /// the recipe must not fall back to picking off the directory's contents
    /// one file at a time. Callers suppress this recipe beneath such a root.
    GateFailed,
    /// No spec selected the directory; the recipe has nothing to say about it.
    NoMatch,
}

/// Classify a directory entry against a recipe, distinguishing "not eligible"
/// from "not relevant".
///
/// This exists because a `path_glob` like `~/Library/Caches/Foo/**` selects the
/// cache directory *and* every file beneath it. When an age gate rejects the
/// directory (one fresh file inside), the individually-old files beneath it
/// still satisfy the same recipe on their own. With no surviving ancestor
/// action there is nothing for the planner to prune them into, so the recipe
/// silently degrades from "trash this unused cache" into "shred N files out of
/// an actively used cache" — slow, and destructive to caches that need their
/// contents to stay consistent with an index.
#[must_use]
pub fn directory_gate(
    recipe: &RecipeDocument,
    entry: &FileEntry,
    newest_in_subtree: impl Fn(&Path) -> Option<SystemTime>,
) -> DirectoryGate {
    directory_gate_with_context(
        recipe,
        entry,
        |parent: &Path, marker: &str| parent.join(marker).exists(),
        newest_in_subtree,
    )
}

/// [`directory_gate`] with the "does this directory contain `marker`" probe
/// injected, so bulk callers can serve it from a per-directory cache instead of
/// running a `stat(2)` per (directory, recipe) pair.
#[must_use]
pub fn directory_gate_with_context(
    recipe: &RecipeDocument,
    entry: &FileEntry,
    parent_contains: impl Fn(&Path, &str) -> bool,
    newest_in_subtree: impl Fn(&Path) -> Option<SystemTime>,
) -> DirectoryGate {
    if entry.kind != FileKind::Directory {
        return DirectoryGate::NoMatch;
    }
    // Mirror the safety floors: a directory a recipe could never act on must not
    // suppress anything either.
    if DEFAULT_PROTECTED.is_protected_fast(&entry.path) || is_sensitive_basename(&entry.path) {
        return DirectoryGate::NoMatch;
    }

    let mut gate_failed = false;
    for spec in std::iter::once(&recipe.matcher).chain(recipe.matcher.any_of.iter()) {
        if !spec_selects_entry(spec, entry, &parent_contains) {
            continue;
        }
        if spec_gates_pass(spec, entry, &newest_in_subtree) {
            // Any fully-satisfied alternative makes the directory itself a
            // candidate, which is the outcome we want; it wins over a sibling
            // alternative that merely gate-failed.
            return DirectoryGate::Matched;
        }
        gate_failed = true;
    }

    if gate_failed {
        DirectoryGate::GateFailed
    } else {
        DirectoryGate::NoMatch
    }
}

/// The on-disk context proofs: `parent_must_contain` (all-of),
/// `parent_must_contain_any` (any-of), and `self_must_contain` (all markers
/// inside the matched directory itself). `dir_contains` is the injected
/// "does `dir/marker` exist" probe shared by all three.
#[must_use]
fn context_markers_hold(
    matcher: &crate::MatchSpec,
    entry: &FileEntry,
    dir_contains: &impl Fn(&Path, &str) -> bool,
) -> bool {
    if let Some(markers) = &matcher.parent_must_contain {
        let Some(parent) = entry.path.parent() else {
            return false;
        };
        if !markers.iter().all(|marker| dir_contains(parent, marker)) {
            return false;
        }
    }

    if let Some(markers) = &matcher.parent_must_contain_any {
        let Some(parent) = entry.path.parent() else {
            return false;
        };
        if !markers.iter().any(|marker| dir_contains(parent, marker)) {
            return false;
        }
    }

    if let Some(markers) = &matcher.self_must_contain {
        if entry.kind != FileKind::Directory {
            return false;
        }
        if !markers
            .iter()
            .all(|marker| dir_contains(&entry.path, marker))
        {
            return false;
        }
    }

    true
}

#[must_use]
pub fn action_for_entry(recipe: &RecipeDocument, entry: &FileEntry) -> Option<CleanupAction> {
    recipe_matches_entry(recipe, entry).then(|| build_action(recipe, entry))
}

/// Like [`action_for_entry`], but the caller supplies a precomputed
/// newest-modified-in-subtree lookup for directory entries. Bulk analysis builds
/// this once from the scan it already performed, avoiding a fresh recursive
/// `walkdir` per matched directory — which on a large tree (thousands of
/// `node_modules` / `target` dirs) is an O(n²) filesystem storm.
#[must_use]
pub fn action_for_entry_with_subtree_mtime(
    recipe: &RecipeDocument,
    entry: &FileEntry,
    newest_in_subtree: impl Fn(&Path) -> Option<SystemTime>,
) -> Option<CleanupAction> {
    action_for_entry_with_context(
        recipe,
        entry,
        |parent, marker| parent.join(marker).exists(),
        newest_in_subtree,
    )
}

/// Like [`action_for_entry_with_subtree_mtime`], but both injected probes are
/// supplied by the caller: the newest-mtime-in-subtree lookup *and* the
/// "does this directory contain `marker`" context probe.
///
/// Bulk analysis runs the context probe once per (entry, recipe) pair, i.e.
/// millions of `stat(2)` calls for `parent_must_contain` recipes. Having the
/// caller supply a memoized probe turns that into at most one `stat` per
/// (directory, marker) without changing any matching semantics.
#[must_use]
pub fn action_for_entry_with_context(
    recipe: &RecipeDocument,
    entry: &FileEntry,
    parent_contains: impl Fn(&Path, &str) -> bool,
    newest_in_subtree: impl Fn(&Path) -> Option<SystemTime>,
) -> Option<CleanupAction> {
    recipe_matches_entry_full(recipe, entry, parent_contains, newest_in_subtree)
        .then(|| build_action(recipe, entry))
}

fn build_action(recipe: &RecipeDocument, entry: &FileEntry) -> CleanupAction {
    CleanupAction {
        target: entry.path.clone(),
        logical_bytes: entry.logical_bytes,
        reclaimable_bytes: entry.allocated_bytes,
        recipe_id: RecipeId(recipe.recipe.id.clone()),
        category: recipe.recipe.category.clone(),
        action_type: recipe.action.action_type,
        confidence: Confidence::High,
        safety_level: recipe.recipe.safety_level,
        reason: recipe.recipe.description.clone(),
        fingerprint: entry.fingerprint(),
    }
}

/// Basenames that must never be matched by any recipe. These are credentials,
/// auth tokens, secrets, and tool settings files. Compared case-insensitively.
const SENSITIVE_BASENAMES: &[&str] = &[
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    ".credentials.json",
    "auth.json",
    ".auth.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "kubeconfig",
    "secrets.yaml",
    "secrets.yml",
    "service-account.json",
    "settings.json",
    "settings.local.json",
    "mcp.json",
    ".mcp.json",
];

fn is_sensitive_basename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    // Every basename in SENSITIVE_BASENAMES is <= 20 ASCII bytes; stack-lowercasing
    // avoids allocating a heap String for every scanned file on the hot path.
    if name.is_empty() || name.len() > 32 || !name.is_ascii() {
        return false;
    }
    let mut buf = [0_u8; 32];
    let bytes = name.as_bytes();
    for (dst, src) in buf.iter_mut().zip(bytes.iter()) {
        *dst = src.to_ascii_lowercase();
    }
    let Ok(lower) = std::str::from_utf8(buf.get(..bytes.len()).unwrap_or(&[])) else {
        return false;
    };
    SENSITIVE_BASENAMES.contains(&lower)
}

#[derive(Debug)]
enum CompiledNameMatcher {
    Exact(String),
    Glob(Pattern),
}

impl CompiledNameMatcher {
    fn compile(raw: &str) -> Option<Self> {
        if !contains_glob_meta(raw) {
            Some(Self::Exact(raw.to_owned()))
        } else {
            Pattern::new(raw).ok().map(Self::Glob)
        }
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(expected) => name == expected,
            Self::Glob(pattern) => pattern.matches(name),
        }
    }
}

#[derive(Debug)]
struct CompiledPathGlob {
    full: Option<Pattern>,
    stripped_dir_base: Option<Pattern>,
    literal_prefix: Option<PathBuf>,
    required_substring: Option<String>,
}

impl CompiledPathGlob {
    fn compile(raw: &str, min_age_days: Option<u64>) -> Self {
        let expanded = if raw.starts_with('~') {
            expand_tilde(&PathBuf::from(raw))
                .to_string_lossy()
                .into_owned()
        } else {
            raw.to_owned()
        };
        let full = Pattern::new(&expanded).ok();
        let stripped_dir_base = if min_age_days.is_none() {
            expanded
                .strip_suffix("/**")
                .and_then(|base| Pattern::new(base).ok())
        } else {
            None
        };
        let effective_for_prefix = expanded.strip_suffix("/**").unwrap_or(&expanded);
        let literal_prefix = extract_literal_prefix(effective_for_prefix);
        let required_substring = if literal_prefix.is_none() {
            extract_longest_literal_segment(effective_for_prefix)
        } else {
            None
        };
        Self {
            full,
            stripped_dir_base,
            literal_prefix,
            required_substring,
        }
    }

    #[inline]
    fn matches_entry(&self, entry: &FileEntry) -> bool {
        if let Some(prefix) = &self.literal_prefix
            && !entry.path.starts_with(prefix)
        {
            return false;
        }
        if let Some(required) = &self.required_substring {
            let path_lossy = entry.path.to_string_lossy();
            if !path_lossy.contains(required.as_str()) {
                return false;
            }
        }
        if self
            .full
            .as_ref()
            .is_some_and(|pattern| pattern.matches_path(&entry.path))
        {
            return true;
        }
        entry.kind == FileKind::Directory
            && self
                .stripped_dir_base
                .as_ref()
                .is_some_and(|base| base.matches_path(&entry.path))
    }
}

fn contains_glob_meta(text: &str) -> bool {
    text.bytes().any(|b| matches!(b, b'*' | b'?' | b'[' | b']'))
}

fn extract_literal_prefix(pattern: &str) -> Option<PathBuf> {
    if pattern.is_empty() || pattern.starts_with("./") || pattern.contains('\\') {
        return None;
    }
    let leading_slash = pattern.starts_with('/');
    let mut prefix = if leading_slash {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    let mut count = 0_usize;
    for part in pattern.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." || contains_glob_meta(part) {
            break;
        }
        prefix.push(part);
        count = count.saturating_add(1);
    }
    (count > 0).then_some(prefix)
}

fn extract_longest_literal_segment(pattern: &str) -> Option<String> {
    pattern
        .split('/')
        .filter(|part| {
            !part.is_empty() && *part != "." && *part != ".." && !contains_glob_meta(part)
        })
        .max_by_key(|part| part.len())
        .filter(|part| part.len() >= 2)
        .map(str::to_owned)
}

#[derive(Debug)]
struct CompiledSpec {
    exclude_names: Vec<String>,
    exclude_paths: Vec<Option<Pattern>>,
    directory_name: Option<String>,
    file_name: Option<Option<CompiledNameMatcher>>,
    file_extensions: Option<Vec<String>>,
    path_glob: Option<CompiledPathGlob>,
    parent_must_contain: Option<Vec<String>>,
    parent_must_contain_any: Option<Vec<String>>,
    self_must_contain: Option<Vec<String>>,
    min_size_bytes: Option<u64>,
    min_age_days: Option<u64>,
}

impl CompiledSpec {
    fn compile(spec: &crate::MatchSpec) -> Self {
        let exclude_paths = spec
            .exclude
            .paths
            .iter()
            .map(|raw| {
                let expanded = if raw.starts_with('~') {
                    expand_tilde(&PathBuf::from(raw))
                        .to_string_lossy()
                        .into_owned()
                } else {
                    raw.clone()
                };
                Pattern::new(&expanded).ok()
            })
            .collect();
        let file_name = spec
            .file_name
            .as_deref()
            .map(CompiledNameMatcher::compile);
        let file_extensions = spec.file_extension.as_ref().map(|exts| {
            exts.iter()
                .map(|ext| ext.strip_prefix('.').unwrap_or(ext).to_owned())
                .collect()
        });
        let path_glob = spec
            .path_glob
            .as_deref()
            .map(|raw| CompiledPathGlob::compile(raw, spec.min_age_days));

        Self {
            exclude_names: spec.exclude.names.clone(),
            exclude_paths,
            directory_name: spec.directory_name.clone(),
            file_name,
            file_extensions,
            path_glob,
            parent_must_contain: spec.parent_must_contain.clone(),
            parent_must_contain_any: spec.parent_must_contain_any.clone(),
            self_must_contain: spec.self_must_contain.clone(),
            min_size_bytes: spec.min_size_mb.map(|mb| mb.saturating_mul(1_048_576)),
            min_age_days: spec.min_age_days,
        }
    }

    fn selects_entry(
        &self,
        entry: &FileEntry,
        entry_name: Option<&str>,
        entry_ext: Option<&str>,
        dir_contains: &impl Fn(&Path, &str) -> bool,
    ) -> bool {
        if let Some( expected ) = &self.directory_name {
            if entry.kind != FileKind::Directory || entry_name != Some(expected.as_str()) {
                return false;
            }
        }
        if let Some(compiled_name) = &self.file_name {
            if entry.kind != FileKind::File {
                return false;
            }
            let Some(matcher) = compiled_name.as_ref() else {
                return false;
            };
            let Some(actual) = entry_name else {
                return false;
            };
            if !matcher.matches(actual) {
                return false;
            }
        }
        if let Some(extensions) = &self.file_extensions {
            if entry.kind != FileKind::File {
                return false;
            }
            let Some(ext) = entry_ext else {
                return false;
            };
            if !extensions.iter().any(|item| item == ext) {
                return false;
            }
        }
        if !self.exclude_names.is_empty()
            && entry
                .path
                .file_name()
                .is_some_and(|candidate| self.exclude_names.iter().any(|n| candidate == n.as_str()))
        {
            return false;
        }
        if self.exclude_paths.iter().any(|pat| {
            pat.as_ref()
                .is_some_and(|compiled| compiled.matches_path(&entry.path))
        }) {
            return false;
        }
        if let Some(glob) = &self.path_glob
            && !glob.matches_entry(entry)
        {
            return false;
        }
        if let Some(markers) = &self.parent_must_contain {
            let Some(parent) = entry.path.parent() else {
                return false;
            };
            if !markers.iter().all(|marker| dir_contains(parent, marker)) {
                return false;
            }
        }
        if let Some(markers) = &self.parent_must_contain_any {
            let Some(parent) = entry.path.parent() else {
                return false;
            };
            if !markers.iter().any(|marker| dir_contains(parent, marker)) {
                return false;
            }
        }
        if let Some(markers) = &self.self_must_contain {
            if entry.kind != FileKind::Directory {
                return false;
            }
            if !markers
                .iter()
                .all(|marker| dir_contains(&entry.path, marker))
            {
                return false;
            }
        }
        true
    }

    fn gates_pass(
        &self,
        entry: &FileEntry,
        newest_in_subtree: &impl Fn(&Path) -> Option<SystemTime>,
    ) -> bool {
        if let Some(min_bytes) = self.min_size_bytes
            && entry.allocated_bytes < min_bytes
        {
            return false;
        }
        if let Some(min_age_days) = self.min_age_days {
            let modified = if entry.kind == FileKind::Directory {
                newest_in_subtree(&entry.path).or(entry.modified)
            } else {
                entry.modified
            };
            if !is_old_enough(modified, min_age_days) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug)]
struct CompiledRecipe<'a> {
    doc: &'a RecipeDocument,
    has_gates: bool,
    specs: Vec<CompiledSpec>,
}

/// Lock-free, precompiled, indexed matcher over an ordered slice of recipes.
///
/// Built once per analysis pass so bulk matching avoids all `RwLock` contention,
/// redundant `ProtectedPaths` / sensitive-basename checks, and irrelevant glob
/// evaluations.
#[derive(Debug)]
pub struct CompiledRecipeMatcher<'a> {
    recipes: Vec<CompiledRecipe<'a>>,
    home_dir: Option<PathBuf>,
    by_dir_name: HashMap<String, Vec<usize>>,
    by_file_ext: HashMap<String, Vec<usize>>,
    by_home_top_dir: HashMap<String, Vec<usize>>,
    fallback_dirs: Vec<usize>,
    fallback_files: Vec<usize>,
}

impl<'a> CompiledRecipeMatcher<'a> {
    #[must_use]
    pub fn new(ordered: &[&'a RecipeDocument]) -> Self {
        let home_dir = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute());
        let mut recipes = Vec::with_capacity(ordered.len());
        let mut by_dir_name: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_file_ext: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_home_top_dir: HashMap<String, Vec<usize>> = HashMap::new();
        let mut fallback_dirs: Vec<usize> = Vec::new();
        let mut fallback_files: Vec<usize> = Vec::new();

        for (recipe_idx, &doc) in ordered.iter().enumerate() {
            let specs = std::iter::once(&doc.matcher)
                .chain(doc.matcher.any_of.iter())
                .map(CompiledSpec::compile)
                .collect::<Vec<_>>();
            let has_gates = recipe_has_gates(doc);

            for spec in &specs {
                if let Some(dir_name) = &spec.directory_name {
                    push_unique(by_dir_name.entry(dir_name.clone()).or_default(), recipe_idx);
                    continue;
                }
                if let Some(exts) = &spec.file_extensions {
                    for ext in exts {
                        push_unique(by_file_ext.entry(ext.clone()).or_default(), recipe_idx);
                    }
                    continue;
                }
                if let Some(top) = home_dir
                    .as_deref()
                    .and_then(|home| spec_home_top_component(spec, home))
                {
                    push_unique(by_home_top_dir.entry(top).or_default(), recipe_idx);
                    continue;
                }
                if spec.file_name.is_none() {
                    push_unique(&mut fallback_dirs, recipe_idx);
                }
                push_unique(&mut fallback_files, recipe_idx);
            }

            recipes.push(CompiledRecipe {
                doc,
                has_gates,
                specs,
            });
        }

        Self {
            recipes,
            home_dir,
            by_dir_name,
            by_file_ext,
            by_home_top_dir,
            fallback_dirs,
            fallback_files,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.recipes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recipes.is_empty()
    }

    /// Return the indices of gated recipes whose directory selector matched `entry`
    /// (`FileKind::Directory`) while every matching spec failed its size/age gate.
    pub fn gate_failed_recipe_indices(
        &self,
        entry: &FileEntry,
        candidates_buf: &mut Vec<usize>,
        dir_contains: impl Fn(&Path, &str) -> bool,
        newest_in_subtree: impl Fn(&Path) -> Option<SystemTime>,
    ) -> Vec<usize> {
        if entry.kind != FileKind::Directory
            || DEFAULT_PROTECTED.is_protected_fast(&entry.path)
            || is_sensitive_basename(&entry.path)
        {
            return Vec::new();
        }
        let entry_name = entry.path.file_name().map(|n| n.to_string_lossy());
        self.collect_candidates(entry, entry_name.as_deref(), None, candidates_buf);

        let mut failed = Vec::new();
        for &recipe_idx in candidates_buf.iter() {
            let Some(compiled) = self.recipes.get(recipe_idx) else {
                continue;
            };
            if !compiled.has_gates {
                continue;
            }
            let mut gate_failed = false;
            let mut matched = false;
            for spec in &compiled.specs {
                if !spec.selects_entry(entry, entry_name.as_deref(), None, &dir_contains) {
                    continue;
                }
                if spec.gates_pass(entry, &newest_in_subtree) {
                    matched = true;
                    break;
                }
                gate_failed = true;
            }
            if !matched && gate_failed {
                failed.push(recipe_idx);
            }
        }
        failed
    }

    /// Evaluate candidate recipes in priority order and return the first matching
    /// [`CleanupAction`], skipping any recipe for which `is_suppressed(recipe_idx)` is true.
    pub fn first_matching_action(
        &self,
        entry: &FileEntry,
        candidates_buf: &mut Vec<usize>,
        is_suppressed: impl Fn(usize) -> bool,
        dir_contains: impl Fn(&Path, &str) -> bool,
        newest_in_subtree: impl Fn(&Path) -> Option<SystemTime>,
    ) -> Option<CleanupAction> {
        if DEFAULT_PROTECTED.is_protected_fast(&entry.path) || is_sensitive_basename(&entry.path) {
            return None;
        }
        let entry_name = entry.path.file_name().map(|n| n.to_string_lossy());
        let entry_ext = if entry.kind == FileKind::File {
            entry.path.extension().map(|e| e.to_string_lossy())
        } else {
            None
        };
        self.collect_candidates(
            entry,
            entry_name.as_deref(),
            entry_ext.as_deref(),
            candidates_buf,
        );

        for &recipe_idx in candidates_buf.iter() {
            if is_suppressed(recipe_idx) {
                continue;
            }
            let Some(compiled) = self.recipes.get(recipe_idx) else {
                continue;
            };
            let hit = compiled.specs.iter().any(|spec| {
                spec.selects_entry(
                    entry,
                    entry_name.as_deref(),
                    entry_ext.as_deref(),
                    &dir_contains,
                ) && spec.gates_pass(entry, &newest_in_subtree)
            });
            if hit {
                return Some(build_action(compiled.doc, entry));
            }
        }
        None
    }

    fn collect_candidates(
        &self,
        entry: &FileEntry,
        entry_name: Option<&str>,
        entry_ext: Option<&str>,
        out: &mut Vec<usize>,
    ) {
        out.clear();
        match entry.kind {
            FileKind::Directory => {
                if let Some(name) = entry_name
                    && let Some(indices) = self.by_dir_name.get(name)
                {
                    out.extend_from_slice(indices);
                }
                out.extend_from_slice(&self.fallback_dirs);
            }
            FileKind::File => {
                if let Some(ext) = entry_ext
                    && let Some(indices) = self.by_file_ext.get(ext)
                {
                    out.extend_from_slice(indices);
                }
                out.extend_from_slice(&self.fallback_files);
            }
            FileKind::Symlink | FileKind::Other => {
                out.extend_from_slice(&self.fallback_files);
            }
        }
        if let Some(home) = &self.home_dir
            && let Ok(rel) = entry.path.strip_prefix(home)
            && let Some(first) = rel.components().next()
            && let Some(top) = first.as_os_str().to_str()
            && let Some(indices) = self.by_home_top_dir.get(top)
        {
            out.extend_from_slice(indices);
        }
        out.sort_unstable();
        out.dedup();
    }
}

fn push_unique(vec: &mut Vec<usize>, idx: usize) {
    if vec.last().copied() != Some(idx) && !vec.contains(&idx) {
        vec.push(idx);
    }
}

fn spec_home_top_component(spec: &CompiledSpec, home: &Path) -> Option<String> {
    let prefix = spec.path_glob.as_ref()?.literal_prefix.as_ref()?;
    let rel = prefix.strip_prefix(home).ok()?;
    let first = rel.components().next()?;
    first.as_os_str().to_str().map(str::to_owned)
}

fn is_old_enough(modified: Option<SystemTime>, min_age_days: u64) -> bool {
    let Some(modified) = modified else {
        return false;
    };
    let min_age = Duration::from_secs(min_age_days.saturating_mul(24 * 60 * 60));
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age >= min_age)
}

fn get_newest_modified_in_subtree(dir: &Path) -> Option<SystemTime> {
    let mut newest = None;
    for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
        if entry.depth() > 0
            && let Ok(metadata) = entry.metadata()
            && let Ok(modified) = metadata.modified()
            && newest.is_none_or(|n| modified > n)
        {
            newest = Some(modified);
        }
    }
    newest
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        time::{Duration, SystemTime},
    };

    use cleanton_common::{ActionType, FileEntry, FileKind, SafetyLevel};

    use crate::{ActionSpec, MatchSpec, Recipe, RecipeDocument, RecipeSet, RecipeTest};

    use super::*;

    #[test]
    fn file_name_matchers_only_match_files() {
        let recipe = test_recipe(MatchSpec {
            file_name: Some("cache.bin".to_owned()),
            ..MatchSpec::default()
        });
        let entry = test_entry("project/cache.bin", FileKind::Directory);

        assert!(!recipe_matches_entry(&recipe, &entry));
    }

    #[test]
    fn file_extension_matchers_only_match_files() {
        let recipe = test_recipe(MatchSpec {
            file_extension: Some(vec![".log".to_owned()]),
            ..MatchSpec::default()
        });
        let entry = test_entry("project/archive.log", FileKind::Directory);

        assert!(!recipe_matches_entry(&recipe, &entry));
    }

    #[test]
    fn parent_markers_are_checked_against_direct_parent() {
        let recipe = test_recipe(MatchSpec {
            directory_name: Some("target".to_owned()),
            parent_must_contain: Some(vec!["Cargo.toml".to_owned()]),
            ..MatchSpec::default()
        });
        let entry = test_entry("projects/app/target", FileKind::Directory);

        assert!(recipe_matches_entry_with_parent_lookup(
            &recipe,
            &entry,
            |parent, marker| parent == Path::new("projects/app") && marker == "Cargo.toml",
        ));
    }

    #[test]
    fn parent_must_contain_any_accepts_any_single_marker() {
        let recipe = test_recipe(MatchSpec {
            directory_name: Some("build".to_owned()),
            parent_must_contain_any: Some(vec![
                "build.gradle".to_owned(),
                "build.gradle.kts".to_owned(),
            ]),
            ..MatchSpec::default()
        });
        let entry = test_entry("projects/app/build", FileKind::Directory);

        // Only the Kotlin-DSL manifest exists: still a match.
        assert!(recipe_matches_entry_with_parent_lookup(
            &recipe,
            &entry,
            |_, marker| marker == "build.gradle.kts",
        ));
        // Neither manifest exists: no match.
        assert!(!recipe_matches_entry_with_parent_lookup(
            &recipe,
            &entry,
            |_, _| false,
        ));
    }

    #[test]
    fn self_must_contain_probes_inside_the_matched_directory() {
        let recipe = test_recipe(MatchSpec {
            directory_name: Some("build".to_owned()),
            self_must_contain: Some(vec!["CMakeCache.txt".to_owned()]),
            ..MatchSpec::default()
        });
        let entry = test_entry("projects/native/build", FileKind::Directory);

        // The lookup receives the matched directory itself, not its parent.
        assert!(recipe_matches_entry_with_parent_lookup(
            &recipe,
            &entry,
            |dir, marker| dir == Path::new("projects/native/build") && marker == "CMakeCache.txt",
        ));
        assert!(!recipe_matches_entry_with_parent_lookup(
            &recipe,
            &entry,
            |_, _| false,
        ));
    }

    #[test]
    fn self_must_contain_never_matches_files() {
        let recipe = test_recipe(MatchSpec {
            directory_name: Some("build".to_owned()),
            self_must_contain: Some(vec!["CMakeCache.txt".to_owned()]),
            ..MatchSpec::default()
        });
        let entry = test_entry("projects/native/build", FileKind::File);

        assert!(!recipe_matches_entry_with_parent_lookup(
            &recipe,
            &entry,
            |_, _| true,
        ));
    }

    #[test]
    fn any_of_alternatives_match_when_primary_does_not() {
        let recipe = test_recipe(MatchSpec {
            path_glob: Some("**/*.ckpt".to_owned()),
            any_of: vec![MatchSpec {
                path_glob: Some("**/checkpoint-*".to_owned()),
                self_must_contain: Some(vec!["trainer_state.json".to_owned()]),
                ..MatchSpec::default()
            }],
            ..MatchSpec::default()
        });

        // Primary spec: a .ckpt file.
        let ckpt = test_entry("projects/ml/last.ckpt", FileKind::File);
        assert!(recipe_matches_entry_with_parent_lookup(
            &recipe,
            &ckpt,
            |_, _| true,
        ));

        // Alternative spec: a checkpoint-* directory with its self marker.
        let dir = test_entry("projects/ml/out/checkpoint-500", FileKind::Directory);
        assert!(recipe_matches_entry_with_parent_lookup(
            &recipe,
            &dir,
            |dir, marker| {
                dir == Path::new("projects/ml/out/checkpoint-500") && marker == "trainer_state.json"
            },
        ));

        // Neither spec: an unrelated file.
        let other = test_entry("projects/ml/train.py", FileKind::File);
        assert!(!recipe_matches_entry_with_parent_lookup(
            &recipe,
            &other,
            |_, _| true,
        ));
    }

    #[test]
    fn any_of_alternatives_still_respect_safety_floors() {
        let recipe = test_recipe(MatchSpec {
            path_glob: Some("**/*.ckpt".to_owned()),
            any_of: vec![MatchSpec {
                path_glob: Some("**/checkpoint-*".to_owned()),
                self_must_contain: Some(vec!["trainer_state.json".to_owned()]),
                ..MatchSpec::default()
            }],
            ..MatchSpec::default()
        });

        // The alternative's glob matches, but the path sits under a hard-coded
        // protected root: the recipe-wide floor must refuse it.
        let protected = test_entry("/Applications/Foo/checkpoint-500", FileKind::Directory);
        assert!(!recipe_matches_entry_with_parent_lookup(
            &recipe,
            &protected,
            |_, _| true,
        ));
    }

    #[test]
    fn self_must_contain_with_path_glob_never_matches_files() {
        // A path_glob-selected spec with self_must_contain proves a directory
        // target: a FILE whose path matches the glob must be refused.
        let recipe = test_recipe(MatchSpec {
            path_glob: Some("**/checkpoint-*".to_owned()),
            self_must_contain: Some(vec!["trainer_state.json".to_owned()]),
            ..MatchSpec::default()
        });
        let file = test_entry("projects/ml/out/checkpoint-500.tar", FileKind::File);

        assert!(!recipe_matches_entry_with_parent_lookup(
            &recipe,
            &file,
            |_, _| true,
        ));
    }

    #[test]
    fn path_glob_semantics_match_absolute_paths_and_span_separators() {
        // Documents the `glob` crate defaults the matcher relies on: patterns
        // match absolute scanned paths, and `*` spans `/` (so `dir/*` also
        // matches nested descendants — recipes must not rely on `*` meaning
        // "direct child only").
        assert!(glob_matches_path(
            "**/*.ckpt",
            Path::new("/Users/dev/projects/ml/last.ckpt"),
        ));
        assert!(glob_matches_path(
            "**/checkpoint-*",
            Path::new("/Users/dev/ml/out/checkpoint-500/nested/file.bin"),
        ));
        assert!(!glob_matches_path(
            "**/*.pt",
            Path::new("/Users/dev/slides/report.ppt"),
        ));
    }

    #[test]
    fn min_age_days_rejects_recent_entries() {
        let recipe = test_recipe(MatchSpec {
            file_name: Some("old.log".to_owned()),
            min_age_days: Some(7),
            ..MatchSpec::default()
        });
        let mut entry = test_entry("project/old.log", FileKind::File);
        entry.modified = Some(SystemTime::now() - Duration::from_hours(48));

        assert!(!recipe_matches_entry(&recipe, &entry));
    }

    #[test]
    fn min_age_days_accepts_old_entries() {
        let recipe = test_recipe(MatchSpec {
            file_name: Some("old.log".to_owned()),
            min_age_days: Some(7),
            ..MatchSpec::default()
        });
        let mut entry = test_entry("project/old.log", FileKind::File);
        entry.modified = Some(SystemTime::now() - Duration::from_hours(192));

        assert!(recipe_matches_entry(&recipe, &entry));
    }

    #[test]
    fn builtin_recipes_reject_protected_secret_and_user_document_fixtures() {
        let recipes = RecipeSet::load_builtin().expect("built-in recipes should validate");
        let fixtures = safety_negative_fixtures();

        for recipe in recipes.iter() {
            for (path, kind) in &fixtures {
                let entry = test_entry(cleanton_common::paths::expand_tilde(path), *kind);
                assert!(
                    !recipe_matches_entry_with_parent_lookup(recipe, &entry, |_, _| true),
                    "built-in recipe {:?} unexpectedly matched safety fixture {}",
                    recipe.recipe.id,
                    entry.path.display(),
                );
            }
        }
    }

    fn test_recipe(matcher: MatchSpec) -> RecipeDocument {
        RecipeDocument {
            recipe: Recipe {
                id: "test-recipe".to_owned(),
                name: "Test Recipe".to_owned(),
                description: "test".to_owned(),
                category: "test".to_owned(),
                icon: None,
                safety_level: SafetyLevel::Safe,
                enabled: true,
                priority: 50,
            },
            matcher,
            action: ActionSpec {
                action_type: ActionType::Trash,
                prompt: "Trash?".to_owned(),
            },
            test: RecipeTest::default(),
        }
    }

    fn test_entry(path: impl Into<PathBuf>, kind: FileKind) -> FileEntry {
        FileEntry {
            path: path.into(),
            kind,
            logical_bytes: 1_048_576,
            allocated_bytes: 1_048_576,
            modified: Some(SystemTime::now() - Duration::from_hours(720)),
            depth: 0,
            device_id: None,
            inode: None,
            hardlink_count: None,
            symlink_target: None,
            ignored_by_git: false,
        }
    }

    fn safety_negative_fixtures() -> Vec<(PathBuf, FileKind)> {
        [
            ("~/Documents/ml/model.ckpt", FileKind::File),
            ("~/Documents/ml/chroma.sqlite3", FileKind::File),
            ("~/Documents/project/target", FileKind::Directory),
            ("~/Documents/project/node_modules", FileKind::Directory),
            ("~/Desktop/project/.venv", FileKind::Directory),
            ("~/Downloads/project/dist", FileKind::Directory),
            ("~/Pictures/checkpoints/model.ckpt", FileKind::File),
            ("~/Library/Keychains/login.keychain-db", FileKind::File),
            ("~/Library/Mail/V10/MailData/Envelope Index", FileKind::File),
            ("~/Library/Messages/chat.db", FileKind::File),
            ("~/.ssh/id_rsa", FileKind::File),
            ("~/.aws/credentials", FileKind::File),
            ("~/.docker/config.json", FileKind::File),
            ("~/.npmrc", FileKind::File),
            ("projects/app/.env", FileKind::File),
            ("projects/app/.netrc", FileKind::File),
            ("projects/app/id_rsa", FileKind::File),
            ("projects/app/config/credentials.json", FileKind::File),
            ("projects/app/secrets.yaml", FileKind::File),
            ("projects/app/service-account.json", FileKind::File),
            ("projects/app/kubeconfig", FileKind::File),
            ("projects/app/resume.pdf", FileKind::File),
            ("projects/app/tax-return.pdf", FileKind::File),
            ("projects/app/family-photo.jpg", FileKind::File),
            ("projects/app/notes.docx", FileKind::File),
        ]
        .into_iter()
        .map(|(path, kind)| (PathBuf::from(path), kind))
        .collect()
    }

    #[test]
    fn min_age_days_directory_uses_newest_in_subtree() {
        use std::fs;
        let temp = tempfile::Builder::new()
            .prefix("cleanton-recipes-")
            .tempdir_in(std::env::current_dir().expect("current dir"))
            .expect("tempdir");
        let dir = temp.path().join("old_dir");
        fs::create_dir(&dir).expect("create dir");

        let file = dir.join("new_file.txt");
        fs::write(&file, "recent").expect("write file");

        let recipe = test_recipe(MatchSpec {
            directory_name: Some("old_dir".to_owned()),
            min_age_days: Some(7),
            ..MatchSpec::default()
        });

        // Set modification time of the file to now (recent)
        let _ = fs::OpenOptions::new()
            .write(true)
            .open(&file)
            .and_then(|f| f.set_modified(SystemTime::now()));

        let mut entry = test_entry(&dir, FileKind::Directory);
        // Set the directory's own modification time to 10 days ago (old)
        let ten_days_ago = SystemTime::now() - Duration::from_hours(240);
        entry.modified = Some(ten_days_ago);

        // It should NOT match, because there is a recent file in the subtree
        assert!(!recipe_matches_entry(&recipe, &entry));

        // Set the file's modification time to 10 days ago (old)
        let _ = fs::OpenOptions::new()
            .write(true)
            .open(&file)
            .and_then(|f| f.set_modified(ten_days_ago));

        // Now it should match, because all files in the subtree are old
        assert!(recipe_matches_entry(&recipe, &entry));
    }

    #[test]
    fn compiled_matcher_matches_sequential_builtin_behavior() {
        let set = RecipeSet::load_builtin().expect("builtin recipes");
        let mut ordered = set
            .iter()
            .filter(|doc| doc.recipe.enabled)
            .collect::<Vec<_>>();
        ordered.sort_by_key(|doc| std::cmp::Reverse(doc.recipe.priority));
        let compiled = CompiledRecipeMatcher::new(&ordered);

        let sample_paths = [
            ("~/Library/Caches/pip", FileKind::Directory),
            ("~/Library/Caches/pip/http/wheel.whl", FileKind::File),
            ("~/.cache/pip/http/wheel.whl", FileKind::File),
            ("~/Projects/app/__pycache__", FileKind::Directory),
            ("~/Projects/app/__pycache__/mod.cpython-312.pyc", FileKind::File),
            ("~/Projects/app/target", FileKind::Directory),
            ("~/Projects/app/node_modules", FileKind::Directory),
            ("~/Projects/app/src/main.rs", FileKind::File),
            ("~/Projects/app/.env", FileKind::File),
            ("~/Documents/secret/target", FileKind::Directory),
            ("~/Models/llama-3.gguf", FileKind::File),
        ];

        let mut buf = Vec::new();
        for (raw, kind) in sample_paths {
            let mut candidate = test_entry(expand_tilde(Path::new(raw)), kind);
            candidate.allocated_bytes = 256 * 1_048_576;
            candidate.logical_bytes = candidate.allocated_bytes;
            candidate.modified = Some(SystemTime::now() - Duration::from_hours(24 * 120));

            let marker_fn = |_: &Path, marker: &str| {
                matches!(marker, "Cargo.toml" | "package.json" | "pyproject.toml")
            };
            let mtime_fn = |_: &Path| candidate.modified;

            let expected = ordered.iter().copied().find_map(|recipe| {
                action_for_entry_with_context(recipe, &candidate, marker_fn, mtime_fn)
            });
            let actual = compiled.first_matching_action(
                &candidate,
                &mut buf,
                |_| false,
                marker_fn,
                mtime_fn,
            );
            assert_eq!(
                actual.as_ref().map(|a| &a.recipe_id),
                expected.as_ref().map(|a| &a.recipe_id),
                "mismatch for {raw}"
            );
        }
    }
}
