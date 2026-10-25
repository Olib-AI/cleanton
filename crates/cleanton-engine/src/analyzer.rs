use std::{
    cell::{Cell, RefCell},
    cmp::Reverse,
    path::{Path, PathBuf},
    time::Instant,
};

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use cleanton_common::{CleantonConfig, CleanupAction, CleanupPlan, FileKind, ScanResult};
use cleanton_ml::MlEngine;
use cleanton_recipes::{
    DirectoryGate, RecipeDocument, RecipeSet, action_for_entry_with_context,
    directory_gate_with_context, recipe_has_gates,
};

use crate::ml::{
    ActionAnnotation, AnnotatedAction, DEFAULT_ML_CONFIDENCE_THRESHOLD, FileClassifier,
    adjust_actions,
};

/// The full analysis outcome: an executable [`CleanupPlan`] plus the ML
/// annotations and the items ML/orphan-detection set aside for explicit
/// confirmation.
#[derive(Debug, Clone)]
pub struct AnalyzedPlan {
    /// The executable proposal: recipe candidates ML kept, plus orphan
    /// candidates. Protected-path filtering is applied by the planner.
    pub plan: CleanupPlan,
    /// Every action that reached the plan, with its ML / orphan annotation.
    pub annotations: Vec<AnnotatedAction>,
    /// Recipe candidates ML demoted: NOT in `plan`, require explicit confirmation.
    pub held: Vec<AnnotatedAction>,
    /// Orphaned application-data candidates (also represented in `plan.actions`),
    /// trash-only and confirmation-required.
    pub orphans: Vec<AnnotatedAction>,
}

impl AnalyzedPlan {
    /// Look up the annotation recorded for a planned action target.
    #[must_use]
    pub fn annotation(&self, target: &Path) -> Option<&ActionAnnotation> {
        self.annotations
            .iter()
            .find(|annotated| annotated.action.target == target)
            .map(|annotated| &annotated.annotation)
    }
}

pub(crate) fn analyze_scan(
    config: &CleantonConfig,
    scan: &ScanResult,
    recipes: &RecipeSet,
) -> CleanupPlan {
    // Real, embedded ML classifier; falls back cleanly to recipe-only behaviour
    // if the backend is unavailable (every action is then `NotEvaluated`).
    let classifier = MlEngine::embedded();
    let orphans = crate::orphans::detect_orphans(config);
    analyze_with(
        config,
        scan,
        recipes,
        &classifier,
        DEFAULT_ML_CONFIDENCE_THRESHOLD,
        orphans,
    )
    .plan
}

/// Core analysis pipeline, with the classifier and orphan candidates injected so
/// it can be exercised deterministically in tests.
pub(crate) fn analyze_with<C: FileClassifier>(
    config: &CleantonConfig,
    scan: &ScanResult,
    recipes: &RecipeSet,
    classifier: &C,
    threshold: f32,
    mut orphans: Vec<AnnotatedAction>,
) -> AnalyzedPlan {
    let started = Instant::now();

    // 0. Advisory ML badges for orphan candidates (display only; orphans stay
    //    trash-only and confirmation-required regardless of the verdict).
    crate::ml::annotate_orphans(classifier, &mut orphans);

    // 1. Recipe matching (unchanged): the matcher already enforces ProtectedPaths
    //    + the sensitive-basename floor, so only cleared candidates appear here.
    let recipe_actions = match_recipes(scan, recipes);

    // 2. Assemble the executable action set: recipe candidates + orphans. ML is
    //    advisory and never gates, so the planner sees every candidate.
    let mut executable: Vec<CleanupAction> = recipe_actions;
    executable.extend(orphans.iter().map(|annotated| annotated.action.clone()));

    // 3. The planner re-applies ProtectedPaths, dedups, and drops candidates
    //    nested inside another selected target.
    let mut plan = crate::planner::plan_from_actions(config, executable, scan, started.elapsed());

    // 4. Advisory ML annotation of the SURVIVING plan actions. Annotating after
    //    the planner matters: on real scans most raw candidates are descendants
    //    that the planner subsumes into their ancestor action, and spending the
    //    bounded inference budget on them left the visible plan largely
    //    unbadged. Orphans were already annotated above and keep their badge.
    let orphan_targets: HashSet<&Path> = orphans
        .iter()
        .map(|annotated| annotated.action.target.as_path())
        .collect();
    let (recipe_planned, orphan_planned): (Vec<CleanupAction>, Vec<CleanupAction>) = plan
        .actions
        .iter()
        .cloned()
        .partition(|action| !orphan_targets.contains(action.target.as_path()));
    let adjusted = adjust_actions(classifier, threshold, recipe_planned, scan);

    // 5. Rebuild the plan's actions so the `[ML ...]` badge lands on `reason`,
    //    restoring the planner's largest-first presentation order.
    let mut planned: Vec<CleanupAction> = adjusted
        .kept
        .iter()
        .map(|annotated| annotated.action.clone())
        .collect();
    planned.extend(orphan_planned);
    planned.sort_by_key(|action| Reverse(action.reclaimable_bytes));
    plan.actions = planned;

    // 6. Annotations for everything in the plan.
    let mut annotations = adjusted.kept;
    annotations.extend(orphans.iter().cloned());

    AnalyzedPlan {
        plan,
        annotations,
        held: adjusted.held,
        orphans,
    }
}

fn match_recipes(scan: &ScanResult, recipes: &RecipeSet) -> Vec<CleanupAction> {
    let mut ordered = recipes
        .iter()
        .filter(|recipe| recipe.recipe.enabled)
        .collect::<Vec<_>>();
    ordered.sort_by_key(|recipe| Reverse(recipe.recipe.priority));

    // Precompute, from the scan we already performed, the newest modification
    // time within each scanned directory's subtree. `min_age_days` directory
    // recipes need this; without it the matcher re-walks every matched
    // directory's subtree from disk (an O(n²) `stat` storm on trees full of
    // `node_modules` / `target`). One O(entries) pass over in-memory data
    // replaces all of it.
    let newest = newest_subtree_mtimes(scan);

    // Memoized "does this directory contain <marker>?" probe. Without it the
    // matcher runs one `stat(2)` per (entry, recipe) pair for every
    // `parent_must_contain` / `self_must_contain` recipe — tens of millions of
    // syscalls on a home-sized scan, and the single biggest cost of the
    // post-scan analysis.
    let markers = MarkerCache::new(ordered.iter().copied());

    // Per recipe, the directory roots it must not reach inside of (see
    // `suppressed_roots`).
    let suppressed = suppressed_roots(scan, &ordered, &newest, &markers);

    // Matching stays single-threaded on purpose: the per-match work is dominated
    // by a process-wide compiled-glob cache, and fanning this loop across the CPU
    // pool turned that cache's lock into a contention hot spot that ran *slower*
    // than serial. First matching recipe wins per entry.
    scan.entries
        .iter()
        .filter_map(|entry| {
            ordered
                .iter()
                .copied()
                .enumerate()
                .find_map(|(index, recipe)| {
                    // Suppression is per recipe, not global: another recipe with
                    // its own intent (say a stray model file) may still legitimately
                    // match inside this directory, so we fall through rather than
                    // skipping the entry outright.
                    if suppressed
                        .get(index)
                        .is_some_and(|roots| is_under_suppressed_root(&entry.path, roots))
                    {
                        return None;
                    }
                    action_for_entry_with_context(
                        recipe,
                        entry,
                        |dir, marker| markers.contains(dir, marker),
                        |dir| newest.get(dir).copied(),
                    )
                })
        })
        .collect()
}

/// Marker bitmaps per directory, memoized for one analysis pass.
///
/// The matcher's context proofs (`parent_must_contain`, `parent_must_contain_any`,
/// `self_must_contain`) ask "does this directory contain `<marker>`?" once per
/// (entry, recipe) pair, which on a home-sized scan means millions of `stat(2)`
/// calls for the same few dozen (directory, marker) combinations. Answers are
/// memoized per directory in two bitmaps — probed markers and existing markers —
/// so each pair costs at most one syscall, once. `overflow` (more than 64
/// distinct markers, e.g. after a user adds many custom recipes) falls back to
/// probing directly, which is always correct.
#[derive(Debug, Default, Clone, Copy)]
struct DirProbe {
    probed: u64,
    exists: u64,
}

#[derive(Debug)]
struct MarkerCache<'a> {
    markers: HashMap<&'a str, usize>,
    probes: RefCell<HashMap<PathBuf, DirProbe>>,
    /// Most recently probed directory (scan entries arrive per directory, so
    /// this hit rate is high and it skips the map lookup entirely).
    last_dir: RefCell<Option<PathBuf>>,
    last_probe: Cell<DirProbe>,
    overflow: bool,
}

impl<'a> MarkerCache<'a> {
    fn new<'r>(recipes: impl Iterator<Item = &'r RecipeDocument>) -> Self
    where
        'r: 'a,
    {
        let mut markers: HashMap<&'a str, usize> = HashMap::new();
        let mut overflow = false;
        for recipe in recipes {
            for spec in std::iter::once(&recipe.matcher).chain(recipe.matcher.any_of.iter()) {
                for marker in spec
                    .parent_must_contain
                    .iter()
                    .flatten()
                    .chain(spec.parent_must_contain_any.iter().flatten())
                    .chain(spec.self_must_contain.iter().flatten())
                {
                    if markers.contains_key(marker.as_str()) {
                        continue;
                    }
                    if markers.len() >= u64::BITS as usize {
                        overflow = true;
                        continue;
                    }
                    let bit = markers.len();
                    markers.insert(marker.as_str(), bit);
                }
            }
        }
        Self {
            markers,
            probes: RefCell::new(HashMap::new()),
            last_dir: RefCell::new(None),
            last_probe: Cell::new(DirProbe::default()),
            overflow,
        }
    }

    /// True when `dir` contains `marker`. Falls back to a direct `stat` for
    /// markers outside the bit budget.
    fn contains(&self, dir: &Path, marker: &str) -> bool {
        let Some(&bit) = self.markers.get(marker) else {
            return dir.join(marker).exists();
        };
        if self.overflow {
            return dir.join(marker).exists();
        }

        let mask = 1_u64 << bit;
        // Scope the shared borrow: an `if`-condition temporary would otherwise
        // stay alive into the block and panic on the `borrow_mut` below.
        let is_last = {
            let last = self.last_dir.borrow();
            last.as_deref() == Some(dir)
        };
        let cached = if is_last {
            self.last_probe.get()
        } else {
            let known = self.probes.borrow().get(dir).copied().unwrap_or_default();
            *self.last_dir.borrow_mut() = Some(dir.to_path_buf());
            known
        };

        let mut probe = cached;
        if probe.probed & mask == 0 {
            probe.probed |= mask;
            if dir.join(marker).exists() {
                probe.exists |= mask;
            }
            self.probes.borrow_mut().insert(dir.to_path_buf(), probe);
        }
        self.last_probe.set(probe);
        probe.exists & mask != 0
    }
}

/// For each recipe (parallel to `ordered`), the directories whose gate it failed.
///
/// A recipe whose glob selects a directory *and* everything beneath it means
/// "this directory, as a unit". When its size/age gate rejects the directory,
/// the recipe must not then act on the directory's contents individually: that
/// inverts the gate's intent (shredding an actively-used cache the gate was
/// protecting) and replaces one folder action with thousands of per-file ones.
/// Only gated recipes can fail a gate, so the rest are skipped without touching
/// a single directory.
fn suppressed_roots<'a>(
    scan: &'a ScanResult,
    ordered: &[&RecipeDocument],
    newest: &HashMap<&Path, SystemTime>,
    markers: &MarkerCache<'_>,
) -> Vec<HashSet<&'a Path>> {
    ordered
        .iter()
        .map(|recipe| {
            if !recipe_has_gates(recipe) {
                return HashSet::new();
            }
            scan.entries
                .iter()
                .filter(|entry| entry.kind == FileKind::Directory)
                .filter(|entry| {
                    directory_gate_with_context(
                        recipe,
                        entry,
                        |dir, marker| markers.contains(dir, marker),
                        |dir| newest.get(dir).copied(),
                    ) == DirectoryGate::GateFailed
                })
                .map(|entry| entry.path.as_path())
                .collect()
        })
        .collect()
}

/// True when `path` is a suppressed root or lives beneath one. The root itself is
/// included: it failed its own gate, so it is not a candidate either way.
fn is_under_suppressed_root(path: &Path, roots: &HashSet<&Path>) -> bool {
    if roots.is_empty() {
        return false;
    }
    path.ancestors().any(|ancestor| roots.contains(ancestor))
}

/// For every scanned directory, the newest `modified` time anywhere in its
/// subtree (including itself), derived purely from the in-memory scan. Each
/// entry's mtime is propagated up to its ancestor directories that were
/// themselves scanned; non-directory ancestors and paths outside the scan are
/// ignored.
fn newest_subtree_mtimes(scan: &ScanResult) -> HashMap<&Path, SystemTime> {
    let dirs: HashSet<&Path> = scan
        .entries
        .iter()
        .filter(|entry| entry.kind == FileKind::Directory)
        .map(|entry| entry.path.as_path())
        .collect();

    // One lookup per entry: each entry's mtime is folded into its direct parent
    // (and into itself when it IS a scanned directory), then the directories are
    // reduced deepest-first. The previous version walked every ancestor of every
    // entry, hashing the full path at each level — O(entries x depth) hash
    // lookups on the analysis hot path for the same result.
    let mut newest: HashMap<&Path, SystemTime> = HashMap::with_capacity(dirs.len());
    for entry in &scan.entries {
        let Some(modified) = entry.modified else {
            continue;
        };
        if entry.kind == FileKind::Directory && dirs.contains(entry.path.as_path()) {
            newest
                .entry(entry.path.as_path())
                .and_modify(|current| {
                    if modified > *current {
                        *current = modified;
                    }
                })
                .or_insert(modified);
        }
        if let Some(parent) = entry.path.parent()
            && dirs.contains(parent)
        {
            newest
                .entry(parent)
                .and_modify(|current| {
                    if modified > *current {
                        *current = modified;
                    }
                })
                .or_insert(modified);
        }
    }

    // Reduce bottom-up: a directory's subtree newest must reach its ancestors.
    let mut order: Vec<&Path> = dirs.iter().copied().collect();
    order.sort_unstable_by_key(|dir| Reverse(dir.components().count()));
    for dir in order {
        let Some(modified) = newest.get(dir).copied() else {
            continue;
        };
        let Some(parent) = dir.parent() else {
            continue;
        };
        if !dirs.contains(parent) {
            continue;
        }
        newest
            .entry(parent)
            .and_modify(|current| {
                if modified > *current {
                    *current = modified;
                }
            })
            .or_insert(modified);
    }
    newest
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing into expected results clearer.
    #![allow(clippy::indexing_slicing)]
    use std::{path::PathBuf, time::Duration};

    use cleanton_common::{FileEntry, FileKind, ScanResult};
    use cleanton_ml::{CleanupLabel, FileContext, MlClassification, MlResult};

    use crate::ml::MlAdjustment;

    use super::*;

    struct Fixed(CleanupLabel, f32);
    impl FileClassifier for Fixed {
        fn classify(&self, _e: &FileEntry, _c: &FileContext) -> MlResult<MlClassification> {
            Ok(MlClassification {
                label: self.0,
                confidence: self.1,
            })
        }
    }

    fn cache_entry(path: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            kind: FileKind::File,
            logical_bytes: 4096,
            allocated_bytes: 4096,
            modified: None,
            depth: 5,
            device_id: None,
            inode: None,
            hardlink_count: None,
            symlink_target: None,
            ignored_by_git: false,
        }
    }

    fn scan(entries: Vec<FileEntry>) -> ScanResult {
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

    /// An isolated `RecipeSet` containing only a permissive cache recipe, so the
    /// end-to-end pipeline is exercised deterministically (built-in recipes need
    /// on-disk parent markers we cannot materialise here).
    fn permissive_recipe_set() -> (tempfile::TempDir, RecipeSet) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("permissive.toml"),
            r#"
[recipe]
id = "permissive-cache"
name = "Permissive Cache"
description = "permissive cache"
category = "test"
safety_level = "safe"
enabled = true
priority = 50

[match]
path_glob = "**/cache/**"

[action]
type = "trash"
prompt = "Trash?"

[test]
should_match = ["project/cache/item"]
should_not_match = ["project/src/item"]
"#,
        )
        .expect("write recipe");
        let mut set = RecipeSet::default();
        set.load_from_dir(dir.path()).expect("load recipe");
        (dir, set)
    }

    #[test]
    fn ml_is_advisory_and_never_removes_recipe_candidates() {
        let (_dir, recipes) = permissive_recipe_set();
        let scan = scan(vec![cache_entry("/Users/x/proj/cache/blob.bin")]);

        // Clean verdict: the candidate is planned and annotated.
        let kept = analyze_with(
            &CleantonConfig::default(),
            &scan,
            &recipes,
            &Fixed(CleanupLabel::SafeToRemove, 0.99),
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            Vec::new(),
        );
        assert_eq!(
            kept.plan.actions.len(),
            1,
            "clean candidate must be planned"
        );

        // `keep` verdict: ML is advisory, so the SAME candidate still stays on
        // the executable plan (recipes decide; ML only informs). Nothing is
        // held back by ML.
        let advisory = analyze_with(
            &CleantonConfig::default(),
            &scan,
            &recipes,
            &Fixed(CleanupLabel::Keep, 0.99),
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            Vec::new(),
        );
        assert_eq!(
            advisory.plan.actions.len(),
            1,
            "ML keep verdict must NOT remove a curated recipe candidate"
        );
        assert!(advisory.held.is_empty());
        assert_eq!(
            advisory.annotations[0].annotation.ml_label,
            Some(CleanupLabel::Keep)
        );
    }

    /// A gated cache recipe shaped like the real ones: a `**` glob that selects
    /// the cache directory AND everything beneath it, plus an age gate.
    fn aged_cache_recipe_set() -> (tempfile::TempDir, RecipeSet) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("aged.toml"),
            r#"
[recipe]
id = "aged-cache"
name = "Aged Cache"
description = "aged cache"
category = "test"
safety_level = "safe"
enabled = true
priority = 50

[match]
path_glob = "**/cache/**"
min_age_days = 30

[action]
type = "trash"
prompt = "Trash?"

[test]
should_match = ["project/cache/item"]
should_not_match = ["project/src/item"]
"#,
        )
        .expect("write recipe");
        let mut set = RecipeSet::default();
        set.load_from_dir(dir.path()).expect("load recipe");
        (dir, set)
    }

    fn aged_entry(path: &str, kind: FileKind, days_old: u64) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            kind,
            logical_bytes: 4096,
            allocated_bytes: 4096,
            modified: Some(
                SystemTime::now() - Duration::from_secs(days_old.saturating_mul(24 * 60 * 60)),
            ),
            depth: 5,
            device_id: None,
            inode: None,
            hardlink_count: None,
            symlink_target: None,
            ignored_by_git: false,
        }
    }

    /// The cache folder and 200 old files inside it, plus `extra` entries.
    fn cache_tree(extra: Vec<FileEntry>) -> Vec<FileEntry> {
        let mut entries = vec![aged_entry(
            "/Users/x/proj/cache/blobs",
            FileKind::Directory,
            365,
        )];
        entries.extend((0..200).map(|i| {
            aged_entry(
                &format!("/Users/x/proj/cache/blobs/old-{i}.bin"),
                FileKind::File,
                365,
            )
        }));
        entries.extend(extra);
        entries
    }

    fn planned_under_cache(recipes: &RecipeSet, entries: Vec<FileEntry>) -> Vec<PathBuf> {
        let plan = crate::planner::plan_from_actions(
            &CleantonConfig::default(),
            match_recipes(&scan(entries), recipes),
            &scan(Vec::new()),
            Duration::ZERO,
        );
        plan.actions
            .iter()
            .map(|action| action.target.clone())
            .filter(|target| target.starts_with("/Users/x/proj"))
            .collect()
    }

    /// A wholly-unused cache is planned as ONE folder action, not N per-file
    /// actions: the planner subsumes the contents into the directory, and the
    /// executor trashes it with a single `trash::delete`.
    #[test]
    fn unused_cache_folder_is_planned_as_a_single_action() {
        let (_dir, recipes) = aged_cache_recipe_set();

        let targets = planned_under_cache(&recipes, cache_tree(Vec::new()));

        assert_eq!(targets, vec![PathBuf::from("/Users/x/proj/cache/blobs")]);
    }

    /// The regression this guards: ONE recently touched file makes the cache
    /// directory fail its age gate, but must NOT cause the recipe to fall back to
    /// trashing the 200 individually-old files inside it. That inverted the gate's
    /// intent (shredding an in-use cache) and turned 1 action into 200.
    #[test]
    fn in_use_cache_folder_never_decomposes_into_per_file_actions() {
        let (_dir, recipes) = aged_cache_recipe_set();

        let targets = planned_under_cache(
            &recipes,
            cache_tree(vec![aged_entry(
                "/Users/x/proj/cache/blobs/fresh.bin",
                FileKind::File,
                0,
            )]),
        );

        assert!(
            targets.is_empty(),
            "an in-use cache must be left alone, got {} action(s): {:?}",
            targets.len(),
            targets.iter().take(3).collect::<Vec<_>>()
        );
    }

    /// Suppression is scoped to the recipe that failed the gate. An unrelated
    /// recipe with its own intent still matches inside the same directory.
    #[test]
    fn suppression_does_not_block_an_unrelated_recipe() {
        let (_dir, mut recipes) = aged_cache_recipe_set();
        let extra = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            extra.path().join("models.toml"),
            r#"
[recipe]
id = "stray-model"
name = "Stray Model"
description = "stray model weights"
category = "test"
safety_level = "safe"
enabled = true
priority = 10

[match]
path_glob = "**/*.gguf"

[action]
type = "trash"
prompt = "Trash?"

[test]
should_match = ["a/model.gguf"]
should_not_match = ["a/model.txt"]
"#,
        )
        .expect("write recipe");
        recipes.load_from_dir(extra.path()).expect("load recipe");

        let targets = planned_under_cache(
            &recipes,
            cache_tree(vec![
                aged_entry("/Users/x/proj/cache/blobs/fresh.bin", FileKind::File, 0),
                aged_entry("/Users/x/proj/cache/blobs/model.gguf", FileKind::File, 1),
            ]),
        );

        assert_eq!(
            targets,
            vec![PathBuf::from("/Users/x/proj/cache/blobs/model.gguf")],
            "the ungated recipe must still match inside a suppressed directory"
        );
    }

    /// A `dir/**` recipe with no gate -- the `python-bytecode` shape. The folder
    /// must be the single action; its files must not be planned individually.
    #[test]
    fn dir_glob_recipe_plans_the_folder_not_its_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("pyc.toml"),
            r#"
[recipe]
id = "python-bytecode"
name = "Python Bytecode"
description = "Python __pycache__ directories and bytecode files"
category = "python"
safety_level = "safe"
enabled = true
priority = 70

[match]
path_glob = "**/__pycache__/**"

[action]
type = "trash"
prompt = "Trash?"

[test]
should_match = ["api/__pycache__/m.cpython-311.pyc"]
should_not_match = ["api/m.py"]
"#,
        )
        .expect("write recipe");
        let mut recipes = RecipeSet::default();
        recipes.load_from_dir(dir.path()).expect("load recipe");

        let mut entries = vec![aged_entry(
            "/Users/x/proj/api/__pycache__",
            FileKind::Directory,
            1,
        )];
        entries.extend((0..50).map(|i| {
            aged_entry(
                &format!("/Users/x/proj/api/__pycache__/m{i}.cpython-311.pyc"),
                FileKind::File,
                1,
            )
        }));

        let targets = planned_under_cache(&recipes, entries);

        assert_eq!(
            targets,
            vec![PathBuf::from("/Users/x/proj/api/__pycache__")],
            "the folder must be trashed as one unit, not file by file"
        );
    }

    /// An age-gated `dir/**` recipe (the `ms-playwright` shape) must keep
    /// reclaiming its stale subdirectories one whole folder at a time, even when
    /// a sibling is in active use. Hoisting the recipe to the cache root would
    /// gate the whole cache on its freshest file and reclaim nothing.
    #[test]
    fn age_gated_recipe_still_reclaims_stale_subfolders() {
        let (_dir, recipes) = aged_cache_recipe_set();

        let entries = vec![
            aged_entry("/Users/x/proj/cache", FileKind::Directory, 0),
            // Stale browser build: must still be reclaimed, as ONE folder.
            aged_entry("/Users/x/proj/cache/old-build", FileKind::Directory, 365),
            aged_entry("/Users/x/proj/cache/old-build/bin", FileKind::File, 365),
            // Sibling in active use: must be left alone.
            aged_entry("/Users/x/proj/cache/live-build", FileKind::Directory, 0),
            aged_entry("/Users/x/proj/cache/live-build/bin", FileKind::File, 0),
        ];

        let targets = planned_under_cache(&recipes, entries);

        assert_eq!(
            targets,
            vec![PathBuf::from("/Users/x/proj/cache/old-build")],
            "the stale subfolder must be reclaimed as one action, the live one untouched"
        );
    }

    #[test]
    fn every_planned_action_carries_an_ml_annotation() {
        let (_dir, recipes) = permissive_recipe_set();
        let scan = scan(vec![cache_entry("/Users/x/proj/cache/blob.bin")]);

        let analyzed = analyze_with(
            &CleantonConfig::default(),
            &scan,
            &recipes,
            &Fixed(CleanupLabel::SafeToRemove, 0.99),
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            Vec::new(),
        );

        assert_eq!(analyzed.plan.actions.len(), 1);
        for action in &analyzed.plan.actions {
            let annotation = analyzed
                .annotation(&action.target)
                .expect("every planned action must be annotated");
            assert_eq!(annotation.ml_label, Some(CleanupLabel::SafeToRemove));
            assert!(annotation.ml_confidence.is_some());
            assert_eq!(annotation.adjustment, MlAdjustment::Confirmed);
        }
    }
}
