use std::{cmp::Reverse, path::Path, time::Instant};

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use cleanton_common::{CleantonConfig, CleanupAction, CleanupPlan, FileKind, ScanResult};
use cleanton_ml::MlEngine;
use cleanton_recipes::{RecipeSet, action_for_entry_with_subtree_mtime};

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
    orphans: Vec<AnnotatedAction>,
) -> AnalyzedPlan {
    let started = Instant::now();

    // 1. Recipe matching (unchanged): the matcher already enforces ProtectedPaths
    //    + the sensitive-basename floor, so only cleared candidates appear here.
    let recipe_actions = match_recipes(scan, recipes);

    // 2. ML adjustment: demote unsafe-looking candidates, annotate the rest.
    let adjusted = adjust_actions(classifier, threshold, recipe_actions, scan);

    // 3. Assemble the executable action set: ML-kept candidates + orphans. ML can
    //    only ever shrink this set; it never introduces targets.
    let mut executable: Vec<CleanupAction> = adjusted
        .kept
        .iter()
        .map(|annotated| annotated.action.clone())
        .collect();
    executable.extend(orphans.iter().map(|annotated| annotated.action.clone()));

    // 4. The planner re-applies ProtectedPaths and breadth checks downstream.
    let plan = crate::planner::plan_from_actions(config, executable, scan, started.elapsed());

    // 5. Annotations for everything that could reach the plan.
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
    // `node_modules` / `target`). One O(entries × depth) pass over in-memory
    // data replaces all of it.
    let newest = newest_subtree_mtimes(scan);

    // Matching stays single-threaded on purpose: the per-match work is dominated
    // by a process-wide compiled-glob cache, and fanning this loop across the CPU
    // pool turned that cache's lock into a contention hot spot that ran *slower*
    // than serial. First matching recipe wins per entry.
    scan.entries
        .iter()
        .filter_map(|entry| {
            ordered.iter().copied().find_map(|recipe| {
                action_for_entry_with_subtree_mtime(recipe, entry, |dir| newest.get(dir).copied())
            })
        })
        .collect()
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

    let mut newest: HashMap<&Path, SystemTime> = HashMap::with_capacity(dirs.len());
    for entry in &scan.entries {
        let Some(modified) = entry.modified else {
            continue;
        };
        for ancestor in entry.path.ancestors() {
            if !dirs.contains(ancestor) {
                continue;
            }
            newest
                .entry(ancestor)
                .and_modify(|current| {
                    if modified > *current {
                        *current = modified;
                    }
                })
                .or_insert(modified);
        }
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
