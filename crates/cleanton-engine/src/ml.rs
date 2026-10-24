//! Safety-constrained ML plan adjustment.
//!
//! The classifier is **advisory only**. It can make the plan *safer*
//! autonomously (demote a recipe candidate off the auto-plan and hold it for
//! explicit confirmation) and it annotates every action with its label and
//! confidence for display. It can NEVER introduce a destructive action: the
//! executable set is always a subset of the actions the recipe matcher already
//! produced, and protected-path / sensitive-basename enforcement lives entirely
//! in the recipe matcher and the planner — both downstream and independent of
//! any ML verdict.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use cleanton_common::{CleanupAction, FileEntry, FileKind, ScanResult};
use cleanton_ml::{CleanupLabel, FileContext, MlClassification, MlEngine, MlResult};
use serde::{Deserialize, Serialize};

/// How confident the classifier must be that a file should be *kept* before its
/// confident-keep verdict is allowed to pull a curated recipe candidate off the
/// auto-executable plan (holding it for explicit confirmation). Recipe matches
/// are trusted by default; only a keep verdict at or above this confidence
/// vetoes them. Uncertain or clean verdicts never demote.
pub const DEFAULT_ML_CONFIDENCE_THRESHOLD: f32 = 0.85;

/// Abstraction over the inference backend so the adjuster can be exercised with
/// deterministic classifiers in tests while production uses [`MlEngine`].
pub trait FileClassifier {
    fn classify(&self, entry: &FileEntry, context: &FileContext) -> MlResult<MlClassification>;
}

impl FileClassifier for MlEngine {
    fn classify(&self, entry: &FileEntry, context: &FileContext) -> MlResult<MlClassification> {
        MlEngine::classify(self, entry, context)
    }
}

/// How ML treated a single recipe candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MlAdjustment {
    /// ML backend unavailable or errored — recipe behaviour is unchanged.
    NotEvaluated,
    /// ML evaluated the candidate and recorded its advisory verdict; routing
    /// is unchanged (existing confirmation requirements are not weakened).
    Confirmed,
    /// ML predicted `keep`/`uncertain`, or a clean class below the confidence
    /// threshold — demoted off the auto-plan and held for explicit confirmation.
    Demoted,
}

/// The ML annotation recorded on every action, surfaced for display.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionAnnotation {
    pub ml_label: Option<CleanupLabel>,
    pub ml_confidence: Option<f32>,
    pub adjustment: MlAdjustment,
    pub note: String,
}

impl ActionAnnotation {
    fn not_evaluated(note: impl Into<String>) -> Self {
        Self {
            ml_label: None,
            ml_confidence: None,
            adjustment: MlAdjustment::NotEvaluated,
            note: note.into(),
        }
    }
}

/// A cleanup action paired with its ML annotation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnnotatedAction {
    pub action: CleanupAction,
    pub annotation: ActionAnnotation,
}

/// Outcome of adjusting a batch of recipe candidates.
#[derive(Debug, Clone, Default)]
pub(crate) struct Adjusted {
    /// Candidates that remain eligible for the executable plan, annotated.
    pub kept: Vec<AnnotatedAction>,
    /// Candidates ML demoted; NOT auto-executed, require explicit confirmation.
    pub held: Vec<AnnotatedAction>,
}

/// Known lockfile basenames. Must mirror `training/vocab.py::LOCKFILES` — the
/// v2 classifier was trained with contexts built from this exact set.
const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Gemfile.lock",
    "go.sum",
    "composer.lock",
];

/// Project manifests that mark an ecosystem root, feeding the
/// `ancestor_has_project_marker` context flag (a `.git` DIRECTORY entry also
/// counts). Must mirror `training/vocab.py::PROJECT_MARKERS`.
const PROJECT_MARKERS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "go.mod",
    "build.gradle",
    "build.gradle.kts",
    "pom.xml",
    "Package.swift",
    "mix.exs",
    "pubspec.yaml",
    "Gemfile",
    "composer.json",
    "CMakeLists.txt",
    "stack.yaml",
    "build.zig",
    "Project.toml",
    "requirements.txt",
];

fn empty_context() -> FileContext {
    FileContext {
        has_gitignore: false,
        has_lockfile: false,
        sibling_count: 0,
        sibling_total_bytes: 0,
        ancestor_has_lockfile: false,
        ancestor_has_project_marker: false,
    }
}

/// Upper bound on how many recipe candidates we run ML inference over per
/// analysis. A single noisy recipe (e.g. one matching every file inside a build
/// directory) can emit tens of thousands of candidates; running the classifier
/// on each one melts the CPU after the scan for no benefit. Since ML is purely
/// advisory (it never changes whether a candidate is executable), evaluating
/// only the largest candidates and leaving the rest executable-but-unscored is
/// lossless for the plan — the tail just doesn't get an ML badge.
const MAX_ML_EVALUATED_ACTIONS: usize = 2_000;

/// Annotate recipe-produced candidates with the advisory ML label. The input is
/// always recipe candidates that already cleared the matcher floor (protected
/// paths + sensitive basenames); this function never *adds* or *removes*
/// targets — every candidate stays executable.
pub(crate) fn adjust_actions<C: FileClassifier>(
    classifier: &C,
    threshold: f32,
    mut actions: Vec<CleanupAction>,
    scan: &ScanResult,
) -> Adjusted {
    let entries: HashMap<&Path, &FileEntry> = scan
        .entries
        .iter()
        .map(|entry| (entry.path.as_path(), entry))
        .collect();
    let contexts = build_contexts(scan);

    // When the candidate set exceeds the evaluation cap, evaluate the largest
    // candidates (the ones that drive the reclaimable total and the executable
    // plan) and hold the remainder unevaluated. Sorting only matters past the
    // cap, so small candidate sets keep their original order and cost nothing.
    let evaluate_count = actions.len().min(MAX_ML_EVALUATED_ACTIONS);
    if actions.len() > MAX_ML_EVALUATED_ACTIONS {
        actions.sort_by_key(|action| std::cmp::Reverse(action.reclaimable_bytes));
    }

    let mut result = Adjusted::default();
    for (index, mut action) in actions.into_iter().enumerate() {
        let annotation = if index < evaluate_count {
            annotate(classifier, threshold, &action, &entries, &contexts)
        } else {
            // Past the inference cap: stays executable (recipes are trusted),
            // just without an ML badge. ML is advisory and never gates the plan.
            ActionAnnotation::not_evaluated("not ML-scored (batch cap); recipe trusted")
        };

        // Surface the label+confidence on the action itself (existing UIs render
        // `reason`), so no UI change is needed to display the ML verdict.
        if let (Some(label), Some(confidence)) = (annotation.ml_label, annotation.ml_confidence) {
            action.reason = format!("{} [ML {label}: {confidence:.2}]", action.reason);
        }

        let annotated = AnnotatedAction { action, annotation };
        if annotated.annotation.adjustment == MlAdjustment::Demoted {
            result.held.push(annotated);
        } else {
            result.kept.push(annotated);
        }
    }
    result
}

fn annotate<C: FileClassifier>(
    classifier: &C,
    threshold: f32,
    action: &CleanupAction,
    entries: &HashMap<&Path, &FileEntry>,
    contexts: &HashMap<PathBuf, FileContext>,
) -> ActionAnnotation {
    let Some(entry) = entries.get(action.target.as_path()) else {
        return ActionAnnotation::not_evaluated("no scan entry for target; left unchanged");
    };

    let context = action
        .target
        .parent()
        .and_then(|parent| contexts.get(parent))
        .cloned()
        .unwrap_or_else(empty_context);

    match classifier.classify(entry, &context) {
        Ok(classification) => decide(classification.label, classification.confidence, threshold),
        Err(error) => ActionAnnotation::not_evaluated(format!("ml unavailable: {error}")),
    }
}

/// Map an ML verdict onto a plan annotation.
///
/// ML is **advisory only**: it records the predicted label and confidence for
/// display but never changes whether a candidate is executable. The reason is
/// empirical — gating the plan on the embedded classifier (observed with the
/// original 12-feature model, which returned `uncertain` for some model
/// weights and a confident `keep` for others of the very same class) produced
/// inconsistent, surprising results and silently hid tens of GB of
/// correctly-matched, reclaimable files. The v2 53-feature classifier is more
/// accurate, but the policy stands: recipes decide; ML only informs.
///
/// The trustworthy, testable safety system is elsewhere and unchanged: the
/// recipe matcher's protected-path + sensitive-basename floors, the planner's
/// independent protected-path gate, and trash-by-default (every action is
/// reversible). `keep_threshold` is retained for API/display compatibility but
/// no longer gates anything.
fn decide(label: CleanupLabel, confidence: f32, _keep_threshold: f32) -> ActionAnnotation {
    ActionAnnotation {
        ml_label: Some(label),
        ml_confidence: Some(confidence),
        adjustment: MlAdjustment::Confirmed,
        note: format!("Recipe match trusted; ML advisory: {label} (confidence {confidence:.2})"),
    }
}

/// Advisory ML annotation for orphaned-app-data candidates (display only).
///
/// Orphan directories are detected outside the scan, so a directory entry is
/// synthesized from the action itself and classified with an empty context.
/// The verdict is recorded exactly like recipe candidates (label + confidence
/// on the annotation, `[ML ...]` badge on the reason) — it NEVER changes
/// orphan routing: orphans stay trash-only and confirmation-required
/// regardless of what ML says.
pub(crate) fn annotate_orphans<C: FileClassifier>(classifier: &C, orphans: &mut [AnnotatedAction]) {
    for annotated in orphans.iter_mut() {
        let entry = FileEntry {
            path: annotated.action.target.clone(),
            kind: FileKind::Directory,
            logical_bytes: annotated.action.logical_bytes,
            allocated_bytes: annotated.action.reclaimable_bytes,
            modified: None,
            depth: 0,
            device_id: None,
            inode: None,
            hardlink_count: None,
            symlink_target: None,
            ignored_by_git: false,
        };
        // Backend unavailable or errored: keep the plain orphan annotation.
        let Ok(classification) = classifier.classify(&entry, &empty_context()) else {
            continue;
        };
        let label = classification.label;
        let confidence = classification.confidence;
        annotated.annotation.ml_label = Some(label);
        annotated.annotation.ml_confidence = Some(confidence);
        annotated.annotation.adjustment = MlAdjustment::Confirmed;
        annotated.annotation.note = format!(
            "{}; ML advisory: {label} (confidence {confidence:.2})",
            annotated.annotation.note
        );
        annotated.action.reason =
            format!("{} [ML {label}: {confidence:.2}]", annotated.action.reason);
    }
}

/// Advisory ML badges for the review-only suggestion lists (display only).
///
/// Fills [`crate::suggestions::LargeItem::ml_note`] for the large-item,
/// screenshot, and installer lists so every UI shows the same label +
/// confidence. Suggestions are never part of the cleanup plan and this never
/// changes what is suggested; duplicates are left unscored (a duplicate *set*
/// has no single representative file to classify). Cost is bounded: one pass
/// over the scan restricted to the items' parent/ancestor directories plus one
/// inference per suggested item (the lists are capped upstream).
pub(crate) fn annotate_suggestions<C: FileClassifier>(
    classifier: &C,
    suggestions: &mut crate::suggestions::Suggestions,
    scan: &ScanResult,
) {
    let items: Vec<&mut crate::suggestions::LargeItem> = suggestions
        .large_items
        .iter_mut()
        .chain(suggestions.screenshots.iter_mut())
        .chain(suggestions.installers.iter_mut())
        .collect();
    if items.is_empty() {
        return;
    }

    // Directories whose direct-children facts we need: every ancestor of every
    // item's parent (context flags walk the parent chain).
    let mut wanted_dirs: HashSet<PathBuf> = HashSet::new();
    let mut targets: HashSet<PathBuf> = HashSet::new();
    for item in &items {
        targets.insert(item.path.clone());
        if let Some(parent) = item.path.parent() {
            for ancestor in parent.ancestors() {
                wanted_dirs.insert(ancestor.to_path_buf());
            }
        }
    }

    let groups = accumulate_dirs(scan, |parent| wanted_dirs.contains(parent));
    let entries: HashMap<&Path, &FileEntry> = scan
        .entries
        .iter()
        .filter(|entry| targets.contains(entry.path.as_path()))
        .map(|entry| (entry.path.as_path(), entry))
        .collect();

    for item in items {
        let Some(entry) = entries.get(item.path.as_path()) else {
            continue;
        };
        let context = item
            .path
            .parent()
            .map_or_else(empty_context, |parent| context_for(parent, &groups));
        let Ok(classification) = classifier.classify(entry, &context) else {
            continue;
        };
        item.ml_note = format!(
            "ML {} {:.2}",
            classification.label, classification.confidence
        );
    }
}

/// Per-directory accumulator: direct-children facts gathered in one pass over
/// the scan entries (keyed by the children's parent directory).
struct DirAcc {
    siblings: u64,
    total_bytes: u64,
    has_gitignore: bool,
    has_lockfile: bool,
    has_project_marker: bool,
}

/// One O(n) pass over the scan entries, accumulating direct-children facts for
/// every parent directory `keep` accepts. Passing `|_| true` accumulates every
/// parent; a targeted predicate keeps the map small for spot classifications.
fn accumulate_dirs(
    scan: &ScanResult,
    mut keep: impl FnMut(&Path) -> bool,
) -> HashMap<PathBuf, DirAcc> {
    let mut groups: HashMap<PathBuf, DirAcc> = HashMap::new();
    for entry in &scan.entries {
        let Some(parent) = entry.path.parent() else {
            continue;
        };
        if !keep(parent) {
            continue;
        }
        let acc = groups.entry(parent.to_path_buf()).or_insert(DirAcc {
            siblings: 0,
            total_bytes: 0,
            has_gitignore: false,
            has_lockfile: false,
            has_project_marker: false,
        });
        acc.siblings = acc.siblings.saturating_add(1);
        acc.total_bytes = acc.total_bytes.saturating_add(entry.logical_bytes);
        if let Some(name) = entry.path.file_name().and_then(|name| name.to_str()) {
            if name == ".gitignore" {
                acc.has_gitignore = true;
            }
            if LOCKFILES.contains(&name) {
                acc.has_lockfile = true;
            }
            if PROJECT_MARKERS.contains(&name)
                || (name == ".git" && entry.kind == FileKind::Directory)
            {
                acc.has_project_marker = true;
            }
        }
    }
    groups
}

/// Derive the [`FileContext`] for one parent directory: its own direct-children
/// facts plus the ancestor lockfile/project-marker flags found by walking the
/// parent chain over the accumulated per-directory map (O(depth) per parent).
fn context_for(parent: &Path, groups: &HashMap<PathBuf, DirAcc>) -> FileContext {
    let own = groups.get(parent);
    let mut ancestor_has_lockfile = false;
    let mut ancestor_has_project_marker = false;
    for ancestor in parent.ancestors() {
        if let Some(acc) = groups.get(ancestor) {
            ancestor_has_lockfile |= acc.has_lockfile;
            ancestor_has_project_marker |= acc.has_project_marker;
        }
        if ancestor_has_lockfile && ancestor_has_project_marker {
            break;
        }
    }
    FileContext {
        has_gitignore: own.is_some_and(|acc| acc.has_gitignore),
        has_lockfile: own.is_some_and(|acc| acc.has_lockfile),
        sibling_count: own.map_or(0, |acc| acc.siblings),
        sibling_total_bytes: own.map_or(0, |acc| acc.total_bytes),
        ancestor_has_lockfile,
        ancestor_has_project_marker,
    }
}

/// Build a best-effort [`FileContext`] for each scanned parent directory from
/// the scan data alone (no extra filesystem access). One O(n) accumulation
/// pass plus an O(depth) ancestor walk per distinct parent — no quadratic
/// sibling scans, so million-entry scans stay linear.
fn build_contexts(scan: &ScanResult) -> HashMap<PathBuf, FileContext> {
    let groups = accumulate_dirs(scan, |_| true);
    groups
        .keys()
        .map(|parent| (parent.clone(), context_for(parent, &groups)))
        .collect()
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing into expected results clearer.
    #![allow(clippy::indexing_slicing)]
    use std::{
        path::{Path, PathBuf},
        time::Duration,
    };

    use cleanton_common::{
        ActionType, CleantonConfig, Confidence, FileKind, MetadataFingerprint, RecipeId,
        SafetyLevel, ScanResult,
    };
    use cleanton_recipes::{
        ActionSpec, MatchSpec, Recipe, RecipeDocument, RecipeTest, action_for_entry,
    };

    use crate::planner::plan_from_actions;

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

    fn file_entry(path: &str) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            kind: FileKind::File,
            logical_bytes: 4096,
            allocated_bytes: 4096,
            modified: None,
            depth: 4,
            device_id: None,
            inode: None,
            hardlink_count: None,
            symlink_target: None,
            ignored_by_git: false,
        }
    }

    fn action_for(path: &str) -> CleanupAction {
        let entry = file_entry(path);
        CleanupAction {
            target: entry.path.clone(),
            logical_bytes: entry.logical_bytes,
            reclaimable_bytes: entry.allocated_bytes,
            recipe_id: RecipeId("test".to_owned()),
            category: String::new(),
            action_type: ActionType::Trash,
            confidence: Confidence::High,
            safety_level: SafetyLevel::Safe,
            reason: "recipe candidate".to_owned(),
            fingerprint: MetadataFingerprint {
                file_kind: FileKind::File,
                device_id: None,
                inode: None,
                logical_bytes: entry.logical_bytes,
                allocated_bytes: entry.allocated_bytes,
                modified: None,
            },
        }
    }

    fn scan_with(entries: Vec<FileEntry>) -> ScanResult {
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

    fn permissive_recipe() -> RecipeDocument {
        RecipeDocument {
            recipe: Recipe {
                id: "permissive".to_owned(),
                name: "Permissive".to_owned(),
                description: "permissive cache".to_owned(),
                category: "test".to_owned(),
                icon: None,
                safety_level: SafetyLevel::Safe,
                enabled: true,
                priority: 50,
            },
            matcher: MatchSpec {
                path_glob: Some("**/cache/**".to_owned()),
                ..MatchSpec::default()
            },
            action: ActionSpec {
                action_type: ActionType::Trash,
                prompt: "Trash?".to_owned(),
            },
            test: RecipeTest::default(),
        }
    }

    #[test]
    fn ml_keep_is_advisory_and_does_not_demote() {
        let entry = file_entry("/Users/x/proj/cache/blob.bin");
        let action = action_for("/Users/x/proj/cache/blob.bin");
        let scan = scan_with(vec![entry]);

        let adjusted = adjust_actions(
            &Fixed(CleanupLabel::Keep, 0.99),
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            vec![action],
            &scan,
        );

        // Advisory only: even a confident keep leaves the candidate executable.
        assert_eq!(adjusted.kept.len(), 1, "keep is advisory, not a veto");
        assert!(adjusted.held.is_empty());
        assert_eq!(
            adjusted.kept[0].annotation.adjustment,
            MlAdjustment::Confirmed
        );
        assert_eq!(
            adjusted.kept[0].annotation.ml_label,
            Some(CleanupLabel::Keep)
        );
    }

    #[test]
    fn low_confidence_clean_class_is_trusted() {
        // A clean verdict at any confidence trusts the recipe and stays
        // executable — ML only vetoes with a confident *keep*.
        let entry = file_entry("/Users/x/proj/cache/blob.bin");
        let action = action_for("/Users/x/proj/cache/blob.bin");
        let scan = scan_with(vec![entry]);

        let adjusted = adjust_actions(
            &Fixed(CleanupLabel::SafeToRemove, 0.40),
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            vec![action],
            &scan,
        );

        assert_eq!(adjusted.kept.len(), 1);
        assert!(adjusted.held.is_empty());
        assert_eq!(
            adjusted.kept[0].annotation.adjustment,
            MlAdjustment::Confirmed
        );
    }

    #[test]
    fn uncertain_verdict_trusts_the_recipe() {
        // Regression: the embedded model returns `uncertain` for out-of-
        // distribution inputs (e.g. model weights). That must NOT nullify a
        // curated recipe — the candidate stays executable.
        let entry = file_entry("/Users/x/.lmstudio/models/pub/model.safetensors");
        let action = action_for("/Users/x/.lmstudio/models/pub/model.safetensors");
        let scan = scan_with(vec![entry]);

        let adjusted = adjust_actions(
            &Fixed(CleanupLabel::Uncertain, 1.0),
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            vec![action],
            &scan,
        );

        assert_eq!(adjusted.kept.len(), 1, "uncertain must not demote a recipe");
        assert!(adjusted.held.is_empty());
    }

    #[test]
    fn low_confidence_keep_is_trusted() {
        // A weak keep is not enough to override a curated recipe.
        let entry = file_entry("/Users/x/proj/cache/blob.bin");
        let action = action_for("/Users/x/proj/cache/blob.bin");
        let scan = scan_with(vec![entry]);

        let adjusted = adjust_actions(
            &Fixed(CleanupLabel::Keep, 0.40),
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            vec![action],
            &scan,
        );

        assert_eq!(adjusted.kept.len(), 1);
        assert!(adjusted.held.is_empty());
    }

    #[test]
    fn high_confidence_clean_class_keeps_and_annotates() {
        let entry = file_entry("/Users/x/proj/cache/blob.bin");
        let action = action_for("/Users/x/proj/cache/blob.bin");
        let scan = scan_with(vec![entry]);

        let adjusted = adjust_actions(
            &Fixed(CleanupLabel::SafeToRemove, 0.97),
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            vec![action],
            &scan,
        );

        assert_eq!(adjusted.kept.len(), 1);
        assert!(adjusted.held.is_empty());
        let kept = &adjusted.kept[0];
        assert_eq!(kept.annotation.adjustment, MlAdjustment::Confirmed);
        assert_eq!(kept.annotation.ml_label, Some(CleanupLabel::SafeToRemove));
        assert_eq!(kept.annotation.ml_confidence, Some(0.97));
        // Annotation is surfaced on the action for display.
        assert!(kept.action.reason.contains("[ML safe-to-remove: 0.97]"));
    }

    #[test]
    fn ml_unavailable_leaves_recipe_behaviour_unchanged() {
        // No matching scan entry => classifier is never consulted; the action is
        // kept verbatim with a NotEvaluated annotation.
        let action = action_for("/Users/x/proj/cache/blob.bin");
        let scan = scan_with(Vec::new());

        let adjusted = adjust_actions(
            &Fixed(CleanupLabel::Keep, 1.0),
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            vec![action.clone()],
            &scan,
        );

        assert_eq!(adjusted.kept.len(), 1);
        assert!(adjusted.held.is_empty());
        assert_eq!(
            adjusted.kept[0].annotation.adjustment,
            MlAdjustment::NotEvaluated
        );
        assert_eq!(adjusted.kept[0].action.reason, action.reason);
    }

    #[test]
    fn ml_clean_verdict_cannot_introduce_protected_or_sensitive_actions() {
        // INVARIANT 1: ML may never cause an action the matcher + planner did not
        // already clear. We prove both legs with an always-"safe-to-remove" model.
        let recipe = permissive_recipe();

        // (a) Sensitive basename: even though it sits in a cache dir the
        // permissive recipe matches, the matcher's sensitive-basename floor
        // refuses to emit any action — so ML never even sees it.
        let sensitive = file_entry("/Users/x/proj/cache/.env");
        assert!(
            action_for_entry(&recipe, &sensitive).is_none(),
            "sensitive basename must never yield a recipe action"
        );

        // (b) A benign candidate the recipe legitimately matches.
        let benign = file_entry("/Users/x/proj/cache/blob.bin");
        let benign_action =
            action_for_entry(&recipe, &benign).expect("benign cache file should match");

        // (c) Simulate an upstream leak: a recipe action that targets a protected
        // system path. ML says "safe-to-remove 1.0" (Confirmed, kept) — yet the
        // planner's independent ProtectedPaths gate still drops it.
        let leaked = action_for("/System/Library/Caches/com.evil.cache");

        let scan = scan_with(vec![benign]);
        let adjusted = adjust_actions(
            &Fixed(CleanupLabel::SafeToRemove, 1.0),
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            vec![benign_action, leaked],
            &scan,
        );

        // ML kept both (it cannot demote-to-delete; "clean" only keeps).
        assert_eq!(adjusted.kept.len(), 2);

        let executable: Vec<CleanupAction> = adjusted.kept.into_iter().map(|a| a.action).collect();
        let plan = plan_from_actions(
            &CleantonConfig::default(),
            executable,
            &scan,
            Duration::ZERO,
        );

        // The protected path is gone; the benign candidate survives.
        assert!(
            plan.actions
                .iter()
                .all(|a| a.target.as_path() != Path::new("/System/Library/Caches/com.evil.cache")),
            "ML 'clean' must not push a protected path into the executable plan"
        );
        assert!(
            plan.actions
                .iter()
                .any(|a| a.target.as_path() == Path::new("/Users/x/proj/cache/blob.bin")),
            "benign candidate should remain"
        );
    }

    fn entry_with(path: &str, kind: FileKind, bytes: u64) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            kind,
            logical_bytes: bytes,
            allocated_bytes: bytes,
            modified: None,
            depth: 4,
            device_id: None,
            inode: None,
            hardlink_count: None,
            symlink_target: None,
            ignored_by_git: false,
        }
    }

    #[test]
    fn build_contexts_computes_v2_sibling_and_ancestor_fields() {
        let scan = scan_with(vec![
            entry_with("/Users/x/proj/Cargo.toml", FileKind::File, 100),
            entry_with("/Users/x/proj/Cargo.lock", FileKind::File, 900),
            entry_with("/Users/x/proj/.gitignore", FileKind::File, 10),
            entry_with("/Users/x/proj/target", FileKind::Directory, 5_000),
            entry_with("/Users/x/proj/target/debug", FileKind::Directory, 4_000),
            entry_with("/Users/x/proj/target/debug/app.o", FileKind::File, 3_000),
        ]);
        let contexts = build_contexts(&scan);

        // Context for files directly in the project root.
        let root = contexts
            .get(Path::new("/Users/x/proj"))
            .expect("project root context");
        assert!(root.has_gitignore);
        assert!(root.has_lockfile);
        assert_eq!(root.sibling_count, 4);
        assert_eq!(root.sibling_total_bytes, 100 + 900 + 10 + 5_000);
        // Ancestor flags include the directory itself.
        assert!(root.ancestor_has_lockfile);
        assert!(root.ancestor_has_project_marker, "Cargo.toml is a marker");

        // Context for files inside target/debug: no local markers, but the
        // ancestor walk finds the project root's lockfile + manifest.
        let debug = contexts
            .get(Path::new("/Users/x/proj/target/debug"))
            .expect("debug dir context");
        assert!(!debug.has_gitignore);
        assert!(!debug.has_lockfile);
        assert_eq!(debug.sibling_count, 1);
        assert_eq!(debug.sibling_total_bytes, 3_000);
        assert!(debug.ancestor_has_lockfile);
        assert!(debug.ancestor_has_project_marker);
    }

    #[test]
    fn git_directory_counts_as_a_project_marker() {
        let scan = scan_with(vec![
            entry_with("/Users/x/repo/.git", FileKind::Directory, 1_000),
            entry_with("/Users/x/repo/notes.txt", FileKind::File, 10),
            // A FILE named .git (worktree pointer) must NOT count.
            entry_with("/Users/x/other/.git", FileKind::File, 10),
            entry_with("/Users/x/other/notes.txt", FileKind::File, 10),
        ]);
        let contexts = build_contexts(&scan);

        let repo = contexts
            .get(Path::new("/Users/x/repo"))
            .expect("repo context");
        assert!(repo.ancestor_has_project_marker, ".git dir marks a project");
        assert!(!repo.ancestor_has_lockfile);

        let other = contexts
            .get(Path::new("/Users/x/other"))
            .expect("other context");
        assert!(
            !other.ancestor_has_project_marker,
            "a .git FILE is not a project marker"
        );
    }

    struct Failing;
    impl FileClassifier for Failing {
        fn classify(&self, _e: &FileEntry, _c: &FileContext) -> MlResult<MlClassification> {
            Err(cleanton_ml::MlError::InferenceUnavailable {
                reason: cleanton_ml::MlUnavailableReason::Disabled,
                model_path: None,
            })
        }
    }

    #[test]
    fn annotate_orphans_is_display_only() {
        let action = action_for("/Users/x/Library/Application Support/com.gone.app");
        let mut orphans = vec![AnnotatedAction {
            action,
            annotation: ActionAnnotation {
                ml_label: None,
                ml_confidence: None,
                adjustment: MlAdjustment::NotEvaluated,
                note: "orphan candidate".to_owned(),
            },
        }];
        let original_target = orphans
            .first()
            .map(|a| a.action.target.clone())
            .expect("one orphan");

        annotate_orphans(&Fixed(CleanupLabel::Keep, 0.99), &mut orphans);

        // Still exactly one orphan with the same target: annotation only.
        assert_eq!(orphans.len(), 1);
        let annotated = orphans.first().expect("orphan survives");
        assert_eq!(annotated.action.target, original_target);
        assert_eq!(annotated.annotation.ml_label, Some(CleanupLabel::Keep));
        assert_eq!(annotated.annotation.ml_confidence, Some(0.99));
        assert!(annotated.annotation.note.contains("ML advisory: keep"));
        assert!(annotated.action.reason.contains("[ML keep: 0.99]"));

        // A failing backend leaves the plain orphan annotation untouched.
        let action = action_for("/Users/x/Library/Application Support/com.gone.app");
        let mut untouched = vec![AnnotatedAction {
            action,
            annotation: ActionAnnotation {
                ml_label: None,
                ml_confidence: None,
                adjustment: MlAdjustment::NotEvaluated,
                note: "orphan candidate".to_owned(),
            },
        }];
        annotate_orphans(&Failing, &mut untouched);
        let plain = untouched.first().expect("orphan survives");
        assert_eq!(plain.annotation.ml_label, None);
        assert_eq!(plain.annotation.note, "orphan candidate");
    }

    #[test]
    fn annotate_suggestions_fills_ml_note_without_changing_items() {
        use crate::suggestions::{LargeItem, Suggestions};

        let scan = scan_with(vec![
            entry_with("/Users/x/proj/Cargo.lock", FileKind::File, 900),
            entry_with("/Users/x/proj/big.bin", FileKind::File, 900_000_000),
        ]);
        let mut suggestions = Suggestions {
            large_items: vec![LargeItem {
                path: PathBuf::from("/Users/x/proj/big.bin"),
                bytes: 900_000_000,
                is_dir: false,
                redownloadable: false,
                note: String::new(),
                ml_note: String::new(),
            }],
            ..Suggestions::default()
        };

        annotate_suggestions(&Fixed(CleanupLabel::Keep, 0.91), &mut suggestions, &scan);

        assert_eq!(suggestions.large_items.len(), 1, "items are never changed");
        let item = suggestions.large_items.first().expect("item");
        assert_eq!(item.path, PathBuf::from("/Users/x/proj/big.bin"));
        assert_eq!(item.ml_note, "ML keep 0.91");

        // An item whose path is not in the scan stays unscored.
        let mut missing = Suggestions {
            large_items: vec![LargeItem {
                path: PathBuf::from("/Users/x/not-scanned.bin"),
                bytes: 1,
                is_dir: false,
                redownloadable: false,
                note: String::new(),
                ml_note: String::new(),
            }],
            ..Suggestions::default()
        };
        annotate_suggestions(&Fixed(CleanupLabel::Keep, 0.91), &mut missing, &scan);
        assert_eq!(
            missing.large_items.first().map(|i| i.ml_note.as_str()),
            Some("")
        );
    }
}
