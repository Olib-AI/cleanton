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
    collections::HashMap,
    path::{Path, PathBuf},
};

use cleanton_common::{CleanupAction, FileEntry, ScanResult};
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
    /// ML agreed the candidate is a clean class with high confidence; kept for
    /// the normal confirmation flow (existing requirements are not weakened).
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

fn empty_context() -> FileContext {
    FileContext {
        has_gitignore: false,
        has_lockfile: false,
        sibling_count: 0,
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
            action.reason = format!(
                "{} [ML {}: {:.2}]",
                action.reason,
                label_text(label),
                confidence
            );
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
/// empirical — the embedded 12-feature classifier is unreliable on real data:
/// it returns `uncertain` for some model weights and a confident `keep` for
/// others of the very same class (re-downloadable Hugging Face cache), so gating
/// the plan on it produced inconsistent, surprising results and silently hid
/// tens of GB of correctly-matched, reclaimable files.
///
/// The trustworthy, testable safety system is elsewhere and unchanged: the
/// recipe matcher's protected-path + sensitive-basename floors, the planner's
/// independent protected-path gate, and trash-by-default (every action is
/// reversible). Recipes decide; ML only informs. `keep_threshold` is retained
/// for API/display compatibility but no longer gates anything.
fn decide(label: CleanupLabel, confidence: f32, _keep_threshold: f32) -> ActionAnnotation {
    ActionAnnotation {
        ml_label: Some(label),
        ml_confidence: Some(confidence),
        adjustment: MlAdjustment::Confirmed,
        note: format!(
            "Recipe match trusted; ML advisory: {} (confidence {confidence:.2})",
            label_text(label)
        ),
    }
}

fn label_text(label: CleanupLabel) -> &'static str {
    match label {
        CleanupLabel::SafeToRemove => "safe-to-remove",
        CleanupLabel::LikelyJunk => "likely-junk",
        CleanupLabel::Uncertain => "uncertain",
        CleanupLabel::Keep => "keep",
    }
}

/// Build a best-effort [`FileContext`] for each scanned parent directory from
/// the scan data alone (no extra filesystem access).
fn build_contexts(scan: &ScanResult) -> HashMap<PathBuf, FileContext> {
    struct Acc {
        siblings: u64,
        has_gitignore: bool,
        has_lockfile: bool,
    }

    let mut groups: HashMap<PathBuf, Acc> = HashMap::new();
    for entry in &scan.entries {
        let Some(parent) = entry.path.parent() else {
            continue;
        };
        let acc = groups.entry(parent.to_path_buf()).or_insert(Acc {
            siblings: 0,
            has_gitignore: false,
            has_lockfile: false,
        });
        acc.siblings = acc.siblings.saturating_add(1);
        if let Some(name) = entry.path.file_name().and_then(|name| name.to_str()) {
            if name == ".gitignore" {
                acc.has_gitignore = true;
            }
            if LOCKFILES.contains(&name) {
                acc.has_lockfile = true;
            }
        }
    }

    groups
        .into_iter()
        .map(|(parent, acc)| {
            (
                parent,
                FileContext {
                    has_gitignore: acc.has_gitignore,
                    has_lockfile: acc.has_lockfile,
                    sibling_count: acc.siblings,
                },
            )
        })
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
                group: false,
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
}
