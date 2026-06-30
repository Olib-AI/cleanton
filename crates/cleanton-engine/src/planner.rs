use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    time::Duration,
};

use cleanton_common::{
    ActionType, CleantonConfig, CleanupAction, CleanupPlan, FileKind, ProtectedPaths, ScanResult,
    paths::{normalize_for_case_insensitive_comparison, normalize_for_comparison},
};

pub(crate) fn plan_from_actions(
    config: &CleantonConfig,
    actions: Vec<CleanupAction>,
    scan: &ScanResult,
    analysis_duration: Duration,
) -> CleanupPlan {
    let protected = ProtectedPaths::new(config.safety.protected_paths.clone());
    let mut deduped = BTreeMap::new();
    for action in actions {
        if !is_plannable(&action, &protected) {
            continue;
        }
        deduped.entry(action.target.clone()).or_insert(action);
    }

    let mut actions = deduped.into_values().collect::<Vec<_>>();
    actions.sort_by(|left, right| {
        path_depth(&left.target)
            .cmp(&path_depth(&right.target))
            .then_with(|| left.target.cmp(&right.target))
    });
    actions = remove_descendant_actions(actions);
    actions.sort_by_key(|action| Reverse(action.reclaimable_bytes));

    let total_reclaimable = actions
        .iter()
        .map(|action| action.reclaimable_bytes)
        .sum::<u64>();

    CleanupPlan {
        actions,
        total_reclaimable,
        scan_duration: scan.duration,
        analysis_duration,
        incomplete_scan: scan.incomplete,
        created_at: std::time::SystemTime::now(),
    }
}

fn is_plannable(action: &CleanupAction, protected: &ProtectedPaths) -> bool {
    (action.action_type == ActionType::Trash || action.action_type == ActionType::Delete)
        && action.fingerprint.file_kind != FileKind::Other
        && (action.reclaimable_bytes > 0 || action.fingerprint.file_kind == FileKind::Symlink)
        && !protected.is_protected(&action.target)
}

/// Drop any action whose target lives inside another selected action's target
/// (the ancestor action already reclaims it). `actions` is pre-sorted
/// shallowest-first, so an ancestor is always selected before its descendants.
///
/// Rather than the previous O(n²) pairwise `is_same_or_descendant` — which fell
/// through to a per-comparison `fs::metadata` probe and hung on directories with
/// thousands of sibling candidates (e.g. ~/.cargo/registry/cache) — this
/// normalizes each target once and tests its ancestors against a set of selected
/// targets: O(n × path-depth) with no filesystem access. Keys are case-folded so
/// a case-insensitive volume still collapses `/Foo` into `/foo` (the safe,
/// over-collapsing direction), matching how protected-path comparison folds.
fn remove_descendant_actions(actions: Vec<CleanupAction>) -> Vec<CleanupAction> {
    let mut selected_keys: HashSet<PathBuf> = HashSet::with_capacity(actions.len());
    let mut selected = Vec::<CleanupAction>::with_capacity(actions.len());
    for action in actions {
        let key = descendant_key(&action.target);
        let covered = key
            .ancestors()
            .skip(1)
            .any(|ancestor| selected_keys.contains(ancestor));
        if covered {
            continue;
        }
        selected_keys.insert(key);
        selected.push(action);
    }
    selected
}

/// Canonical key for descendant comparison: firmlink/Unicode-normalized then
/// case-folded, so equivalent spellings of the same path collapse together.
fn descendant_key(path: &Path) -> PathBuf {
    normalize_for_case_insensitive_comparison(&normalize_for_comparison(path))
}

fn path_depth(path: &Path) -> usize {
    path.components().count()
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing into expected results clearer.
    #![allow(clippy::indexing_slicing)]
    use std::{path::PathBuf, time::Duration};

    use cleanton_common::{
        Confidence, MetadataFingerprint, RecipeId, SafetyLevel, ScanError, Severity,
    };

    use super::*;

    fn action(path: &str, bytes: u64, kind: FileKind) -> CleanupAction {
        CleanupAction {
            target: PathBuf::from(path),
            logical_bytes: bytes,
            reclaimable_bytes: bytes,
            recipe_id: RecipeId("test-recipe".to_owned()),
            action_type: ActionType::Trash,
            confidence: Confidence::High,
            safety_level: SafetyLevel::Safe,
            reason: "test".to_owned(),
            fingerprint: MetadataFingerprint {
                file_kind: kind,
                device_id: Some(1),
                inode: Some(bytes),
                logical_bytes: bytes,
                allocated_bytes: bytes,
                modified: None,
            },
        }
    }

    fn scan(incomplete: bool) -> ScanResult {
        ScanResult {
            entries: Vec::new(),
            project_roots: Vec::new(),
            total_files: 0,
            total_dirs: 0,
            logical_bytes: 0,
            allocated_bytes: 0,
            duration: Duration::ZERO,
            errors: if incomplete {
                vec![ScanError {
                    path: PathBuf::from("/tmp/denied"),
                    severity: Severity::Warning,
                    message: "permission denied".to_owned(),
                }]
            } else {
                Vec::new()
            },
            incomplete,
        }
    }

    #[test]
    fn planner_filters_unexecutable_targets() {
        let config = CleantonConfig {
            safety: cleanton_common::SafetyConfig {
                protected_paths: vec![PathBuf::from("/Users/example/cleanton-protected")],
                ..cleanton_common::SafetyConfig::default()
            },
            ..CleantonConfig::default()
        };
        let mut delete_action = action("/Users/example/cleanton-delete", 100, FileKind::Directory);
        delete_action.action_type = ActionType::Delete;

        let plan = plan_from_actions(
            &config,
            vec![
                action(
                    "/Users/example/cleanton-protected/cache",
                    100,
                    FileKind::Directory,
                ),
                action("/Users/example/cleanton-link", 100, FileKind::Symlink),
                action("/Users/example/cleanton-empty", 0, FileKind::Directory),
                delete_action,
                action("/Users/example/cleanton-keep", 100, FileKind::Directory),
            ],
            &scan(false),
            Duration::ZERO,
        );

        assert_eq!(plan.actions.len(), 3);
        let targets: Vec<PathBuf> = plan.actions.iter().map(|a| a.target.clone()).collect();
        assert!(targets.contains(&PathBuf::from("/Users/example/cleanton-keep")));
        assert!(targets.contains(&PathBuf::from("/Users/example/cleanton-link")));
        assert!(targets.contains(&PathBuf::from("/Users/example/cleanton-delete")));
        assert_eq!(plan.total_reclaimable, 300);
    }

    #[test]
    fn planner_keeps_parent_action_over_descendants() {
        let parent = action("/Users/example/project/target", 1_000, FileKind::Directory);
        let child = action(
            "/Users/example/project/target/debug",
            100,
            FileKind::Directory,
        );

        let plan = plan_from_actions(
            &CleantonConfig::default(),
            vec![child, parent],
            &scan(false),
            Duration::ZERO,
        );

        assert_eq!(plan.actions.len(), 1);
        assert_eq!(
            plan.actions[0].target,
            PathBuf::from("/Users/example/project/target")
        );
        assert_eq!(plan.total_reclaimable, 1_000);
    }
}
