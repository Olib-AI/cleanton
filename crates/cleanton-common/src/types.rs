use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecipeId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SafetyLevel {
    Safe,
    Cautious,
    Aggressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    High,
    Medium,
    Low,
    MlInferred(f32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionType {
    Trash,
    Delete,
    Archive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataFingerprint {
    pub file_kind: FileKind,
    pub device_id: Option<u64>,
    pub inode: Option<u64>,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub kind: FileKind,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub modified: Option<SystemTime>,
    pub depth: usize,
    pub device_id: Option<u64>,
    pub inode: Option<u64>,
    pub hardlink_count: Option<u64>,
    pub symlink_target: Option<PathBuf>,
    pub ignored_by_git: bool,
}

impl FileEntry {
    #[must_use]
    pub fn fingerprint(&self) -> MetadataFingerprint {
        MetadataFingerprint {
            file_kind: self.kind,
            device_id: self.device_id,
            inode: self.inode,
            logical_bytes: self.logical_bytes,
            allocated_bytes: self.allocated_bytes,
            modified: self.modified,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanError {
    pub path: PathBuf,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ecosystem {
    Rust,
    Swift,
    Node,
    Python,
    Go,
    Docker,
    Xcode,
    Git,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRoot {
    pub path: PathBuf,
    pub ecosystem: Ecosystem,
    pub artifact_dirs: Vec<PathBuf>,
    pub total_size: u64,
    pub artifact_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    pub entries: Vec<FileEntry>,
    #[serde(default)]
    pub project_roots: Vec<ProjectRoot>,
    pub total_files: u64,
    pub total_dirs: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub duration: Duration,
    pub errors: Vec<ScanError>,
    pub incomplete: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CleanupAction {
    pub target: PathBuf,
    pub logical_bytes: u64,
    pub reclaimable_bytes: u64,
    pub recipe_id: RecipeId,
    /// The originating recipe's category (e.g. "rust", "node", "ai-tools").
    /// Presentation-only: lets the UIs bucket actions without guessing from the
    /// recipe id. Defaults to empty for plans persisted before it existed.
    #[serde(default)]
    pub category: String,
    pub action_type: ActionType,
    pub confidence: Confidence,
    pub safety_level: SafetyLevel,
    pub reason: String,
    pub fingerprint: MetadataFingerprint,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CleanupPlan {
    pub actions: Vec<CleanupAction>,
    pub total_reclaimable: u64,
    pub scan_duration: Duration,
    pub analysis_duration: Duration,
    pub incomplete_scan: bool,
    #[serde(default = "std::time::SystemTime::now")]
    pub created_at: SystemTime,
}

/// Presentation-only aggregation of a [`CleanupPlan`]'s actions, collapsed by
/// recipe so a plan with tens of thousands of per-file actions becomes a handful
/// of human-reviewable rows. This never affects execution: the granular
/// [`CleanupPlan::actions`] remain the source of truth and are what gets trashed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionGroup {
    /// The grouping key, i.e. [`RecipeId`]'s inner string.
    pub recipe_id: String,
    /// Human-readable label: the group's most common `reason` with any trailing
    /// ML badge stripped, falling back to `recipe_id` when empty.
    pub label: String,
    /// Number of underlying actions folded into this group.
    pub action_count: usize,
    /// Sum of `reclaimable_bytes` across the group's actions.
    pub total_reclaimable: u64,
    /// The action type shared by the group (taken from its first action).
    pub action_type: ActionType,
    /// Up to three largest targets (by `reclaimable_bytes`, descending) for display.
    pub sample_targets: Vec<PathBuf>,
}

/// Strip a trailing ` [ML <label>: <conf>]` badge that the ML pass appends to a
/// recipe `reason`, leaving the human recipe description. Splits at the *last*
/// ` [ML ` so a recipe description that itself contains brackets is preserved.
fn strip_ml_badge(reason: &str) -> &str {
    match reason.rfind(" [ML ") {
        Some(idx) => reason.get(..idx).unwrap_or(reason).trim_end(),
        None => reason.trim_end(),
    }
}

impl CleanupPlan {
    /// Aggregate [`Self::actions`] into per-recipe [`ActionGroup`]s for display.
    ///
    /// Groups are keyed by `recipe_id`, `label` is the most common (ML-stripped)
    /// `reason`, `sample_targets` holds the three largest targets, and the result
    /// is sorted by `total_reclaimable` descending (ties broken by `recipe_id`).
    /// This is purely presentational and leaves the executable plan untouched.
    #[must_use]
    pub fn grouped(&self) -> Vec<ActionGroup> {
        use std::collections::HashMap;

        struct GroupAcc<'a> {
            recipe_id: &'a str,
            action_type: ActionType,
            action_count: usize,
            total_reclaimable: u64,
            // reason -> (count, first-seen ordinal); the ordinal keeps tie-breaks
            // deterministic regardless of HashMap iteration order.
            reasons: Vec<(&'a str, usize, usize)>,
            // Up to three largest targets, kept sorted by bytes descending.
            samples: Vec<(u64, &'a PathBuf)>,
        }

        let mut index: HashMap<&str, usize> = HashMap::new();
        let mut groups: Vec<GroupAcc<'_>> = Vec::new();

        for action in &self.actions {
            let key = action.recipe_id.0.as_str();
            let slot = if let Some(&slot) = index.get(key) {
                slot
            } else {
                let slot = groups.len();
                index.insert(key, slot);
                groups.push(GroupAcc {
                    recipe_id: key,
                    action_type: action.action_type,
                    action_count: 0,
                    total_reclaimable: 0,
                    reasons: Vec::new(),
                    samples: Vec::new(),
                });
                slot
            };
            let Some(group) = groups.get_mut(slot) else {
                continue;
            };

            group.action_count += 1;
            group.total_reclaimable = group
                .total_reclaimable
                .saturating_add(action.reclaimable_bytes);

            let reason = action.reason.as_str();
            if let Some(entry) = group.reasons.iter_mut().find(|(r, _, _)| *r == reason) {
                entry.1 += 1;
            } else {
                let ordinal = group.reasons.len();
                group.reasons.push((reason, 1, ordinal));
            }

            // Maintain a descending top-three of targets by reclaimable bytes,
            // holding references and only cloning the survivors at the end.
            let bytes = action.reclaimable_bytes;
            let pos = group
                .samples
                .iter()
                .position(|(existing, _)| bytes > *existing);
            match pos {
                Some(i) => group.samples.insert(i, (bytes, &action.target)),
                None => group.samples.push((bytes, &action.target)),
            }
            group.samples.truncate(3);
        }

        let mut result = groups
            .into_iter()
            .map(|group| {
                // Most common reason; ties resolved to the first-seen (smallest
                // ordinal) so the label is stable across runs.
                let label = group
                    .reasons
                    .iter()
                    .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.2.cmp(&a.2)))
                    .map(|(reason, _, _)| strip_ml_badge(reason).to_owned())
                    .filter(|label| !label.is_empty())
                    .unwrap_or_else(|| group.recipe_id.to_owned());
                ActionGroup {
                    recipe_id: group.recipe_id.to_owned(),
                    label,
                    action_count: group.action_count,
                    total_reclaimable: group.total_reclaimable,
                    action_type: group.action_type,
                    sample_targets: group
                        .samples
                        .into_iter()
                        .map(|(_, target)| target.clone())
                        .collect(),
                }
            })
            .collect::<Vec<_>>();

        result.sort_by(|a, b| {
            b.total_reclaimable
                .cmp(&a.total_reclaimable)
                .then_with(|| a.recipe_id.cmp(&b.recipe_id))
        });
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub attempted_actions: u64,
    pub moved_to_trash_bytes: u64,
    pub freed_bytes: u64,
    pub skipped_actions: u64,
    pub log_path: Option<PathBuf>,
    pub actions: Vec<ExecutionActionResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionActionResult {
    pub target: PathBuf,
    pub recipe_id: RecipeId,
    pub action_type: ActionType,
    pub status: ExecutionStatus,
    pub logical_bytes: u64,
    pub moved_to_trash_bytes: u64,
    pub freed_bytes: u64,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionStatus {
    MovedToTrash,
    Deleted,
    Skipped,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(recipe: &str, reason: &str, bytes: u64, target: &str) -> CleanupAction {
        CleanupAction {
            target: PathBuf::from(target),
            logical_bytes: bytes,
            reclaimable_bytes: bytes,
            recipe_id: RecipeId(recipe.to_owned()),
            category: String::new(),
            action_type: ActionType::Trash,
            confidence: Confidence::High,
            safety_level: SafetyLevel::Safe,
            reason: reason.to_owned(),
            fingerprint: MetadataFingerprint {
                file_kind: FileKind::File,
                device_id: None,
                inode: None,
                logical_bytes: bytes,
                allocated_bytes: bytes,
                modified: None,
            },
        }
    }

    fn plan(actions: Vec<CleanupAction>) -> CleanupPlan {
        let total_reclaimable = actions.iter().map(|a| a.reclaimable_bytes).sum();
        CleanupPlan {
            actions,
            total_reclaimable,
            scan_duration: Duration::ZERO,
            analysis_duration: Duration::ZERO,
            incomplete_scan: false,
            created_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn strip_ml_badge_removes_trailing_badge() {
        assert_eq!(
            strip_ml_badge("Cargo Registry Cache [ML safe-to-remove: 0.97]"),
            "Cargo Registry Cache"
        );
        assert_eq!(strip_ml_badge("Plain reason"), "Plain reason");
        // A recipe description with its own brackets is preserved; only the last
        // ` [ML ` segment is stripped.
        assert_eq!(
            strip_ml_badge("Cache [user] dir [ML keep: 0.40]"),
            "Cache [user] dir"
        );
    }

    #[test]
    fn grouped_aggregates_sorts_and_labels() {
        let plan = plan(vec![
            // Small recipe, two actions.
            action("node-modules", "Node Modules", 10, "/a/node_modules/x"),
            action("node-modules", "Node Modules", 20, "/b/node_modules/y"),
            // Large recipe, three actions with an ML badge on the reason and a
            // single odd reason that must not win the label vote.
            action(
                "rust-cargo-registry-cache",
                "Cargo Registry Cache [ML safe-to-remove: 0.97]",
                100,
                "/cache/small.crate",
            ),
            action(
                "rust-cargo-registry-cache",
                "Cargo Registry Cache [ML safe-to-remove: 0.91]",
                900,
                "/cache/large.crate",
            ),
            action(
                "rust-cargo-registry-cache",
                "Odd one out",
                500,
                "/cache/mid.crate",
            ),
        ]);

        let groups = plan.grouped();
        assert_eq!(groups.len(), 2);

        // Sorted by total_reclaimable descending: cargo cache (1500) before node (30).
        let first = groups.first().expect("first group");
        assert_eq!(first.recipe_id, "rust-cargo-registry-cache");
        assert_eq!(first.action_count, 3);
        assert_eq!(first.total_reclaimable, 1500);
        // Most common reason wins (2x), with the ML badge stripped.
        assert_eq!(first.label, "Cargo Registry Cache");
        // Sample targets are the three largest, descending.
        assert_eq!(
            first.sample_targets,
            vec![
                PathBuf::from("/cache/large.crate"),
                PathBuf::from("/cache/mid.crate"),
                PathBuf::from("/cache/small.crate"),
            ]
        );

        let second = groups.get(1).expect("second group");
        assert_eq!(second.recipe_id, "node-modules");
        assert_eq!(second.action_count, 2);
        assert_eq!(second.total_reclaimable, 30);
        assert_eq!(second.label, "Node Modules");
        // Only two targets exist, largest first.
        assert_eq!(
            second.sample_targets,
            vec![
                PathBuf::from("/b/node_modules/y"),
                PathBuf::from("/a/node_modules/x"),
            ]
        );
    }

    #[test]
    fn grouped_falls_back_to_recipe_id_when_reason_empty() {
        let plan = plan(vec![action("orphan-app-support", "", 42, "/x/app")]);
        let groups = plan.grouped();
        let group = groups.first().expect("group");
        assert_eq!(group.label, "orphan-app-support");
        assert_eq!(group.sample_targets, vec![PathBuf::from("/x/app")]);
    }
}
