//! Safety release-gate corpus: executor refusal / TOCTOU revalidation (SAFETY §1 Layer 8).
//!
//! Drives the PUBLIC executor (`Orchestrator::execute_plan`) and proves it
//! REFUSES to act — and deletes NOTHING — when the world no longer matches the
//! recorded plan: a symlink swapped for the planned target, stale recorded
//! metadata (size / mtime / inode), an incomplete scan, or a plan older than the
//! staleness window. Every target lives in a tempdir under the crate directory
//! (NOT $TMPDIR, which is the protected /private/var on macOS).
#![cfg(unix)]
// Integration-test crate: setup helpers (outside `#[test]` fns) use `.expect()` on
// fixture I/O, and fixed-shape result assertions index directly; neither is covered
// by clippy.toml's per-test exemptions.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use cleanton_common::{
    ActionType, CleantonConfig, CleantonError, CleanupAction, CleanupPlan, Confidence, FileKind,
    MetadataFingerprint, RecipeId, SafetyLevel,
};
use cleanton_engine::{EngineEvent, Orchestrator};
use tokio::sync::mpsc;

fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("cleanton-executor-refusal-")
        .tempdir_in(std::env::current_dir().expect("cwd"))
        .expect("tempdir")
}

/// A faithful fingerprint of the on-disk state, mirroring the executor's own
/// `fingerprint_for_path`. Mutating one field yields a "stale" record.
fn faithful_fingerprint(path: &Path) -> MetadataFingerprint {
    let metadata = fs::symlink_metadata(path).expect("symlink_metadata");
    let file_type = metadata.file_type();
    let file_kind = if file_type.is_dir() {
        FileKind::Directory
    } else if file_type.is_file() {
        FileKind::File
    } else if file_type.is_symlink() {
        FileKind::Symlink
    } else {
        FileKind::Other
    };
    MetadataFingerprint {
        file_kind,
        device_id: Some(metadata.dev()),
        inode: Some(metadata.ino()),
        logical_bytes: metadata.len(),
        allocated_bytes: metadata.blocks().saturating_mul(512),
        modified: metadata.modified().ok(),
    }
}

fn trash_action(target: &Path, fingerprint: MetadataFingerprint) -> CleanupAction {
    CleanupAction {
        target: target.to_path_buf(),
        logical_bytes: 1024,
        reclaimable_bytes: 1024,
        recipe_id: RecipeId("test-refusal".to_owned()),
        action_type: ActionType::Trash,
        confidence: Confidence::High,
        safety_level: SafetyLevel::Safe,
        reason: "refusal fixture".to_owned(),
        fingerprint,
    }
}

fn plan_with(
    actions: Vec<CleanupAction>,
    incomplete_scan: bool,
    created_at: SystemTime,
) -> CleanupPlan {
    let total_reclaimable = actions.iter().map(|action| action.reclaimable_bytes).sum();
    CleanupPlan {
        actions,
        total_reclaimable,
        scan_duration: Duration::ZERO,
        analysis_duration: Duration::ZERO,
        incomplete_scan,
        created_at,
    }
}

/// An orchestrator whose execution-log retention is effectively infinite, so the
/// real `~/.config/cleanton/logs` directory is never pruned by these tests.
fn orchestrator() -> Orchestrator {
    let mut config = CleantonConfig::default();
    config.general.log_retention_count = usize::MAX;
    config.general.log_retention_days = u32::MAX;
    Orchestrator::new(config).expect("orchestrator")
}

fn execute(plan: &CleanupPlan) -> cleanton_common::Result<cleanton_common::ExecutionResult> {
    let (tx, _rx) = mpsc::channel::<EngineEvent>(16);
    orchestrator().execute_plan(plan, &tx)
}

#[test]
fn symlink_swapped_for_planned_target_is_refused() {
    let temp = temp_dir();
    let dest = temp.path().join("important_destination");
    fs::write(&dest, b"do not delete me").expect("write dest");
    let planned = temp.path().join("planned_target");
    std::os::unix::fs::symlink(&dest, &planned).expect("symlink");

    // The plan recorded a DIRECTORY at this path; at execution time it is a symlink.
    let mut fingerprint = faithful_fingerprint(&planned);
    fingerprint.file_kind = FileKind::Directory;
    let plan = plan_with(
        vec![trash_action(&planned, fingerprint)],
        false,
        SystemTime::now(),
    );

    let result = execute(&plan).expect("execute returns a result");

    assert_eq!(
        result.skipped_actions, 1,
        "the type mismatch must be skipped"
    );
    assert_eq!(result.moved_to_trash_bytes, 0);
    assert_eq!(result.freed_bytes, 0);
    assert!(
        result.actions[0].message.contains("kind changed"),
        "skip reason must cite the kind mismatch, was: {}",
        result.actions[0].message
    );
    // Nothing was deleted: both the link and its destination survive.
    assert!(planned.symlink_metadata().is_ok(), "symlink must remain");
    assert!(dest.exists(), "the symlink destination must remain");
}

#[test]
fn stale_logical_size_is_refused() {
    let temp = temp_dir();
    let target = temp.path().join("artifact.bin");
    fs::write(&target, b"eight!!!").expect("write target"); // 8 bytes

    let mut fingerprint = faithful_fingerprint(&target);
    fingerprint.logical_bytes = fingerprint.logical_bytes.saturating_add(1);
    let plan = plan_with(
        vec![trash_action(&target, fingerprint)],
        false,
        SystemTime::now(),
    );

    let result = execute(&plan).expect("result");
    assert_eq!(result.skipped_actions, 1);
    assert!(result.actions[0].message.contains("logical size changed"));
    assert!(target.exists(), "stale-size target must not be deleted");
}

#[test]
fn stale_modified_time_is_refused() {
    let temp = temp_dir();
    let target = temp.path().join("artifact.bin");
    fs::write(&target, b"contents").expect("write target");

    let mut fingerprint = faithful_fingerprint(&target);
    fingerprint.modified = Some(SystemTime::UNIX_EPOCH);
    let plan = plan_with(
        vec![trash_action(&target, fingerprint)],
        false,
        SystemTime::now(),
    );

    let result = execute(&plan).expect("result");
    assert_eq!(result.skipped_actions, 1);
    assert!(result.actions[0].message.contains("modified time changed"));
    assert!(target.exists(), "stale-mtime target must not be deleted");
}

#[test]
fn stale_inode_is_refused() {
    let temp = temp_dir();
    let target = temp.path().join("artifact.bin");
    fs::write(&target, b"contents").expect("write target");

    let mut fingerprint = faithful_fingerprint(&target);
    fingerprint.inode = fingerprint.inode.map(|inode| inode.wrapping_add(1));
    let plan = plan_with(
        vec![trash_action(&target, fingerprint)],
        false,
        SystemTime::now(),
    );

    let result = execute(&plan).expect("result");
    assert_eq!(result.skipped_actions, 1);
    assert!(result.actions[0].message.contains("inode changed"));
    assert!(target.exists(), "stale-inode target must not be deleted");
}

#[test]
fn incomplete_scan_plan_is_refused_entirely() {
    let temp = temp_dir();
    let target = temp.path().join("artifact.bin");
    fs::write(&target, b"contents").expect("write target");

    let plan = plan_with(
        vec![trash_action(&target, faithful_fingerprint(&target))],
        true, // incomplete scan
        SystemTime::now(),
    );

    let err = execute(&plan).expect_err("incomplete-scan plan must be refused");
    assert!(matches!(err, CleantonError::ExecutionRefused(_)));
    assert!(err.to_string().contains("incomplete scan"));
    assert!(
        target.exists(),
        "nothing may be deleted from an incomplete-scan plan"
    );
}

#[test]
fn plan_older_than_staleness_window_is_refused_entirely() {
    let temp = temp_dir();
    let target = temp.path().join("artifact.bin");
    fs::write(&target, b"contents").expect("write target");

    let plan = plan_with(
        vec![trash_action(&target, faithful_fingerprint(&target))],
        false,
        SystemTime::now() - Duration::from_mins(20), // 20 minutes > 15-minute window
    );

    let err = execute(&plan).expect_err("stale plan must be refused");
    assert!(matches!(err, CleantonError::ExecutionRefused(_)));
    assert!(err.to_string().contains("stale"));
    assert!(target.exists(), "nothing may be deleted from a stale plan");
}
