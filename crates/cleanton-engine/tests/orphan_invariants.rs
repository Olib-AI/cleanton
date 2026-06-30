//! Safety release-gate corpus: orphaned-application-data invariants (SAFETY §2 orphans).
//!
//! Deterministic, injectable-root orphan fixtures (a real orphan is flagged;
//! installed-app data / `com.apple.*` ids / protected paths / too-recent entries
//! are NOT) are covered by the unit tests in `engine/src/orphans.rs`, because the
//! `OrphanDetector` roots are intentionally `pub(crate)`. This integration test
//! exercises the PUBLIC surface (`Orchestrator::analyze`) and asserts every
//! orphan the engine surfaces on the host obeys the safety contract: trash-only,
//! `Cautious`, confirmation-gated, never Apple/system, never protected, and
//! consistently represented in the executable plan.

use std::time::Duration;

use cleanton_common::paths::is_same_or_descendant;
use cleanton_common::{ActionType, CleantonConfig, ProtectedPaths, SafetyLevel, ScanResult};
use cleanton_engine::{MlAdjustment, ORPHAN_CATEGORY, Orchestrator};

fn empty_scan() -> ScanResult {
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

#[test]
fn every_surfaced_orphan_obeys_the_safety_contract() {
    let orchestrator = Orchestrator::new(CleantonConfig::default()).expect("orchestrator");
    let analyzed = orchestrator.analyze(&empty_scan());
    let protected = ProtectedPaths::defaults();

    for orphan in &analyzed.orphans {
        let action = &orphan.action;
        let target = &action.target;

        // Trash-only; never a permanent delete.
        assert_eq!(
            action.action_type,
            ActionType::Trash,
            "orphan must be trash-only: {}",
            target.display()
        );
        // Cautious => full-path review + explicit per-item confirmation.
        assert_eq!(
            action.safety_level,
            SafetyLevel::Cautious,
            "orphan must be Cautious: {}",
            target.display()
        );
        // Engine inference, never ML-evaluated.
        assert_eq!(orphan.annotation.adjustment, MlAdjustment::NotEvaluated);
        assert_eq!(action.recipe_id.0, "engine-orphaned-app-data");
        assert!(
            orphan.annotation.note.contains("orphaned application data"),
            "annotation must describe the orphan"
        );
        // Something to reclaim.
        assert!(action.reclaimable_bytes > 0, "orphan must reclaim bytes");

        // Never a protected path.
        assert!(
            !protected.is_protected(target),
            "orphan must never be a protected path: {}",
            target.display()
        );

        // Never an Apple / system bundle id.
        let leaf = target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            !leaf.starts_with("com.apple"),
            "orphan must never target an Apple bundle id: {}",
            target.display()
        );

        // Consistently represented: present in the executable plan, or covered by an
        // ancestor action the planner kept in its place.
        let in_plan = analyzed
            .plan
            .actions
            .iter()
            .any(|planned| is_same_or_descendant(target, &planned.target));
        assert!(
            in_plan,
            "every orphan must be represented in the executable plan: {}",
            target.display()
        );
    }

    // Plan-side cross-check: any orphan-sourced action in the plan is trash + cautious.
    for action in &analyzed.plan.actions {
        if action.recipe_id.0 == "engine-orphaned-app-data" {
            assert_eq!(action.action_type, ActionType::Trash);
            assert_eq!(action.safety_level, SafetyLevel::Cautious);
        }
    }

    // The category label the UIs group orphans under is stable.
    assert_eq!(ORPHAN_CATEGORY, "Orphaned application data");
}
