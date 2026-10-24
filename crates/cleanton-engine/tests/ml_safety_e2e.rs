//! Safety release-gate corpus: ML cannot bypass safety, end-to-end (SAFETY Layer 9).
//!
//! Runs the real pipeline — `Orchestrator::scan_only` then `Orchestrator::analyze`
//! (real embedded ML + real orphan detection) — over a fixture tree containing
//! BOTH a regenerable cache and several credential files. Regardless of what the
//! ML model decides, no planned action may target a protected or sensitive path,
//! and any ML-demoted candidate must live in `held`, never in `plan.actions`.

// Integration-test crate: setup helpers (outside `#[test]` fns) use `.expect()` on
// fixture I/O, not covered by clippy.toml's `allow-expect-in-tests`.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use cleanton_common::{CleantonConfig, CleanupAction, ProtectedPaths};
use cleanton_engine::Orchestrator;
use cleanton_scanner::ScanOptions;
use tokio::sync::mpsc;

/// Credential / settings basenames planted in the fixture. None may ever be planned.
const SENSITIVE_BASENAMES: &[&str] = &[
    ".env",
    "credentials.json",
    ".credentials.json",
    "id_rsa",
    "settings.json",
    "mcp.json",
];

fn build_fixture(root: &Path) -> PathBuf {
    // A regenerable Python bytecode cache (matched by the `python-bytecode` recipe).
    let pycache = root.join("api").join("__pycache__");
    fs::create_dir_all(&pycache).expect("create __pycache__");
    let cache_file = pycache.join("module.cpython-311.pyc");
    fs::write(&cache_file, [0_u8; 4096]).expect("write pyc");

    // Credentials and settings scattered through the same tree.
    fs::write(root.join("api").join(".env"), b"SECRET=1").expect("write .env");
    let secrets = root.join("secrets");
    fs::create_dir_all(&secrets).expect("create secrets");
    fs::write(secrets.join("credentials.json"), b"{}").expect("write credentials.json");
    fs::write(secrets.join(".credentials.json"), b"{}").expect("write .credentials.json");
    fs::write(secrets.join("id_rsa"), b"PRIVATE KEY").expect("write id_rsa");
    fs::write(root.join("api").join("settings.json"), b"{}").expect("write settings.json");
    fs::write(root.join("api").join("mcp.json"), b"{}").expect("write mcp.json");

    cache_file
}

fn is_sensitive(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            SENSITIVE_BASENAMES.iter().any(|item| *item == lower)
        })
}

fn targets(actions: &[CleanupAction]) -> Vec<PathBuf> {
    actions.iter().map(|action| action.target.clone()).collect()
}

/// True when `path` is reclaimed by `targets` — either as its own target or via
/// an ancestor directory that is itself a target (and therefore takes `path`
/// with it).
fn covers(targets: &[PathBuf], path: &Path) -> bool {
    path.ancestors()
        .any(|ancestor| targets.iter().any(|target| target == ancestor))
}

#[tokio::test]
async fn ml_pipeline_never_plans_a_protected_or_sensitive_target() {
    let temp = tempfile::Builder::new()
        .prefix("cleanton-ml-safety-")
        .tempdir_in(std::env::current_dir().expect("cwd"))
        .expect("tempdir");
    let root = temp.path();
    let cache_file = build_fixture(root);

    let orchestrator = Orchestrator::new(CleantonConfig::default()).expect("orchestrator");

    let (event_tx, _event_rx) = mpsc::channel(64);
    let scan = orchestrator
        .scan_only(
            ScanOptions {
                roots: vec![root.to_path_buf()],
                max_depth: 20,
                ..ScanOptions::default()
            },
            event_tx,
        )
        .await
        .expect("scan");

    let analyzed = orchestrator.analyze(&scan);
    let protected = ProtectedPaths::defaults();

    // INVARIANT 1: no PLANNED action targets a protected or sensitive path.
    for action in &analyzed.plan.actions {
        assert!(
            !protected.is_protected(&action.target),
            "ML pipeline planned a protected target: {}",
            action.target.display()
        );
        assert!(
            !is_sensitive(&action.target),
            "ML pipeline planned a credential/settings target: {}",
            action.target.display()
        );
    }

    // INVARIANT 2: the planted credentials never appear ANYWHERE in the analysis —
    // not in the plan, the held set, the orphan set, or the annotations.
    let everywhere: Vec<PathBuf> = targets(&analyzed.plan.actions)
        .into_iter()
        .chain(analyzed.held.iter().map(|held| held.action.target.clone()))
        .chain(
            analyzed
                .orphans
                .iter()
                .map(|orphan| orphan.action.target.clone()),
        )
        .chain(
            analyzed
                .annotations
                .iter()
                .map(|annotated| annotated.action.target.clone()),
        )
        .collect();
    for path in &everywhere {
        assert!(
            !is_sensitive(path),
            "a credential reached the analysis pipeline: {}",
            path.display()
        );
    }

    // INVARIANT 3: the regenerable cache IS a recognised candidate — routed to the
    // plan if ML confirmed it, or held for explicit confirmation if ML demoted it,
    // but never silently dropped.
    //
    // Coverage is by self OR ancestor: the `python-bytecode` recipe targets the
    // `__pycache__` directory as a unit, so the cache file is reclaimed by its
    // parent's single action rather than by an action of its own. Reclaiming the
    // whole directory covers strictly more than the file did, so the invariant
    // ("never silently dropped") is what is asserted here — not the granularity.
    let plan_targets = targets(&analyzed.plan.actions);
    let held_targets: Vec<PathBuf> = analyzed
        .held
        .iter()
        .map(|held| held.action.target.clone())
        .collect();
    assert!(
        covers(&plan_targets, &cache_file) || covers(&held_targets, &cache_file),
        "the regenerable cache must be planned or held, never dropped: {}",
        cache_file.display()
    );

    // INVARIANT 4: demoted (held) candidates live in `held`, NEVER in the plan.
    for held in &analyzed.held {
        assert_eq!(
            held.annotation.adjustment,
            cleanton_engine::MlAdjustment::Demoted,
            "everything in `held` must be ML-demoted"
        );
        assert!(
            !plan_targets.contains(&held.action.target),
            "a held (demoted) candidate must not also be in the executable plan: {}",
            held.action.target.display()
        );
    }
}
