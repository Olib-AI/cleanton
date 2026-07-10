//! Parity + safety tests for the embedded v2 ONNX classifier.
//!
//! The golden cases are loaded verbatim from `models/parity_cases_v2.json`
//! (produced by `training/export_onnx.py` under onnxruntime): raw 53-feature
//! vectors with expected logits, softmax probabilities, and argmax. tract must
//! reproduce the logits and probabilities within 1e-4 and the argmax exactly.
//!
//! These are gated on the `ml` feature so the crate still compiles and tests
//! cleanly with `--no-default-features`.
#![cfg(feature = "ml")]
// Integration-test crate: fixture-loading helpers (outside `#[test]` fns) use
// `.expect()`/`panic!` on the embedded golden JSON, not covered by
// clippy.toml's `allow-expect-in-tests`.
#![allow(clippy::expect_used, clippy::panic)]

use cleanton_common::{FileEntry, FileKind};
use cleanton_ml::{
    CleanupLabel, FEATURE_COUNT, FeatureVector, FileContext, MlAvailability, MlClassification,
    MlEngine, classify_features, logits_for_features,
};
use serde::Deserialize;

/// Recorded fixtures from `models/parity_cases_v2.json`.
const PARITY_CASES_JSON: &str = include_str!("../models/parity_cases_v2.json");

/// Logit/probability agreement demanded between tract and onnxruntime.
const PARITY_TOLERANCE: f32 = 1e-4;

#[derive(Debug, Deserialize)]
struct ParityFile {
    version: String,
    cases: Vec<ParityCase>,
}

#[derive(Debug, Deserialize)]
struct ParityCase {
    path: String,
    raw: Vec<f32>,
    logits: Vec<f32>,
    probs: Vec<f32>,
    predicted_index: usize,
    predicted_label: String,
    confidence: f32,
}

fn parity_cases() -> Vec<ParityCase> {
    let file: ParityFile = serde_json::from_str(PARITY_CASES_JSON).expect("parity cases parse");
    assert_eq!(file.version, "v2", "parity fixture version");
    assert!(
        file.cases.len() >= 20,
        "expected a substantial golden set, got {}",
        file.cases.len()
    );
    file.cases
}

fn raw_vector(case: &ParityCase) -> [f32; FEATURE_COUNT] {
    let raw: [f32; FEATURE_COUNT] = case
        .raw
        .clone()
        .try_into()
        .unwrap_or_else(|_| panic!("case {} must carry {FEATURE_COUNT} features", case.path));
    raw
}

fn label_for(name: &str) -> CleanupLabel {
    match name {
        "keep" => CleanupLabel::Keep,
        "safe-to-remove" => CleanupLabel::SafeToRemove,
        "likely-junk" => CleanupLabel::LikelyJunk,
        "uncertain" => CleanupLabel::Uncertain,
        other => panic!("unknown label in parity fixture: {other}"),
    }
}

#[test]
fn rust_tract_matches_python_onnx_logits_and_argmax() {
    let mut worst_drift = 0.0_f32;
    for case in parity_cases() {
        let raw = raw_vector(&case);
        let logits = logits_for_features(&raw).expect("inference should succeed");

        assert_eq!(case.logits.len(), 4, "case {}", case.path);
        for (index, (&actual, &expected)) in logits.iter().zip(case.logits.iter()).enumerate() {
            let drift = (actual - expected).abs();
            worst_drift = worst_drift.max(drift);
            assert!(
                drift <= PARITY_TOLERANCE,
                "logit {index} drift {drift} for {}: rust={actual} python={expected}",
                case.path
            );
        }

        // Same argmax as onnxruntime (first-maximum tie-breaking).
        let argmax = logits
            .iter()
            .enumerate()
            .fold((0, f32::NEG_INFINITY), |(best_i, best_v), (i, v)| {
                if *v > best_v {
                    (i, *v)
                } else {
                    (best_i, best_v)
                }
            })
            .0;
        assert_eq!(argmax, case.predicted_index, "argmax for {}", case.path);
    }
    // Surface the observed worst-case drift in test output (run with --nocapture).
    println!("worst logit drift across parity cases: {worst_drift:e}");
}

#[test]
fn rust_tract_matches_python_onnx_labels_and_confidence() {
    for case in parity_cases() {
        let raw = raw_vector(&case);
        let prediction = classify_features(&raw).expect("inference should succeed");

        assert_eq!(
            prediction.label,
            label_for(&case.predicted_label),
            "label mismatch for {}",
            case.path
        );
        assert!(
            (prediction.confidence - case.confidence).abs() <= PARITY_TOLERANCE,
            "confidence drift for {}: rust={} python={}",
            case.path,
            prediction.confidence,
            case.confidence
        );
        // The recorded softmax must be internally consistent with the argmax
        // probability tract reproduces.
        let recorded_max = case.probs.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        assert!(
            (prediction.confidence - recorded_max).abs() <= PARITY_TOLERANCE,
            "softmax drift for {}",
            case.path
        );
    }
}

#[test]
fn credential_document_and_source_vectors_are_never_classified_clean() {
    // Safety-critical fixtures from the golden set: credentials, user
    // documents, lockfiles, and source files must never be predicted as a
    // clean (removable) class.
    let critical_markers = ["/.ssh/", "/Documents/", "Cargo.lock", "main.py"];
    let mut checked = 0_usize;
    for case in parity_cases() {
        if !critical_markers
            .iter()
            .any(|marker| case.path.contains(marker))
        {
            continue;
        }
        checked += 1;
        let prediction = classify_features(&raw_vector(&case)).expect("inference");
        assert!(
            !matches!(
                prediction.label,
                CleanupLabel::SafeToRemove | CleanupLabel::LikelyJunk
            ),
            "critical path {} must never be a clean class, got {:?}",
            case.path,
            prediction.label
        );
    }
    assert!(
        checked >= 3,
        "expected credential/document/source fixtures in the golden set, found {checked}"
    );
}

#[test]
fn classify_features_is_deterministic() {
    let case = parity_cases()
        .into_iter()
        .next()
        .expect("at least one case");
    let raw = raw_vector(&case);
    let first = classify_features(&raw).expect("first");
    for _ in 0..16 {
        let again = classify_features(&raw).expect("repeat");
        assert_eq!(first, again);
    }
}

#[test]
fn feature_vector_roundtrips_through_classify_features() {
    let case = parity_cases()
        .into_iter()
        .next()
        .expect("at least one case");
    let vector = FeatureVector::new(raw_vector(&case));
    let prediction = classify_features(vector.values()).expect("inference");
    assert_eq!(prediction.label, label_for(&case.predicted_label));
}

#[test]
fn embedded_engine_runs_real_inference() {
    let engine = MlEngine::embedded();
    assert!(matches!(
        engine.availability(),
        MlAvailability::BackendReady { .. }
    ));

    // A regenerable build artifact (deterministic: no modified time -> age 0).
    let entry = FileEntry {
        path: "/Users/dev/code/api-server/target/release/app.o".into(),
        kind: FileKind::File,
        logical_bytes: 40_000_000,
        allocated_bytes: 40_000_000,
        modified: None,
        depth: 6,
        device_id: None,
        inode: None,
        hardlink_count: None,
        symlink_target: None,
        ignored_by_git: true,
    };
    let context = FileContext {
        has_gitignore: true,
        has_lockfile: true,
        sibling_count: 400,
        sibling_total_bytes: 400_000_000,
        ancestor_has_lockfile: true,
        ancestor_has_project_marker: true,
    };

    let prediction = engine.classify(&entry, &context).expect("inference");
    assert!(prediction.confidence > 0.5);

    // Deterministic across repeated calls (modified is None -> age is fixed).
    let again = engine.classify(&entry, &context).expect("inference");
    assert_eq!(prediction, again);

    // Sanity: it returns a structurally valid classification.
    let _: MlClassification = prediction;
}

#[test]
fn embedded_engine_keeps_a_credential_file() {
    let engine = MlEngine::embedded();
    let entry = FileEntry {
        path: "/Users/dev/.ssh/id_rsa".into(),
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
    };
    let context = FileContext {
        has_gitignore: false,
        has_lockfile: false,
        sibling_count: 8,
        sibling_total_bytes: 40_000,
        ancestor_has_lockfile: false,
        ancestor_has_project_marker: false,
    };

    let prediction = engine.classify(&entry, &context).expect("inference");
    assert!(
        !matches!(
            prediction.label,
            CleanupLabel::SafeToRemove | CleanupLabel::LikelyJunk
        ),
        "a credential file must never be classified as a clean class, got {:?}",
        prediction.label
    );
}
