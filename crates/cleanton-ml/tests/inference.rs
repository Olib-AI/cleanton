//! Parity + safety tests for the embedded ONNX classifier.
//!
//! These are gated on the `ml` feature so the crate still compiles and tests
//! cleanly with `--no-default-features`.
#![cfg(feature = "ml")]
// Fixture vectors are copied verbatim from `models/parity_cases.json`; keep them
// readable as recorded rather than re-grouping digits.
#![allow(clippy::unreadable_literal)]

use cleanton_common::{FileEntry, FileKind};
use cleanton_ml::{
    CleanupLabel, FeatureVector, FileContext, MlAvailability, MlClassification, MlEngine,
    classify_features,
};

/// One recorded Python/ONNX fixture: a raw 12-feature vector and the prediction
/// the exported model produced under onnxruntime. tract must reproduce both.
struct Case {
    raw: [f32; 12],
    label: CleanupLabel,
    confidence: f32,
}

/// Recorded from `models/parity_cases.json` (produced by `export_onnx.py`).
const PARITY_CASES: &[Case] = &[
    // /Users/dev/.ssh/id_rsa -> keep
    Case {
        raw: [
            0.0, 3.61247, 365.0, 4.0, 0.0, 0.0, 0.0, 0.0, 0.954243, 0.0, 0.0, 0.0,
        ],
        label: CleanupLabel::Keep,
        confidence: 0.999092,
    },
    // /Users/dev/Documents/thesis.pdf -> keep
    Case {
        raw: [
            55.0, 6.90309, 200.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.32222, 0.0, 0.0, 0.0,
        ],
        label: CleanupLabel::Keep,
        confidence: 0.998771,
    },
    // /Users/dev/code/api-server/src/main.rs -> keep
    Case {
        raw: [
            1.0, 3.61247, 5.0, 5.0, 8.0, 1.0, 1.0, 0.0, 1.11394, 0.0, 1.0, 0.0,
        ],
        label: CleanupLabel::Keep,
        confidence: 0.999997,
    },
    // /Users/dev/code/api-server/target/release/app.o -> safe-to-remove
    Case {
        raw: [
            36.0, 7.60206, 10.0, 6.0, 0.0, 1.0, 1.0, 0.0, 2.60314, 1.0, 0.0, 0.0,
        ],
        label: CleanupLabel::SafeToRemove,
        confidence: 1.0,
    },
    // /Users/dev/code/web-app/node_modules/react/index.js -> safe-to-remove
    Case {
        raw: [
            5.0, 5.30103, 30.0, 6.0, 0.0, 1.0, 1.0, 0.0, 2.95472, 0.0, 1.0, 0.0,
        ],
        label: CleanupLabel::SafeToRemove,
        confidence: 1.0,
    },
    // /Users/dev/Library/Caches/pip/wheels/foo.whl -> safe-to-remove
    Case {
        raw: [
            0.0, 6.69897, 120.0, 6.0, 0.0, 0.0, 0.0, 0.0, 2.47857, 0.0, 0.0, 1.0,
        ],
        label: CleanupLabel::SafeToRemove,
        confidence: 1.0,
    },
    // /Users/dev/code/ml-pipeline/.venv/.../numpy/x.py -> likely-junk
    Case {
        raw: [
            7.0, 5.69897, 200.0, 8.0, 0.0, 1.0, 0.0, 0.0, 2.69984, 0.0, 1.0, 0.0,
        ],
        label: CleanupLabel::LikelyJunk,
        confidence: 0.99984,
    },
    // /Users/dev/code/ml-pipeline/checkpoints/epoch-12.ckpt -> likely-junk
    Case {
        raw: [
            59.0, 9.30103, 120.0, 5.0, 0.0, 1.0, 0.0, 0.0, 1.04139, 0.0, 0.0, 0.0,
        ],
        label: CleanupLabel::LikelyJunk,
        confidence: 0.996421,
    },
    // /Users/dev/scratch/loose/target/blob.bin -> uncertain (near-miss decoy)
    Case {
        raw: [
            0.0, 6.69897, 50.0, 5.0, 1.0, 0.0, 0.0, 0.0, 0.954243, 1.0, 0.0, 0.0,
        ],
        label: CleanupLabel::Uncertain,
        confidence: 0.999917,
    },
    // /Users/dev/scratch/data.bin -> keep (unknown blob, conservative)
    Case {
        raw: [
            0.0, 6.0, 100.0, 3.0, 0.0, 0.0, 0.0, 0.0, 0.69897, 0.0, 0.0, 0.0,
        ],
        label: CleanupLabel::Keep,
        confidence: 0.821992,
    },
];

const CONFIDENCE_TOLERANCE: f32 = 2e-3;

#[test]
fn rust_tract_matches_python_onnx_outputs() {
    for case in PARITY_CASES {
        let prediction = classify_features(&case.raw).expect("inference should succeed");
        assert_eq!(
            prediction.label, case.label,
            "label mismatch for raw {:?}",
            case.raw
        );
        assert!(
            (prediction.confidence - case.confidence).abs() <= CONFIDENCE_TOLERANCE,
            "confidence drift for raw {:?}: rust={} python={}",
            case.raw,
            prediction.confidence,
            case.confidence
        );
    }
}

#[test]
fn credential_and_document_vectors_are_never_classified_clean() {
    // Raw feature vectors for safety-critical files (credentials, documents,
    // source). None may ever be predicted as a clean (removable) class.
    let critical: &[[f32; 12]] = &[
        // credential (id_rsa)
        [
            0.0, 3.61247, 365.0, 4.0, 0.0, 0.0, 0.0, 0.0, 0.954243, 0.0, 0.0, 0.0,
        ],
        // user document (thesis.pdf)
        [
            55.0, 6.90309, 200.0, 3.0, 0.0, 0.0, 0.0, 0.0, 1.32222, 0.0, 0.0, 0.0,
        ],
        // source file (main.rs)
        [
            1.0, 3.61247, 5.0, 5.0, 8.0, 1.0, 1.0, 0.0, 1.11394, 0.0, 1.0, 0.0,
        ],
    ];

    for raw in critical {
        let prediction = classify_features(raw).expect("inference should succeed");
        assert_eq!(
            prediction.label,
            CleanupLabel::Keep,
            "critical vector must be Keep, got {:?} for {:?}",
            prediction.label,
            raw
        );
        assert!(
            !matches!(
                prediction.label,
                CleanupLabel::SafeToRemove | CleanupLabel::LikelyJunk
            ),
            "critical vector must never be a clean class"
        );
    }
}

#[test]
fn classify_features_is_deterministic() {
    let raw = [
        36.0, 7.60206, 10.0, 6.0, 0.0, 1.0, 1.0, 0.0, 2.60314, 1.0, 0.0, 0.0,
    ];
    let first = classify_features(&raw).expect("first");
    for _ in 0..16 {
        let again = classify_features(&raw).expect("repeat");
        assert_eq!(first, again);
    }
}

#[test]
fn feature_vector_roundtrips_through_classify_features() {
    let vector = FeatureVector::new([
        5.0, 5.30103, 30.0, 6.0, 0.0, 1.0, 1.0, 0.0, 2.95472, 0.0, 1.0, 0.0,
    ]);
    let prediction = classify_features(vector.values()).expect("inference");
    assert_eq!(prediction.label, CleanupLabel::SafeToRemove);
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
