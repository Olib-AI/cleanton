use std::{
    fmt,
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use cleanton_common::{CleantonError, FileEntry, MlConfig};
use serde::{Deserialize, Serialize};

mod features;
#[cfg(feature = "ml")]
mod inference;

pub use features::{FEATURE_COUNT, FEATURE_NAMES, FeatureVector, SCHEMA_SHA256, extract_features};
#[cfg(feature = "ml")]
pub use inference::{classify_features, logits_for_features};

pub type MlResult<T> = std::result::Result<T, MlError>;

/// Synthetic path reported for the model embedded in the binary.
const EMBEDDED_MODEL_NAME: &str = "<embedded>/file_classifier_v2.onnx";

/// Trained ONNX classifier shipped inside the binary.
const EMBEDDED_MODEL_BYTES: &[u8] = include_bytes!("../models/file_classifier_v2.onnx");

/// Embedded sidecar: normalization constants, label order, and the full v2
/// feature schema (vocab tables + semantics + schema hash). The `features`
/// module's tests assert the code-generated tables match it exactly.
pub(crate) const EMBEDDED_SIDECAR: &str = include_str!("../models/file_classifier_v2.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupLabel {
    SafeToRemove,
    LikelyJunk,
    Uncertain,
    Keep,
}

impl fmt::Display for CleanupLabel {
    /// Kebab-case text matching the serde encoding, so every UI surface (CLI
    /// JSON, CLI badges, TUI badges, app reason strings) shows the same label.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SafeToRemove => "safe-to-remove",
            Self::LikelyJunk => "likely-junk",
            Self::Uncertain => "uncertain",
            Self::Keep => "keep",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MlClassification {
    pub label: CleanupLabel,
    pub confidence: f32,
}

/// Cheap per-file context derived from scan data alone (no extra filesystem
/// access). `has_gitignore` / `has_lockfile` / `sibling_count` /
/// `sibling_total_bytes` describe the file's PARENT directory contents; the
/// `ancestor_*` flags scan every ancestor directory within the scan (parent
/// upward) for a known lockfile or project marker (manifest or `.git` dir).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileContext {
    pub has_gitignore: bool,
    pub has_lockfile: bool,
    pub sibling_count: u64,
    /// Sum of logical bytes over the entries sharing the parent directory.
    pub sibling_total_bytes: u64,
    /// Any ancestor directory within the scan contains a known lockfile.
    pub ancestor_has_lockfile: bool,
    /// Any ancestor directory within the scan contains a project manifest
    /// (`Cargo.toml`, `package.json`, ...) or a `.git` directory.
    pub ancestor_has_project_marker: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlModel {
    pub path: PathBuf,
    pub byte_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MlUnavailableReason {
    Disabled,
    NoInferenceBackend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MlAvailability {
    Disabled,
    BackendUnavailable {
        reason: MlUnavailableReason,
        model: MlModel,
    },
    /// A local inference backend is loaded and ready to classify.
    BackendReady {
        model: MlModel,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MlError {
    ModelPathNotConfigured,
    RemoteModelUnsupported {
        path: PathBuf,
    },
    ModelNotFound {
        path: PathBuf,
    },
    ModelPathNotFile {
        path: PathBuf,
    },
    ModelUnreadable {
        path: PathBuf,
        message: String,
    },
    InferenceUnavailable {
        reason: MlUnavailableReason,
        model_path: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlEngine {
    availability: MlAvailability,
}

impl Default for MlEngine {
    fn default() -> Self {
        Self::disabled()
    }
}

impl MlEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::disabled()
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self {
            availability: MlAvailability::Disabled,
        }
    }

    /// Construct an engine backed by the classifier embedded in the binary.
    ///
    /// With the `ml` feature enabled (the default) this returns a ready engine
    /// whose [`classify`](Self::classify) runs real `tract` inference. With the
    /// feature disabled it reports the embedded model but fails closed with a
    /// clear "no inference backend" error, never a fabricated label.
    #[must_use]
    pub fn embedded() -> Self {
        let model = MlModel {
            path: PathBuf::from(EMBEDDED_MODEL_NAME),
            byte_len: EMBEDDED_MODEL_BYTES.len() as u64,
        };

        #[cfg(feature = "ml")]
        let availability = MlAvailability::BackendReady { model };
        #[cfg(not(feature = "ml"))]
        let availability = MlAvailability::BackendUnavailable {
            reason: MlUnavailableReason::NoInferenceBackend,
            model,
        };

        Self { availability }
    }

    pub fn from_config(config: &MlConfig) -> MlResult<Self> {
        if !config.enabled {
            return Ok(Self::disabled());
        }

        Self::from_model_path(&config.model_path)
    }

    pub fn from_model_path(path: impl AsRef<Path>) -> MlResult<Self> {
        let model = Self::validate_model_path(path)?;
        Ok(Self {
            availability: MlAvailability::BackendUnavailable {
                reason: MlUnavailableReason::NoInferenceBackend,
                model,
            },
        })
    }

    pub fn validate_model_path(path: impl AsRef<Path>) -> MlResult<MlModel> {
        let path = path.as_ref();

        if path.as_os_str().is_empty() {
            return Err(MlError::ModelPathNotConfigured);
        }

        let path_text = path.to_string_lossy();
        if path_text.contains("://") {
            return Err(MlError::RemoteModelUnsupported {
                path: path.to_path_buf(),
            });
        }

        let metadata = fs::metadata(path).map_err(|source| match source.kind() {
            ErrorKind::NotFound => MlError::ModelNotFound {
                path: path.to_path_buf(),
            },
            _ => MlError::ModelUnreadable {
                path: path.to_path_buf(),
                message: source.to_string(),
            },
        })?;

        if !metadata.is_file() {
            return Err(MlError::ModelPathNotFile {
                path: path.to_path_buf(),
            });
        }

        File::open(path).map_err(|source| MlError::ModelUnreadable {
            path: path.to_path_buf(),
            message: source.to_string(),
        })?;

        Ok(MlModel {
            path: path.to_path_buf(),
            byte_len: metadata.len(),
        })
    }

    #[must_use]
    pub fn availability(&self) -> &MlAvailability {
        &self.availability
    }

    pub fn classify(&self, entry: &FileEntry, context: &FileContext) -> MlResult<MlClassification> {
        match &self.availability {
            MlAvailability::Disabled => Err(MlError::InferenceUnavailable {
                reason: MlUnavailableReason::Disabled,
                model_path: None,
            }),
            MlAvailability::BackendUnavailable { reason, model } => {
                Err(MlError::InferenceUnavailable {
                    reason: *reason,
                    model_path: Some(model.path.clone()),
                })
            }
            MlAvailability::BackendReady { model } => Self::classify_ready(entry, context, model),
        }
    }

    #[cfg(feature = "ml")]
    fn classify_ready(
        entry: &FileEntry,
        context: &FileContext,
        _model: &MlModel,
    ) -> MlResult<MlClassification> {
        let features = extract_features(entry, context);
        inference::classify_features(features.values())
    }

    #[cfg(not(feature = "ml"))]
    fn classify_ready(
        _entry: &FileEntry,
        _context: &FileContext,
        model: &MlModel,
    ) -> MlResult<MlClassification> {
        Err(MlError::InferenceUnavailable {
            reason: MlUnavailableReason::NoInferenceBackend,
            model_path: Some(model.path.clone()),
        })
    }
}

impl fmt::Display for MlUnavailableReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("ML is disabled"),
            Self::NoInferenceBackend => {
                formatter.write_str("no local ML inference backend is available")
            }
        }
    }
}

impl fmt::Display for MlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelPathNotConfigured => formatter.write_str("ML model path is not configured"),
            Self::RemoteModelUnsupported { path } => write!(
                formatter,
                "ML model path must be a local filesystem path: {}",
                path.display()
            ),
            Self::ModelNotFound { path } => {
                write!(formatter, "ML model file not found: {}", path.display())
            }
            Self::ModelPathNotFile { path } => {
                write!(formatter, "ML model path is not a file: {}", path.display())
            }
            Self::ModelUnreadable { path, message } => write!(
                formatter,
                "ML model file is not readable: {}: {message}",
                path.display()
            ),
            Self::InferenceUnavailable { reason, model_path } => {
                if let Some(path) = model_path {
                    write!(
                        formatter,
                        "ML inference unavailable for {}: {reason}",
                        path.display()
                    )
                } else {
                    write!(formatter, "ML inference unavailable: {reason}")
                }
            }
        }
    }
}

impl std::error::Error for MlError {}

impl From<MlError> for CleantonError {
    fn from(error: MlError) -> Self {
        Self::Ml(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use cleanton_common::{FileKind, MlConfig};

    use super::*;

    fn file_entry(path: impl Into<PathBuf>) -> FileEntry {
        FileEntry {
            path: path.into(),
            kind: FileKind::File,
            logical_bytes: 1,
            allocated_bytes: 1,
            modified: None,
            depth: 0,
            device_id: None,
            inode: None,
            hardlink_count: None,
            symlink_target: None,
            ignored_by_git: false,
        }
    }

    fn context() -> FileContext {
        FileContext {
            has_gitignore: false,
            has_lockfile: false,
            sibling_count: 0,
            sibling_total_bytes: 0,
            ancestor_has_lockfile: false,
            ancestor_has_project_marker: false,
        }
    }

    #[test]
    fn disabled_engine_fails_closed_for_classification() {
        let engine = MlEngine::new();
        let entry = file_entry("/workspace/target/cache.bin");

        let error = engine
            .classify(&entry, &context())
            .expect_err("classification should fail closed");

        assert_eq!(
            error,
            MlError::InferenceUnavailable {
                reason: MlUnavailableReason::Disabled,
                model_path: None,
            }
        );
    }

    #[test]
    fn classification_does_not_use_path_or_extension_heuristics() {
        let engine = MlEngine::new();

        for path in [
            "/workspace/node_modules/package/index.js",
            "/workspace/src/main.rs",
        ] {
            let error = engine
                .classify(&file_entry(path), &context())
                .expect_err("classification must not return labels without a backend");

            assert!(matches!(
                error,
                MlError::InferenceUnavailable {
                    reason: MlUnavailableReason::Disabled,
                    model_path: None,
                }
            ));
        }
    }

    #[test]
    fn disabled_config_does_not_require_a_model_path() {
        let config = MlConfig {
            enabled: false,
            model_path: PathBuf::new(),
            confidence_threshold: 0.85,
        };

        let engine = MlEngine::from_config(&config).expect("disabled ML should construct");

        assert_eq!(engine.availability(), &MlAvailability::Disabled);
    }

    #[test]
    fn enabled_config_validates_model_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_path = temp.path().join("missing-model.bin");
        let config = MlConfig {
            enabled: true,
            model_path: model_path.clone(),
            confidence_threshold: 0.85,
        };

        let error = MlEngine::from_config(&config).expect_err("missing model should fail");

        assert_eq!(error, MlError::ModelNotFound { path: model_path });
    }

    #[test]
    fn local_model_file_constructs_but_inference_is_unavailable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_path = temp.path().join("model.bin");
        std::fs::write(&model_path, b"not-a-real-model").expect("write model");

        let engine = MlEngine::from_model_path(&model_path).expect("model path should validate");
        assert_eq!(
            engine.availability(),
            &MlAvailability::BackendUnavailable {
                reason: MlUnavailableReason::NoInferenceBackend,
                model: MlModel {
                    path: model_path.clone(),
                    byte_len: 16,
                },
            }
        );

        let error = engine
            .classify(&file_entry("/workspace/cache/file.bin"), &context())
            .expect_err("backend is intentionally unavailable");

        assert_eq!(
            error,
            MlError::InferenceUnavailable {
                reason: MlUnavailableReason::NoInferenceBackend,
                model_path: Some(model_path),
            }
        );
    }

    #[test]
    fn remote_model_paths_are_rejected() {
        let error = MlEngine::from_model_path("https://example.test/model.onnx")
            .expect_err("remote model path should be rejected");

        assert_eq!(
            error,
            MlError::RemoteModelUnsupported {
                path: PathBuf::from("https://example.test/model.onnx"),
            }
        );
    }

    #[test]
    fn classification_types_remain_serializable() {
        let classification = MlClassification {
            label: CleanupLabel::SafeToRemove,
            confidence: 0.5,
        };

        let label_json = serde_json::to_string(&CleanupLabel::LikelyJunk).expect("serialize label");
        let classification_json =
            serde_json::to_string(&classification).expect("serialize classification");
        let decoded: MlClassification =
            serde_json::from_str(&classification_json).expect("deserialize classification");

        assert_eq!(label_json, "\"likely-junk\"");
        assert_eq!(decoded, classification);
    }

    #[test]
    fn extracts_the_documented_v2_feature_vector_shape() {
        // Detailed per-feature parity lives in `features::tests`; here we pin
        // the public contract: 53 features in the sidecar's order.
        assert_eq!(FEATURE_COUNT, 53);
        assert_eq!(FEATURE_NAMES.len(), FEATURE_COUNT);
        let features =
            extract_features(&file_entry("/workspace/project/notes.unknown"), &context());
        assert_eq!(features.values().len(), FEATURE_COUNT);
        assert_eq!(features.as_slice().len(), FEATURE_COUNT);
    }
}
