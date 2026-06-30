use std::{
    fmt,
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use cleanton_common::{CleantonError, FileEntry, FileKind, MlConfig};
use serde::{Deserialize, Serialize};

#[cfg(feature = "ml")]
mod inference;

#[cfg(feature = "ml")]
pub use inference::classify_features;

pub type MlResult<T> = std::result::Result<T, MlError>;

/// Synthetic path reported for the model embedded in the binary.
const EMBEDDED_MODEL_NAME: &str = "<embedded>/file_classifier_v1.onnx";

/// Trained ONNX classifier shipped inside the binary.
const EMBEDDED_MODEL_BYTES: &[u8] = include_bytes!("../models/file_classifier_v1.onnx");

pub const FEATURE_COUNT: usize = 12;
pub const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "extension_id",
    "size_log10",
    "age_days",
    "depth",
    "parent_id",
    "has_gitignore",
    "has_lockfile",
    "is_hidden",
    "sibling_count",
    "in_build_dir",
    "is_source_ext",
    "in_cache_dir",
];

const SECONDS_PER_DAY: f64 = 86_400.0;

const EXTENSION_ID_UNKNOWN: u8 = 0;
const EXTENSION_ID_RS: u8 = 1;
const EXTENSION_ID_SWIFT: u8 = 2;
const EXTENSION_ID_TS: u8 = 3;
const EXTENSION_ID_TSX: u8 = 4;
const EXTENSION_ID_JS: u8 = 5;
const EXTENSION_ID_JSX: u8 = 6;
const EXTENSION_ID_PY: u8 = 7;
const EXTENSION_ID_GO: u8 = 8;
const EXTENSION_ID_JAVA: u8 = 9;
const EXTENSION_ID_KT: u8 = 10;
const EXTENSION_ID_C: u8 = 11;
const EXTENSION_ID_H: u8 = 12;
const EXTENSION_ID_CPP: u8 = 13;
const EXTENSION_ID_HPP: u8 = 14;
const EXTENSION_ID_CS: u8 = 15;
const EXTENSION_ID_RB: u8 = 16;
const EXTENSION_ID_PHP: u8 = 17;
const EXTENSION_ID_SCALA: u8 = 18;
const EXTENSION_ID_SH: u8 = 19;
const EXTENSION_ID_ZSH: u8 = 20;
const EXTENSION_ID_FISH: u8 = 21;
const EXTENSION_ID_HTML: u8 = 22;
const EXTENSION_ID_CSS: u8 = 23;
const EXTENSION_ID_SCSS: u8 = 24;
const EXTENSION_ID_JSON: u8 = 25;
const EXTENSION_ID_TOML: u8 = 26;
const EXTENSION_ID_YAML: u8 = 27;
const EXTENSION_ID_YML: u8 = 28;
const EXTENSION_ID_LOCK: u8 = 29;
const EXTENSION_ID_MD: u8 = 30;
const EXTENSION_ID_TXT: u8 = 31;
const EXTENSION_ID_LOG: u8 = 32;
const EXTENSION_ID_TMP: u8 = 33;
const EXTENSION_ID_CACHE: u8 = 34;
const EXTENSION_ID_PYC: u8 = 35;
const EXTENSION_ID_O: u8 = 36;
const EXTENSION_ID_SO: u8 = 37;
const EXTENSION_ID_DYLIB: u8 = 38;
const EXTENSION_ID_DLL: u8 = 39;
const EXTENSION_ID_EXE: u8 = 40;
const EXTENSION_ID_A: u8 = 41;
const EXTENSION_ID_WASM: u8 = 42;
const EXTENSION_ID_CLASS: u8 = 43;
const EXTENSION_ID_JAR: u8 = 44;
const EXTENSION_ID_ZIP: u8 = 45;
const EXTENSION_ID_GZ: u8 = 46;
const EXTENSION_ID_TAR: u8 = 47;
const EXTENSION_ID_TGZ: u8 = 48;
const EXTENSION_ID_PNG: u8 = 49;
const EXTENSION_ID_JPG: u8 = 50;
const EXTENSION_ID_JPEG: u8 = 51;
const EXTENSION_ID_GIF: u8 = 52;
const EXTENSION_ID_WEBP: u8 = 53;
const EXTENSION_ID_SVG: u8 = 54;
const EXTENSION_ID_PDF: u8 = 55;
const EXTENSION_ID_DB: u8 = 56;
const EXTENSION_ID_SQLITE: u8 = 57;
const EXTENSION_ID_SQLITE3: u8 = 58;
const EXTENSION_ID_CKPT: u8 = 59;
const EXTENSION_ID_SAFETENSORS: u8 = 60;
const EXTENSION_ID_ONNX: u8 = 61;

const PARENT_ID_UNKNOWN: u8 = 0;
const PARENT_ID_TARGET: u8 = 1;
const PARENT_ID_BUILD: u8 = 2;
const PARENT_ID_DIST: u8 = 3;
const PARENT_ID_OUT: u8 = 4;
const PARENT_ID_CACHE: u8 = 5;
const PARENT_ID_TMP: u8 = 6;
const PARENT_ID_NODE_MODULES: u8 = 7;
const PARENT_ID_SRC: u8 = 8;
const PARENT_ID_SOURCES: u8 = 9;
const PARENT_ID_TESTS: u8 = 10;
const PARENT_ID_TEST: u8 = 11;
const PARENT_ID_DOCS: u8 = 12;
const PARENT_ID_ASSETS: u8 = 13;
const PARENT_ID_DERIVED_DATA: u8 = 14;
const PARENT_ID_NEXT: u8 = 15;
const PARENT_ID_NUXT: u8 = 16;
const PARENT_ID_VENV: u8 = 17;
const PARENT_ID_TOX: u8 = 18;
const PARENT_ID_MYPY_CACHE: u8 = 19;
const PARENT_ID_PYTEST_CACHE: u8 = 20;
const PARENT_ID_GIT: u8 = 21;
const PARENT_ID_CARGO: u8 = 22;
const PARENT_ID_WANDB: u8 = 23;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FeatureVector {
    values: [f32; FEATURE_COUNT],
}

impl FeatureVector {
    #[must_use]
    pub const fn new(values: [f32; FEATURE_COUNT]) -> Self {
        Self { values }
    }

    #[must_use]
    pub const fn values(&self) -> &[f32; FEATURE_COUNT] {
        &self.values
    }

    #[must_use]
    pub const fn into_values(self) -> [f32; FEATURE_COUNT] {
        self.values
    }

    #[must_use]
    pub fn as_slice(&self) -> &[f32] {
        &self.values
    }

    #[must_use]
    pub const fn extension_id(&self) -> f32 {
        self.values[0]
    }

    #[must_use]
    pub const fn size_log10(&self) -> f32 {
        self.values[1]
    }

    #[must_use]
    pub const fn age_days(&self) -> f32 {
        self.values[2]
    }

    #[must_use]
    pub const fn depth(&self) -> f32 {
        self.values[3]
    }

    #[must_use]
    pub const fn parent_id(&self) -> f32 {
        self.values[4]
    }

    #[must_use]
    pub const fn has_gitignore(&self) -> f32 {
        self.values[5]
    }

    #[must_use]
    pub const fn has_lockfile(&self) -> f32 {
        self.values[6]
    }

    #[must_use]
    pub const fn is_hidden(&self) -> f32 {
        self.values[7]
    }

    #[must_use]
    pub const fn sibling_count(&self) -> f32 {
        self.values[8]
    }

    #[must_use]
    pub const fn in_build_dir(&self) -> f32 {
        self.values[9]
    }

    #[must_use]
    pub const fn is_source_ext(&self) -> f32 {
        self.values[10]
    }

    #[must_use]
    pub const fn in_cache_dir(&self) -> f32 {
        self.values[11]
    }
}

impl From<[f32; FEATURE_COUNT]> for FeatureVector {
    fn from(values: [f32; FEATURE_COUNT]) -> Self {
        Self::new(values)
    }
}

impl AsRef<[f32; FEATURE_COUNT]> for FeatureVector {
    fn as_ref(&self) -> &[f32; FEATURE_COUNT] {
        self.values()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupLabel {
    SafeToRemove,
    LikelyJunk,
    Uncertain,
    Keep,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MlClassification {
    pub label: CleanupLabel,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileContext {
    pub has_gitignore: bool,
    pub has_lockfile: bool,
    pub sibling_count: u64,
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

#[must_use]
pub fn extract_features(entry: &FileEntry, context: &FileContext) -> FeatureVector {
    extract_features_at(entry, context, SystemTime::now())
}

fn extract_features_at(entry: &FileEntry, context: &FileContext, now: SystemTime) -> FeatureVector {
    let extension_id = extension_id(&entry.path);
    let size_log10 = log10_u64(entry.logical_bytes);
    let age_days = entry
        .modified
        .map_or(0.0, |modified| age_days_since(modified, now));
    let depth = bounded_usize_to_f32(entry.depth);
    let parent_id = parent_id(&entry.path);
    let has_gitignore = binary(context.has_gitignore);
    let has_lockfile = binary(context.has_lockfile);
    let is_hidden = binary(is_hidden(&entry.path));
    let sibling_count = log10_u64(context.sibling_count);
    let in_build_dir = binary(in_build_dir(&entry.path, entry.kind));
    let is_source_ext = binary(is_source_extension(&entry.path));
    let in_cache_dir = binary(in_cache_dir(&entry.path, entry.kind));

    FeatureVector::new([
        f32::from(extension_id),
        size_log10,
        age_days,
        depth,
        f32::from(parent_id),
        has_gitignore,
        has_lockfile,
        is_hidden,
        sibling_count,
        in_build_dir,
        is_source_ext,
        in_cache_dir,
    ])
}

fn extension_id(path: &Path) -> u8 {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return EXTENSION_ID_UNKNOWN;
    };

    match extension.to_ascii_lowercase().as_str() {
        "rs" => EXTENSION_ID_RS,
        "swift" => EXTENSION_ID_SWIFT,
        "ts" => EXTENSION_ID_TS,
        "tsx" => EXTENSION_ID_TSX,
        "js" => EXTENSION_ID_JS,
        "jsx" => EXTENSION_ID_JSX,
        "py" => EXTENSION_ID_PY,
        "go" => EXTENSION_ID_GO,
        "java" => EXTENSION_ID_JAVA,
        "kt" | "kts" => EXTENSION_ID_KT,
        "c" => EXTENSION_ID_C,
        "h" => EXTENSION_ID_H,
        "cc" | "cpp" | "cxx" => EXTENSION_ID_CPP,
        "hh" | "hpp" | "hxx" => EXTENSION_ID_HPP,
        "cs" => EXTENSION_ID_CS,
        "rb" => EXTENSION_ID_RB,
        "php" => EXTENSION_ID_PHP,
        "scala" => EXTENSION_ID_SCALA,
        "sh" | "bash" => EXTENSION_ID_SH,
        "zsh" => EXTENSION_ID_ZSH,
        "fish" => EXTENSION_ID_FISH,
        "html" | "htm" => EXTENSION_ID_HTML,
        "css" => EXTENSION_ID_CSS,
        "scss" | "sass" => EXTENSION_ID_SCSS,
        "json" => EXTENSION_ID_JSON,
        "toml" => EXTENSION_ID_TOML,
        "yaml" => EXTENSION_ID_YAML,
        "yml" => EXTENSION_ID_YML,
        "lock" => EXTENSION_ID_LOCK,
        "md" | "markdown" => EXTENSION_ID_MD,
        "txt" => EXTENSION_ID_TXT,
        "log" => EXTENSION_ID_LOG,
        "tmp" => EXTENSION_ID_TMP,
        "cache" => EXTENSION_ID_CACHE,
        "pyc" | "pyo" => EXTENSION_ID_PYC,
        "o" | "obj" => EXTENSION_ID_O,
        "so" => EXTENSION_ID_SO,
        "dylib" => EXTENSION_ID_DYLIB,
        "dll" => EXTENSION_ID_DLL,
        "exe" => EXTENSION_ID_EXE,
        "a" | "lib" => EXTENSION_ID_A,
        "wasm" => EXTENSION_ID_WASM,
        "class" => EXTENSION_ID_CLASS,
        "jar" => EXTENSION_ID_JAR,
        "zip" => EXTENSION_ID_ZIP,
        "gz" => EXTENSION_ID_GZ,
        "tar" => EXTENSION_ID_TAR,
        "tgz" => EXTENSION_ID_TGZ,
        "png" => EXTENSION_ID_PNG,
        "jpg" => EXTENSION_ID_JPG,
        "jpeg" => EXTENSION_ID_JPEG,
        "gif" => EXTENSION_ID_GIF,
        "webp" => EXTENSION_ID_WEBP,
        "svg" => EXTENSION_ID_SVG,
        "pdf" => EXTENSION_ID_PDF,
        "db" => EXTENSION_ID_DB,
        "sqlite" => EXTENSION_ID_SQLITE,
        "sqlite3" => EXTENSION_ID_SQLITE3,
        "ckpt" | "pt" | "pth" => EXTENSION_ID_CKPT,
        "safetensors" => EXTENSION_ID_SAFETENSORS,
        "onnx" => EXTENSION_ID_ONNX,
        _ => EXTENSION_ID_UNKNOWN,
    }
}

fn parent_id(path: &Path) -> u8 {
    let Some(parent) = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|parent| parent.to_str())
    else {
        return PARENT_ID_UNKNOWN;
    };

    directory_id(parent)
}

fn directory_id(directory: &str) -> u8 {
    match directory.to_ascii_lowercase().as_str() {
        "target" => PARENT_ID_TARGET,
        "build" | ".build" => PARENT_ID_BUILD,
        "dist" => PARENT_ID_DIST,
        "out" => PARENT_ID_OUT,
        "cache" | ".cache" => PARENT_ID_CACHE,
        "tmp" | "temp" => PARENT_ID_TMP,
        "node_modules" => PARENT_ID_NODE_MODULES,
        "src" => PARENT_ID_SRC,
        "sources" => PARENT_ID_SOURCES,
        "tests" | "__tests__" => PARENT_ID_TESTS,
        "test" => PARENT_ID_TEST,
        "docs" | "doc" => PARENT_ID_DOCS,
        "assets" | "resources" => PARENT_ID_ASSETS,
        "deriveddata" => PARENT_ID_DERIVED_DATA,
        ".next" => PARENT_ID_NEXT,
        ".nuxt" => PARENT_ID_NUXT,
        ".venv" | "venv" => PARENT_ID_VENV,
        ".tox" => PARENT_ID_TOX,
        ".mypy_cache" => PARENT_ID_MYPY_CACHE,
        ".pytest_cache" => PARENT_ID_PYTEST_CACHE,
        ".git" => PARENT_ID_GIT,
        ".cargo" | "cargo" => PARENT_ID_CARGO,
        "wandb" => PARENT_ID_WANDB,
        _ => PARENT_ID_UNKNOWN,
    }
}

fn is_source_extension(path: &Path) -> bool {
    matches!(
        extension_id(path),
        EXTENSION_ID_RS
            | EXTENSION_ID_SWIFT
            | EXTENSION_ID_TS
            | EXTENSION_ID_TSX
            | EXTENSION_ID_JS
            | EXTENSION_ID_JSX
            | EXTENSION_ID_PY
            | EXTENSION_ID_GO
            | EXTENSION_ID_JAVA
            | EXTENSION_ID_KT
            | EXTENSION_ID_C
            | EXTENSION_ID_H
            | EXTENSION_ID_CPP
            | EXTENSION_ID_HPP
            | EXTENSION_ID_CS
            | EXTENSION_ID_RB
            | EXTENSION_ID_PHP
            | EXTENSION_ID_SCALA
            | EXTENSION_ID_SH
            | EXTENSION_ID_ZSH
            | EXTENSION_ID_FISH
            | EXTENSION_ID_HTML
            | EXTENSION_ID_CSS
            | EXTENSION_ID_SCSS
    )
}

fn in_build_dir(path: &Path, kind: FileKind) -> bool {
    any_directory_component(path, kind, |component| {
        matches!(
            component,
            "target"
                | "build"
                | ".build"
                | "dist"
                | "out"
                | ".next"
                | ".nuxt"
                | ".svelte-kit"
                | "coverage"
                | "deriveddata"
                | "debug"
                | "release"
        )
    })
}

fn in_cache_dir(path: &Path, kind: FileKind) -> bool {
    any_directory_component(path, kind, |component| {
        component.contains("cache") || component.contains("tmp")
    })
}

fn any_directory_component(
    path: &Path,
    kind: FileKind,
    mut predicate: impl FnMut(&str) -> bool,
) -> bool {
    let signal_path = if matches!(kind, FileKind::Directory) {
        path
    } else {
        path.parent().unwrap_or_else(|| Path::new(""))
    };

    signal_path.components().any(|component| {
        let std::path::Component::Normal(name) = component else {
            return false;
        };
        name.to_str()
            .is_some_and(|name| predicate(&name.to_ascii_lowercase()))
    })
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|file_name| file_name.to_str())
        .is_some_and(|file_name| {
            file_name.starts_with('.') && file_name != "." && file_name != ".."
        })
}

#[allow(clippy::cast_possible_truncation)]
fn age_days_since(modified: SystemTime, now: SystemTime) -> f32 {
    let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
    (age.as_secs_f64() / SECONDS_PER_DAY) as f32
}

#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn log10_u64(value: u64) -> f32 {
    ((value as f64) + 1.0).log10() as f32
}

fn bounded_usize_to_f32(value: usize) -> f32 {
    u16::try_from(value).map_or(f32::from(u16::MAX), f32::from)
}

fn binary(value: bool) -> f32 {
    if value { 1.0 } else { 0.0 }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{Duration, UNIX_EPOCH},
    };

    use cleanton_common::MlConfig;

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
        }
    }

    fn assert_float_eq(actual: f32, expected: f32) {
        assert!(
            (actual - expected).abs() < f32::EPSILON,
            "expected {actual} to equal {expected}",
        );
    }

    fn assert_feature_values_eq(actual: [f32; FEATURE_COUNT], expected: [f32; FEATURE_COUNT]) {
        for (actual, expected) in actual.into_iter().zip(expected) {
            assert_float_eq(actual, expected);
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
    fn extracts_documented_twelve_feature_vector() {
        let now = UNIX_EPOCH + Duration::from_hours(240);
        let mut entry = file_entry("/workspace/project/target/cache/.artifact.rs");
        entry.logical_bytes = 999;
        entry.modified = Some(now - Duration::from_hours(48));
        entry.depth = 4;

        let context = FileContext {
            has_gitignore: true,
            has_lockfile: false,
            sibling_count: 99,
        };
        let features = extract_features_at(&entry, &context, now);

        assert_eq!(FEATURE_COUNT, 12);
        assert_eq!(features.values().len(), FEATURE_COUNT);
        assert_float_eq(features.extension_id(), 1.0);
        assert_float_eq(features.size_log10(), 3.0);
        assert_float_eq(features.age_days(), 2.0);
        assert_float_eq(features.depth(), 4.0);
        assert_float_eq(features.parent_id(), 5.0);
        assert_float_eq(features.has_gitignore(), 1.0);
        assert_float_eq(features.has_lockfile(), 0.0);
        assert_float_eq(features.is_hidden(), 1.0);
        assert_float_eq(features.sibling_count(), 2.0);
        assert_float_eq(features.in_build_dir(), 1.0);
        assert_float_eq(features.is_source_ext(), 1.0);
        assert_float_eq(features.in_cache_dir(), 1.0);
        assert_feature_values_eq(
            features.into_values(),
            [1.0, 3.0, 2.0, 4.0, 5.0, 1.0, 0.0, 1.0, 2.0, 1.0, 1.0, 1.0],
        );
    }

    #[test]
    fn unknown_paths_extract_conservative_zero_signals() {
        let entry = file_entry("/workspace/project/notes.unknown");
        let features = extract_features_at(&entry, &context(), UNIX_EPOCH);

        assert_feature_values_eq(
            features.into_values(),
            [
                0.0,
                std::f32::consts::LOG10_2,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
            ],
        );
    }
}
