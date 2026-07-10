//! Feature schema v2 — the Rust port of `training/features.py`.
//!
//! Every vocabulary table and component set below is code-generated from the
//! embedded sidecar (`models/file_classifier_v2.json`), and the unit tests at
//! the bottom re-parse that sidecar and assert every table, the feature order,
//! and the schema hash still match — so the Rust port and the sidecar cannot
//! silently drift.
//!
//! Semantics pinned by the sidecar (`schema.semantics`, covered by the schema
//! hash) that this port follows exactly:
//!
//! - `depth` is the count of `Normal` components of the ABSOLUTE path
//!   (`/Users/maya/x` -> 3), NOT the scanner's root-relative `FileEntry::depth`.
//! - `size_bytes` is `FileEntry::logical_bytes` (directories carry the
//!   scanner's aggregated subtree total).
//! - `age_days` is `duration_since(modified).as_secs_f64() / 86400` truncated
//!   to `f32` first (0.0 when `modified` is `None`); the log10 then runs in
//!   `f64` and truncates back, mirroring the Python trainer bit-for-bit.
//! - Lowercasing is Unicode (`str::to_lowercase`, mirroring Python
//!   `str.lower`); hashed-name token characters are restricted to ASCII
//!   `[a-z0-9]` so both sides agree on every ASCII name.
//! - Rust `Path::extension` returning `Some("")` for names ending in `.` and
//!   Python returning `None` both map to extension id 0 (the empty string is
//!   not in the vocabulary).

use std::{
    borrow::Cow,
    path::{Component, Path},
    time::{Duration, SystemTime},
};

use cleanton_common::{FileEntry, FileKind};
use serde::{Deserialize, Serialize};

use crate::FileContext;

pub const FEATURE_COUNT: usize = 53;

/// Feature order — must match the sidecar's `schema.feature_order` exactly
/// (asserted by `feature_names_match_sidecar`).
pub const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "extension_id",
    "parent_id",
    "grandparent_id",
    "size_log10",
    "age_log10",
    "depth",
    "sibling_count_log10",
    "name_len_log10",
    "digit_ratio",
    "size_vs_siblings",
    "is_dir",
    "is_hidden",
    "under_hidden_dir",
    "has_gitignore",
    "has_lockfile",
    "ancestor_has_lockfile",
    "ancestor_has_project_marker",
    "in_build_dir",
    "in_cache_dir",
    "in_node_modules",
    "in_venv",
    "in_git_dir",
    "in_library",
    "in_library_caches",
    "in_app_support",
    "in_containers",
    "in_logs",
    "in_derived_data",
    "in_user_data",
    "in_system_root",
    "is_source_ext",
    "is_media_ext",
    "is_doc_ext",
    "is_archive_ext",
    "is_artifact_ext",
    "is_ml_weight_ext",
    "is_log_tmp_ext",
    "name_hash_bucket_0",
    "name_hash_bucket_1",
    "name_hash_bucket_2",
    "name_hash_bucket_3",
    "name_hash_bucket_4",
    "name_hash_bucket_5",
    "name_hash_bucket_6",
    "name_hash_bucket_7",
    "name_hash_bucket_8",
    "name_hash_bucket_9",
    "name_hash_bucket_10",
    "name_hash_bucket_11",
    "name_hash_bucket_12",
    "name_hash_bucket_13",
    "name_hash_bucket_14",
    "name_hash_bucket_15",
];

/// SHA-256 of the canonical schema JSON the trainer exported. The tests both
/// assert this equals the sidecar's `schema_sha256` field and recompute it
/// from the sidecar's `schema` object, so any semantic change to the feature
/// contract fails loudly here.
pub const SCHEMA_SHA256: &str = "97761b9ec6fd08fbaac24546659d8bde6323d2ec2ab2127f2e0409da1953cc03";

const SECONDS_PER_DAY: f64 = 86_400.0;
const NAME_HASH_BUCKETS: usize = 16;
/// Number of features before the hashed-name buckets (indices 37..52).
const HEAD_FEATURES: usize = FEATURE_COUNT - NAME_HASH_BUCKETS;

// --- Component sets (generated from the sidecar; asserted against it) ----------

const BUILD_COMPONENTS: &[&str] = &[
    ".build",
    ".next",
    ".nuxt",
    ".stack-work",
    ".svelte-kit",
    "_build",
    "build",
    "coverage",
    "debug",
    "deriveddata",
    "dist",
    "out",
    "release",
    "target",
    "zig-cache",
    "zig-out",
];

const CMAKE_BUILD_PREFIX: &str = "cmake-build-";

/// Compared case-SENSITIVELY, exactly like the Python reference.
const VENV_COMPONENTS: &[&str] = &[".tox", ".venv", "site-packages", "venv", "virtualenvs"];

const USER_DATA_ROOTS: &[&str] = &[
    "desktop",
    "documents",
    "downloads",
    "movies",
    "music",
    "pictures",
];

const SYSTEM_ROOTS: &[&str] = &[
    "applications",
    "bin",
    "etc",
    "library",
    "private",
    "sbin",
    "system",
    "usr",
    "var",
];

// --- Feature vector -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FeatureVector {
    values: [f32; FEATURE_COUNT],
}

// serde's built-in array impls stop at 32 elements, so the 53-wide vector is
// encoded as a plain sequence by hand (mirroring `#[serde(transparent)]`).
impl Serialize for FeatureVector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.values.iter())
    }
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

// serde only derives `Deserialize` for arrays up to 32 elements, so the
// 53-wide vector is decoded through a length-checked `Vec`.
impl<'de> Deserialize<'de> for FeatureVector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::<f32>::deserialize(deserializer)?;
        let length = values.len();
        let values: [f32; FEATURE_COUNT] = values.try_into().map_err(|_| {
            serde::de::Error::invalid_length(length, &"an array of 53 feature values")
        })?;
        Ok(Self { values })
    }
}

// --- Extraction -------------------------------------------------------------------

#[must_use]
pub fn extract_features(entry: &FileEntry, context: &FileContext) -> FeatureVector {
    extract_features_at(entry, context, SystemTime::now())
}

pub(crate) fn extract_features_at(
    entry: &FileEntry,
    context: &FileContext,
    now: SystemTime,
) -> FeatureVector {
    let path = entry.path.as_path();
    let kind = entry.kind;

    let name = basename(path);
    let name_len = name.len();
    let digit_count = name.bytes().filter(u8::is_ascii_digit).count();

    // Component views used by the path-shape features. `signal` is the path
    // itself for directories and the parent for files (the v1 convention);
    // `full` is every Normal component of the absolute path.
    let full: Vec<Cow<'_, str>> = normal_components(path);
    let signal: Vec<Cow<'_, str>> = normal_components(signal_path(path, kind));
    let signal_lower: Vec<String> = signal
        .iter()
        .map(|component| component.to_lowercase())
        .collect();

    let ext_id = extension_id(path);
    let size_log10 = log10_plus1_u64(entry.logical_bytes);
    let age_days = entry
        .modified
        .map_or(0.0_f32, |modified| age_days_since(modified, now));
    let age_log10 = log10_plus1_f32(age_days);
    let sibling_total_log10 = log10_plus1_u64(context.sibling_total_bytes);

    let head: [f32; HEAD_FEATURES] = [
        f32::from(ext_id),
        f32::from(parent_id(path)),
        f32::from(grandparent_id(path)),
        size_log10,
        age_log10,
        bounded_usize_to_f32(full.len()),
        log10_plus1_u64(context.sibling_count),
        log10_plus1_u64(name_len as u64),
        digit_ratio(digit_count, name_len),
        size_log10 - sibling_total_log10,
        binary(matches!(kind, FileKind::Directory)),
        binary(is_hidden_name(&name)),
        binary(under_hidden_dir(path)),
        binary(context.has_gitignore),
        binary(context.has_lockfile),
        binary(context.ancestor_has_lockfile),
        binary(context.ancestor_has_project_marker),
        binary(in_build_dir(&signal_lower)),
        binary(in_cache_dir(&signal_lower)),
        binary(has_component(&signal, "node_modules")),
        binary(in_venv(&signal)),
        binary(has_component(&signal, ".git")),
        binary(has_lower_component(&signal_lower, "library")),
        binary(consecutive(&signal_lower, "library", "caches")),
        binary(consecutive(&signal_lower, "library", "application support")),
        binary(
            consecutive(&signal_lower, "library", "containers")
                || consecutive(&signal_lower, "library", "group containers"),
        ),
        binary(
            consecutive(&signal_lower, "library", "logs")
                || has_lower_component(&signal_lower, "logs"),
        ),
        binary(has_lower_component(&signal_lower, "deriveddata")),
        binary(in_user_data(&full)),
        binary(in_system_root(&full)),
        binary(is_source_ext_id(ext_id)),
        binary(is_media_ext_id(ext_id)),
        binary(is_doc_ext_id(ext_id)),
        binary(is_archive_ext_id(ext_id)),
        binary(is_artifact_ext_id(ext_id)),
        binary(is_ml_weight_ext_id(ext_id)),
        binary(is_log_tmp_ext_id(ext_id)),
    ];
    let buckets = name_hash_buckets(&name);

    let mut values = [0.0_f32; FEATURE_COUNT];
    for (slot, value) in values.iter_mut().zip(head.into_iter().chain(buckets)) {
        *slot = value;
    }
    FeatureVector::new(values)
}

// --- Vocabulary lookups (generated from the sidecar) --------------------------------

/// Extension id per the sidecar's `schema.extension_ids` (0 = unknown).
// Code-generated vocabulary table: one arm per sidecar alias group, kept flat
// on purpose so the sidecar-parity test reads 1:1 against it.
#[allow(clippy::too_many_lines)]
fn extension_id(path: &Path) -> u16 {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return 0;
    };

    match extension.to_lowercase().as_str() {
        "rs" => 1,
        "swift" => 2,
        "ts" => 3,
        "tsx" => 4,
        "js" => 5,
        "jsx" => 6,
        "py" => 7,
        "go" => 8,
        "java" => 9,
        "kt" | "kts" => 10,
        "c" => 11,
        "h" => 12,
        "cc" | "cpp" | "cxx" => 13,
        "hh" | "hpp" | "hxx" => 14,
        "cs" => 15,
        "rb" => 16,
        "php" => 17,
        "scala" => 18,
        "bash" | "sh" => 19,
        "zsh" => 20,
        "fish" => 21,
        "htm" | "html" => 22,
        "css" => 23,
        "sass" | "scss" => 24,
        "json" => 25,
        "toml" => 26,
        "yaml" => 27,
        "yml" => 28,
        "lock" => 29,
        "markdown" | "md" => 30,
        "txt" => 31,
        "log" => 32,
        "tmp" => 33,
        "cache" => 34,
        "pyc" | "pyo" => 35,
        "o" | "obj" => 36,
        "so" => 37,
        "dylib" => 38,
        "dll" => 39,
        "exe" => 40,
        "a" | "lib" => 41,
        "wasm" => 42,
        "class" => 43,
        "jar" => 44,
        "zip" => 45,
        "gz" => 46,
        "tar" => 47,
        "tgz" => 48,
        "png" => 49,
        "jpg" => 50,
        "jpeg" => 51,
        "gif" => 52,
        "webp" => 53,
        "svg" => 54,
        "pdf" => 55,
        "db" => 56,
        "sqlite" => 57,
        "sqlite3" => 58,
        "ckpt" | "pt" | "pth" => 59,
        "safetensors" => 60,
        "onnx" => 61,
        "ipynb" => 62,
        "whl" => 63,
        "dmg" => 64,
        "pkg" => 65,
        "mov" => 66,
        "m4v" | "mp4" => 67,
        "avi" => 68,
        "mkv" => 69,
        "webm" => 70,
        "mp3" => 71,
        "aac" | "m4a" => 72,
        "wav" => 73,
        "flac" => 74,
        "ogg" => 75,
        "heic" | "heif" => 76,
        "tif" | "tiff" => 77,
        "bmp" => 78,
        "raw" => 79,
        "doc" | "docx" => 80,
        "xls" | "xlsx" => 81,
        "ppt" | "pptx" => 82,
        "key" => 83,
        "pages" => 84,
        "numbers" => 85,
        "csv" | "tsv" => 86,
        "xml" => 87,
        "plist" => 88,
        "rlib" => 89,
        "rmeta" => 90,
        "d" => 91,
        "pdb" => 92,
        "node" => 93,
        "map" => 94,
        "otf" | "ttf" => 95,
        "woff" | "woff2" => 96,
        "ico" => 97,
        "icns" => 98,
        "jsonl" => 99,
        "arrow" | "parquet" => 100,
        "npy" | "npz" => 101,
        "h5" | "hdf5" => 102,
        "gguf" => 103,
        "bin" => 104,
        "dat" => 105,
        "swp" => 106,
        "bak" | "old" | "orig" => 107,
        "crdownload" | "download" | "part" => 108,
        "torrent" => 109,
        "iso" => 110,
        "bz2" | "xz" => 111,
        "7z" | "rar" => 112,
        "br" | "zst" => 113,
        "deb" | "rpm" => 114,
        "aab" | "apk" | "ipa" => 115,
        "cjs" | "mjs" => 116,
        "vue" => 117,
        "astro" | "svelte" => 118,
        "dart" => 119,
        "erl" | "ex" | "exs" => 120,
        "hs" => 121,
        "jl" => 122,
        "lua" => 123,
        "r" => 124,
        "m" | "mm" => 125,
        "graphql" | "proto" => 126,
        "sql" => 127,
        "tfstate" | "tfvars" => 128,
        "dsym" | "xcarchive" => 129,
        "car" | "nib" | "storyboardc" => 130,
        "idx" | "pack" => 131,
        "mlmodel" | "pb" | "tflite" => 132,
        "env" => 133,
        "cer" | "crt" | "p12" | "pem" => 134,
        "editorconfig" | "gitignore" => 135,
        _ => 0,
    }
}

/// Directory id per the sidecar's `schema.dir_ids` (0 = unknown).
// Code-generated vocabulary table (see `extension_id`).
#[allow(clippy::too_many_lines)]
fn dir_id(directory: &str) -> u16 {
    match directory.to_lowercase().as_str() {
        "target" => 1,
        ".build" | "build" => 2,
        "dist" => 3,
        "out" => 4,
        ".cache" | "cache" => 5,
        "temp" | "tmp" => 6,
        "node_modules" => 7,
        "src" => 8,
        "sources" => 9,
        "__tests__" | "tests" => 10,
        "test" => 11,
        "doc" | "docs" => 12,
        "assets" | "resources" => 13,
        "deriveddata" => 14,
        ".next" => 15,
        ".nuxt" => 16,
        ".venv" | "venv" => 17,
        ".tox" => 18,
        ".mypy_cache" => 19,
        ".pytest_cache" => 20,
        ".git" => 21,
        ".cargo" | "cargo" => 22,
        "wandb" => 23,
        "__pycache__" => 24,
        "site-packages" => 25,
        "checkpoints" => 26,
        "lightning_logs" => 27,
        "log" | "logs" => 28,
        "downloads" => 29,
        "documents" => 30,
        "desktop" => 31,
        "pictures" => 32,
        "movies" => 33,
        "music" => 34,
        "library" => 35,
        "caches" => 36,
        "applications" => 37,
        "containers" | "group containers" => 38,
        "application support" => 39,
        "preferences" => 40,
        ".gradle" | "gradle" => 41,
        ".npm" => 42,
        "_cacache" => 43,
        ".yarn" => 44,
        ".pnpm-store" => 45,
        ".bun" => 46,
        ".deno" => 47,
        ".docker" => 48,
        ".kube" => 49,
        ".ssh" => 50,
        ".aws" => 51,
        ".config" => 52,
        ".local" => 53,
        "share" => 54,
        "bin" => 55,
        "lib" => 56,
        "include" => 57,
        "frameworks" => 58,
        "plugins" => 59,
        "extensions" => 60,
        "models" => 61,
        "datasets" => 62,
        "data" => 63,
        "weights" => 64,
        "runs" => 65,
        "output" | "outputs" => 66,
        "artifacts" => 67,
        ".terraform" => 68,
        ".stack-work" => 69,
        "_build" => 70,
        "zig-cache" | "zig-out" => 71,
        ".dart_tool" => 72,
        ".pub-cache" => 73,
        ".cocoapods" => 74,
        "pods" => 75,
        ".idea" => 76,
        ".vscode" => 77,
        "objects" => 78,
        "blobs" => 79,
        "snapshots" => 80,
        "refs" => 81,
        "statsig" => 82,
        "huggingface" => 83,
        "hub" => 84,
        "torch" => 85,
        "pip" => 86,
        "wheels" => 87,
        "homebrew" => 88,
        ".rustup" => 89,
        "toolchains" => 90,
        "registry" => 91,
        "git" => 92,
        "worktrees" => 93,
        "coverage" => 94,
        ".claude" => 95,
        "projects" => 96,
        "sessions" => 97,
        "history" => 98,
        "todos" => 99,
        "developer" => 100,
        "xcode" => 101,
        "simulator" => 102,
        "devices" => 103,
        "screenshots" => 104,
        "attachments" => 105,
        "mail" => 106,
        "messages" => 107,
        "keychains" => 108,
        "incremental" => 109,
        "deps" => 110,
        ".fingerprint" => 111,
        "release" => 112,
        "debug" => 113,
        "virtualenvs" => 114,
        "pypoetry" => 115,
        "uv" => 116,
        "go-build" => 117,
        "mod" => 118,
        "pkg" => 119,
        "vendor" => 120,
        _ => 0,
    }
}

fn parent_id(path: &Path) -> u16 {
    path.parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .map_or(0, dir_id)
}

fn grandparent_id(path: &Path) -> u16 {
    path.parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .map_or(0, dir_id)
}

// Extension classes: id-range membership generated from the sidecar's
// `schema.extension_classes` (asserted against it exhaustively in tests).
const fn is_source_ext_id(id: u16) -> bool {
    matches!(id, 1..=24 | 116..=127)
}
const fn is_media_ext_id(id: u16) -> bool {
    matches!(id, 49..=54 | 66..=79)
}
const fn is_doc_ext_id(id: u16) -> bool {
    matches!(id, 30..=31 | 55 | 80..=86)
}
const fn is_archive_ext_id(id: u16) -> bool {
    matches!(id, 44..=48 | 63..=65 | 109..=115)
}
const fn is_artifact_ext_id(id: u16) -> bool {
    matches!(id, 35..=43 | 89..=94 | 129..=131)
}
const fn is_ml_weight_ext_id(id: u16) -> bool {
    matches!(id, 59..=61 | 102..=103 | 132)
}
const fn is_log_tmp_ext_id(id: u16) -> bool {
    matches!(id, 32..=34 | 106..=108)
}

// --- Path helpers -------------------------------------------------------------------

fn basename(path: &Path) -> Cow<'_, str> {
    path.file_name()
        .map_or(Cow::Borrowed(""), |name| name.to_string_lossy())
}

/// The path whose components carry directory signals: the path itself for
/// directories, its parent for files (the v1 convention, kept in v2).
fn signal_path(path: &Path, kind: FileKind) -> &Path {
    if matches!(kind, FileKind::Directory) {
        path
    } else {
        path.parent().unwrap_or_else(|| Path::new(""))
    }
}

fn normal_components(path: &Path) -> Vec<Cow<'_, str>> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy()),
            _ => None,
        })
        .collect()
}

fn has_component(components: &[Cow<'_, str>], wanted: &str) -> bool {
    components.iter().any(|component| component == wanted)
}

fn has_lower_component(lowered: &[String], wanted: &str) -> bool {
    lowered.iter().any(|component| component == wanted)
}

fn consecutive(lowered: &[String], first: &str, second: &str) -> bool {
    lowered
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a == first && b == second))
}

fn in_build_dir(signal_lower: &[String]) -> bool {
    signal_lower.iter().any(|component| {
        BUILD_COMPONENTS.contains(&component.as_str()) || component.starts_with(CMAKE_BUILD_PREFIX)
    })
}

fn in_cache_dir(signal_lower: &[String]) -> bool {
    signal_lower
        .iter()
        .any(|component| component.contains("cache") || component.contains("tmp"))
}

/// Compared case-sensitively, exactly like the Python reference.
fn in_venv(signal: &[Cow<'_, str>]) -> bool {
    signal
        .iter()
        .any(|component| VENV_COMPONENTS.contains(&component.as_ref()))
}

fn in_user_data(full: &[Cow<'_, str>]) -> bool {
    let Some(root) = full.first() else {
        return false;
    };
    let Some(third) = full.get(2) else {
        return false;
    };
    root.to_lowercase() == "users" && USER_DATA_ROOTS.contains(&third.to_lowercase().as_str())
}

fn in_system_root(full: &[Cow<'_, str>]) -> bool {
    full.first()
        .is_some_and(|root| SYSTEM_ROOTS.contains(&root.to_lowercase().as_str()))
}

fn is_hidden_name(name: &str) -> bool {
    name.starts_with('.') && name != "." && name != ".."
}

fn under_hidden_dir(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    parent.components().any(|component| {
        let Component::Normal(name) = component else {
            return false;
        };
        name.to_string_lossy().starts_with('.')
    })
}

// --- Hashed-name buckets ---------------------------------------------------------

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

/// 16 binary buckets over the basename's alphanumeric tokens: lowercase the
/// basename, split on characters outside ASCII `[a-z0-9]`, drop empty and
/// all-digit tokens, and set bucket `fnv1a32(token) % 16` for each token.
fn name_hash_buckets(name: &str) -> [f32; NAME_HASH_BUCKETS] {
    let mut buckets = [0.0_f32; NAME_HASH_BUCKETS];
    let lowered = name.to_lowercase();
    let mut token = String::new();

    let flush = |token: &mut String, buckets: &mut [f32; NAME_HASH_BUCKETS]| {
        if !token.is_empty() && !token.bytes().all(|byte| byte.is_ascii_digit()) {
            let bucket = fnv1a32(token.as_bytes()) as usize % NAME_HASH_BUCKETS;
            if let Some(slot) = buckets.get_mut(bucket) {
                *slot = 1.0;
            }
        }
        token.clear();
    };

    for character in lowered.chars() {
        if matches!(character, 'a'..='z' | '0'..='9') {
            token.push(character);
        } else {
            flush(&mut token, &mut buckets);
        }
    }
    flush(&mut token, &mut buckets);
    buckets
}

// --- Numeric helpers ---------------------------------------------------------------

#[allow(clippy::cast_possible_truncation)]
fn age_days_since(modified: SystemTime, now: SystemTime) -> f32 {
    let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
    (age.as_secs_f64() / SECONDS_PER_DAY) as f32
}

#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn log10_plus1_u64(value: u64) -> f32 {
    ((value as f64) + 1.0).log10() as f32
}

#[allow(clippy::cast_possible_truncation)]
fn log10_plus1_f32(value: f32) -> f32 {
    (f64::from(value) + 1.0).log10() as f32
}

#[allow(clippy::cast_precision_loss)]
fn digit_ratio(digit_count: usize, name_len: usize) -> f32 {
    if name_len == 0 {
        return 0.0;
    }
    (digit_count as f32) / (name_len as f32)
}

fn bounded_usize_to_f32(value: usize) -> f32 {
    u16::try_from(value).map_or(f32::from(u16::MAX), f32::from)
}

fn binary(value: bool) -> f32 {
    if value { 1.0 } else { 0.0 }
}

// --- Sidecar-parity tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Test-only: fixed expectations mirror the Python reference's exact f32
    // arithmetic, so strict float comparisons and narrowing casts are the point.
    #![allow(
        clippy::float_cmp,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss
    )]

    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::EMBEDDED_SIDECAR;

    fn sidecar() -> serde_json::Value {
        serde_json::from_str(EMBEDDED_SIDECAR).expect("sidecar parses")
    }

    fn schema() -> serde_json::Value {
        sidecar()
            .get("schema")
            .cloned()
            .expect("sidecar has schema")
    }

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

    fn empty_context() -> FileContext {
        FileContext {
            has_gitignore: false,
            has_lockfile: false,
            sibling_count: 0,
            sibling_total_bytes: 0,
            ancestor_has_lockfile: false,
            ancestor_has_project_marker: false,
        }
    }

    fn string_set(value: &serde_json::Value, key: &str) -> Vec<String> {
        value
            .get(key)
            .and_then(|list| list.as_array())
            .expect("string list")
            .iter()
            .map(|item| item.as_str().expect("string entry").to_owned())
            .collect()
    }

    fn id_map(value: &serde_json::Value, key: &str) -> BTreeMap<String, u16> {
        value
            .get(key)
            .and_then(|map| map.as_object())
            .expect("id table")
            .iter()
            .map(|(name, id)| {
                (
                    name.clone(),
                    u16::try_from(id.as_u64().expect("integer id")).expect("id fits u16"),
                )
            })
            .collect()
    }

    #[test]
    fn feature_names_match_sidecar() {
        let schema = schema();
        assert_eq!(
            schema
                .get("feature_count")
                .and_then(serde_json::Value::as_u64),
            Some(FEATURE_COUNT as u64)
        );
        let order: Vec<String> = string_set(&schema, "feature_order");
        let names: Vec<String> = FEATURE_NAMES.iter().map(|&n| n.to_owned()).collect();
        assert_eq!(order, names);

        // The top-level sidecar mirrors the same order and count.
        let sidecar = sidecar();
        assert_eq!(
            sidecar
                .get("feature_count")
                .and_then(serde_json::Value::as_u64),
            Some(FEATURE_COUNT as u64)
        );
        assert_eq!(string_set(&sidecar, "feature_order"), names);
    }

    #[test]
    fn schema_hash_matches_stored_and_recomputed() {
        let sidecar = sidecar();
        assert_eq!(
            sidecar
                .get("schema_sha256")
                .and_then(serde_json::Value::as_str),
            Some(SCHEMA_SHA256),
            "sidecar schema hash must match the constant baked into the port"
        );

        // Recompute: serde_json's Value (BTreeMap-backed) serializes objects
        // with sorted keys and compact separators — byte-identical to Python's
        // json.dumps(schema, sort_keys=True, separators=(",", ":")).
        let canonical = serde_json::to_string(&schema()).expect("canonical schema JSON");
        let digest = Sha256::digest(canonical.as_bytes());
        let recomputed = digest.iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        assert_eq!(recomputed, SCHEMA_SHA256, "schema hash must recompute");
    }

    #[test]
    fn extension_vocab_matches_sidecar() {
        let schema = schema();
        let table = id_map(&schema, "extension_ids");
        assert_eq!(table.len(), 189, "extension alias count");
        for (extension, expected) in &table {
            let path = PathBuf::from(format!("/x/file.{extension}"));
            assert_eq!(
                extension_id(&path),
                *expected,
                "extension id mismatch for .{extension}"
            );
        }
        // Unknowns, no-extension names, dotfiles, and trailing dots map to 0.
        assert_eq!(extension_id(Path::new("/x/file.zzznope")), 0);
        assert_eq!(extension_id(Path::new("/x/README")), 0);
        assert_eq!(extension_id(Path::new("/x/.gitignore")), 0);
        assert_eq!(extension_id(Path::new("/x/foo.")), 0);
        // Uppercase spellings hit the same ids (Unicode lowercase).
        assert_eq!(extension_id(Path::new("/x/A.RS")), 1);
    }

    #[test]
    fn dir_vocab_matches_sidecar() {
        let schema = schema();
        let table = id_map(&schema, "dir_ids");
        assert_eq!(table.len(), 133, "dir alias count");
        for (name, expected) in &table {
            assert_eq!(dir_id(name), *expected, "dir id mismatch for {name}");
            assert_eq!(
                dir_id(&name.to_uppercase()),
                *expected,
                "dir id must be case-insensitive for {name}"
            );
        }
        assert_eq!(dir_id("definitely-not-a-vocab-dir"), 0);
    }

    type ClassPredicate = fn(u16) -> bool;

    #[test]
    fn extension_classes_match_sidecar() {
        let schema = schema();
        let classes = schema
            .get("extension_classes")
            .and_then(|c| c.as_object())
            .expect("extension classes");
        let vocab_size = schema
            .get("extension_vocab_size")
            .and_then(serde_json::Value::as_u64)
            .expect("vocab size");

        let expectations: [(&str, ClassPredicate); 7] = [
            ("source", is_source_ext_id),
            ("media", is_media_ext_id),
            ("doc", is_doc_ext_id),
            ("archive", is_archive_ext_id),
            ("artifact", is_artifact_ext_id),
            ("ml_weight", is_ml_weight_ext_id),
            ("log_tmp", is_log_tmp_ext_id),
        ];
        for (name, predicate) in expectations {
            let ids: Vec<u64> = classes
                .get(name)
                .and_then(|ids| ids.as_array())
                .expect("class id list")
                .iter()
                .map(|id| id.as_u64().expect("integer id"))
                .collect();
            for id in 0..vocab_size {
                let expected = ids.contains(&id);
                let actual = predicate(u16::try_from(id).expect("id fits u16"));
                assert_eq!(actual, expected, "class {name} membership for id {id}");
            }
        }
    }

    #[test]
    fn component_sets_match_sidecar() {
        let schema = schema();
        let sorted = |set: &[&str]| {
            let mut copy: Vec<String> = set.iter().map(|&s| s.to_owned()).collect();
            copy.sort();
            copy
        };
        assert_eq!(
            string_set(&schema, "build_components"),
            sorted(BUILD_COMPONENTS)
        );
        assert_eq!(
            string_set(&schema, "venv_components"),
            sorted(VENV_COMPONENTS)
        );
        assert_eq!(
            string_set(&schema, "user_data_roots"),
            sorted(USER_DATA_ROOTS)
        );
        assert_eq!(string_set(&schema, "system_roots"), sorted(SYSTEM_ROOTS));
        assert_eq!(
            schema
                .get("cmake_build_prefix")
                .and_then(serde_json::Value::as_str),
            Some(CMAKE_BUILD_PREFIX)
        );
        assert_eq!(
            schema
                .get("name_hash")
                .and_then(|h| h.get("buckets"))
                .and_then(serde_json::Value::as_u64),
            Some(NAME_HASH_BUCKETS as u64)
        );
    }

    #[test]
    fn fnv1a32_reference_values() {
        // Standard FNV-1a 32-bit test vectors.
        assert_eq!(fnv1a32(b""), 2_166_136_261);
        assert_eq!(fnv1a32(b"a"), 0xe40c_292c);
        assert_eq!(fnv1a32(b"foobar"), 0xbf9c_f968);
    }

    /// Mirror of `features.py self_check()` — the fixed vector the Python
    /// reference asserts bit-for-bit.
    #[test]
    fn self_check_vector_matches_python_reference() {
        let mut entry =
            file_entry("/Users/dev/code/acme-api/target/debug/deps/libacme_api-8f2c.rlib");
        entry.logical_bytes = 999;
        let now = UNIX_EPOCH + Duration::from_hours(240);
        entry.modified = Some(now - Duration::from_hours(48));
        let context = FileContext {
            has_gitignore: false,
            has_lockfile: false,
            sibling_count: 99,
            sibling_total_bytes: 9_999,
            ancestor_has_lockfile: true,
            ancestor_has_project_marker: true,
        };
        let features = extract_features_at(&entry, &context, now);
        let values = features.values();

        let expect = |index: usize, expected: f32| {
            let actual = values.get(index).copied().expect("index in range");
            assert!(
                (actual - expected).abs() < 1e-6,
                "feature {index} ({}): {actual} != {expected}",
                FEATURE_NAMES.get(index).copied().unwrap_or("?"),
            );
        };
        let name = "libacme_api-8f2c.rlib";
        expect(0, 89.0); // rlib
        expect(1, 110.0); // deps
        expect(2, 113.0); // debug
        expect(3, 3.0); // log10(1000)
        expect(4, 3.0_f64.log10() as f32);
        expect(5, 8.0); // absolute depth
        expect(6, 2.0); // log10(100)
        expect(7, ((name.len() as f64) + 1.0).log10() as f32);
        expect(8, 2.0 / name.len() as f32); // digits '8' and '2'
        expect(10, 0.0); // not a dir
        expect(15, 1.0); // ancestor lockfile
        expect(16, 1.0); // ancestor marker
        expect(17, 1.0); // target + debug
        expect(19, 0.0); // not node_modules
        expect(30, 0.0); // not source
        expect(34, 1.0); // artifact ext
    }

    #[test]
    fn unknown_blob_extracts_conservative_zero_signals() {
        let mut entry = file_entry("/opt/blob");
        entry.logical_bytes = 1;
        let features = extract_features_at(&entry, &empty_context(), UNIX_EPOCH);
        let values = features.values();
        assert_eq!(values.first().copied(), Some(0.0), "extension id");
        assert_eq!(values.get(1).copied(), Some(0.0), "parent id");
        assert_eq!(values.get(29).copied(), Some(0.0), "system root");
    }

    #[test]
    fn name_hash_buckets_depend_only_on_the_basename() {
        assert_eq!(name_hash_buckets("index.js"), name_hash_buckets("index.js"));
        let features_a = extract_features_at(
            &file_entry("/a/node_modules/react/index.js"),
            &empty_context(),
            UNIX_EPOCH,
        );
        let features_b =
            extract_features_at(&file_entry("/b/x/index.js"), &empty_context(), UNIX_EPOCH);
        let buckets = |features: &FeatureVector| -> Vec<f32> {
            features
                .values()
                .iter()
                .skip(HEAD_FEATURES)
                .copied()
                .collect()
        };
        assert_eq!(buckets(&features_a), buckets(&features_b));
    }

    #[test]
    fn all_digit_tokens_are_dropped_from_name_hash() {
        // "2024" is all digits -> dropped; a fully numeric name sets no bucket.
        assert_eq!(name_hash_buckets("2024.log"), {
            let mut expected = [0.0_f32; NAME_HASH_BUCKETS];
            let bucket = fnv1a32(b"log") as usize % NAME_HASH_BUCKETS;
            if let Some(slot) = expected.get_mut(bucket) {
                *slot = 1.0;
            }
            expected
        });
        assert_eq!(name_hash_buckets("123456"), [0.0_f32; NAME_HASH_BUCKETS]);
    }

    #[test]
    fn depth_is_absolute_not_scan_relative() {
        let mut entry = file_entry("/Users/maya/x");
        entry.depth = 1; // scanner-relative depth must be ignored
        let features = extract_features_at(&entry, &empty_context(), UNIX_EPOCH);
        assert_eq!(features.values().get(5).copied(), Some(3.0));
    }

    #[test]
    fn macos_library_signals_fire_for_files_via_parent() {
        let entry = file_entry("/Users/maya/Library/Caches/com.foo/blob.dat");
        let features = extract_features_at(&entry, &empty_context(), UNIX_EPOCH);
        let values = features.values();
        assert_eq!(values.get(22).copied(), Some(1.0), "in_library");
        assert_eq!(values.get(23).copied(), Some(1.0), "in_library_caches");
        assert_eq!(values.get(18).copied(), Some(1.0), "in_cache_dir");
        assert_eq!(values.get(29).copied(), Some(0.0), "not a system root");
    }

    #[test]
    fn user_data_and_system_root_use_full_path_components() {
        let document = file_entry("/Users/maya/Documents/thesis.pdf");
        let features = extract_features_at(&document, &empty_context(), UNIX_EPOCH);
        assert_eq!(
            features.values().get(28).copied(),
            Some(1.0),
            "in_user_data"
        );

        let system = file_entry("/Library/Caches/com.foo/blob.dat");
        let features = extract_features_at(&system, &empty_context(), UNIX_EPOCH);
        assert_eq!(
            features.values().get(29).copied(),
            Some(1.0),
            "in_system_root"
        );
    }

    #[test]
    fn feature_vector_deserializes_only_at_exact_length() {
        let full: Vec<f32> = vec![0.0; FEATURE_COUNT];
        let json = serde_json::to_string(&full).expect("serialize");
        let decoded: FeatureVector = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.values().len(), FEATURE_COUNT);

        let short = serde_json::to_string(&vec![0.0_f32; 12]).expect("serialize");
        assert!(serde_json::from_str::<FeatureVector>(&short).is_err());
    }
}
