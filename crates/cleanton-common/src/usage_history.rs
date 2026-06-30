//! Append-only disk-usage history shared by both Cleanton UIs.
//!
//! This is an *additive* module: it does not touch any existing `cleanton-common`
//! API. Both the ratatui TUI (`cleanton-ui`) and the Slint GUI (`cleanton-app`)
//! persist a small rolling window of real volume-capacity samples here so the
//! dashboard can draw an honest usage trend instead of synthesized data. Samples
//! are stored as JSON under the existing config directory
//! (`~/.config/cleanton/usage_history.json`).
//!
//! The honesty contract (see `doc/PLATFORM.md` §1.3): every value persisted comes
//! from a real `statfs`-backed [`crate`]-external capacity read. Nothing here ever
//! fabricates a data point. When fewer than two samples exist, callers must show a
//! "collecting history" state rather than inventing one.

use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use crate::{CleantonError, Result};

/// Maximum number of samples retained on disk. Older samples are dropped
/// (FIFO) once the window is full so the file stays small and bounded.
pub const MAX_SAMPLES: usize = 240;

/// A single disk-usage observation. All byte fields come from a real volume
/// capacity read; `recorded_at` is the wall-clock time the sample was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageSample {
    /// When the sample was recorded.
    pub recorded_at: SystemTime,
    /// Total capacity of the volume in bytes.
    pub total_bytes: u64,
    /// Used bytes (`total - free`) at sample time.
    pub used_bytes: u64,
    /// User-available bytes at sample time (a conservative lower bound on
    /// Finder's "Available"; see the scanner's `VolumeCapacity` docs).
    pub available_bytes: u64,
}

/// A rolling window of [`UsageSample`]s in chronological (append) order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageHistory {
    /// Oldest-first list of samples.
    #[serde(default)]
    pub samples: Vec<UsageSample>,
}

impl UsageHistory {
    /// Number of stored samples.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// `true` if there are no samples yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// `true` once there are enough samples to draw a meaningful trend (≥2).
    #[must_use]
    pub fn has_trend(&self) -> bool {
        self.samples.len() >= 2
    }

    /// The most recent sample, if any.
    #[must_use]
    pub fn latest(&self) -> Option<&UsageSample> {
        self.samples.last()
    }

    /// Used-bytes series in chronological order, for sparkline rendering.
    #[must_use]
    pub fn used_series(&self) -> Vec<u64> {
        self.samples
            .iter()
            .map(|sample| sample.used_bytes)
            .collect()
    }
}

/// Default on-disk location for the history file
/// (`$HOME/.config/cleanton/usage_history.json`). Returns `None` if `$HOME`
/// is unset (the caller then skips persistence rather than failing).
#[must_use]
pub fn default_history_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("cleanton")
            .join("usage_history.json")
    })
}

/// Loads the history from `path`. A missing file yields an empty history; a
/// corrupt or unreadable file is logged and also treated as empty so the UI
/// never breaks on a bad cache. This function never returns an error.
#[must_use]
pub fn load(path: &Path) -> UsageHistory {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return UsageHistory::default(),
        Err(err) => {
            tracing::warn!("could not read usage history {}: {err}", path.display());
            return UsageHistory::default();
        }
    };

    match serde_json::from_slice::<UsageHistory>(&bytes) {
        Ok(history) => history,
        Err(err) => {
            tracing::warn!("ignoring corrupt usage history {}: {err}", path.display());
            UsageHistory::default()
        }
    }
}

/// Appends `sample` to the history at `path`, enforces the [`MAX_SAMPLES`]
/// window, and writes it back atomically (temp file + rename). Returns the
/// updated in-memory history on success.
///
/// # Errors
///
/// Returns [`CleantonError::Io`] if the parent directory cannot be created or
/// the file cannot be written/renamed.
pub fn append(path: &Path, sample: UsageSample) -> Result<UsageHistory> {
    let mut history = load(path);
    history.samples.push(sample);
    let len = history.samples.len();
    if len > MAX_SAMPLES {
        history.samples.drain(0..len - MAX_SAMPLES);
    }
    write(path, &history)?;
    Ok(history)
}

/// Atomically serializes `history` to `path` (write to a sibling temp file,
/// then rename over the target).
///
/// # Errors
///
/// Returns [`CleantonError::Io`] on directory-creation, serialization, write,
/// or rename failure.
pub fn write(path: &Path, history: &UsageHistory) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| CleantonError::io(parent, err))?;
    }

    let json = serde_json::to_vec_pretty(history).map_err(|err| {
        CleantonError::io(
            path,
            std::io::Error::new(std::io::ErrorKind::InvalidData, err),
        )
    })?;

    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &json).map_err(|err| CleantonError::io(&tmp, err))?;
    fs::rename(&tmp, path).map_err(|err| CleantonError::io(path, err))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(used: u64) -> UsageSample {
        UsageSample {
            recorded_at: SystemTime::UNIX_EPOCH,
            total_bytes: 1_000,
            used_bytes: used,
            available_bytes: 1_000 - used,
        }
    }

    #[test]
    fn load_missing_file_is_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        let history = load(&temp.path().join("does-not-exist.json"));
        assert!(history.is_empty());
        assert!(!history.has_trend());
    }

    #[test]
    fn append_persists_and_round_trips() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("usage_history.json");

        append(&path, sample(100)).expect("first append");
        let history = append(&path, sample(200)).expect("second append");

        assert_eq!(history.len(), 2);
        assert!(history.has_trend());
        assert_eq!(history.used_series(), vec![100, 200]);
        assert_eq!(history.latest().map(|s| s.used_bytes), Some(200));

        // Reloading from disk reproduces the same data (no fabrication).
        assert_eq!(load(&path), history);
    }

    #[test]
    fn append_enforces_max_samples_window() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("usage_history.json");

        for i in 0..(MAX_SAMPLES as u64 + 10) {
            append(&path, sample(i)).expect("append");
        }

        let history = load(&path);
        assert_eq!(history.len(), MAX_SAMPLES);
        // The oldest 10 samples were dropped; the series starts at 10.
        assert_eq!(history.used_series().first().copied(), Some(10));
        assert_eq!(
            history.used_series().last().copied(),
            Some(MAX_SAMPLES as u64 + 9)
        );
    }

    #[test]
    fn corrupt_file_is_treated_as_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("usage_history.json");
        fs::write(&path, b"{not valid json").expect("write garbage");
        assert!(load(&path).is_empty());
    }
}
