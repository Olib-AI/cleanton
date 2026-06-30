//! Honest disk-capacity surfacing for the TUI dashboard.
//!
//! Wraps the `cleanton-scanner` capacity/snapshot reads and records each reading
//! into the shared append-only usage history (`cleanton-common`). Per
//! `doc/PLATFORM.md` §1.3 the "available" figure is a conservative lower bound
//! (Finder folds in purgeable space we cannot reach from libc), so the UI labels
//! it as approximate. Snapshots are disclosed, never deleted (§1.2).

use std::{path::Path, time::SystemTime};

use cleanton_common::{UsageHistory, UsageSample, usage_history};
use cleanton_scanner::{LocalSnapshots, VolumeCapacity, list_local_snapshots, volume_capacity};

/// A point-in-time view of volume capacity plus the persisted usage history and
/// any local-snapshot disclosure.
#[derive(Debug, Default)]
pub struct CapacityView {
    /// The latest capacity reading, if the `statfs` call succeeded.
    pub capacity: Option<VolumeCapacity>,
    /// Local APFS / Time Machine snapshot disclosure for the boot volume.
    pub snapshots: Option<LocalSnapshots>,
    /// Real, persisted disk-usage history (used for the sparkline).
    pub history: UsageHistory,
    /// A human-readable error if the capacity read failed.
    pub error: Option<String>,
}

impl CapacityView {
    /// Number of local snapshots disclosed (0 if the query did not succeed).
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.as_ref().map_or(0, LocalSnapshots::count)
    }
}

/// Reads capacity for the volume containing `root`, discloses local snapshots
/// for `/`, and appends the reading to the persisted usage history. Never
/// panics; a failed capacity read is reported via [`CapacityView::error`] while
/// still returning whatever history is already on disk.
#[must_use]
pub fn read(root: &Path) -> CapacityView {
    let snapshots = Some(list_local_snapshots(Path::new("/")));

    match volume_capacity(root) {
        Ok(capacity) => {
            let history = record_sample(&capacity);
            CapacityView {
                capacity: Some(capacity),
                snapshots,
                history,
                error: None,
            }
        }
        Err(err) => CapacityView {
            capacity: None,
            snapshots,
            history: usage_history::default_history_path()
                .map(|path| usage_history::load(&path))
                .unwrap_or_default(),
            error: Some(err.to_string()),
        },
    }
}

/// Appends a real sample for `capacity` and returns the updated history. If the
/// history path is unavailable or the write fails, the existing on-disk history
/// (or an empty one) is returned — we never fabricate samples.
fn record_sample(capacity: &VolumeCapacity) -> UsageHistory {
    let Some(path) = usage_history::default_history_path() else {
        return UsageHistory::default();
    };

    let sample = UsageSample {
        recorded_at: SystemTime::now(),
        total_bytes: capacity.total_bytes,
        used_bytes: capacity.used_bytes,
        available_bytes: capacity.available_for_important_usage_bytes,
    };

    match usage_history::append(&path, sample) {
        Ok(history) => history,
        Err(err) => {
            tracing::warn!("could not persist usage sample: {err}");
            usage_history::load(&path)
        }
    }
}
