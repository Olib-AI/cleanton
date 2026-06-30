//! Honest disk-capacity surfacing for the Slint GUI.
//!
//! Mirrors the TUI's capacity helper: reads `cleanton-scanner` volume capacity +
//! local snapshots and records a real sample into the shared `cleanton-common`
//! usage history. The "available" figure is a conservative lower bound and is
//! always labelled approximate in the UI (`doc/PLATFORM.md` §1.3); snapshots are
//! only disclosed, never deleted (§1.2).

use std::{path::Path, time::SystemTime};

use cleanton_common::{UsageHistory, UsageSample, usage_history};
use cleanton_scanner::{LocalSnapshots, VolumeCapacity, list_local_snapshots, volume_capacity};

/// A point-in-time capacity reading plus persisted usage history and snapshots.
#[derive(Debug, Default)]
pub struct CapacityView {
    pub capacity: Option<VolumeCapacity>,
    pub snapshots: Option<LocalSnapshots>,
    pub history: UsageHistory,
    pub error: Option<String>,
}

impl CapacityView {
    /// Number of local snapshots disclosed (0 when the query did not succeed).
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.as_ref().map_or(0, LocalSnapshots::count)
    }
}

/// Reads capacity for the volume containing `root`, discloses `/` snapshots, and
/// appends a real usage sample. Never panics; a failed read is reported via
/// [`CapacityView::error`].
#[must_use]
pub fn read(root: &Path) -> CapacityView {
    let snapshots = Some(list_local_snapshots(Path::new("/")));

    match volume_capacity(root) {
        Ok(capacity) => CapacityView {
            history: record_sample(&capacity),
            capacity: Some(capacity),
            snapshots,
            error: None,
        },
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

/// Normalizes the tail of the used-bytes series to `0.0..=1.0` heights for the
/// GUI sparkline. Returns at most `max_bars` values (most recent last). Empty
/// when fewer than two samples exist — callers must show a "collecting" state
/// instead of synthesizing data.
#[must_use]
pub fn normalized_used_series(history: &UsageHistory, max_bars: usize) -> Vec<f32> {
    let series = history.used_series();
    if series.len() < 2 {
        return Vec::new();
    }

    let tail = if series.len() > max_bars {
        &series[series.len() - max_bars..]
    } else {
        &series[..]
    };

    let max = tail.iter().copied().max().unwrap_or(0);
    if max == 0 {
        return tail.iter().map(|_| 0.0).collect();
    }

    tail.iter()
        .map(|&v| (v as f64 / max as f64) as f32)
        .collect()
}
