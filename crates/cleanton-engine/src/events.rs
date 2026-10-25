use std::{path::PathBuf, time::Duration};

use cleanton_common::{CleantonError, CleanupAction, CleanupPlan, ScanError, ScanResult};
use serde::{Deserialize, Serialize};

/// Aggregate outcome of a completed scan.
///
/// Deliberately does NOT carry the per-entry inventory. `EngineEvent` is sent
/// through a bounded channel, and cloning a multi-million-entry [`ScanResult`]
/// just to hand a subscriber a handful of totals doubled the scan's peak memory
/// (and cost seconds of `PathBuf` copying) for data nothing downstream read.
/// Callers that need the inventory keep the `ScanResult` they already own; the
/// event only reports what the UIs actually display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_files: u64,
    pub total_dirs: u64,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub duration: Duration,
    pub errors: Vec<ScanError>,
    pub incomplete: bool,
    /// Number of detected project roots (count only, not the roots themselves).
    pub project_roots: usize,
}

impl ScanSummary {
    #[must_use]
    pub fn from_scan(scan: &ScanResult) -> Self {
        Self {
            total_files: scan.total_files,
            total_dirs: scan.total_dirs,
            logical_bytes: scan.logical_bytes,
            allocated_bytes: scan.allocated_bytes,
            duration: scan.duration,
            errors: scan.errors.clone(),
            incomplete: scan.incomplete,
            project_roots: scan.project_roots.len(),
        }
    }
}

impl From<&ScanResult> for ScanSummary {
    fn from(scan: &ScanResult) -> Self {
        Self::from_scan(scan)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EngineEvent {
    ScanStarted {
        root: PathBuf,
    },
    ScanProgress {
        files_scanned: u64,
        dirs_entered: u64,
        bytes_seen: u64,
    },
    ScanCompleted {
        summary: ScanSummary,
    },
    AnalysisStarted,
    AnalysisProgress {
        items_analyzed: u64,
        total: u64,
    },
    AnalysisCompleted {
        plan: CleanupPlan,
    },
    ActionStarted {
        action: CleanupAction,
    },
    ActionCompleted {
        action: CleanupAction,
        freed: u64,
    },
    ActionFailed {
        action: CleanupAction,
        error: String,
    },
    PipelineCompleted {
        total_reclaimable: u64,
        duration: Duration,
    },
    PipelineFailed {
        error: String,
    },
}

impl From<CleantonError> for EngineEvent {
    fn from(error: CleantonError) -> Self {
        Self::PipelineFailed {
            error: error.to_string(),
        }
    }
}
