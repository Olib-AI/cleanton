use std::{path::PathBuf, time::Duration};

use cleanton_common::{CleantonError, CleanupAction, CleanupPlan, ScanResult};
use serde::{Deserialize, Serialize};

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
        result: ScanResult,
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
