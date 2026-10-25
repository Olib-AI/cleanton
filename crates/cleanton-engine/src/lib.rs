mod advisories;
mod analyzer;
pub mod background;
mod docker;
mod elevated_trash;
mod events;
mod executor;
mod ml;
mod orchestrator;
mod orphans;
mod planner;
pub mod security;
pub mod security_baseline;
mod snapshots;
mod suggestions;
mod uninstall;

pub use advisories::{
    Advisory, AdvisoryDatabase, AdvisoryMatch, AffectedRange, Ecosystem, PackageSubject,
    compare_versions,
};
pub use analyzer::AnalyzedPlan;
pub use background::{PackageWatcher, ResourceKind, WatchEvent, WatchOptions};
pub use docker::{
    BuildCacheInfo, ContainerInfo, DockerAnalysis, DockerCleaner, DockerCleanupPlan,
    DockerCleanupResult, ImageInfo, VolumeInfo,
};
pub use events::{EngineEvent, ScanSummary};
pub use ml::{
    ActionAnnotation, AnnotatedAction, DEFAULT_ML_CONFIDENCE_THRESHOLD, FileClassifier,
    MlAdjustment,
};
pub use orchestrator::{AnalyzedFull, Orchestrator, PipelineResult};
pub use orphans::{DEFAULT_ORPHAN_MIN_AGE_DAYS, ORPHAN_CATEGORY};
pub use security::{
    Assessment, ChangeKind, PackageReport, SecurityFinding, SecurityProgress, SecurityReport,
    SecurityScanOptions, SecurityTarget, SecurityTargetKind, SeverityCounts, assess,
    change_kind_label, discover_targets, is_benign_context, is_install_context,
    lifecycle_script_paths, review_packages, run_security_scan, run_security_scan_with_options,
    scan_targets, scan_targets_with_options, verdict_corroborated,
};
pub use security_baseline::{
    BaselineEntry, SecurityBaseline, default_baseline_path, fingerprint_package,
};
pub use snapshots::{
    SnapshotAnalysis, SnapshotCleanupResult, SnapshotConfirmState, SnapshotDeleteFailure,
    SnapshotInfo, delete_local_snapshots, format_snapshot_date, is_snapshot_date,
    snapshot_date_from_identifier,
};
pub use suggestions::{DuplicateSet, LargeItem, Suggestions, detect_suggestions};
pub use uninstall::{
    AppRemovalWatcher, InstalledApp, LeftoverItem, LeftoverKind, UninstallPlan, cask_token_for,
    find_leftovers, list_installed_apps,
};
