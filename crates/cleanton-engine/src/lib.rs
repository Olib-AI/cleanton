mod analyzer;
mod docker;
mod events;
mod executor;
mod ml;
mod orchestrator;
mod orphans;
mod planner;
mod suggestions;
mod uninstall;

pub use analyzer::AnalyzedPlan;
pub use docker::{
    BuildCacheInfo, ContainerInfo, DockerAnalysis, DockerCleaner, DockerCleanupPlan,
    DockerCleanupResult, ImageInfo, VolumeInfo,
};
pub use events::EngineEvent;
pub use ml::{
    ActionAnnotation, AnnotatedAction, DEFAULT_ML_CONFIDENCE_THRESHOLD, FileClassifier,
    MlAdjustment,
};
pub use orchestrator::{AnalyzedFull, Orchestrator, PipelineResult};
pub use orphans::{DEFAULT_ORPHAN_MIN_AGE_DAYS, ORPHAN_CATEGORY};
pub use suggestions::{DuplicateSet, LargeItem, Suggestions, detect_suggestions};
pub use uninstall::{
    AppRemovalWatcher, InstalledApp, LeftoverItem, LeftoverKind, UninstallPlan, cask_token_for,
    find_leftovers, list_installed_apps,
};
