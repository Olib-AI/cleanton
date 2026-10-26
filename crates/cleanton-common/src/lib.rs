pub mod config;
pub mod display;
pub mod error;
pub mod paths;
pub mod safety;
pub mod types;
pub mod usage_history;

pub use config::{
    BackgroundConfig, CleantonConfig, GeneralConfig, MlConfig, SafetyConfig, ScanningConfig,
    UiConfig,
};
pub use error::{CleantonError, Result};
pub use paths::{FIRMLINK_ALIASES, firmlink_canonical};
pub use safety::{
    HARDCODED_PROTECTED, ProtectedPaths, USER_DATA_CONTENT_ROOTS, USER_PROTECTED,
    is_user_data_content_path, is_user_data_content_root,
};
pub use types::{
    ActionGroup, ActionType, CleanupAction, CleanupPlan, Confidence, Ecosystem,
    ExecutionActionResult, ExecutionResult, ExecutionStatus, FileEntry, FileKind,
    MetadataFingerprint, ProjectRoot, RecipeId, SafetyLevel, ScanError, ScanResult, Severity,
};
pub use usage_history::{UsageHistory, UsageSample};
