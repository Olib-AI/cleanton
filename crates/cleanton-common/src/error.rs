use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CleantonError>;

#[derive(Debug, Error)]
pub enum CleantonError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("permission denied at {path}")]
    PermissionDenied { path: PathBuf },

    #[error("recipe error in {path}: {message}")]
    Recipe { path: PathBuf, message: String },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("protected path refused: {0}")]
    ProtectedPath(PathBuf),

    #[error("scan failed: {0}")]
    Scan(String),

    #[error("execution refused: {0}")]
    ExecutionRefused(String),

    #[error("execution failed for {path}: {message}")]
    Execution { path: PathBuf, message: String },

    #[error("ML unavailable: {0}")]
    Ml(String),

    #[error("root privileges required: {0}")]
    RootPrivilegesRequired(String),
}

impl CleantonError {
    #[must_use]
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
