//! Error type for the antivirus scanner.

/// Errors that can occur while loading, extracting, or scanning a target.
#[derive(Debug, thiserror::Error)]
pub enum AvError {
    /// Underlying filesystem / IO failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The scan target (path) does not exist.
    #[error("scan target not found: {0}")]
    NotFound(String),

    /// An archive could not be opened or extracted.
    #[error("archive error: {0}")]
    Archive(String),

    /// A safety limit was hit while loading the target (file count, total
    /// bytes, recursion depth, zip-bomb guard). Treated as a potential threat
    /// by callers, not silently ignored.
    #[error("scan limit exceeded: {0}")]
    LimitExceeded(String),

    /// A signature / rule database failed to parse.
    #[error("signature database error: {0}")]
    SignatureDb(String),

    /// Any other internal error with a description.
    #[error("antivirus error: {0}")]
    Other(String),
}

/// Convenience result alias for the crate.
pub type AvResult<T> = Result<T, AvError>;
