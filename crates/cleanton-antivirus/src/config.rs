//! Scan configuration and safety limits.

use std::path::PathBuf;

/// Tunable limits and thresholds for a scan. `Default` is safe for untrusted
/// input (bounded memory, zip-bomb protection) and is what the platform uses
/// when vetting an MCP package.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Skip (and record) any single file larger than this many bytes.
    pub max_file_size: u64,
    /// Stop loading after this many files (records a [`crate::error::AvError::LimitExceeded`]).
    pub max_total_files: usize,
    /// Maximum nested-archive recursion depth.
    pub max_archive_depth: usize,
    /// Maximum total extracted bytes across all archives (zip-bomb guard).
    pub max_extracted_bytes: u64,
    /// Follow symlinks while walking directories (default: false — symlink
    /// escapes are an attack vector).
    pub follow_symlinks: bool,
    /// Score (0..=100) at/above which a target is at least [`crate::types::Verdict::Suspicious`].
    pub min_score_suspicious: u32,
    /// Score (0..=100) at/above which a target is [`crate::types::Verdict::Malicious`].
    pub min_score_malicious: u32,
    /// Extra signature/hash database files to load (newline `sha256[:label]`).
    pub signature_db_paths: Vec<PathBuf>,
    /// Extra rule files to load (engine-defined format).
    pub rule_paths: Vec<PathBuf>,
    /// Rule IDs to suppress (operator allowlist for known false positives).
    pub allowlisted_rule_ids: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size: 32 * 1024 * 1024, // 32 MiB per file
            max_total_files: 50_000,
            max_archive_depth: 8,
            max_extracted_bytes: 1024 * 1024 * 1024, // 1 GiB total
            follow_symlinks: false,
            min_score_suspicious: 25,
            min_score_malicious: 70,
            signature_db_paths: Vec::new(),
            rule_paths: Vec::new(),
            allowlisted_rule_ids: Vec::new(),
        }
    }
}

impl ScanConfig {
    /// Whether a given rule id is suppressed by the operator allowlist.
    pub fn is_allowlisted(&self, rule_id: &str) -> bool {
        self.allowlisted_rule_ids.iter().any(|r| r == rule_id)
    }
}
