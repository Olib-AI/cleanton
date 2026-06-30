//! Local APFS / Time Machine snapshot disclosure.
//!
//! APFS local snapshots pin "deleted" blocks as *purgeable* until they are thinned (see
//! `PLATFORM.md` §1.2). Cleanton never deletes snapshots; it only *discloses* them so the
//! UI can warn that freed bytes may not be immediately available. This module shells out
//! to `tmutil listlocalsnapshots <volume>` and parses the identifiers. Absence of
//! `tmutil`, a non-zero exit, or a permission error are all handled as "no snapshots
//! observed" — the query never panics and never propagates an error.

use std::path::{Path, PathBuf};

/// Result of querying local snapshots for a volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSnapshots {
    /// The volume the query targeted (typically `/`).
    pub volume: PathBuf,
    /// Snapshot identifiers, e.g. `com.apple.TimeMachine.2026-06-29-120000.local`.
    pub identifiers: Vec<String>,
    /// `true` if `tmutil` ran and produced parseable output; `false` if the tool was
    /// missing, errored, or denied. Distinguishes "ran, zero snapshots" from "could not
    /// query".
    pub query_succeeded: bool,
}

impl LocalSnapshots {
    /// Number of local snapshots disclosed.
    #[must_use]
    pub fn count(&self) -> usize {
        self.identifiers.len()
    }

    /// `true` if no snapshots were disclosed (whether or not the query succeeded).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.identifiers.is_empty()
    }

    fn unavailable(volume: &Path) -> Self {
        Self {
            volume: volume.to_path_buf(),
            identifiers: Vec::new(),
            query_succeeded: false,
        }
    }
}

/// Lists local APFS snapshots for `volume` by invoking `tmutil listlocalsnapshots`.
///
/// Never panics and never returns an error: any failure (missing binary, non-zero exit,
/// permission denied) yields an empty listing with `query_succeeded == false`.
#[must_use]
pub fn list_local_snapshots(volume: &Path) -> LocalSnapshots {
    // `tmutil listlocalsnapshots` is a read-only disclosure invocation; it mutates nothing.
    // `Command::new` is otherwise reserved for service/executor adapters (see clippy.toml),
    // so this single call is explicitly allowed here with that justification.
    #[allow(clippy::disallowed_methods)]
    let output = std::process::Command::new("tmutil")
        .arg("listlocalsnapshots")
        .arg(volume)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            LocalSnapshots {
                volume: volume.to_path_buf(),
                identifiers: parse_snapshot_identifiers(&stdout),
                query_succeeded: true,
            }
        }
        _ => LocalSnapshots::unavailable(volume),
    }
}

/// Extracts snapshot identifiers from `tmutil listlocalsnapshots` output.
///
/// The command prints a header line (e.g. `Snapshots for volume group containing disk /:`)
/// followed by one identifier per line. We keep only lines that look like snapshot
/// identifiers (`com.apple.TimeMachine.*`) so the header and any stray output are ignored.
fn parse_snapshot_identifiers(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("com.apple.TimeMachine."))
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing into expected results clearer.
    #![allow(clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn parses_identifiers_and_ignores_header() {
        let sample = "Snapshots for volume group containing disk /:\n\
             com.apple.TimeMachine.2026-06-29-120000.local\n\
             com.apple.TimeMachine.2026-06-29-130000.local\n";
        let ids = parse_snapshot_identifiers(sample);
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], "com.apple.TimeMachine.2026-06-29-120000.local");
        assert_eq!(ids[1], "com.apple.TimeMachine.2026-06-29-130000.local");
    }

    #[test]
    fn parses_empty_output_as_no_snapshots() {
        let sample = "Snapshots for volume group containing disk /:\n";
        assert!(parse_snapshot_identifiers(sample).is_empty());
    }

    #[test]
    fn parse_tolerates_indentation_and_blank_lines() {
        let sample =
            "Snapshots for disk /:\n\n  com.apple.TimeMachine.2026-06-29-120000.local  \n\n";
        let ids = parse_snapshot_identifiers(sample);
        assert_eq!(ids, vec!["com.apple.TimeMachine.2026-06-29-120000.local"]);
    }

    #[test]
    fn listing_root_volume_does_not_panic_and_is_self_consistent() {
        // On CI/dev machines `/` may or may not have local snapshots, and `tmutil` may be
        // absent or restricted. All outcomes are valid; we only require no panic and that
        // count() agrees with the identifier vector.
        let snapshots = list_local_snapshots(Path::new("/"));
        assert_eq!(snapshots.count(), snapshots.identifiers.len());
        assert_eq!(snapshots.is_empty(), snapshots.identifiers.is_empty());
        assert_eq!(snapshots.volume, PathBuf::from("/"));
    }

    #[test]
    fn missing_volume_is_handled_gracefully() {
        // tmutil will fail for a bogus volume path; we must get a non-succeeded empty result
        // rather than a panic or error.
        let snapshots = list_local_snapshots(Path::new("/no-such-cleanton-volume-xyz"));
        assert!(snapshots.is_empty());
    }
}
