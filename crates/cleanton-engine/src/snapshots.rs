//! Time Machine local snapshot review and confirm-gated deletion.
//!
//! Local APFS snapshots pin "deleted" blocks as purgeable space (see
//! `PLATFORM.md` §1.2). The scanner discloses them read-only; this module adds
//! the one Cleanton flow that can actually release that space. Deleting an APFS
//! snapshot is NOT trash-reversible — a snapshot is volume metadata, not files,
//! so there is nothing to move to the Trash. Because of that, deletion here is
//! gated harder than anywhere else:
//!
//! - the UI must show the snapshot list and obtain an explicit, per-run user
//!   confirmation (two-step arm → confirm, mirroring the Docker/Suggestions
//!   review panels) before calling [`delete_local_snapshots`];
//! - each deletion is one precise `tmutil deletelocalsnapshots <date>` for a
//!   date parsed from a disclosed snapshot identifier and re-validated against
//!   a strict shape check — arbitrary strings never reach the command line;
//! - a blanket `tmutil thinlocalsnapshots` is deliberately not offered: it lets
//!   the OS pick victims, which is neither precise nor attributable;
//! - failures are surfaced verbatim (exit status + stderr) and never retried.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use cleanton_scanner::LocalSnapshots;

/// One disclosed local snapshot, with the date token used for deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// Full identifier, e.g. `com.apple.TimeMachine.2026-06-29-120000.local`.
    pub identifier: String,
    /// The snapshot date token, e.g. `2026-06-29-120000`. This exact string is
    /// what `tmutil deletelocalsnapshots` accepts.
    pub date: String,
}

/// Review model for the snapshot panel: the disclosed snapshots plus the
/// volume-level purgeable estimate (per-snapshot sizes are not observable via
/// `tmutil listlocalsnapshots`; the purgeable pool is the honest upper bound).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotAnalysis {
    /// The volume the listing targeted (typically `/`).
    pub volume: PathBuf,
    /// Snapshots whose identifiers carried a parseable date. Identifiers with
    /// no recognizable date are omitted — they could not be deleted precisely.
    pub snapshots: Vec<SnapshotInfo>,
    /// Rough volume purgeable estimate (`free - available`), NOT a per-snapshot
    /// figure. `0` when capacity could not be read.
    pub purgeable_estimate_bytes: u64,
    /// Mirrors [`LocalSnapshots::query_succeeded`]: distinguishes "ran, zero
    /// snapshots" from "could not query" so the UI never claims a clean disk it
    /// did not observe.
    pub query_succeeded: bool,
}

impl SnapshotAnalysis {
    /// Builds the review model from an existing read-only listing (both UIs
    /// already hold one via their capacity view — no second `tmutil` run).
    #[must_use]
    pub fn from_listing(listing: &LocalSnapshots, purgeable_estimate_bytes: u64) -> Self {
        let snapshots = listing
            .identifiers
            .iter()
            .filter_map(|identifier| {
                snapshot_date_from_identifier(identifier).map(|date| SnapshotInfo {
                    identifier: identifier.clone(),
                    date,
                })
            })
            .collect();
        Self {
            volume: listing.volume.clone(),
            snapshots,
            purgeable_estimate_bytes,
            query_succeeded: listing.query_succeeded,
        }
    }
}

/// One snapshot deletion that failed, with the operator-facing reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotDeleteFailure {
    pub date: String,
    pub message: String,
}

/// Outcome of a confirmed snapshot cleanup run.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SnapshotCleanupResult {
    /// Dates whose `tmutil deletelocalsnapshots` invocation exited 0.
    pub deleted: Vec<String>,
    /// Dates that were refused (invalid shape) or whose invocation failed.
    pub failures: Vec<SnapshotDeleteFailure>,
}

impl SnapshotCleanupResult {
    /// Shared status copy for both UIs, so the Slint app and the TUI report
    /// identical results.
    #[must_use]
    pub fn status_message(&self) -> String {
        match (self.deleted.len(), self.failures.first()) {
            (0, None) => "No snapshots were deleted.".to_owned(),
            (deleted, None) => {
                format!("Deleted {deleted} local snapshot(s). APFS releases the space shortly.")
            }
            (0, Some(first)) => format!(
                "Snapshot deletion failed ({} failure(s)). {}: {}",
                self.failures.len(),
                first.date,
                first.message
            ),
            (deleted, Some(first)) => format!(
                "Deleted {deleted} snapshot(s); {} failed. {}: {}",
                self.failures.len(),
                first.date,
                first.message
            ),
        }
    }
}

/// Two-step arm → confirm state machine for the snapshot panel. Both UIs drive
/// their "Delete selected" affordance through this so the gating logic (and its
/// tests) live in one place: nothing is deletable while `Idle`, and `confirm`
/// hands out the armed dates exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SnapshotConfirmState {
    /// Nothing armed; deletion requests are ignored.
    #[default]
    Idle,
    /// The user selected these dates and pressed Delete once; a second explicit
    /// confirmation is required before anything runs.
    Armed { dates: Vec<String> },
}

impl SnapshotConfirmState {
    /// Arms the confirmation for `dates`, dropping anything that is not a
    /// valid snapshot date. Returns `false` (and stays/returns to `Idle`) when
    /// nothing valid was selected.
    pub fn arm(&mut self, dates: Vec<String>) -> bool {
        let valid: Vec<String> = dates
            .into_iter()
            .filter(|date| is_snapshot_date(date))
            .collect();
        if valid.is_empty() {
            *self = Self::Idle;
            false
        } else {
            *self = Self::Armed { dates: valid };
            true
        }
    }

    /// Consumes the armed dates (second step of the two-step confirm) and
    /// resets to `Idle`. Returns `None` when nothing was armed.
    pub fn confirm(&mut self) -> Option<Vec<String>> {
        match std::mem::take(self) {
            Self::Armed { dates } => Some(dates),
            Self::Idle => None,
        }
    }

    /// Disarms without deleting anything.
    pub fn cancel(&mut self) {
        *self = Self::Idle;
    }

    #[must_use]
    pub fn is_armed(&self) -> bool {
        matches!(self, Self::Armed { .. })
    }

    #[must_use]
    pub fn armed_count(&self) -> usize {
        match self {
            Self::Armed { dates } => dates.len(),
            Self::Idle => 0,
        }
    }
}

/// Extracts the snapshot date token from a `tmutil listlocalsnapshots`
/// identifier (`com.apple.TimeMachine.<date>.local`) or accepts a bare date
/// (the `tmutil listlocalsnapshotdates` / `diskutil apfs listSnapshots` form).
/// Returns `None` for anything that does not carry a strict
/// `YYYY-MM-DD-HHMMSS` date — such snapshots are review-only.
#[must_use]
pub fn snapshot_date_from_identifier(identifier: &str) -> Option<String> {
    let trimmed = identifier.trim();
    let candidate = trimmed
        .strip_prefix("com.apple.TimeMachine.")
        .map_or(trimmed, |rest| rest.strip_suffix(".local").unwrap_or(rest));
    is_snapshot_date(candidate).then(|| candidate.to_owned())
}

/// Strict shape check for a tmutil snapshot date: `YYYY-MM-DD-HHMMSS` (17
/// bytes, digits and dashes in fixed positions). This is the injection guard —
/// only strings passing this check are ever placed on a command line.
#[must_use]
pub fn is_snapshot_date(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    bytes.iter().enumerate().all(|(idx, byte)| match idx {
        4 | 7 | 10 => *byte == b'-',
        _ => byte.is_ascii_digit(),
    })
}

/// Formats a snapshot date token for display: `2026-06-29-120000` becomes
/// `2026-06-29 12:00:00`. Anything that is not a strict snapshot date is
/// returned unchanged (never panics, never slices blindly).
#[must_use]
pub fn format_snapshot_date(date: &str) -> String {
    if !is_snapshot_date(date) {
        return date.to_owned();
    }
    match (
        date.get(..10),
        date.get(11..13),
        date.get(13..15),
        date.get(15..17),
    ) {
        (Some(day), Some(hours), Some(minutes), Some(seconds)) => {
            format!("{day} {hours}:{minutes}:{seconds}")
        }
        _ => date.to_owned(),
    }
}

/// The exact command a deletion runs, exposed for tests (which must never
/// execute it). `None` when the date fails validation.
#[must_use]
pub fn delete_command_spec(date: &str) -> Option<(&'static str, Vec<String>)> {
    if !is_snapshot_date(date) {
        return None;
    }
    Some((
        "/usr/bin/tmutil",
        vec!["deletelocalsnapshots".to_owned(), date.to_owned()],
    ))
}

/// Deletes the given local snapshots, one `tmutil deletelocalsnapshots <date>`
/// per entry. Only ever call this with dates the user explicitly reviewed and
/// confirmed in the UI — deletion is permanent and does not go to the Trash.
///
/// Each invocation's exit status and stderr are inspected; a failure is
/// recorded verbatim and NEVER retried. Invalid dates are refused up front
/// without spawning anything.
#[must_use]
pub fn delete_local_snapshots(dates: &[String]) -> SnapshotCleanupResult {
    let mut result = SnapshotCleanupResult::default();
    for date in dates {
        match run_delete(date) {
            Ok(()) => result.deleted.push(date.clone()),
            Err(message) => result.failures.push(SnapshotDeleteFailure {
                date: date.clone(),
                message,
            }),
        }
    }
    result
}

/// Runs a single validated deletion. Split from the loop so the command
/// construction ([`delete_command_spec`]) and the outcome interpretation
/// ([`interpret_delete_output`]) stay pure and testable without execution.
fn run_delete(date: &str) -> std::result::Result<(), String> {
    let Some((program, args)) = delete_command_spec(date) else {
        return Err("not a valid snapshot date; refusing to run tmutil".to_owned());
    };

    // Audited destructive-command adapter, the snapshot counterpart of the
    // executor's trash path. `Command::new` is banned workspace-wide
    // (clippy.toml) precisely so this is the only place a snapshot deletion can
    // originate. SAFETY of this invocation:
    // - `program` is the absolute `/usr/bin/tmutil` (no PATH lookup);
    // - the only variable argument is `date`, which `delete_command_spec` just
    //   re-validated against the strict `YYYY-MM-DD-HHMMSS` shape, so no
    //   attacker-influenced string can smuggle flags or paths in;
    // - the subcommand is `deletelocalsnapshots <date>` — precise, one snapshot
    //   per invocation, never a blanket thin;
    // - callers reach this only through the UIs' explicit review-then-confirm
    //   flow (see `SnapshotConfirmState`), and the operation is documented to
    //   the user as permanent (not trash-reversible).
    #[allow(clippy::disallowed_methods)]
    let output = std::process::Command::new(program)
        .args(&args)
        .output()
        .map_err(|err| format!("could not launch tmutil: {err}"))?;

    interpret_delete_output(
        output.status.success(),
        output.status.code(),
        &String::from_utf8_lossy(&output.stderr),
    )
}

/// Interprets a `tmutil deletelocalsnapshots` outcome. Pure so tests can feed
/// mocked statuses/stderr without ever executing tmutil.
fn interpret_delete_output(
    success: bool,
    exit_code: Option<i32>,
    stderr: &str,
) -> std::result::Result<(), String> {
    if success {
        return Ok(());
    }

    let detail = stderr.trim();
    let lowercase = detail.to_lowercase();
    let needs_fda_hint = detail.is_empty()
        || lowercase.contains("not permitted")
        || lowercase.contains("permission")
        || lowercase.contains("privilege");

    let status = exit_code.map_or_else(
        || "terminated by signal".to_owned(),
        |code| format!("exit status {code}"),
    );
    let mut message = if detail.is_empty() {
        format!("tmutil failed ({status})")
    } else {
        format!("tmutil failed ({status}): {detail}")
    };
    if needs_fda_hint {
        message.push_str(
            "; tmutil may require Full Disk Access (System Settings > Privacy & Security).",
        );
    }
    Err(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn listing(identifiers: &[&str], query_succeeded: bool) -> LocalSnapshots {
        LocalSnapshots {
            volume: Path::new("/").to_path_buf(),
            identifiers: identifiers.iter().map(ToString::to_string).collect(),
            query_succeeded,
        }
    }

    #[test]
    fn extracts_date_from_tmutil_identifier() {
        assert_eq!(
            snapshot_date_from_identifier("com.apple.TimeMachine.2026-06-29-120000.local"),
            Some("2026-06-29-120000".to_owned())
        );
        // Older identifiers had no `.local` suffix.
        assert_eq!(
            snapshot_date_from_identifier("com.apple.TimeMachine.2019-01-02-030405"),
            Some("2019-01-02-030405".to_owned())
        );
        // Bare dates (listlocalsnapshotdates / diskutil) pass through.
        assert_eq!(
            snapshot_date_from_identifier("2026-06-29-120000"),
            Some("2026-06-29-120000".to_owned())
        );
    }

    #[test]
    fn rejects_identifiers_without_a_strict_date() {
        assert_eq!(snapshot_date_from_identifier(""), None);
        assert_eq!(snapshot_date_from_identifier("com.apple.TimeMachine"), None);
        assert_eq!(
            snapshot_date_from_identifier("com.apple.TimeMachine.notadate.local"),
            None
        );
        // Injection attempts must never yield a runnable date.
        assert_eq!(
            snapshot_date_from_identifier("2026-06-29-120000; rm -rf /"),
            None
        );
        assert_eq!(snapshot_date_from_identifier("--force"), None);
        assert_eq!(snapshot_date_from_identifier("/"), None);
    }

    #[test]
    fn snapshot_date_shape_is_strict() {
        assert!(is_snapshot_date("2026-06-29-120000"));
        assert!(!is_snapshot_date("2026-06-29-12000")); // too short
        assert!(!is_snapshot_date("2026-06-29-1200000")); // too long
        assert!(!is_snapshot_date("2026_06-29-120000")); // wrong separator
        assert!(!is_snapshot_date("2026-06-29 120000")); // space
        assert!(!is_snapshot_date("2026-06-29-12000a")); // non-digit
    }

    #[test]
    fn from_listing_maps_identifiers_and_query_flag() {
        let analysis = SnapshotAnalysis::from_listing(
            &listing(
                &[
                    "com.apple.TimeMachine.2026-06-29-120000.local",
                    "garbage-line",
                    "com.apple.TimeMachine.2026-06-30-090000.local",
                ],
                true,
            ),
            42,
        );
        assert!(analysis.query_succeeded);
        assert_eq!(analysis.purgeable_estimate_bytes, 42);
        assert_eq!(analysis.snapshots.len(), 2);
        let first = analysis.snapshots.first().unwrap();
        assert_eq!(first.date, "2026-06-29-120000");
        assert_eq!(
            first.identifier,
            "com.apple.TimeMachine.2026-06-29-120000.local"
        );

        let failed = SnapshotAnalysis::from_listing(&listing(&[], false), 0);
        assert!(!failed.query_succeeded);
        assert!(failed.snapshots.is_empty());
    }

    #[test]
    fn confirm_state_machine_arms_confirms_and_cancels() {
        let mut state = SnapshotConfirmState::default();
        assert!(!state.is_armed());
        assert_eq!(state.confirm(), None); // confirming while idle is a no-op

        // Arming with nothing valid stays idle.
        assert!(!state.arm(vec![]));
        assert!(!state.arm(vec!["not-a-date".to_owned()]));
        assert!(!state.is_armed());

        // Invalid entries are dropped, valid ones survive.
        assert!(state.arm(vec![
            "2026-06-29-120000".to_owned(),
            "bogus".to_owned(),
            "2026-06-30-090000".to_owned(),
        ]));
        assert!(state.is_armed());
        assert_eq!(state.armed_count(), 2);

        // Confirm hands the dates out exactly once and resets.
        let dates = state.confirm().unwrap();
        assert_eq!(dates, vec!["2026-06-29-120000", "2026-06-30-090000"]);
        assert!(!state.is_armed());
        assert_eq!(state.confirm(), None);

        // Cancel disarms without deleting.
        assert!(state.arm(vec!["2026-06-29-120000".to_owned()]));
        state.cancel();
        assert!(!state.is_armed());
        assert_eq!(state.confirm(), None);
    }

    #[test]
    fn formats_dates_for_display() {
        assert_eq!(
            format_snapshot_date("2026-06-29-120000"),
            "2026-06-29 12:00:00"
        );
        // Non-dates pass through untouched.
        assert_eq!(format_snapshot_date("not-a-date"), "not-a-date");
        assert_eq!(format_snapshot_date(""), "");
    }

    #[test]
    fn delete_command_is_precise_and_refuses_invalid_dates() {
        let (program, args) = delete_command_spec("2026-06-29-120000").unwrap();
        assert_eq!(program, "/usr/bin/tmutil");
        assert_eq!(args, vec!["deletelocalsnapshots", "2026-06-29-120000"]);

        assert!(delete_command_spec("2026-06-29-120000 /").is_none());
        assert!(delete_command_spec("thinlocalsnapshots").is_none());
        assert!(delete_command_spec("").is_none());
    }

    #[test]
    fn invalid_dates_are_refused_without_spawning_tmutil() {
        // Only invalid dates here: `delete_local_snapshots` must record refusals
        // via the validation short-circuit and never reach the Command path.
        let result = delete_local_snapshots(&[
            "not-a-date".to_owned(),
            "2026-06-29-120000; whoami".to_owned(),
        ]);
        assert!(result.deleted.is_empty());
        assert_eq!(result.failures.len(), 2);
        for failure in &result.failures {
            assert!(failure.message.contains("refusing to run tmutil"));
        }
    }

    #[test]
    fn interprets_mocked_tmutil_outcomes() {
        // Success.
        assert_eq!(interpret_delete_output(true, Some(0), ""), Ok(()));

        // Plain failure with stderr: message carries the detail verbatim.
        let err =
            interpret_delete_output(false, Some(1), "tmutil: no such snapshot\n").unwrap_err();
        assert!(err.contains("exit status 1"));
        assert!(err.contains("no such snapshot"));
        assert!(!err.contains("Full Disk Access"));

        // Permission-shaped failure gets the Full Disk Access hint.
        let err = interpret_delete_output(false, Some(1), "Operation not permitted").unwrap_err();
        assert!(err.contains("Full Disk Access"));

        // Empty stderr also hints (sealed volume / TCC denials are often mute).
        let err = interpret_delete_output(false, Some(78), "").unwrap_err();
        assert!(err.contains("exit status 78"));
        assert!(err.contains("Full Disk Access"));

        // Signal termination is reported honestly.
        let err = interpret_delete_output(false, None, "").unwrap_err();
        assert!(err.contains("terminated by signal"));
    }

    #[test]
    fn cleanup_result_status_copy_is_shared() {
        let ok = SnapshotCleanupResult {
            deleted: vec!["2026-06-29-120000".to_owned()],
            failures: vec![],
        };
        assert_eq!(
            ok.status_message(),
            "Deleted 1 local snapshot(s). APFS releases the space shortly."
        );

        let mixed = SnapshotCleanupResult {
            deleted: vec!["2026-06-29-120000".to_owned()],
            failures: vec![SnapshotDeleteFailure {
                date: "2026-06-30-090000".to_owned(),
                message: "tmutil failed (exit status 1): denied".to_owned(),
            }],
        };
        let message = mixed.status_message();
        assert!(message.contains("Deleted 1 snapshot(s); 1 failed."));
        assert!(message.contains("2026-06-30-090000"));

        let none = SnapshotCleanupResult::default();
        assert_eq!(none.status_message(), "No snapshots were deleted.");
    }
}
