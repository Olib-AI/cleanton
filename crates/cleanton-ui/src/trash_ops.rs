//! User-initiated Trash emptying.
//!
//! Per `doc/PLATFORM.md` §1.1 Cleanton must NEVER empty the Trash automatically:
//! trashing relocates bytes but does not free them until the user empties the
//! Trash. This module provides the explicit, confirmation-gated "Empty Trash now"
//! affordance that realizes that space. It shells out to Finder via `osascript`,
//! the supported macOS path to empty all per-volume Trashes (and to honor the
//! user's own Finder "warn before emptying" preference).

/// Empties the macOS Trash via Finder. This is only ever called after an explicit
/// user confirmation in the UI; it is never invoked automatically.
///
/// # Errors
///
/// Returns a human-readable message if `osascript`/Finder is unavailable or the
/// command exits non-zero (e.g. automation permission was denied).
pub fn empty_trash() -> Result<(), String> {
    // `osascript` is the audited, user-confirmed exception to the workspace-wide
    // ban on `Command::new` (clippy.toml). It mirrors the scanner's `tmutil`
    // disclosure call: a single, explicit, justified subprocess invocation.
    #[allow(clippy::disallowed_methods)]
    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg("tell application \"Finder\" to empty trash")
        .output()
        .map_err(|err| format!("could not launch osascript: {err}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    if detail.is_empty() {
        Err("emptying the Trash failed (Finder returned a non-zero status)".to_owned())
    } else {
        Err(format!("emptying the Trash failed: {detail}"))
    }
}
