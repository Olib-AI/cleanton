//! User-initiated Trash emptying for the Slint GUI.
//!
//! Per `doc/PLATFORM.md` §1.1 Cleanton must NEVER empty the Trash automatically.
//! This module provides the explicit, confirmation-gated "Empty Trash now"
//! affordance that realizes trashed-but-not-freed space. It shells out to Finder
//! via `osascript`, the supported macOS path to empty all per-volume Trashes.

/// Empties the macOS Trash via Finder. Only ever called after an explicit user
/// confirmation in the UI; never invoked automatically.
///
/// # Errors
///
/// Returns a human-readable message if `osascript`/Finder is unavailable or the
/// command exits non-zero (e.g. automation permission was denied).
pub fn empty_trash() -> Result<(), String> {
    // Audited, user-confirmed exception to the workspace-wide ban on
    // `Command::new`; mirrors the scanner's `tmutil` disclosure call.
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

/// Whether the user's Trash currently holds anything.
///
/// Cheap directory listing of the well-known per-user Trash locations
/// (macOS `~/.Trash`, Linux XDG `~/.local/share/Trash/files`); used only to
/// enable/disable the "Empty Trash now" affordance and its label. Any read
/// error degrades to `false` ("looks empty") rather than enabling a
/// destructive action on a guess.
#[must_use]
pub fn trash_has_items() -> bool {
    let Some(home) = std::env::var_os("HOME") else {
        return false;
    };
    let home = std::path::PathBuf::from(home);
    [home.join(".Trash"), home.join(".local/share/Trash/files")]
        .iter()
        .any(|dir| std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some()))
}
