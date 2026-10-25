//! Audited subprocess adapter for the one uninstall case that genuinely needs
//! administrator rights: moving an app bundle or leftover the user's account
//! cannot write to (App Store bundles are root-owned) into the user's own Trash.
//!
//! SAFETY: this is **not** a permanent delete. The item lands in `~/.Trash`
//! exactly like a Finder drag, so it stays recoverable, and it only runs for a
//! path the user explicitly reviewed and confirmed in the Applications tab,
//! after the unprivileged Trash move already failed. The elevated command is a
//! single `/bin/mv -f` with fully quoted arguments; nothing in a path can add a
//! shell metacharacter.
//!
//! `Command::new` is lint-disallowed outside audited adapters. This module IS
//! that audited adapter for the uninstall move (compare
//! `cleanton-services::reviewed_process`), hence the scoped allow.

use std::path::{Path, PathBuf};

/// Move `path` into `~/.Trash` using a targeted macOS administrator prompt.
///
/// Returns the destination path on success. Never removes data permanently: the
/// item is renamed into the Trash, so the user can still restore it.
#[cfg(target_os = "macos")]
pub(crate) fn move_to_trash_elevated(path: &Path) -> std::io::Result<PathBuf> {
    let Some(destination) = unique_trash_destination(path) else {
        return Err(std::io::Error::other(
            "cannot resolve a free destination in ~/.Trash",
        ));
    };
    let command = format!(
        "/bin/mv -f {} {}",
        shell_quote(&path.to_string_lossy()),
        shell_quote(&destination.to_string_lossy())
    );
    let script = format!(
        "do shell script {} with administrator privileges",
        applescript_quote(&command)
    );

    #[allow(clippy::disallowed_methods)]
    let status = std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .status()?;

    if status.success() && !path.exists() {
        Ok(destination)
    } else {
        Err(std::io::Error::other(format!(
            "elevated move to Trash did not complete ({status})"
        )))
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn move_to_trash_elevated(_path: &Path) -> std::io::Result<PathBuf> {
    Err(std::io::Error::other(
        "elevated Trash moves are only supported on macOS",
    ))
}

/// A free `~/.Trash/<name>`, suffixed on collision so an existing Trash entry is
/// never overwritten (an `mv -f` onto an existing name would replace it).
#[cfg(target_os = "macos")]
fn unique_trash_destination(path: &Path) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let trash = PathBuf::from(home).join(".Trash");
    let name = path.file_name()?;

    let direct = trash.join(name);
    if !direct.exists() {
        return Some(direct);
    }

    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("item");
    let extension = path.extension().and_then(|extension| extension.to_str());
    for attempt in 1..1_000_u16 {
        let name = match extension {
            Some(extension) => format!("{stem} {attempt}.{extension}"),
            None => format!("{stem} {attempt}"),
        };
        let candidate = trash.join(name);
        if !candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn applescript_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn shell_quoting_neutralises_embedded_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        // A shell metacharacter stays inside the single quotes.
        assert_eq!(shell_quote("a; rm -rf /"), "'a; rm -rf /'");
    }

    #[test]
    fn applescript_quoting_escapes_backslash_and_quote() {
        assert_eq!(applescript_quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(applescript_quote("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn collision_suffix_keeps_the_extension() {
        let path = Path::new("/Applications/Some App.app");
        assert_eq!(
            path.file_stem().and_then(|stem| stem.to_str()),
            Some("Some App")
        );
        assert_eq!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("app")
        );
    }
}
