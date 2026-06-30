//! Full Disk Access (TCC) detection and first-run guidance.
//!
//! macOS grants Full Disk Access (FDA) to the *host* process, not to the
//! abstract "Cleanton" application:
//!
//! - A terminal-hosted CLI/TUI inherits the FDA grant of the terminal emulator
//!   that launched it (Terminal.app, iTerm2, Ghostty, WezTerm, …). The user
//!   must grant FDA to that **terminal**, not to the `cleanton` binary.
//! - A double-clicked `.app` bundle has its own TCC identity, tied to its code
//!   signature / bundle id, and needs its **own** grant.
//!
//! Detection probes read access to a known TCC-protected location. Every probe
//! is infallible: a permission denial is a normal, first-class result and is
//! never allowed to panic. This mirrors the engine invariant that permission
//! errors are results, not crashes.
//!
//! This module is intentionally self-contained and duplicated (kept in sync)
//! between `cleanton-cli` and `cleanton-app` so the guidance does not require a
//! shared dependency in other crates. Because the two hosts surface FDA
//! differently (CLI prints JSON/text; the app drives a Slint panel), not every
//! item is exercised by both, so module-wide dead-code is allowed here.
#![allow(dead_code)]
// This module's docs name many product/terminal identifiers in prose
// (Terminal.app, iTerm2, WezTerm, TCC.db, …); backticking each is noise.
#![allow(clippy::doc_markdown)]

use std::path::{Path, PathBuf};

/// Deep link to System Settings → Privacy & Security → Full Disk Access.
///
/// Opening this URL with `open` sends the user straight to the correct pane on
/// modern macOS (including Tahoe 26, where Settings labels were reorganised).
pub const SETTINGS_FDA_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";

/// Result of probing a TCC-protected location for read access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdaStatus {
    /// A protected location was read successfully: FDA is effectively present.
    Granted,
    /// A protected location returned permission-denied: FDA is likely missing.
    LikelyMissing,
    /// Could not determine (no probe target available, or a non-permission
    /// error such as the path not existing).
    Unknown,
}

impl FdaStatus {
    /// True only when a probe positively observed a permission denial.
    #[must_use]
    pub fn is_likely_missing(self) -> bool {
        matches!(self, FdaStatus::LikelyMissing)
    }

    /// Stable machine-readable token (used in `--json` output).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FdaStatus::Granted => "granted",
            FdaStatus::LikelyMissing => "likely-missing",
            FdaStatus::Unknown => "unknown",
        }
    }
}

/// How Cleanton is being hosted right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostContext {
    /// Running from inside a `.app` bundle (`…/Contents/MacOS/<exe>`).
    AppBundle,
    /// Running as a terminal-hosted CLI/TUI binary.
    Terminal,
}

impl HostContext {
    /// Stable machine-readable token (used in `--json` output).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HostContext::AppBundle => "app-bundle",
            HostContext::Terminal => "terminal",
        }
    }
}

/// Detect whether the current executable lives inside a `.app` bundle.
#[must_use]
pub fn host_context() -> HostContext {
    let in_bundle = std::env::current_exe()
        .ok()
        .is_some_and(|exe| exe_is_in_app_bundle(&exe));
    if in_bundle {
        HostContext::AppBundle
    } else {
        HostContext::Terminal
    }
}

/// A bundled binary lives at `<Name>.app/Contents/MacOS/<exe>`.
fn exe_is_in_app_bundle(exe: &Path) -> bool {
    let Some(macos) = exe.parent() else {
        return false;
    };
    if macos.file_name() != Some(std::ffi::OsStr::new("MacOS")) {
        return false;
    }
    let Some(contents) = macos.parent() else {
        return false;
    };
    if contents.file_name() != Some(std::ffi::OsStr::new("Contents")) {
        return false;
    }
    contents
        .parent()
        .and_then(Path::extension)
        .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
}

/// Best-effort, friendly name of the host terminal for CLI guidance.
///
/// Falls back to a generic phrase when the terminal cannot be identified, so we
/// never print a misleading specific name.
#[must_use]
pub fn terminal_label() -> String {
    match std::env::var("TERM_PROGRAM").ok().as_deref() {
        Some("Apple_Terminal") => "Terminal".to_owned(),
        Some("iTerm.app") => "iTerm2".to_owned(),
        Some("vscode") => "Visual Studio Code".to_owned(),
        Some("ghostty" | "Ghostty") => "Ghostty".to_owned(),
        Some("WezTerm") => "WezTerm".to_owned(),
        Some("Tabby") => "Tabby".to_owned(),
        Some("Hyper") => "Hyper".to_owned(),
        Some("Alacritty") => "Alacritty".to_owned(),
        Some(other) if !other.is_empty() => other.to_owned(),
        _ => "your terminal app".to_owned(),
    }
}

enum ProbeOutcome {
    Readable,
    Denied,
    Indeterminate,
}

/// Probe read access to a known TCC-protected location without crashing on
/// denial. Returns [`FdaStatus::Unknown`] when nothing conclusive is observed.
#[must_use]
pub fn probe() -> FdaStatus {
    let Some(home) = home_dir() else {
        return FdaStatus::Unknown;
    };

    // Primary probe: the TCC database itself can only be read with Full Disk
    // Access. A clean success means FDA is effectively present for this host.
    let tcc_db = home.join("Library/Application Support/com.apple.TCC/TCC.db");
    match probe_file_readable(&tcc_db) {
        ProbeOutcome::Readable => return FdaStatus::Granted,
        ProbeOutcome::Denied => return FdaStatus::LikelyMissing,
        ProbeOutcome::Indeterminate => {}
    }

    // Secondary probe: ~/Library/Mail is FDA-gated when it exists.
    let mail = home.join("Library/Mail");
    match probe_dir_readable(&mail) {
        ProbeOutcome::Readable => FdaStatus::Granted,
        ProbeOutcome::Denied => FdaStatus::LikelyMissing,
        ProbeOutcome::Indeterminate => FdaStatus::Unknown,
    }
}

fn probe_file_readable(path: &Path) -> ProbeOutcome {
    match std::fs::File::open(path) {
        Ok(_) => ProbeOutcome::Readable,
        Err(err) => classify(&err),
    }
}

fn probe_dir_readable(path: &Path) -> ProbeOutcome {
    match std::fs::read_dir(path) {
        Ok(mut entries) => {
            // Some directories only raise TCC when their entries are read.
            match entries.next() {
                Some(Err(err)) => classify(&err),
                _ => ProbeOutcome::Readable,
            }
        }
        Err(err) => classify(&err),
    }
}

fn classify(err: &std::io::Error) -> ProbeOutcome {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        ProbeOutcome::Denied
    } else {
        // NotFound and anything else are inconclusive for FDA purposes.
        ProbeOutcome::Indeterminate
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

/// One-line headline summarising the FDA situation for the current host.
#[must_use]
pub fn headline(context: HostContext) -> String {
    match context {
        HostContext::Terminal => format!(
            "Full Disk Access is granted to {} (the host terminal), not to the cleanton binary.",
            terminal_label()
        ),
        HostContext::AppBundle => {
            "Full Disk Access is granted to the Cleanton app's own identity (separate from any \
             terminal)."
                .to_owned()
        }
    }
}

/// Full, non-alarming, step-by-step guidance lines for the given host context.
///
/// These are informational. Normal operation is never blocked; Cleanton runs in
/// degraded mode and reports skipped locations honestly.
#[must_use]
pub fn guidance_lines(context: HostContext) -> Vec<String> {
    let mut lines = Vec::new();
    match context {
        HostContext::Terminal => {
            let term = terminal_label();
            lines.push(format!(
                "macOS evaluates Full Disk Access against {term} — the terminal that launched \
                 cleanton — not against the cleanton binary itself."
            ));
            lines.push("To grant it:".to_owned());
            lines.push(
                "  1. Open System Settings → Privacy & Security → Full Disk Access.".to_owned(),
            );
            lines.push(format!("     (or run: open \"{SETTINGS_FDA_URL}\")"));
            lines.push(format!(
                "  2. Enable {term} in the list. If it is not shown, add it with +."
            ));
            lines.push(format!(
                "  3. Quit and reopen {term}, then re-run cleanton."
            ));
            lines.push(
                "Note: the Cleanton.app bundle has its own Full Disk Access entry and must be \
                 granted separately."
                    .to_owned(),
            );
        }
        HostContext::AppBundle => {
            lines.push(
                "The Cleanton app has its own Full Disk Access identity, tied to its bundle id — \
                 separate from any terminal."
                    .to_owned(),
            );
            lines.push("To grant it:".to_owned());
            lines.push(
                "  1. Open System Settings → Privacy & Security → Full Disk Access.".to_owned(),
            );
            lines.push(format!("     (or run: open \"{SETTINGS_FDA_URL}\")"));
            lines.push(
                "  2. Enable Cleanton in the list. If it is not shown, add it with + and choose \
                 Cleanton.app."
                    .to_owned(),
            );
            lines.push("  3. Quit and reopen Cleanton.".to_owned());
            lines.push(
                "Note: running the `cleanton` CLI from a terminal instead uses that terminal's \
                 Full Disk Access grant."
                    .to_owned(),
            );
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn bundle_detection_matches_app_layout() {
        let bundled = PathBuf::from("/Applications/Cleanton.app/Contents/MacOS/Cleanton");
        assert!(exe_is_in_app_bundle(&bundled));

        let cli = PathBuf::from("/usr/local/bin/cleanton");
        assert!(!exe_is_in_app_bundle(&cli));

        let target = PathBuf::from("/home/x/cleanton/target/release/cleanton-app");
        assert!(!exe_is_in_app_bundle(&target));
    }

    #[test]
    fn status_and_context_tokens_are_stable() {
        assert_eq!(FdaStatus::Granted.as_str(), "granted");
        assert_eq!(FdaStatus::LikelyMissing.as_str(), "likely-missing");
        assert_eq!(FdaStatus::Unknown.as_str(), "unknown");
        assert!(FdaStatus::LikelyMissing.is_likely_missing());
        assert!(!FdaStatus::Granted.is_likely_missing());
        assert_eq!(HostContext::AppBundle.as_str(), "app-bundle");
        assert_eq!(HostContext::Terminal.as_str(), "terminal");
    }

    #[test]
    fn guidance_is_context_specific() {
        let cli = guidance_lines(HostContext::Terminal);
        assert!(cli.iter().any(|line| line.contains("Full Disk Access")));
        // CLI guidance must point at the bundle's separate grant.
        assert!(cli.iter().any(|line| line.contains("Cleanton.app")));

        let app = guidance_lines(HostContext::AppBundle);
        assert!(app.iter().any(|line| line.contains("own Full Disk Access")));
        // App guidance must mention the deep link.
        assert!(app.iter().any(|line| line.contains(SETTINGS_FDA_URL)));
    }

    #[test]
    fn probe_never_panics() {
        // Whatever the host grants, this must return without panicking.
        let _ = probe();
        let _ = host_context();
        let _ = headline(host_context());
    }
}
