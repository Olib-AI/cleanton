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

/// A short, reassuring lead sentence: scanning works now, but access unlocks the
/// rest. Never alarming — normal operation is never blocked.
#[must_use]
pub fn lead(context: HostContext) -> String {
    match context {
        HostContext::Terminal => format!(
            "You can scan now, but macOS grants Full Disk Access to {} — the terminal that \
             launched Cleanton — so some protected folders are skipped until you turn it on.",
            terminal_label()
        ),
        HostContext::AppBundle => "You can scan now, but macOS keeps some protected folders \
                                   hidden until you give Cleanton Full Disk Access. Turn it on \
                                   for a complete picture of what's reclaimable."
            .to_owned(),
    }
}

/// The grant steps, one short instruction per entry (no leading numbers — the UI
/// numbers them). Kept free of raw URLs and code formatting.
#[must_use]
pub fn steps(context: HostContext) -> Vec<String> {
    match context {
        HostContext::Terminal => {
            let term = terminal_label();
            vec![
                "Open System Settings → Privacy & Security → Full Disk Access (the button below \
                 takes you there)."
                    .to_owned(),
                format!("Turn on {term}. If it isn't listed, click + and add it."),
                format!("Quit and reopen {term}, then run cleanton again."),
            ]
        }
        HostContext::AppBundle => vec![
            "Open System Settings → Privacy & Security → Full Disk Access (the button below takes \
             you there)."
                .to_owned(),
            "Turn on Cleanton. If it isn't listed, click + and choose Cleanton.".to_owned(),
            "Quit and reopen Cleanton.".to_owned(),
        ],
    }
}

/// A quiet footnote clarifying the app/CLI access split, shown muted under the
/// steps.
#[must_use]
pub fn note(context: HostContext) -> String {
    match context {
        HostContext::Terminal => {
            "The Cleanton app has its own separate Full Disk Access entry.".to_owned()
        }
        HostContext::AppBundle => {
            "Running the cleanton command-line tool instead uses your terminal's own access."
                .to_owned()
        }
    }
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
        // Terminal guidance points at the app's separate grant.
        assert!(note(HostContext::Terminal).contains("separate"));
        let cli_steps = steps(HostContext::Terminal);
        assert_eq!(cli_steps.len(), 3);
        assert!(
            cli_steps
                .iter()
                .any(|line| line.contains("Full Disk Access"))
        );

        // App guidance names Cleanton and clarifies the CLI fallback.
        assert!(lead(HostContext::AppBundle).contains("Cleanton"));
        let app_steps = steps(HostContext::AppBundle);
        assert_eq!(app_steps.len(), 3);
        assert!(app_steps.iter().any(|line| line.contains("Cleanton")));
        assert!(note(HostContext::AppBundle).contains("command-line"));

        // Steps must stay free of raw deep-link URLs and code formatting.
        for line in cli_steps.iter().chain(app_steps.iter()) {
            assert!(!line.contains(SETTINGS_FDA_URL));
            assert!(!line.contains('`'));
        }
    }

    #[test]
    fn probe_never_panics() {
        // Whatever the host grants, this must return without panicking.
        let _ = probe();
        let _ = host_context();
        let _ = lead(host_context());
    }
}
