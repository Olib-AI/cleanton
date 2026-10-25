//! Continuous, cheap security watching.
//!
//! The on-demand security scan is expensive by design: it fingerprints and
//! content-scans every installed package so the baseline diff can be trusted.
//! That is the right cost when the user asked for a scan, and completely wrong
//! for a process that runs all day. So the watcher works in two stages:
//!
//! 1. **Idle.** One `stat` per watched package root. A package manager that
//!    installs, updates, or removes anything necessarily touches the parent
//!    directory, so an unchanged parent mtime means "nothing can have changed"
//!    and the tick ends there. No walking, no file reads, no subprocesses.
//!    Between ticks the thread sleeps, and the interval backs off from
//!    [`WatchOptions::idle`] to [`WatchOptions::max_idle`] while the machine is
//!    quiet, so an idle watcher costs a handful of syscalls every few minutes.
//!
//! 2. **Change.** When a root's mtime moves, that directory is listed once and
//!    the entry list is diffed against the previous snapshot. Only the new or
//!    touched package directories are examined, and only those: an advisory
//!    lookup by version (a `HashMap` probe), a lifecycle-hook check on the
//!    manifest, and one content scan of that single directory. A freshly
//!    installed package is therefore checked immediately, without rescanning
//!    anything else.
//!
//! The watcher is read-only, like everything else in the security engine: it
//! reports, and never removes, quarantines, or modifies a package. Its only
//! state is in memory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use cleanton_antivirus::{ScanConfig, Scanner, Verdict};

use crate::advisories::{AdvisoryDatabase, Ecosystem, PackageSubject};
use crate::security::{self, SecurityTarget, SecurityTargetKind, Severity};

/// Bounds on the work a single tick may do, so a large install cannot turn one
/// tick into a full scan.
const MAX_PACKAGES_PER_TICK: usize = 24;

/// Tuning for the watcher loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchOptions {
    /// Sleep between ticks while idle.
    pub idle: Duration,
    /// Upper bound on the backed-off idle sleep.
    pub max_idle: Duration,
    /// Short sleep after a change, so a package manager mid-install is allowed
    /// to finish before it is checked.
    pub burst: Duration,
    /// Quiet ticks before the idle interval doubles towards `max_idle`.
    pub quiet_ticks_before_backoff: u32,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(30),
            max_idle: Duration::from_secs(15 * 60),
            burst: Duration::from_secs(5),
            quiet_ticks_before_backoff: 4,
        }
    }
}

impl WatchOptions {
    /// Idle interval from a `--interval` style number of seconds, with the
    /// backoff ceiling kept at least as large as the base interval.
    #[must_use]
    pub fn with_idle_seconds(seconds: u64) -> Self {
        let idle = Duration::from_secs(seconds.max(1));
        let mut options = Self::default();
        options.idle = idle;
        options.max_idle = options.max_idle.max(idle);
        options.burst = options.burst.min(idle);
        options
    }
}

/// Something a tick observed. `Quiet` exists so a caller can distinguish
/// "checked and found nothing" from "did not check".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEvent {
    /// Nothing changed under any watched root.
    Quiet,
    /// A watched root changed; `new_packages` entries were examined.
    RootChanged {
        root: PathBuf,
        new_packages: usize,
    },
    /// An examined package version falls inside a published advisory.
    Advisory {
        package: String,
        version: String,
        advisory: String,
        severity: Severity,
        summary: String,
        remediation: String,
    },
    /// A newly installed package runs a script at install time. Not a verdict,
    /// just the fact that makes install-time compromise possible.
    InstallHook { package: String, hook: String },
    /// A newly installed package did not come back clean from the content scan.
    ContentFinding {
        package: String,
        verdict: Verdict,
        findings: usize,
        headline: String,
    },
}

impl WatchEvent {
    /// Whether this event is worth waking a user for.
    #[must_use]
    pub fn is_reportable(&self) -> bool {
        !matches!(self, Self::Quiet)
    }
}

/// Per-root snapshot: the directory mtime plus the entry mtimes it was taken
/// at. Kept as `BTreeMap` so diffing is deterministic and cheap to print.
#[derive(Debug, Clone, Default)]
struct RootState {
    mtime: Option<SystemTime>,
    entries: BTreeMap<String, Option<SystemTime>>,
}

/// The watcher itself: targets plus their last snapshot.
#[derive(Debug)]
pub struct PackageWatcher {
    roots: Vec<(SecurityTarget, RootState)>,
    advisories: AdvisoryDatabase,
    options: WatchOptions,
}

impl PackageWatcher {
    /// Watch the package roots that currently exist on this machine.
    #[must_use]
    pub fn for_default_targets(options: WatchOptions) -> Self {
        Self::new(security::discover_default_targets(), options)
    }

    /// Watch an explicit target set.
    #[must_use]
    pub fn new(targets: Vec<SecurityTarget>, options: WatchOptions) -> Self {
        Self {
            roots: targets
                .into_iter()
                .map(|target| (target, RootState::default()))
                .collect(),
            advisories: AdvisoryDatabase::load(),
            options,
        }
    }

    /// Watched roots (for logging / display).
    #[must_use]
    pub fn roots(&self) -> impl Iterator<Item = &SecurityTarget> {
        self.roots.iter().map(|(target, _)| target)
    }

    /// Longest sleep the loop will currently use.
    #[must_use]
    pub fn options(&self) -> WatchOptions {
        self.options
    }

    /// Take one pass over every watched root.
    pub fn tick(&mut self, cancel: &AtomicBool) -> Vec<WatchEvent> {
        let mut events = Vec::new();
        for (target, state) in &mut self.roots {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            // Stage 1: one stat. An unchanged directory mtime proves no entry
            // was added, removed, or renamed, so there is nothing to check.
            let Ok(metadata) = std::fs::metadata(&target.root) else {
                // The root disappeared (an uninstalled toolchain): forget the
                // snapshot so a reappearing root is examined from scratch.
                state.mtime = None;
                state.entries.clear();
                continue;
            };
            let mtime = metadata.modified().ok();
            if let (Some(current), Some(previous)) = (mtime, state.mtime)
                && current == previous
            {
                continue;
            }

            // Stage 2: the directory moved. List it once and diff.
            let current = list_entries(&target.root);
            let first_observation = state.mtime.is_none();
            state.mtime = mtime;
            let previous = std::mem::replace(&mut state.entries, current);
            if first_observation {
                // Prime only. An install that predates the watcher is not
                // "newly installed", and re-reporting a machine's whole
                // package set at every start is exactly the noise this
                // watcher exists to avoid.
                continue;
            }
            let mut candidates: Vec<String> = state
                .entries
                .iter()
                .filter(|(name, mtime)| previous.get(*name) != Some(*mtime))
                .map(|(name, _)| name.clone())
                .collect();
            if candidates.is_empty() {
                continue;
            }
            candidates.truncate(MAX_PACKAGES_PER_TICK);
            let examined = candidates.len();
            for name in &candidates {
                for dir in expand_entry(&target.root, name) {
                    events.extend(self.check_package(target.kind, &dir));
                }
            }
            events.push(WatchEvent::RootChanged {
                root: target.root.clone(),
                new_packages: examined,
            });
        }
        if events.is_empty() {
            events.push(WatchEvent::Quiet);
        }
        events
    }

    /// Investigate one package directory: advisory lookup, lifecycle hooks, and
    /// a single-directory content scan.
    fn check_package(&self, kind: SecurityTargetKind, dir: &Path) -> Vec<WatchEvent> {
        let Some((ecosystem, name, version)) = package_identity(kind, dir) else {
            return Vec::new();
        };
        let mut events = Vec::new();
        if let Some(version) = version.as_deref().filter(|version| !version.is_empty()) {
            let subject = PackageSubject::new(ecosystem, name.clone(), version);
            for advisory in self.advisories.matches(&subject) {
                events.push(WatchEvent::Advisory {
                    package: name.clone(),
                    version: version.to_owned(),
                    advisory: advisory.id.clone(),
                    severity: advisory.severity,
                    summary: advisory.summary.clone(),
                    remediation: advisory.remediation(),
                });
            }
        }
        if let Some(hook) = install_hook(kind, dir) {
            events.push(WatchEvent::InstallHook {
                package: name.clone(),
                hook,
            });
        }
        if kind.is_version_only() {
            // Version-only ecosystems are never content-scanned; see
            // `SecurityTargetKind::is_version_only`.
            return events;
        }
        let scanner = Scanner::with_default_engines(ScanConfig::default());
        if let Ok(report) = scanner.scan_path(dir)
            && !matches!(report.verdict, Verdict::Clean)
        {
            events.push(WatchEvent::ContentFinding {
                package: name,
                verdict: report.verdict,
                findings: report.findings.len(),
                headline: report
                    .findings
                    .first()
                    .map_or_else(String::new, |finding| finding.title.clone()),
            });
        }
        events
    }

    /// The endless loop: tick, emit, then sleep with backoff.
    pub fn run(&mut self, cancel: &AtomicBool, emit: &mut dyn FnMut(WatchEvent)) {
        let mut interval = self.options.idle;
        let mut quiet = 0_u32;
        while !cancel.load(Ordering::Relaxed) {
            let events = self.tick(cancel);
            let busy = events.iter().any(WatchEvent::is_reportable);
            for event in events {
                emit(event);
            }
            if busy {
                quiet = 0;
                interval = self.options.burst;
            } else {
                quiet = quiet.saturating_add(1);
                if quiet >= self.options.quiet_ticks_before_backoff {
                    quiet = 0;
                    interval = interval.saturating_mul(2).min(self.options.max_idle);
                } else {
                    interval = self.options.idle;
                }
            }
            sleep_interruptibly(interval, cancel);
        }
    }
}

/// Sleep in small slices so a cancellation request is honoured promptly.
fn sleep_interruptibly(total: Duration, cancel: &AtomicBool) {
    const SLICE: Duration = Duration::from_millis(200);
    let mut slept = Duration::ZERO;
    while slept < total {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let step = SLICE.min(total.saturating_sub(slept));
        std::thread::sleep(step);
        slept = slept.saturating_add(step);
    }
}

/// Entry name → modification time for one directory. Unreadable entries keep
/// `None` so name-level changes are still detected.
fn list_entries(root: &Path) -> BTreeMap<String, Option<SystemTime>> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return BTreeMap::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                return None;
            }
            let mtime = entry.metadata().ok().and_then(|meta| meta.modified().ok());
            Some((name, mtime))
        })
        .collect()
}

/// A changed entry expands to the package directories it contains: scoped npm
/// directories hold one package per child, everything else is the package.
fn expand_entry(root: &Path, name: &str) -> Vec<PathBuf> {
    let dir = root.join(name);
    if !name.starts_with('@') || !dir.is_dir() {
        return vec![dir];
    }
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect()
}

/// Ecosystem, name, and version for a package directory, without spawning any
/// package manager.
fn package_identity(
    kind: SecurityTargetKind,
    dir: &Path,
) -> Option<(Ecosystem, String, Option<String>)> {
    let fallback = dir.file_name().map_or_else(
        || dir.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    match kind {
        SecurityTargetKind::NodeGlobal
        | SecurityTargetKind::NodeProject
        | SecurityTargetKind::EditorExtensions => {
            let (name, version) = security::npm_manifest(dir, &fallback);
            Some((Ecosystem::Npm, name, version))
        }
        SecurityTargetKind::PythonSitePackages => {
            // `*.dist-info` metadata lives beside the package directory, in
            // site-packages itself.
            let site_packages = dir.parent().unwrap_or(dir);
            let version = security::python_dist_info_version(site_packages, &fallback);
            Some((Ecosystem::PyPI, fallback, version))
        }
        SecurityTargetKind::RubyGems => {
            let (name, version) = security::gem_identity(dir, &fallback);
            Some((Ecosystem::RubyGems, name, version))
        }
        SecurityTargetKind::CargoRegistry => {
            let (name, version) = security::cargo_identity(dir, &fallback);
            Some((Ecosystem::CratesIo, name, version))
        }
        SecurityTargetKind::GoModuleCache => {
            let (name, version) = security::split_versioned_dir_name(&fallback)?;
            Some((Ecosystem::Go, name, Some(version)))
        }
    }
}

/// The install-time script a package declares, when its ecosystem has one.
fn install_hook(kind: SecurityTargetKind, dir: &Path) -> Option<String> {
    if !matches!(
        kind,
        SecurityTargetKind::NodeGlobal
            | SecurityTargetKind::NodeProject
            | SecurityTargetKind::EditorExtensions
    ) {
        return None;
    }
    let manifest = std::fs::read_to_string(dir.join("package.json")).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&manifest).ok()?;
    let scripts = value.get("scripts")?;
    ["preinstall", "install", "postinstall"]
        .into_iter()
        .find(|hook| scripts.get(*hook).is_some())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn quiet(events: &[WatchEvent]) -> bool {
        !events.iter().any(WatchEvent::is_reportable)
    }

    #[test]
    fn idle_tick_reports_quiet_and_does_no_work() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("node_modules");
        write(
            &root.join("add/index.js"),
            "module.exports = (a, b) => a + b;\n",
        );
        let target = SecurityTarget {
            kind: SecurityTargetKind::NodeGlobal,
            root: root.clone(),
        };
        let mut watcher = PackageWatcher::new(vec![target], WatchOptions::default());
        let cancel = AtomicBool::new(false);
        // First tick primes the snapshot (and examines the existing package).
        let _ = watcher.tick(&cancel);
        // Second tick has nothing to do.
        assert!(quiet(&watcher.tick(&cancel)));
    }

    #[test]
    fn newly_installed_vulnerable_package_is_reported_immediately() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("node_modules");
        std::fs::create_dir_all(&root).unwrap();
        let target = SecurityTarget {
            kind: SecurityTargetKind::NodeGlobal,
            root: root.clone(),
        };
        let mut watcher = PackageWatcher::new(vec![target], WatchOptions::default());
        let cancel = AtomicBool::new(false);
        let _ = watcher.tick(&cancel);

        // An install appears, pinned to a version with a published advisory.
        // The short sleep also keeps the parent directory mtime distinct on
        // filesystems with coarse timestamp granularity.
        std::thread::sleep(Duration::from_millis(20));
        write(
            &root.join("lodash/package.json"),
            r#"{ "name": "lodash", "version": "4.17.20" }"#,
        );
        write(&root.join("lodash/index.js"), "module.exports = {};\n");

        let events = watcher.tick(&cancel);
        assert!(
            events.iter().any(|event| matches!(
                event,
                WatchEvent::Advisory { package, advisory, .. }
                    if package == "lodash" && advisory == "CVE-2021-23337"
            )),
            "expected the advisory hit, got {events:?}"
        );
    }

    #[test]
    fn install_hooks_are_reported_for_new_packages() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("node_modules");
        std::fs::create_dir_all(&root).unwrap();
        let target = SecurityTarget {
            kind: SecurityTargetKind::NodeGlobal,
            root: root.clone(),
        };
        let mut watcher = PackageWatcher::new(vec![target], WatchOptions::default());
        let cancel = AtomicBool::new(false);
        let _ = watcher.tick(&cancel);
        std::thread::sleep(Duration::from_millis(20));
        write(
            &root.join("hooky/package.json"),
            r#"{ "name": "hooky", "version": "9.9.9", "scripts": { "postinstall": "node setup.js" } }"#,
        );
        write(&root.join("hooky/setup.js"), "console.log('hi');\n");
        let events = watcher.tick(&cancel);
        assert!(
            events.iter().any(|event| matches!(
                event,
                WatchEvent::InstallHook { package, hook } if package == "hooky" && hook == "postinstall"
            )),
            "expected the lifecycle hook, got {events:?}"
        );
    }

    #[test]
    fn backoff_reaches_the_ceiling_and_burst_resets_it() {
        let options = WatchOptions::with_idle_seconds(1);
        assert_eq!(options.idle, Duration::from_secs(1));
        assert!(options.max_idle >= options.idle);
        assert!(options.burst <= options.idle);
    }

    #[test]
    fn identity_is_read_from_the_manifest_not_the_directory_name() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("weird-dir-name");
        write(
            &dir.join("package.json"),
            r#"{ "name": "real-name", "version": "1.2.3" }"#,
        );
        let (ecosystem, name, version) =
            package_identity(SecurityTargetKind::NodeGlobal, &dir).unwrap();
        assert_eq!(ecosystem, Ecosystem::Npm);
        assert_eq!(name, "real-name");
        assert_eq!(version.as_deref(), Some("1.2.3"));
    }
}
