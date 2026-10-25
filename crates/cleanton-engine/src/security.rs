//! Read-only supply-chain security scan of installed packages.
//!
//! Discovers package trees that exist on disk (npm/yarn/pnpm/bun globals,
//! project `node_modules`, Python site-packages, VS Code/Cursor extensions)
//! purely by filesystem inspection — no package-manager process is ever
//! spawned — and runs each top-level package through the static
//! [`cleanton_antivirus::Scanner`] so findings attribute to a package.
//!
//! Results are interpreted through the baseline + diff model in
//! [`crate::security_baseline`]: the first scan records the installed set as
//! the trusted baseline; later scans surface only packages that are new,
//! updated, or — the high signal — changed WITHOUT a version bump. Known,
//! byte-identical packages are suppressed regardless of their raw AV verdict,
//! so a legitimate toolchain (npm, pip, editor extensions) stops crying wolf
//! once reviewed.
//!
//! On top of the diff sits the ASSESSMENT policy (see [`assess`] and
//! [`verdict_corroborated`]): raw AV verdicts stay in the report for
//! transparency, but every display path, count, and exit code derives from a
//! per-package [`Assessment`]. INVARIANT: a red/alert presentation can come
//! ONLY from (a) a same-version tamper, or (b) a CORROBORATED verdict — a
//! known-malware signature hit, or Critical/High findings spanning at least
//! two distinct attack categories outside benign contexts (CI workflows,
//! test/fixture/example trees, docs) with at least one of them anchored in
//! an INSTALL/LIFECYCLE context (the manifest, or a script a lifecycle hook
//! executes). The anchor matches the real threat model: a worm's
//! distinguishing act is running at install time (Shai-Hulud-class npm worms
//! propagate through install hooks), whereas a legitimate extension's
//! minified runtime bundle tripping clipboard/exfiltration heuristics is not
//! install-executed and must not corroborate on its own. Everything else —
//! including a raw "malicious" heuristic verdict on a freshly updated npm
//! tool or editor extension — is presented as a neutral notice.
//!
//! POLICY: this module is detection + notification ONLY. It never produces a
//! `CleanupAction`, never quarantines, and never modifies anything. The
//! [`SecurityReport`] is informational; the only affordances are showing paths
//! so the user can review manually, and updating the BASELINE FILE metadata
//! when the user marks a package reviewed (never the package itself).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use cleanton_antivirus::{ScanConfig, Scanner, Verdict as AvVerdict};
// Re-exported so front ends can consume the report without depending on the
// vendored scanner crate directly. `Finding` is re-exported for the pure
// assessment-policy functions ([`verdict_corroborated`]), which operate on
// the scanner's full finding list.
pub use cleanton_antivirus::{
    Confidence, FileLocation, Finding, Severity, ThreatCategory, Verdict,
};
use cleanton_common::Result;
use serde::{Deserialize, Serialize};

use crate::advisories::{Advisory, AdvisoryDatabase, Ecosystem, PackageSubject};
use crate::security_baseline::{self, BaselineEntry, SecurityBaseline};

/// Cap on the per-package findings retained in the report, worst-first. The
/// full finding count is still recorded in [`PackageReport::finding_count`].
const TOP_FINDINGS_PER_PACKAGE: usize = 6;

/// Evidence snippets are truncated to keep reports small (and to never carry a
/// large chunk of malicious payload around in UI models).
const EVIDENCE_SNIPPET_MAX: usize = 160;

/// Directory walk depth when locating `node_modules` / `site-packages` trees
/// under a user-chosen project root.
const PROJECT_DISCOVERY_DEPTH: usize = 6;

/// Upper bound on scan worker threads. The scanner is CPU-bound and loads each
/// package into memory, so a small pool keeps peak memory bounded.
const MAX_SCAN_WORKERS: usize = 4;

// ── Targets ──────────────────────────────────────────────────────────────────

/// What kind of package tree a discovered target root is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityTargetKind {
    /// A global `node_modules` tree (npm, yarn, pnpm, or bun).
    NodeGlobal,
    /// A project-local `node_modules` tree under a user-chosen root.
    NodeProject,
    /// A Python `site-packages` tree (user installs, pipx venvs, uv tools,
    /// or a project virtualenv).
    PythonSitePackages,
    /// An editor extension directory (`~/.vscode/extensions`,
    /// `~/.cursor/extensions`) — npm-style packages and a real attack vector.
    EditorExtensions,
    /// Installed gems (`~/.gem/ruby/<abi>/gems`, Homebrew's gem tree).
    ///
    /// Version-only: gem trees are large and the installed-version question
    /// ("is this release known-bad?") is answerable from metadata alone, so
    /// these packages are matched against the advisory database and never
    /// content-scanned unless a version matches.
    RubyGems,
    /// Crate sources in the Cargo registry cache (`~/.cargo/registry/src/*`).
    /// Version-only, for the same reason as [`Self::RubyGems`].
    CargoRegistry,
    /// Extracted modules in the Go module cache (`~/go/pkg/mod`).
    /// Version-only.
    GoModuleCache,
}

impl SecurityTargetKind {
    /// Short human label shared by the CLI and both UIs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::NodeGlobal => "global npm packages",
            Self::NodeProject => "project node_modules",
            Self::PythonSitePackages => "Python site-packages",
            Self::EditorExtensions => "editor extensions",
            Self::RubyGems => "installed gems",
            Self::CargoRegistry => "Cargo registry cache",
            Self::GoModuleCache => "Go module cache",
        }
    }

    /// Whether this target is matched by version only (advisory database) and
    /// never handed to the content scanner.
    #[must_use]
    pub fn is_version_only(self) -> bool {
        matches!(
            self,
            Self::RubyGems | Self::CargoRegistry | Self::GoModuleCache
        )
    }
}

/// One package tree root to scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityTarget {
    pub kind: SecurityTargetKind,
    pub root: PathBuf,
}

// ── Report model ─────────────────────────────────────────────────────────────

/// How a package relates to the trusted baseline. Ordering of the variants is
/// meaningless; use [`ChangeKind::rank`] for worst-first sorting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Contents changed but the manifest version did NOT — the worm-injection
    /// / republish-over signature. A legitimate package almost never mutates
    /// bytes without bumping its version. Highest signal.
    ChangedSameVersion,
    /// Identity not present in the baseline: newly installed, unreviewed.
    New,
    /// Version bumped and contents changed — an expected update, worth a
    /// glance before trusting.
    Updated,
    /// Identity and fingerprint match the baseline: known and byte-identical.
    /// Suppressed from the alert list regardless of the raw AV verdict.
    Unchanged,
    /// No baseline was available for comparison (raw scan mode).
    Uncompared,
}

impl ChangeKind {
    /// Worst-first sort rank (higher is worse).
    #[must_use]
    fn rank(self) -> u8 {
        match self {
            Self::ChangedSameVersion => 3,
            Self::New => 2,
            Self::Updated => 1,
            Self::Unchanged | Self::Uncompared => 0,
        }
    }

    /// Short human label shared by the CLI and both UIs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ChangedSameVersion => "changed (no version bump)",
            Self::New => "new",
            Self::Updated => "updated",
            Self::Unchanged => "unchanged",
            Self::Uncompared => "not compared",
        }
    }

    /// One-sentence explanation shown next to a surfaced package. Shared copy
    /// so the CLI and both UIs say exactly the same thing.
    #[must_use]
    pub fn notice(self) -> &'static str {
        match self {
            Self::ChangedSameVersion => {
                "Contents changed since your baseline WITHOUT a version bump; a \
                 legitimate package almost never mutates without a new version. \
                 Verify it with its package manager and reinstall if unexpected."
            }
            Self::New => {
                "Not in your trusted baseline yet. Review it, then mark it \
                 reviewed to trust this exact content."
            }
            Self::Updated => {
                "Version changed since your baseline; expected after an \
                 upgrade. Glance over it, then mark it reviewed."
            }
            Self::Unchanged => "Byte-identical to your reviewed baseline.",
            Self::Uncompared => "No baseline was available for comparison.",
        }
    }
}

/// Shared display label for a change kind (free-function form, matching
/// [`verdict_label`]/[`severity_label`]).
#[must_use]
pub fn change_kind_label(kind: ChangeKind) -> &'static str {
    kind.label()
}

// ── Assessment policy (corroboration gates every alert) ─────────────────────

/// How a surfaced package is PRESENTED and counted. The raw AV `verdict` and
/// `score` stay in the report for transparency, but every display path,
/// count, and exit code derives from this assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "verdict")]
pub enum Assessment {
    /// A corroborated threat, or a same-version tamper: presented with the
    /// raw verdict, counted in the suspicious/malicious tallies, and driving
    /// the exit code.
    Alert(Verdict),
    /// Surfaced for awareness only ("updated — capabilities noted"): neutral
    /// presentation, never counted as a threat, never affects the exit code.
    /// The raw verdict remains visible only as muted secondary detail (see
    /// [`PackageReport::heuristic_note`]), never as the row's badge.
    Notice,
}

impl Assessment {
    /// `true` for the alert (red/amber) presentation.
    #[must_use]
    pub fn is_alert(self) -> bool {
        matches!(self, Self::Alert(_))
    }

    /// Shared badge label: the verdict for alerts, `"notice"` otherwise.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Alert(verdict) => verdict_label(verdict),
            Self::Notice => "notice",
        }
    }
}

/// Threat categories that can corroborate a verdict: the classes where a
/// Critical/High-confidence finding in a package's OWN code indicates an
/// actual attack rather than a generic capability.
const STRONG_CATEGORIES: [ThreatCategory; 8] = [
    ThreatCategory::KnownMalware,
    ThreatCategory::SupplyChain,
    ThreatCategory::InstallScript,
    ThreatCategory::Exfiltration,
    ThreatCategory::CredentialAccess,
    ThreatCategory::CryptoStealer,
    ThreatCategory::Typosquatting,
    ThreatCategory::DependencyConfusion,
];

/// Path segments that mark a benign evidence context inside a package.
/// `.github`/`.circleci` are dependency CI workflows; `man` is roff
/// documentation (npm ships man pages that describe token handling verbatim).
const BENIGN_CONTEXT_SEGMENTS: [&str; 12] = [
    ".github",
    ".circleci",
    "test",
    "tests",
    "__tests__",
    "spec",
    "fixture",
    "fixtures",
    "example",
    "examples",
    "docs",
    "man",
];

/// `true` when a finding's evidence file lives in a benign context within the
/// package: dependency CI workflows (any `.github/`/`.circleci/` segment,
/// which covers the `.yml`/`.yaml` workflows under them), test/fixture/
/// example/docs/man trees (case-insensitive path segments), Markdown
/// documentation, or non-executable build artifacts (`.d.ts` type
/// declarations, `.map` source maps). Real packages ship their upstream
/// repo's CI, test suites, docs, and build metadata verbatim, and those files
/// "read tokens" and "publish to npm" by design (or merely quote code that
/// does) — evidence there never counts toward corroboration and is
/// deprioritized when picking `top_findings`.
#[must_use]
pub fn is_benign_context(path: &str) -> bool {
    let as_path = Path::new(path);
    if as_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("map"))
    {
        return true;
    }
    // TypeScript declaration files contain type text, never executable code
    // (`.d.ts` is a dotted suffix, not a Path::extension).
    if as_path.file_name().is_some_and(|name| {
        name.to_string_lossy()
            .to_ascii_lowercase()
            .ends_with(".d.ts")
    }) {
        return true;
    }
    as_path.components().any(|component| {
        let std::path::Component::Normal(name) = component else {
            return false;
        };
        let name = name.to_string_lossy();
        BENIGN_CONTEXT_SEGMENTS
            .iter()
            .any(|segment| name.eq_ignore_ascii_case(segment))
    })
}

/// A "strong" finding: Critical severity at High confidence, in one of the
/// corroborating categories, with its evidence OUTSIDE any benign context.
fn is_strong_finding(finding: &Finding) -> bool {
    matches!(finding.severity, Severity::Critical)
        && matches!(finding.confidence, Confidence::High)
        && STRONG_CATEGORIES.contains(&finding.category)
        && !finding
            .location
            .as_ref()
            .is_some_and(|location| is_benign_context(&location.path))
}

/// Package manifest files: strong evidence located in (or inline in) the
/// manifest itself is install/lifecycle context — the manifest declares what
/// runs at install time.
const MANIFEST_FILES: [&str; 5] = [
    "package.json",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "METADATA",
];

/// npm lifecycle hooks that execute during install/publish. A script file
/// referenced by one of these is install/lifecycle context.
const NPM_LIFECYCLE_HOOKS: [&str; 6] = [
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
];

/// Command tokens that are interpreters/runners, never the payload file.
const LIFECYCLE_RUNNERS: [&str; 8] = [
    "node", "sh", "bash", "zsh", "python", "python3", "npm", "npx",
];

/// Resolve the package-relative paths of files executed by the package's npm
/// lifecycle hooks: parse `package.json` `scripts.{preinstall, install,
/// postinstall, prepare, prepublish, prepublishOnly}` and keep every command
/// token that names an EXISTING file inside the package (e.g. `"postinstall":
/// "node bundle.js"` yields `bundle.js`). Read-only filesystem inspection;
/// a missing or unparsable manifest yields the empty set.
#[must_use]
pub fn lifecycle_script_paths(package_dir: &Path) -> HashSet<String> {
    let mut paths = HashSet::new();
    let Ok(bytes) = std::fs::read(package_dir.join("package.json")) else {
        return paths;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return paths;
    };
    let Some(scripts) = value.get("scripts").and_then(serde_json::Value::as_object) else {
        return paths;
    };
    for hook in NPM_LIFECYCLE_HOOKS {
        let Some(command) = scripts.get(hook).and_then(serde_json::Value::as_str) else {
            continue;
        };
        for token in command.split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|')) {
            let token = token.trim().trim_start_matches("./");
            if token.is_empty()
                || token.starts_with('-')
                || LIFECYCLE_RUNNERS.contains(&token)
                || token.contains("..")
            {
                continue;
            }
            if package_dir.join(token).is_file() {
                paths.insert(token.replace('\\', "/"));
            }
        }
    }
    paths
}

/// `true` when an evidence path is INSTALL/LIFECYCLE context: the package
/// manifest itself, or a script referenced by a lifecycle hook (see
/// [`lifecycle_script_paths`]). Plain runtime bundles (`dist/`, `out/`,
/// `build/`, minified payloads not referenced by a hook) do NOT qualify —
/// they run when the user runs the tool, not at install time.
#[must_use]
pub fn is_install_context<S: std::hash::BuildHasher>(
    path: &str,
    lifecycle_scripts: &HashSet<String, S>,
) -> bool {
    let normalized = path.trim_start_matches("./");
    MANIFEST_FILES.contains(&normalized) || lifecycle_scripts.contains(normalized)
}

/// Whether the FULL finding list corroborates a raw AV verdict:
///
/// - any strong [`ThreatCategory::KnownMalware`] finding (a hash/signature
///   hit is real wherever it is), OR
/// - strong findings spanning at least two DISTINCT corroborating categories
///   AND at least one strong finding anchored in an install/lifecycle
///   context (see [`is_install_context`]).
///
/// A single capability hit — an npm-style tool reading `.npmrc`, an
/// extension touching the clipboard — is exactly the legitimate-tool pattern
/// and never corroborates. Neither does a multi-category match confined to
/// runtime bundles: a worm's distinguishing act is running at install time,
/// and a minified `dist/` bundle tripping several heuristics at once is the
/// legitimate-extension pattern, not the worm pattern.
#[must_use]
pub fn verdict_corroborated<S: std::hash::BuildHasher>(
    findings: &[Finding],
    lifecycle_scripts: &HashSet<String, S>,
) -> bool {
    let mut categories: HashSet<ThreatCategory> = HashSet::new();
    let mut install_anchor = false;
    for finding in findings {
        if !is_strong_finding(finding) {
            continue;
        }
        if matches!(finding.category, ThreatCategory::KnownMalware) {
            return true;
        }
        categories.insert(finding.category);
        install_anchor = install_anchor
            || finding
                .location
                .as_ref()
                .is_some_and(|location| is_install_context(&location.path, lifecycle_scripts));
    }
    categories.len() >= 2 && install_anchor
}

/// The presentation policy, pure so it is directly testable.
///
/// INVARIANT: an [`Assessment::Alert`] — the only red/amber presentation —
/// can come ONLY from (a) a [`ChangeKind::ChangedSameVersion`] tamper, or
/// (b) a corroborated non-clean verdict. Every other combination — including
/// a raw "malicious" heuristic verdict on a new or freshly updated package —
/// is a neutral [`Assessment::Notice`].
#[must_use]
pub fn assess(change: ChangeKind, verdict: AvVerdict, corroborated: bool) -> Assessment {
    match change {
        // The worm-injection signature is an unconditional alert, whatever
        // the AV verdict says (a tampered package can look "clean").
        ChangeKind::ChangedSameVersion => Assessment::Alert(verdict),
        // Known baseline entries are trusted; --all rows stay neutral.
        ChangeKind::Unchanged => Assessment::Notice,
        ChangeKind::New | ChangeKind::Updated | ChangeKind::Uncompared => {
            if corroborated && !matches!(verdict, AvVerdict::Clean) {
                Assessment::Alert(verdict)
            } else {
                Assessment::Notice
            }
        }
    }
}

/// One piece of evidence retained in the report (a trimmed
/// [`cleanton_antivirus::Finding`] projection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: ThreatCategory,
    pub title: String,
    pub description: String,
    /// Package-relative path of the file the finding was located in.
    pub file: Option<String>,
    /// Short sanitized snippet of the matched content.
    pub evidence: Option<String>,
}

/// The scan outcome for one flagged package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageReport {
    /// Package name parsed from its manifest (falls back to the directory name).
    pub name: String,
    /// Version parsed from the manifest, when available.
    pub version: Option<String>,
    /// On-disk location of the package (what the user reviews manually).
    pub path: PathBuf,
    pub source: SecurityTargetKind,
    pub verdict: AvVerdict,
    /// How this package relates to the trusted baseline.
    pub change: ChangeKind,
    /// Presentation assessment derived from the change kind + corroboration
    /// (see [`assess`]). All display paths, counts, and exit codes use this;
    /// the raw `verdict`/`score` stay for transparency.
    pub assessment: Assessment,
    /// Whether the FULL finding list corroborates the raw verdict (see
    /// [`verdict_corroborated`]).
    pub corroborated: bool,
    /// Content fingerprint of the package at scan time (see
    /// [`crate::security_baseline::fingerprint_package`]). Empty when the
    /// fingerprint could not be computed — such a package is always surfaced,
    /// never silently trusted.
    pub fingerprint: String,
    /// Aggregate risk score 0..=100.
    pub score: u32,
    /// Worst findings, sorted severity-then-confidence descending, capped at
    /// [`TOP_FINDINGS_PER_PACKAGE`].
    pub top_findings: Vec<SecurityFinding>,
    /// Total findings the engines emitted (may exceed `top_findings.len()`).
    pub finding_count: usize,
}

impl PackageReport {
    /// `name version` (or just the name when the version is unknown). Shared
    /// display copy for the CLI table and both UIs.
    #[must_use]
    pub fn display_name(&self) -> String {
        match &self.version {
            Some(version) => format!("{} {}", self.name, version),
            None => self.name.clone(),
        }
    }

    /// One-line headline. Alerts lead with the verdict and score; notices
    /// lead with the neutral "capabilities noted" copy — the raw verdict is
    /// available separately via [`Self::heuristic_note`].
    #[must_use]
    pub fn headline(&self) -> String {
        let top = self
            .top_findings
            .first()
            .map_or("no detail", |finding| finding.title.as_str());
        match self.assessment {
            Assessment::Alert(verdict) => {
                format!("{} (score {}): {}", verdict_label(verdict), self.score, top)
            }
            Assessment::Notice if self.finding_count == 0 => {
                format!("{}, no static findings", self.change.label())
            }
            Assessment::Notice => {
                format!("{}, capabilities noted: {}", self.change.label(), top)
            }
        }
    }

    /// `true` for the alert (red/amber) presentation.
    #[must_use]
    pub fn is_alert(&self) -> bool {
        self.assessment.is_alert()
    }

    /// Shared badge label: the verdict for alerts, `"notice"` otherwise.
    #[must_use]
    pub fn assessment_label(&self) -> &'static str {
        self.assessment.label()
    }

    /// Muted secondary detail for notice rows whose RAW verdict was not
    /// clean: keeps the heuristic outcome visible ("heuristics: malicious
    /// (score 95, uncorroborated)") without letting it drive the badge.
    /// `None` for alerts and for clean-verdict notices.
    #[must_use]
    pub fn heuristic_note(&self) -> Option<String> {
        if self.assessment.is_alert() || matches!(self.verdict, AvVerdict::Clean) {
            return None;
        }
        Some(format!(
            "heuristics: {} (score {}, uncorroborated)",
            verdict_label(self.verdict),
            self.score
        ))
    }

    /// Human-readable lines for the retained findings, identical in both UIs:
    /// one `severity · title — description` line per finding, followed by an
    /// indented file/evidence line when present.
    #[must_use]
    pub fn finding_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for finding in &self.top_findings {
            lines.push(format!(
                "[{}] {}: {}",
                severity_label(finding.severity),
                finding.title,
                finding.description
            ));
            let mut detail = String::new();
            if let Some(file) = &finding.file {
                detail.push_str(file);
            }
            if let Some(evidence) = &finding.evidence {
                if !detail.is_empty() {
                    detail.push_str(": ");
                }
                detail.push_str(evidence);
            }
            if !detail.is_empty() {
                lines.push(format!("    {detail}"));
            }
        }
        lines
    }

    /// The worst severity among the retained findings.
    #[must_use]
    pub fn worst_severity(&self) -> Option<Severity> {
        self.top_findings.iter().map(|f| f.severity).max()
    }

    /// Shared label for this package's baseline change kind.
    #[must_use]
    pub fn change_label(&self) -> &'static str {
        self.change.label()
    }

    /// `true` for the same-version-tamper case (the highest-signal alert).
    #[must_use]
    pub fn is_tampered(&self) -> bool {
        matches!(self.change, ChangeKind::ChangedSameVersion)
    }

    /// A critical alert: a same-version tamper, or a CORROBORATED malicious
    /// assessment. Uncorroborated raw verdicts (notices) are never critical.
    #[must_use]
    pub fn is_critical_alert(&self) -> bool {
        self.is_tampered() || matches!(self.assessment, Assessment::Alert(AvVerdict::Malicious))
    }

    /// The editor-extension id (`publisher.ext`) for an extension whose
    /// identity is the versioned directory name (`publisher.ext-1.2.3`); the
    /// plain name otherwise. Used to build `code --uninstall-extension` hints.
    #[must_use]
    fn extension_id(&self) -> String {
        if let Some(version) = &self.version
            && let Some(stripped) = self.name.strip_suffix(&format!("-{version}"))
        {
            return stripped.to_owned();
        }
        self.name.clone()
    }

    /// A short verb classifying the recommended response, shared by every
    /// surface (badge/heading): `"Investigate now"` for alerts, `"Verify
    /// then trust"` for notices.
    #[must_use]
    pub fn action_label(&self) -> &'static str {
        if self.is_alert() {
            "Investigate now"
        } else {
            "Verify then trust"
        }
    }

    /// A copy-pasteable command the USER can run in their own shell to remove
    /// (alerts) or reinstall from a trusted source (tampers) this package with
    /// its package manager. ADVISORY ONLY — Cleanton never runs it. `None`
    /// when no manager mapping applies. The identifier is single-quoted so
    /// scoped/dotted names stay one shell token.
    #[must_use]
    pub fn suggested_command(&self) -> Option<String> {
        let reinstall = self.is_tampered();
        let cmd = match self.source {
            SecurityTargetKind::NodeGlobal => {
                let name = shell_single_quote(&self.name);
                if reinstall {
                    format!(
                        "npm install -g {name}@{}",
                        version_or_latest(self.version.as_deref())
                    )
                } else {
                    format!("npm uninstall -g {name}")
                }
            }
            SecurityTargetKind::NodeProject => {
                let name = shell_single_quote(&self.name);
                if reinstall {
                    format!(
                        "npm install {name}@{}",
                        version_or_latest(self.version.as_deref())
                    )
                } else {
                    format!("npm uninstall {name}")
                }
            }
            SecurityTargetKind::PythonSitePackages => {
                let name = shell_single_quote(&self.name);
                if reinstall {
                    format!("pip install --force-reinstall {name}")
                } else {
                    format!("pip uninstall {name}")
                }
            }
            SecurityTargetKind::EditorExtensions => {
                let editor = if self.path.to_string_lossy().contains(".cursor") {
                    "cursor"
                } else {
                    "code"
                };
                let id = shell_single_quote(&self.extension_id());
                if reinstall {
                    format!("{editor} --install-extension {id} --force")
                } else {
                    format!("{editor} --uninstall-extension {id}")
                }
            }
        };
        Some(cmd)
    }

    /// The package-relative evidence file to inspect first: the highest
    /// install/lifecycle-anchored strong finding if any (that is what makes a
    /// worm a worm), else the worst finding's file. `None` when no finding
    /// carries a location.
    #[must_use]
    fn primary_evidence_file(&self) -> Option<&str> {
        self.top_findings
            .iter()
            .find(|finding| {
                matches!(finding.severity, Severity::Critical)
                    && finding
                        .file
                        .as_deref()
                        .is_some_and(|file| !is_benign_context(file))
            })
            .or_else(|| self.top_findings.first())
            .and_then(|finding| finding.file.as_deref())
    }

    /// Concrete, review-only NEXT STEPS for this package, shared verbatim by
    /// the CLI and both UIs. ADVISORY: every step is something the USER does —
    /// Cleanton never removes, reinstalls, or runs anything here.
    ///
    /// - Tamper: do not trust; inspect the changed file; reinstall from a
    ///   trusted source to restore known-good bytes.
    /// - Alert (corroborated): inspect the flagged install/lifecycle evidence,
    ///   then remove if unexpected.
    /// - Notice: expected for updated dev tooling; recognize the change and
    ///   mark it reviewed to trust it (no destructive action suggested).
    #[must_use]
    pub fn action_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.is_tampered() {
            lines.push(
                "Do NOT trust: contents changed since your baseline without a version bump."
                    .to_owned(),
            );
            if let Some(file) = self.primary_evidence_file() {
                lines.push(format!(
                    "Inspect what changed: {}",
                    join_rel(&self.path, file)
                ));
            }
            lines.push("Reinstall from a trusted source to restore known-good bytes:".to_owned());
            if let Some(cmd) = self.suggested_command() {
                lines.push(format!("$ {cmd}"));
            }
        } else if self.is_alert() {
            lines.push(
                "Corroborated threat indicators: review the flagged install/lifecycle code."
                    .to_owned(),
            );
            if let Some(file) = self.primary_evidence_file() {
                lines.push(format!("Inspect first: {}", join_rel(&self.path, file)));
            }
            lines
                .push("If you did not expect this, remove it with its package manager:".to_owned());
            if let Some(cmd) = self.suggested_command() {
                lines.push(format!("$ {cmd}"));
            }
        } else {
            lines.push(
                "No corroborated threat; uncorroborated heuristics are normal for dev tooling."
                    .to_owned(),
            );
            lines.push(
                "If you recognize this change, mark it reviewed to trust it (nothing is removed)."
                    .to_owned(),
            );
        }
        lines
    }
}

/// Single-quote a shell token, escaping embedded single quotes, so a
/// scoped/dotted package name stays one argument in a copy-pasted command.
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// A concrete version pin, or `latest` when the version is unknown.
fn version_or_latest(version: Option<&str>) -> String {
    version.unwrap_or("latest").to_owned()
}

/// Display a package-relative evidence file under the package's on-disk path.
fn join_rel(base: &Path, rel: &str) -> String {
    base.join(rel).display().to_string()
}

/// Normalize typographic punctuation (em/en dashes, smart quotes, arrows,
/// bullets, ellipses) to plain ASCII. Applied at the boundary where finding
/// text sourced from the vendored antivirus crate is copied into the report,
/// so every surface (CLI table and both UIs) shows clean copy without
/// editing the vendored crate itself.
fn sanitize_display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\u{2014}' | '\u{2013}' | '\u{2022}' => out.push('-'),
            '\u{2018}' | '\u{2019}' => out.push('\''),
            '\u{201C}' | '\u{201D}' => out.push('"'),
            '\u{2192}' | '\u{21D2}' => out.push_str("->"),
            '\u{2190}' => out.push_str("<-"),
            '\u{2026}' => out.push_str("..."),
            _ => out.push(ch),
        }
    }
    out
}

/// Finding counts bucketed by severity (across all flagged packages).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub info: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

impl SeverityCounts {
    fn record(&mut self, severity: Severity) {
        match severity {
            Severity::Info => self.info = self.info.saturating_add(1),
            Severity::Low => self.low = self.low.saturating_add(1),
            Severity::Medium => self.medium = self.medium.saturating_add(1),
            Severity::High => self.high = self.high.saturating_add(1),
            Severity::Critical => self.critical = self.critical.saturating_add(1),
        }
    }
}

/// Aggregated result of one security scan. Purely informational: nothing in
/// this report is ever executed, removed, or modified by Cleanton.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    /// The package-tree roots that were scanned (existing locations only).
    pub targets: Vec<SecurityTarget>,
    /// Distinct packages scanned (identical paths are scanned once).
    pub packages_scanned: usize,
    pub duration: Duration,
    /// Surfaced packages, sorted worst-first. With a baseline this contains
    /// ONLY new/changed/updated packages (plus, on request, AV-flagged
    /// unchanged ones); without a baseline it is the raw AV-flagged list.
    pub flagged: Vec<PackageReport>,
    /// Packages with a clean AV verdict (raw scanner tally, baseline-blind).
    pub clean_packages: usize,
    /// Suspicious/malicious ASSESSMENTS among the surfaced (non-unchanged)
    /// packages — uncorroborated raw verdicts (notices) and suppressed
    /// baseline entries do not count here.
    pub suspicious_packages: usize,
    pub malicious_packages: usize,
    /// Surfaced packages presented as alerts (corroborated threats and
    /// same-version tampers).
    pub alert_packages: usize,
    /// Surfaced packages presented as neutral notices ("capabilities noted"):
    /// never counted as threats, never affect the exit code.
    pub notice_packages: usize,
    /// Packages recorded silently at baseline establishment whose RAW verdict
    /// was not clean but was NOT corroborated (the muted "capabilities noted
    /// in M packages" tally). Zero outside establishment runs.
    pub baseline_capability_notes: usize,
    /// Finding counts by severity across the listed packages.
    pub severity_counts: SeverityCounts,
    /// Packages that could not be scanned (path + reason). Non-fatal.
    pub errors: Vec<String>,
    /// True when the scan was cancelled before every package was inspected.
    pub incomplete: bool,
    /// True when the scan was diffed against (or established) a baseline.
    pub baseline_used: bool,
    /// True when THIS run recorded the baseline (first run or forced
    /// re-establish): the installed set is now the trusted reference.
    pub baseline_established: bool,
    /// Known packages, byte-identical to the baseline, suppressed from the
    /// alert list. This is the "N packages known/unchanged" tally.
    pub known_unchanged: usize,
    /// Surfaced-package counts by change kind.
    pub new_packages: usize,
    pub updated_packages: usize,
    pub changed_same_version: usize,
    /// Surfaced packages that are critical alerts (same-version tamper or a
    /// corroborated malicious assessment).
    pub critical_packages: usize,
}

impl SecurityReport {
    /// An empty report over no targets (used when discovery finds nothing).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            targets: Vec::new(),
            packages_scanned: 0,
            duration: Duration::ZERO,
            flagged: Vec::new(),
            clean_packages: 0,
            suspicious_packages: 0,
            malicious_packages: 0,
            alert_packages: 0,
            notice_packages: 0,
            baseline_capability_notes: 0,
            severity_counts: SeverityCounts::default(),
            errors: Vec::new(),
            incomplete: false,
            baseline_used: false,
            baseline_established: false,
            known_unchanged: 0,
            new_packages: 0,
            updated_packages: 0,
            changed_same_version: 0,
            critical_packages: 0,
        }
    }

    /// The worst ASSESSED verdict across the surfaced packages (derived from
    /// the alert counts, so uncorroborated notices never raise it).
    #[must_use]
    pub fn worst_verdict(&self) -> AvVerdict {
        if self.malicious_packages > 0 {
            AvVerdict::Malicious
        } else if self.suspicious_packages > 0 {
            AvVerdict::Suspicious
        } else {
            AvVerdict::Clean
        }
    }

    /// Number of surfaced changes (new + updated + same-version tampered).
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.new_packages
            .saturating_add(self.updated_packages)
            .saturating_add(self.changed_same_version)
    }

    /// Shared status copy for the CLI and both UIs, so every front end reports
    /// identical results (mirrors `SnapshotCleanupResult::status_message`).
    #[must_use]
    pub fn summary_message(&self) -> String {
        let scope = format!(
            "{} package(s) across {} location(s) in {:.1}s",
            self.packages_scanned,
            self.targets.len(),
            self.duration.as_secs_f64()
        );
        let suffix = if self.incomplete {
            " Scan was cancelled before completing; results are partial."
        } else {
            ""
        };
        if !self.baseline_used {
            return self.raw_summary_message(&scope, suffix);
        }
        if self.baseline_established {
            let callout = if self.alert_packages > 0 {
                format!(
                    " {} package(s) show corroborated threat indicators; \
                     review them below before trusting.",
                    self.alert_packages
                )
            } else {
                String::new()
            };
            let notes = if self.baseline_capability_notes > 0 {
                format!(
                    " Capabilities noted in {} package(s) (uncorroborated heuristics, \
                     normal for dev tooling; details in the JSON report or with --all).",
                    self.baseline_capability_notes
                )
            } else {
                String::new()
            };
            return format!(
                "Baseline established: {} package(s) recorded as trusted; scanned {scope}. \
                 Future scans flag only new or changed packages.{suffix}{callout}{notes}",
                self.packages_scanned
            );
        }
        if self.change_count() == 0 {
            return format!(
                "No changes since last baseline: {} known package(s) unchanged; \
                 scanned {scope}.{suffix}",
                self.known_unchanged
            );
        }
        if self.alert_packages == 0 {
            return format!(
                "Baseline: {} known, {} new, {} updated (no corroborated threats, \
                 capabilities noted only); scanned {scope}. \
                 Cleanton never removes packages automatically.{suffix}",
                self.known_unchanged, self.new_packages, self.updated_packages
            );
        }
        format!(
            "Baseline: {} known, {} new, {} updated, {} changed without a version bump \
             ({} critical, {} corroborated alert(s)); scanned {scope}. Review the flagged \
             packages below; Cleanton never removes packages automatically.{suffix}",
            self.known_unchanged,
            self.new_packages,
            self.updated_packages,
            self.changed_same_version,
            self.critical_packages,
            self.alert_packages
        )
    }

    /// The pre-baseline wording, kept for raw (`baseline_used == false`) runs.
    /// The malicious/suspicious tallies are ASSESSED counts — uncorroborated
    /// heuristic verdicts appear only in the notice clause.
    fn raw_summary_message(&self, scope: &str, suffix: &str) -> String {
        let notes = if self.notice_packages > 0 {
            format!(
                " Capabilities noted in {} package(s) (uncorroborated heuristics, \
                 normal for dev tooling).",
                self.notice_packages
            )
        } else {
            String::new()
        };
        match (self.malicious_packages, self.suspicious_packages) {
            (0, 0) if self.notice_packages > 0 => {
                format!("No corroborated threats; scanned {scope}.{suffix}{notes}")
            }
            (0, 0) => format!("No threats found; scanned {scope}.{suffix}"),
            (0, suspicious) => format!(
                "{suspicious} suspicious package(s) found; scanned {scope}. \
                 Review each package below; Cleanton never removes packages \
                 automatically.{suffix}{notes}"
            ),
            (malicious, 0) => format!(
                "{malicious} malicious package(s) found; scanned {scope}. \
                 Review each package below; Cleanton never removes packages \
                 automatically.{suffix}{notes}"
            ),
            (malicious, suspicious) => format!(
                "{malicious} malicious and {suspicious} suspicious package(s) found; \
                 scanned {scope}. Review each package below; Cleanton never removes \
                 packages automatically.{suffix}{notes}"
            ),
        }
    }

    /// One-line headline for the summary banner, shared by both UIs.
    #[must_use]
    pub fn banner_headline(&self) -> String {
        if self.baseline_established {
            if self.alert_packages > 0 {
                return format!(
                    "Baseline established: {} corroborated threat(s) to review",
                    self.alert_packages
                );
            }
            return format!(
                "Baseline established: {} package(s) trusted",
                self.packages_scanned
            );
        }
        if !self.baseline_used {
            return match self.worst_verdict() {
                AvVerdict::Clean if self.notice_packages > 0 => {
                    "No corroborated threats".to_owned()
                }
                AvVerdict::Clean => "No threats found".to_owned(),
                AvVerdict::Suspicious => "Suspicious packages found".to_owned(),
                AvVerdict::Malicious => "Malicious packages found".to_owned(),
            };
        }
        if self.change_count() == 0 {
            return "No changes since last baseline".to_owned();
        }
        if self.changed_same_version > 0 {
            return format!(
                "{} package(s) changed WITHOUT a version bump",
                self.changed_same_version
            );
        }
        if self.alert_packages == 0 {
            if self.new_packages == 0 {
                return format!(
                    "{} package(s) updated, no corroborated threats",
                    self.updated_packages
                );
            }
            return format!(
                "{} package change(s), no corroborated threats",
                self.change_count()
            );
        }
        format!(
            "{} package change(s) since last baseline",
            self.change_count()
        )
    }

    /// Banner tone shared by both UIs: `"danger"`, `"warning"`, `"info"`, or
    /// `"success"`. Drives the summary banner color so the Slint app and the
    /// TUI always agree on how alarming a result looks. Notices (updates and
    /// new packages with no corroborated threat) are the neutral `"info"`
    /// tone — never amber or red.
    #[must_use]
    pub fn banner_tone(&self) -> &'static str {
        if self.changed_same_version > 0 || self.malicious_packages > 0 {
            "danger"
        } else if self.suspicious_packages > 0 {
            "warning"
        } else if self.notice_packages > 0 {
            "info"
        } else {
            "success"
        }
    }

    /// CLI exit code, kept distinct from the plan/clean codes (2 = empty
    /// plan, 4 = incomplete scan):
    ///
    /// - `0` — no ALERTS: no corroborated threats and no tampers (a baseline
    ///   just established with only uncorroborated heuristics also exits 0).
    /// - `3` — a new/updated package has a CORROBORATED suspicious verdict.
    /// - `5` — a new/updated package has a CORROBORATED malicious verdict, OR
    ///   any package changed without a version bump (same-version tamper).
    ///
    /// Known baseline packages and uncorroborated notices never affect the
    /// exit code, whatever their raw AV verdict.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.baseline_used && self.changed_same_version > 0 {
            return 5;
        }
        match self.worst_verdict() {
            AvVerdict::Clean => 0,
            AvVerdict::Suspicious => 3,
            AvVerdict::Malicious => 5,
        }
    }

    /// Recompute all surfaced-package counts from `self.flagged`. Unchanged
    /// rows (shown only in "--all" mode) are excluded from the alert counts.
    fn recount_flagged(&mut self) {
        let surfaced = |pkg: &&PackageReport| !matches!(pkg.change, ChangeKind::Unchanged);
        self.new_packages = self
            .flagged
            .iter()
            .filter(|pkg| matches!(pkg.change, ChangeKind::New))
            .count();
        self.updated_packages = self
            .flagged
            .iter()
            .filter(|pkg| matches!(pkg.change, ChangeKind::Updated))
            .count();
        self.changed_same_version = self
            .flagged
            .iter()
            .filter(|pkg| matches!(pkg.change, ChangeKind::ChangedSameVersion))
            .count();
        // Threat tallies derive from ASSESSMENTS, not raw verdicts:
        // uncorroborated notices never count.
        self.suspicious_packages = self
            .flagged
            .iter()
            .filter(surfaced)
            .filter(|pkg| matches!(pkg.assessment, Assessment::Alert(AvVerdict::Suspicious)))
            .count();
        self.malicious_packages = self
            .flagged
            .iter()
            .filter(surfaced)
            .filter(|pkg| matches!(pkg.assessment, Assessment::Alert(AvVerdict::Malicious)))
            .count();
        self.alert_packages = self
            .flagged
            .iter()
            .filter(surfaced)
            .filter(|pkg| pkg.assessment.is_alert())
            .count();
        self.notice_packages = self
            .flagged
            .iter()
            .filter(surfaced)
            .filter(|pkg| !pkg.assessment.is_alert())
            .count();
        self.critical_packages = self
            .flagged
            .iter()
            .filter(|pkg| pkg.is_critical_alert())
            .count();
        let mut severity_counts = SeverityCounts::default();
        for package in &self.flagged {
            for finding in &package.top_findings {
                severity_counts.record(finding.severity);
            }
        }
        self.severity_counts = severity_counts;
    }

    /// Sort the surfaced list worst-first: critical alerts (same-version
    /// tamper / corroborated malicious) on top, then every other alert, then
    /// notices — within each band by change kind, verdict, score, name.
    fn sort_flagged(&mut self) {
        self.flagged.sort_by(|a, b| {
            b.is_critical_alert()
                .cmp(&a.is_critical_alert())
                .then_with(|| b.assessment.is_alert().cmp(&a.assessment.is_alert()))
                .then_with(|| b.change.rank().cmp(&a.change.rank()))
                .then_with(|| verdict_rank(b.verdict).cmp(&verdict_rank(a.verdict)))
                .then_with(|| b.score.cmp(&a.score))
                .then_with(|| a.name.cmp(&b.name))
        });
    }

    /// Mark the flagged package at `index` as reviewed/trusted: records its
    /// CURRENT fingerprint + version in the baseline file (metadata only —
    /// the package itself is never touched), removes it from the surfaced
    /// list, and refreshes the counts. Returns the package's display name.
    ///
    /// # Errors
    ///
    /// Returns an error when `index` is out of range or the baseline file
    /// cannot be written.
    pub fn trust_flagged(&mut self, index: usize, baseline_path: &Path) -> Result<String> {
        let Some(package) = self.flagged.get(index) else {
            return Err(cleanton_common::CleantonError::Config(format!(
                "no flagged package at index {index}"
            )));
        };
        review_packages(baseline_path, std::slice::from_ref(package))?;
        // Bounds re-checked by the `get` above; `remove` cannot panic here.
        let package = self.flagged.remove(index);
        if !matches!(package.change, ChangeKind::Unchanged) {
            self.known_unchanged = self.known_unchanged.saturating_add(1);
        }
        self.recount_flagged();
        Ok(package.display_name())
    }

    /// Mark EVERY surfaced package as reviewed/trusted in one baseline write.
    /// Returns how many packages were recorded.
    ///
    /// # Errors
    ///
    /// Returns an error when the baseline file cannot be written.
    pub fn trust_all_flagged(&mut self, baseline_path: &Path) -> Result<usize> {
        if self.flagged.is_empty() {
            return Ok(0);
        }
        review_packages(baseline_path, &self.flagged)?;
        let trusted = self.flagged.len();
        let newly_known = self
            .flagged
            .iter()
            .filter(|pkg| !matches!(pkg.change, ChangeKind::Unchanged))
            .count();
        self.known_unchanged = self.known_unchanged.saturating_add(newly_known);
        self.flagged.clear();
        self.recount_flagged();
        Ok(trusted)
    }
}

/// Progress callback payload: packages scanned so far out of the total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityProgress {
    pub scanned: usize,
    pub total: usize,
}

/// Shared display label for a verdict.
#[must_use]
pub fn verdict_label(verdict: AvVerdict) -> &'static str {
    match verdict {
        AvVerdict::Clean => "clean",
        AvVerdict::Suspicious => "suspicious",
        AvVerdict::Malicious => "malicious",
    }
}

/// Shared display label for a severity.
#[must_use]
pub fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn verdict_rank(verdict: AvVerdict) -> u8 {
    match verdict {
        AvVerdict::Malicious => 2,
        AvVerdict::Suspicious => 1,
        AvVerdict::Clean => 0,
    }
}

// ── Target discovery (filesystem only; never spawns a package manager) ──────

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// Push `path` as a target when it exists and is a directory (absent
/// conventions are skipped silently).
fn push_if_dir(targets: &mut Vec<SecurityTarget>, kind: SecurityTargetKind, path: PathBuf) {
    if path.is_dir() {
        targets.push(SecurityTarget { kind, root: path });
    }
}

/// Directories directly under `base` (non-recursive), sorted for determinism.
fn subdirs(base: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// Enumerate the package trees that exist on this machine: npm/yarn/pnpm/bun
/// globals, Python user/pipx/uv site-packages, and VS Code/Cursor extensions.
/// Locations that do not exist are skipped silently. Filesystem inspection
/// only — no `npm`, `pip`, or other process is ever spawned.
#[must_use]
pub fn discover_default_targets() -> Vec<SecurityTarget> {
    let mut targets = Vec::new();

    // Node globals at fixed prefixes (Homebrew and /usr/local installs).
    for prefix in [
        "/opt/homebrew/lib/node_modules",
        "/usr/local/lib/node_modules",
    ] {
        push_if_dir(
            &mut targets,
            SecurityTargetKind::NodeGlobal,
            PathBuf::from(prefix),
        );
    }

    let Some(home) = home_dir() else {
        return targets;
    };

    // Per-user Node global conventions.
    push_if_dir(
        &mut targets,
        SecurityTargetKind::NodeGlobal,
        home.join(".npm-global/lib/node_modules"),
    );
    push_if_dir(
        &mut targets,
        SecurityTargetKind::NodeGlobal,
        home.join(".bun/install/global/node_modules"),
    );
    push_if_dir(
        &mut targets,
        SecurityTargetKind::NodeGlobal,
        home.join(".yarn/global/node_modules"),
    );
    // pnpm keeps versioned global dirs: ~/Library/pnpm/global/<n>/node_modules.
    for version_dir in subdirs(&home.join("Library/pnpm/global")) {
        push_if_dir(
            &mut targets,
            SecurityTargetKind::NodeGlobal,
            version_dir.join("node_modules"),
        );
    }

    // Python user installs: ~/Library/Python/<ver>/lib/python<ver>/site-packages.
    for version_dir in subdirs(&home.join("Library/Python")) {
        for lib_dir in subdirs(&version_dir.join("lib")) {
            push_if_dir(
                &mut targets,
                SecurityTargetKind::PythonSitePackages,
                lib_dir.join("site-packages"),
            );
        }
    }
    // pipx venvs: ~/.local/pipx/venvs/<tool>/lib/<python>/site-packages.
    for venv in subdirs(&home.join(".local/pipx/venvs")) {
        for lib_dir in subdirs(&venv.join("lib")) {
            push_if_dir(
                &mut targets,
                SecurityTargetKind::PythonSitePackages,
                lib_dir.join("site-packages"),
            );
        }
    }
    // uv tools: ~/.local/share/uv/tools/<tool>/lib/<python>/site-packages.
    for tool in subdirs(&home.join(".local/share/uv/tools")) {
        for lib_dir in subdirs(&tool.join("lib")) {
            push_if_dir(
                &mut targets,
                SecurityTargetKind::PythonSitePackages,
                lib_dir.join("site-packages"),
            );
        }
    }

    // Editor extensions (npm-style packages; a real attack vector).
    push_if_dir(
        &mut targets,
        SecurityTargetKind::EditorExtensions,
        home.join(".vscode/extensions"),
    );
    push_if_dir(
        &mut targets,
        SecurityTargetKind::EditorExtensions,
        home.join(".cursor/extensions"),
    );

    // Version-only ecosystems. A gem tree, the Cargo registry cache, and the
    // Go module cache together hold tens of thousands of directories; running
    // the content scanner over all of them would dominate a scan for very
    // little extra signal (their source is public and reviewed). They are
    // matched against the advisory database by version instead, which answers
    // the question that actually matters for them: is this release known-bad?
    for version_dir in subdirs(&home.join(".gem/ruby")) {
        push_if_dir(
            &mut targets,
            SecurityTargetKind::RubyGems,
            version_dir.join("gems"),
        );
    }
    for prefix in ["/opt/homebrew/lib/ruby/gems", "/usr/local/lib/ruby/gems"] {
        for version_dir in subdirs(&PathBuf::from(prefix)) {
            push_if_dir(
                &mut targets,
                SecurityTargetKind::RubyGems,
                version_dir.join("gems"),
            );
        }
    }
    for registry in subdirs(&home.join(".cargo/registry/src")) {
        push_if_dir(&mut targets, SecurityTargetKind::CargoRegistry, registry);
    }
    push_if_dir(
        &mut targets,
        SecurityTargetKind::GoModuleCache,
        home.join("go/pkg/mod"),
    );

    targets
}

/// Locate `node_modules` and virtualenv `site-packages` trees under a
/// user-chosen project root (bounded depth; never descends into a matched
/// tree or `.git`).
#[must_use]
pub fn discover_project_targets(root: &Path) -> Vec<SecurityTarget> {
    let mut targets = Vec::new();
    if !root.is_dir() {
        return targets;
    }
    let walker = walkdir::WalkDir::new(root)
        .max_depth(PROJECT_DISCOVERY_DEPTH)
        .follow_links(false)
        .into_iter();
    let mut it = walker;
    while let Some(entry) = it.next() {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".git" {
            it.skip_current_dir();
            continue;
        }
        if name == "node_modules" {
            targets.push(SecurityTarget {
                kind: SecurityTargetKind::NodeProject,
                root: entry.path().to_path_buf(),
            });
            it.skip_current_dir();
            continue;
        }
        if name == "site-packages" {
            targets.push(SecurityTarget {
                kind: SecurityTargetKind::PythonSitePackages,
                root: entry.path().to_path_buf(),
            });
            it.skip_current_dir();
        }
    }
    targets
}

/// Default targets plus the trees under each provided project root.
#[must_use]
pub fn discover_targets(project_roots: &[PathBuf]) -> Vec<SecurityTarget> {
    let mut targets = discover_default_targets();
    for root in project_roots {
        targets.extend(discover_project_targets(root));
    }
    // Deduplicate identical roots (e.g. overlapping project roots).
    let mut seen: HashSet<PathBuf> = HashSet::new();
    targets.retain(|target| seen.insert(target.root.clone()));
    targets
}

// ── Package enumeration ──────────────────────────────────────────────────────

/// One package directory (or single-module file) queued for scanning.
#[derive(Debug, Clone)]
struct PackageCandidate {
    name: String,
    version: Option<String>,
    /// Path shown to the user (the entry inside the target root).
    display_path: PathBuf,
    /// Path handed to the scanner (symlinks resolved, e.g. pnpm globals).
    scan_path: PathBuf,
    source: SecurityTargetKind,
    /// Ecosystem used for advisory (known-vulnerable-version) matching.
    ecosystem: Option<Ecosystem>,
}

/// Parse `name`/`version` from a `package.json` next to `dir`, falling back to
/// the directory name.
fn npm_manifest(dir: &Path, fallback: &str) -> (String, Option<String>) {
    let manifest = dir.join("package.json");
    let Ok(bytes) = std::fs::read(&manifest) else {
        return (fallback.to_owned(), None);
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (fallback.to_owned(), None);
    };
    let name = value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| fallback.to_owned(), std::borrow::ToOwned::to_owned);
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .map(std::borrow::ToOwned::to_owned);
    (name, version)
}

/// Best-effort version for a site-packages dir `name` from a sibling
/// `<name>-<version>.dist-info` directory (PEP 376 normalized comparison).
fn python_dist_info_version(site_packages: &Path, package: &str) -> Option<String> {
    let normalized = package.to_lowercase().replace('-', "_");
    for dir in subdirs(site_packages) {
        let Some(file_name) = dir.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let Some(stem) = file_name.strip_suffix(".dist-info") else {
            continue;
        };
        let Some((dist_name, version)) = stem.rsplit_once('-') else {
            continue;
        };
        if dist_name.to_lowercase().replace('-', "_") == normalized {
            return Some(version.to_owned());
        }
    }
    None
}

/// Enumerate the top-level packages of one `node_modules`-style tree
/// (`@scope` dirs are expanded one level; dot-dirs like `.bin`/`.pnpm` are
/// metadata, not packages). Symlinked entries (pnpm/bun global layouts) are
/// resolved so the real package directory is scanned.
fn enumerate_node_packages(target: &SecurityTarget, out: &mut Vec<PackageCandidate>) {
    let mut entries = subdirs(&target.root);
    // Symlinked package dirs also count; subdirs() already follows the
    // is_dir() metadata (which traverses symlinks).
    entries.retain(|path| {
        path.file_name()
            .is_some_and(|name| !name.to_string_lossy().starts_with('.'))
    });
    for entry in entries {
        let name = entry
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.starts_with('@') {
            for scoped in subdirs(&entry) {
                push_node_package(target, &scoped, out);
            }
        } else {
            push_node_package(target, &entry, out);
        }
    }
}

fn push_node_package(target: &SecurityTarget, dir: &Path, out: &mut Vec<PackageCandidate>) {
    let fallback = dir.file_name().map_or_else(
        || dir.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let (name, version) = npm_manifest(dir, &fallback);
    // Editor extension trees keep MULTIPLE versioned dirs of the same
    // extension side by side (`publisher.ext-1.2.3` next to `-1.3.0`), and
    // the manifest name is the same in each. Identity must be the versioned
    // directory name, or the copies collide on one baseline entry and the
    // winner flip-flops with scan order (phantom "updated" packages).
    let name = if target.kind == SecurityTargetKind::EditorExtensions {
        fallback.clone()
    } else {
        name
    };
    let scan_path = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    out.push(PackageCandidate {
        name,
        version,
        display_path: dir.to_path_buf(),
        scan_path,
        source: target.kind,
        ecosystem: Some(Ecosystem::Npm),
    });
}

/// Enumerate the top-level packages of a Python `site-packages` tree: package
/// directories plus single-module `.py` files. Distribution metadata dirs
/// (`*.dist-info`, `*.egg-info`, `__pycache__`) are consulted for versions but
/// not scanned as packages themselves.
fn enumerate_python_packages(target: &SecurityTarget, out: &mut Vec<PackageCandidate>) {
    let Ok(entries) = std::fs::read_dir(&target.root) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    for path in paths {
        let Some(file_name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        // Case-sensitive on purpose: these are exact installer-written names,
        // and macOS-default-case-insensitive volumes still round-trip them
        // verbatim. Structured as suffix checks (not Path::extension) because
        // `.dist-info`/`.egg-info` are dotted name suffixes, not extensions.
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        let metadata_entry = file_name.starts_with('.')
            || file_name == "__pycache__"
            || file_name.ends_with(".dist-info")
            || file_name.ends_with(".egg-info")
            || file_name.ends_with(".egg-link")
            || file_name.ends_with(".pth");
        if metadata_entry {
            continue;
        }
        let (name, is_package) = if path.is_dir() {
            (file_name.clone(), true)
        } else if let Some(stem) = file_name.strip_suffix(".py") {
            (stem.to_owned(), true)
        } else {
            (String::new(), false)
        };
        if !is_package {
            continue;
        }
        let version = python_dist_info_version(&target.root, &name);
        let scan_path = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        out.push(PackageCandidate {
            name,
            version,
            display_path: path,
            scan_path,
            source: target.kind,
            ecosystem: Some(Ecosystem::PyPI),
        });
    }
}

/// One `field = "value"` lookup in a `.gemspec` (lines look like
/// `s.name = "rack".freeze` or `s.version = "2.2.8"`).
fn gemspec_field(text: &str, field: &str) -> Option<String> {
    let needle = format!(".{field}");
    for line in text.lines() {
        let line = line.trim();
        if !line.contains(needle.as_str()) {
            continue;
        }
        let Some((_, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let Some(quoted) = value.strip_prefix('"') else {
            continue;
        };
        if let Some((inner, _)) = quoted.split_once('"') {
            return Some(inner.to_owned());
        }
    }
    None
}

/// Read `name`/`version` from the gemspec inside an installed gem directory.
fn gem_identity(dir: &Path, fallback: &str) -> (String, Option<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (fallback.to_owned(), None);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "gemspec") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let (Some(name), version) = (gemspec_field(&text, "name"), gemspec_field(&text, "version"))
        {
            return (name, version);
        }
    }
    (fallback.to_owned(), None)
}

/// Read `package.name`/`package.version` from a crate's `Cargo.toml`.
fn cargo_identity(dir: &Path, fallback: &str) -> (String, Option<String>) {
    let Ok(text) = std::fs::read_to_string(dir.join("Cargo.toml")) else {
        return (fallback.to_owned(), None);
    };
    let Ok(value) = toml::from_str::<toml::Value>(&text) else {
        return (fallback.to_owned(), None);
    };
    let Some(package) = value.get("package") else {
        return (fallback.to_owned(), None);
    };
    let name = package
        .get("name")
        .and_then(toml::Value::as_str)
        .unwrap_or(fallback)
        .to_owned();
    let version = package
        .get("version")
        .and_then(toml::Value::as_str)
        .map(str::to_owned);
    (name, version)
}

/// Split a cache entry name into `(name, version)`, e.g. `rack-2.2.8` or
/// `github.com/foo/bar@v1.2.3`.
fn split_versioned_dir_name(name: &str) -> Option<(String, String)> {
    if let Some((package, version)) = name.rsplit_once('@') {
        if !package.is_empty() && !version.is_empty() {
            return Some((package.to_owned(), version.to_owned()));
        }
    }
    // `name-1.2.3`: split at the last `-` that is followed by a digit.
    let indices = name
        .char_indices()
        .filter(|(index, character)| {
            *character == '-'
                && name
                    .get(index.saturating_add(1)..)
                    .and_then(|rest| rest.chars().next())
                    .is_some_and(|next| next.is_ascii_digit())
        })
        .map(|(index, _)| index);
    let split = indices.last()?;
    let package = name.get(..split)?;
    let version = name.get(split.saturating_add(1)..)?;
    Some((package.to_owned(), version.to_owned()))
}

/// Version-only enumeration of installed gems. These are matched against the
/// advisory database and never handed to the content scanner: a gem tree is
/// large, and "is this release known-bad?" is a metadata question.
fn enumerate_ruby_packages(target: &SecurityTarget, out: &mut Vec<PackageCandidate>) {
    for dir in subdirs(&target.root) {
        let fallback = dir.file_name().map_or_else(
            || dir.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        let (name, version) = gem_identity(&dir, &fallback);
        out.push(PackageCandidate {
            name,
            version,
            display_path: dir.clone(),
            scan_path: dir,
            source: target.kind,
            ecosystem: Some(Ecosystem::RubyGems),
        });
    }
}

/// Version-only enumeration of the Cargo registry source cache.
fn enumerate_cargo_packages(target: &SecurityTarget, out: &mut Vec<PackageCandidate>) {
    for dir in subdirs(&target.root) {
        let fallback = dir.file_name().map_or_else(
            || dir.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        let (name, version) = cargo_identity(&dir, &fallback);
        out.push(PackageCandidate {
            name,
            version,
            display_path: dir.clone(),
            scan_path: dir,
            source: target.kind,
            ecosystem: Some(Ecosystem::CratesIo),
        });
    }
}

/// Version-only enumeration of the Go module cache (`module@version` dirs,
/// sometimes nested one level inside a module path).
fn enumerate_go_packages(target: &SecurityTarget, out: &mut Vec<PackageCandidate>) {
    let mut candidates = subdirs(&target.root);
    for dir in &mut candidates {
        if dir.file_name().is_some_and(|name| name == "cache") {
            continue;
        }
        let name = dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.contains('@') {
            push_go_package(dir, out);
            continue;
        }
        // One nesting level: `github.com/foo/bar@v1.2.3`.
        for nested in subdirs(dir) {
            push_go_package(&nested, out);
        }
    }
}

fn push_go_package(dir: &Path, out: &mut Vec<PackageCandidate>) {
    let Some(name) = dir.file_name().map(|name| name.to_string_lossy().into_owned()) else {
        return;
    };
    let Some((package, version)) = split_versioned_dir_name(&name) else {
        return;
    };
    out.push(PackageCandidate {
        name: package,
        version: Some(version),
        display_path: dir.to_path_buf(),
        scan_path: dir.to_path_buf(),
        source: SecurityTargetKind::GoModuleCache,
        ecosystem: Some(Ecosystem::Go),
    });
}

/// All distinct packages across the targets. Identical resolved paths (e.g. a
/// pnpm symlink farm pointing at one store dir) are scanned once.
fn enumerate_packages(targets: &[SecurityTarget]) -> Vec<PackageCandidate> {
    let mut packages = Vec::new();
    for target in targets {
        match target.kind {
            SecurityTargetKind::NodeGlobal
            | SecurityTargetKind::NodeProject
            | SecurityTargetKind::EditorExtensions => {
                enumerate_node_packages(target, &mut packages);
            }
            SecurityTargetKind::PythonSitePackages => {
                enumerate_python_packages(target, &mut packages);
            }
            SecurityTargetKind::RubyGems => enumerate_ruby_packages(target, &mut packages),
            SecurityTargetKind::CargoRegistry => enumerate_cargo_packages(target, &mut packages),
            SecurityTargetKind::GoModuleCache => enumerate_go_packages(target, &mut packages),
        }
    }
    let mut seen: HashSet<PathBuf> = HashSet::new();
    packages.retain(|pkg| seen.insert(pkg.scan_path.clone()));
    packages
}

// ── Scan orchestration ───────────────────────────────────────────────────────

/// The scan configuration used for every per-package run: the library's
/// untrusted-input defaults (bounded memory, zip-bomb guards, no symlink
/// following inside a package).
fn scan_config() -> ScanConfig {
    ScanConfig::default()
}

/// Advisory matches for a candidate, when both its ecosystem and version are
/// known. An unknown version is `None` here rather than a guess: a false
/// "vulnerable" claim is worse than silence.
fn advisory_matches(database: &AdvisoryDatabase, candidate: &PackageCandidate) -> Vec<Advisory> {
    let (Some(ecosystem), Some(version)) = (candidate.ecosystem, candidate.version.as_deref())
    else {
        return Vec::new();
    };
    let subject = PackageSubject::new(ecosystem, candidate.name.clone(), version);
    database.matches(&subject)
}

/// How a scan interprets its results against the trusted baseline.
#[derive(Debug, Clone, Default)]
pub struct SecurityScanOptions {
    /// Where the baseline lives. `None` disables the baseline model entirely
    /// (raw AV behavior; every non-clean verdict is surfaced).
    pub baseline_path: Option<PathBuf>,
    /// Record the current package set as the trusted baseline even when one
    /// already exists (the "re-establish baseline" affordance).
    pub establish_baseline: bool,
    /// Also list AV-flagged packages that are unchanged since the baseline
    /// (the old raw view, for power users). Unchanged rows never affect the
    /// counts or the exit code.
    pub include_unchanged: bool,
}

impl SecurityScanOptions {
    /// The default product behavior: diff against (or establish) the baseline
    /// at its standard `~/.config/cleanton/security_baseline.json` location.
    #[must_use]
    pub fn with_default_baseline() -> Self {
        Self {
            baseline_path: security_baseline::default_baseline_path(),
            ..Self::default()
        }
    }
}

/// Mark packages as reviewed/trusted: upsert a baseline entry per package
/// with its CURRENT fingerprint and version, stamping `last_reviewed`. This
/// is a metadata write to the baseline file ONLY — packages are never
/// touched. Existing `first_seen` timestamps are preserved.
///
/// # Errors
///
/// Returns an error when the baseline file cannot be written.
pub fn review_packages(baseline_path: &Path, packages: &[PackageReport]) -> Result<usize> {
    let mut baseline = security_baseline::load(baseline_path);
    let now = SystemTime::now();
    let mut recorded = 0usize;
    for package in packages {
        let key = security_baseline::identity_key(package.source, &package.name);
        let first_seen = baseline
            .entries
            .get(&key)
            .map_or(now, |entry| entry.first_seen);
        baseline.entries.insert(
            key,
            BaselineEntry {
                version: package.version.clone(),
                fingerprint: package.fingerprint.clone(),
                first_seen,
                last_reviewed: Some(now),
                verdict_at_baseline: verdict_label(package.verdict).to_owned(),
            },
        );
        recorded = recorded.saturating_add(1);
    }
    security_baseline::save(baseline_path, &baseline)?;
    Ok(recorded)
}

/// Classify one scanned package against the baseline.
fn classify_change(entry: Option<&BaselineEntry>, package: &PackageReport) -> ChangeKind {
    let Some(entry) = entry else {
        return ChangeKind::New;
    };
    // An empty fingerprint means "could not verify" — never treat as a match.
    if !package.fingerprint.is_empty() && entry.fingerprint == package.fingerprint {
        return ChangeKind::Unchanged;
    }
    if entry.version == package.version {
        // Same version, different bytes: the worm-injection signature.
        ChangeKind::ChangedSameVersion
    } else {
        ChangeKind::Updated
    }
}

/// `true` when the finding's evidence lives in a benign context (no location
/// counts as the package's own code).
fn finding_in_benign_context(finding: &Finding) -> bool {
    finding
        .location
        .as_ref()
        .is_some_and(|location| is_benign_context(&location.path))
}

/// Project advisories into report findings. Hard facts, so they lead the list
/// and are never demoted by the benign-context heuristic.
fn advisory_findings(advisories: &[Advisory]) -> Vec<SecurityFinding> {
    advisories
        .iter()
        .map(|advisory| SecurityFinding {
            severity: advisory.severity,
            confidence: Confidence::High,
            category: ThreatCategory::SupplyChain,
            title: sanitize_display(&format!(
                "Vulnerable version: {} ({})",
                advisory.id, advisory.summary
            )),
            description: sanitize_display(&format!(
                "{} {} is inside a published affected range. {}",
                advisory.package,
                advisory
                    .ranges
                    .iter()
                    .map(crate::advisories::AffectedRange::display)
                    .collect::<Vec<_>>()
                    .join(" or "),
                advisory.remediation()
            )),
            file: None,
            evidence: advisory.references.first().cloned(),
        })
        .collect()
}

/// Does an advisory hit justify a red assessment on its own?
///
/// Yes, and unlike the content heuristics it needs no corroboration: a
/// published advisory naming the exact installed version is a fact, not a
/// guess, so it takes the same route as a known-malware signature instead of
/// the "notice" route an uncorroborated heuristic verdict takes.
fn advisory_escalates(advisories: &[Advisory]) -> bool {
    advisories
        .iter()
        .any(|advisory| matches!(advisory.severity, Severity::Critical | Severity::High))
}

fn advisory_verdict(advisories: &[Advisory]) -> AvVerdict {
    if advisories.iter().any(|advisory| advisory.malicious) {
        AvVerdict::Malicious
    } else {
        AvVerdict::Suspicious
    }
}

/// Score floor for a version-only package, so a critical advisory cannot look
/// quieter than a weak content heuristic.
fn advisory_score(advisories: &[Advisory]) -> u32 {
    advisories
        .iter()
        .map(|advisory| match advisory.severity {
            Severity::Critical => 92,
            Severity::High => 74,
            Severity::Medium => 48,
            Severity::Low => 22,
            Severity::Info => 8,
        })
        .max()
        .unwrap_or(0)
}

fn build_package_report(
    candidate: &PackageCandidate,
    report: &cleanton_antivirus::ScanReport,
    fingerprint: String,
    advisories: &[Advisory],
) -> PackageReport {
    // Corroboration is computed over the FULL finding list (top_findings is
    // a display cap, not a policy input) and is change-kind independent; the
    // assessment is re-derived once the baseline diff assigns a change kind.
    // The install/lifecycle anchor comes from the package's own manifest.
    let lifecycle_scripts = lifecycle_script_paths(&candidate.scan_path);
    let corroborated =
        verdict_corroborated(&report.findings, &lifecycle_scripts) || advisory_escalates(advisories);
    let mut findings: Vec<&Finding> = report.findings.iter().collect();
    // Benign-context evidence (CI workflows, tests, fixtures, docs) is
    // deprioritized for display — still shown when nothing else exists.
    findings.sort_by(|a, b| {
        finding_in_benign_context(a)
            .cmp(&finding_in_benign_context(b))
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| b.confidence.cmp(&a.confidence))
    });
    // Advisory matches lead: they are facts about the installed version, and
    // they must survive the display cap even when the content engines also
    // produced something.
    let mut top_findings = advisory_findings(advisories);
    let remaining = TOP_FINDINGS_PER_PACKAGE.saturating_sub(top_findings.len());
    top_findings.extend(
        findings
        .iter()
        .take(remaining)
        .map(|finding| SecurityFinding {
            severity: finding.severity,
            confidence: finding.confidence,
            category: finding.category,
            title: sanitize_display(&finding.title),
            description: sanitize_display(&finding.description),
            file: finding.location.as_ref().map(|loc| loc.path.clone()),
            evidence: finding.evidence.as_ref().map(|snippet| {
                let mut end = snippet.len().min(EVIDENCE_SNIPPET_MAX);
                while end > 0 && !snippet.is_char_boundary(end) {
                    end = end.saturating_sub(1);
                }
                sanitize_display(snippet.get(..end).unwrap_or_default())
            }),
        }),
    );
    PackageReport {
        name: candidate.name.clone(),
        version: candidate.version.clone(),
        path: candidate.display_path.clone(),
        source: candidate.source,
        verdict: report.verdict,
        change: ChangeKind::Uncompared,
        assessment: assess(ChangeKind::Uncompared, report.verdict, corroborated),
        corroborated,
        fingerprint,
        score: advisory_score(advisories).max(report.score),
        top_findings,
        finding_count: report.findings.len().saturating_add(advisories.len()),
    }
}

/// Report for a version-only package that matched at least one advisory. These
/// are never content-scanned, so there is no AV evidence and no fingerprint;
/// the advisory itself is the finding, and the empty fingerprint makes the
/// baseline diff surface it every run (a known-vulnerable version must not be
/// suppressed by having been seen before).
fn build_advisory_only_report(candidate: &PackageCandidate, advisories: &[Advisory]) -> PackageReport {
    let verdict = advisory_verdict(advisories);
    let top_findings = advisory_findings(advisories);
    PackageReport {
        name: candidate.name.clone(),
        version: candidate.version.clone(),
        path: candidate.display_path.clone(),
        source: candidate.source,
        verdict,
        change: ChangeKind::Uncompared,
        assessment: assess(ChangeKind::Uncompared, verdict, true),
        corroborated: true,
        fingerprint: String::new(),
        score: advisory_score(advisories),
        finding_count: top_findings.len(),
        top_findings,
    }
}

/// Scan every distinct package under `targets` (fingerprint + AV verdict per
/// package) and interpret the results against the baseline per `options`.
/// Read-only by construction for PACKAGES: nothing is removed, quarantined,
/// or modified, and no `CleanupAction` is ever produced from these findings.
/// The only write this function can perform is the baseline metadata file,
/// and only when establishing a baseline.
///
/// Runs on a bounded worker pool ([`MAX_SCAN_WORKERS`] threads at most);
/// `progress` is invoked after each package (it must be cheap and `Sync`).
/// Setting `cancel` stops promptly after the in-flight packages finish and the
/// returned report is marked [`SecurityReport::incomplete`]. A cancelled run
/// never establishes a baseline (a partial package set must not become the
/// trusted reference).
#[must_use]
pub fn scan_targets_with_options(
    targets: Vec<SecurityTarget>,
    options: &SecurityScanOptions,
    cancel: Option<&AtomicBool>,
    progress: &(dyn Fn(SecurityProgress) + Sync),
) -> SecurityReport {
    let started = Instant::now();
    let all_candidates = enumerate_packages(&targets);
    // Version-only ecosystems are answered from metadata: no file reads beyond
    // the manifest already parsed during enumeration, so they cost nothing and
    // are resolved here rather than in the worker pool.
    let database = AdvisoryDatabase::load();
    let (packages, version_only): (Vec<PackageCandidate>, Vec<PackageCandidate>) = all_candidates
        .into_iter()
        .partition(|candidate| !candidate.source.is_version_only());
    let total = packages.len();
    progress(SecurityProgress { scanned: 0, total });

    let scanner = Scanner::with_default_engines(scan_config());
    let next = AtomicUsize::new(0);
    let done_count = AtomicUsize::new(0);
    // EVERY scanned package is retained here (clean ones included): the
    // baseline diff needs identity + fingerprint even for AV-clean packages.
    let results: Mutex<Vec<PackageReport>> = Mutex::new(Vec::new());
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let cancelled = AtomicBool::new(false);

    let workers = std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(1, MAX_SCAN_WORKERS);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                        cancelled.store(true, Ordering::Relaxed);
                        break;
                    }
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(candidate) = packages.get(index) else {
                        break;
                    };
                    // Content fingerprint first (cheap relative to the AV
                    // engines). A failure leaves it empty, which the diff
                    // treats as "cannot verify" — surfaced, never trusted.
                    let fingerprint =
                        match security_baseline::fingerprint_package(&candidate.scan_path) {
                            Ok(fingerprint) => fingerprint,
                            Err(err) => {
                                let mut guard = match errors.lock() {
                                    Ok(guard) => guard,
                                    Err(poisoned) => poisoned.into_inner(),
                                };
                                guard.push(format!(
                                    "{}: fingerprint failed: {err}",
                                    candidate.display_path.display()
                                ));
                                String::new()
                            }
                        };
                    let advisories = advisory_matches(&database, candidate);
                    match scanner.scan_path(&candidate.scan_path) {
                        Ok(report) => {
                            let package_report = build_package_report(
                                candidate,
                                &report,
                                fingerprint,
                                &advisories,
                            );
                            let mut guard = match results.lock() {
                                Ok(guard) => guard,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            guard.push(package_report);
                        }
                        Err(err) => {
                            let mut guard = match errors.lock() {
                                Ok(guard) => guard,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            guard.push(format!("{}: {err}", candidate.display_path.display()));
                        }
                    }
                    let done = done_count.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                    progress(SecurityProgress {
                        scanned: done,
                        total,
                    });
                }
            });
        }
    });

    let mut results = match results.into_inner() {
        Ok(results) => results,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut errors = match errors.into_inner() {
        Ok(errors) => errors,
        Err(poisoned) => poisoned.into_inner(),
    };
    errors.sort();

    // Version-only packages enter the report ONLY when an advisory matches:
    // listing tens of thousands of healthy crates and gems as "clean" would
    // bury the packages that matter.
    for candidate in &version_only {
        let advisories = advisory_matches(&database, candidate);
        if !advisories.is_empty() {
            results.push(build_advisory_only_report(candidate, &advisories));
        }
    }

    let mut report = SecurityReport {
        targets,
        packages_scanned: done_count.load(Ordering::Relaxed),
        duration: started.elapsed(),
        clean_packages: results
            .iter()
            .filter(|pkg| matches!(pkg.verdict, AvVerdict::Clean))
            .count(),
        errors,
        incomplete: cancelled.load(Ordering::Relaxed),
        ..SecurityReport::empty()
    };
    apply_baseline(&mut report, results, options);
    report.duration = started.elapsed();
    report
}

/// Interpret the scanned packages against the baseline: establish it on the
/// first run (or on request), otherwise diff and keep only the changes.
fn apply_baseline(
    report: &mut SecurityReport,
    scanned: Vec<PackageReport>,
    options: &SecurityScanOptions,
) {
    let Some(baseline_path) = options.baseline_path.as_deref() else {
        // Raw mode (no baseline available): every non-clean AV verdict is
        // still LISTED, but the assessment policy applies here too —
        // uncorroborated verdicts are notices, and only corroborated alerts
        // reach the threat counts and the exit code.
        report.baseline_used = false;
        report.flagged = scanned
            .into_iter()
            .filter(|pkg| !matches!(pkg.verdict, AvVerdict::Clean))
            .collect();
        report.sort_flagged();
        report.recount_flagged();
        return;
    };

    report.baseline_used = true;
    let existing = security_baseline::load(baseline_path);
    let establish = options.establish_baseline || existing.is_empty();

    if establish && !report.incomplete {
        // First run (or forced re-establish): record the current set as the
        // trusted baseline. Do NOT dump raw AV verdicts on the user — only
        // CORROBORATED verdicts are called out as review items; single-signal
        // heuristic hits (the normal dev-toolchain pattern) are counted into
        // the muted "capabilities noted" tally instead.
        let now = SystemTime::now();
        let mut baseline = SecurityBaseline::default();
        for package in &scanned {
            let key = security_baseline::identity_key(package.source, &package.name);
            let first_seen = existing
                .entries
                .get(&key)
                .map_or(now, |entry| entry.first_seen);
            baseline.entries.insert(
                key,
                BaselineEntry {
                    version: package.version.clone(),
                    fingerprint: package.fingerprint.clone(),
                    first_seen,
                    last_reviewed: None,
                    verdict_at_baseline: verdict_label(package.verdict).to_owned(),
                },
            );
        }
        if let Err(err) = security_baseline::save(baseline_path, &baseline) {
            report
                .errors
                .push(format!("could not write security baseline: {err}"));
        }
        report.baseline_established = true;
        let total = scanned.len();
        let mut capability_notes = 0usize;
        report.flagged = scanned
            .into_iter()
            .filter_map(|mut pkg| {
                pkg.change = ChangeKind::New;
                pkg.assessment = assess(pkg.change, pkg.verdict, pkg.corroborated);
                if pkg.assessment.is_alert() {
                    return Some(pkg);
                }
                if !matches!(pkg.verdict, AvVerdict::Clean) {
                    capability_notes = capability_notes.saturating_add(1);
                }
                None
            })
            .collect();
        report.baseline_capability_notes = capability_notes;
        report.known_unchanged = total.saturating_sub(report.flagged.len());
        report.sort_flagged();
        report.recount_flagged();
        return;
    }

    // Diff mode: classify every package; the baseline file is NOT modified
    // (only an explicit review/trust or re-establish writes it).
    let mut flagged = Vec::new();
    let mut known_unchanged = 0usize;
    for mut package in scanned {
        let key = security_baseline::identity_key(package.source, &package.name);
        package.change = classify_change(existing.entries.get(&key), &package);
        package.assessment = assess(package.change, package.verdict, package.corroborated);
        if matches!(package.change, ChangeKind::Unchanged) {
            known_unchanged = known_unchanged.saturating_add(1);
            // Known + byte-identical: suppressed, whatever the AV verdict —
            // unless the caller asked for the raw "--all" view AND the AV
            // flagged it.
            if options.include_unchanged && !matches!(package.verdict, AvVerdict::Clean) {
                flagged.push(package);
            }
        } else {
            flagged.push(package);
        }
    }
    report.known_unchanged = known_unchanged;
    report.flagged = flagged;
    report.sort_flagged();
    report.recount_flagged();
}

/// Scan `targets` without a baseline (raw AV behavior). Kept for callers that
/// explicitly want the unfiltered view; the product entry points use
/// [`scan_targets_with_options`].
#[must_use]
pub fn scan_targets(
    targets: Vec<SecurityTarget>,
    cancel: Option<&AtomicBool>,
    progress: &(dyn Fn(SecurityProgress) + Sync),
) -> SecurityReport {
    scan_targets_with_options(targets, &SecurityScanOptions::default(), cancel, progress)
}

/// Convenience entry point shared by the CLI and both UIs: discover the
/// default global/extension targets plus any project roots, then scan with
/// baseline interpretation per `options`.
#[must_use]
pub fn run_security_scan_with_options(
    project_roots: &[PathBuf],
    options: &SecurityScanOptions,
    cancel: Option<&AtomicBool>,
    progress: &(dyn Fn(SecurityProgress) + Sync),
) -> SecurityReport {
    scan_targets_with_options(discover_targets(project_roots), options, cancel, progress)
}

/// Discover + scan with the default baseline model (the product behavior:
/// first run establishes the baseline, later runs surface the diff).
#[must_use]
pub fn run_security_scan(
    project_roots: &[PathBuf],
    cancel: Option<&AtomicBool>,
    progress: &(dyn Fn(SecurityProgress) + Sync),
) -> SecurityReport {
    run_security_scan_with_options(
        project_roots,
        &SecurityScanOptions::with_default_baseline(),
        cancel,
        progress,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    /// A harmless npm package: manifest + trivial module.
    fn make_benign_package(node_modules: &Path, name: &str) {
        let dir = node_modules.join(name);
        write(
            &dir.join("package.json"),
            &format!(r#"{{ "name": "{name}", "version": "1.0.0", "main": "index.js" }}"#),
        );
        write(
            &dir.join("index.js"),
            "module.exports = function add(a, b) { return a + b; };\n",
        );
    }

    /// Advisory (known-vulnerable version) wiring, end to end: a pinned old
    /// lodash must produce a vulnerable-version finding, and the fixed version
    /// must not.
    #[test]
    fn advisory_hit_is_reported_for_a_known_vulnerable_version() {
        let temp = tempfile::tempdir().unwrap();
        let node_modules = temp.path().join("node_modules");
        let vulnerable = node_modules.join("lodash");
        write(
            &vulnerable.join("package.json"),
            r#"{ "name": "lodash", "version": "4.17.20", "main": "index.js" }"#,
        );
        write(&vulnerable.join("index.js"), "module.exports = {};\n");
        let safe = node_modules.join("lodash-safe");
        write(
            &safe.join("package.json"),
            r#"{ "name": "lodash", "version": "4.17.21", "main": "index.js" }"#,
        );
        write(&safe.join("index.js"), "module.exports = {};\n");

        let targets = vec![SecurityTarget {
            kind: SecurityTargetKind::NodeGlobal,
            root: node_modules,
        }];
        let report = scan_targets(targets, None, &|_| {});

        let hits = report
            .flagged
            .iter()
            .filter(|package| {
                package
                    .top_findings
                    .iter()
                    .any(|finding| finding.title.contains("Vulnerable version"))
            })
            .collect::<Vec<_>>();
        assert_eq!(hits.len(), 1, "only the 4.17.20 copy is affected");
        assert_eq!(hits[0].version.as_deref(), Some("4.17.20"));
        assert!(
            hits[0].top_findings.iter().any(|finding| {
                finding.description.contains("Upgrade lodash")
                    && matches!(
                        finding.severity,
                        Severity::High | Severity::Critical | Severity::Medium
                    )
            }),
            "the finding must name the remedy and carry the advisory severity"
        );
    }

    /// A malicious-looking npm package replaying the Shai-Hulud structural
    /// indicators (postinstall hook + token harvest + republish), mirroring
    /// the cleanton-antivirus worm-campaign fixtures.
    fn make_malicious_package(node_modules: &Path, name: &str) {
        let dir = node_modules.join(name);
        write(
            &dir.join("package.json"),
            &format!(
                r#"{{ "name": "{name}", "version": "2.0.1", "scripts": {{ "postinstall": "node bundle.js" }} }}"#
            ),
        );
        write(
            &dir.join("bundle.js"),
            r"
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');
// harvest npm auth token from ~/.npmrc
const npmrcPath = path.join(os.homedir(), '.npmrc');
let NPM_TOKEN = '';
try {
    const npmrcContent = fs.readFileSync(npmrcPath, 'utf8');
    const match = npmrcContent.match(/_authToken\s*=\s*(.+)/);
    if (match) NPM_TOKEN = match[1].trim();
} catch (_) {}
// validate via https://registry.npmjs.org/-/whoami then enumerate
// https://registry.npmjs.org/-/v1/search?text=maintainer:X and republish
execSync('npm publish --access public', { env: { ...process.env, NPM_TOKEN } });
",
        );
    }

    fn node_target(root: &Path) -> SecurityTarget {
        SecurityTarget {
            kind: SecurityTargetKind::NodeProject,
            root: root.to_path_buf(),
        }
    }

    #[test]
    fn flags_malicious_package_and_not_benign() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        make_benign_package(&node_modules, "left-pad-ish");
        make_malicious_package(&node_modules, "rxnt-auth-utils");

        let report = scan_targets(vec![node_target(&node_modules)], None, &|_| {});

        assert_eq!(report.packages_scanned, 2);
        assert!(!report.incomplete);
        assert_eq!(report.flagged.len(), 1, "only the wormy package is flagged");
        let flagged = &report.flagged[0];
        assert_eq!(flagged.name, "rxnt-auth-utils");
        assert_eq!(flagged.version.as_deref(), Some("2.0.1"));
        assert_eq!(flagged.verdict, AvVerdict::Malicious);
        assert!(flagged.score >= 70);
        assert!(!flagged.top_findings.is_empty());
        assert_eq!(report.malicious_packages, 1);
        assert_eq!(report.clean_packages, 1);
        assert_eq!(report.exit_code(), 5);
        assert!(report.summary_message().contains("1 malicious"));
    }

    #[test]
    fn clean_tree_reports_no_threats_and_exit_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        make_benign_package(&node_modules, "alpha");
        make_benign_package(&node_modules, "beta");

        let report = scan_targets(vec![node_target(&node_modules)], None, &|_| {});

        assert_eq!(report.packages_scanned, 2);
        assert!(report.flagged.is_empty());
        assert_eq!(report.worst_verdict(), AvVerdict::Clean);
        assert_eq!(report.exit_code(), 0);
        assert!(report.summary_message().starts_with("No threats found"));
    }

    #[test]
    fn scoped_packages_enumerate_and_manifests_parse() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        make_benign_package(&node_modules, "plain");
        // @scope/pkg nests one level down.
        let scoped = node_modules.join("@acme");
        make_benign_package(&scoped, "tool");
        // Dot-dirs are npm metadata, not packages.
        std::fs::create_dir_all(node_modules.join(".bin")).unwrap();

        let candidates = enumerate_packages(&[node_target(&node_modules)]);
        let mut names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["plain", "tool"]);
    }

    #[test]
    fn identical_resolved_paths_scan_once() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        make_benign_package(&node_modules, "real");
        // A second target listing the same tree must not double-scan.
        let targets = vec![node_target(&node_modules), node_target(&node_modules)];
        let deduped = discover_targets(&[]); // unrelated; just exercise it
        let _ = deduped;
        let candidates = enumerate_packages(&targets);
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn project_discovery_finds_node_modules_and_site_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("web/node_modules/lodash-ish")).unwrap();
        std::fs::create_dir_all(root.join(".venv/lib/python3.12/site-packages/requestz")).unwrap();
        std::fs::create_dir_all(root.join(".git/objects")).unwrap();

        let targets = discover_project_targets(root);
        let kinds: Vec<SecurityTargetKind> = targets.iter().map(|t| t.kind).collect();
        assert!(kinds.contains(&SecurityTargetKind::NodeProject));
        assert!(kinds.contains(&SecurityTargetKind::PythonSitePackages));
        assert_eq!(targets.len(), 2, "nothing under .git is a target");
    }

    #[test]
    fn python_site_packages_enumerates_dirs_and_modules_with_versions() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("site-packages");
        std::fs::create_dir_all(site.join("requests_like")).unwrap();
        write(
            &site.join("requests_like/__init__.py"),
            "def get(url):\n    return None\n",
        );
        std::fs::create_dir_all(site.join("requests_like-2.31.0.dist-info")).unwrap();
        write(&site.join("six_like.py"), "PY3 = True\n");
        std::fs::create_dir_all(site.join("__pycache__")).unwrap();

        let target = SecurityTarget {
            kind: SecurityTargetKind::PythonSitePackages,
            root: site.clone(),
        };
        let candidates = enumerate_packages(&[target]);
        let mut names: Vec<(String, Option<String>)> = candidates
            .iter()
            .map(|c| (c.name.clone(), c.version.clone()))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                ("requests_like".to_owned(), Some("2.31.0".to_owned())),
                ("six_like".to_owned(), None),
            ]
        );
    }

    #[test]
    fn cancellation_marks_report_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        for idx in 0..8 {
            make_benign_package(&node_modules, &format!("pkg-{idx}"));
        }
        let cancel = AtomicBool::new(true); // cancelled before it starts
        let report = scan_targets(vec![node_target(&node_modules)], Some(&cancel), &|_| {});
        assert!(report.incomplete);
        assert!(report.packages_scanned < 8);
    }

    #[test]
    fn flagged_packages_sort_worst_first() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        make_malicious_package(&node_modules, "zz-worm");
        // A mildly suspicious package: obfuscation-ish eval of base64 payload.
        let sus = node_modules.join("aa-sus");
        write(
            &sus.join("package.json"),
            r#"{ "name": "aa-sus", "version": "0.1.0" }"#,
        );
        write(
            &sus.join("index.js"),
            "const p = Buffer.from('ZXZhbCgnMScp', 'base64').toString();\neval(p);\n",
        );
        make_benign_package(&node_modules, "mm-fine");

        let report = scan_targets(vec![node_target(&node_modules)], None, &|_| {});
        assert!(report.flagged.len() >= 2, "worm + suspicious both flagged");
        assert_eq!(report.flagged[0].name, "zz-worm");
        assert_eq!(report.flagged[0].verdict, AvVerdict::Malicious);
        // A suspicious-only report exits 3 (malicious wins here, so derive it).
        let suspicious_only = SecurityReport {
            malicious_packages: 0,
            suspicious_packages: 1,
            ..report.clone()
        };
        assert_eq!(suspicious_only.exit_code(), 3);
        // Every later row ranks no worse than the one before it.
        for pair in report.flagged.windows(2) {
            assert!(
                verdict_rank(pair[0].verdict) > verdict_rank(pair[1].verdict)
                    || (pair[0].verdict == pair[1].verdict && pair[0].score >= pair[1].score)
            );
        }
    }

    #[test]
    fn progress_reports_reach_total() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        make_benign_package(&node_modules, "one");
        make_benign_package(&node_modules, "two");
        let max_seen = AtomicUsize::new(0);
        let report = scan_targets(vec![node_target(&node_modules)], None, &|progress| {
            max_seen.fetch_max(progress.scanned, Ordering::Relaxed);
            assert_eq!(progress.total, 2);
        });
        assert_eq!(report.packages_scanned, 2);
        assert_eq!(max_seen.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn shared_copy_helpers_are_stable() {
        assert_eq!(verdict_label(AvVerdict::Malicious), "malicious");
        assert_eq!(severity_label(Severity::Critical), "critical");
        assert_eq!(
            change_kind_label(ChangeKind::ChangedSameVersion),
            "changed (no version bump)"
        );
        let package = PackageReport {
            name: "evil".to_owned(),
            version: Some("1.0.0".to_owned()),
            path: PathBuf::from("/tmp/evil"),
            source: SecurityTargetKind::NodeGlobal,
            verdict: AvVerdict::Malicious,
            change: ChangeKind::New,
            assessment: Assessment::Alert(AvVerdict::Malicious),
            corroborated: true,
            fingerprint: "fp".to_owned(),
            score: 92,
            top_findings: vec![SecurityFinding {
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: ThreatCategory::SupplyChain,
                title: "Token harvest".to_owned(),
                description: "Reads ~/.npmrc auth token".to_owned(),
                file: Some("bundle.js".to_owned()),
                evidence: Some("_authToken".to_owned()),
            }],
            finding_count: 1,
        };
        assert_eq!(package.display_name(), "evil 1.0.0");
        assert!(package.headline().contains("malicious (score 92)"));
        assert!(package.is_critical_alert());
        let lines = package.finding_lines();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("[critical] Token harvest"));
        assert!(lines[1].contains("bundle.js: _authToken"));
    }

    // ── Baseline + diff model ────────────────────────────────────────────────

    fn baseline_options(path: &Path) -> SecurityScanOptions {
        SecurityScanOptions {
            baseline_path: Some(path.to_path_buf()),
            ..SecurityScanOptions::default()
        }
    }

    fn scan_with_baseline(node_modules: &Path, baseline: &Path) -> SecurityReport {
        scan_targets_with_options(
            vec![node_target(node_modules)],
            &baseline_options(baseline),
            None,
            &|_| {},
        )
    }

    /// The core cry-wolf fix: the FIRST run must establish a baseline instead
    /// of dumping raw malicious verdicts for the whole toolchain, and a
    /// byte-identical re-run must suppress even AV-malicious known packages.
    #[test]
    fn first_run_establishes_baseline_and_rerun_suppresses_known() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "left-pad-ish");
        // A toolchain-like package the raw AV would call malicious.
        make_malicious_package(&node_modules, "npm-ish");

        let first = scan_with_baseline(&node_modules, &baseline);
        assert!(first.baseline_used);
        assert!(first.baseline_established);
        assert_eq!(first.packages_scanned, 2);
        assert!(
            first.summary_message().starts_with("Baseline established"),
            "got: {}",
            first.summary_message()
        );
        // Genuinely CORROBORATED hits are still called out at baseline time
        // (framed as review items, not a wall of verdicts).
        assert_eq!(first.flagged.len(), 1);
        assert_eq!(first.flagged[0].name, "npm-ish");
        assert!(first.flagged[0].corroborated);
        assert!(first.flagged[0].is_alert());
        assert!(baseline.exists(), "baseline file written");

        // Second run, nothing changed: EVERYTHING suppressed, including the
        // package the AV flags — it is byte-identical to the reviewed set.
        let second = scan_with_baseline(&node_modules, &baseline);
        assert!(!second.baseline_established);
        assert!(second.flagged.is_empty(), "known packages are suppressed");
        assert_eq!(second.known_unchanged, 2);
        assert_eq!(second.change_count(), 0);
        assert_eq!(second.exit_code(), 0);
        assert_eq!(second.banner_tone(), "success");
        assert!(
            second
                .summary_message()
                .starts_with("No changes since last baseline"),
            "got: {}",
            second.summary_message()
        );
    }

    /// Same version + different bytes = the worm-injection signature. Must be
    /// elevated to a critical alert and exit 5 even when the AV verdict is
    /// clean.
    #[test]
    fn same_version_content_change_is_elevated() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "alpha");
        make_benign_package(&node_modules, "beta");
        let first = scan_with_baseline(&node_modules, &baseline);
        assert!(first.baseline_established);

        // Tamper: mutate alpha's code without touching its version.
        write(
            &node_modules.join("alpha/index.js"),
            "module.exports = function add(a, b) { return a + b + 0; };\n",
        );
        let report = scan_with_baseline(&node_modules, &baseline);
        assert_eq!(report.changed_same_version, 1);
        assert_eq!(report.flagged.len(), 1);
        let flagged = &report.flagged[0];
        assert_eq!(flagged.name, "alpha");
        assert_eq!(flagged.change, ChangeKind::ChangedSameVersion);
        assert!(flagged.is_tampered());
        assert!(
            flagged.is_critical_alert(),
            "tamper is critical even if AV-clean"
        );
        assert!(
            flagged.assessment.is_alert(),
            "tamper alerts regardless of corroboration"
        );
        assert_eq!(report.critical_packages, 1);
        assert_eq!(report.exit_code(), 5, "same-version tamper exits 5");
        assert_eq!(report.banner_tone(), "danger");
        assert!(
            report
                .summary_message()
                .contains("1 changed without a version bump")
        );
    }

    /// Version bump + content change = a normal update: surfaced, not
    /// critical, exit 0 when the AV verdict is clean.
    #[test]
    fn version_bump_with_change_is_updated() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "alpha");
        let _ = scan_with_baseline(&node_modules, &baseline);

        write(
            &node_modules.join("alpha/package.json"),
            r#"{ "name": "alpha", "version": "1.1.0", "main": "index.js" }"#,
        );
        let report = scan_with_baseline(&node_modules, &baseline);
        assert_eq!(report.updated_packages, 1);
        assert_eq!(report.flagged.len(), 1);
        assert_eq!(report.flagged[0].change, ChangeKind::Updated);
        assert_eq!(report.flagged[0].assessment, Assessment::Notice);
        assert!(!report.flagged[0].is_critical_alert());
        assert_eq!(report.notice_packages, 1);
        assert_eq!(report.alert_packages, 0);
        assert_eq!(report.exit_code(), 0, "clean-verdict update is exit 0");
        assert_eq!(report.banner_tone(), "info", "notices are the info tone");
        assert!(
            report.banner_headline().contains("no corroborated threats"),
            "got: {}",
            report.banner_headline()
        );
    }

    /// A package that appears after the baseline is surfaced as new; a
    /// malicious new package drives exit 5, worst-first at the top.
    #[test]
    fn new_packages_are_surfaced() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "alpha");
        let _ = scan_with_baseline(&node_modules, &baseline);

        make_benign_package(&node_modules, "zz-later");
        make_malicious_package(&node_modules, "aa-worm");
        let report = scan_with_baseline(&node_modules, &baseline);
        assert_eq!(report.new_packages, 2);
        assert_eq!(report.known_unchanged, 1);
        assert_eq!(report.flagged.len(), 2);
        // Critical (corroborated malicious) new package sorts above the
        // clean new one, which is a neutral notice.
        assert_eq!(report.flagged[0].name, "aa-worm");
        assert_eq!(report.flagged[0].change, ChangeKind::New);
        assert!(report.flagged[0].is_alert());
        assert_eq!(report.flagged[1].name, "zz-later");
        assert_eq!(report.flagged[1].assessment, Assessment::Notice);
        assert_eq!(report.exit_code(), 5);
    }

    /// Marking a surfaced package reviewed updates the BASELINE FILE only and
    /// silences it until it changes again.
    #[test]
    fn review_updates_baseline_and_silences_package() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "alpha");
        let _ = scan_with_baseline(&node_modules, &baseline);

        make_malicious_package(&node_modules, "toolchain-ish");
        let mut report = scan_with_baseline(&node_modules, &baseline);
        assert_eq!(report.flagged.len(), 1);
        let package_dir = node_modules.join("toolchain-ish");
        let before = std::fs::read(package_dir.join("bundle.js")).unwrap();

        let name = report.trust_flagged(0, &baseline).unwrap();
        assert!(name.starts_with("toolchain-ish"));
        assert!(report.flagged.is_empty());
        assert_eq!(report.known_unchanged, 2);
        assert_eq!(report.malicious_packages, 0);
        assert_eq!(report.exit_code(), 0);

        // The review NEVER touches the package itself.
        assert_eq!(
            std::fs::read(package_dir.join("bundle.js")).unwrap(),
            before
        );
        let stored = crate::security_baseline::load(&baseline);
        let entry = stored
            .entries
            .get(&crate::security_baseline::identity_key(
                SecurityTargetKind::NodeProject,
                "toolchain-ish",
            ))
            .expect("reviewed entry recorded");
        assert!(entry.last_reviewed.is_some());
        assert_eq!(entry.verdict_at_baseline, "malicious");

        // Re-scan: the reviewed package is now known/unchanged.
        let after = scan_with_baseline(&node_modules, &baseline);
        assert!(after.flagged.is_empty());
        assert_eq!(after.known_unchanged, 2);
        assert_eq!(after.exit_code(), 0);
    }

    /// `include_unchanged` restores the raw view (power users): AV-flagged
    /// known packages are listed, but never counted or exit-code relevant.
    #[test]
    fn include_unchanged_lists_but_never_alerts() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "alpha");
        make_malicious_package(&node_modules, "npm-ish");
        let _ = scan_with_baseline(&node_modules, &baseline);

        let options = SecurityScanOptions {
            baseline_path: Some(baseline.clone()),
            include_unchanged: true,
            ..SecurityScanOptions::default()
        };
        let report =
            scan_targets_with_options(vec![node_target(&node_modules)], &options, None, &|_| {});
        assert_eq!(report.flagged.len(), 1, "the raw AV hit is listed");
        assert_eq!(report.flagged[0].change, ChangeKind::Unchanged);
        assert_eq!(report.flagged[0].assessment, Assessment::Notice);
        assert_eq!(report.malicious_packages, 0, "…but not counted");
        assert_eq!(report.change_count(), 0);
        assert_eq!(report.exit_code(), 0, "…and does not affect the exit code");
    }

    /// "Trust all shown" records every surfaced package in one write and
    /// zeroes the alert counts.
    #[test]
    fn trust_all_flagged_silences_every_surfaced_package() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "alpha");
        let _ = scan_with_baseline(&node_modules, &baseline);

        make_benign_package(&node_modules, "new-one");
        make_malicious_package(&node_modules, "new-two");
        let mut report = scan_with_baseline(&node_modules, &baseline);
        assert_eq!(report.flagged.len(), 2);

        let trusted = report.trust_all_flagged(&baseline).unwrap();
        assert_eq!(trusted, 2);
        assert!(report.flagged.is_empty());
        assert_eq!(report.known_unchanged, 3);
        assert_eq!(report.change_count(), 0);
        assert_eq!(report.exit_code(), 0);

        let after = scan_with_baseline(&node_modules, &baseline);
        assert!(after.flagged.is_empty());
        assert_eq!(after.known_unchanged, 3);
    }

    /// A forced re-establish trusts the current state wholesale.
    #[test]
    fn reestablish_baseline_trusts_current_state() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "alpha");
        let _ = scan_with_baseline(&node_modules, &baseline);

        // Tamper, then re-establish: the tampered state becomes the baseline.
        write(
            &node_modules.join("alpha/index.js"),
            "module.exports = 2;\n",
        );
        let options = SecurityScanOptions {
            baseline_path: Some(baseline.clone()),
            establish_baseline: true,
            ..SecurityScanOptions::default()
        };
        let report =
            scan_targets_with_options(vec![node_target(&node_modules)], &options, None, &|_| {});
        assert!(report.baseline_established);
        assert_eq!(report.exit_code(), 0);

        let after = scan_with_baseline(&node_modules, &baseline);
        assert!(after.flagged.is_empty());
        assert_eq!(after.known_unchanged, 1);
    }

    // ── Assessment policy (corroboration gates every alert) ─────────────────

    /// A package whose only strong signal is ONE capability in its own code:
    /// the npm/pip/editor-extension pattern. Raw AV calls it malicious;
    /// policy must present a neutral notice.
    fn make_capability_package(node_modules: &Path, name: &str, version: &str) {
        let dir = node_modules.join(name);
        write(
            &dir.join("package.json"),
            &format!(
                r#"{{ "name": "{name}", "version": "{version}", "scripts": {{ "postinstall": "node collect.js" }} }}"#
            ),
        );
        write(
            &dir.join("collect.js"),
            r"
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
// read npm auth token from ~/.npmrc (single capability, no exfil/publish)
const npmrcPath = path.join(os.homedir(), '.npmrc');
let token = '';
try {
    const npmrcContent = fs.readFileSync(npmrcPath, 'utf8');
    const match = npmrcContent.match(/_authToken\s*=\s*(.+)/);
    if (match) token = match[1].trim();
} catch (_) {}
module.exports = token;
",
        );
    }

    fn strong_finding(category: ThreatCategory, file: &str) -> Finding {
        Finding::new(
            "test-engine",
            category,
            Severity::Critical,
            Confidence::High,
            "strong finding",
            "synthetic",
        )
        .with_location(FileLocation::file(file))
    }

    /// Finding text sourced from the vendored antivirus crate is sanitized at
    /// the projection boundary: typographic symbols never reach the report.
    #[test]
    fn antivirus_finding_text_is_sanitized_for_display() {
        let candidate = PackageCandidate {
            name: "pkg".to_owned(),
            version: Some("1.0.0".to_owned()),
            display_path: PathBuf::from("/tmp/pkg"),
            scan_path: PathBuf::from("/tmp/pkg"),
            source: SecurityTargetKind::NodeGlobal,
        };
        let mut finding = strong_finding(ThreatCategory::SupplyChain, "package.json");
        finding.title = "Token harvest \u{2014} \u{201C}quoted\u{201D}".to_owned();
        finding.description =
            "reads ~/.npmrc \u{2192} exfiltrates\u{2026} \u{2022} badly".to_owned();
        finding.evidence = Some("token \u{2013} \u{2018}stolen\u{2019}".to_owned());
        let av_report = cleanton_antivirus::ScanReport {
            target: "/tmp/pkg".to_owned(),
            verdict: AvVerdict::Malicious,
            score: 95,
            findings: vec![finding],
            files_scanned: 1,
            bytes_scanned: 10,
            duration_ms: 1,
            engine_stats: Vec::new(),
            errors: Vec::new(),
        };
        let report = build_package_report(&candidate, &av_report, "fp".to_owned());
        let top = report.top_findings.first().expect("one finding retained");
        assert_eq!(top.title, "Token harvest - \"quoted\"");
        assert_eq!(top.description, "reads ~/.npmrc -> exfiltrates... - badly");
        assert_eq!(top.evidence.as_deref(), Some("token - 'stolen'"));
        let symbols = [
            '\u{2014}', '\u{2013}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2192}',
            '\u{2190}', '\u{21D2}', '\u{2022}', '\u{2026}',
        ];
        for line in report.finding_lines() {
            assert!(
                !line.chars().any(|ch| symbols.contains(&ch)),
                "finding line still carries a typographic symbol: {line}"
            );
        }
    }

    #[test]
    fn benign_context_paths_are_recognized() {
        assert!(is_benign_context(".github/workflows/publish.yml"));
        assert!(is_benign_context(
            "node_modules/json-schema-traverse/.github/workflows/publish.yml"
        ));
        assert!(is_benign_context("tests/fixtures/evil.js"));
        assert!(is_benign_context("__tests__/token.spec.js"));
        assert!(is_benign_context("Examples/demo.js"));
        assert!(is_benign_context("docs/security.txt"));
        assert!(is_benign_context("README.md"));
        assert!(is_benign_context("lib/README.MD"));
        // CI configs, man pages, and non-executable build artifacts are the
        // real-machine corroboration false positives (npm/serve/apify-cli).
        assert!(is_benign_context(
            "node_modules/configparser/.circleci/config.yml"
        ));
        assert!(is_benign_context("man/man5/npmrc.5"));
        assert!(is_benign_context("dist/_register-BL3IPgYh.js.map"));
        assert!(is_benign_context(
            "node_modules/type-fest/source/package-json.d.ts"
        ));
        assert!(!is_benign_context("lib/index.js"));
        assert!(!is_benign_context("bundle.js"));
        assert!(!is_benign_context("dist/index.ts"), ".ts alone is code");
        assert!(!is_benign_context("src/protest/index.js"), "substring only");
        assert!(!is_benign_context("src/manual.js"), "segment match only");
    }

    #[test]
    fn corroboration_needs_two_categories_or_known_malware() {
        // A lifecycle-hook script set as [`lifecycle_script_paths`] would
        // resolve it (postinstall → bundle.js).
        let hooks: HashSet<String> = ["bundle.js".to_owned()].into_iter().collect();
        let no_hooks: HashSet<String> = HashSet::new();
        // Single capability (the legit-tool pattern) never corroborates,
        // even in an install script.
        assert!(!verdict_corroborated(
            &[strong_finding(
                ThreatCategory::CredentialAccess,
                "bundle.js"
            )],
            &hooks
        ));
        // Two strong findings in the SAME category: still one capability.
        assert!(!verdict_corroborated(
            &[
                strong_finding(ThreatCategory::CredentialAccess, "bundle.js"),
                strong_finding(ThreatCategory::CredentialAccess, "b.js"),
            ],
            &hooks
        ));
        // Two DISTINCT categories anchored in the lifecycle script corroborate.
        assert!(verdict_corroborated(
            &[
                strong_finding(ThreatCategory::SupplyChain, "bundle.js"),
                strong_finding(ThreatCategory::Exfiltration, "bundle.js"),
            ],
            &hooks
        ));
        // The manifest itself is install context (inline hook payloads).
        assert!(verdict_corroborated(
            &[
                strong_finding(ThreatCategory::SupplyChain, "package.json"),
                strong_finding(ThreatCategory::Exfiltration, "lib/helper.js"),
            ],
            &no_hooks
        ));
        // The same two categories confined to runtime bundles do NOT — the
        // VS Code extension false-positive case (nothing runs at install).
        assert!(!verdict_corroborated(
            &[
                strong_finding(ThreatCategory::CryptoStealer, "dist/bundle.min.js"),
                strong_finding(ThreatCategory::Exfiltration, "dist/bundle.min.js"),
                strong_finding(ThreatCategory::SupplyChain, "out/client/extension.js"),
            ],
            &no_hooks
        ));
        // A known-malware signature hit corroborates alone, anywhere.
        assert!(verdict_corroborated(
            &[strong_finding(
                ThreatCategory::KnownMalware,
                "dist/payload.bin"
            )],
            &no_hooks
        ));
        // Benign-context evidence never counts toward corroboration.
        assert!(!verdict_corroborated(
            &[
                strong_finding(ThreatCategory::SupplyChain, ".github/workflows/publish.yml"),
                strong_finding(ThreatCategory::Exfiltration, "tests/fixture.js"),
                strong_finding(ThreatCategory::CredentialAccess, "docs/example.md"),
            ],
            &hooks
        ));
        // One benign-context + one own-code strong finding: one real category.
        assert!(!verdict_corroborated(
            &[
                strong_finding(ThreatCategory::SupplyChain, ".github/workflows/ci.yml"),
                strong_finding(ThreatCategory::CredentialAccess, "bundle.js"),
            ],
            &hooks
        ));
        // Non-critical severity or non-high confidence is never strong.
        let weak = Finding::new(
            "test-engine",
            ThreatCategory::SupplyChain,
            Severity::High,
            Confidence::High,
            "weak",
            "synthetic",
        )
        .with_location(FileLocation::file("bundle.js"));
        let unsure = Finding::new(
            "test-engine",
            ThreatCategory::Exfiltration,
            Severity::Critical,
            Confidence::Medium,
            "unsure",
            "synthetic",
        )
        .with_location(FileLocation::file("bundle.js"));
        assert!(!verdict_corroborated(&[weak, unsure], &hooks));
        // Non-strong categories (obfuscation, IOC, …) never corroborate.
        assert!(!verdict_corroborated(
            &[
                strong_finding(ThreatCategory::Obfuscation, "bundle.js"),
                strong_finding(ThreatCategory::Ioc, "bundle.js"),
            ],
            &hooks
        ));
    }

    /// The install-context predicate and lifecycle-hook script resolution
    /// from a real `package.json`.
    #[test]
    fn lifecycle_script_paths_resolve_from_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("pkg");
        write(
            &dir.join("package.json"),
            r#"{ "name": "pkg", "version": "1.0.0", "scripts": {
                "postinstall": "node ./bundle.js && node scripts/setup.js",
                "preinstall": "sh hooks/pre.sh",
                "prepare": "node missing.js",
                "test": "node test-runner.js",
                "build": "node build.js"
            } }"#,
        );
        write(&dir.join("bundle.js"), "// payload\n");
        write(&dir.join("scripts/setup.js"), "// setup\n");
        write(&dir.join("hooks/pre.sh"), "true\n");
        write(&dir.join("test-runner.js"), "// not a lifecycle hook\n");
        write(&dir.join("build.js"), "// not a lifecycle hook\n");

        let hooks = lifecycle_script_paths(&dir);
        assert!(hooks.contains("bundle.js"), "got: {hooks:?}");
        assert!(hooks.contains("scripts/setup.js"), "got: {hooks:?}");
        assert!(hooks.contains("hooks/pre.sh"), "got: {hooks:?}");
        assert!(!hooks.contains("missing.js"), "nonexistent file skipped");
        assert!(
            !hooks.contains("test-runner.js") && !hooks.contains("build.js"),
            "non-lifecycle scripts (test/build) are not install context"
        );

        // The predicate: hook scripts + manifests yes, runtime bundles no.
        assert!(is_install_context("bundle.js", &hooks));
        assert!(is_install_context("./bundle.js", &hooks));
        assert!(is_install_context("scripts/setup.js", &hooks));
        assert!(is_install_context("package.json", &hooks));
        assert!(is_install_context("setup.py", &hooks));
        assert!(!is_install_context("dist/extension.js", &hooks));
        assert!(!is_install_context("out/client/extension.js", &hooks));
        assert!(!is_install_context("index.js", &hooks));
    }

    /// The VS Code extension false-positive shape end to end: strong
    /// crypto-stealer + exfiltration heuristics ONLY in runtime bundles, no
    /// lifecycle hook — NOT corroborated, so an update stays a Notice.
    #[test]
    fn runtime_bundle_multi_category_stays_notice() {
        let candidate = PackageCandidate {
            name: "publisher.some-ext-1.2.3".to_owned(),
            version: Some("1.2.3".to_owned()),
            display_path: PathBuf::from("/tmp/ext"),
            scan_path: PathBuf::from("/tmp/ext"),
            source: SecurityTargetKind::EditorExtensions,
        };
        let av_report = cleanton_antivirus::ScanReport {
            target: "/tmp/ext".to_owned(),
            verdict: AvVerdict::Malicious,
            score: 95,
            findings: vec![
                strong_finding(ThreatCategory::CryptoStealer, "dist/bundle.min.js"),
                strong_finding(ThreatCategory::Exfiltration, "dist/bundle.min.js"),
                strong_finding(ThreatCategory::SupplyChain, "dist/extension.js"),
            ],
            files_scanned: 2,
            bytes_scanned: 1_000_000,
            duration_ms: 1,
            engine_stats: Vec::new(),
            errors: Vec::new(),
        };
        let report = build_package_report(&candidate, &av_report, "fp".to_owned());
        assert!(
            !report.corroborated,
            "runtime-bundle-only evidence must not corroborate"
        );
        assert_eq!(
            assess(ChangeKind::Updated, report.verdict, report.corroborated),
            Assessment::Notice
        );
    }

    /// Recommended-action copy is concrete, per-manager, and matches the
    /// safety model: remove for alerts, reinstall-pinned for tampers, and a
    /// trust-only path (no destructive command) for notices.
    #[test]
    fn recommended_actions_are_manager_specific_and_safe() {
        let base = PackageReport {
            name: "left-pad".to_owned(),
            version: Some("1.3.0".to_owned()),
            path: PathBuf::from("/globals/node_modules/left-pad"),
            source: SecurityTargetKind::NodeGlobal,
            verdict: AvVerdict::Malicious,
            change: ChangeKind::New,
            assessment: Assessment::Alert(AvVerdict::Malicious),
            corroborated: true,
            fingerprint: "fp".to_owned(),
            score: 90,
            top_findings: vec![SecurityFinding {
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: ThreatCategory::SupplyChain,
                title: "worm".to_owned(),
                description: "d".to_owned(),
                file: Some("bundle.js".to_owned()),
                evidence: None,
            }],
            finding_count: 1,
        };

        // Alert on a global npm package → uninstall command + inspect path.
        assert_eq!(base.action_label(), "Investigate now");
        assert_eq!(
            base.suggested_command().as_deref(),
            Some("npm uninstall -g 'left-pad'")
        );
        let alert_lines = base.action_lines().join("\n");
        assert!(alert_lines.contains("$ npm uninstall -g 'left-pad'"));
        assert!(alert_lines.contains("/globals/node_modules/left-pad/bundle.js"));

        // Tamper → reinstall pinned to the baseline version, never uninstall.
        let tamper = PackageReport {
            change: ChangeKind::ChangedSameVersion,
            assessment: Assessment::Alert(AvVerdict::Clean),
            corroborated: false,
            ..base.clone()
        };
        assert_eq!(
            tamper.suggested_command().as_deref(),
            Some("npm install -g 'left-pad'@1.3.0")
        );
        assert!(tamper.action_lines().join("\n").contains("Do NOT trust"));

        // Notice → no destructive command; trust-only guidance.
        let notice = PackageReport {
            assessment: Assessment::Notice,
            corroborated: false,
            ..base.clone()
        };
        assert_eq!(notice.action_label(), "Verify then trust");
        let notice_lines = notice.action_lines().join("\n");
        assert!(notice_lines.contains("mark it reviewed"));
        assert!(
            !notice_lines.contains("uninstall"),
            "no removal for notices"
        );

        // Editor extension: strip the versioned dir to the extension id and
        // route through the editor CLI.
        let ext = PackageReport {
            name: "publisher.tool-2.4.0".to_owned(),
            version: Some("2.4.0".to_owned()),
            path: PathBuf::from("/Users/x/.vscode/extensions/publisher.tool-2.4.0"),
            source: SecurityTargetKind::EditorExtensions,
            ..base.clone()
        };
        assert_eq!(
            ext.suggested_command().as_deref(),
            Some("code --uninstall-extension 'publisher.tool'")
        );

        // Python site-packages → pip.
        let py = PackageReport {
            name: "requests".to_owned(),
            source: SecurityTargetKind::PythonSitePackages,
            ..base.clone()
        };
        assert_eq!(
            py.suggested_command().as_deref(),
            Some("pip uninstall 'requests'")
        );
    }

    #[test]
    fn assessment_policy_matrix() {
        // Tamper: always an alert, whatever the verdict or corroboration.
        assert_eq!(
            assess(ChangeKind::ChangedSameVersion, AvVerdict::Clean, false),
            Assessment::Alert(AvVerdict::Clean)
        );
        // New/updated corroborated: alert with the raw verdict.
        assert_eq!(
            assess(ChangeKind::Updated, AvVerdict::Malicious, true),
            Assessment::Alert(AvVerdict::Malicious)
        );
        assert_eq!(
            assess(ChangeKind::New, AvVerdict::Suspicious, true),
            Assessment::Alert(AvVerdict::Suspicious)
        );
        // New/updated uncorroborated: neutral notice even when the raw
        // verdict screams (the brew-bump / extension-auto-update case).
        assert_eq!(
            assess(ChangeKind::Updated, AvVerdict::Malicious, false),
            Assessment::Notice
        );
        assert_eq!(
            assess(ChangeKind::New, AvVerdict::Malicious, false),
            Assessment::Notice
        );
        // Clean verdicts are notices even when "corroborated" (defensive).
        assert_eq!(
            assess(ChangeKind::New, AvVerdict::Clean, true),
            Assessment::Notice
        );
        // Known baseline entries stay neutral in the --all view.
        assert_eq!(
            assess(ChangeKind::Unchanged, AvVerdict::Malicious, true),
            Assessment::Notice
        );
    }

    /// `top_findings` must prefer own-code evidence over benign-context
    /// evidence, whatever the severity ordering says.
    #[test]
    fn top_findings_prefer_non_benign_context_evidence() {
        let candidate = PackageCandidate {
            name: "pkg".to_owned(),
            version: Some("1.0.0".to_owned()),
            display_path: PathBuf::from("/tmp/pkg"),
            scan_path: PathBuf::from("/tmp/pkg"),
            source: SecurityTargetKind::NodeProject,
        };
        let av_report = cleanton_antivirus::ScanReport {
            target: "/tmp/pkg".to_owned(),
            verdict: AvVerdict::Suspicious,
            score: 60,
            findings: vec![
                strong_finding(ThreatCategory::SupplyChain, ".github/workflows/publish.yml"),
                strong_finding(ThreatCategory::Exfiltration, "tests/fixture.js"),
                Finding::new(
                    "test-engine",
                    ThreatCategory::CredentialAccess,
                    Severity::Medium,
                    Confidence::Medium,
                    "own-code capability",
                    "synthetic",
                )
                .with_location(FileLocation::file("lib/index.js")),
            ],
            files_scanned: 3,
            bytes_scanned: 100,
            duration_ms: 1,
            engine_stats: Vec::new(),
            errors: Vec::new(),
        };
        let report = build_package_report(&candidate, &av_report, "fp".to_owned());
        // The medium own-code finding outranks both critical benign-context
        // ones for display…
        assert_eq!(report.top_findings[0].title, "own-code capability");
        // …but benign-context findings are still shown after it.
        assert_eq!(report.top_findings.len(), 3);
        // And benign-context criticals never corroborated the verdict.
        assert!(!report.corroborated);
    }

    /// Spec test 1: an UPDATED package whose own code gains a single
    /// Critical/High `CredentialAccess` capability is a Notice — exit 0,
    /// excluded from the critical/malicious counts.
    #[test]
    fn updated_single_capability_is_notice() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_capability_package(&node_modules, "toolish", "1.0.0");
        let first = scan_with_baseline(&node_modules, &baseline);
        assert!(first.baseline_established);

        // A version bump plus the same single capability: a normal update.
        make_capability_package(&node_modules, "toolish", "1.1.0");
        let report = scan_with_baseline(&node_modules, &baseline);
        assert_eq!(report.updated_packages, 1);
        assert_eq!(report.flagged.len(), 1);
        let flagged = &report.flagged[0];
        assert_eq!(flagged.change, ChangeKind::Updated);
        assert!(!flagged.corroborated, "one capability never corroborates");
        assert_eq!(flagged.assessment, Assessment::Notice);
        assert_eq!(flagged.assessment_label(), "notice");
        assert!(!flagged.is_critical_alert());
        assert_eq!(report.malicious_packages, 0);
        assert_eq!(report.critical_packages, 0);
        assert_eq!(report.notice_packages, 1);
        assert_eq!(report.exit_code(), 0, "uncorroborated update exits 0");
        assert_eq!(report.banner_tone(), "info");
        // The raw verdict stays visible as muted secondary detail only.
        if !matches!(flagged.verdict, AvVerdict::Clean) {
            let note = flagged.heuristic_note().expect("note for non-clean raw");
            assert!(note.contains("uncorroborated"), "got: {note}");
        }
    }

    /// Spec test 2: an UPDATED package whose own code gains strong findings
    /// in >= 2 distinct categories (the actual malicious-update scenario)
    /// must still scream: Alert with the raw verdict, exit 5.
    #[test]
    fn updated_multi_category_worm_is_alert() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "alpha");
        let _ = scan_with_baseline(&node_modules, &baseline);

        // The "update" ships the worm combo (token harvest + whoami +
        // maintainer enumeration + npm publish) in its own postinstall.
        make_malicious_package(&node_modules, "alpha");
        let report = scan_with_baseline(&node_modules, &baseline);
        assert_eq!(report.updated_packages, 1);
        assert_eq!(report.flagged.len(), 1);
        let flagged = &report.flagged[0];
        assert_eq!(flagged.change, ChangeKind::Updated);
        assert!(flagged.corroborated, "worm combo spans multiple categories");
        assert_eq!(flagged.assessment, Assessment::Alert(AvVerdict::Malicious));
        assert!(flagged.is_critical_alert());
        assert_eq!(report.malicious_packages, 1);
        assert_eq!(report.alert_packages, 1);
        assert_eq!(report.exit_code(), 5, "corroborated malicious update is 5");
        assert_eq!(report.banner_tone(), "danger");
    }

    /// Spec test 3: an UPDATED package whose only strong findings live in
    /// benign contexts (dependency CI workflows, test fixtures) is a Notice —
    /// benign-context evidence is excluded from corroboration.
    #[test]
    fn updated_benign_context_evidence_stays_notice() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "traverse-ish");
        let _ = scan_with_baseline(&node_modules, &baseline);

        // Version bump; the wormy content arrives ONLY in the upstream CI
        // workflow and the shipped test fixture — the real-machine false
        // positive pattern (e.g. json-schema-traverse's publish.yml).
        let dir = node_modules.join("traverse-ish");
        write(
            &dir.join("package.json"),
            r#"{ "name": "traverse-ish", "version": "1.1.0", "main": "index.js" }"#,
        );
        write(
            &dir.join(".github/workflows/publish.yml"),
            "on: release\njobs:\n  publish:\n    steps:\n      - run: npm publish --access public\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n",
        );
        write(
            &dir.join("tests/fixture.js"),
            r"
const fs = require('fs');
const os = require('os');
const npmrcContent = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
const match = npmrcContent.match(/_authToken\s*=\s*(.+)/);
require('https').get('https://registry.npmjs.org/-/whoami');
require('child_process').execSync('npm publish --access public');
",
        );
        let report = scan_with_baseline(&node_modules, &baseline);
        assert_eq!(report.flagged.len(), 1);
        let flagged = &report.flagged[0];
        assert_eq!(flagged.change, ChangeKind::Updated);
        assert!(
            !flagged.corroborated,
            "benign-context evidence must not corroborate"
        );
        assert_eq!(flagged.assessment, Assessment::Notice);
        assert_eq!(report.critical_packages, 0);
        assert_eq!(report.exit_code(), 0);
    }

    /// Extension: a NEW package with an uncorroborated raw verdict (the
    /// freshly auto-installed extension case) is a Notice, not a red row.
    #[test]
    fn new_uncorroborated_package_is_notice() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "alpha");
        let _ = scan_with_baseline(&node_modules, &baseline);

        make_capability_package(&node_modules, "fresh-ext", "0.1.0");
        let report = scan_with_baseline(&node_modules, &baseline);
        assert_eq!(report.new_packages, 1);
        assert_eq!(report.flagged.len(), 1);
        let flagged = &report.flagged[0];
        assert_eq!(flagged.change, ChangeKind::New);
        assert_eq!(flagged.assessment, Assessment::Notice);
        assert!(!flagged.is_critical_alert());
        assert_eq!(report.malicious_packages, 0);
        assert_eq!(report.exit_code(), 0, "uncorroborated new package is 0");
        assert_eq!(report.banner_tone(), "info");
    }

    /// Extension: the first run must read as calm success when the installed
    /// set only has single-capability heuristic hits (npm-like tooling) —
    /// no Alert rows, exit 0, a muted capability tally.
    #[test]
    fn first_run_with_capability_packages_is_calm() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "left-pad-ish");
        make_capability_package(&node_modules, "npm-like", "10.0.0");

        let report = scan_with_baseline(&node_modules, &baseline);
        assert!(report.baseline_established);
        assert!(report.flagged.is_empty(), "no alert rows at calm baseline");
        assert_eq!(report.alert_packages, 0);
        assert!(report.baseline_capability_notes >= 1);
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.banner_tone(), "success");
        assert!(
            report.banner_headline().contains("trusted"),
            "got: {}",
            report.banner_headline()
        );
        assert!(
            report.summary_message().contains("Capabilities noted"),
            "got: {}",
            report.summary_message()
        );
    }

    /// Extension: a genuine multi-category worm still gets exactly one Alert
    /// at baseline establishment.
    #[test]
    fn first_run_with_worm_alerts_only_the_worm() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "left-pad-ish");
        make_capability_package(&node_modules, "npm-like", "10.0.0");
        make_malicious_package(&node_modules, "worm");

        let report = scan_with_baseline(&node_modules, &baseline);
        assert!(report.baseline_established);
        assert_eq!(report.flagged.len(), 1, "only the corroborated worm");
        assert_eq!(report.flagged[0].name, "worm");
        assert!(report.flagged[0].corroborated);
        assert!(report.flagged[0].is_alert());
        assert_eq!(report.banner_tone(), "danger");
        assert_eq!(report.exit_code(), 5);
    }

    /// The module invariant: across a mixed surfaced list, every red
    /// presentation is a tamper or a corroborated alert — nothing else.
    #[test]
    fn red_presentation_requires_tamper_or_corroboration() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        make_benign_package(&node_modules, "alpha");
        make_benign_package(&node_modules, "beta");
        let _ = scan_with_baseline(&node_modules, &baseline);

        // alpha: tampered (same version, new bytes). beta: updated with a
        // single capability. gamma: new worm (corroborated).
        write(
            &node_modules.join("alpha/index.js"),
            "module.exports = function add(a, b) { return a + b + 0; };\n",
        );
        make_capability_package(&node_modules, "beta", "2.0.0");
        make_malicious_package(&node_modules, "gamma");
        let report = scan_with_baseline(&node_modules, &baseline);
        assert_eq!(report.flagged.len(), 3);
        for package in &report.flagged {
            if package.is_alert() {
                assert!(
                    package.is_tampered() || package.corroborated,
                    "{} is an alert without tamper or corroboration",
                    package.name
                );
            }
        }
        // Alerts sort above the notice.
        assert!(report.flagged[0].is_alert());
        assert!(report.flagged[1].is_alert());
        assert_eq!(report.flagged[2].assessment, Assessment::Notice);
        assert_eq!(report.flagged[2].name, "beta");
        assert_eq!(report.exit_code(), 5);
    }

    /// A cancelled run must never establish a baseline (a partial package set
    /// cannot become the trusted reference).
    #[test]
    fn cancelled_run_does_not_establish_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let node_modules = tmp.path().join("node_modules");
        let baseline = tmp.path().join("security_baseline.json");
        for idx in 0..8 {
            make_benign_package(&node_modules, &format!("pkg-{idx}"));
        }
        let cancel = AtomicBool::new(true);
        let report = scan_targets_with_options(
            vec![node_target(&node_modules)],
            &baseline_options(&baseline),
            Some(&cancel),
            &|_| {},
        );
        assert!(report.incomplete);
        assert!(!report.baseline_established);
        assert!(!baseline.exists());
    }
}
