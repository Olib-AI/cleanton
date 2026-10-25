//! Offline advisory matching: is this *version* known to be broken?
//!
//! The antivirus engines answer one half of the supply-chain question — "does
//! this package's code look malicious?" — by reading files. They cannot answer
//! the other half, which is what actually dominates the public CVE stream: "is
//! this installed version known to be vulnerable?" That answer is a fact about
//! a (ecosystem, package, version) triple, not about file contents, and it
//! changes weekly.
//!
//! So this module keeps a small ADVISORY DATABASE and matches installed
//! versions against it. The database ships with a curated snapshot (see
//! `data/advisories.json`) and is EXTENDED at runtime from
//! `~/.config/cleanton/advisories/*.json`, which accepts an OSV-compatible
//! subset. Dropping an OSV export there is the update path; nothing here
//! touches the network.
//!
//! Design rules:
//!
//! * Version checks are METADATA ONLY. Enumerating a Cargo registry or a gem
//!   tree and running the full static scanner over every crate would cost more
//!   CPU than the cleanup scan users actually asked for, so those ecosystems
//!   are matched by version and never content-scanned implicitly.
//! * Nothing here removes, quarantines, or modifies anything. A match is
//!   reported and nothing else, exactly like the rest of the security engine.
//! * Every range is half-open `[introduced, fixed)`. An advisory without
//!   `fixed` matches everything from `introduced` onward, which is what OSV
//!   expresses with an empty `fixed` event.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;

use crate::security::Severity;

/// Package ecosystem an advisory applies to. The string forms are the OSV
/// ecosystem names so a user-supplied OSV export loads without translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ecosystem {
    Npm,
    PyPI,
    RubyGems,
    CratesIo,
    Go,
    Maven,
    Packagist,
    NuGet,
    Homebrew,
}

impl Ecosystem {
    /// OSV spelling of the ecosystem.
    #[must_use]
    pub const fn osv_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPI => "PyPI",
            Self::RubyGems => "RubyGems",
            Self::CratesIo => "crates.io",
            Self::Go => "Go",
            Self::Maven => "Maven",
            Self::Packagist => "Packagist",
            Self::NuGet => "NuGet",
            Self::Homebrew => "Homebrew",
        }
    }

    /// Short label shown next to a match.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPI => "PyPI",
            Self::RubyGems => "RubyGems",
            Self::CratesIo => "crates.io",
            Self::Go => "Go modules",
            Self::Maven => "Maven",
            Self::Packagist => "Packagist",
            Self::NuGet => "NuGet",
            Self::Homebrew => "Homebrew",
        }
    }

    /// Parse an OSV ecosystem string (accepts the common aliases too).
    #[must_use]
    pub fn from_osv(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "npm" => Some(Self::Npm),
            "pypi" => Some(Self::PyPI),
            "rubygems" => Some(Self::RubyGems),
            "crates.io" | "cargo" => Some(Self::CratesIo),
            "go" => Some(Self::Go),
            "maven" => Some(Self::Maven),
            "packagist" | "composer" => Some(Self::Packagist),
            "nuget" => Some(Self::NuGet),
            "homebrew" => Some(Self::Homebrew),
            _ => None,
        }
    }
}

/// An installed package name + version + ecosystem, as advisory matching sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSubject {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

impl PackageSubject {
    #[must_use]
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            version: version.into(),
        }
    }

    /// The name as an advisory would spell it. Python and npm both allow the
    /// separators `-`, `_`, and `.` to be used interchangeably, so matching is
    /// done on the normalized form to avoid missing `typing_extensions` for a
    /// `typing-extensions` advisory.
    fn normalized_name(&self) -> String {
        normalize_package_name(&self.name)
    }
}

/// Normalize a package name for comparison (case-insensitive, separators folded).
#[must_use]
pub fn normalize_package_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(['_', '.'], "-")
}

/// Half-open affected range `[introduced, fixed)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedRange {
    /// First affected version (`0` means "every version before `fixed`").
    pub introduced: String,
    /// First *unaffected* version. `None` means "still affected today".
    pub fixed: Option<String>,
}

impl AffectedRange {
    fn matches(&self, version: &str) -> bool {
        let at_or_after_introduced =
            self.introduced == "0" || compare_versions(version, &self.introduced) != Ordering::Less;
        if !at_or_after_introduced {
            return false;
        }
        match &self.fixed {
            Some(fixed) => compare_versions(version, fixed) == Ordering::Less,
            None => true,
        }
    }

    /// Human-readable range, e.g. `>= 1.0.0, < 1.6.1`.
    #[must_use]
    pub fn display(&self) -> String {
        match &self.fixed {
            Some(fixed) if self.introduced == "0" => format!("< {fixed}"),
            Some(fixed) => format!(">= {}, < {fixed}", self.introduced),
            None if self.introduced == "0" => "all versions".to_owned(),
            None => format!(">= {}", self.introduced),
        }
    }
}

/// One advisory record.
#[derive(Debug, Clone)]
pub struct Advisory {
    /// Primary identifier (`GHSA-…`, `CVE-…`, `RUSTSEC-…`).
    pub id: String,
    /// Secondary identifiers; searched as well when the user quotes one.
    pub aliases: Vec<String>,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub severity: Severity,
    pub summary: String,
    pub ranges: Vec<AffectedRange>,
    /// `true` when the published versions themselves were malicious rather
    /// than merely vulnerable (event-stream, ua-parser-js). These are reported
    /// at the severity they carry and never downgraded by context.
    pub malicious: bool,
    /// Reference URLs (rendered as plain text; never fetched).
    pub references: Vec<String>,
}

impl Advisory {
    /// True when `subject` falls inside one of this advisory's ranges.
    #[must_use]
    pub fn matches(&self, subject: &PackageSubject) -> bool {
        if self.ecosystem != subject.ecosystem
            || normalize_package_name(&self.package) != subject.normalized_name()
        {
            return false;
        }
        self.ranges
            .iter()
            .any(|range| range.matches(&subject.version))
    }

    /// One-line "what to do" copy: the first fixed version, when there is one.
    #[must_use]
    pub fn remediation(&self) -> String {
        let package = self.package.as_str();
        let fixed = self
            .ranges
            .iter()
            .filter_map(|range| range.fixed.as_deref())
            .min_by(|left, right| compare_versions(left, right));
        match fixed {
            Some(fixed) => format!("Upgrade {package} to {fixed} or later."),
            None => format!("No fixed version is published for {package}. Remove or replace it."),
        }
    }
}

/// A match: the installed subject plus every advisory that hits it.
#[derive(Debug, Clone)]
pub struct AdvisoryMatch {
    pub subject: PackageSubject,
    pub advisories: Vec<Advisory>,
}

impl AdvisoryMatch {
    /// Worst severity among the matching advisories.
    #[must_use]
    pub fn worst_severity(&self) -> Severity {
        self.advisories
            .iter()
            .map(|advisory| advisory.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    /// True when any matching advisory is a published-malicious version.
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.advisories.iter().any(|advisory| advisory.malicious)
    }

    /// Comma-joined identifiers for display.
    #[must_use]
    pub fn id_list(&self) -> String {
        self.advisories
            .iter()
            .map(|advisory| advisory.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The advisory set: a bundled snapshot plus any user-supplied OSV exports.
#[derive(Debug, Default, Clone)]
pub struct AdvisoryDatabase {
    advisories: Vec<Advisory>,
}

impl AdvisoryDatabase {
    /// The bundled snapshot, parsed once on first use.
    ///
    /// A malformed bundle is not fatal: the database loads empty and the scan
    /// continues, because a security scan that fails open on a data-file typo
    /// is worse than one that reports no version matches.
    #[must_use]
    pub fn embedded() -> &'static Self {
        static EMBEDDED: OnceLock<AdvisoryDatabase> = OnceLock::new();
        EMBEDDED.get_or_init(|| {
            let mut database = Self::default();
            database.extend_from_json(BUNDLED_ADVISORIES);
            database
        })
    }

    /// Bundled snapshot plus `*.json` files from `directory` (missing directory
    /// is fine). Bad files are skipped, never fatal.
    #[must_use]
    pub fn with_overrides(directory: &Path) -> Self {
        let mut database = Self::embedded().clone();
        let Ok(entries) = std::fs::read_dir(directory) else {
            return database;
        };
        let mut paths = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            database.extend_from_json(&contents);
        }
        database
    }

    /// The user extension directory (`~/.config/cleanton/advisories`).
    #[must_use]
    pub fn user_override_dir() -> Option<PathBuf> {
        let home = std::env::var_os("HOME")?;
        Some(PathBuf::from(home).join(".config/cleanton/advisories"))
    }

    /// Bundled snapshot plus the user's override directory, when it exists.
    #[must_use]
    pub fn load() -> Self {
        match Self::user_override_dir() {
            Some(directory) => Self::with_overrides(&directory),
            None => Self::embedded().clone(),
        }
    }

    /// Number of loaded advisories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.advisories.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }

    /// Append advisories from a JSON document. Accepts both this module's
    /// compact shape (`{"advisories": [...]}`) and a plain OSV array
    /// (`[{"id": ..., "affected": [...]}, ...]`), because "drop in an OSV
    /// export" is the documented update path.
    pub fn extend_from_json(&mut self, contents: &str) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(contents) else {
            return;
        };
        let records = match value {
            serde_json::Value::Array(records) => records,
            serde_json::Value::Object(ref object) => object
                .get("advisories")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default(),
            _ => return,
        };
        for record in &records {
            for advisory in parse_advisory(record) {
                self.advisories.push(advisory);
            }
        }
    }

    /// Advisories affecting `subject`.
    #[must_use]
    pub fn matches(&self, subject: &PackageSubject) -> Vec<Advisory> {
        self.advisories
            .iter()
            .filter(|advisory| advisory.matches(subject))
            .cloned()
            .collect()
    }

    /// Match a subject, returning only when at least one advisory hits.
    #[must_use]
    pub fn check(&self, subject: &PackageSubject) -> Option<AdvisoryMatch> {
        let advisories = self.matches(subject);
        if advisories.is_empty() {
            None
        } else {
            Some(AdvisoryMatch {
                subject: subject.clone(),
                advisories,
            })
        }
    }
}

/// Compact advisory record (also accepted inside an OSV array entry).
#[derive(Deserialize)]
struct RawAdvisory {
    #[serde(default)]
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    ecosystem: Option<String>,
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    malicious: bool,
    #[serde(default)]
    references: Vec<ValueOrString>,
    /// Compact ranges: `{"introduced": "1.0.0", "fixed": "1.6.1"}`.
    #[serde(default)]
    ranges: Vec<RawRange>,
    /// OSV ranges: `{"type": "SEMVER", "events": [{"introduced": ...}, {"fixed": ...}]}`.
    #[serde(default)]
    affected: Vec<RawAffected>,
}

#[derive(Deserialize)]
struct RawRange {
    #[serde(default = "zero_version")]
    introduced: String,
    #[serde(default)]
    fixed: Option<String>,
}

#[derive(Deserialize)]
struct RawAffected {
    #[serde(default)]
    package: Option<RawPackage>,
    #[serde(default)]
    ranges: Vec<RawOsvRange>,
}

#[derive(Deserialize)]
struct RawPackage {
    #[serde(default)]
    ecosystem: Option<String>,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct RawOsvRange {
    #[serde(default)]
    events: Vec<RawEvent>,
}

#[derive(Deserialize)]
struct RawEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
}

/// Reference entries are either a bare URL or `{"type": ..., "url": ...}`.
#[derive(Deserialize)]
#[serde(untagged)]
enum ValueOrString {
    Text(String),
    Object { url: Option<String> },
}

impl ValueOrString {
    fn url(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text.as_str()),
            Self::Object { url } => url.as_deref(),
        }
    }
}

fn zero_version() -> String {
    "0".to_owned()
}

/// Parse one record in either shape. Returns one advisory per affected
/// (ecosystem, package) pair so an OSV entry naming several packages becomes
/// several matchable advisories.
fn parse_advisory(value: &serde_json::Value) -> Vec<Advisory> {
    let Ok(raw) = RawAdvisory::deserialize(value) else {
        return Vec::new();
    };
    let severity = raw
        .severity
        .as_deref()
        .map_or(Severity::High, severity_from_label);
    let references = raw
        .references
        .iter()
        .filter_map(ValueOrString::url)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let compact_ranges = raw
        .ranges
        .iter()
        .map(|range| AffectedRange {
            introduced: range.introduced.clone(),
            fixed: range.fixed.clone(),
        })
        .collect::<Vec<_>>();

    // OSV shape: ecosystem/package live inside each `affected` entry.
    let mut parsed = Vec::new();
    for affected in &raw.affected {
        let Some(package) = affected.package.as_ref() else {
            continue;
        };
        let Some(ecosystem) = package.ecosystem.as_deref().and_then(Ecosystem::from_osv) else {
            continue;
        };
        if package.name.is_empty() {
            continue;
        }
        let ranges = affected
            .ranges
            .iter()
            .filter_map(|range| {
                let mut introduced: Option<String> = None;
                let mut fixed: Option<String> = None;
                for event in &range.events {
                    if let Some(value) = &event.introduced {
                        introduced.get_or_insert_with(|| value.clone());
                    }
                    if let Some(value) = &event.fixed {
                        fixed = Some(value.clone());
                    }
                }
                Some(AffectedRange {
                    introduced: introduced.unwrap_or_else(zero_version),
                    fixed,
                })
            })
            .collect::<Vec<_>>();
        if ranges.is_empty() {
            continue;
        }
        parsed.push(Advisory {
            id: display_id(&raw),
            aliases: raw.aliases.clone(),
            ecosystem,
            package: package.name.clone(),
            severity,
            summary: summary_for(&raw),
            ranges,
            malicious: raw.malicious,
            references: references.clone(),
        });
    }

    // Compact shape: ecosystem/package at the top level.
    if let (Some(ecosystem), Some(package)) = (
        raw.ecosystem.as_deref().and_then(Ecosystem::from_osv),
        raw.package.clone().filter(|name| !name.is_empty()),
    ) && !compact_ranges.is_empty()
    {
        parsed.push(Advisory {
            id: display_id(&raw),
            aliases: raw.aliases.clone(),
            ecosystem,
            package,
            severity,
            summary: summary_for(&raw),
            ranges: compact_ranges,
            malicious: raw.malicious,
            references,
        });
    }
    parsed
}

fn display_id(raw: &RawAdvisory) -> String {
    if !raw.id.is_empty() {
        return raw.id.clone();
    }
    raw.aliases
        .first()
        .cloned()
        .unwrap_or_else(|| "unlabelled advisory".to_owned())
}

fn summary_for(raw: &RawAdvisory) -> String {
    if !raw.summary.is_empty() {
        return raw.summary.clone();
    }
    raw.details.clone().unwrap_or_default()
}

fn severity_from_label(label: &str) -> Severity {
    match label.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "moderate" | "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::High,
    }
}

/// Compare two version strings the way package managers order them.
///
/// Deliberately pragmatic rather than a full semver implementation: this only
/// has to decide "is this installed version inside a published range", and the
/// ranges are published in the ecosystem's own loose style (`1.2`, `1.2.3`,
/// `v1.2.3`, `1.2.3.4`, `1.2.3-rc1`, `2.2.8.1`). Rules:
///
/// * a leading `v`/`=` and surrounding whitespace are ignored;
/// * dot-separated segments are compared numerically when both are numeric,
///   otherwise lexicographically, and a missing segment counts as `0`
///   (so `1.2` == `1.2.0`);
/// * a pre-release suffix (`-alpha`, `-rc1`) sorts BELOW the release version;
/// * build metadata (`+build`) is ignored.
#[must_use]
pub fn compare_versions(left: &str, right: &str) -> Ordering {
    let (left_core, left_pre) = split_prerelease(left);
    let (right_core, right_pre) = split_prerelease(right);
    let left_segments = left_core.split('.').collect::<Vec<_>>();
    let right_segments = right_core.split('.').collect::<Vec<_>>();
    let length = left_segments.len().max(right_segments.len());
    for index in 0..length {
        let left_segment = left_segments.get(index).copied().unwrap_or("0");
        let right_segment = right_segments.get(index).copied().unwrap_or("0");
        let ordering = match (numeric_prefix(left_segment), numeric_prefix(right_segment)) {
            (Some(left_number), Some(right_number)) => left_number.cmp(&right_number),
            _ => left_segment.cmp(right_segment),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    match (left_pre, right_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left_pre), Some(right_pre)) => left_pre.cmp(right_pre),
    }
}

fn split_prerelease(version: &str) -> (String, Option<String>) {
    let trimmed = version
        .trim()
        .trim_start_matches(['v', 'V', '='])
        .trim()
        // Build metadata is not part of precedence.
        .split('+')
        .next()
        .unwrap_or_default();
    match trimmed.split_once('-') {
        Some((core, pre)) => (core.to_owned(), Some(pre.to_ascii_lowercase())),
        None => (trimmed.to_owned(), None),
    }
}

fn numeric_prefix(segment: &str) -> Option<u64> {
    let digits = segment
        .char_indices()
        .take_while(|(_, character)| character.is_ascii_digit())
        .map(|(index, _)| index)
        .last()?;
    segment.get(..=digits)?.parse().ok()
}

/// The bundled snapshot. Kept in a separate file so refreshing it is a data
/// change with a visible diff rather than a code change.
const BUNDLED_ADVISORIES: &str = include_str!("../data/advisories.json");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ordering_matches_package_manager_expectations() {
        assert_eq!(compare_versions("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(compare_versions("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(compare_versions("v1.2.4", "1.2.3"), Ordering::Greater);
        assert_eq!(compare_versions("1.10.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("2.2.8.1", "2.2.8"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0-rc1", "1.0.0"), Ordering::Less);
        assert_eq!(compare_versions("1.0.0+build5", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn range_matching_is_half_open() {
        let range = AffectedRange {
            introduced: "4.0.0".to_owned(),
            fixed: Some("4.17.21".to_owned()),
        };
        assert!(!range.matches("3.10.1"));
        assert!(range.matches("4.0.0"));
        assert!(range.matches("4.17.20"));
        assert!(!range.matches("4.17.21"));
        assert_eq!(range.display(), ">= 4.0.0, < 4.17.21");
    }

    #[test]
    fn open_ended_range_never_expires() {
        let range = AffectedRange {
            introduced: "0".to_owned(),
            fixed: None,
        };
        assert!(range.matches("0.0.1"));
        assert!(range.matches("99.0.0"));
        assert_eq!(range.display(), "all versions");
    }

    #[test]
    fn bundled_database_loads_and_matches_a_known_range() {
        let database = AdvisoryDatabase::embedded();
        assert!(!database.is_empty(), "bundled snapshot must not be empty");
        let lodash = PackageSubject::new(Ecosystem::Npm, "lodash", "4.17.20");
        let matched = database.matches(&lodash);
        assert!(
            matched.iter().any(|advisory| advisory.package == "lodash"),
            "lodash 4.17.20 must match its template-injection advisory"
        );
        let fixed = PackageSubject::new(Ecosystem::Npm, "lodash", "4.17.21");
        assert!(database.matches(&fixed).is_empty());
    }

    #[test]
    fn ecosystem_mismatch_never_matches() {
        let database = AdvisoryDatabase::embedded();
        // Same name, wrong ecosystem.
        let wrong = PackageSubject::new(Ecosystem::PyPI, "lodash", "4.17.20");
        assert!(database.matches(&wrong).is_empty());
    }

    #[test]
    fn osv_array_shape_is_accepted() {
        let osv = r#"[{
            "id": "GHSA-test-0000-0000",
            "aliases": ["CVE-2099-0001"],
            "summary": "Example",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "Example_Package"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}]
            }]
        }]"#;
        let mut database = AdvisoryDatabase::default();
        database.extend_from_json(osv);
        assert_eq!(database.len(), 1);
        let subject = PackageSubject::new(Ecosystem::Npm, "example-package", "1.1.0");
        assert!(database.check(&subject).is_some());
        let safe = PackageSubject::new(Ecosystem::Npm, "example-package", "1.2.0");
        assert!(database.check(&safe).is_none());
    }

    #[test]
    fn malformed_json_is_ignored_rather_than_fatal() {
        let mut database = AdvisoryDatabase::default();
        database.extend_from_json("{not json");
        database.extend_from_json("[]");
        assert!(database.is_empty());
    }

    #[test]
    fn remediation_names_the_first_fixed_version() {
        let advisory = Advisory {
            id: "GHSA-x".to_owned(),
            aliases: Vec::new(),
            ecosystem: Ecosystem::Npm,
            package: "example".to_owned(),
            severity: Severity::High,
            summary: "Example".to_owned(),
            ranges: vec![
                AffectedRange {
                    introduced: "1.0.0".to_owned(),
                    fixed: Some("1.4.0".to_owned()),
                },
                AffectedRange {
                    introduced: "2.0.0".to_owned(),
                    fixed: Some("2.1.3".to_owned()),
                },
            ],
            malicious: false,
            references: Vec::new(),
        };
        assert_eq!(advisory.remediation(), "Upgrade example to 1.4.0 or later.");
    }
}
