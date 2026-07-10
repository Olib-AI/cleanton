//! Core result types shared by every detection engine and the scanner: a
//! [`Finding`] (one piece of evidence), its [`Severity`]/[`Confidence`]/
//! [`ThreatCategory`] classifiers, and the aggregated [`ScanReport`]/[`Verdict`].
//!
//! These types are the stable contract that detection engines emit and the
//! scoring policy consumes. Engines MUST NOT depend on each other — only on
//! this module and [`crate::engine`].

use serde::{Deserialize, Serialize};

/// How dangerous a single finding is on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational; not a threat by itself (e.g. a noted capability).
    Info,
    /// Minor concern; common in benign code but worth recording.
    Low,
    /// Notable; suspicious in context.
    Medium,
    /// Strong indicator of malicious intent.
    High,
    /// Near-certain malware / active compromise indicator.
    Critical,
}

impl Severity {
    /// Base risk weight (0..=100) used by the scoring policy.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 8,
            Severity::Medium => 25,
            Severity::High => 60,
            Severity::Critical => 100,
        }
    }
}

/// How confident the engine is that the finding is a true positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    /// Multiplier (0.0..=1.0) applied to the severity weight in scoring.
    pub fn factor(self) -> f32 {
        match self {
            Confidence::Low => 0.4,
            Confidence::Medium => 0.7,
            Confidence::High => 1.0,
        }
    }
}

/// The class of threat a finding belongs to. Used for reporting, policy, and
/// de-duplication. Keep this list general (not npm-specific) — supply-chain is
/// one category among many.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    /// Matched a known-malware signature (hash or rule).
    KnownMalware,
    /// Generic supply-chain attack indicator.
    SupplyChain,
    /// Malicious / suspicious package install or lifecycle script.
    InstallScript,
    /// Obfuscated / encoded code intended to hide behavior.
    Obfuscation,
    /// Data exfiltration (sending local data to a remote endpoint).
    Exfiltration,
    /// Arbitrary command / process execution.
    CommandExecution,
    /// Suspicious outbound network activity / C2.
    Network,
    /// Reading/writing sensitive files or persistence.
    FilesystemAbuse,
    /// Access to credentials, tokens, env secrets, keychains.
    CredentialAccess,
    /// Cryptocurrency wallet / clipboard hijack stealer.
    CryptoStealer,
    /// Name confusingly similar to a popular package (typosquat).
    Typosquatting,
    /// Internal/scoped name published publicly (dependency confusion).
    DependencyConfusion,
    /// A suspicious string / IOC (URL, IP, wallet, webhook).
    Ioc,
    /// Packed / high-entropy payload.
    Packer,
    /// Native executable indicator (ELF/PE/Mach-O, shellcode).
    NativeBinary,
    /// Anything not covered above.
    Other,
}

/// Where in the scanned target a finding was located.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileLocation {
    /// Path relative to the scan root (or archive-internal path).
    pub path: String,
    /// 1-based line number, if applicable.
    pub line: Option<usize>,
    /// Byte offset within the file, if applicable.
    pub offset: Option<usize>,
}

impl FileLocation {
    /// Location at a file path with no line/offset.
    pub fn file(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            line: None,
            offset: None,
        }
    }
    /// Location at a file path and 1-based line.
    pub fn at_line(path: impl Into<String>, line: usize) -> Self {
        Self {
            path: path.into(),
            line: Some(line),
            offset: None,
        }
    }
}

/// One piece of evidence emitted by a detection engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Name of the engine that produced this finding (e.g. `"hashdb"`).
    pub engine: String,
    /// Stable rule/signature identifier, if the engine has one
    /// (e.g. `"NPM_POSTINSTALL_CURL_BASH"`). Used for de-dup and allowlisting.
    pub rule_id: Option<String>,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Short human-readable title.
    pub title: String,
    /// Longer explanation of why this is suspicious.
    pub description: String,
    /// Where it was found.
    pub location: Option<FileLocation>,
    /// A SHORT, sanitized snippet of the matched content (truncate to keep
    /// reports small; never include secrets verbatim).
    pub evidence: Option<String>,
}

impl Finding {
    /// Build a finding with the required fields; chain the `with_*` setters for
    /// the optional ones.
    pub fn new(
        engine: impl Into<String>,
        category: ThreatCategory,
        severity: Severity,
        confidence: Confidence,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            engine: engine.into(),
            rule_id: None,
            category,
            severity,
            confidence,
            title: title.into(),
            description: description.into(),
            location: None,
            evidence: None,
        }
    }

    #[must_use]
    pub fn with_rule_id(mut self, id: impl Into<String>) -> Self {
        self.rule_id = Some(id.into());
        self
    }

    #[must_use]
    pub fn with_location(mut self, loc: FileLocation) -> Self {
        self.location = Some(loc);
        self
    }

    /// Attach a snippet of evidence, truncated to `max` bytes (on a char
    /// boundary) so reports stay small.
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<String>, max: usize) -> Self {
        let mut s = evidence.into();
        if s.len() > max {
            let mut end = max;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            s.truncate(end);
            s.push('…');
        }
        self.evidence = Some(s);
        self
    }
}

/// The overall conclusion for a scanned target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No findings, or only informational ones.
    Clean,
    /// Findings present that warrant review / blocking by policy.
    Suspicious,
    /// High-confidence malware; must be blocked.
    Malicious,
}

/// Per-engine execution stats for the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStat {
    pub engine: String,
    pub findings: usize,
    pub duration_ms: u64,
}

/// The aggregated result of scanning a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// What was scanned (path or package spec).
    pub target: String,
    pub verdict: Verdict,
    /// Aggregate risk score 0..=100.
    pub score: u32,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub duration_ms: u64,
    pub engine_stats: Vec<EngineStat>,
    /// Non-fatal problems encountered (e.g. a file skipped for size). Empty
    /// values are positive evidence — never omit via serde skip.
    pub errors: Vec<String>,
}

impl ScanReport {
    /// True when policy says this target must be blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self.verdict, Verdict::Malicious)
    }
}
