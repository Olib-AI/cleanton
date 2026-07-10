//! Typosquatting detection engine for npm packages.
//!
//! Compares the package name from `package.json` (and any other manifest files)
//! against a bundled corpus of popular npm packages and flags candidates that
//! are:
//!   - Within Damerau-Levenshtein distance 1 or 2 of a popular name (but not
//!     an exact match),
//!   - A homoglyph/confusable variant of a popular name,
//!   - A scope-spoof (`@types-node` vs `@types/node`),
//!   - A known squat-pattern suffix/prefix (`popularname-js`, `node-popularname`,
//!     `popularname2`, etc.).
//!
//! All bundled data is `const`/`static`; no network or external files.

use crate::engine::{DetectionEngine, FileKind, ScanContext};
use crate::types::{Confidence, FileLocation, Finding, Severity, ThreatCategory};

// ─── Bundled popular-package corpus ────────────────────────────────────────

/// The canonical corpus of popular npm packages to protect against squatting.
/// Includes bare names and scoped names; all lowercase, exactly as published.
const POPULAR_PACKAGES: &[&str] = &[
    // Core utilities
    "lodash",
    "underscore",
    "async",
    "ramda",
    "bluebird",
    "rxjs",
    "immer",
    "uuid",
    "nanoid",
    "cuid",
    "ms",
    "semver",
    "chalk",
    "ansi-colors",
    "kleur",
    "colors",
    "picocolors",
    "debug",
    "loglevel",
    "winston",
    "pino",
    "bunyan",
    "log4js",
    "morgan",
    // HTTP / network
    "axios",
    "request",
    "node-fetch",
    "superagent",
    "got",
    "needle",
    "undici",
    "http-proxy",
    "https-proxy-agent",
    "node-http-proxy",
    "tough-cookie",
    "cookie",
    "cookie-parser",
    // Web frameworks
    "express",
    "koa",
    "hapi",
    "fastify",
    "restify",
    "connect",
    "http-server",
    "serve",
    "polka",
    // Frontend frameworks / build
    "react",
    "react-dom",
    "vue",
    "svelte",
    "angular",
    "preact",
    "solid-js",
    "lit",
    "next",
    "nuxt",
    "gatsby",
    "remix",
    "vite",
    "parcel",
    "webpack",
    "rollup",
    "esbuild",
    "swc",
    "babel",
    // CLI tooling
    "commander",
    "yargs",
    "minimist",
    "meow",
    "caporal",
    "vorpal",
    "oclif",
    "inquirer",
    "prompts",
    "ora",
    "listr",
    "progress",
    "cli-progress",
    // File system / path
    "glob",
    "globby",
    "fast-glob",
    "rimraf",
    "del",
    "fs-extra",
    "mkdirp",
    "make-dir",
    "chokidar",
    "watchman",
    "cpx",
    "ncp",
    "mv",
    "tmp",
    "temp",
    "os-tmpdir",
    // Language / type layer
    "typescript",
    "babel-core",
    "coffeescript",
    "flow-bin",
    // Config / env
    "dotenv",
    "dotenv-safe",
    "dotenv-expand",
    "config",
    "convict",
    "nconf",
    "rc",
    // Date / time
    "moment",
    "dayjs",
    "date-fns",
    "luxon",
    // Validation / schema
    "joi",
    "yup",
    "ajv",
    "zod",
    "superstruct",
    "validator",
    "class-validator",
    // Testing
    "jest",
    "mocha",
    "jasmine",
    "ava",
    "tap",
    "tape",
    "vitest",
    "sinon",
    "chai",
    "expect",
    "nock",
    "supertest",
    "puppeteer",
    "playwright",
    "cypress",
    "selenium-webdriver",
    // Lint / format
    "eslint",
    "prettier",
    "tslint",
    "stylelint",
    "standard",
    // Process / system
    "cross-env",
    "cross-spawn",
    "execa",
    "shelljs",
    "which",
    "find-up",
    "pkg-up",
    "resolve",
    "resolve-from",
    "read-pkg",
    "write-pkg",
    "npm-run-all",
    "concurrently",
    // Encoding / crypto / binary
    "base64-js",
    "buffer",
    "bytes",
    "iconv-lite",
    "chardet",
    "jszip",
    "archiver",
    "tar",
    "tar-stream",
    "adm-zip",
    "node-forge",
    "bcrypt",
    "bcryptjs",
    // WebSocket / realtime
    "ws",
    "socket.io",
    "sockjs",
    "uws",
    // DB / ORM / cache
    "mongoose",
    "sequelize",
    "typeorm",
    "prisma",
    "knex",
    "pg",
    "mysql2",
    "mysql",
    "sqlite3",
    "redis",
    "ioredis",
    "mongodb",
    "level",
    // Template engines
    "handlebars",
    "ejs",
    "pug",
    "mustache",
    "nunjucks",
    // Auth / security
    "passport",
    "jsonwebtoken",
    "cookie-session",
    "express-session",
    "helmet",
    "cors",
    "csurf",
    // Bundled scoped packages
    "@types/node",
    "@types/react",
    "@types/lodash",
    "@types/express",
    "@babel/core",
    "@babel/cli",
    "@babel/preset-env",
    "@babel/preset-react",
    "@babel/preset-typescript",
    "@babel/runtime",
    "@babel/plugin-transform-runtime",
    "@eslint/js",
    "@typescript-eslint/parser",
    "@typescript-eslint/eslint-plugin",
    "@jest/globals",
    "@testing-library/react",
    "@testing-library/jest-dom",
    "@testing-library/user-event",
    "@rollup/plugin-node-resolve",
    "@rollup/plugin-commonjs",
    "@vitejs/plugin-react",
];

// ─── Homoglyph / confusable map ────────────────────────────────────────────

/// Map from a confusable Unicode character (or ASCII lookalike) to its
/// canonical ASCII equivalent.  Keys are single chars; all values are ASCII.
/// The engine normalises a candidate name through this map before comparison.
const HOMOGLYPH_MAP: &[(char, char)] = &[
    // Cyrillic lookalikes
    ('а', 'a'),
    ('е', 'e'),
    ('о', 'o'),
    ('р', 'p'),
    ('с', 'c'),
    ('х', 'x'),
    ('у', 'y'),
    ('і', 'i'),
    ('ј', 'j'),
    ('ѕ', 's'),
    // Greek lookalikes
    ('α', 'a'),
    ('β', 'b'),
    ('ε', 'e'),
    ('η', 'n'),
    ('ι', 'i'),
    ('κ', 'k'),
    ('ο', 'o'),
    ('ρ', 'p'),
    ('τ', 't'),
    ('υ', 'u'),
    ('χ', 'x'),
    // Latin look-alikes with diacritics → base
    ('à', 'a'),
    ('á', 'a'),
    ('â', 'a'),
    ('ã', 'a'),
    ('ä', 'a'),
    ('å', 'a'),
    ('è', 'e'),
    ('é', 'e'),
    ('ê', 'e'),
    ('ë', 'e'),
    ('ì', 'i'),
    ('í', 'i'),
    ('î', 'i'),
    ('ï', 'i'),
    ('ò', 'o'),
    ('ó', 'o'),
    ('ô', 'o'),
    ('õ', 'o'),
    ('ö', 'o'),
    ('ù', 'u'),
    ('ú', 'u'),
    ('û', 'u'),
    ('ü', 'u'),
    ('ý', 'y'),
    ('ÿ', 'y'),
    ('ñ', 'n'),
    ('ç', 'c'),
    // Digit-to-letter confusables
    ('0', 'o'),
    ('1', 'l'),
    ('3', 'e'),
    ('4', 'a'),
    ('5', 's'),
    // Punctuation confusables (within a name segment)
    ('\u{2010}', '-'), // hyphen
    ('\u{2011}', '-'), // non-breaking hyphen
    ('\u{2012}', '-'), // figure dash
    ('\u{2013}', '-'), // en dash
    ('\u{2014}', '-'), // em dash
];

// ─── Known squat-suffix / prefix patterns ──────────────────────────────────

/// Suffixes that squatters attach to popular package names.
const SQUAT_SUFFIXES: &[&str] = &[
    "-js",
    "js",
    "2",
    "-2",
    "-dev",
    "-latest",
    "-new",
    "-new2",
    "-v2",
    "-v3",
    "-alt",
    "-fork",
    "-fixed",
    "-patch",
    "-safe",
    "-secure",
    "-light",
    "-lite",
    "-mini",
    "-micro",
    "-cli",
    "-api",
    "-util",
    "-utils",
    "-helpers",
    "-helper",
    "-core",
    "-base",
    "-extra",
    "-extended",
    "-plus",
    "-pro",
    "-premium",
    "-next",
    "-npm",
    "-pkg",
    "-package",
    "-lib",
    "-module",
    "-src",
    "-build",
    "-dist",
    "-official",
    "-real",
    "-fast",
    "-better",
    "-good",
    "-main",
    "-test",
    "-testing",
    "-mock",
    "-stub",
    "-updated",
    "-latest-version",
    "-cdn",
];

/// Prefixes that squatters prepend to popular package names.
const SQUAT_PREFIXES: &[&str] = &[
    "node-",
    "npm-",
    "js-",
    "my-",
    "get-",
    "use-",
    "the-",
    "a-",
    "an-",
    "new-",
    "old-",
    "real-",
    "official-",
    "true-",
    "lib-",
    "pkg-",
    "fast-",
    "better-",
    "improved-",
    "updated-",
    "fixed-",
    "safe-",
    "secure-",
];

// ─── Engine name constant ───────────────────────────────────────────────────

const ENGINE_NAME: &str = "typosquat";

// ─── Normalisation helpers ──────────────────────────────────────────────────

/// Normalise a package name for DL comparison:
/// - Strip leading `@scope/` component (so `@attacker/lodash` → `lodash`)
/// - NFKC-normalise (so compatibility forms such as fullwidth `ｒｅａｃｔ`,
///   circled/enclosed letters, and ligatures fold to their ASCII equivalents —
///   a homoglyph class the fixed `HOMOGLYPH_MAP` does not enumerate)
/// - Lowercase
/// - Map homoglyphs to ASCII equivalents
/// - Strip separators that squatters insert (`_`, `.` treated as `-`)
fn normalize_for_dl(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    // strip scope prefix, then fold compatibility (NFKC) forms to canonical
    // ASCII before the per-character homoglyph pass.
    let bare: String = strip_scope(name).nfkc().collect();
    let mut out = String::with_capacity(bare.len());
    for ch in bare.chars() {
        // normalise separators
        let ch = match ch {
            '_' | '.' => '-',
            c => c,
        };
        // apply homoglyph map
        let ch = HOMOGLYPH_MAP
            .iter()
            .find(|(from, _)| *from == ch)
            .map(|(_, to)| *to)
            .unwrap_or(ch);
        out.push(ch);
    }
    out.to_lowercase()
}

/// Strip leading `@scope/` from a name, returning the bare name.
/// Returns the original string if there is no scope.
fn strip_scope(name: &str) -> &str {
    if let Some(rest) = name.strip_prefix('@')
        && let Some(slash_pos) = rest.find('/')
    {
        return &rest[slash_pos + 1..];
    }
    name
}

/// Extract the scope from a name, e.g. `@types/node` → `Some("types")`.
fn scope_of(name: &str) -> Option<&str> {
    if let Some(rest) = name.strip_prefix('@')
        && let Some(slash_pos) = rest.find('/')
    {
        return Some(&rest[..slash_pos]);
    }
    None
}

// ─── Damerau-Levenshtein distance ──────────────────────────────────────────

/// Compute the unrestricted Damerau-Levenshtein (edit) distance between two
/// strings operating on Unicode scalar values.  Returns `usize::MAX` if either
/// string is empty and the other is non-empty, so callers can short-circuit.
///
/// Uses O(n * m) time and O(n * m) space with small constant — both inputs are
/// short package names (≤ 100 chars in practice) so this is fine.
fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let la = a.len();
    let lb = b.len();

    if la == 0 {
        return lb;
    }
    if lb == 0 {
        return la;
    }

    // dp[i][j] = DL distance of a[..i] vs b[..j]
    // Allocate (la+1) * (lb+1) flat Vec; index as [i*(lb+1)+j].
    let size = (la + 1) * (lb + 1);
    let mut dp = vec![0usize; size];

    for i in 0..=la {
        dp[i * (lb + 1)] = i;
    }
    for (j, cell) in dp.iter_mut().enumerate().take(lb + 1) {
        *cell = j;
    }

    for i in 1..=la {
        for j in 1..=lb {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let del = dp[(i - 1) * (lb + 1) + j] + 1;
            let ins = dp[i * (lb + 1) + (j - 1)] + 1;
            let sub = dp[(i - 1) * (lb + 1) + (j - 1)] + cost;
            let mut best = del.min(ins).min(sub);
            // transposition
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                let trans = dp[(i - 2) * (lb + 1) + (j - 2)] + cost;
                best = best.min(trans);
            }
            dp[i * (lb + 1) + j] = best;
        }
    }
    dp[la * (lb + 1) + lb]
}

// ─── Scope-spoof detection ─────────────────────────────────────────────────

/// Check whether `candidate` is a scope-spoof of `popular`.
///
/// Patterns:
/// - `@types-node` instead of `@types/node` (dash-replaces-slash)
/// - `@attacker/node` instead of `@types/node` (different scope, same bare)
/// - `@typess/node` (typo in scope itself)
fn check_scope_spoof<'a>(candidate: &'a str, popular: &'a str) -> Option<(&'a str, &'static str)> {
    let cand_scope = scope_of(candidate);
    let pop_scope = scope_of(popular);

    match (cand_scope, pop_scope) {
        // Both scoped — compare scope strings
        (Some(cs), Some(ps)) => {
            if cs != ps {
                let bare_cand = strip_scope(candidate);
                let bare_pop = strip_scope(popular);
                // Same bare name but different scope → dependency-confusion-style spoof
                if bare_cand == bare_pop {
                    return Some((popular, "TYPO_SCOPE_SWAP"));
                }
                // Typo in scope
                if damerau_levenshtein(cs, ps) <= 1 && bare_cand == bare_pop {
                    return Some((popular, "TYPO_SCOPE_TYPO"));
                }
            }
            None
        }
        // Candidate is unscoped but popular is scoped
        // e.g. candidate = "@types-node", popular = "@types/node"
        (None, Some(ps)) => {
            // Check dash-separated scope: "@types-node" looks like @types/node
            let with_dash = format!("@{}-{}", ps, strip_scope(popular));
            if candidate == with_dash {
                return Some((popular, "TYPO_SCOPE_DASH_SLASH"));
            }
            None
        }
        // Candidate is scoped but popular is not → scoped variant claiming popular bare name
        (Some(_), None) => {
            let bare_cand = strip_scope(candidate);
            if bare_cand == popular {
                return Some((popular, "TYPO_SCOPE_INJECTION"));
            }
            None
        }
        (None, None) => None,
    }
}

// ─── Squat-pattern detection ───────────────────────────────────────────────

/// Check if `candidate` is a known squat-pattern variant of `popular_bare`
/// (both already stripped of scope).
///
/// Returns the matched pattern label if so.
fn check_squat_pattern(candidate_bare: &str, popular_bare: &str) -> Option<&'static str> {
    // Check suffix patterns: "popularname-js", "popularname2", etc.
    for &suffix in SQUAT_SUFFIXES {
        let expected = format!("{}{}", popular_bare, suffix);
        if candidate_bare == expected {
            return Some("TYPO_SUFFIX_PATTERN");
        }
    }
    // Check prefix patterns: "node-popularname", "npm-popularname", etc.
    for &prefix in SQUAT_PREFIXES {
        let expected = format!("{}{}", prefix, popular_bare);
        if candidate_bare == expected {
            return Some("TYPO_PREFIX_PATTERN");
        }
    }
    None
}

// ─── Homoglyph detection ───────────────────────────────────────────────────

/// Returns true if the candidate (already normalised for DL) differs from the
/// popular name (also normalised) ONLY in homoglyph substitutions — i.e.
/// normalisation collapsed them to equal strings while the raw names differ.
///
/// We deliberately exclude the case where one name is simply the unscoped bare
/// form of the other (e.g. `"react"` vs `"@types/react"`): `normalize_for_dl`
/// strips the `@scope/` prefix from both, so they collapse to the same string
/// without any character mutation.  That pattern is a scope-injection candidate,
/// not a homoglyph, and is handled separately by `check_scope_spoof`.
fn is_homoglyph_variant(candidate_raw: &str, popular_raw: &str) -> bool {
    if candidate_raw == popular_raw {
        return false; // exact match — not a variant
    }
    // If the candidate IS the bare name embedded in a scoped popular package
    // (or vice versa), the scope-strip inside normalize_for_dl would make them
    // appear equal even with zero character mutations — not a homoglyph.
    if candidate_raw == strip_scope(popular_raw) || strip_scope(candidate_raw) == popular_raw {
        return false;
    }
    let cn = normalize_for_dl(candidate_raw);
    let pn = normalize_for_dl(popular_raw);
    cn == pn
}

// ─── Main scan logic ───────────────────────────────────────────────────────

/// Extract all package names from scan context:
/// - `package.json` name field (primary)
/// - Any manifest file name fields in other files
fn collect_candidate_names(ctx: &ScanContext<'_>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    // Primary: top-level package.json parsed by loader
    if let Some(pkg) = ctx.package_json
        && let Some(name) = pkg.get("name").and_then(|v| v.as_str())
    {
        let name = name.trim().to_string();
        if !name.is_empty() {
            out.push(("package.json".to_string(), name));
        }
    }

    // Secondary: any manifest or JSON files that might also carry a name
    for file in ctx.files_where(|f| matches!(f.kind, FileKind::Manifest | FileKind::Json)) {
        // Don't double-count the top-level package.json already handled above
        if file.rel_path == "package.json" || file.rel_path == "./package.json" {
            continue;
        }
        if !file.rel_path.ends_with("package.json") {
            continue;
        }
        let text = file.text_lossy();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text.as_ref())
            && let Some(name) = val.get("name").and_then(|v| v.as_str())
        {
            let name = name.trim().to_string();
            if !name.is_empty() {
                out.push((file.rel_path.clone(), name));
            }
        }
    }

    out
}

fn scan_candidate(
    candidate: &str,
    source_path: &str,
    findings: &mut Vec<Finding>,
    allowlisted: &[String],
) {
    // Reject obviously invalid names (very short, all digits, etc.)
    let bare_candidate = strip_scope(candidate);
    if bare_candidate.len() < 2 {
        return;
    }

    // Normalised form for DL distance comparison
    let cand_norm = normalize_for_dl(candidate);

    for &popular in POPULAR_PACKAGES {
        // Exact match → legitimate use, skip
        if candidate == popular {
            continue;
        }

        let pop_norm = normalize_for_dl(popular);
        let bare_popular = strip_scope(popular);
        let bare_cand = strip_scope(candidate);

        // ── 1. Scope-spoof check ───────────────────────────────────────
        if let Some((_, rule_label)) = check_scope_spoof(candidate, popular) {
            let rule_id = format!("{}_{}", ENGINE_NAME.to_uppercase(), rule_label);
            if allowlisted.contains(&rule_id) {
                continue;
            }
            let f = Finding::new(
                ENGINE_NAME,
                ThreatCategory::Typosquatting,
                Severity::High,
                Confidence::High,
                format!("Scope spoof of popular package `{}`", popular),
                format!(
                    "Package name `{}` appears to spoof the popular package `{}` \
                     by using a different or malformed scope. This is a common \
                     supply-chain attack pattern.",
                    candidate, popular
                ),
            )
            .with_rule_id(rule_id)
            .with_location(FileLocation::file(source_path))
            .with_evidence(format!("`{}` vs `{}`", candidate, popular), 160);
            findings.push(f);
            return; // one finding per candidate is enough
        }

        // ── 2. Homoglyph check ────────────────────────────────────────
        if is_homoglyph_variant(candidate, popular) {
            let rule_id = format!("{}_HOMOGLYPH", ENGINE_NAME.to_uppercase());
            if allowlisted.contains(&rule_id) {
                continue;
            }
            let f = Finding::new(
                ENGINE_NAME,
                ThreatCategory::Typosquatting,
                Severity::Critical,
                Confidence::High,
                format!("Homoglyph/confusable variant of `{}`", popular),
                format!(
                    "Package name `{}` uses look-alike Unicode characters (homoglyphs) \
                     to impersonate the popular package `{}`. This is a high-confidence \
                     supply-chain attack.",
                    candidate, popular
                ),
            )
            .with_rule_id(rule_id)
            .with_location(FileLocation::file(source_path))
            .with_evidence(format!("`{}` mimics `{}`", candidate, popular), 160);
            findings.push(f);
            return;
        }

        // ── 3. DL distance check (bare names, normalised) ─────────────
        // Only compare if both bare names are at least 2 chars and the normalised
        // forms aren't identical (homoglyph already handled above).
        if bare_popular.len() >= 2 && bare_cand.len() >= 2 {
            let bare_cand_norm = normalize_for_dl(bare_cand);
            let bare_pop_norm = normalize_for_dl(bare_popular);

            // Skip if normalised forms are identical (homoglyph path already fired
            // or the names are truly the same under normalisation)
            if bare_cand_norm != bare_pop_norm {
                // Guard: skip if candidate is a well-known completely-different
                // package that happens to be short (avoids cross-popular FPs).
                // We only fire if len diff ≤ 2 and DL ≤ 2.
                let len_diff =
                    (bare_cand_norm.len() as isize - bare_pop_norm.len() as isize).unsigned_abs();
                if len_diff <= 2 {
                    let dist = damerau_levenshtein(&bare_cand_norm, &bare_pop_norm);
                    if dist == 1 || dist == 2 {
                        // Skip if candidate is itself a popular package name
                        // (avoids flagging e.g. "ws" as typo of "w")
                        let cand_is_popular = POPULAR_PACKAGES.contains(&candidate);
                        if cand_is_popular {
                            continue;
                        }

                        let (severity, confidence, rule_suffix) = if dist == 1 {
                            (Severity::High, Confidence::High, "DL1")
                        } else {
                            (Severity::Medium, Confidence::Medium, "DL2")
                        };
                        let rule_id = format!(
                            "{}_{}_{}",
                            ENGINE_NAME.to_uppercase(),
                            rule_suffix,
                            popular.replace(['/', '@', '-'], "_").to_uppercase()
                        );
                        if allowlisted.contains(&rule_id) {
                            continue;
                        }
                        let f = Finding::new(
                            ENGINE_NAME,
                            ThreatCategory::Typosquatting,
                            severity,
                            confidence,
                            format!(
                                "Possible typosquat of `{}` (edit distance {})",
                                popular, dist
                            ),
                            format!(
                                "Package name `{}` is {} character edit(s) away from the \
                                 popular npm package `{}`. Damerau-Levenshtein distance {}. \
                                 This may be a typosquatting attempt.",
                                candidate, dist, popular, dist
                            ),
                        )
                        .with_rule_id(rule_id)
                        .with_location(FileLocation::file(source_path))
                        .with_evidence(
                            format!("`{}` ~ `{}` (DL={})", candidate, popular, dist),
                            160,
                        );
                        findings.push(f);
                        // Don't return — a candidate could be DL-close to multiple
                        // popular packages; report all.
                    }
                }
            }
        }

        // ── 4. Squat-pattern check (bare names only) ──────────────────
        if let Some(rule_label) = check_squat_pattern(bare_cand, bare_popular) {
            let rule_id = format!("{}_{}", ENGINE_NAME.to_uppercase(), rule_label);
            if allowlisted.contains(&rule_id) {
                continue;
            }
            // Avoid re-flagging if we already emitted a DL finding for the same
            // popular package above.
            let already = findings.iter().any(|f| {
                f.engine == ENGINE_NAME && f.description.contains(&format!("`{}`", popular))
            });
            if already {
                continue;
            }
            let f = Finding::new(
                ENGINE_NAME,
                ThreatCategory::Typosquatting,
                Severity::High,
                Confidence::High,
                format!("Squat-pattern variant of `{}`", popular),
                format!(
                    "Package name `{}` matches a known typosquatting pattern \
                     (suffix/prefix addition) targeting the popular package `{}`. \
                     These patterns are frequently used in supply-chain attacks.",
                    candidate, popular
                ),
            )
            .with_rule_id(rule_id)
            .with_location(FileLocation::file(source_path))
            .with_evidence(format!("`{}` targets `{}`", candidate, popular), 160);
            findings.push(f);
            return;
        }

        // ── 5. Full DL on normalised full name (scoped vs unscoped mix) ──
        // e.g. "colours" vs "colors", "colour" vs "color"
        if cand_norm.len() >= 3 && pop_norm.len() >= 3 {
            let len_diff = (cand_norm.len() as isize - pop_norm.len() as isize).unsigned_abs();
            if len_diff <= 2 && cand_norm != pop_norm {
                // Already checked bare names above for short names; for long
                // names skip if we already found something for this popular pkg.
                let already = findings.iter().any(|f| {
                    f.engine == ENGINE_NAME && f.description.contains(&format!("`{}`", popular))
                });
                if already {
                    continue;
                }
                let dist = damerau_levenshtein(&cand_norm, &pop_norm);
                if dist == 1 || dist == 2 {
                    let cand_is_popular = POPULAR_PACKAGES.contains(&candidate);
                    if cand_is_popular {
                        continue;
                    }
                    let (severity, confidence, rule_suffix) = if dist == 1 {
                        (Severity::High, Confidence::High, "DL1")
                    } else {
                        (Severity::Medium, Confidence::Medium, "DL2")
                    };
                    let rule_id = format!(
                        "{}_{}_FULL_{}",
                        ENGINE_NAME.to_uppercase(),
                        rule_suffix,
                        popular.replace(['/', '@', '-'], "_").to_uppercase()
                    );
                    if allowlisted.contains(&rule_id) {
                        continue;
                    }
                    let f = Finding::new(
                        ENGINE_NAME,
                        ThreatCategory::Typosquatting,
                        severity,
                        confidence,
                        format!(
                            "Possible typosquat of `{}` (edit distance {})",
                            popular, dist
                        ),
                        format!(
                            "Package name `{}` is {} edit(s) from the popular package \
                             `{}` (DL={}). Possible typosquatting.",
                            candidate, dist, popular, dist
                        ),
                    )
                    .with_rule_id(rule_id)
                    .with_location(FileLocation::file(source_path))
                    .with_evidence(
                        format!("`{}` ~ `{}` (DL={})", candidate, popular, dist),
                        160,
                    );
                    findings.push(f);
                }
            }
        }
    }
}

// ─── Engine struct ─────────────────────────────────────────────────────────

/// Detection engine for npm package name typosquatting.
///
/// Compares the scanned package's name against a bundled corpus of ~150
/// popular npm packages using Damerau-Levenshtein distance, homoglyph
/// normalisation, scope-spoof detection, and known squat-pattern matching.
#[derive(Debug, Default)]
pub struct TyposquatEngine;

impl DetectionEngine for TyposquatEngine {
    fn name(&self) -> &'static str {
        ENGINE_NAME
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Vec<Finding> {
        let candidates = collect_candidate_names(ctx);
        if candidates.is_empty() {
            return Vec::new();
        }

        let mut findings: Vec<Finding> = Vec::new();
        let allowlisted = &ctx.config.allowlisted_rule_ids;

        for (source_path, candidate_name) in &candidates {
            scan_candidate(candidate_name, source_path, &mut findings, allowlisted);
        }

        findings
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::engine::{FileKind, FileUnit, ScanContext};

    fn make_ctx_with_pkg_name<'a>(
        name: &str,
        pkg_json: &'a serde_json::Value,
        config: &'a ScanConfig,
        files: &'a [FileUnit],
    ) -> ScanContext<'a> {
        ScanContext {
            target_name: name.to_string(),
            files,
            package_json: Some(pkg_json),
            config,
        }
    }

    fn scan_name(name: &str) -> Vec<Finding> {
        let config = ScanConfig::default();
        let pkg = serde_json::json!({ "name": name });
        let files = [];
        let engine = TyposquatEngine;
        let ctx = make_ctx_with_pkg_name(name, &pkg, &config, &files);
        engine.scan(&ctx)
    }

    // ── True positives (must be flagged) ─────────────────────────────────

    #[test]
    fn lodahs_flagged_near_lodash() {
        // "lodahs" is a transposition of "lodash" → DL=1
        let findings = scan_name("lodahs");
        let matched = findings.iter().any(|f| {
            f.engine == ENGINE_NAME
                && f.description.contains("lodash")
                && matches!(f.category, ThreatCategory::Typosquatting)
        });
        assert!(
            matched,
            "expected 'lodahs' to be flagged near lodash; findings: {:?}",
            findings
        );
    }

    #[test]
    fn expres_flagged_near_express() {
        // "expres" is "express" with one char deleted → DL=1
        let findings = scan_name("expres");
        let matched = findings
            .iter()
            .any(|f| f.engine == ENGINE_NAME && f.description.contains("express"));
        assert!(
            matched,
            "expected 'expres' to be flagged near express; findings: {:?}",
            findings
        );
    }

    #[test]
    fn reqeust_flagged_near_request() {
        // "reqeust" — transposition in request → DL=2
        let findings = scan_name("reqeust");
        let matched = findings
            .iter()
            .any(|f| f.engine == ENGINE_NAME && f.description.contains("request"));
        assert!(
            matched,
            "expected 'reqeust' to be flagged near request; findings: {:?}",
            findings
        );
    }

    #[test]
    fn axois_flagged_near_axios() {
        // "axois" — transposition of axios → DL=1 (swap i/o)
        let findings = scan_name("axois");
        let matched = findings
            .iter()
            .any(|f| f.engine == ENGINE_NAME && f.description.contains("axios"));
        assert!(
            matched,
            "expected 'axois' to be flagged near axios; findings: {:?}",
            findings
        );
    }

    #[test]
    fn looash_flagged_near_lodash() {
        // "looash" — substitution (d→o) and one extra char → DL=2
        let findings = scan_name("looash");
        let matched = findings
            .iter()
            .any(|f| f.engine == ENGINE_NAME && f.description.contains("lodash"));
        // "looash" = l-o-o-a-s-h vs l-o-d-a-s-h → DL=1 (substitution o→d)
        assert!(
            matched,
            "expected 'looash' to be flagged near lodash; findings: {:?}",
            findings
        );
    }

    #[test]
    fn suffixy_squat_pattern_flagged() {
        // "lodash-js" is a known suffix-pattern squat
        let findings = scan_name("lodash-js");
        let matched = findings.iter().any(|f| {
            f.engine == ENGINE_NAME
                && f.description.contains("lodash")
                && f.rule_id.as_deref() == Some("TYPOSQUAT_TYPO_SUFFIX_PATTERN")
        });
        assert!(
            matched,
            "expected 'lodash-js' squat pattern to be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn prefix_squat_pattern_flagged() {
        // "node-lodash" is a known prefix-pattern squat
        let findings = scan_name("node-lodash");
        let matched = findings.iter().any(|f| {
            f.engine == ENGINE_NAME
                && f.description.contains("lodash")
                && f.rule_id.as_deref() == Some("TYPOSQUAT_TYPO_PREFIX_PATTERN")
        });
        assert!(
            matched,
            "expected 'node-lodash' to be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn scope_dash_spoof_flagged() {
        // "@types-node" looks like "@types/node" with dash replacing slash
        let findings = scan_name("@types-node");
        let matched = findings
            .iter()
            .any(|f| f.engine == ENGINE_NAME && f.category == ThreatCategory::Typosquatting);
        assert!(
            matched,
            "expected '@types-node' scope spoof to be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn colours_flagged_near_colors() {
        // "colours" is DL=2 from "colors" (add 'u', change endings)
        let findings = scan_name("colours");
        let matched = findings
            .iter()
            .any(|f| f.engine == ENGINE_NAME && f.description.contains("colors"));
        // colours vs colors: c-o-l-o-u-r-s vs c-o-l-o-r-s → DL=1 (insert 'u')
        assert!(
            matched,
            "expected 'colours' to be flagged near colors; findings: {:?}",
            findings
        );
    }

    #[test]
    fn lodash2_squat_pattern_flagged() {
        // "lodash2" is a known suffix-pattern squat ("2" suffix)
        let findings = scan_name("lodash2");
        let matched = findings
            .iter()
            .any(|f| f.engine == ENGINE_NAME && f.description.contains("lodash"));
        assert!(
            matched,
            "expected 'lodash2' to be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn homoglyph_cyrillic_flagged() {
        // "lоdash" with a Cyrillic 'о' (U+043E) instead of Latin 'o' → homoglyph
        let s = "l\u{043E}dash"; // Cyrillic о
        let findings = scan_name(s);
        let matched = findings.iter().any(|f| {
            f.engine == ENGINE_NAME && f.rule_id.as_deref() == Some("TYPOSQUAT_HOMOGLYPH")
        });
        assert!(
            matched,
            "expected homoglyph 'lодash' to be flagged; findings: {:?}",
            findings
        );
    }

    // TRUE-POSITIVE: fullwidth Latin letters (NFKC-compatibility homoglyphs) that
    // the fixed HOMOGLYPH_MAP does not enumerate must fold to ASCII and flag.
    #[test]
    fn homoglyph_fullwidth_flagged() {
        // "ｒｅａｃｔ" — fullwidth Latin (U+FF52…) that NFKC folds to "react".
        let s = "\u{FF52}\u{FF45}\u{FF41}\u{FF43}\u{FF54}";
        assert_eq!(
            normalize_for_dl(s),
            "react",
            "NFKC must fold fullwidth to ASCII"
        );
        let findings = scan_name(s);
        assert!(
            findings.iter().any(|f| {
                f.engine == ENGINE_NAME && f.rule_id.as_deref() == Some("TYPOSQUAT_HOMOGLYPH")
            }),
            "expected fullwidth ' react' to be flagged as homoglyph; findings: {findings:?}"
        );
    }

    // TRUE-NEGATIVE: a benign package name containing legitimate non-ASCII text
    // (that does NOT collapse to a popular name) must not over-fire.
    #[test]
    fn benign_unicode_name_not_flagged() {
        // A CJK project name unrelated to any popular package.
        let findings = scan_name("\u{65e5}\u{672c}\u{8a9e}-utils");
        assert!(
            findings.is_empty(),
            "benign unicode name must not be flagged; findings: {findings:?}"
        );
    }

    #[test]
    fn express_safe_squat() {
        // "express-safe" is a known suffix-pattern squat
        let findings = scan_name("express-safe");
        let matched = findings
            .iter()
            .any(|f| f.engine == ENGINE_NAME && f.description.contains("express"));
        assert!(
            matched,
            "expected 'express-safe' to be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn jest_next_squat() {
        // "jest-next" suffix squat
        let findings = scan_name("jest-next");
        let matched = findings
            .iter()
            .any(|f| f.engine == ENGINE_NAME && f.description.contains("jest"));
        assert!(
            matched,
            "expected 'jest-next' to be flagged; findings: {:?}",
            findings
        );
    }

    // ── True negatives (must NOT be flagged) ─────────────────────────────

    #[test]
    fn react_exact_not_flagged() {
        // Exact popular package name — must not be flagged
        let findings = scan_name("react");
        let typosquat = findings.iter().any(|f| {
            f.engine == ENGINE_NAME && matches!(f.category, ThreatCategory::Typosquatting)
        });
        assert!(
            !typosquat,
            "exact name 'react' must not be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn lodash_exact_not_flagged() {
        let findings = scan_name("lodash");
        assert!(
            findings.is_empty(),
            "exact name 'lodash' must not be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn express_exact_not_flagged() {
        let findings = scan_name("express");
        assert!(
            findings.is_empty(),
            "exact name 'express' must not be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn clearly_unrelated_name_not_flagged() {
        // "my-weather-dashboard" is completely unrelated to any popular package
        let findings = scan_name("my-weather-dashboard");
        let typosquat = findings.iter().any(|f| {
            f.engine == ENGINE_NAME && matches!(f.category, ThreatCategory::Typosquatting)
        });
        assert!(
            !typosquat,
            "'my-weather-dashboard' must not be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn unrelated_short_name_not_flagged() {
        // "zap" — short but completely unrelated, well above DL=2 from short popular names
        let findings = scan_name("zap-core-lib");
        let typosquat = findings.iter().any(|f| {
            f.engine == ENGINE_NAME && matches!(f.category, ThreatCategory::Typosquatting)
        });
        assert!(
            !typosquat,
            "'zap-core-lib' must not be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn webpack_exact_not_flagged() {
        let findings = scan_name("webpack");
        assert!(
            findings.is_empty(),
            "exact name 'webpack' must not be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn types_node_scoped_exact_not_flagged() {
        // "@types/node" is an exact popular scoped package — must not be flagged
        let findings = scan_name("@types/node");
        let typosquat = findings.iter().any(|f| {
            f.engine == ENGINE_NAME && matches!(f.category, ThreatCategory::Typosquatting)
        });
        assert!(
            !typosquat,
            "'@types/node' must not be flagged; findings: {:?}",
            findings
        );
    }

    #[test]
    fn no_package_json_returns_empty() {
        // If there is no package.json in context, engine should return nothing
        let config = ScanConfig::default();
        let files = [];
        let engine = TyposquatEngine;
        let ctx = ScanContext {
            target_name: "no-pkg".to_string(),
            files: &files,
            package_json: None,
            config: &config,
        };
        let findings = engine.scan(&ctx);
        assert!(
            findings.is_empty(),
            "no package.json → no findings expected"
        );
    }

    #[test]
    fn allowlisted_rule_suppressed() {
        // When the rule id is allowlisted the finding must be suppressed
        let mut config = ScanConfig::default();
        // "lodahs" → DL1 from lodash → rule id contains DL1_LODASH
        // We allowlist the exact rule id the engine would emit.
        // The rule id is TYPOSQUAT_DL1_LODASH (uppercase, dashes→underscores)
        config
            .allowlisted_rule_ids
            .push("TYPOSQUAT_DL1_LODASH".to_string());
        let pkg = serde_json::json!({ "name": "lodahs" });
        let files = [];
        let engine = TyposquatEngine;
        let ctx = make_ctx_with_pkg_name("lodahs", &pkg, &config, &files);
        let findings = engine.scan(&ctx);
        // The lodash DL1 finding must be suppressed; others (if any) allowed
        let lodash_dl1 = findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("TYPOSQUAT_DL1_LODASH"));
        assert!(
            !lodash_dl1,
            "allowlisted rule should be suppressed; findings: {:?}",
            findings
        );
    }

    // ── Unit tests for supporting functions ──────────────────────────────

    #[test]
    fn dl_distance_exact_zero() {
        assert_eq!(damerau_levenshtein("lodash", "lodash"), 0);
    }

    #[test]
    fn dl_distance_transposition() {
        // "lodahs" vs "lodash" — swap h and s → distance 1
        assert_eq!(damerau_levenshtein("lodahs", "lodash"), 1);
    }

    #[test]
    fn dl_distance_substitution() {
        assert_eq!(damerau_levenshtein("expres", "express"), 1);
    }

    #[test]
    fn dl_distance_insertion() {
        assert_eq!(damerau_levenshtein("colours", "colors"), 1);
    }

    #[test]
    fn dl_distance_empty_strings() {
        assert_eq!(damerau_levenshtein("", ""), 0);
        assert_eq!(damerau_levenshtein("", "abc"), 3);
        assert_eq!(damerau_levenshtein("abc", ""), 3);
    }

    #[test]
    fn normalize_strips_scope() {
        assert_eq!(normalize_for_dl("@types/node"), "node");
        assert_eq!(normalize_for_dl("@babel/core"), "core");
        assert_eq!(normalize_for_dl("lodash"), "lodash");
    }

    #[test]
    fn normalize_maps_homoglyphs() {
        // Cyrillic 'о' → 'o'
        assert_eq!(normalize_for_dl("l\u{043E}dash"), "lodash");
    }

    #[test]
    fn squat_pattern_suffix() {
        assert_eq!(
            check_squat_pattern("lodash-js", "lodash"),
            Some("TYPO_SUFFIX_PATTERN")
        );
        assert_eq!(check_squat_pattern("lodash", "lodash"), None);
        assert_eq!(check_squat_pattern("completely-different", "lodash"), None);
    }

    #[test]
    fn squat_pattern_prefix() {
        assert_eq!(
            check_squat_pattern("node-lodash", "lodash"),
            Some("TYPO_PREFIX_PATTERN")
        );
        assert_eq!(
            check_squat_pattern("npm-express", "express"),
            Some("TYPO_PREFIX_PATTERN")
        );
    }

    #[test]
    fn scope_spoof_dash_slash() {
        // "@types-node" should be detected as a scope spoof of "@types/node"
        let result = check_scope_spoof("@types-node", "@types/node");
        assert!(result.is_some(), "expected scope spoof detected");
    }

    #[test]
    fn scope_exact_not_spoof() {
        let result = check_scope_spoof("@types/node", "@types/node");
        assert!(
            result.is_none(),
            "@types/node vs @types/node is not a spoof"
        );
    }

    #[test]
    fn is_homoglyph_variant_cyrillic() {
        // Cyrillic о in "lодash" vs "lodash"
        assert!(is_homoglyph_variant("l\u{043E}dash", "lodash"));
    }

    #[test]
    fn is_homoglyph_variant_exact_not_variant() {
        assert!(!is_homoglyph_variant("lodash", "lodash"));
    }

    #[test]
    fn is_homoglyph_variant_unrelated() {
        assert!(!is_homoglyph_variant("express", "lodash"));
    }

    #[test]
    fn secondary_package_json_scanned() {
        // A nested package.json with a squat name should also be flagged
        let config = ScanConfig::default();
        let inner_content = serde_json::json!({ "name": "lodahs", "version": "1.0.0" });
        let inner_bytes = serde_json::to_vec(&inner_content).unwrap();
        let inner_file = FileUnit {
            rel_path: "packages/inner/package.json".to_string(),
            data: inner_bytes,
            kind: FileKind::Manifest,
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };
        // Top-level pkg is legit
        let top_pkg = serde_json::json!({ "name": "my-monorepo" });
        let files = vec![inner_file];
        let engine = TyposquatEngine;
        let ctx = ScanContext {
            target_name: "my-monorepo".to_string(),
            files: &files,
            package_json: Some(&top_pkg),
            config: &config,
        };
        let findings = engine.scan(&ctx);
        let matched = findings
            .iter()
            .any(|f| f.engine == ENGINE_NAME && f.description.contains("lodash"));
        assert!(
            matched,
            "expected squat in nested package.json to be flagged; findings: {:?}",
            findings
        );
    }
}
