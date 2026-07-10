//! False-positive review: run the Scanner against realistic benign inputs
//! and collect every finding so we can reason about which rules mis-fire.
//!
//! Each test asserts two things:
//!   1. The verdict is Clean or Suspicious (never Malicious) — unchanged from before.
//!   2. No `worm_propagation` engine findings fire — the WormPropagationEngine must
//!      not produce false positives on any of these benign samples.
//!
//! S1-S6: the 5 originally-noted FP cases plus S6 (fetch+env SDK client), all
//! confirmed resolved after the worm engine was integrated into default_engines().
//!
//! S7-S11: extended corpus — prebuilt native addon (bcrypt/sharp-like), 12-factor
//! app (process.env config + own-API calls), funding-URL-only package, husky +
//! node-gyp build hooks, and packages with `my-`/`the-` name prefixes.

use cleanton_antivirus::{ScanConfig, Scanner, Verdict};

// ── tgz builder (same helper as integration.rs) ──────────────────────────────

fn make_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::{Compression, write::GzEncoder};

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

/// Assert the worm_propagation engine produced no findings on a benign sample.
fn assert_no_worm_findings(report: &cleanton_antivirus::ScanReport, label: &str) {
    let worm_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.engine == "worm_propagation")
        .collect();
    assert!(
        worm_findings.is_empty(),
        "{label}: worm_propagation engine must not fire on benign sample; \
         worm findings: {worm_findings:#?}"
    );
}

/// Run a scan and dump findings to stdout so we can inspect them during review.
fn scan_and_dump(label: &str, target: &str, data: &[u8]) -> cleanton_antivirus::ScanReport {
    let report = default_scanner()
        .scan_bytes(target, data)
        .expect("scan must not error");

    println!(
        "\n=== {} ===\nverdict={:?}  score={}\nfindings ({}):",
        label,
        report.verdict,
        report.score,
        report.findings.len()
    );
    for f in &report.findings {
        println!(
            "  [{:?}/{:?}/{:?}] engine={} rule={:?}\n    title={}\n    loc={:?}\n    evidence={:?}",
            f.severity,
            f.confidence,
            f.category,
            f.engine,
            f.rule_id,
            f.title,
            f.location
                .as_ref()
                .map(|l| format!("{}:{:?}", l.path, l.line)),
            f.evidence,
        );
    }
    report
}

// ── SAMPLE 1: package.json with build/test/prepare scripts ───────────────────

#[test]
fn fp_s1_package_json_build_test_prepare() {
    // Real-world shape: tsc build, jest test, husky prepare, no install hook.
    let pkg_json = br#"{
  "name": "my-app",
  "version": "1.2.3",
  "description": "A typical TypeScript application",
  "main": "dist/index.js",
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "prepare": "husky install",
    "lint": "eslint src --ext .ts",
    "format": "prettier --write src/**/*.ts"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "jest": "^29.0.0",
    "husky": "^9.0.0",
    "eslint": "^8.0.0",
    "prettier": "^3.0.0"
  },
  "dependencies": {
    "express": "^4.18.0",
    "dotenv": "^16.0.0"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/myorg/my-app"
  },
  "license": "MIT"
}"#;

    let index_ts = br#"import express from 'express';
import * as dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.get('/health', (_req, res) => {
    res.json({ status: 'ok', port: PORT });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
"#;

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json),
        ("package/src/index.ts", index_ts),
    ]);

    let report = scan_and_dump(
        "S1: package.json {build:tsc, test:jest, prepare:husky install}",
        "my-app-1.2.3.tgz",
        &tgz,
    );

    // Expectations: husky install and tsc are in the benign allow-set;
    // prepare hook is a lifecycle hook but must pass. Verdict should be Clean.
    // process.env.PORT is a single access, not enumeration.
    assert!(
        report.verdict == Verdict::Clean || report.verdict == Verdict::Suspicious,
        "S1 benign package.json must not be Malicious; got {:?} score={} findings={:?}",
        report.verdict,
        report.score,
        report.findings,
    );
    // FP resolved: prepare:husky install must NOT trigger WORM_NPM_PUBLISH_FROM_HOOK.
    assert_no_worm_findings(&report, "S1");
}

// ── SAMPLE 2: minified-but-benign UMD bundle ─────────────────────────────────

#[test]
fn fp_s2_minified_umd_bundle() {
    // A realistic minified UMD bundle (math utility library).  Dense JS but
    // no obfuscation: normal identifier names, standard characters only.
    // Entropy will be moderately high (minified) but well below 6.2.
    let bundle: Vec<u8> = br#"!function(e,t){"object"==typeof exports&&"object"==typeof module?module.exports=t():"function"==typeof define&&define.amd?define([],t):"object"==typeof exports?exports.MathLib=t():e.MathLib=t()}(this,function(){return{add:function(e,t){return e+t},sub:function(e,t){return e-t},mul:function(e,t){return e*t},div:function(e,t){if(0===t)throw new RangeError("Cannot divide by zero");return e/t},clamp:function(e,t,n){return Math.min(Math.max(e,t),n)},lerp:function(e,t,n){return e*(1-n)+t*n},map:function(e,t,n,r,i){return r+(e-t)/(n-t)*(i-r)},norm:function(e,t,n){return(e-t)/(n-t)},deg2rad:function(e){return e*Math.PI/180},rad2deg:function(e){return 180*e/Math.PI},isPrime:function(e){if(e<2)return!1;for(var t=2;t<=Math.sqrt(e);t++)if(e%t==0)return!1;return!0},gcd:function t(e,n){return 0===n?e:t(n,e%n)},lcm:function(e,t){return e/this.gcd(e,t)*t},factorial:function(e){if(e<0)throw new RangeError("Factorial of negative");return 0===e?1:e*this.factorial(e-1)},choose:function(e,t){if(t<0||t>e)return 0;var n=1;for(var r=0;r<t;r++)n=n*(e-r)/(r+1);return Math.round(n)},fibonacci:function(e){var t=0,n=1;for(var r=0;r<e;r++){var i=t+n;t=n,n=i}return t},sum:function(e){return e.reduce(function(e,t){return e+t},0)},mean:function(e){return this.sum(e)/e.length},variance:function(e){var t=this.mean(e);return this.mean(e.map(function(e){return(e-t)*(e-t)}))},stddev:function(e){return Math.sqrt(this.variance(e))},median:function(e){var t=e.slice().sort(function(e,t){return e-t}),n=Math.floor(t.length/2);return t.length%2?t[n]:(t[n-1]+t[n])/2}}});
"#.to_vec();

    let pkg_json = br#"{"name":"mathlib","version":"2.3.1","main":"dist/mathlib.umd.min.js"}"#;

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json),
        ("package/dist/mathlib.umd.min.js", &bundle),
    ]);

    let report = scan_and_dump(
        "S2: minified-but-benign UMD bundle",
        "mathlib-2.3.1.tgz",
        &tgz,
    );

    // A minified but readable bundle should not be Malicious.
    // It may be Suspicious due to entropy thresholds on minified code,
    // but we do NOT expect Malicious.
    assert!(
        report.verdict == Verdict::Clean || report.verdict == Verdict::Suspicious,
        "S2 benign UMD bundle must not be Malicious; got {:?} score={} findings={:?}",
        report.verdict,
        report.score,
        report.findings,
    );
    // FP resolved: dense minified JS must not trigger worm_propagation rules.
    assert_no_worm_findings(&report, "S2");
}

// ── SAMPLE 3: legit native Node addon (.node) in a documented package ─────────

#[test]
fn fp_s3_native_node_addon_documented() {
    // Many packages (bcrypt, canvas, sharp, node-sqlite3) ship pre-built
    // .node addons.  The package.json documents this via binary/install.
    // The binary_indicators engine will flag BIN_NATIVE_IN_NPM_PACKAGE
    // for ANY native binary in a JS package; this is intentional behaviour,
    // not a false positive — but the verdict must not cross Malicious from
    // that signal alone (it needs a second high-signal finding to do so).
    let pkg_json = br#"{
  "name": "fast-hash",
  "version": "3.1.0",
  "description": "Native hash functions for Node.js (bcrypt, sha256, etc.)",
  "main": "index.js",
  "scripts": {
    "install": "node-gyp rebuild"
  },
  "binary": {
    "module_name": "fast_hash",
    "module_path": "./lib/binding/{platform}_{arch}"
  }
}"#;

    // Minimal ELF stub (just magic + zero-padded header, no suspicious strings).
    let mut elf_addon = Vec::new();
    elf_addon.extend_from_slice(b"\x7fELF");
    elf_addon.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]);
    elf_addon.extend_from_slice(&[0u8; 120]); // rest of ELF header, all zeros

    let index_js = b"module.exports = require('./lib/binding/linux_x64/fast_hash.node');";

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json),
        ("package/index.js", index_js),
        ("package/lib/binding/linux_x64/fast_hash.node", &elf_addon),
    ]);

    let report = scan_and_dump(
        "S3: legit native Node addon (.node) in npm package",
        "fast-hash-3.1.0.tgz",
        &tgz,
    );

    // A benign addon ships with node-gyp rebuild (benign install hook) and
    // an ELF that has no suspicious strings.
    // Expected: Suspicious at most (BIN_NATIVE_IN_NPM_PACKAGE fires but no
    // exfil/network combo to push it to Malicious).
    assert!(
        report.verdict == Verdict::Clean || report.verdict == Verdict::Suspicious,
        "S3 native addon must not be Malicious; got {:?} score={} findings={:?}",
        report.verdict,
        report.score,
        report.findings,
    );
    // FP resolved: install:node-gyp rebuild must NOT trigger WORM_NPM_PUBLISH_FROM_HOOK.
    assert_no_worm_findings(&report, "S3");
}

// ── SAMPLE 4: config-heavy package with many npm/github URLs ─────────────────

#[test]
fn fp_s4_config_heavy_many_urls() {
    // A realistic package.json from a CLI tool with many URLs pointing to
    // npm and GitHub — homepage, bugs, repository, funding, contributors,
    // and a lockfile-style resolved field.
    let pkg_json = br#"{
  "name": "my-cli",
  "version": "4.2.1",
  "description": "A command-line tool for managing projects",
  "homepage": "https://github.com/myorg/my-cli#readme",
  "bugs": {
    "url": "https://github.com/myorg/my-cli/issues"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/myorg/my-cli.git"
  },
  "funding": [
    { "type": "github", "url": "https://github.com/sponsors/myorg" },
    { "type": "opencollective", "url": "https://opencollective.com/myorg" }
  ],
  "license": "Apache-2.0",
  "main": "dist/cli.js",
  "bin": { "my-cli": "./dist/cli.js" },
  "dependencies": {
    "commander": "^11.0.0",
    "chalk": "^5.3.0",
    "ora": "^7.0.0",
    "got": "^13.0.0",
    "semver": "^7.5.0"
  },
  "devDependencies": {
    "typescript": "^5.1.0",
    "jest": "^29.5.0",
    "eslint": "^8.43.0"
  },
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "prepare": "husky install"
  }
}"#;

    // A lockfile excerpt with npm registry URLs (very common).
    let lockfile = br#"{
  "name": "my-cli",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "node_modules/commander": {
      "version": "11.0.0",
      "resolved": "https://registry.npmjs.org/commander/-/commander-11.0.0.tgz",
      "integrity": "sha512-9HMlXtt/BNoYr8ooyjjNRdIilOTkZqMDgs1Xppu4BSKRqS3mP9E1h2lfowFaNLLQUPwMHY9p+0NDg7Cme5Ow=="
    },
    "node_modules/chalk": {
      "version": "5.3.0",
      "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz",
      "integrity": "sha512-dLitG79d+GV1Nb/VYcCDFivJeK1hiukt9QjRNVuxoy9ef0+eqdm8A9M6gPQDNBJP3cZA3FdwHAOa3YKN0UBQ=="
    },
    "node_modules/got": {
      "version": "13.0.0",
      "resolved": "https://registry.npmjs.org/got/-/got-13.0.0.tgz",
      "integrity": "sha512-SF2EIZY9FWPF3N1O7eHgQ7JxJjO3CJzRgBbVGCCHHFVYjpAzU2AKbCm9Emrep0gI5vkqJHxfCRHSqLlLbZSA=="
    }
  }
}"#;

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json),
        ("package/package-lock.json", lockfile),
        (
            "package/dist/cli.js",
            b"#!/usr/bin/env node\nconsole.log('my-cli v4.2.1');",
        ),
    ]);

    let report = scan_and_dump(
        "S4: config-heavy package with many npm/github URLs",
        "my-cli-4.2.1.tgz",
        &tgz,
    );

    // All URLs point to npm registry or GitHub; the benign-url allow-set
    // covers those.  Verdict must not be Malicious.
    assert!(
        report.verdict == Verdict::Clean || report.verdict == Verdict::Suspicious,
        "S4 config-heavy package must not be Malicious; got {:?} score={} findings={:?}",
        report.verdict,
        report.score,
        report.findings,
    );
    // FP resolved: lockfile registry URLs must not trigger worm_propagation rules.
    assert_no_worm_findings(&report, "S4");
}

// ── SAMPLE 5: package using dotenv / process.env legitimately ─────────────────

#[test]
fn fp_s5_dotenv_process_env_legitimate() {
    // A web server that reads its config from environment variables via dotenv.
    // Uses process.env.* for individual named keys (not enumeration).
    let pkg_json = br#"{
  "name": "api-server",
  "version": "2.0.0",
  "description": "REST API server",
  "main": "src/server.js",
  "dependencies": {
    "express": "^4.18.0",
    "dotenv": "^16.3.0",
    "pg": "^8.11.0"
  },
  "scripts": {
    "start": "node src/server.js",
    "build": "tsc",
    "test": "jest"
  }
}"#;

    // Normal dotenv usage: read named env vars one by one.
    let server_js = br#"'use strict';
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_URL = process.env.DATABASE_URL;
const API_KEY = process.env.INTERNAL_API_KEY;

if (!DB_URL) {
    console.error('DATABASE_URL must be set');
    process.exit(1);
}

const pool = new Pool({ connectionString: DB_URL });

app.use(express.json());

app.get('/api/v1/health', async (req, res) => {
    const result = await pool.query('SELECT NOW()');
    res.json({ status: 'ok', time: result.rows[0].now });
});

app.get('/api/v1/items', async (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const result = await pool.query('SELECT * FROM items LIMIT 100');
    res.json(result.rows);
});

app.listen(PORT, () => {
    console.log('Server listening on port', PORT);
});
"#;

    // A .env.example file (no secrets, just template).
    let env_example =
        b"PORT=3000\nDATABASE_URL=postgres://user:pass@localhost/mydb\nINTERNAL_API_KEY=changeme\n";

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json),
        ("package/src/server.js", server_js),
        ("package/.env.example", env_example),
    ]);

    let report = scan_and_dump(
        "S5: dotenv / process.env used legitimately",
        "api-server-2.0.0.tgz",
        &tgz,
    );

    // process.env.NAMED_KEY is not enumeration.
    // dotenv.config() + named reads should not reach Malicious.
    assert!(
        report.verdict == Verdict::Clean || report.verdict == Verdict::Suspicious,
        "S5 dotenv/process.env legitimate usage must not be Malicious; got {:?} score={} findings={:?}",
        report.verdict,
        report.score,
        report.findings,
    );
    // FP resolved: reading named env vars must not trigger worm_propagation rules.
    assert_no_worm_findings(&report, "S5");
}

// ── SAMPLE 6: package that uses fetch + process.env for a legit API client ────

#[test]
fn fp_s6_fetch_plus_process_env_api_client() {
    // An SDK/client library that reads its API key from process.env and makes
    // HTTP requests — a pattern that should NOT trigger the exfiltration combo
    // unless it's in a lifecycle hook context.
    let pkg_json = br#"{
  "name": "@myorg/sdk-client",
  "version": "1.0.5",
  "description": "Official SDK for the MyOrg API",
  "main": "dist/index.js",
  "scripts": {
    "build": "tsc",
    "test": "jest"
  },
  "dependencies": {
    "node-fetch": "^3.3.0"
  }
}"#;

    let client_js = br#"'use strict';
const fetch = require('node-fetch');

const BASE_URL = 'https://api.myorg.com/v2';

class MyOrgClient {
    constructor(apiKey) {
        // apiKey typically comes from process.env.MYORG_API_KEY
        this.apiKey = apiKey || process.env.MYORG_API_KEY;
        if (!this.apiKey) {
            throw new Error('MYORG_API_KEY is required');
        }
    }

    async listUsers() {
        const res = await fetch(`${BASE_URL}/users`, {
            headers: { 'Authorization': `Bearer ${this.apiKey}` },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
    }

    async createUser(name, email) {
        const res = await fetch(`${BASE_URL}/users`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.apiKey}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, email }),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
    }
}

module.exports = MyOrgClient;
"#;

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json),
        ("package/dist/index.js", client_js),
    ]);

    let report = scan_and_dump(
        "S6: fetch + process.env in a legitimate SDK client (not a lifecycle hook)",
        "sdk-client-1.0.5.tgz",
        &tgz,
    );

    // The process.env + fetch combination IS suspicious-looking but should NOT
    // force Malicious because:
    // a) The code is in dist/index.js (not a lifecycle hook path).
    // b) The IOC engine's url context is "has_process_env=true" which elevates
    //    URL findings to IOC_URL_INSTALL_SCRIPT (Medium/Exfil) — potential FP.
    // We document all findings but do not expect Malicious verdict.
    assert!(
        report.verdict == Verdict::Clean || report.verdict == Verdict::Suspicious,
        "S6 fetch+process.env SDK client must not be Malicious; got {:?} score={} findings={:?}",
        report.verdict,
        report.score,
        report.findings,
    );
    // FP resolved: fetch + process.env in a library file must not trigger worm_propagation.
    assert_no_worm_findings(&report, "S6");
}

// ── SAMPLE 7: prebuilt native addon (bcrypt/sharp-like) ──────────────────────

#[test]
fn fp_s7_prebuilt_native_addon_bcrypt_shape() {
    // Many packages (bcrypt, sharp, canvas, sqlite3) ship a pre-built binary in
    // build/Release/<name>.node and use node-gyp only as a fallback install hook.
    // The binary_indicators engine MUST fire BIN_NATIVE_IN_NPM_PACKAGE (that is
    // correct behaviour), but the verdict must not reach Malicious from that
    // single signal alone — it requires a second independent high-confidence
    // finding in a distinct threat category.
    let pkg_json = br#"{
  "name": "bcrypt",
  "version": "5.1.1",
  "description": "A bcrypt library for NodeJS",
  "main": "bcrypt.js",
  "scripts": {
    "install": "node-gyp rebuild"
  },
  "dependencies": {
    "node-addon-api": "^7.0.0",
    "node-pre-gyp": "^1.0.11"
  },
  "binary": {
    "module_name": "bcrypt_lib",
    "module_path": "./lib/binding/napi-v{napi_build_version}",
    "remote_path": "v{version}",
    "host": "https://github.com/kelektiv/node.bcrypt.js/releases/download/",
    "package_name": "{module_name}-v{version}-napi-v{napi_build_version}-{platform}-{arch}-{libc}.tar.gz"
  }
}"#;

    // Minimal ELF stub for the pre-built .node file.
    let mut elf_node = Vec::new();
    elf_node.extend_from_slice(b"\x7fELF");
    elf_node.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]);
    elf_node.extend_from_slice(&[0u8; 120]);

    let bcrypt_js = br#"'use strict';
const binary = require('@mapbox/node-pre-gyp');
const path = require('path');
const binding_path = binary.find(path.resolve(path.join(__dirname, './package.json')));
const bcrypt = require(binding_path);

module.exports = {
    genSaltSync: bcrypt.gen_salt_sync,
    genSalt: bcrypt.gen_salt,
    hashSync: bcrypt.hash_sync,
    hash: bcrypt.hash,
    compareSync: bcrypt.compare_sync,
    compare: bcrypt.compare,
    getRounds: bcrypt.get_rounds,
};
"#;

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json),
        ("package/bcrypt.js", bcrypt_js),
        ("package/lib/binding/napi-v3/bcrypt_lib.node", &elf_node),
    ]);

    let report = scan_and_dump(
        "S7: prebuilt native addon (bcrypt-shape) with node-gyp install hook",
        "bcrypt-5.1.1.tgz",
        &tgz,
    );

    // BIN_NATIVE_IN_NPM_PACKAGE WILL fire (correct behaviour — reviewing operators
    // should inspect pre-built binaries), but without a network/command-exec
    // co-signal the combo rule D (NativeBinary + Network/CommandExec) must NOT
    // force Malicious.
    assert!(
        report.verdict == Verdict::Clean || report.verdict == Verdict::Suspicious,
        "S7 prebuilt native addon must not be Malicious; got {:?} score={} findings={:?}",
        report.verdict,
        report.score,
        report.findings,
    );
    assert_no_worm_findings(&report, "S7");
}

// ── SAMPLE 8: 12-factor app reading process.env config + calling its own API ──

#[test]
fn fp_s8_twelve_factor_app_process_env_own_api() {
    // A well-structured 12-factor app (https://12factor.net) reads ALL its config
    // from named environment variables and makes outbound calls only to its own
    // backend API.  This legitimately combines process.env access + HTTP requests
    // in the same file, which should NOT be flagged as exfiltration.
    let pkg_json = br#"{
  "name": "acme-dashboard",
  "version": "1.0.0",
  "description": "Acme internal analytics dashboard",
  "main": "src/app.js",
  "dependencies": {
    "express": "^4.18.0",
    "axios": "^1.6.0",
    "dotenv": "^16.3.0"
  },
  "scripts": {
    "start": "node src/app.js",
    "build": "tsc"
  }
}"#;

    // 12-factor: each config key is read individually by name, not enumerated.
    let app_js = br#"'use strict';
require('dotenv').config();
const express = require('express');
const axios = require('axios');

const PORT = process.env.PORT || 8080;
const BACKEND_URL = process.env.BACKEND_URL || 'https://api.acme-internal.com';
const SERVICE_KEY = process.env.ACME_SERVICE_KEY;

if (!SERVICE_KEY) {
    console.error('ACME_SERVICE_KEY is required');
    process.exit(1);
}

const app = express();
app.use(express.json());

// Proxy calls to the internal backend -- this is the app's own API.
app.get('/api/metrics', async (req, res) => {
    try {
        const resp = await axios.get(`${BACKEND_URL}/v1/metrics`, {
            headers: { 'X-Service-Key': SERVICE_KEY },
        });
        res.json(resp.data);
    } catch (err) {
        res.status(502).json({ error: 'backend unavailable' });
    }
});

app.post('/api/events', async (req, res) => {
    try {
        const resp = await axios.post(`${BACKEND_URL}/v1/events`, req.body, {
            headers: { 'X-Service-Key': SERVICE_KEY },
        });
        res.json(resp.data);
    } catch (err) {
        res.status(502).json({ error: 'backend unavailable' });
    }
});

app.listen(PORT, () => console.log(`Dashboard running on port ${PORT}`));
"#;

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json),
        ("package/src/app.js", app_js),
    ]);

    let report = scan_and_dump(
        "S8: 12-factor app — process.env config + own-API calls (no lifecycle hooks)",
        "acme-dashboard-1.0.0.tgz",
        &tgz,
    );

    // process.env.NAMED_KEY + axios calls to the app's own backend must not reach
    // Malicious.  Informational/Suspicious findings on the individual signals are
    // acceptable; Malicious is not.
    assert!(
        report.verdict == Verdict::Clean || report.verdict == Verdict::Suspicious,
        "S8 12-factor app must not be Malicious; got {:?} score={} findings={:?}",
        report.verdict,
        report.score,
        report.findings,
    );
    assert_no_worm_findings(&report, "S8");
}

// ── SAMPLE 9: package with funding URLs ──────────────────────────────────────

#[test]
fn fp_s9_funding_urls_only() {
    // A package whose package.json contains funding URLs pointing to GitHub
    // Sponsors and Open Collective.  No install hooks, no code with sensitive
    // patterns.  The IOC engine must not mistake these for exfil endpoints.
    let pkg_json = br#"{
  "name": "the-best-parser",
  "version": "2.0.0",
  "description": "Fast zero-dependency JSON-schema validator",
  "main": "index.js",
  "funding": [
    { "type": "github", "url": "https://github.com/sponsors/acme-oss" },
    { "type": "opencollective", "url": "https://opencollective.com/the-best-parser" },
    { "type": "patreon", "url": "https://www.patreon.com/acme_oss" }
  ],
  "repository": {
    "type": "git",
    "url": "https://github.com/acme-oss/the-best-parser.git"
  },
  "license": "MIT",
  "scripts": {
    "test": "jest",
    "build": "tsc"
  }
}"#;

    let index_js = b"'use strict';\nmodule.exports = require('./dist/index.js');\n";

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json),
        ("package/index.js", index_js),
    ]);

    let report = scan_and_dump(
        "S9: package with funding URLs (GitHub Sponsors, Open Collective, Patreon)",
        "the-best-parser-2.0.0.tgz",
        &tgz,
    );

    // Funding URLs in package.json metadata are benign. Verdict must not be Malicious.
    assert!(
        report.verdict == Verdict::Clean || report.verdict == Verdict::Suspicious,
        "S9 funding-URL package must not be Malicious; got {:?} score={} findings={:?}",
        report.verdict,
        report.score,
        report.findings,
    );
    assert_no_worm_findings(&report, "S9");
}

// ── SAMPLE 10: husky + node-gyp build hooks ──────────────────────────────────

#[test]
fn fp_s10_husky_and_node_gyp_build_hooks() {
    // A package that uses BOTH husky (git-hooks bootstrap in `prepare`) AND
    // node-gyp (native addon compilation in `install`).  Both script bodies are
    // in the benign allow-set; neither should trigger any malice rule.
    let pkg_json = br#"{
  "name": "fast-xml-parser",
  "version": "4.3.2",
  "description": "Validate & parse XML fast with a native addon",
  "main": "src/index.js",
  "scripts": {
    "install": "node-gyp rebuild",
    "prepare": "husky install",
    "build": "tsc",
    "test": "jest"
  },
  "dependencies": {
    "strnum": "^1.0.5"
  },
  "devDependencies": {
    "node-gyp": "^10.0.0",
    "husky": "^9.0.0",
    "typescript": "^5.0.0",
    "jest": "^29.0.0"
  }
}"#;

    let index_js = b"'use strict';\nconst binding = require('./build/Release/fast_xml.node');\nmodule.exports = binding;\n";

    // Pre-built stub for the native addon (no suspicious strings).
    let mut elf_stub = Vec::new();
    elf_stub.extend_from_slice(b"\x7fELF");
    elf_stub.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]);
    elf_stub.extend_from_slice(&[0u8; 120]);

    let tgz = make_tgz(&[
        ("package/package.json", pkg_json),
        ("package/src/index.js", index_js),
        ("package/build/Release/fast_xml.node", &elf_stub),
    ]);

    let report = scan_and_dump(
        "S10: husky + node-gyp build hooks (both in benign allow-set)",
        "fast-xml-parser-4.3.2.tgz",
        &tgz,
    );

    // Both `install: node-gyp rebuild` and `prepare: husky install` are in
    // BENIGN_PATTERNS. Neither must trigger any InstallScript/Obfuscation/
    // Exfiltration/CommandExecution finding from the supply_chain engine.
    let bad_sc_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            f.engine == "supply_chain"
                && matches!(
                    f.category,
                    cleanton_antivirus::ThreatCategory::InstallScript
                        | cleanton_antivirus::ThreatCategory::Obfuscation
                        | cleanton_antivirus::ThreatCategory::Exfiltration
                        | cleanton_antivirus::ThreatCategory::CommandExecution
                )
        })
        .collect();
    assert!(
        bad_sc_findings.is_empty(),
        "S10 husky+node-gyp hooks must not trigger supply_chain malice rules; \
         unexpected findings: {bad_sc_findings:#?}"
    );
    assert!(
        report.verdict == Verdict::Clean || report.verdict == Verdict::Suspicious,
        "S10 must not be Malicious; got {:?} score={} findings={:?}",
        report.verdict,
        report.score,
        report.findings,
    );
    assert_no_worm_findings(&report, "S10");
}

// ── SAMPLE 11: packages with `my-` / `the-` name prefixes ────────────────────

#[test]
fn fp_s11_my_the_name_prefixes() {
    // Package names like `my-logger` (no popular bare name match) and
    // `the-validator` (bare name `validator` IS popular → typosquat prefix FP)
    // must not reach Malicious from typosquatting signals alone.
    //
    // `my-logger` — "logger" is not in POPULAR_PACKAGES, so no typosquat signal.
    // `the-validator` — "validator" IS popular; TYPOSQUAT_TYPO_PREFIX_PATTERN fires
    // (severity=High/confidence=High → score≈55 → Suspicious). This is a documented
    // FP: `the-` prefix on a common English noun should not be treated as a squat of
    // a popular npm package with that name.  Verdict must stay ≤ Suspicious.
    let pkg_json_my = br#"{
  "name": "my-logger",
  "version": "1.0.0",
  "description": "A simple structured logger for my projects",
  "main": "index.js",
  "scripts": {
    "test": "jest"
  },
  "license": "MIT"
}"#;

    let tgz_my = make_tgz(&[
        ("package/package.json", pkg_json_my),
        (
            "package/index.js",
            b"'use strict';\nconsole.log('logger ready');\nmodule.exports = { log: console.log };\n",
        ),
    ]);

    let report_my = scan_and_dump(
        "S11a: package named `my-logger` (no popular bare-name match)",
        "my-logger-1.0.0.tgz",
        &tgz_my,
    );

    assert!(
        report_my.verdict == Verdict::Clean || report_my.verdict == Verdict::Suspicious,
        "S11a my-logger must not be Malicious; got {:?} score={} findings={:?}",
        report_my.verdict,
        report_my.score,
        report_my.findings,
    );
    assert_no_worm_findings(&report_my, "S11a");

    // `the-validator` hits TYPOSQUAT_TYPO_PREFIX_PATTERN against `validator`.
    // Documented remaining FP: prefix patterns on generic English nouns that
    // happen to share a bare name with a popular package are over-broad.
    // Must stay ≤ Suspicious (not Malicious).
    let pkg_json_the = br#"{
  "name": "the-validator",
  "version": "1.0.0",
  "description": "Schema validation utilities",
  "main": "index.js",
  "scripts": {
    "test": "jest"
  },
  "license": "MIT"
}"#;

    let tgz_the = make_tgz(&[
        ("package/package.json", pkg_json_the),
        (
            "package/index.js",
            b"'use strict';\nmodule.exports = { validate: (v) => Boolean(v) };\n",
        ),
    ]);

    let report_the = scan_and_dump(
        "S11b: package named `the-validator` (typosquat prefix FP against `validator`)",
        "the-validator-1.0.0.tgz",
        &tgz_the,
    );

    // The TYPOSQUAT_TYPO_PREFIX_PATTERN rule fires here — this is the documented
    // FP.  It must NOT push the verdict to Malicious (a single Typosquatting/High
    // finding scores ≈55 → Suspicious, below the 70-threshold for Malicious).
    assert!(
        report_the.verdict == Verdict::Clean || report_the.verdict == Verdict::Suspicious,
        "S11b the-validator must not be Malicious; got {:?} score={} findings={:?}",
        report_the.verdict,
        report_the.score,
        report_the.findings,
    );
    assert_no_worm_findings(&report_the, "S11b");
}
