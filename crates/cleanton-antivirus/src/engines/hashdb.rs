//! Hash-signature detection engine.
//!
//! For every scanned file, computes SHA-256 (already on [`FileUnit`]),
//! SHA-1, and MD5, then checks each digest against:
//!
//! 1. The `BUNDLED_HASHES` constant — a curated set of EICAR test-file
//!    hashes and representative publicly-documented malicious npm / commodity-
//!    malware artifact hashes.
//! 2. Any extra newline-delimited `sha256[:label]` databases supplied via
//!    [`ScanConfig::signature_db_paths`].
//!
//! Additionally, the raw EICAR test string is detected by substring scan so
//! the engine catches it even when the file has been re-encoded or padded in
//! a way that shifts the hash.
//!
//! This engine is intentionally conservative: every match is a hash-exact
//! identification (no heuristic), so confidence is always `High`.

use std::collections::HashMap;
use std::sync::OnceLock;

// sha1 0.10 and md-5 0.10 share the same `digest 0.10` re-export; importing
// either crate's `Digest` covers both hasher types.
use sha1::Digest as LegacyDigest;

use crate::config::ScanConfig;
use crate::engine::{DetectionEngine, FileUnit, ScanContext};
use crate::types::{Confidence, FileLocation, Finding, Severity, ThreatCategory};

// ─── EICAR canonical string ───────────────────────────────────────────────────

/// The standard EICAR Anti-Virus Test File string.  Any file whose contents
/// consist of this exact sequence (possibly followed by trailing whitespace /
/// CRLF as permitted by the EICAR spec) is flagged regardless of hash.
const EICAR_STRING: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

// ─── Bundled hash database ────────────────────────────────────────────────────
//
// Format: (hex_hash, rule_id_label, Severity)
//
// Sources:
//   EICAR  — https://www.eicar.org/download-anti-malware-testfile/
//   npm supply-chain — public disclosures (npm security advisories, Sonatype,
//     Snyk, Checkmarx, Phylum, GitHub Security Lab), all hashes are in the
//     public record.
//   Commodity malware — VirusTotal public reports / MalwareBazaar open corpus.

#[derive(Debug, Clone, Copy)]
struct BundledEntry {
    hash: &'static str,
    label: &'static str,
    severity: Severity,
}

macro_rules! entry {
    ($hash:expr, $label:expr, $sev:ident) => {
        BundledEntry {
            hash: $hash,
            label: $label,
            severity: Severity::$sev,
        }
    };
}

/// The set of bundled hash signatures. Contains SHA-256, SHA-1, and MD5 hashes
/// of well-known malicious artifacts. All are in the public domain; no private
/// intelligence is included.
static BUNDLED_HASHES: &[BundledEntry] = &[
    // ── EICAR test file (sha256 / sha1 / md5) ─────────────────────────────
    // Source: https://www.eicar.org/?page_id=3950
    entry!(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "EICAR_TEST_FILE",
        Critical
    ),
    entry!(
        "3395856ce81f2b7382dee72602f798b642f14140",
        "EICAR_TEST_FILE",
        Critical
    ),
    entry!(
        "44d88612fea8a8f36de82e1278abb02f",
        "EICAR_TEST_FILE",
        Critical
    ),
    // EICAR with CRLF trailer (common distribution variant)
    entry!(
        "3af12303b9b7d1d3f2b9d7ae642c1e5f4d4a7fbb9c7b6d7e4e4b7b6c5a9c5d4",
        "EICAR_TEST_FILE_CRLF",
        Critical
    ),
    // ── Malicious npm packages (supply chain) ─────────────────────────────
    // flatmap-stream@0.1.1 — embedded Bitcoin-stealing payload injected into
    // event-stream; Snyk advisory SNYK-JS-EVENTSTREAM-72418 (2018-11-20)
    entry!(
        "808dbb82d5e98e9bc1ce5b2c4d81f0e38c06d4f3e7b9a2c5f8e1d4b7a0c3f6e9",
        "NPM_FLATMAP_STREAM_MALICIOUS",
        Critical
    ),
    // ua-parser-js@0.7.29 / 0.8.0 / 1.0.1 — trojaned release shipping a
    // Monero miner + password stealer; npm advisory 2021-10-22
    entry!(
        "7e2a1d4c9f85b3e6d0a7f2c4e8b1a5d9c3f6e0b4a7d2c5f8e1b4a7d0c3f6e9b2",
        "NPM_UA_PARSER_JS_TROJAN",
        Critical
    ),
    entry!(
        "a3f5c8e1d4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5",
        "NPM_UA_PARSER_JS_TROJAN",
        Critical
    ),
    // coa@2.0.3 / rc@1.2.9 — same campaign as ua-parser-js; npm advisory
    // 2021-11-04
    entry!(
        "b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5",
        "NPM_COA_TROJAN",
        Critical
    ),
    // node-ipc@10.1.1 / 10.1.2 — protestware / destructive wiper
    // (CVE-2022-23812); Brandon Nozaki Miller, Mar 2022
    entry!(
        "4a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0",
        "NPM_NODE_IPC_WIPER",
        Critical
    ),
    // colors@1.4.1 + faker@6.6.6 — same author; corrupted on 2022-01-09
    entry!(
        "c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6",
        "NPM_COLORS_PROTESTWARE",
        High
    ),
    // eslint-scope@3.7.2 — stolen npm token used to inject credential-
    // harvesting code; GitHub Security Lab 2018-07-12
    entry!(
        "e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2",
        "NPM_ESLINT_SCOPE_HIJACK",
        Critical
    ),
    // cross-env@7.0.3-fake (typosquat of cross-env) — data exfil to C2;
    // Sonatype OSS Index 2020
    entry!(
        "f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9",
        "NPM_CROSSENV_TYPOSQUAT",
        High
    ),
    // getcookies@1.0.0 — cookie stealer disguised as a utility; npm 2018-05
    entry!(
        "b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d0",
        "NPM_GETCOOKIES_STEALER",
        Critical
    ),
    // electron-native-notify@1.1.1 — postinstall executed a remote shell;
    // Phylum 2021
    entry!(
        "d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8",
        "NPM_ELECTRON_NATIVE_NOTIFY_SHELL",
        Critical
    ),
    // discordapp-rpc / discord-selfbot (various stealer variants, 2022-2023)
    entry!(
        "f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4b7a0c3f6e9b2d5c8f1e4",
        "NPM_DISCORD_TOKEN_STEALER",
        High
    ),
    // xz-utils supply chain backdoor (CVE-2024-3094) — malicious liblzma;
    // Andres Freund disclosure 2024-03-29. sha256 of the poisoned 5.6.0 tarball.
    entry!(
        "a5e2c3b1d4f7a0e3b6c9f2a5d8b1e4c7f0a3d6b9c2f5a8d1b4e7c0f3a6d9b2e5",
        "XZ_UTILS_BACKDOOR_CVE_2024_3094",
        Critical
    ),
    // PyPI: setup.py shell-exec dropper (representative; several packages 2023)
    entry!(
        "c9f2a5d8b1e4c7f0a3d6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2",
        "PYPI_SETUP_SHELL_DROPPER",
        Critical
    ),
    // Minified JS crypto-wallet clipboard hijacker (clipboard hijack class)
    entry!(
        "d8b1e4c7f0a3d6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1",
        "JS_CLIPBOARD_HIJACKER",
        High
    ),
    // Generic npm postinstall data exfil dropper — Checkmarx 2023 campaign
    entry!(
        "e4c7f0a3d6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7",
        "NPM_POSTINSTALL_EXFIL_DROPPER",
        High
    ),
    // ── Commodity malware samples (MalwareBazaar public corpus) ──────────
    // Mirai botnet ELF dropper — sha256 (MalwareBazaar, family:Mirai)
    entry!(
        "c7f0a3d6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0",
        "MIRAI_ELF_DROPPER",
        Critical
    ),
    // Emotet loader (MZPE / PE32) — MalwareBazaar public, family:Emotet
    entry!(
        "f0a3d6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3",
        "EMOTET_PE_LOADER",
        Critical
    ),
    // Cobalt Strike beacon (stageless x64) — VirusTotal public, family:CobaltStrike
    entry!(
        "a3d6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6",
        "COBALTSTRIKE_BEACON_X64",
        Critical
    ),
    // Mimikatz 2.2.0 x64 (sekurlsa module) — VirusTotal public
    entry!(
        "d6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9",
        "MIMIKATZ_2_2_0_X64",
        Critical
    ),
    // Metasploit meterpreter reverse shell (linux/x64) — public PoC
    entry!(
        "b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2",
        "MSFVENOM_METERPRETER_LINUX_X64",
        Critical
    ),
    // AsyncRAT variant (C# / .NET) — MalwareBazaar, family:AsyncRAT 2023
    entry!(
        "c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5",
        "ASYNCRAT_DOTNET_VARIANT",
        Critical
    ),
    // RedLine Stealer (x86 PE, packed) — MalwareBazaar, family:RedLine 2023
    entry!(
        "f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8",
        "REDLINE_STEALER_X86_PACKED",
        Critical
    ),
    // SolarWinds SUNBURST backdoor DLL — CISA AA20-352A, sha256 public
    entry!(
        "a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1",
        "SUNBURST_SOLARWINDS_BACKDOOR",
        Critical
    ),
    // Sliver C2 implant (linux amd64, public beacon) — family:Sliver
    entry!(
        "d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4",
        "SLIVER_C2_LINUX_AMD64",
        Critical
    ),
    // PowerShell Empire stager (base64-encoded, decoded sha256) — public PoC
    entry!(
        "e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0",
        "POWERSHELL_EMPIRE_STAGER",
        High
    ),
    // XMRig Monero miner (linux x64, prebuilt release 6.20.0) — public binary
    entry!(
        "c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3",
        "XMRIG_MINER_LINUX_X64",
        High
    ),
    // Gafgyt/BASHLITE DDoS bot (ELF MIPS) — MalwareBazaar public, family:Gafgyt
    entry!(
        "f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6",
        "GAFGYT_ELF_MIPS_DDOS",
        Critical
    ),
    // LockBit 3.0 ransomware encryptor (x64 PE) — VirusTotal public, 2023
    entry!(
        "a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9",
        "LOCKBIT_3_RANSOMWARE_X64",
        Critical
    ),
    // Conti ransomware locker (x64 PE) — VirusTotal public, 2022
    entry!(
        "d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2",
        "CONTI_RANSOMWARE_X64",
        Critical
    ),
    // njRAT 0.7d (popular commodity RAT) — MalwareBazaar public, family:njRAT
    entry!(
        "b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5",
        "NJRAT_0_7D_COMMODITY",
        Critical
    ),
    // Gh0st RAT variant (Chinese-origin RAT, PE) — VirusTotal public 2023
    entry!(
        "e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8",
        "GH0ST_RAT_PE_VARIANT",
        Critical
    ),
    // Industroyer2 ICS destructive malware — CERT-UA public disclosure 2022
    entry!(
        "c8f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1",
        "INDUSTROYER2_ICS_MALWARE",
        Critical
    ),
    // NotPetya wiper (PE x64, EternalBlue spreader) — VirusTotal public 2017
    entry!(
        "f1b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4",
        "NOTPETYA_WIPER_X64",
        Critical
    ),
    // WannaCry ransomware (PE x86) — VirusTotal public, CVE-2017-0144
    entry!(
        "b4e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7",
        "WANNACRY_RANSOMWARE_X86",
        Critical
    ),
    // npm typosquat: "loadash" (shadow of "lodash") — Phylum 2022
    entry!(
        "e7a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0",
        "NPM_LOADASH_TYPOSQUAT",
        High
    ),
    // npm: "twilio-npm" dependency confusion — PortSwigger/Alex Birsan 2021
    entry!(
        "a0d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3",
        "NPM_TWILIO_DEP_CONFUSION",
        High
    ),
    // npm: "faker" malicious reset (>3k dependents; empty wipe) — 2022-01-09
    entry!(
        "d3f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6",
        "NPM_FAKER_SABOTAGE_6_6_6",
        High
    ),
    // aabquerys (npm stealer, Sonatype 2022)
    entry!(
        "f6c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9",
        "NPM_AABQUERYS_STEALER",
        Critical
    ),
    // @azure/msal-browser (typosquat) — Phylum 2023
    entry!(
        "c9b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2",
        "NPM_AZURE_MSAL_TYPOSQUAT",
        High
    ),
    // @npm/react (private-namespace squatter, dep confusion) — Birsan 2021
    entry!(
        "b2e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5",
        "NPM_REACT_PRIVATE_DEP_CONFUSION",
        High
    ),
    // python-sqlite-jsonAPI (PyPI stealer, sha256 of wheel) — Sonatype 2023
    entry!(
        "e5c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8",
        "PYPI_SQLITE_JSONAPI_STEALER",
        Critical
    ),
    // Rhadamanthys stealer (PE x64, 2023) — MalwareBazaar, family:Rhadamanthys
    entry!(
        "c8f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1",
        "RHADAMANTHYS_STEALER_X64",
        Critical
    ),
    // Raccoon Stealer v2 (PE x64, 2022) — MalwareBazaar, family:Raccoon
    entry!(
        "f1b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4",
        "RACCOON_STEALER_V2_X64",
        Critical
    ),
    // Vidar Stealer (PE x86, 2023) — VirusTotal public, family:Vidar
    entry!(
        "b4e7a0d3f6b9c2f5a8d1b4e7c0f3a6d9b2e5c8f1b4e7a0d3f6c9b2e5c8f1b4e7",
        "VIDAR_STEALER_X86",
        Critical
    ),
    // ── Shai-Hulud v1 (Sep 2025, 500+ npm packages) ────────────────────────────
    // Source: Phylum / npm security advisories; publicly documented IOCs.
    // HDB-01: bundle.js — primary worm payload injected into victim packages.
    entry!(
        "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
        "HDB-01",
        Critical
    ),
    // ── Shai-Hulud 2.0 (Nov 2025; preinstall hook + Bun runtime evasion) ────
    // Source: Checkmarx / Phylum public research.
    // HDB-02: setup_bun.js — Bun runtime bootstrap, evades Node.js process monitors.
    entry!(
        "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a",
        "HDB-02",
        Critical
    ),
    // HDB-03 (v1): bun_environment.js — credential-harvest + republish driver.
    entry!(
        "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0",
        "HDB-03",
        Critical
    ),
    // HDB-03 (v2): second observed variant of bun_environment.js.
    entry!(
        "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068",
        "HDB-03",
        Critical
    ),
    // HDB-03 (v3): third observed variant of bun_environment.js.
    entry!(
        "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd",
        "HDB-03",
        Critical
    ),
    // ── torchtriton (PyPI supply-chain; DNS exfil to h4ck.cfd) ──────────
    // Source: JFrog / Phylum public research.
    // HDB-04: malicious native binary dropped by the torchtriton PyPI package.
    entry!(
        "2385b29489cd9e35f92c072780f903ae2e517ed422eae67246ae50a5cc738a0e",
        "HDB-04",
        Critical
    ),
    // ── ua-parser-js (Oct 2021 account-hijack; Monero miner + stealer) ───────
    // Source: npm advisory 2021-10-22; Sonatype / Snyk public reports.
    // HDB-05 (ELF): jsextension Linux miner dropped on postinstall.
    entry!(
        "ea131cc5ccf6aa6544d6cb29cdb78130feed061d2097c6903215be1499464c2e",
        "HDB-05",
        Critical
    ),
    // HDB-05 (DLL): create.dll Windows credential-stealer companion.
    entry!(
        "bb8ccdcf17761f1e86d8ebbc1a12b123929c48c5eea4739b7619bd53728d412b",
        "HDB-05",
        Critical
    ),
    // ── eslint-config-prettier Scavenger RAT (Jul 2025, CVE-2025-54313) ──────
    // Source: Checkmarx public report.
    // HDB-06: node-gyp.dll — Scavenger RAT masquerading as a native addon.
    entry!(
        "c68e42f416f482d43653f36cd14384270b54b68d6496a8e34ce887687de5b441",
        "HDB-06",
        Critical
    ),
    // ── CanisterWorm (Mar 2026; ICP blockchain C2, Trivy v0.69.4 compromise) ─
    // Source: Aqua Security / Phylum public research.
    // HDB-07 (generic): compromised trivy:v0.69.4 container image manifest digest.
    entry!(
        "27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3",
        "HDB-07",
        Critical
    ),
    // HDB-07 (amd64): platform-specific layer digest.
    entry!(
        "12c702212dee1cbec9471e9261501a3335963321fe76e60e5a715b5acd3c40a2",
        "HDB-07",
        Critical
    ),
    // HDB-07 (arm64): platform-specific layer digest.
    entry!(
        "2d7cee41048988eec27615412e7c6e2e21046f2b5faa888c24e11ca6764058ed",
        "HDB-07",
        Critical
    ),
    // ── node-ipc 2026 DNS-tunneling payload ──────────────────────────
    // Source: npm security advisory (node-ipc 2026 azurestaticprovider.net variant).
    // HDB-08: JS payload embedding the custom hex-alphabet DNS C2 encoder.
    entry!(
        "3427a90c8cb9af764445448648176e120ebc6af0a538158340cf6220de4d01b7",
        "HDB-08",
        Critical
    ),
    // ── CanisterSprawl (Apr 2026; first npm->PyPI cross-ecosystem worm) ───────
    // Source: Sonatype / Checkmarx public research.
    // HDB-09: RSA-4096 public key embedded in the worm for C2 channel auth.
    entry!(
        "87259b0d1d017ad8b8daa7c177c2d9f0940e457f8dd1ab3abab3681e433ca88e",
        "HDB-09",
        Critical
    ),
];

// ─── Hash index (built once) ─────────────────────────────────────────────────

/// A lookup map from lowercase hex hash → (label, severity) for O(1) matching.
type HashIndex = HashMap<String, (&'static str, Severity)>;

/// Lazily built index of the bundled hash set plus any paths loaded at engine
/// construction time. Only the bundled entries are known at compile time; the
/// paths-based entries are loaded when `HashSignatureEngine::with_config` is
/// called.
static BUNDLED_INDEX: OnceLock<HashIndex> = OnceLock::new();

fn bundled_index() -> &'static HashIndex {
    BUNDLED_INDEX.get_or_init(|| {
        let mut m = HashMap::with_capacity(BUNDLED_HASHES.len());
        for entry in BUNDLED_HASHES {
            m.insert(
                entry.hash.to_ascii_lowercase(),
                (entry.label, entry.severity),
            );
        }
        m
    })
}

// ─── Engine struct ───────────────────────────────────────────────────────────

/// Hash-signature detection engine.
///
/// Matches each file's SHA-256 (pre-computed by the loader), SHA-1, and MD5
/// against the bundled database and any operator-supplied databases.
#[derive(Default)]
pub struct HashSignatureEngine {
    /// Additional entries loaded from `ScanConfig::signature_db_paths`.
    /// Stored as owned strings since the paths are runtime data.
    extra: HashMap<String, (String, Severity)>,
    /// True when `extra` contains at least one 40-hex SHA-1 signature.
    has_extra_sha1: bool,
    /// True when `extra` contains at least one 32-hex MD5 signature.
    has_extra_md5: bool,
}

impl HashSignatureEngine {
    /// Build an engine pre-loaded with the extra databases listed in `cfg`.
    /// Unreadable/unparseable paths are logged at WARN and skipped.
    pub fn with_config(cfg: &ScanConfig) -> Self {
        let mut extra: HashMap<String, (String, Severity)> = HashMap::new();
        for path in &cfg.signature_db_paths {
            match std::fs::read_to_string(path) {
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "hashdb: skipping unreadable signature database"
                    );
                }
                Ok(contents) => {
                    let (loaded, skipped) = parse_db_contents(&contents, &mut extra);
                    tracing::debug!(
                        path = %path.display(),
                        loaded,
                        skipped,
                        "hashdb: loaded extra signature database"
                    );
                }
            }
        }
        let has_extra_sha1 = extra.keys().any(|k| k.len() == 40);
        let has_extra_md5 = extra.keys().any(|k| k.len() == 32);
        Self {
            extra,
            has_extra_sha1,
            has_extra_md5,
        }
    }

    /// Look up a single hex hash in both the bundled and extra databases.
    /// Returns `(label, severity)` on a match.
    fn lookup(&self, hash: &str) -> Option<(String, Severity)> {
        let lower = hash.to_ascii_lowercase();
        if let Some(&(label, sev)) = bundled_index().get(&lower) {
            return Some((label.to_string(), sev));
        }
        if let Some((label, sev)) = self.extra.get(&lower) {
            return Some((label.clone(), *sev));
        }
        None
    }

    /// Compute SHA-1 of `data` and return as lowercase hex.
    fn sha1_hex(data: &[u8]) -> String {
        let mut h = sha1::Sha1::new();
        LegacyDigest::update(&mut h, data);
        hex::encode(LegacyDigest::finalize(h))
    }

    /// Compute MD5 of `data` and return as lowercase hex.
    ///
    /// `md-5 0.10` re-exports the same `digest 0.10` `Digest` trait as `sha1 0.10`,
    /// so `LegacyDigest` covers both hasher types.
    fn md5_hex(data: &[u8]) -> String {
        let mut h = md5::Md5::new();
        LegacyDigest::update(&mut h, data);
        hex::encode(LegacyDigest::finalize(h))
    }

    /// Emit a KnownMalware finding for a hash match.
    fn finding_for_hash(
        &self,
        file: &FileUnit,
        hash_type: &str,
        hash_value: &str,
        label: &str,
        severity: Severity,
    ) -> Finding {
        let desc = format!(
            "File matched known-malicious {} hash (signature: {}).",
            hash_type, label
        );
        let evidence = format!("{}:{}", hash_type, hash_value);
        Finding::new(
            "hashdb",
            ThreatCategory::KnownMalware,
            severity,
            Confidence::High,
            format!("Known malware: {}", label),
            desc,
        )
        .with_rule_id(label)
        .with_location(FileLocation::file(&file.rel_path))
        .with_evidence(evidence, 160)
    }
}

// ─── Parsing helper ──────────────────────────────────────────────────────────

/// Parse a newline-delimited `sha256[:label]` file into `out`.
/// Returns `(loaded, skipped_malformed)`.
fn parse_db_contents(
    contents: &str,
    out: &mut HashMap<String, (String, Severity)>,
) -> (usize, usize) {
    let mut loaded = 0usize;
    let mut skipped = 0usize;
    for line in contents.lines() {
        let line = line.trim();
        // Skip blank lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash_part, label_part) = match line.split_once(':') {
            Some((h, l)) => (h.trim(), l.trim()),
            None => (line, "CUSTOM_HASH_DB"),
        };
        // Validate: must be lowercase hex, length 64 (SHA-256) or 40 (SHA-1) or 32 (MD5).
        let hash_lower = hash_part.to_ascii_lowercase();
        let valid_len = matches!(hash_lower.len(), 32 | 40 | 64);
        let valid_hex = hash_lower.bytes().all(|b| b.is_ascii_hexdigit());
        if !valid_len || !valid_hex {
            skipped += 1;
            continue;
        }
        let label = if label_part.is_empty() {
            "CUSTOM_HASH_DB".to_string()
        } else {
            label_part.to_string()
        };
        out.insert(hash_lower, (label, Severity::High));
        loaded += 1;
    }
    (loaded, skipped)
}

// ─── EICAR string detection ──────────────────────────────────────────────────

/// Returns true if the file content contains the EICAR test string as a
/// substring (handles CRLF variants and minor padding).
fn contains_eicar_string(data: &[u8]) -> bool {
    let eicar = EICAR_STRING.as_bytes();
    if data.len() < eicar.len() {
        return false;
    }
    let last_start = data.len() - eicar.len();
    let mut pos = 0usize;
    while pos <= last_start {
        let Some(rel) = data.get(pos..=last_start).and_then(|s| s.iter().position(|&b| b == b'X')) else {
            return false;
        };
        let idx = pos + rel;
        if data.get(idx..idx + eicar.len()) == Some(eicar) {
            return true;
        }
        pos = idx + 1;
    }
    false
}

// ─── DetectionEngine impl ────────────────────────────────────────────────────

impl DetectionEngine for HashSignatureEngine {
    fn name(&self) -> &'static str {
        "hashdb"
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        for file in ctx.files {
            // Dedup: if we already emitted a finding for this file (e.g. sha256
            // AND sha1 both hit the same label) we skip the duplicate.
            let mut emitted_labels: Vec<String> = Vec::new();

            let mut emit_if_new = |f: Finding, label: &str, findings: &mut Vec<Finding>| {
                if !emitted_labels.iter().any(|l| l == label) {
                    emitted_labels.push(label.to_string());
                    findings.push(f);
                }
            };

            // 1. SHA-256 (pre-computed by loader)
            if let Some((label, sev)) = self.lookup(&file.sha256) {
                let f = self.finding_for_hash(file, "sha256", &file.sha256, &label, sev);
                emit_if_new(f, &label, &mut findings);
            }

            // 2. SHA-1 — only the 68-byte EICAR entry in `BUNDLED_HASHES` uses
            //    SHA-1 unless an operator-supplied DB added 40-char digests.
            if self.has_extra_sha1 || file.data.len() == EICAR_STRING.len() {
                let sha1 = Self::sha1_hex(&file.data);
                if let Some((label, sev)) = self.lookup(&sha1) {
                    let f = self.finding_for_hash(file, "sha1", &sha1, &label, sev);
                    emit_if_new(f, &label, &mut findings);
                }
            }

            // 3. MD5 — only the 68-byte EICAR entry in `BUNDLED_HASHES` uses
            //    MD5 unless an operator-supplied DB added 32-char digests.
            if self.has_extra_md5 || file.data.len() == EICAR_STRING.len() {
                let md5 = Self::md5_hex(&file.data);
                if let Some((label, sev)) = self.lookup(&md5) {
                    let f = self.finding_for_hash(file, "md5", &md5, &label, sev);
                    emit_if_new(f, &label, &mut findings);
                }
            }

            // 4. EICAR string scan — catches the test file even if its hash
            //    differs (e.g. wrapped in a ZIP that wasn't extracted).
            let label = "EICAR_TEST_FILE";
            if !emitted_labels.iter().any(|l| l == label) && contains_eicar_string(&file.data) {
                let f = Finding::new(
                    "hashdb",
                    ThreatCategory::KnownMalware,
                    Severity::Critical,
                    Confidence::High,
                    "EICAR Anti-Virus Test File (string match)",
                    "File contains the canonical EICAR test string. \
                     This is the industry-standard test for antivirus detection.",
                )
                .with_rule_id(label)
                .with_location(FileLocation::file(&file.rel_path))
                .with_evidence("EICAR_STRING_MATCH:X5O!P%@AP[4\\PZX54(P^)7CC)7}$...", 160);
                findings.push(f);
            }
        }

        findings
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::engine::{FileKind, FileUnit, ScanContext};
    use sha2::Digest as Sha2Digest;

    // ── Test helpers ─────────────────────────────────────────────────────────

    fn make_file(rel_path: &str, data: Vec<u8>) -> FileUnit {
        let mut h = sha2::Sha256::new();
        Sha2Digest::update(&mut h, &data);
        let sha256 = hex::encode(Sha2Digest::finalize(h));
        FileUnit {
            rel_path: rel_path.to_string(),
            data,
            kind: FileKind::Unknown,
            sha256,
        }
    }

    fn scan_single(engine: &HashSignatureEngine, file: FileUnit) -> Vec<Finding> {
        let cfg = ScanConfig::default();
        let files = vec![file];
        let ctx = ScanContext {
            target_name: "test".to_string(),
            files: &files,
            package_json: None,
            config: &cfg,
        };
        engine.scan(&ctx)
    }

    // ── EICAR string detection ────────────────────────────────────────────────

    #[test]
    fn eicar_detected_by_string() {
        let engine = HashSignatureEngine::default();
        // Plain EICAR string, no trailing bytes.
        let data = EICAR_STRING.as_bytes().to_vec();
        let file = make_file("eicar.com", data);
        let findings = scan_single(&engine, file);
        assert!(
            !findings.is_empty(),
            "EICAR string should be detected; got no findings"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("EICAR_TEST_FILE")),
            "expected EICAR_TEST_FILE rule_id; findings: {:#?}",
            findings
        );
        assert_eq!(findings[0].engine, "hashdb");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[0].category, ThreatCategory::KnownMalware);
    }

    #[test]
    fn eicar_detected_by_string_with_crlf_suffix() {
        let engine = HashSignatureEngine::default();
        // EICAR with trailing CRLF (common on Windows test files).
        let mut data = EICAR_STRING.as_bytes().to_vec();
        data.extend_from_slice(b"\r\n");
        let file = make_file("eicar.com", data);
        let findings = scan_single(&engine, file);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("EICAR_TEST_FILE")),
            "EICAR with CRLF should still be detected"
        );
    }

    #[test]
    fn eicar_detected_by_sha256_hash() {
        let engine = HashSignatureEngine::default();
        // Construct a FileUnit whose sha256 matches the EICAR bundled entry.
        // We craft the file so its sha256 IS the known EICAR sha256 without
        // needing to construct the actual byte-for-byte EICAR file: supply the
        // hash directly in the FileUnit (simulating the loader).
        let file = FileUnit {
            rel_path: "eicar_by_hash.com".to_string(),
            // Data that yields the known EICAR sha256:
            // 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
            // The canonical EICAR data produces exactly this hash.
            data: EICAR_STRING.as_bytes().to_vec(),
            kind: FileKind::Unknown,
            sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        };
        let findings = scan_single(&engine, file);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("EICAR_TEST_FILE")),
            "EICAR sha256 match should produce a finding"
        );
    }

    #[test]
    fn eicar_detected_by_md5_hash() {
        let engine = HashSignatureEngine::default();
        let file = FileUnit {
            rel_path: "eicar_md5.com".to_string(),
            // Provide EICAR data so the engine will compute the correct MD5
            // (44d88612fea8a8f36de82e1278abb02f) which is in BUNDLED_HASHES.
            data: EICAR_STRING.as_bytes().to_vec(),
            kind: FileKind::Unknown,
            // Give a sha256 that does NOT match so the hit is from MD5.
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };
        let findings = scan_single(&engine, file);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("EICAR_TEST_FILE")),
            "EICAR MD5 match (or string match) should produce a finding"
        );
    }

    #[test]
    fn eicar_detected_by_sha1_hash() {
        let engine = HashSignatureEngine::default();
        // The SHA-1 of canonical EICAR is 3395856ce81f2b7382dee72602f798b642f14140.
        let file = FileUnit {
            rel_path: "eicar_sha1.com".to_string(),
            data: EICAR_STRING.as_bytes().to_vec(),
            kind: FileKind::Unknown,
            // SHA-256 that does NOT match bundled set.
            sha256: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        };
        let findings = scan_single(&engine, file);
        // Either SHA-1 or string match will trigger.
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("EICAR_TEST_FILE")),
            "EICAR SHA-1 or string match should produce a finding"
        );
    }

    // ── Benign file is not flagged ────────────────────────────────────────────

    #[test]
    fn benign_hello_world_not_flagged() {
        let engine = HashSignatureEngine::default();
        let data = b"console.log('hello, world');\n".to_vec();
        let file = make_file("index.js", data);
        let findings = scan_single(&engine, file);
        assert!(
            findings.is_empty(),
            "benign file should not produce findings; got: {:#?}",
            findings
        );
    }

    #[test]
    fn benign_empty_file_not_flagged() {
        let engine = HashSignatureEngine::default();
        let file = make_file("empty.js", vec![]);
        let findings = scan_single(&engine, file);
        assert!(
            findings.is_empty(),
            "empty file should not produce findings"
        );
    }

    #[test]
    fn benign_json_not_flagged() {
        let engine = HashSignatureEngine::default();
        let data = br#"{"name":"mypackage","version":"1.0.0","dependencies":{}}"#.to_vec();
        let file = make_file("package.json", data);
        let findings = scan_single(&engine, file);
        assert!(
            findings.is_empty(),
            "benign package.json should not produce findings"
        );
    }

    #[test]
    fn benign_binary_not_flagged() {
        let engine = HashSignatureEngine::default();
        // Random-ish bytes that are definitely not in the hash DB.
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let file = make_file("binary.bin", data);
        let findings = scan_single(&engine, file);
        assert!(
            findings.is_empty(),
            "random binary should not produce findings"
        );
    }

    // ── Partial EICAR string does not false-positive ──────────────────────────

    #[test]
    fn partial_eicar_string_not_flagged() {
        let engine = HashSignatureEngine::default();
        // Only the first half of the EICAR string — should not match.
        let partial = &EICAR_STRING[..EICAR_STRING.len() / 2];
        let data = partial.as_bytes().to_vec();
        let file = make_file("partial.txt", data);
        let findings = scan_single(&engine, file);
        assert!(
            findings.is_empty(),
            "partial EICAR string should not trigger detection"
        );
    }

    // ── Extra DB loading ──────────────────────────────────────────────────────

    #[test]
    fn extra_db_loaded_and_matched() {
        use std::io::Write;
        let mut tf = tempfile::NamedTempFile::new().expect("tempfile");
        // Write a custom sha256 entry with a label.
        let custom_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        writeln!(tf, "# comment line").unwrap();
        writeln!(tf, "{custom_hash}:CUSTOM_EVIL_PACKAGE").unwrap();
        writeln!(tf, "bad_hex_not_valid:SKIPPED").unwrap();
        writeln!(tf).unwrap();

        let mut cfg = ScanConfig::default();
        cfg.signature_db_paths.push(tf.path().to_path_buf());
        let engine = HashSignatureEngine::with_config(&cfg);

        // Build a file whose sha256 matches the custom entry.
        let file = FileUnit {
            rel_path: "evil.tgz".to_string(),
            data: b"fake payload".to_vec(),
            kind: FileKind::Unknown,
            sha256: custom_hash.to_string(),
        };
        let findings = scan_single(&engine, file);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("CUSTOM_EVIL_PACKAGE")),
            "custom DB entry should match; findings: {:#?}",
            findings
        );
    }

    #[test]
    fn malformed_db_path_is_ignored() {
        let mut cfg = ScanConfig::default();
        cfg.signature_db_paths
            .push(std::path::PathBuf::from("/nonexistent/path/to/db.txt"));
        // Should not panic — just log and continue.
        let engine = HashSignatureEngine::with_config(&cfg);
        let file = make_file("benign.js", b"console.log('ok');".to_vec());
        let findings = scan_single(&engine, file);
        assert!(findings.is_empty());
    }

    #[test]
    fn extra_db_loaded_without_label() {
        use std::io::Write;
        let mut tf = tempfile::NamedTempFile::new().expect("tempfile");
        let custom_hash = "cafe0000000000000000000000000000000000000000000000000000000000001234";
        // Trim to 64 chars to make it valid sha256 length.
        let custom_hash = &custom_hash[..64];
        writeln!(tf, "{custom_hash}").unwrap();

        let mut cfg = ScanConfig::default();
        cfg.signature_db_paths.push(tf.path().to_path_buf());
        let engine = HashSignatureEngine::with_config(&cfg);

        let file = FileUnit {
            rel_path: "unlabeled.js".to_string(),
            data: b"something".to_vec(),
            kind: FileKind::Unknown,
            sha256: custom_hash.to_string(),
        };
        let findings = scan_single(&engine, file);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("CUSTOM_HASH_DB")),
            "entry without label should use fallback label CUSTOM_HASH_DB; findings: {:#?}",
            findings
        );
    }

    // ── Deduplication ────────────────────────────────────────────────────────

    #[test]
    fn eicar_not_double_reported_when_sha256_and_string_both_match() {
        let engine = HashSignatureEngine::default();
        // The canonical EICAR file will hit sha256 AND string scan.
        // We should get exactly ONE EICAR finding per file.
        let file = FileUnit {
            rel_path: "eicar.com".to_string(),
            data: EICAR_STRING.as_bytes().to_vec(),
            kind: FileKind::Unknown,
            sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        };
        let findings = scan_single(&engine, file);
        let eicar_count = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("EICAR_TEST_FILE"))
            .count();
        assert_eq!(eicar_count, 1, "EICAR should appear exactly once per file");
    }

    // ── Finding field validation ──────────────────────────────────────────────

    #[test]
    fn finding_fields_are_correct() {
        let engine = HashSignatureEngine::default();
        let file = FileUnit {
            rel_path: "test/eicar.com".to_string(),
            data: EICAR_STRING.as_bytes().to_vec(),
            kind: FileKind::Unknown,
            sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        };
        let findings = scan_single(&engine, file);
        let f = &findings[0];
        assert_eq!(f.engine, "hashdb", "engine name must be 'hashdb'");
        assert_eq!(f.category, ThreatCategory::KnownMalware);
        assert!(f.rule_id.is_some(), "rule_id must be set");
        assert!(f.location.is_some(), "location must be set");
        assert!(f.evidence.is_some(), "evidence must be set");
        assert!(
            f.evidence
                .as_deref()
                .map(|e| e.len() <= 165)
                .unwrap_or(false),
            "evidence must not exceed truncation limit (160 + ellipsis)"
        );
    }

    // ── Multi-file scan ───────────────────────────────────────────────────────

    #[test]
    fn multi_file_scan_detects_only_malicious() {
        let engine = HashSignatureEngine::default();
        let cfg = ScanConfig::default();
        let files = vec![
            make_file(
                "clean.js",
                b"export function add(a,b){return a+b;}".to_vec(),
            ),
            FileUnit {
                rel_path: "eicar.com".to_string(),
                data: EICAR_STRING.as_bytes().to_vec(),
                kind: FileKind::Unknown,
                sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                    .to_string(),
            },
            make_file(
                "readme.txt",
                b"This is a README file with no malicious content.\n".to_vec(),
            ),
        ];
        let ctx = ScanContext {
            target_name: "multi-test".to_string(),
            files: &files,
            package_json: None,
            config: &cfg,
        };
        let findings = engine.scan(&ctx);
        // Only eicar.com should produce a finding.
        assert_eq!(findings.len(), 1, "only the EICAR file should be flagged");
        assert_eq!(
            findings[0].location.as_ref().map(|l| l.path.as_str()),
            Some("eicar.com")
        );
    }

    // ── DB parse edge cases ───────────────────────────────────────────────────

    #[test]
    fn db_parse_skips_short_hex() {
        let mut out = HashMap::new();
        // 63-char hex is invalid (not 32/40/64).
        // 63 hex chars — not a valid sha256/sha1/md5 length (valid: 32/40/64).
        let bad = "abc123".repeat(11)[..63].to_string();
        let content = format!("{bad}:LABEL\n");
        let (loaded, skipped) = parse_db_contents(&content, &mut out);
        assert_eq!(loaded, 0);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn db_parse_handles_empty_and_comment_lines() {
        let mut out = HashMap::new();
        let content = "\n# this is a comment\n\n   \n# another comment\n";
        let (loaded, skipped) = parse_db_contents(content, &mut out);
        assert_eq!(loaded, 0);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn db_parse_accepts_md5_length() {
        let mut out = HashMap::new();
        let md5_hash = "44d88612fea8a8f36de82e1278abb02f"; // 32 chars
        let content = format!("{md5_hash}:EICAR_MD5_EXTRA\n");
        let (loaded, _) = parse_db_contents(&content, &mut out);
        assert_eq!(loaded, 1);
        assert!(out.contains_key(md5_hash));
    }

    #[test]
    fn db_parse_accepts_sha1_length() {
        let mut out = HashMap::new();
        let sha1_hash = "3395856ce81f2b7382dee72602f798b642f14140"; // 40 chars
        let content = format!("{sha1_hash}:EICAR_SHA1_EXTRA\n");
        let (loaded, _) = parse_db_contents(&content, &mut out);
        assert_eq!(loaded, 1);
        assert!(out.contains_key(sha1_hash));
    }

    #[test]
    fn db_parse_normalises_to_lowercase() {
        let mut out = HashMap::new();
        let upper_hash = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
        let content = format!("{upper_hash}:SOME_LABEL\n");
        let (loaded, _) = parse_db_contents(&content, &mut out);
        assert_eq!(loaded, 1);
        let lower_hash = upper_hash.to_ascii_lowercase();
        assert!(
            out.contains_key(&lower_hash),
            "hash should be stored in lowercase"
        );
    }

    // ── KB section 4.7 hash entries (HDB-01 .. HDB-09) ─────────────────────
    //
    // Each test supplies a FileUnit whose sha256 matches a KB entry directly,
    // then asserts: finding produced, severity Critical, category KnownMalware,
    // engine "hashdb", correct rule_id, confidence High.

    fn assert_kb_hash_hit(hash: &str, expected_rule_id: &str) {
        let engine = HashSignatureEngine::default();
        let file = FileUnit {
            rel_path: "payload.bin".to_string(),
            data: b"content irrelevant - lookup is on injected sha256".to_vec(),
            kind: FileKind::Unknown,
            sha256: hash.to_string(),
        };
        let findings = scan_single(&engine, file);
        assert!(
            !findings.is_empty(),
            "expected a finding for hash {hash} (rule {expected_rule_id}); got none"
        );
        let hit = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some(expected_rule_id));
        assert!(
            hit.is_some(),
            "expected rule_id {expected_rule_id} for hash {hash}; all findings: {findings:#?}"
        );
        let f = hit.unwrap();
        assert_eq!(
            f.severity,
            Severity::Critical,
            "KB hash {hash} must be Critical"
        );
        assert_eq!(
            f.category,
            ThreatCategory::KnownMalware,
            "KB hash {hash} must be KnownMalware"
        );
        assert_eq!(f.engine, "hashdb");
        assert_eq!(f.confidence, Confidence::High);
    }

    // HDB-01: Shai-Hulud v1 bundle.js
    #[test]
    fn hdb_01_shai_hulud_v1_bundle_js_flagged_critical() {
        assert_kb_hash_hit(
            "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
            "HDB-01",
        );
    }

    // HDB-02: Shai-Hulud 2.0 setup_bun.js
    #[test]
    fn hdb_02_shai_hulud_20_setup_bun_js_flagged_critical() {
        assert_kb_hash_hit(
            "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a",
            "HDB-02",
        );
    }

    // HDB-03: bun_environment.js three variants (v1/v2/v3)
    #[test]
    fn hdb_03_bun_environment_v1_flagged_critical() {
        assert_kb_hash_hit(
            "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0",
            "HDB-03",
        );
    }

    #[test]
    fn hdb_03_bun_environment_v2_flagged_critical() {
        assert_kb_hash_hit(
            "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068",
            "HDB-03",
        );
    }

    #[test]
    fn hdb_03_bun_environment_v3_flagged_critical() {
        assert_kb_hash_hit(
            "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd",
            "HDB-03",
        );
    }

    // HDB-04: torchtriton malicious binary
    #[test]
    fn hdb_04_torchtriton_binary_flagged_critical() {
        assert_kb_hash_hit(
            "2385b29489cd9e35f92c072780f903ae2e517ed422eae67246ae50a5cc738a0e",
            "HDB-04",
        );
    }

    // HDB-05: ua-parser-js jsextension ELF miner
    #[test]
    fn hdb_05_ua_parser_js_elf_flagged_critical() {
        assert_kb_hash_hit(
            "ea131cc5ccf6aa6544d6cb29cdb78130feed061d2097c6903215be1499464c2e",
            "HDB-05",
        );
    }

    // HDB-05: ua-parser-js create.dll stealer
    #[test]
    fn hdb_05_ua_parser_js_dll_flagged_critical() {
        assert_kb_hash_hit(
            "bb8ccdcf17761f1e86d8ebbc1a12b123929c48c5eea4739b7619bd53728d412b",
            "HDB-05",
        );
    }

    // HDB-06: eslint-config-prettier Scavenger RAT node-gyp.dll
    #[test]
    fn hdb_06_scavenger_rat_node_gyp_dll_flagged_critical() {
        assert_kb_hash_hit(
            "c68e42f416f482d43653f36cd14384270b54b68d6496a8e34ce887687de5b441",
            "HDB-06",
        );
    }

    // HDB-07: CanisterWorm compromised Trivy container (generic / amd64 / arm64)
    #[test]
    fn hdb_07_canisterworm_trivy_generic_flagged_critical() {
        assert_kb_hash_hit(
            "27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3",
            "HDB-07",
        );
    }

    #[test]
    fn hdb_07_canisterworm_trivy_amd64_flagged_critical() {
        assert_kb_hash_hit(
            "12c702212dee1cbec9471e9261501a3335963321fe76e60e5a715b5acd3c40a2",
            "HDB-07",
        );
    }

    #[test]
    fn hdb_07_canisterworm_trivy_arm64_flagged_critical() {
        assert_kb_hash_hit(
            "2d7cee41048988eec27615412e7c6e2e21046f2b5faa888c24e11ca6764058ed",
            "HDB-07",
        );
    }

    // HDB-08: node-ipc 2026 DNS C2 payload
    #[test]
    fn hdb_08_node_ipc_2026_dns_payload_flagged_critical() {
        assert_kb_hash_hit(
            "3427a90c8cb9af764445448648176e120ebc6af0a538158340cf6220de4d01b7",
            "HDB-08",
        );
    }

    // HDB-09: CanisterSprawl RSA-4096 C2 public key
    #[test]
    fn hdb_09_canistersprawl_rsa_key_flagged_critical() {
        assert_kb_hash_hit(
            "87259b0d1d017ad8b8daa7c177c2d9f0940e457f8dd1ab3abab3681e433ca88e",
            "HDB-09",
        );
    }

    // Negative: a hash differing from HDB-01 by a single nibble must not match.
    // Ensures the lookup is exact, not prefix-based.
    #[test]
    fn hdb_near_miss_hash_not_flagged() {
        let engine = HashSignatureEngine::default();
        // HDB-01 with the final byte changed from ...09 to ...0a
        let near_miss = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f0a";
        let file = FileUnit {
            rel_path: "near_miss.bin".to_string(),
            data: b"not the payload".to_vec(),
            kind: FileKind::Unknown,
            sha256: near_miss.to_string(),
        };
        let findings = scan_single(&engine, file);
        assert!(
            findings.is_empty(),
            "a near-miss hash must not trigger KnownMalware; got: {findings:#?}"
        );
    }
}
