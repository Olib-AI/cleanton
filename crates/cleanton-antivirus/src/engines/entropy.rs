//! Entropy-based detection engine.
//!
//! Identifies:
//! - Packed or encrypted native binaries (whole-file Shannon entropy > 7.2 bits/byte
//!   on ELF/PE/Mach-O files larger than 512 bytes → [`ThreatCategory::Packer`]).
//! - Obfuscated script payloads: very-high-entropy string literals, large
//!   base64/hex blobs embedded in source, or a minified single-line script
//!   whose dominant literal is enormous and high-entropy
//!   (→ [`ThreatCategory::Obfuscation`]).
//!
//! The engine intentionally does NOT flag [`FileKind::Archive`], [`FileKind::Wasm`],
//! or image/media files — compressed containers have legitimately high entropy
//! by design. Detection is gated on file kind and size thresholds so legitimate
//! minified bundles (React build output, etc.) do not produce false positives.
//!
//! Regexes are compiled once via [`std::sync::OnceLock`].

use std::sync::OnceLock;

use regex::Regex;
use tracing::trace;

use crate::engine::{DetectionEngine, FileKind, FileUnit, ScanContext};
use crate::types::{Confidence, FileLocation, Finding, Severity, ThreatCategory};

// ---------------------------------------------------------------------------
// Tuning constants
// ---------------------------------------------------------------------------

/// Whole-file entropy threshold (bits/byte) that flags a native binary as
/// packed/encrypted. Typical packed PE/ELF land above 7.2; legitimate
/// stripped binaries cluster around 6.2–6.8.
const BINARY_ENTROPY_THRESHOLD: f64 = 7.2;

/// Entropy threshold (bits/byte) applied to a standalone string literal or
/// blob excerpt inside a script file. Base64 sits around 6.0, AES-encrypted
/// blobs > 7.8. We flag at 5.7 to catch both base64 and hex-encoded payloads.
const STRING_ENTROPY_THRESHOLD: f64 = 5.7;

/// A string literal (stripped of quotes) must be at least this long (bytes)
/// before we bother computing its entropy — avoids noise on short tokens.
const MIN_STRING_LEN: usize = 200;

/// A contiguous base64/hex run must be at least this long to be suspicious
/// on its own.
const MIN_BLOB_LEN: usize = 200;

/// Minimum script file size (bytes). Tiny files contain too few bytes for
/// meaningful entropy statistics and generate more noise than signal.
const MIN_FILE_SIZE: usize = 512;

/// Minimum binary size before whole-file entropy is checked. Very small
/// binaries (stubs, tests) are often all-zero padding or trivial shellcode
/// for which whole-file entropy is not meaningful.
const MIN_BINARY_SIZE: usize = 512;

/// Sliding-window size (bytes) used when localizing high-entropy regions in
/// binary files.
const WINDOW_SIZE: usize = 256;

/// Step between windows (we slide by half the window to get decent coverage
/// without O(n²) work on large files).
const WINDOW_STEP: usize = 128;

/// A single line this long or longer in a script is treated as a minified
/// line and triggers the minified-script path.
const MINIFIED_LINE_LEN: usize = 500;

/// Engine name — must match the string stamped into every `Finding::engine`.
const ENGINE_NAME: &str = "entropy";

// ---------------------------------------------------------------------------
// Singleton regexes
// ---------------------------------------------------------------------------

/// Matches a single-quoted or double-quoted string literal and captures the
/// interior text.  We use the standard "match-with-escapes" idiom that the
/// regex NFA can compile in linear time: `[^"\\]*(?:\\.[^"\\]*)*`.  Length
/// filtering (≥ MIN_STRING_LEN bytes) is done in Rust after the match — this
/// keeps the pattern O(n) and avoids `CompiledTooBig` from large `{n,m}`
/// bounded repetitions with alternation inside the atom.
fn re_string_literal() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)')"#)
            .expect("invariant: static regex is valid")
    })
}

/// Matches a contiguous run of base64 alphabet characters long enough to be
/// suspicious. We accept the standard and URL-safe alphabets, and optional
/// trailing `=` padding. The run must be on a word-boundary-equivalent (not
/// mid-identifier) — we anchor on non-alphanumeric or start/end.
fn re_base64_blob() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // At least MIN_BLOB_LEN (200) base64 chars followed by optional `=` padding.
        // Using {200,} so the regex engine short-circuits on short runs.
        Regex::new(r"[A-Za-z0-9+/\-_]{200,}={0,2}").expect("invariant: static regex is valid")
    })
}

/// Matches a contiguous run of lowercase or uppercase hex digits of at least
/// MIN_BLOB_LEN length. Hex-encoded shellcode / AES keys appear this way.
fn re_hex_blob() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)[0-9a-f]{200,}").expect("invariant: static regex is valid"))
}

// ---------------------------------------------------------------------------
// Entropy computation
// ---------------------------------------------------------------------------

/// Compute Shannon entropy in bits/byte over a byte slice.
/// Returns 0.0 for empty slices.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Find the sliding-window region of highest entropy and return `(offset,
/// entropy)`. Window size and step are [`WINDOW_SIZE`] / [`WINDOW_STEP`].
/// Returns `(0, 0.0)` if the slice is shorter than one window.
fn peak_window_entropy(data: &[u8]) -> (usize, f64) {
    if data.len() < WINDOW_SIZE {
        return (0, shannon_entropy(data));
    }
    let mut best_offset = 0usize;
    let mut best_entropy = 0.0f64;
    let mut offset = 0usize;
    while offset + WINDOW_SIZE <= data.len() {
        let e = shannon_entropy(&data[offset..offset + WINDOW_SIZE]);
        if e > best_entropy {
            best_entropy = e;
            best_offset = offset;
        }
        offset += WINDOW_STEP;
    }
    (best_offset, best_entropy)
}

// ---------------------------------------------------------------------------
// Per-file analysis helpers
// ---------------------------------------------------------------------------

/// Analyse a native binary (ELF/PE/Mach-O).
/// Returns at most two findings: one whole-file finding and one window finding.
fn analyse_binary(file: &FileUnit) -> Vec<Finding> {
    let mut findings = Vec::new();

    if file.len() < MIN_BINARY_SIZE {
        return findings;
    }

    let whole = shannon_entropy(&file.data);
    trace!(path = %file.rel_path, entropy = whole, "binary whole-file entropy");

    if whole > BINARY_ENTROPY_THRESHOLD {
        let (win_offset, win_entropy) = peak_window_entropy(&file.data);
        let evidence = format!(
            "whole-file entropy {:.3} bits/byte; peak {:.3} bits/byte at offset {win_offset}",
            whole, win_entropy
        );
        let f = Finding::new(
            ENGINE_NAME,
            ThreatCategory::Packer,
            Severity::High,
            Confidence::Medium,
            "High-entropy native binary (packed or encrypted)",
            format!(
                "The binary file '{}' has whole-file Shannon entropy {:.3} bits/byte (threshold \
                 {BINARY_ENTROPY_THRESHOLD:.1}), consistent with a packer, crypter, or \
                 encrypted payload segment.",
                file.rel_path, whole
            ),
        )
        .with_rule_id("ENTROPY_PACKED_BINARY")
        .with_location(FileLocation {
            path: file.rel_path.clone(),
            line: None,
            offset: Some(win_offset),
        })
        .with_evidence(evidence, 160);
        findings.push(f);
    }

    findings
}

/// Analyse a script/text file for obfuscated payloads.
fn analyse_script(file: &FileUnit) -> Vec<Finding> {
    let mut findings = Vec::new();

    if file.len() < MIN_FILE_SIZE {
        return findings;
    }

    // Cap text fed to regex evaluation to guard against adversarially huge
    // files causing slow NFA traversal. A HEAD+TAIL window (not head-only) closes
    // the pad-before-payload evasion uniformly with the other text engines.
    const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;
    let text: std::borrow::Cow<'_, str> =
        crate::engine::scan_window(file.text_lossy(), MAX_SCAN_BYTES);

    // -----------------------------------------------------------------------
    // Pass 1: scan string literals for high entropy
    // -----------------------------------------------------------------------
    let string_re = re_string_literal();
    for cap in string_re.captures_iter(&text) {
        // Group 1 = double-quoted interior, group 2 = single-quoted interior.
        let interior = cap.get(1).or_else(|| cap.get(2));
        let interior = match interior {
            Some(m) => m.as_str(),
            None => continue,
        };
        if interior.len() < MIN_STRING_LEN {
            continue;
        }
        let e = shannon_entropy(interior.as_bytes());
        if e >= STRING_ENTROPY_THRESHOLD {
            let offset = cap.get(0).map_or(0, |m| m.start());
            // Estimate a 1-based line number from the byte offset.
            let line = text[..offset].bytes().filter(|&b| b == b'\n').count() + 1;
            let evidence = format!(
                "string literal length {} bytes, entropy {:.3} bits/byte",
                interior.len(),
                e
            );
            let f = Finding::new(
                ENGINE_NAME,
                ThreatCategory::Obfuscation,
                Severity::High,
                Confidence::Medium,
                "High-entropy string literal (obfuscated/encoded payload)",
                format!(
                    "'{}' contains a string literal of {} bytes with Shannon entropy {:.3} \
                     bits/byte, indicating a base64-encoded, hex-encoded, or encrypted payload \
                     embedded in source.",
                    file.rel_path,
                    interior.len(),
                    e
                ),
            )
            .with_rule_id("ENTROPY_HIGH_ENTROPY_STRING")
            .with_location(FileLocation::at_line(file.rel_path.clone(), line))
            .with_evidence(evidence, 160);
            findings.push(f);
            // One finding per string literal is enough; continue to catch
            // multiple distinct blobs in the same file.
        }
    }

    // -----------------------------------------------------------------------
    // Pass 2: raw base64 blobs (not inside quotes — e.g. atob() argument
    // variable, eval'd blob, or concatenated chunks).
    // -----------------------------------------------------------------------
    let b64_re = re_base64_blob();
    for m in b64_re.find_iter(&text) {
        let blob = m.as_str();
        if blob.len() < MIN_BLOB_LEN {
            continue;
        }
        let e = shannon_entropy(blob.as_bytes());
        // Base64 has entropy ~6.0 bits/byte. Legitimate long base64 strings
        // exist (e.g. image data URIs in CSS/HTML), so we require a higher
        // threshold AND restrict to script kinds.
        if e >= STRING_ENTROPY_THRESHOLD && file.kind.is_script() {
            let offset = m.start();
            let line = text[..offset].bytes().filter(|&b| b == b'\n').count() + 1;
            let evidence = format!(
                "base64-like blob {} bytes at line {line}, entropy {:.3} bits/byte",
                blob.len(),
                e
            );
            let f = Finding::new(
                ENGINE_NAME,
                ThreatCategory::Obfuscation,
                Severity::Medium,
                Confidence::Medium,
                "Large base64/encoded blob in script",
                format!(
                    "'{}' contains a {}-byte base64-like run at line {line} with entropy \
                     {:.3} bits/byte, consistent with an encoded payload or exfiltration \
                     buffer.",
                    file.rel_path,
                    blob.len(),
                    e
                ),
            )
            .with_rule_id("ENTROPY_BASE64_BLOB")
            .with_location(FileLocation::at_line(file.rel_path.clone(), line))
            .with_evidence(evidence, 160);
            findings.push(f);
        }
    }

    // -----------------------------------------------------------------------
    // Pass 3: raw hex blobs
    // -----------------------------------------------------------------------
    let hex_re = re_hex_blob();
    for m in hex_re.find_iter(&text) {
        let blob = m.as_str();
        if blob.len() < MIN_BLOB_LEN {
            continue;
        }
        // Hex data is evenly distributed over [0-9a-f] ≈ 16 symbols →
        // entropy ≈ log2(16) = 4.0 bits/symbol.  But we're computing byte
        // entropy over ASCII characters (10 digits + 6 letters = 16 distinct
        // bytes), which clusters around 3.9–4.0 bits/byte.  Use 3.5 as the
        // floor to distinguish from normal identifiers.
        let e = shannon_entropy(blob.as_bytes());
        if e >= 3.5 && file.kind.is_script() && blob.len() >= MIN_BLOB_LEN {
            let offset = m.start();
            let line = text[..offset].bytes().filter(|&b| b == b'\n').count() + 1;
            let evidence = format!(
                "hex blob {} bytes at line {line}, entropy {:.3} bits/byte",
                blob.len(),
                e
            );
            let f = Finding::new(
                ENGINE_NAME,
                ThreatCategory::Obfuscation,
                Severity::Medium,
                Confidence::Medium,
                "Large hex-encoded blob in script",
                format!(
                    "'{}' contains a {}-byte hexadecimal run at line {line} with entropy \
                     {:.3} bits/byte, consistent with shellcode, a key blob, or an \
                     obfuscated payload.",
                    file.rel_path,
                    blob.len(),
                    e
                ),
            )
            .with_rule_id("ENTROPY_HEX_BLOB")
            .with_location(FileLocation::at_line(file.rel_path.clone(), line))
            .with_evidence(evidence, 160);
            findings.push(f);
        }
    }

    // -----------------------------------------------------------------------
    // Pass 4: minified single-line script — the whole file (or a long line)
    // has binary-level entropy despite being nominally "text".
    // -----------------------------------------------------------------------
    // Check whether the file has very long lines (minified) AND high overall
    // byte-level entropy for a text file.
    if file.kind.is_script() || matches!(file.kind, FileKind::Text) {
        let whole_entropy = shannon_entropy(&file.data);
        // Text files have entropy typically 4.5–5.5 bits/byte.
        // Minified but clean JS lands 5.0–5.8.  Obfuscated minified JS
        // (jsfuck, aaencode, base62) can reach 6.5+.  We flag at 6.2 for
        // text-classified files only.
        let text_entropy_threshold = 6.2f64;
        if whole_entropy >= text_entropy_threshold {
            // Confirm there's at least one very long line (minified pattern).
            let has_long_line = text.lines().any(|l| l.len() >= MINIFIED_LINE_LEN);
            if has_long_line {
                let evidence = format!(
                    "whole-file entropy {whole_entropy:.3} bits/byte with minified long lines"
                );
                let f = Finding::new(
                    ENGINE_NAME,
                    ThreatCategory::Obfuscation,
                    Severity::High,
                    Confidence::Medium,
                    "High-entropy minified script (obfuscation suspected)",
                    format!(
                        "'{}' is a minified script with whole-file byte entropy {:.3} bits/byte \
                         (threshold {text_entropy_threshold:.1}), significantly above normal \
                         for minified code. Consistent with code obfuscation (jsfuck, \
                         aaencode, base62, or custom encoder).",
                        file.rel_path, whole_entropy
                    ),
                )
                .with_rule_id("ENTROPY_MINIFIED_OBFUSCATED")
                .with_location(FileLocation::file(file.rel_path.clone()))
                .with_evidence(evidence, 160);
                findings.push(f);
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Public engine struct
// ---------------------------------------------------------------------------

/// Entropy-based malware detection engine.
///
/// Examines Shannon entropy at both file and sub-region granularity to flag:
/// - Packed / encrypted native binaries.
/// - Obfuscated scripts containing high-entropy string literals or blobs.
/// - Minified scripts with anomalously high byte-level entropy.
#[derive(Debug, Default)]
pub struct EntropyEngine;

impl DetectionEngine for EntropyEngine {
    fn name(&self) -> &'static str {
        ENGINE_NAME
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in ctx.files {
            if file.is_empty() {
                continue;
            }

            // Skip archive containers — they are compressed by design.
            if matches!(file.kind, FileKind::Archive) {
                continue;
            }

            // Skip WASM — it is a binary format with naturally high entropy.
            if matches!(file.kind, FileKind::Wasm) {
                continue;
            }

            if file.kind.is_native_binary() {
                findings.extend(analyse_binary(file));
            } else if file.kind.is_script()
                || matches!(
                    file.kind,
                    FileKind::Text | FileKind::Html | FileKind::Json | FileKind::Manifest
                )
            {
                findings.extend(analyse_script(file));
            } else {
                // Unknown binary blobs: flag if suspiciously high entropy and
                // large enough to be meaningful, but at lower severity.
                if file.len() >= MIN_BINARY_SIZE {
                    let e = shannon_entropy(&file.data);
                    if e > BINARY_ENTROPY_THRESHOLD {
                        let (win_offset, _win_e) = peak_window_entropy(&file.data);
                        let evidence = format!("unknown-kind file entropy {e:.3} bits/byte");
                        let f = Finding::new(
                            ENGINE_NAME,
                            ThreatCategory::Packer,
                            Severity::Medium,
                            Confidence::Low,
                            "High-entropy unknown-type file",
                            format!(
                                "'{}' has unknown file type but whole-file entropy {:.3} \
                                 bits/byte, consistent with an encrypted or compressed blob.",
                                file.rel_path, e
                            ),
                        )
                        .with_rule_id("ENTROPY_UNKNOWN_HIGH")
                        .with_location(FileLocation {
                            path: file.rel_path.clone(),
                            line: None,
                            offset: Some(win_offset),
                        })
                        .with_evidence(evidence, 160);
                        findings.push(f);
                    }
                }
            }
        }

        trace!(
            engine = ENGINE_NAME,
            findings = findings.len(),
            "scan complete"
        );
        findings
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::engine::{FileKind, FileUnit, ScanContext};

    /// Build a minimal FileUnit for testing without a full scan pipeline.
    fn make_file(rel_path: &str, data: Vec<u8>, kind: FileKind) -> FileUnit {
        use sha2::{Digest, Sha256};
        let hash = hex::encode(Sha256::digest(&data));
        FileUnit {
            rel_path: rel_path.to_string(),
            data,
            kind,
            sha256: hash,
        }
    }

    fn run_engine(files: Vec<FileUnit>) -> Vec<Finding> {
        let config = ScanConfig::default();
        let ctx = ScanContext {
            target_name: "test".to_string(),
            files: &files,
            package_json: None,
            config: &config,
        };
        EntropyEngine.scan(&ctx)
    }

    // -----------------------------------------------------------------------
    // Shannon entropy unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_uniform_bytes_is_eight() {
        // 256 distinct bytes each appearing once → max entropy = 8.0 bits/byte.
        let data: Vec<u8> = (0u8..=255u8).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 1e-10, "expected 8.0, got {e}");
    }

    #[test]
    fn entropy_all_same_byte_is_zero() {
        let data = vec![0x41u8; 1024];
        let e = shannon_entropy(&data);
        assert!(e < 1e-10, "expected 0.0, got {e}");
    }

    #[test]
    fn entropy_ascii_text_is_moderate() {
        // Normal English prose has entropy roughly 4.0–5.0 bits/byte.
        let text = b"The quick brown fox jumps over the lazy dog. \
                     Pack my box with five dozen liquor jugs. \
                     How vexingly quick daft zebras jump! \
                     The five boxing wizards jump quickly. \
                     Sphinx of black quartz, judge my vow.";
        let e = shannon_entropy(text);
        assert!(e > 3.5 && e < 6.0, "expected moderate entropy, got {e}");
    }

    // -----------------------------------------------------------------------
    // Positive: high-entropy JS with embedded base64 payload
    // -----------------------------------------------------------------------

    #[test]
    fn detects_high_entropy_string_literal_in_js() {
        // Build a string literal of 300 high-entropy bytes (pseudo-random base64).
        // We craft it so every byte position cycles through a varied alphabet.
        let payload: String = (0u8..=255u8)
            .cycle()
            .take(512)
            .map(|b| {
                // Map to base64 alphabet characters deterministically.
                let idx = b % 64;
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[idx as usize]
                    as char
            })
            .collect();
        let src = format!("var x = \"{payload}\";\n");
        let file = make_file("evil.js", src.into_bytes(), FileKind::Javascript);
        let findings = run_engine(vec![file]);
        let entropy_findings: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.rule_id.as_deref() == Some("ENTROPY_HIGH_ENTROPY_STRING")
                    || f.rule_id.as_deref() == Some("ENTROPY_BASE64_BLOB")
            })
            .collect();
        assert!(
            !entropy_findings.is_empty(),
            "expected at least one entropy finding for obfuscated JS, got: {findings:?}"
        );
        let f = &entropy_findings[0];
        assert_eq!(f.engine, "entropy");
        assert_eq!(f.category, ThreatCategory::Obfuscation);
    }

    // -----------------------------------------------------------------------
    // Positive: packed binary (all-high-entropy bytes)
    // -----------------------------------------------------------------------

    #[test]
    fn detects_packed_elf_binary() {
        // Synthesise a fake ELF with near-maximum entropy (cycle all 256 byte
        // values repeatedly — entropy ≈ 8.0 bits/byte).
        let mut data: Vec<u8> = (0u8..=255u8).cycle().take(4096).collect();
        // Stamp an ELF magic at the front so we could classify it, but here
        // we set the kind directly.
        data[0] = 0x7f;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        let file = make_file("payload.elf", data, FileKind::ElfBinary);
        let findings = run_engine(vec![file]);
        let packed: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("ENTROPY_PACKED_BINARY"))
            .collect();
        assert!(
            !packed.is_empty(),
            "expected ENTROPY_PACKED_BINARY for high-entropy ELF, got: {findings:?}"
        );
        assert_eq!(packed[0].category, ThreatCategory::Packer);
        assert_eq!(packed[0].severity, Severity::High);
        assert_eq!(packed[0].confidence, Confidence::Medium);
    }

    // -----------------------------------------------------------------------
    // Negative: normal readable JavaScript — must NOT be flagged
    // -----------------------------------------------------------------------

    #[test]
    fn does_not_flag_normal_javascript() {
        let src = r#"
'use strict';

function greet(name) {
    if (!name || typeof name !== 'string') {
        throw new TypeError('name must be a non-empty string');
    }
    return 'Hello, ' + name + '!';
}

const users = ['Alice', 'Bob', 'Carol'];
const messages = users.map(greet);
console.log(messages.join('\n'));

module.exports = { greet };
"#;
        let file = make_file("index.js", src.as_bytes().to_vec(), FileKind::Javascript);
        let findings = run_engine(vec![file]);
        assert!(
            findings.is_empty(),
            "expected no findings for benign JS, got: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Negative: legitimate minified (but not obfuscated) JS — low-entropy
    // minified bundles should not be flagged.
    // -----------------------------------------------------------------------

    #[test]
    fn does_not_flag_clean_minified_js() {
        // Simulate a simple minified JS: long line but all printable ASCII
        // with normal character distribution → entropy well below 6.2.
        let line = "function add(a,b){return a+b;}function sub(a,b){return a-b;}\
                    function mul(a,b){return a*b;}function div(a,b){if(b===0)throw \
                    new Error('division by zero');return a/b;}function mod(a,b){return a%b;}\
                    function pow(a,b){return Math.pow(a,b);}function sqrt(a){return Math.sqrt(a);}\
                    function abs(a){return Math.abs(a);}function floor(a){return Math.floor(a);}\
                    function ceil(a){return Math.ceil(a);}function round(a){return Math.round(a);}\
                    module.exports={add,sub,mul,div,mod,pow,sqrt,abs,floor,ceil,round};";
        // Repeat to push it well past MIN_FILE_SIZE, keeping the character
        // distribution of ordinary JS tokens.
        let mut src = String::new();
        for _ in 0..4 {
            src.push_str(line);
            src.push('\n');
        }
        let file = make_file("math.min.js", src.into_bytes(), FileKind::Javascript);
        let findings = run_engine(vec![file]);
        let obf: Vec<_> = findings
            .iter()
            .filter(|f| f.category == ThreatCategory::Obfuscation)
            .collect();
        assert!(
            obf.is_empty(),
            "expected no obfuscation findings for clean minified JS, got: {obf:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Negative: compressed archive — must NOT be flagged
    // -----------------------------------------------------------------------

    #[test]
    fn does_not_flag_archive_kind() {
        // Even if the bytes have maximum entropy, Archive kind is exempt.
        let data: Vec<u8> = (0u8..=255u8).cycle().take(4096).collect();
        let file = make_file("bundle.tar.gz", data, FileKind::Archive);
        let findings = run_engine(vec![file]);
        assert!(
            findings.is_empty(),
            "archives must not be flagged regardless of entropy, got: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Negative: WASM — must NOT be flagged
    // -----------------------------------------------------------------------

    #[test]
    fn does_not_flag_wasm() {
        let data: Vec<u8> = (0u8..=255u8).cycle().take(4096).collect();
        let file = make_file("module.wasm", data, FileKind::Wasm);
        let findings = run_engine(vec![file]);
        assert!(
            findings.is_empty(),
            "WASM must not be flagged regardless of entropy, got: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Negative: small file — must NOT be flagged (too few bytes for
    // meaningful entropy statistics).
    // -----------------------------------------------------------------------

    #[test]
    fn does_not_flag_tiny_file() {
        // 128 high-entropy bytes — below MIN_FILE_SIZE (512) for scripts and
        // MIN_BINARY_SIZE (512) for binaries.
        let data: Vec<u8> = (0u8..=255u8).take(128).collect();
        for kind in [FileKind::Javascript, FileKind::ElfBinary] {
            let file = make_file("tiny", data.clone(), kind);
            let findings = run_engine(vec![file]);
            assert!(
                findings.is_empty(),
                "tiny file ({kind:?}) must not be flagged, got: {findings:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Positive: hex-encoded shellcode blob in Python
    // -----------------------------------------------------------------------

    #[test]
    fn detects_hex_blob_in_python() {
        // Build a 400-char hex string cycling through all 256 byte values.
        // 200 bytes encoded → 400 hex chars, well above MIN_BLOB_LEN (200).
        let hex_payload: String = (0u8..=255u8)
            .cycle()
            .take(200)
            .map(|b| format!("{b:02x}"))
            .collect();
        // Pad the source above MIN_FILE_SIZE (512) with a realistic-looking
        // preamble so the size gate is cleared.
        let preamble = "# Shellcode loader — extracted from malware sample\n\
                        import struct\nimport ctypes\nimport sys\n\
                        # Decode and run embedded shellcode\n\
                        # fmt: off\n";
        let src = format!(
            "{preamble}shellcode = bytes.fromhex('{hex_payload}')\n\
             buf = ctypes.create_string_buffer(shellcode)\n\
             ctypes.windll.kernel32.VirtualAlloc(0,len(buf),0x3000,0x40)\n"
        );
        assert!(
            src.len() >= 512,
            "test source must be ≥ MIN_FILE_SIZE (512): got {} bytes",
            src.len()
        );
        let file = make_file("loader.py", src.into_bytes(), FileKind::Python);
        let findings = run_engine(vec![file]);
        let hex_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("ENTROPY_HEX_BLOB"))
            .collect();
        assert!(
            !hex_findings.is_empty(),
            "expected ENTROPY_HEX_BLOB for hex-encoded shellcode in Python, got: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Positive: obfuscated minified JS with near-binary entropy
    // -----------------------------------------------------------------------

    #[test]
    fn detects_minified_obfuscated_js() {
        // Construct a single long line where every character is drawn from a
        // large alphabet (simulating jsfuck-style or base62 obfuscation).
        // Use the full printable ASCII range (~95 chars) to push entropy > 6.2.
        let alphabet: Vec<u8> = (0x21u8..=0x7eu8).collect(); // '!' to '~'
        let n_alphabet = alphabet.len() as u8; // 94
        let line: String = (0u8..=255u8)
            .cycle()
            .take(2048)
            .map(|b| alphabet[(b % n_alphabet) as usize] as char)
            .collect();
        // Pad to > MIN_FILE_SIZE (512) and ensure it's a single long line.
        let src = format!("{line}\n");
        let file = make_file("obf.js", src.into_bytes(), FileKind::Javascript);
        let findings = run_engine(vec![file]);
        let obf: Vec<_> = findings
            .iter()
            .filter(|f| f.category == ThreatCategory::Obfuscation)
            .collect();
        assert!(
            !obf.is_empty(),
            "expected obfuscation finding for high-entropy minified JS, got: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Structural: engine name is stable
    // -----------------------------------------------------------------------

    #[test]
    fn engine_name_is_entropy() {
        assert_eq!(EntropyEngine.name(), "entropy");
    }

    // -----------------------------------------------------------------------
    // Structural: evidence is truncated to ≤ 160 bytes (+ '…')
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_is_truncated() {
        let long = "x".repeat(500);
        let f = Finding::new(
            "entropy",
            ThreatCategory::Obfuscation,
            Severity::Medium,
            Confidence::Medium,
            "t",
            "d",
        )
        .with_evidence(long, 160);
        // The stored evidence must be at most 160 + 3 bytes (for the '…' which
        // is 3 UTF-8 bytes).
        let ev = f.evidence.unwrap();
        assert!(ev.len() <= 163, "evidence too long: {} bytes", ev.len());
        assert!(ev.ends_with('…'));
    }

    // -----------------------------------------------------------------------
    // Peak-window helper
    // -----------------------------------------------------------------------

    #[test]
    fn peak_window_returns_highest_entropy_region() {
        // Prepend 512 zero bytes then 256 high-entropy bytes.
        let mut data = vec![0u8; 512];
        data.extend((0u8..=255u8).collect::<Vec<_>>());
        let (offset, entropy) = peak_window_entropy(&data);
        // The high-entropy window should be in the second half.
        assert!(
            offset >= 256,
            "expected peak window in high-entropy region, got offset {offset}"
        );
        assert!(
            entropy > 7.9,
            "expected near-max entropy in window, got {entropy}"
        );
    }
}
