//! The detection-engine contract.
//!
//! A [`DetectionEngine`] is a self-contained analysis pass that examines the
//! already-loaded set of files ([`ScanContext`]) and emits [`Finding`]s. Engines
//! are pure with respect to the filesystem — the scanner does all IO/extraction
//! up front and hands engines an in-memory [`FileUnit`] list, so engines are
//! deterministic, parallelizable, and easy to unit-test.
//!
//! Every engine MUST:
//! - implement [`Default`] (the scanner builds the default set via `Default`),
//! - be `Send + Sync`,
//! - depend ONLY on this module, [`crate::types`], and [`crate::config`] (never
//!   on another engine).

use crate::config::ScanConfig;
use crate::types::Finding;
use serde::{Deserialize, Serialize};

/// A coarse classification of a loaded file, used by engines to decide which
/// analyses apply. Determined by the loader from extension + magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Javascript,
    TypeScript,
    Python,
    Shell,
    PowerShell,
    Ruby,
    Php,
    /// Generic JSON (config, lockfile, etc.).
    Json,
    /// A package manifest (`package.json`, `pyproject.toml`, etc.).
    Manifest,
    Wasm,
    ElfBinary,
    PeBinary,
    MachoBinary,
    /// A nested archive that the loader did not (or could not) expand further.
    Archive,
    Html,
    /// Printable text of unknown language.
    Text,
    /// Non-text bytes of unknown type.
    Unknown,
}

impl FileKind {
    /// True for source/script text the behavioral engines should parse.
    pub fn is_script(self) -> bool {
        matches!(
            self,
            FileKind::Javascript
                | FileKind::TypeScript
                | FileKind::Python
                | FileKind::Shell
                | FileKind::PowerShell
                | FileKind::Ruby
                | FileKind::Php
        )
    }

    /// True for a native executable image.
    pub fn is_native_binary(self) -> bool {
        matches!(
            self,
            FileKind::ElfBinary | FileKind::PeBinary | FileKind::MachoBinary
        )
    }
}

/// One loaded file (already read into memory and hashed by the loader).
#[derive(Debug, Clone)]
pub struct FileUnit {
    /// Path relative to the scan root (archive-internal paths use `/`).
    pub rel_path: String,
    /// Raw file bytes.
    pub data: Vec<u8>,
    /// Detected file kind.
    pub kind: FileKind,
    /// Lowercase hex SHA-256 of `data` (computed once by the loader).
    pub sha256: String,
}

impl FileUnit {
    /// The file contents as lossy UTF-8 (cheap, no allocation when already
    /// valid UTF-8). Engines should prefer this for text analysis.
    pub fn text_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.data)
    }

    /// File size in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Heuristic: does this look like text?
    ///
    /// Classifies the first 8 KiB by the fraction of "binary" control bytes —
    /// NUL and the other C0 control characters that never appear in real source
    /// (the common whitespace/formatting controls `\t \n \v \f \r` and `ESC`
    /// are excluded). The file is textual unless more than 10% of the probed
    /// bytes are such binary controls.
    ///
    /// This deliberately does NOT flip to non-textual on a handful of NUL
    /// bytes: a lone NUL embedded in an otherwise-textual script is an evasion
    /// attempt (a single NUL would otherwise make every text detector skip the
    /// file) — not evidence of a genuine binary. Real executables are dense
    /// with control/padding bytes and still classify as non-textual, so the
    /// binary-only passes (shellcode etc.) keep firing on them; a script with a
    /// few injected NULs stays textual and is scanned. High bytes (`0x80..=0xFF`)
    /// are NOT counted so legitimate UTF-8 text (e.g. CJK) stays textual.
    pub fn looks_textual(&self) -> bool {
        let probe = &self.data[..self.data.len().min(8192)];
        if probe.is_empty() {
            return true;
        }
        let binary_controls = probe.iter().filter(|&&b| is_binary_control(b)).count();
        // Non-textual only when binary controls dominate (> 10% of the probe).
        binary_controls * 10 <= probe.len()
    }
}

/// True for C0 control bytes that essentially never occur in text/source: NUL
/// and the other non-whitespace controls. The whitespace/formatting controls
/// `\t`(0x09) `\n`(0x0A) `\v`(0x0B) `\f`(0x0C) `\r`(0x0D) and `ESC`(0x1B) are
/// excluded. High bytes (0x80..=0xFF) are excluded so UTF-8 text stays textual.
#[inline]
fn is_binary_control(b: u8) -> bool {
    matches!(b, 0x00..=0x08 | 0x0E..=0x1A | 0x1C..=0x1F)
}

/// Build a bounded scan window over `text` for a size-capped regex pass.
///
/// When `text` is within `max` bytes it is returned unchanged. When it is
/// larger, a HEAD and a TAIL half are joined (separated by a single `\n`) so a
/// payload padded past the head is still scanned: a **head-only** truncation
/// lets an attacker push the real payload out of view behind `>max` bytes of
/// benign filler. Split points fall on `char` boundaries so the result is always
/// valid UTF-8. If the head and tail would overlap (`max` close to `len`) the
/// text is returned unchanged.
///
/// This is the shared window used by every size-capped text engine so the
/// pad-before-payload evasion is closed uniformly. Byte offsets in the returned
/// window no longer map to original file offsets past the head, so a line number
/// derived from a tail match is approximate — evidence snippets remain exact.
pub fn scan_window(text: std::borrow::Cow<'_, str>, max: usize) -> std::borrow::Cow<'_, str> {
    if text.len() <= max {
        return text;
    }
    let half = max / 2;
    let mut head_end = half;
    while head_end > 0 && !text.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = text.len() - half;
    while tail_start < text.len() && !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    if tail_start <= head_end {
        return text;
    }
    let mut joined = String::with_capacity(max + 2);
    joined.push_str(&text[..head_end]);
    joined.push('\n');
    joined.push_str(&text[tail_start..]);
    std::borrow::Cow::Owned(joined)
}

/// The immutable input handed to every engine for one scan.
pub struct ScanContext<'a> {
    /// Human-readable name of the scanned target (path or package spec).
    pub target_name: String,
    /// All loaded files (post-extraction), capped by [`ScanConfig`].
    pub files: &'a [FileUnit],
    /// The parsed top-level `package.json`, if the target had one. Provided as
    /// a convenience so supply-chain engines don't each re-parse it.
    pub package_json: Option<&'a serde_json::Value>,
    /// Active scan configuration / limits.
    pub config: &'a ScanConfig,
}

impl<'a> ScanContext<'a> {
    /// Iterate only the files matching `pred` — a small helper so engines can
    /// write `ctx.files_where(|f| f.kind.is_script())`.
    pub fn files_where<'s, P>(&'s self, pred: P) -> impl Iterator<Item = &'s FileUnit>
    where
        P: Fn(&&'s FileUnit) -> bool,
    {
        self.files.iter().filter(move |f| pred(f))
    }
}

/// A single malware-detection analysis pass.
pub trait DetectionEngine: Send + Sync {
    /// Stable short name (used in [`Finding::engine`] and stats). Must match the
    /// string the engine stamps into its findings.
    fn name(&self) -> &'static str;

    /// Examine the context and return any findings. Must not panic; on internal
    /// error return an empty/partial result rather than unwinding.
    fn scan(&self, ctx: &ScanContext<'_>) -> Vec<Finding>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(data: Vec<u8>) -> FileUnit {
        FileUnit {
            rel_path: "f".into(),
            data,
            kind: FileKind::Text,
            sha256: String::new(),
        }
    }

    #[test]
    fn empty_file_is_textual() {
        assert!(unit(Vec::new()).looks_textual());
    }

    #[test]
    fn plain_text_is_textual() {
        assert!(unit(b"console.log('hello world');\n".to_vec()).looks_textual());
    }

    // TRUE-NEGATIVE for the NUL-evasion fix: a script with a lone (or a handful
    // of) injected NUL bytes must STILL be treated as text so the text engines
    // do not skip it.
    #[test]
    fn script_with_lone_nul_stays_textual() {
        let mut data = b"/* \x00 */ const x = require('child_process');\n".to_vec();
        assert!(
            unit(data.clone()).looks_textual(),
            "a single NUL must not flip a script to non-textual (evasion)"
        );
        // Even a few dozen scattered NULs in a large text file stay textual.
        data = vec![b'a'; 4096];
        for i in 0..40 {
            data[i * 100] = 0;
        }
        assert!(unit(data).looks_textual());
    }

    // TRUE-POSITIVE: a genuine binary (control-byte-dense) is non-textual, so
    // the binary-only passes still fire on it.
    #[test]
    fn dense_binary_is_non_textual() {
        // 512 bytes that are >10% NUL/control (here ~50%).
        let mut data = Vec::new();
        for _ in 0..256 {
            data.push(0x00);
            data.push(b'A');
        }
        assert!(!unit(data).looks_textual());
    }

    #[test]
    fn utf8_high_bytes_stay_textual() {
        // CJK text is dominated by high bytes but has no C0 controls.
        let data = "日本語のテキストです。これはバイナリではありません。"
            .as_bytes()
            .to_vec();
        assert!(unit(data).looks_textual());
    }

    #[test]
    fn is_binary_control_excludes_whitespace() {
        for b in [b'\t', b'\n', 0x0b, 0x0c, b'\r', 0x1b] {
            assert!(!is_binary_control(b), "byte {b:#x} should not be binary");
        }
        for b in [0x00u8, 0x01, 0x08, 0x0e, 0x1f] {
            assert!(is_binary_control(b), "byte {b:#x} should be binary");
        }
    }
}
