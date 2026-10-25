//! Binary indicator detection engine.
//!
//! Scans native executables (ELF/PE/Mach-O) and non-binary files that embed a
//! native executable payload for suspicious API imports, packer signatures,
//! reverse-shell string triads, and shellcode-like byte patterns.  Also flags
//! native binaries that appear inside a JavaScript/npm package tree, which is a
//! strong supply-chain signal.
//!
//! All regular expressions and byte-pattern tables are compiled/constructed
//! exactly once via [`std::sync::OnceLock`].

use std::sync::OnceLock;

use regex::bytes::Regex as BytesRegex;

use crate::{
    engine::{DetectionEngine, FileKind, FileUnit, ScanContext},
    types::{Confidence, FileLocation, Finding, Severity, ThreatCategory},
};

// ---------------------------------------------------------------------------
// Engine name — must exactly match what we stamp into every Finding::engine.
// ---------------------------------------------------------------------------

const ENGINE: &str = "binary_indicators";

// ---------------------------------------------------------------------------
// Magic-byte constants for executable formats.
// ---------------------------------------------------------------------------

/// MZ header (DOS/PE): bytes 0x4D 0x5A.
#[allow(dead_code)] // reason: used in tests and by starts_with_native_magic; rustc sees no live call-graph edge from non-test production code
const MZ_MAGIC: &[u8] = b"MZ";
/// ELF header: \x7fELF.
#[allow(dead_code)] // reason: same as MZ_MAGIC — used in tests; production path goes through the regex searcher, not this const directly
const ELF_MAGIC: &[u8] = b"\x7fELF";
/// Mach-O magic values (LE 32, LE 64, BE 32, BE 64, fat).
const MACHO_MAGICS: &[[u8; 4]] = &[
    [0xCE, 0xFA, 0xED, 0xFE], // MH_MAGIC
    [0xCF, 0xFA, 0xED, 0xFE], // MH_MAGIC_64
    [0xFE, 0xED, 0xFA, 0xCE], // MH_CIGAM
    [0xFE, 0xED, 0xFA, 0xCF], // MH_CIGAM_64
    [0xCA, 0xFE, 0xBA, 0xBE], // FAT_MAGIC
    [0xBE, 0xBA, 0xFE, 0xCA], // FAT_CIGAM
];

// ---------------------------------------------------------------------------
// Lazy-compiled regex sets (compiled once, used for lifetime of process).
// ---------------------------------------------------------------------------

/// Windows suspicious API imports — matched against extracted printable strings.
static WIN_IMPORTS_RE: OnceLock<BytesRegex> = OnceLock::new();

fn win_imports_re() -> &'static BytesRegex {
    WIN_IMPORTS_RE.get_or_init(|| {
        // Each alternative is a well-known dangerous Win32 API.  We match these
        // as printable ASCII strings inside the binary (import table strings,
        // string literals in .rodata, etc.).
        BytesRegex::new(
            r"(?x)
            CreateRemoteThread
            | VirtualAllocEx
            | WriteProcessMemory
            | NtWriteVirtualMemory
            | NtAllocateVirtualMemory
            | RtlCreateUserThread
            | ZwCreateThreadEx
            | WinExec
            | ShellExecuteA
            | ShellExecuteW
            | ShellExecuteExA
            | ShellExecuteExW
            | URLDownloadToFile[AW]?
            | InternetOpenUrl[AW]?
            | HttpSendRequest[AW]?
            | RegSetValue(?:Ex)?[AW]?
            | IsDebuggerPresent
            | CheckRemoteDebuggerPresent
            | NtQueryInformationProcess
            | OutputDebugString[AW]?
            | SetWindowsHookEx[AW]?
            | GetAsyncKeyState
            | keybd_event
            | mouse_event
            | SuspendThread
            | ResumeThread
            | OpenProcess
            | TerminateProcess
            | GetThreadContext
            | SetThreadContext
            ",
        )
        .expect("invariant: WIN_IMPORTS_RE is a valid pattern")
    })
}

/// Suspicious pairing of LoadLibrary + GetProcAddress in the same file.
static LOADLIB_RE: OnceLock<BytesRegex> = OnceLock::new();
static GETPROC_RE: OnceLock<BytesRegex> = OnceLock::new();

fn loadlib_re() -> &'static BytesRegex {
    LOADLIB_RE.get_or_init(|| {
        BytesRegex::new(r"LoadLibrary[AW]?").expect("invariant: LOADLIB_RE is a valid pattern")
    })
}

fn getproc_re() -> &'static BytesRegex {
    GETPROC_RE.get_or_init(|| {
        BytesRegex::new(r"GetProcAddress").expect("invariant: GETPROC_RE is a valid pattern")
    })
}

/// POSIX suspicious API / path strings.
static POSIX_IMPORTS_RE: OnceLock<BytesRegex> = OnceLock::new();

fn posix_imports_re() -> &'static BytesRegex {
    POSIX_IMPORTS_RE.get_or_init(|| {
        BytesRegex::new(
            r"(?x)
            \bptrace\b
            | /bin/sh\b
            | /bin/bash\b
            | /bin/zsh\b
            | \bsystem\b
            | \bexecve\b
            | \bexecl[pe]?\b
            | \bpopen\b
            | \bdlopen\b
            | \bdlsym\b
            | \bgetenv\b
            | /proc/self/mem\b
            | /proc/self/exe\b
            | /etc/passwd\b
            | /etc/shadow\b
            | \.ssh/authorized_keys\b
            | crontab\b
            ",
        )
        .expect("invariant: POSIX_IMPORTS_RE is a valid pattern")
    })
}

/// Reverse-shell triad: socket/connect/dup2 — each matched individually; we
/// require at least 2 of the 3 before flagging (reduces noise).
static SOCKET_RE: OnceLock<BytesRegex> = OnceLock::new();
static CONNECT_RE: OnceLock<BytesRegex> = OnceLock::new();
static DUP2_RE: OnceLock<BytesRegex> = OnceLock::new();

fn socket_re() -> &'static BytesRegex {
    SOCKET_RE.get_or_init(|| {
        BytesRegex::new(r"\bsocket\b").expect("invariant: SOCKET_RE is a valid pattern")
    })
}

fn connect_re() -> &'static BytesRegex {
    CONNECT_RE.get_or_init(|| {
        BytesRegex::new(r"\bconnect\b").expect("invariant: CONNECT_RE is a valid pattern")
    })
}

fn dup2_re() -> &'static BytesRegex {
    DUP2_RE.get_or_init(|| {
        BytesRegex::new(r"\bdup2\b").expect("invariant: DUP2_RE is a valid pattern")
    })
}

/// Packer markers (ASCII-safe patterns in compressed stubs).
static PACKER_RE: OnceLock<BytesRegex> = OnceLock::new();

fn packer_re() -> &'static BytesRegex {
    PACKER_RE.get_or_init(|| {
        BytesRegex::new(
            r"(?x)
            UPX!
            | \.upx\b
            | ASPack
            | PECompact
            | Themida
            | VMProtect
            | ExeStealth
            | MPRESS
            | Petite
            | nSPack
            | yC\x00
            ",
        )
        .expect("invariant: PACKER_RE is a valid pattern")
    })
}

/// Shellcode-ish byte patterns: common x86/x64 shellcode preambles found
/// verbatim in binary.  We look for these only in non-textual files to reduce
/// false positives in source code comments.
///
/// Patterns (all as raw bytes):
///   - `\xfc\xe8` — common CLD + CALL shellcode preamble (Metasploit stdapi)
///   - `\x60\x89\xe5` — PUSHA + MOV EBP,ESP (common prologue)
///   - `\x31\xc0\x50\x68` — XOR EAX,EAX / PUSH 0 / PUSH <str> (execve shellcode)
///   - `\x48\x31\xc0` — XOR RAX,RAX (64-bit null-byte free shellcode)
///   - `\x6a\x02\x5b\x6a\x29\x58\x99\x0f\x05` — socket(AF_INET,SOCK_STREAM,0) x64
static SHELLCODE_RE: OnceLock<BytesRegex> = OnceLock::new();

fn shellcode_re() -> &'static BytesRegex {
    SHELLCODE_RE.get_or_init(|| {
        BytesRegex::new(
            r"(?x-u)
            \xfc\xe8[\x00-\xff]{0,4}\x89
            | \x60\x89\xe5\x31
            | \x31\xc0\x50\x68
            | \x48\x31\xc0\x48\x31
            | \x6a\x02\x5b\x6a\x29\x58\x99\x0f\x05
            | \xeb\x1a\x5e\x31\xc9
            ",
        )
        .expect("invariant: SHELLCODE_RE is a valid pattern")
    })
}

/// RunKey registry value names — persistence via HKCU/HKLM Run keys.
static RUNKEY_RE: OnceLock<BytesRegex> = OnceLock::new();

fn runkey_re() -> &'static BytesRegex {
    RUNKEY_RE.get_or_init(|| {
        BytesRegex::new(
            r"(?xi)
            Software\\Microsoft\\Windows\\CurrentVersion\\Run\b
            | HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\b
            | HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\b
            ",
        )
        .expect("invariant: RUNKEY_RE is a valid pattern")
    })
}

/// Embedded executable magic inside a non-binary file: MZ or ELF at a non-zero
/// offset — we use a byte regex for this.
static EMBEDDED_MZ_RE: OnceLock<BytesRegex> = OnceLock::new();
static EMBEDDED_ELF_RE: OnceLock<BytesRegex> = OnceLock::new();

fn embedded_mz_re() -> &'static BytesRegex {
    EMBEDDED_MZ_RE.get_or_init(|| {
        BytesRegex::new(r"MZ").expect("invariant: EMBEDDED_MZ_RE is a valid pattern")
    })
}

fn embedded_elf_re() -> &'static BytesRegex {
    EMBEDDED_ELF_RE.get_or_init(|| {
        BytesRegex::new(r"\x7fELF").expect("invariant: EMBEDDED_ELF_RE is a valid pattern")
    })
}

// ---------------------------------------------------------------------------
// File-extension sets for JS/npm package detection.
// ---------------------------------------------------------------------------

/// Extensions considered part of a JavaScript/npm package.
#[allow(dead_code)] // reason: reserved for a future is_js_pkg_file helper; not yet wired into the scan path
const JS_PKG_EXTENSIONS: &[&str] = &[
    "js", "mjs", "cjs", "ts", "tsx", "jsx", "json", "md", "txt", "html", "css",
];

// ---------------------------------------------------------------------------
// Maximum bytes to search for embedded executables in large files.
// We cap to avoid scanning e.g. a 32 MiB concatenated archive byte-by-byte.
// ---------------------------------------------------------------------------
const EMBEDDED_SCAN_LIMIT: usize = 4 * 1024 * 1024; // 4 MiB

// ---------------------------------------------------------------------------
// Maximum bytes of a binary from which we extract printable strings.
// ---------------------------------------------------------------------------
const STRING_EXTRACT_LIMIT: usize = 8 * 1024 * 1024; // 8 MiB

/// Minimum length of a printable run to qualify as a "string".
const MIN_STRING_LEN: usize = 5;

// ---------------------------------------------------------------------------
// Helper: extract printable ASCII runs (like `strings(1)`).
// ---------------------------------------------------------------------------

fn extract_printable_strings(data: &[u8], limit: usize) -> Vec<Vec<u8>> {
    let data = &data[..data.len().min(limit)];
    let mut results = Vec::new();
    let mut current = Vec::new();
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            current.push(b);
        } else {
            if current.len() >= MIN_STRING_LEN {
                results.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= MIN_STRING_LEN {
        results.push(current);
    }
    results
}

// ---------------------------------------------------------------------------
// Helper: check whether `data` starts with a native binary magic.
// ---------------------------------------------------------------------------

#[allow(dead_code)] // reason: utility used by tests; production scan path uses the regex-based embedded search instead
fn starts_with_native_magic(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    if data.starts_with(MZ_MAGIC) || data.starts_with(ELF_MAGIC) {
        return true;
    }
    for m in MACHO_MAGICS {
        if data.starts_with(m.as_ref()) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Helper: is this file path inside an npm-style package?
//
// Heuristic: the scan root contains a package.json AND this file's extension
// is NOT in JS_PKG_EXTENSIONS and the file is a native binary.
// ---------------------------------------------------------------------------

fn is_js_package_context(ctx: &ScanContext<'_>) -> bool {
    ctx.package_json.is_some()
}

fn is_binary_in_js_package(file: &FileUnit, ctx: &ScanContext<'_>) -> bool {
    if !file.kind.is_native_binary() {
        return false;
    }
    if !is_js_package_context(ctx) {
        return false;
    }
    // Also check if the path extension is not a known JS/text extension —
    // but native binary detection via kind is authoritative.
    true
}

// ---------------------------------------------------------------------------
// Helper: find first occurrence of native magic at a non-zero offset.
// Returns the offset and what kind of magic was found ("MZ", "ELF", "Mach-O").
// ---------------------------------------------------------------------------

fn find_embedded_magic(data: &[u8]) -> Option<(usize, &'static str)> {
    let search_data = &data[..data.len().min(EMBEDDED_SCAN_LIMIT)];

    // Search for ELF at any non-zero offset using byte regex.
    if let Some(m) = embedded_elf_re().find_at(search_data, 1) {
        return Some((m.start(), "ELF"));
    }

    // Search for MZ at any non-zero offset.
    if let Some(m) = embedded_mz_re().find_at(search_data, 1) {
        // Verify the byte before is not part of legitimate text.
        // MZ is common in text (e.g. "MHz") so require a low-entropy context:
        // the 4 bytes following "MZ" must look like a DOS header
        // (offset 0x3c is the PE header pointer — typically non-zero).
        let start = m.start();
        if start + 64 <= search_data.len() {
            // Byte at offset+2 in a real MZ header is always 0x00 or 0x90.
            // More pragmatically: if byte[offset+2] <= 0x20 it's not a word.
            let b2 = search_data[start + 2];
            if b2 <= 0x20 || b2 >= 0x80 {
                return Some((start, "MZ (PE)"));
            }
        }
    }

    // Search for Mach-O magic.
    for magic in MACHO_MAGICS {
        // Manual search — OnceLock regexes are for ASCII patterns; Mach-O
        // magics contain non-ASCII bytes we can search with windows.
        for (i, window) in search_data.windows(4).enumerate() {
            if i == 0 {
                continue; // skip offset 0 (that's the file header itself)
            }
            if window == magic.as_ref() {
                return Some((i, "Mach-O"));
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Core string-level analysis helpers, returning individual Findings.
// ---------------------------------------------------------------------------

/// Scan extracted strings against Windows API patterns.
fn check_windows_apis(strings: &[Vec<u8>], path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Gather matched API names for evidence.
    let mut matched_apis: Vec<String> = Vec::new();
    let mut has_loadlib = false;
    let mut has_getproc = false;

    for s in strings {
        if win_imports_re().is_match(s)
            && let Ok(text) = std::str::from_utf8(s)
        {
            let trimmed = text.trim();
            if !trimmed.is_empty() && !matched_apis.contains(&trimmed.to_string()) {
                matched_apis.push(trimmed.to_string());
            }
        }
        if loadlib_re().is_match(s) {
            has_loadlib = true;
        }
        if getproc_re().is_match(s) {
            has_getproc = true;
        }
    }

    if !matched_apis.is_empty() {
        let evidence = matched_apis.join(", ");
        findings.push(
            Finding::new(
                ENGINE,
                ThreatCategory::CommandExecution,
                Severity::High,
                Confidence::High,
                "Suspicious Windows API imports",
                "Binary imports APIs associated with code injection, execution, or anti-debugging.",
            )
            .with_rule_id("BIN_WIN_SUSPICIOUS_APIS")
            .with_location(FileLocation::file(path))
            .with_evidence(evidence, 160),
        );
    }

    if has_loadlib && has_getproc {
        findings.push(
            Finding::new(
                ENGINE,
                ThreatCategory::CommandExecution,
                Severity::High,
                Confidence::High,
                "LoadLibrary + GetProcAddress pairing",
                "Binary uses LoadLibrary paired with GetProcAddress: common for runtime import \
                 hiding and reflective DLL injection.",
            )
            .with_rule_id("BIN_WIN_LOADLIB_GETPROC")
            .with_location(FileLocation::file(path)),
        );
    }

    findings
}

/// Check for Windows Run-key persistence strings.
fn check_run_key(strings: &[Vec<u8>], path: &str) -> Option<Finding> {
    for s in strings {
        if runkey_re().is_match(s) {
            let evidence = String::from_utf8_lossy(s).into_owned();
            return Some(
                Finding::new(
                    ENGINE,
                    ThreatCategory::FilesystemAbuse,
                    Severity::High,
                    Confidence::High,
                    "Registry Run-key persistence",
                    "Binary references a HKCU/HKLM Run registry key used for startup persistence.",
                )
                .with_rule_id("BIN_WIN_RUNKEY_PERSISTENCE")
                .with_location(FileLocation::file(path))
                .with_evidence(evidence, 160),
            );
        }
    }
    None
}

/// Check for POSIX suspicious APIs.
fn check_posix_apis(strings: &[Vec<u8>], path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut matched: Vec<String> = Vec::new();

    for s in strings {
        if posix_imports_re().is_match(s)
            && let Ok(text) = std::str::from_utf8(s)
        {
            let trimmed = text.trim().to_string();
            if !trimmed.is_empty() && !matched.contains(&trimmed) {
                matched.push(trimmed);
            }
        }
    }

    if !matched.is_empty() {
        let evidence = matched.join(", ");
        findings.push(
            Finding::new(
                ENGINE,
                ThreatCategory::CommandExecution,
                Severity::Medium,
                Confidence::Medium,
                "Suspicious POSIX API / path strings",
                "Binary references POSIX APIs or sensitive paths (e.g. /bin/sh, ptrace, \
                 /etc/shadow) commonly seen in post-exploitation payloads.",
            )
            .with_rule_id("BIN_POSIX_SUSPICIOUS_APIS")
            .with_location(FileLocation::file(path))
            .with_evidence(evidence, 160),
        );
    }
    findings
}

/// Check for reverse-shell triad: socket + connect + dup2 (need 2 of 3).
fn check_reverse_shell_triad(strings: &[Vec<u8>], path: &str) -> Option<Finding> {
    // Join extracted strings separated by NUL so word boundaries between adjacent
    // strings work correctly with the \b-anchored patterns.
    let combined: Vec<u8> = strings
        .iter()
        .flat_map(|s| s.iter().copied().chain(std::iter::once(0u8)))
        .collect();

    let has_socket = socket_re().is_match(&combined);
    let has_connect = connect_re().is_match(&combined);
    let has_dup2 = dup2_re().is_match(&combined);

    let count = [has_socket, has_connect, has_dup2]
        .iter()
        .filter(|&&b| b)
        .count();
    if count >= 2 {
        let mut present = Vec::new();
        if has_socket {
            present.push("socket");
        }
        if has_connect {
            present.push("connect");
        }
        if has_dup2 {
            present.push("dup2");
        }

        return Some(
            Finding::new(
                ENGINE,
                ThreatCategory::Network,
                Severity::High,
                Confidence::Medium,
                "Reverse-shell function triad",
                "Binary contains socket/connect/dup2: the canonical POSIX reverse-shell triad.",
            )
            .with_rule_id("BIN_POSIX_REVERSE_SHELL_TRIAD")
            .with_location(FileLocation::file(path))
            .with_evidence(present.join(" + "), 160),
        );
    }
    None
}

/// Check for packer markers in raw binary bytes.
fn check_packer(data: &[u8], path: &str) -> Option<Finding> {
    let scan_data = &data[..data.len().min(STRING_EXTRACT_LIMIT)];
    if let Some(m) = packer_re().find(scan_data) {
        let evidence = String::from_utf8_lossy(m.as_bytes()).into_owned();
        return Some(
            Finding::new(
                ENGINE,
                ThreatCategory::Packer,
                Severity::High,
                Confidence::High,
                "Known binary packer detected",
                "Binary contains a packer signature (e.g. UPX, ASPack). Packers are used to \
                 compress and obfuscate malware.",
            )
            .with_rule_id("BIN_PACKER_SIGNATURE")
            .with_location(FileLocation::file(path))
            .with_evidence(evidence, 160),
        );
    }
    None
}

/// Check for shellcode-ish byte patterns (only for non-textual files).
fn check_shellcode(data: &[u8], path: &str) -> Option<Finding> {
    let scan_data = &data[..data.len().min(STRING_EXTRACT_LIMIT)];
    if let Some(m) = shellcode_re().find(scan_data) {
        return Some(
            Finding::new(
                ENGINE,
                ThreatCategory::NativeBinary,
                Severity::High,
                Confidence::Medium,
                "Shellcode-like byte sequence",
                "Binary contains a byte pattern matching known x86/x64 shellcode preambles \
                 (e.g. Metasploit stdapi, execve stager, socket stager).",
            )
            .with_rule_id("BIN_SHELLCODE_PATTERN")
            .with_location(FileLocation::file(path))
            .with_evidence(format!("at byte offset {}", m.start()), 160),
        );
    }
    None
}

// ---------------------------------------------------------------------------
// Per-file analysis entry points.
// ---------------------------------------------------------------------------

/// Full analysis for a known-native binary file.
fn analyze_native_binary(file: &FileUnit, ctx: &ScanContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let path = &file.rel_path;

    // Supply-chain: native binary inside a JS/npm package.
    if is_binary_in_js_package(file, ctx) {
        let exe_type = match file.kind {
            FileKind::ElfBinary => "ELF",
            FileKind::PeBinary => "PE (Windows)",
            FileKind::MachoBinary => "Mach-O",
            _ => "native",
        };
        findings.push(
            Finding::new(
                ENGINE,
                ThreatCategory::SupplyChain,
                Severity::High,
                Confidence::High,
                "Native binary inside npm/JS package",
                "A native executable was found inside what appears to be a JavaScript/npm \
                 package. Legitimate npm packages almost never ship pre-built binaries; this \
                 is a common supply-chain attack vector.",
            )
            .with_rule_id("BIN_NATIVE_IN_NPM_PACKAGE")
            .with_location(FileLocation::file(path))
            .with_evidence(exe_type, 160),
        );
    }

    // Packer check directly on raw bytes.
    if let Some(f) = check_packer(&file.data, path) {
        findings.push(f);
    }

    // Shellcode byte patterns (only in non-textual files).
    if !file.looks_textual()
        && let Some(f) = check_shellcode(&file.data, path)
    {
        findings.push(f);
    }

    // Extract printable strings for API/import analysis.
    let strings = extract_printable_strings(&file.data, STRING_EXTRACT_LIMIT);

    // Windows API checks.
    findings.extend(check_windows_apis(&strings, path));
    if let Some(f) = check_run_key(&strings, path) {
        findings.push(f);
    }

    // POSIX API checks.
    findings.extend(check_posix_apis(&strings, path));
    if let Some(f) = check_reverse_shell_triad(&strings, path) {
        findings.push(f);
    }

    findings
}

/// Analysis for a non-binary file that may embed a native binary payload.
fn analyze_for_embedded_payload(file: &FileUnit, _ctx: &ScanContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let path = &file.rel_path;

    // Only search files up to EMBEDDED_SCAN_LIMIT.
    let Some((offset, kind)) = find_embedded_magic(&file.data) else {
        return findings;
    };

    findings.push(
        Finding::new(
            ENGINE,
            ThreatCategory::NativeBinary,
            Severity::High,
            Confidence::High,
            "Embedded native binary payload",
            "A native executable magic header was found at a non-zero offset inside a \
             non-binary file. This is a strong indicator of a dropper, polyglot exploit, \
             or supply-chain attack payload.",
        )
        .with_rule_id("BIN_EMBEDDED_NATIVE_PAYLOAD")
        .with_location(FileLocation {
            path: path.clone(),
            line: None,
            offset: Some(offset),
        })
        .with_evidence(format!("{kind} header at offset {offset}"), 160),
    );

    // Also run string analysis on the portion after the embedded magic.
    let tail = &file.data[offset.min(file.data.len())..];
    let strings = extract_printable_strings(tail, STRING_EXTRACT_LIMIT);
    findings.extend(check_windows_apis(&strings, path));
    findings.extend(check_posix_apis(&strings, path));
    if let Some(f) = check_reverse_shell_triad(&strings, path) {
        findings.push(f);
    }

    findings
}

// ---------------------------------------------------------------------------
// The engine struct.
// ---------------------------------------------------------------------------

/// Detects suspicious indicators in native binaries (ELF/PE/Mach-O) and in
/// non-binary files that embed a native executable payload.
///
/// Categories: [`ThreatCategory::NativeBinary`], [`ThreatCategory::CommandExecution`],
/// [`ThreatCategory::Network`], [`ThreatCategory::SupplyChain`],
/// [`ThreatCategory::FilesystemAbuse`], [`ThreatCategory::Packer`].
#[derive(Debug, Default)]
pub struct BinaryIndicatorEngine;

impl DetectionEngine for BinaryIndicatorEngine {
    fn name(&self) -> &'static str {
        ENGINE
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in ctx.files {
            // Skip files that exceed the configured per-file size limit.
            // (The loader normally enforces this, but we double-check for safety.)
            if file.len() as u64 > ctx.config.max_file_size {
                tracing::debug!(
                    engine = ENGINE,
                    path = %file.rel_path,
                    size = file.len(),
                    "skipping oversized file"
                );
                continue;
            }

            if file.kind.is_native_binary() {
                findings.extend(analyze_native_binary(file, ctx));
            } else if !file.is_empty() {
                // For non-binary files: look for embedded native payloads.
                findings.extend(analyze_for_embedded_payload(file, ctx));
            }
        }

        // Deduplicate by rule_id + path to avoid repeating the same finding
        // when the same string pattern matches multiple times.
        findings.dedup_by(|a, b| {
            a.rule_id == b.rule_id
                && a.location.as_ref().map(|l| &l.path) == b.location.as_ref().map(|l| &l.path)
        });

        findings
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::ScanConfig,
        engine::{FileKind, FileUnit, ScanContext},
        types::{Severity, ThreatCategory},
    };

    fn make_file(rel_path: &str, data: Vec<u8>, kind: FileKind) -> FileUnit {
        let sha256 = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&data);
            hex::encode(h.finalize())
        };
        FileUnit {
            rel_path: rel_path.to_string(),
            data,
            kind,
            sha256,
        }
    }

    fn run_engine(files: Vec<FileUnit>, package_json: Option<serde_json::Value>) -> Vec<Finding> {
        let config = ScanConfig::default();
        let ctx = ScanContext {
            target_name: "test".to_string(),
            files: &files,
            package_json: package_json.as_ref(),
            config: &config,
        };
        let engine = BinaryIndicatorEngine;
        engine.scan(&ctx)
    }

    // ----- Helper: build a fake ELF binary with suspicious strings ----------

    fn fake_elf_with_strings(extra: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        // ELF magic + minimal header bytes.
        data.extend_from_slice(ELF_MAGIC);
        data.extend_from_slice(&[
            0x02, // EI_CLASS = 64-bit
            0x01, // EI_DATA = little-endian
            0x01, // EI_VERSION
            0x00, // EI_OSABI
        ]);
        data.extend_from_slice(&[0u8; 8]); // padding
        // e_type, e_machine, e_version
        data.extend_from_slice(&[0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0u8; 48]); // rest of ELF header
        // Append the suspicious strings with NUL separators.
        data.extend_from_slice(extra);
        data
    }

    // ----- Helper: build a fake PE (MZ) binary ------------------------------

    fn fake_pe_with_strings(extra: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        // MZ magic.
        data.extend_from_slice(MZ_MAGIC);
        // Minimal DOS stub (64 bytes) — byte[0x3c] = PE offset.
        data.extend_from_slice(&[0u8; 0x3a]);
        data.push(0x40); // PE offset = 0x40
        data.push(0x00);
        data.extend_from_slice(&[0x00; 0x100]); // padding to PE offset
        // PE signature.
        data.extend_from_slice(b"PE\x00\x00");
        data.extend_from_slice(&[0u8; 20]); // COFF header
        data.extend_from_slice(extra);
        data
    }

    // -----------------------------------------------------------------------
    // Positive tests
    // -----------------------------------------------------------------------

    #[test]
    fn elf_with_win_apis_flagged() {
        let mut payload =
            b"CreateRemoteThread\x00VirtualAllocEx\x00WriteProcessMemory\x00".to_vec();
        payload.extend_from_slice(b"IsDebuggerPresent\x00");
        let data = fake_elf_with_strings(&payload);
        let files = vec![make_file("agent/payload.elf", data, FileKind::ElfBinary)];
        let findings = run_engine(files, None);

        let rule_ids: Vec<_> = findings
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        assert!(
            rule_ids.contains(&"BIN_WIN_SUSPICIOUS_APIS"),
            "expected BIN_WIN_SUSPICIOUS_APIS; got {:?}",
            rule_ids
        );
        // All should have the correct engine name.
        for f in &findings {
            assert_eq!(f.engine, ENGINE);
        }
    }

    #[test]
    fn pe_with_loadlib_getproc_flagged() {
        let payload = b"LoadLibraryA\x00GetProcAddress\x00kernel32.dll\x00".to_vec();
        let data = fake_pe_with_strings(&payload);
        let files = vec![make_file("bin/inject.exe", data, FileKind::PeBinary)];
        let findings = run_engine(files, None);

        let rule_ids: Vec<_> = findings
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        assert!(
            rule_ids.contains(&"BIN_WIN_LOADLIB_GETPROC"),
            "expected BIN_WIN_LOADLIB_GETPROC; got {:?}",
            rule_ids
        );
    }

    #[test]
    fn elf_with_reverse_shell_triad_flagged() {
        let payload = b"socket\x00connect\x00dup2\x00/bin/sh\x00".to_vec();
        let data = fake_elf_with_strings(&payload);
        let files = vec![make_file("tools/implant.elf", data, FileKind::ElfBinary)];
        let findings = run_engine(files, None);

        let rule_ids: Vec<_> = findings
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        assert!(
            rule_ids.contains(&"BIN_POSIX_REVERSE_SHELL_TRIAD"),
            "expected reverse-shell triad; got {:?}",
            rule_ids
        );
        let triad = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("BIN_POSIX_REVERSE_SHELL_TRIAD"))
            .unwrap();
        assert_eq!(triad.category, ThreatCategory::Network);
        assert_eq!(triad.severity, Severity::High);
    }

    #[test]
    fn pe_with_run_key_flagged() {
        let payload = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00evil.exe\x00".to_vec();
        let data = fake_pe_with_strings(&payload);
        let files = vec![make_file("setup/updater.exe", data, FileKind::PeBinary)];
        let findings = run_engine(files, None);

        let rule_ids: Vec<_> = findings
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        assert!(
            rule_ids.contains(&"BIN_WIN_RUNKEY_PERSISTENCE"),
            "expected runkey persistence; got {:?}",
            rule_ids
        );
    }

    #[test]
    fn packer_upx_flagged() {
        let mut data = fake_elf_with_strings(b"");
        data.extend_from_slice(b"UPX!\x00compressed_stub_data_here\x00");
        let files = vec![make_file("packed/sample", data, FileKind::ElfBinary)];
        let findings = run_engine(files, None);

        let rule_ids: Vec<_> = findings
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        assert!(
            rule_ids.contains(&"BIN_PACKER_SIGNATURE"),
            "expected UPX packer signature; got {:?}",
            rule_ids
        );
        let pf = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("BIN_PACKER_SIGNATURE"))
            .unwrap();
        assert_eq!(pf.category, ThreatCategory::Packer);
    }

    #[test]
    fn native_binary_in_npm_package_flagged() {
        let data = fake_elf_with_strings(b"benign_string_here\x00");
        let package_json: serde_json::Value =
            serde_json::json!({"name": "evil-pkg", "version": "1.0.0"});
        let files = vec![make_file("bin/helper", data, FileKind::ElfBinary)];
        let findings = run_engine(files, Some(package_json));

        let rule_ids: Vec<_> = findings
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        assert!(
            rule_ids.contains(&"BIN_NATIVE_IN_NPM_PACKAGE"),
            "expected supply-chain native-binary finding; got {:?}",
            rule_ids
        );
        let sf = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("BIN_NATIVE_IN_NPM_PACKAGE"))
            .unwrap();
        assert_eq!(sf.category, ThreatCategory::SupplyChain);
        assert_eq!(sf.severity, Severity::High);
    }

    #[test]
    fn embedded_mz_in_js_file_flagged() {
        // A JavaScript file that contains an MZ header partway through.
        // We use a low-entropy context after MZ to pass the PE-header heuristic.
        let mut data = b"// legitimate-looking JS code\nconsole.log('hello');\n".to_vec();
        // Append MZ with plausible DOS header structure: MZ + 62 bytes of zeros.
        data.extend_from_slice(MZ_MAGIC);
        // byte[2] = 0x00 (size of last page mod 512) — passes our heuristic.
        data.extend_from_slice(&[0x00u8; 62]);
        // Add enough padding to satisfy the `start + 64 <= search_data.len()` check.
        data.extend_from_slice(&[0u8; 64]);

        let files = vec![make_file("dist/bundle.js", data, FileKind::Javascript)];
        let findings = run_engine(files, None);

        let rule_ids: Vec<_> = findings
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        assert!(
            rule_ids.contains(&"BIN_EMBEDDED_NATIVE_PAYLOAD"),
            "expected embedded payload finding; got {:?}",
            rule_ids
        );
        let ef = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("BIN_EMBEDDED_NATIVE_PAYLOAD"))
            .unwrap();
        assert_eq!(ef.category, ThreatCategory::NativeBinary);
        assert_eq!(ef.severity, Severity::High);
        assert_eq!(ef.confidence, Confidence::High);
    }

    #[test]
    fn embedded_elf_in_json_file_flagged() {
        let mut data = b"{\"name\":\"pkg\",\"scripts\":{\"install\":\"node setup.js\"}}".to_vec();
        // ELF magic embedded inside.
        data.extend_from_slice(ELF_MAGIC);
        data.extend_from_slice(&[0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0u8; 64]);

        let files = vec![make_file("data/blob.json", data, FileKind::Json)];
        let findings = run_engine(files, None);

        let rule_ids: Vec<_> = findings
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        assert!(
            rule_ids.contains(&"BIN_EMBEDDED_NATIVE_PAYLOAD"),
            "expected embedded ELF in JSON; got {:?}",
            rule_ids
        );
    }

    #[test]
    fn posix_sensitive_paths_in_elf() {
        let payload = b"/etc/shadow\x00/etc/passwd\x00ptrace\x00dlopen\x00".to_vec();
        let data = fake_elf_with_strings(&payload);
        let files = vec![make_file("lib/hooker.so", data, FileKind::ElfBinary)];
        let findings = run_engine(files, None);

        let rule_ids: Vec<_> = findings
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        assert!(
            rule_ids.contains(&"BIN_POSIX_SUSPICIOUS_APIS"),
            "expected POSIX API finding; got {:?}",
            rule_ids
        );
    }

    #[test]
    fn shellcode_pattern_in_binary() {
        // Inject the Metasploit CLD+CALL shellcode preamble.
        let mut data = fake_pe_with_strings(b"");
        // \xfc\xe8 + 4 bytes + \x89 = the pattern the regex expects.
        data.extend_from_slice(&[0xFC, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x89, 0xC3]);
        data.extend_from_slice(&[0u8; 32]); // some trailing bytes

        let files = vec![make_file("shellcode.bin", data, FileKind::PeBinary)];
        let findings = run_engine(files, None);

        let rule_ids: Vec<_> = findings
            .iter()
            .filter_map(|f| f.rule_id.as_deref())
            .collect();
        assert!(
            rule_ids.contains(&"BIN_SHELLCODE_PATTERN"),
            "expected shellcode pattern; got {:?}",
            rule_ids
        );
    }

    // -----------------------------------------------------------------------
    // Negative tests — benign input must not be flagged.
    // -----------------------------------------------------------------------

    #[test]
    fn plain_text_file_not_flagged() {
        let data =
            b"Hello, world!\nThis is a perfectly normal text file.\nNo malware here.\n".to_vec();
        let files = vec![make_file("README.txt", data, FileKind::Text)];
        let findings = run_engine(files, None);
        assert!(
            findings.is_empty(),
            "plain text should produce no findings; got {:?}",
            findings
        );
    }

    #[test]
    fn benign_js_file_not_flagged() {
        let data =
            b"'use strict';\nconst x = 1 + 2;\nconsole.log(x);\nmodule.exports = x;\n".to_vec();
        let files = vec![make_file("index.js", data, FileKind::Javascript)];
        let findings = run_engine(files, None);
        assert!(
            findings.is_empty(),
            "benign JS should produce no findings; got {:?}",
            findings
        );
    }

    #[test]
    fn benign_json_not_flagged() {
        let data =
            br#"{"name":"lodash","version":"4.17.21","description":"Utility library"}"#.to_vec();
        let files = vec![make_file("package.json", data, FileKind::Json)];
        let findings = run_engine(files, None);
        assert!(
            findings.is_empty(),
            "benign JSON should produce no findings; got {:?}",
            findings
        );
    }

    #[test]
    fn elf_without_suspicious_strings_minimal_findings() {
        // An ELF with only innocuous strings — no suspicious APIs.
        let payload = b"libdl.so\x00libm.so\x00printf\x00malloc\x00free\x00exit\x00".to_vec();
        let data = fake_elf_with_strings(&payload);
        let files = vec![make_file("lib/libc.so.6", data, FileKind::ElfBinary)];
        let findings = run_engine(files, None);

        // Should produce no high-signal rule_id findings.
        let high_signal: Vec<_> = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.rule_id.as_deref(),
                    Some(
                        "BIN_WIN_SUSPICIOUS_APIS"
                            | "BIN_WIN_LOADLIB_GETPROC"
                            | "BIN_WIN_RUNKEY_PERSISTENCE"
                            | "BIN_POSIX_REVERSE_SHELL_TRIAD"
                            | "BIN_PACKER_SIGNATURE"
                            | "BIN_SHELLCODE_PATTERN"
                            | "BIN_EMBEDDED_NATIVE_PAYLOAD"
                    )
                )
            })
            .collect();
        assert!(
            high_signal.is_empty(),
            "benign ELF should not trigger high-signal rules; got {:?}",
            high_signal
        );
    }

    #[test]
    fn text_file_with_word_mz_not_flagged() {
        // "MHz" and "MHz" contain "MZ" but this is a text file — should not trigger.
        let data = b"The processor runs at 3600 MHz. MZ is a file format prefix.\n".to_vec();
        let files = vec![make_file("notes.txt", data, FileKind::Text)];
        let findings = run_engine(files, None);
        // The embedded-MZ check requires byte[2] to be a control/high byte — in ASCII
        // "MHz" byte[2]='z'=0x7A which does NOT pass the heuristic.
        let embedded: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("BIN_EMBEDDED_NATIVE_PAYLOAD"))
            .collect();
        assert!(
            embedded.is_empty(),
            "plain-text 'MHz' word should not produce embedded-payload finding; got {:?}",
            embedded
        );
    }

    #[test]
    fn empty_file_not_flagged() {
        let files = vec![make_file("empty.bin", vec![], FileKind::Unknown)];
        let findings = run_engine(files, None);
        assert!(findings.is_empty(), "empty file should produce no findings");
    }

    #[test]
    fn finding_evidence_truncated_to_160() {
        // Very long API string list should be truncated to 160 chars.
        let long_str: Vec<u8> = std::iter::repeat_n(b'A', 300)
            .chain(b"\x00".iter().copied())
            .collect();
        let mut payload = b"CreateRemoteThread\x00".to_vec();
        payload.extend_from_slice(&long_str);
        let data = fake_pe_with_strings(&payload);
        let files = vec![make_file("long.exe", data, FileKind::PeBinary)];
        let findings = run_engine(files, None);
        for f in &findings {
            if let Some(ev) = &f.evidence {
                // with_evidence truncates to max chars then adds '…'.
                assert!(
                    ev.len() <= 164,
                    "evidence longer than expected: {} chars",
                    ev.len()
                );
            }
        }
    }

    #[test]
    fn engine_name_consistent_in_findings() {
        let payload = b"CreateRemoteThread\x00VirtualAllocEx\x00".to_vec();
        let data = fake_pe_with_strings(&payload);
        let files = vec![make_file("c2.exe", data, FileKind::PeBinary)];
        let findings = run_engine(files, None);
        assert!(!findings.is_empty());
        for f in &findings {
            assert_eq!(
                f.engine, ENGINE,
                "engine name mismatch: {} != {}",
                f.engine, ENGINE
            );
        }
    }
}
