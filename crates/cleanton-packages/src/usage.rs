//! Bounded codebase scan that maps package names to the files referencing them.
//!
//! Dependency-free (std `fs` only). Every traversal axis is hard-bounded so a
//! pathological tree can never dominate: a wall-clock budget, total files,
//! total bytes, per-file size, and depth are all capped, and a curated
//! skip-list prunes vendored and cache directories. The wall-clock budget is
//! the primary guard: a giant checkout (e.g. an 80 GB / 1.24 M-file
//! `chromium-src`) stops the walk after `SCAN_BUDGET` regardless of the file
//! cap, so the scan can never peg a core for tens of seconds.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Maximum directory depth descended from each root.
const MAX_DEPTH: usize = 8;
/// Hard cap on files inspected across all roots.
const MAX_FILES: usize = 12_000;
/// Hard cap on bytes read across all roots (512 MiB).
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
/// Largest single file we will read (1 MiB).
const MAX_FILE_SIZE: u64 = 1024 * 1024;
/// Maximum referencing files recorded per package name.
const MAX_REFS_PER_NAME: usize = 20;
/// Wall-clock budget for an entire `scan_usage` call. Checked periodically so a
/// huge tree returns partial results promptly instead of grinding to the cap.
const SCAN_BUDGET: Duration = Duration::from_secs(8);
/// How often (in inspected files) the wall-clock budget is re-checked.
const BUDGET_CHECK_STRIDE: usize = 256;

/// Directory basenames pruned during traversal.
const SKIP_DIRS: &[&str] = &[
    "chromium-src",
    "node_modules",
    "target",
    ".git",
    ".cache",
    "Caches",
    "Library",
    ".Trash",
    "dist",
    "build",
    "vendor",
    ".venv",
    "__pycache__",
    ".pyenv",
    ".cargo",
    ".rustup",
    "Pods",
    ".next",
    ".turbo",
    "DerivedData",
];

/// Source-file extensions that get a whole-word / linker-flag grep.
const SOURCE_EXTS: &[&str] = &[
    "sh", "rb", "py", "js", "ts", "go", "rs", "c", "cpp", "h", "mk", "podspec",
];

/// Manifest files matched by exact (lower-cased) basename.
const EXACT_MANIFESTS: &[&str] = &[
    "brewfile",
    "package.json",
    "pipfile",
    "pyproject.toml",
    "makefile",
    "cmakelists.txt",
    "configure",
    "configure.ac",
    ".tool-versions",
];

/// Tunable bounds for a single scan. Exposed only internally so tests can drive
/// the short-circuit paths deterministically; the public API uses [`DEFAULT_LIMITS`].
#[derive(Debug, Clone, Copy)]
struct Limits {
    max_files: usize,
    max_total_bytes: u64,
    budget: Duration,
}

const DEFAULT_LIMITS: Limits = Limits {
    max_files: MAX_FILES,
    max_total_bytes: MAX_TOTAL_BYTES,
    budget: SCAN_BUDGET,
};

/// Mutable traversal state for one `scan_usage` call.
struct Walk<'a> {
    needles: &'a [(String, String)],
    limits: Limits,
    start: Instant,
    hits: HashMap<String, Vec<PathBuf>>,
    files_scanned: usize,
    bytes_read: u64,
}

impl Walk<'_> {
    /// File/byte caps hit (cheap integer comparisons).
    fn exhausted(&self) -> bool {
        self.files_scanned >= self.limits.max_files
            || self.bytes_read >= self.limits.max_total_bytes
    }

    /// Wall-clock budget spent.
    fn budget_spent(&self) -> bool {
        self.start.elapsed() >= self.limits.budget
    }

    fn walk_root(&mut self, root: &Path) {
        // Explicit stack avoids unbounded recursion on deep trees.
        let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];

        while let Some((dir, depth)) = stack.pop() {
            // One budget check per directory keeps overhead negligible while
            // still firing in trees full of non-inspectable files.
            if self.exhausted() || self.budget_spent() {
                return;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                // `file_type` from read_dir does not follow symlinks, so a
                // symlinked directory reports neither dir nor file and is
                // naturally skipped — this also prevents traversal cycles.
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                let path = entry.path();
                if file_type.is_dir() {
                    if depth >= MAX_DEPTH || is_skipped_dir(&path) {
                        continue;
                    }
                    stack.push((path, depth.saturating_add(1)));
                } else if file_type.is_file() && is_inspectable(&path) {
                    if self.exhausted() {
                        return;
                    }
                    // Re-check the wall clock every `BUDGET_CHECK_STRIDE` files;
                    // content matching ~hundreds of names per file is the cost.
                    if self.files_scanned.is_multiple_of(BUDGET_CHECK_STRIDE) && self.budget_spent()
                    {
                        return;
                    }
                    // DirEntry::metadata reuses the traversal's own stat
                    // instead of a second path-based stat per file.
                    if let Ok(metadata) = entry.metadata() {
                        self.inspect_file(&path, metadata.len());
                    }
                }
            }
        }
    }

    fn inspect_file(&mut self, path: &Path, len: u64) {
        if len > MAX_FILE_SIZE {
            return;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        self.files_scanned = self.files_scanned.saturating_add(1);
        self.bytes_read = self
            .bytes_read
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(0));

        let content = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        // Tokenise the file ONCE instead of rescanning the whole content for
        // every package name (previously O(files x packages x bytes) — with
        // ~290 installed packages that dominated the Packages tab load).
        // Tokens keep `-`, `.`, `/`, `@`, `+` so names like `ada-url`,
        // `@scope/pkg` and `libstdc++` survive as single tokens; `/`-joined
        // segments are indexed too (`openssl/ssl.h` still finds `openssl`).
        let mut tokens = std::collections::HashSet::new();
        let mut linker_names = std::collections::HashSet::new();
        for token in content.split(|c: char| {
            !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '@' | '+'))
        }) {
            if token.is_empty() {
                continue;
            }
            tokens.insert(token);
            for segment in token.split('/') {
                if !segment.is_empty() {
                    tokens.insert(segment);
                }
            }
            if let Some(name) = token.strip_prefix("-l")
                && !name.is_empty()
            {
                linker_names.insert(name);
            }
        }
        // `pkg-config <name>` is the one multi-token form worth supporting;
        // find it with a single scan, not one scan per package name.
        let mut pkg_config_names = std::collections::HashSet::new();
        for (start, _) in content.match_indices("pkg-config") {
            let rest = content.get(start + "pkg-config".len()..).unwrap_or("");
            let name = rest
                .trim_start()
                .split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '+')))
                .next()
                .unwrap_or("");
            if !name.is_empty() {
                pkg_config_names.insert(name);
            }
        }

        for (original, lowered) in self.needles {
            let token_safe = !lowered.is_empty()
                && lowered
                    .chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '@' | '+'));
            let matched = if token_safe {
                tokens.contains(lowered.as_str())
                    || linker_names.contains(lowered.as_str())
                    || pkg_config_names.contains(lowered.as_str())
            } else {
                // Exotic names (spaces, quotes, ...) keep the exact old
                // whole-word semantics; there are almost none of them.
                file_matches(&content, lowered)
            };
            if matched {
                let bucket = self.hits.entry(original.clone()).or_default();
                if bucket.len() < MAX_REFS_PER_NAME {
                    bucket.push(path.to_path_buf());
                }
            }
        }
    }
}

/// Scans `roots` for references to each of `package_names`.
///
/// Returns `name -> sorted, unique, capped list of referencing files`. Names
/// with no references are omitted. Missing roots are skipped silently. The walk
/// is bounded by a wall-clock budget ([`SCAN_BUDGET`]) as well as file/byte
/// caps, so it returns whatever it has found once any bound is reached.
#[must_use]
pub fn scan_usage(package_names: &[String], roots: &[PathBuf]) -> HashMap<String, Vec<PathBuf>> {
    scan_usage_with(package_names, roots, DEFAULT_LIMITS).0
}

/// Core scan, parameterized over [`Limits`] and returning the file count so the
/// short-circuit behavior is observable in tests.
fn scan_usage_with(
    package_names: &[String],
    roots: &[PathBuf],
    limits: Limits,
) -> (HashMap<String, Vec<PathBuf>>, usize) {
    // Pre-lower the names once; keep the original for the result key.
    let needles: Vec<(String, String)> = package_names
        .iter()
        .filter(|name| !name.trim().is_empty())
        .map(|name| (name.clone(), name.to_ascii_lowercase()))
        .collect();

    if needles.is_empty() {
        return (HashMap::new(), 0);
    }

    let mut walk = Walk {
        needles: &needles,
        limits,
        start: Instant::now(),
        hits: HashMap::new(),
        files_scanned: 0,
        bytes_read: 0,
    };

    for root in roots {
        if !root.exists() {
            continue;
        }
        walk.walk_root(root);
        if walk.exhausted() || walk.budget_spent() {
            break;
        }
    }

    let files_scanned = walk.files_scanned;
    let mut hits = walk.hits;
    for files in hits.values_mut() {
        files.sort();
        files.dedup();
    }
    (hits, files_scanned)
}

fn is_skipped_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| SKIP_DIRS.contains(&name))
}

/// Whether `path` is a manifest or source file worth grepping.
fn is_inspectable(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    let ext_lower = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase);

    if EXACT_MANIFESTS.contains(&lower.as_str()) {
        return true;
    }
    if lower.starts_with("requirements") && ext_lower.as_deref() == Some("txt") {
        return true;
    }
    if lower.starts_with("dockerfile") {
        return true;
    }

    match ext_lower.as_deref() {
        Some(ext) if SOURCE_EXTS.contains(&ext) => true,
        Some("yml" | "yaml") => under_github(path),
        _ => false,
    }
}

/// CI manifests count only under a `.github/` ancestor.
fn under_github(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|segment| segment == ".github")
    })
}

/// Whole-word name match, plus `-l<name>` and `pkg-config <name>` linker forms.
fn file_matches(content_lower: &str, name_lower: &str) -> bool {
    contains_word(content_lower, name_lower)
        || content_lower.contains(&format!("-l{name_lower}"))
        || content_lower.contains(&format!("pkg-config {name_lower}"))
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `true` when `needle` occurs in `hay` bounded by non-word characters, so
/// `go` does not match inside `google`.
fn contains_word(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    for (start, matched) in hay.match_indices(needle) {
        let end = start.saturating_add(matched.len());
        let before_ok = hay
            .get(..start)
            .and_then(|prefix| prefix.chars().next_back())
            .is_none_or(|c| !is_word_char(c));
        let after_ok = hay
            .get(end..)
            .and_then(|suffix| suffix.chars().next())
            .is_none_or(|c| !is_word_char(c));
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn word_boundaries() {
        assert!(contains_word("uses openssl here", "openssl"));
        assert!(!contains_word("install google sdk", "go"));
        assert!(contains_word("run go build", "go"));
    }

    #[test]
    fn linker_and_pkgconfig_forms() {
        assert!(file_matches("gcc -lz main.c", "z"));
        assert!(file_matches("pkg-config openssl --cflags", "openssl"));
    }

    #[test]
    fn scans_manifests_and_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        fs::write(root.join("Brewfile"), "brew \"openssl\"\n").expect("brewfile");
        fs::write(
            root.join("package.json"),
            "{\n  \"dependencies\": { \"typescript\": \"^5\" }\n}",
        )
        .expect("package.json");

        let sub = root.join("src");
        fs::create_dir_all(&sub).expect("mkdir");
        fs::write(sub.join("build.sh"), "gcc -lssl main.c\n").expect("script");

        // A skipped directory must be ignored.
        let nm = root.join("node_modules");
        fs::create_dir_all(&nm).expect("mkdir nm");
        fs::write(nm.join("package.json"), "{ \"name\": \"jq\" }").expect("nm pkg");

        let names = vec![
            "openssl".to_owned(),
            "jq".to_owned(),
            "typescript".to_owned(),
            "ssl".to_owned(),
            "missing-pkg".to_owned(),
        ];
        let hits = scan_usage(&names, &[root.to_path_buf()]);

        assert!(hits.contains_key("openssl"));
        assert!(hits.contains_key("typescript"));
        assert!(hits.contains_key("ssl"), "matches -lssl in build.sh");
        assert!(!hits.contains_key("missing-pkg"));

        // jq appears only inside node_modules (skipped) => no hit.
        assert!(!hits.contains_key("jq"));
    }

    #[test]
    fn file_cap_short_circuits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        // 40 inspectable files all referencing `openssl`.
        for i in 0..40 {
            fs::write(root.join(format!("build{i}.sh")), "link -lssl\n").expect("write");
        }
        let limits = Limits {
            max_files: 5,
            max_total_bytes: MAX_TOTAL_BYTES,
            budget: Duration::from_secs(8),
        };
        let (_, scanned) = scan_usage_with(&["ssl".to_owned()], &[root.to_path_buf()], limits);
        assert!(scanned <= 5, "scanned {scanned} files, expected <= 5");
    }

    #[test]
    fn zero_budget_short_circuits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        for i in 0..40 {
            fs::write(root.join(format!("build{i}.sh")), "link -lssl\n").expect("write");
        }
        let limits = Limits {
            max_files: MAX_FILES,
            max_total_bytes: MAX_TOTAL_BYTES,
            budget: Duration::ZERO,
        };
        let (hits, scanned) = scan_usage_with(&["ssl".to_owned()], &[root.to_path_buf()], limits);
        // An exhausted budget stops the walk before any file is inspected.
        assert_eq!(scanned, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn missing_root_is_silent() {
        let hits = scan_usage(&["foo".to_owned()], &[PathBuf::from("/no/such/path/xyzzy")]);
        assert!(hits.is_empty());
    }
}
