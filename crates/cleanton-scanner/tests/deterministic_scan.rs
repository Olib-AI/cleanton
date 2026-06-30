//! Safety release-gate corpus: deterministic fixture scans + `.gitignore`-as-signal.
//!
//! These integration tests build a fully known directory tree in a tempdir and
//! assert the public [`scan`] API reports exact, reproducible totals across two
//! runs, and that a `.gitignore`d directory is still *traversed and recorded*
//! (flagged `ignored_by_git`), never silently dropped (PLATFORM §8 / SAFETY).

// Integration-test crate: setup helpers (outside `#[test]` fns, so not covered by
// clippy.toml's `allow-expect-in-tests`) use `.expect()` on fixture I/O.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cleanton_common::{FileKind, ScanResult};
use cleanton_scanner::{ScanOptions, scan};
use tokio::sync::mpsc;

/// One regular (non-hidden) file in the fixture: a relative path and its exact bytes.
///
/// NOTE: the hidden `.gitignore` written by `build_fixture` is now ALSO scanned and
/// counted (the scanner traverses hidden entries by default). It is accounted for
/// separately in the expected totals below so this list stays the non-hidden set.
const FIXTURE_FILES: &[(&str, &[u8])] = &[
    ("top.txt", b"hello-cleanton"),
    ("src/main.rs", b"fn main() {}\n"),
    ("ignored_dir/blob.bin", &[0_u8; 4096]),
    ("ignored_dir/sub/trace.log", &[7_u8; 64]),
    ("data/deep/leaf.dat", b"1234567"),
];

/// Directories explicitly created in the fixture (the scan root is counted separately).
const FIXTURE_DIRS: &[&str] = &["src", "ignored_dir", "ignored_dir/sub", "data", "data/deep"];

/// `.gitignore` contents — written for its rules (read directly by the walker) and
/// now ALSO counted as a scanned hidden file (it is a regular file, not flagged by
/// its own rules), so its bytes are part of the expected totals.
const GITIGNORE_BODY: &[u8] = b"ignored_dir/\n*.log\n";

fn build_fixture(root: &Path) -> (u64, u64) {
    for dir in FIXTURE_DIRS {
        fs::create_dir_all(root.join(dir)).expect("create fixture dir");
    }
    fs::write(root.join(".gitignore"), GITIGNORE_BODY).expect("write .gitignore");

    // The hidden `.gitignore` is now traversed and counted like any other file.
    let mut expected_files = 1_u64;
    let mut expected_logical = GITIGNORE_BODY.len() as u64;
    for (rel, bytes) in FIXTURE_FILES {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(&path, bytes).expect("write fixture file");
        expected_logical += bytes.len() as u64;
    }
    expected_files += FIXTURE_FILES.len() as u64;
    (expected_files, expected_logical)
}

async fn scan_fixture(root: &Path) -> ScanResult {
    let (progress_tx, _progress_rx) = mpsc::channel(16);
    scan(
        ScanOptions {
            roots: vec![root.to_path_buf()],
            max_depth: 20,
            ..ScanOptions::default()
        },
        progress_tx,
    )
    .await
    .expect("scan succeeds")
}

fn sorted_paths(result: &ScanResult) -> Vec<PathBuf> {
    let mut paths = result
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

#[tokio::test]
async fn scan_totals_are_exact_and_reproducible() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    let (expected_files, expected_logical) = build_fixture(root);

    let first = scan_fixture(root).await;
    let second = scan_fixture(root).await;

    // Exact, hand-computed totals.
    assert_eq!(
        first.total_files, expected_files,
        "regular-file count must be exact"
    );
    assert_eq!(
        first.logical_bytes, expected_logical,
        "logical byte total is the exact sum of file contents"
    );
    // The scan root plus every created subdirectory are recorded as directories.
    assert_eq!(
        first.total_dirs,
        FIXTURE_DIRS.len() as u64 + 1,
        "directory count must include the scan root"
    );
    assert!(!first.incomplete, "a fully readable tree is complete");
    assert!(first.errors.is_empty(), "no scan errors expected");

    // Reproducible: a second run over the unchanged tree is byte-for-byte identical.
    assert_eq!(first.total_files, second.total_files);
    assert_eq!(first.total_dirs, second.total_dirs);
    assert_eq!(first.logical_bytes, second.logical_bytes);
    assert_eq!(
        first.allocated_bytes, second.allocated_bytes,
        "allocated bytes are deterministic on a stable filesystem"
    );
    assert_eq!(
        sorted_paths(&first),
        sorted_paths(&second),
        "the recorded path set is identical across runs"
    );
}

#[tokio::test]
async fn gitignored_directory_is_traversed_and_recorded_not_skipped() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    build_fixture(root);

    let result = scan_fixture(root).await;

    let by_name = |needle: &str| {
        result
            .entries
            .iter()
            .find(|entry| entry.path.ends_with(needle))
            .unwrap_or_else(|| panic!("entry {needle} must be recorded, not skipped"))
    };

    // The `.gitignore`d directory itself is entered and recorded.
    let ignored_dir = by_name("ignored_dir");
    assert_eq!(ignored_dir.kind, FileKind::Directory);
    assert!(
        ignored_dir.ignored_by_git,
        "the ignored directory must be flagged as a signal, not dropped"
    );

    // Its descendants — including a nested subdirectory and files — are traversed.
    let ignored_blob = by_name("ignored_dir/blob.bin");
    assert!(
        ignored_blob.ignored_by_git,
        "child of ignored dir is flagged"
    );
    assert_eq!(ignored_blob.logical_bytes, 4096);

    let nested_log = by_name("ignored_dir/sub/trace.log");
    assert!(
        nested_log.ignored_by_git,
        "deeply nested entry under an ignored dir is still traversed and flagged"
    );

    // The whole ignored subtree is present despite being git-ignored.
    let ignored_subtree: BTreeSet<&Path> = result
        .entries
        .iter()
        .map(|entry| entry.path.as_path())
        .filter(|path| path.starts_with(root.join("ignored_dir")))
        .collect();
    assert!(
        ignored_subtree.contains(root.join("ignored_dir/sub").as_path()),
        "the ignored nested directory must appear in the scan"
    );

    // A non-ignored sibling is recorded and NOT flagged.
    let kept = by_name("src/main.rs");
    assert!(!kept.ignored_by_git, "non-ignored file must not be flagged");
}
