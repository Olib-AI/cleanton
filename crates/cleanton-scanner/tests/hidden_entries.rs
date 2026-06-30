//! Regression tests for a REAL SCANNER BUG (now fixed): the walker used to
//! silently omit ALL hidden (dot-prefixed) files and directories.
//!
//! ROOT CAUSE (fixed): `walker::scan_root` built `jwalk::WalkDirGeneric` without
//! calling `.skip_hidden(false)`, and jwalk's `skip_hidden` defaults to `true`.
//! The walker now calls `.skip_hidden(!options.include_hidden)`, and the new
//! `ScanOptions::include_hidden` field defaults to `true`, so hidden entries are
//! traversed and emitted by default.
//!
//! SAFETY / FUNCTIONAL IMPACT of the fix:
//!   * ~34 of the ~70 built-in recipes target hidden locations — `.venv`,
//!     `~/.cargo/registry`, `~/.cache`, `~/.gradle`, `~/.npm`, `~/.ollama`,
//!     `~/.rustup`, `~/.cocoapods`, AI-tool caches, etc. They can now match.
//!   * `cleanton_engine::ml::build_contexts` derives `has_gitignore` by looking
//!     for a `.gitignore` basename among scan entries; `.gitignore` is hidden and
//!     is now emitted, so that ML feature can finally be `true`.

// Integration-test crate: setup helpers (outside `#[test]` fns, so not covered by
// clippy.toml's `allow-expect-in-tests`) use `.expect()` on fixture I/O.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::Path;

use cleanton_scanner::{ScanOptions, scan};
use tokio::sync::mpsc;

async fn scan_root(root: &Path) -> cleanton_common::ScanResult {
    let (tx, _rx) = mpsc::channel(16);
    scan(
        ScanOptions {
            roots: vec![root.to_path_buf()],
            max_depth: 20,
            ..ScanOptions::default()
        },
        tx,
    )
    .await
    .expect("scan")
}

fn build_mixed_tree(root: &Path) {
    // A visible cache file and a hidden cache directory holding a large blob — the
    // shape of a real `.cache` / `.venv` cleanup target.
    fs::write(root.join("visible.bin"), [1_u8; 2048]).expect("write visible");

    let hidden_dir = root.join(".cache");
    fs::create_dir(&hidden_dir).expect("create .cache");
    fs::write(hidden_dir.join("blob.bin"), [2_u8; 4096]).expect("write hidden blob");

    fs::write(root.join(".env"), b"SECRET=1").expect("write .env");
}

/// Visible AND hidden entries are now recorded by default.
#[tokio::test]
async fn hidden_entries_are_scanned_by_default() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    build_mixed_tree(root);

    let result = scan_root(root).await;

    let has = |needle: &str| {
        result
            .entries
            .iter()
            .any(|entry| entry.path.ends_with(needle))
    };

    // The visible file IS recorded.
    assert!(has("visible.bin"), "visible file must be scanned");

    // Hidden entries are now recorded (the previously documented bug is fixed).
    assert!(has(".cache"), "the hidden .cache directory must be scanned");
    assert!(
        has(".cache/blob.bin"),
        "contents of a hidden cache dir must be discovered"
    );
    assert!(has(".env"), "hidden files must be scanned");
}

/// A hidden cache directory and its contents MUST be discoverable AND sized so the
/// many hidden-path recipes (e.g. python-venvs `.venv`, rust `~/.cargo`) can run.
#[tokio::test]
async fn desired_behavior_hidden_cache_dirs_must_be_discoverable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    build_mixed_tree(root);

    let result = scan_root(root).await;

    assert!(
        result
            .entries
            .iter()
            .any(|entry| entry.path.ends_with(".cache")),
        "hidden cache directory must be scanned so its recipe can match"
    );
    assert!(
        result
            .entries
            .iter()
            .any(|entry| entry.path.ends_with(".cache/blob.bin") && entry.logical_bytes == 4096),
        "contents of a hidden cache dir must be sized so the cleaner can reclaim them"
    );
}

/// The toggle still works: setting `include_hidden = false` restores the old
/// behavior of pruning dot-prefixed entries (UI "hide hidden files" path).
#[tokio::test]
async fn include_hidden_false_prunes_dot_entries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    build_mixed_tree(root);

    let (tx, _rx) = mpsc::channel(16);
    let result = scan(
        ScanOptions {
            roots: vec![root.to_path_buf()],
            max_depth: 20,
            include_hidden: false,
            ..ScanOptions::default()
        },
        tx,
    )
    .await
    .expect("scan");

    let has = |needle: &str| {
        result
            .entries
            .iter()
            .any(|entry| entry.path.ends_with(needle))
    };

    assert!(has("visible.bin"), "visible file is still scanned");
    assert!(
        !has(".cache"),
        "hidden dir is pruned when include_hidden=false"
    );
    assert!(
        !has(".env"),
        "hidden file is pruned when include_hidden=false"
    );
}
