//! Cross-checks that the focused [`size_targets`] aggregation agrees with the full-tree
//! walk in [`scan`] over the same candidate subtree, including hardlink de-duplication.

use std::fs;

use cleanton_scanner::{ScanOptions, scan, size_targets};
use tokio::sync::mpsc;

#[tokio::test]
async fn targeted_sizing_matches_full_walk_with_hardlink() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    fs::write(root.join("Cargo.toml"), "[package]\nname=\"fixture\"").expect("cargo.toml");

    let target = root.join("target");
    let deps = target.join("deps");
    fs::create_dir_all(&deps).expect("create target/deps");

    // A regular file plus a hardlinked pair inside the same target subtree.
    fs::write(deps.join("lib.rlib"), [1_u8; 4096]).expect("write rlib");
    let original = target.join("original.bin");
    let hardlink = target.join("copy.bin");
    fs::write(&original, [7_u8; 8192]).expect("write original");
    fs::hard_link(&original, &hardlink).expect("hard link");

    // Full walk.
    let (tx, _rx) = mpsc::channel(8);
    let result = scan(
        ScanOptions {
            roots: vec![root.to_path_buf()],
            max_depth: 10,
            ..ScanOptions::default()
        },
        tx,
    )
    .await
    .expect("scan");

    let target_entry = result
        .entries
        .iter()
        .find(|entry| entry.path == target)
        .expect("target directory entry");

    // Focused sizing over just the candidate directory.
    let sizing = size_targets(std::slice::from_ref(&target));

    // The hardlinked 8192-byte inode is counted once: 4096 + 8192 = 12288.
    assert_eq!(sizing.total_logical_bytes, 12_288);
    assert_eq!(
        sizing.total_logical_bytes, target_entry.logical_bytes,
        "targeted logical sizing must match the full-walk directory aggregate"
    );
    assert_eq!(
        sizing.total_allocated_bytes, target_entry.allocated_bytes,
        "targeted allocated sizing must match the full-walk directory aggregate"
    );

    // Three file paths exist (lib.rlib, original.bin, copy.bin) even though only two
    // distinct inodes contribute bytes.
    assert_eq!(sizing.total_files, 3);
}
