//! Safety release-gate corpus: hardlink de-duplication in sizing (PLATFORM §9).
//!
//! Two hardlinks to a single inode must contribute their bytes exactly once in
//! BOTH the full tree walk ([`scan`]) and the focused [`size_targets`]
//! aggregation, and the two must agree. Overcounting hardlinks would make
//! cleanton overpromise reclaimable space.

use std::fs;

use cleanton_common::FileKind;
use cleanton_scanner::{ScanOptions, scan, size_targets};
use tokio::sync::mpsc;

#[tokio::test]
async fn hardlinked_inode_counted_once_in_full_walk_and_targeted_sizing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();

    // Two separate candidate directories, each holding one link to the SAME inode,
    // plus one unique file per directory.
    let dir_a = root.join("a");
    let dir_b = root.join("b");
    fs::create_dir(&dir_a).expect("create a");
    fs::create_dir(&dir_b).expect("create b");

    let original = dir_a.join("artifact.bin");
    let hardlink = dir_b.join("artifact-link.bin");
    fs::write(&original, [9_u8; 8192]).expect("write original");
    fs::hard_link(&original, &hardlink).expect("create hardlink");

    let unique_a = dir_a.join("unique-a.bin");
    let unique_b = dir_b.join("unique-b.bin");
    fs::write(&unique_a, [1_u8; 1024]).expect("write unique a");
    fs::write(&unique_b, [2_u8; 2048]).expect("write unique b");

    // Distinct inodes: the shared 8192 inode (counted once) + 1024 + 2048.
    let expected_deduped_logical = 8192 + 1024 + 2048;

    // 1. Full walk over the whole tree.
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

    assert_eq!(
        result.logical_bytes, expected_deduped_logical,
        "full-walk total must count the shared inode exactly once"
    );

    // Exactly one of the two hardlinked paths retains its bytes; the other is zeroed.
    let linked: Vec<_> = result
        .entries
        .iter()
        .filter(|entry| entry.path == original || entry.path == hardlink)
        .collect();
    assert_eq!(linked.len(), 2, "both link paths are recorded as entries");
    assert_eq!(
        linked
            .iter()
            .filter(|entry| entry.kind == FileKind::File && entry.allocated_bytes > 0)
            .count(),
        1,
        "only one of the two hardlinks contributes bytes after de-duplication"
    );

    // 2. Focused sizing over BOTH candidate dirs (the cross-target dedup path).
    let sizing = size_targets(&[dir_a.clone(), dir_b.clone()]);
    assert_eq!(
        sizing.total_logical_bytes, expected_deduped_logical,
        "size_targets must also count the shared inode once across targets"
    );
    // Three file paths are still observed even though only the unique inodes pay bytes.
    assert_eq!(sizing.total_files, 4, "all four file paths are examined");

    // 3. The two independent code paths must agree.
    assert_eq!(
        sizing.total_logical_bytes, result.logical_bytes,
        "targeted sizing and the full walk must agree on the deduped total"
    );
}
