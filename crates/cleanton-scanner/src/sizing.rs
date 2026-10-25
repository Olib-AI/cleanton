//! Two-pass targeted project sizing.
//!
//! After a full scan has discovered candidate directories (e.g. `node_modules/`,
//! `target/`), the UI often needs an up-to-date size for *just those* subtrees without
//! paying for another full-tree walk. [`size_targets`] performs a focused aggregation over
//! the given candidate directories only. Sizing is hardlink-deduped by `(device, inode)`
//! across the whole candidate set — matching the full-walk semantics in
//! `walker::aggregate_directory_sizes` (a multiply-linked inode contributes its bytes
//! exactly once). Symlinks and directories are never counted, and symlinks are never
//! followed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Size aggregation for a single candidate target directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSize {
    /// The candidate directory that was sized.
    pub path: PathBuf,
    /// Sum of logical file sizes (`st_size`) newly counted under this target.
    pub logical_bytes: u64,
    /// Sum of allocated blocks in bytes (`st_blocks * 512`) newly counted under this target.
    pub allocated_bytes: u64,
    /// Number of regular files counted under this target (after hardlink de-duplication).
    pub file_count: u64,
    /// Number of paths under this target that could not be read (e.g. permission denied).
    pub unreadable: u64,
}

/// Aggregate result of sizing a set of candidate targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSizing {
    /// Per-target breakdown, in the order the targets were supplied.
    pub targets: Vec<TargetSize>,
    /// Total logical bytes across all targets (hardlink-deduped).
    pub total_logical_bytes: u64,
    /// Total allocated bytes across all targets (hardlink-deduped).
    pub total_allocated_bytes: u64,
    /// Total regular files counted across all targets.
    pub total_files: u64,
}

/// Computes sizes for `targets` without re-walking the entire tree.
///
/// Each target subtree is walked in parallel via `jwalk`. A multiply-linked inode is
/// counted once across the entire `targets` set (the first occurrence wins, mirroring the
/// full walk). Unreadable entries are tallied per target rather than aborting the sizing,
/// so a permission-denied subdirectory degrades gracefully.
#[must_use]
pub fn size_targets(targets: &[PathBuf]) -> TargetSizing {
    let mut seen_inodes = HashSet::<(u64, u64)>::new();
    let mut sized = Vec::with_capacity(targets.len());
    let mut total_logical_bytes = 0_u64;
    let mut total_allocated_bytes = 0_u64;
    let mut total_files = 0_u64;

    for target in targets {
        let size = size_one_target(target, &mut seen_inodes);
        total_logical_bytes = total_logical_bytes.saturating_add(size.logical_bytes);
        total_allocated_bytes = total_allocated_bytes.saturating_add(size.allocated_bytes);
        total_files = total_files.saturating_add(size.file_count);
        sized.push(size);
    }

    TargetSizing {
        targets: sized,
        total_logical_bytes,
        total_allocated_bytes,
        total_files,
    }
}

fn size_one_target(target: &Path, seen_inodes: &mut HashSet<(u64, u64)>) -> TargetSize {
    let mut logical_bytes = 0_u64;
    let mut allocated_bytes = 0_u64;
    let mut file_count = 0_u64;
    let mut unreadable = 0_u64;

    for item in jwalk::WalkDir::new(target)
        .follow_links(false)
        .parallelism(jwalk::Parallelism::RayonNewPool(4))
    {
        let Ok(entry) = item else {
            unreadable += 1;
            continue;
        };

        if !entry.file_type().is_file() {
            continue;
        }

        // jwalk already stats entries on its worker threads; a second
        // path-based `symlink_metadata` per file doubled the syscall count.
        let Ok(metadata) = entry.metadata() else {
            unreadable += 1;
            continue;
        };

        let stats = file_stats(&metadata);
        if let Some(key) = stats.inode_key
            && !seen_inodes.insert(key)
        {
            // Already counted this inode via another (hard) link; count zero bytes but
            // still record that the path exists as a file we examined.
            file_count += 1;
            continue;
        }

        logical_bytes = logical_bytes.saturating_add(stats.logical_bytes);
        allocated_bytes = allocated_bytes.saturating_add(stats.allocated_bytes);
        file_count += 1;
    }

    TargetSize {
        path: target.to_path_buf(),
        logical_bytes,
        allocated_bytes,
        file_count,
        unreadable,
    }
}

struct FileStats {
    logical_bytes: u64,
    allocated_bytes: u64,
    /// `Some((device, inode))` on Unix for hardlink de-duplication; `None` elsewhere.
    inode_key: Option<(u64, u64)>,
}

#[cfg(unix)]
fn file_stats(metadata: &std::fs::Metadata) -> FileStats {
    use std::os::unix::fs::MetadataExt;
    FileStats {
        logical_bytes: metadata.len(),
        allocated_bytes: metadata.blocks().saturating_mul(512),
        inode_key: Some((metadata.dev(), metadata.ino())),
    }
}

#[cfg(not(unix))]
fn file_stats(metadata: &std::fs::Metadata) -> FileStats {
    FileStats {
        logical_bytes: metadata.len(),
        allocated_bytes: metadata.len(),
        inode_key: None,
    }
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing into expected results clearer.
    #![allow(clippy::indexing_slicing)]
    use std::fs;

    use super::*;

    #[test]
    fn sizes_a_single_target_subtree() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target");
        fs::create_dir(&target).expect("create target");
        fs::write(target.join("a.bin"), [1_u8; 4096]).expect("write a");
        fs::write(target.join("b.bin"), [2_u8; 2048]).expect("write b");

        let sizing = size_targets(std::slice::from_ref(&target));
        assert_eq!(sizing.total_logical_bytes, 4096 + 2048);
        assert_eq!(sizing.total_files, 2);
        assert_eq!(sizing.targets.len(), 1);
        assert_eq!(sizing.targets[0].path, target);
        assert!(sizing.targets[0].allocated_bytes >= 4096 + 2048);
    }

    #[test]
    fn hardlinked_file_is_counted_once_across_targets() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir_a = temp.path().join("a");
        let dir_b = temp.path().join("b");
        fs::create_dir(&dir_a).expect("create a");
        fs::create_dir(&dir_b).expect("create b");

        let original = dir_a.join("artifact.bin");
        let linked = dir_b.join("artifact-link.bin");
        fs::write(&original, [7_u8; 8192]).expect("write original");
        fs::hard_link(&original, &linked).expect("hard link");

        let sizing = size_targets(&[dir_a.clone(), dir_b.clone()]);
        // Logical bytes counted exactly once despite two links.
        assert_eq!(sizing.total_logical_bytes, 8192);
        // Both paths are still observed as files.
        assert_eq!(sizing.total_files, 2);
    }

    #[test]
    fn empty_target_set_is_zero() {
        let sizing = size_targets(&[]);
        assert_eq!(sizing.total_logical_bytes, 0);
        assert_eq!(sizing.total_allocated_bytes, 0);
        assert_eq!(sizing.total_files, 0);
        assert!(sizing.targets.is_empty());
    }
}
