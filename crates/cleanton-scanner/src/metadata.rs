use std::{fs::Metadata, path::Path};

use cleanton_common::{FileEntry, FileKind};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub(crate) fn entry_from_metadata(path: &Path, metadata: &Metadata, depth: usize) -> FileEntry {
    let file_type = metadata.file_type();
    let kind = if file_type.is_dir() {
        FileKind::Directory
    } else if file_type.is_file() {
        FileKind::File
    } else if file_type.is_symlink() {
        FileKind::Symlink
    } else {
        FileKind::Other
    };

    #[cfg(unix)]
    let device_id = Some(metadata.dev());
    #[cfg(not(unix))]
    let device_id = None;

    #[cfg(unix)]
    let inode = Some(metadata.ino());
    #[cfg(not(unix))]
    let inode = None;

    #[cfg(unix)]
    let hardlink_count = Some(metadata.nlink());
    #[cfg(not(unix))]
    let hardlink_count = None;

    FileEntry {
        path: path.to_path_buf(),
        kind,
        logical_bytes: metadata.len(),
        allocated_bytes: allocated_bytes(metadata),
        modified: metadata.modified().ok(),
        depth,
        device_id,
        inode,
        hardlink_count,
        symlink_target: if kind == FileKind::Symlink {
            std::fs::read_link(path).ok()
        } else {
            None
        },
        ignored_by_git: false,
    }
}

#[cfg(unix)]
fn allocated_bytes(metadata: &Metadata) -> u64 {
    metadata.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn allocated_bytes(metadata: &Metadata) -> u64 {
    metadata.len()
}
