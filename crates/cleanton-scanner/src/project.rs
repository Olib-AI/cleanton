use std::collections::HashMap;
use std::path::{Path, PathBuf};

use cleanton_common::{Ecosystem, FileEntry, FileKind, ProjectRoot, paths::is_same_or_descendant};

#[must_use]
pub fn detect_project_roots(paths: impl IntoIterator<Item = PathBuf>) -> Vec<ProjectRoot> {
    paths
        .into_iter()
        .filter_map(|path| marker_for(&path).map(|ecosystem| (path, ecosystem)))
        .map(|(marker, ecosystem)| {
            let root = marker
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .to_path_buf();
            let artifact_dirs = artifact_dirs(ecosystem, &root);

            ProjectRoot {
                path: root,
                ecosystem,
                artifact_dirs,
                total_size: 0,
                artifact_size: 0,
            }
        })
        .collect()
}

#[must_use]
pub fn detect_project_roots_from_entries(entries: &[FileEntry]) -> Vec<ProjectRoot> {
    // Index only DIRECTORY entries, and borrow their paths instead of cloning
    // them. The previous index cloned the path of *every* scanned entry into a
    // `HashMap<PathBuf, _>` — millions of `PathBuf` allocations and an extra
    // copy of the whole scan's path data on the analysis hot path — while every
    // lookup below is a directory lookup. Directory entries are a small fraction
    // of a scan, and none of them need a clone.
    let dirs_by_path = entries
        .iter()
        .filter(|entry| entry.kind == FileKind::Directory)
        .map(|entry| (entry.path.as_path(), entry))
        .collect::<HashMap<_, _>>();

    entries
        .iter()
        .filter_map(|entry| marker_for(&entry.path).map(|ecosystem| (&entry.path, ecosystem)))
        .map(|(marker, ecosystem)| {
            let root = marker
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .to_path_buf();
            let artifact_dirs = artifact_dirs(ecosystem, &root)
                .into_iter()
                .filter(|artifact| {
                    dirs_by_path
                        .get(artifact.as_path())
                        .is_some_and(|entry| entry.kind == FileKind::Directory)
                })
                .collect::<Vec<_>>();
            let total_size = scan_entry_size(&root, entries, &dirs_by_path);
            let artifact_size = artifact_dirs
                .iter()
                .map(|artifact| scan_entry_size(artifact, entries, &dirs_by_path))
                .sum();

            ProjectRoot {
                path: root,
                ecosystem,
                artifact_dirs,
                total_size,
                artifact_size,
            }
        })
        .collect()
}

fn scan_entry_size(
    path: &Path,
    entries: &[FileEntry],
    dirs_by_path: &HashMap<&Path, &FileEntry>,
) -> u64 {
    dirs_by_path.get(path).map_or_else(
        || {
            // The directory itself was not part of the scan (pruned, or beyond
            // `max_depth`): fall back to the descendant files we did see. This
            // is the rare path — in a real scan the directory is nearly always
            // present — so the linear scan stays off the hot path.
            entries
                .iter()
                .filter(|entry| {
                    entry.kind == FileKind::File && is_same_or_descendant(&entry.path, path)
                })
                .map(|entry| entry.logical_bytes)
                .sum()
        },
        |entry| entry.logical_bytes,
    )
}

fn marker_for(path: &Path) -> Option<Ecosystem> {
    let name = path.file_name()?.to_string_lossy();
    match name.as_ref() {
        "Cargo.toml" => Some(Ecosystem::Rust),
        "Package.swift" => Some(Ecosystem::Swift),
        "package.json" => Some(Ecosystem::Node),
        "pyproject.toml" | "setup.py" => Some(Ecosystem::Python),
        "go.mod" => Some(Ecosystem::Go),
        "Dockerfile" | "docker-compose.yml" => Some(Ecosystem::Docker),
        ".git" => Some(Ecosystem::Git),
        _ if name.ends_with(".xcodeproj") || name.ends_with(".xcworkspace") => {
            Some(Ecosystem::Xcode)
        }
        _ => None,
    }
}

fn artifact_dirs(ecosystem: Ecosystem, root: &Path) -> Vec<PathBuf> {
    match ecosystem {
        Ecosystem::Rust => vec![root.join("target")],
        Ecosystem::Node => vec![
            root.join("node_modules"),
            root.join(".next"),
            root.join("dist"),
        ],
        Ecosystem::Python => vec![
            root.join("__pycache__"),
            root.join(".venv"),
            root.join(".tox"),
        ],
        Ecosystem::Swift | Ecosystem::Xcode => vec![root.join(".build")],
        Ecosystem::Go => vec![root.join("bin")],
        Ecosystem::Docker | Ecosystem::Git => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing into expected results
    // (e.g. `detected[0]`) clearer than `.get(0).unwrap()`.
    #![allow(clippy::indexing_slicing)]
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn detects_project_roots_from_marker_paths() {
        let project_root = PathBuf::from("/workspace/rust_project");
        let paths = vec![project_root.join("Cargo.toml")];
        let detected = detect_project_roots(paths);

        assert_eq!(detected.len(), 1);
        let proj = &detected[0];
        assert_eq!(proj.path, project_root);
        assert_eq!(proj.ecosystem, Ecosystem::Rust);
        assert_eq!(
            proj.artifact_dirs,
            vec![PathBuf::from("/workspace/rust_project/target")]
        );
        assert_eq!(proj.total_size, 0);
        assert_eq!(proj.artifact_size, 0);
    }

    #[test]
    fn detects_project_sizes_from_scan_entries() {
        let project_root = PathBuf::from("/workspace/rust_project");
        let target = project_root.join("target");
        let entries = vec![
            entry(project_root.clone(), FileKind::Directory, 140),
            entry(project_root.join("Cargo.toml"), FileKind::File, 20),
            entry(project_root.join("src"), FileKind::Directory, 20),
            entry(project_root.join("src/main.rs"), FileKind::File, 20),
            entry(target.clone(), FileKind::Directory, 100),
            entry(target.join("test.bin"), FileKind::File, 100),
        ];

        let detected = detect_project_roots_from_entries(&entries);

        assert_eq!(detected.len(), 1);
        let proj = &detected[0];
        assert_eq!(proj.path, project_root);
        assert_eq!(proj.ecosystem, Ecosystem::Rust);
        assert_eq!(proj.artifact_dirs, vec![target]);
        assert_eq!(proj.total_size, 140);
        assert_eq!(proj.artifact_size, 100);
    }

    #[test]
    fn project_sizes_fallback_to_scanned_descendant_files_without_root_entry() {
        let project_root = PathBuf::from("/workspace/rust_project");
        let target = project_root.join("target");
        let entries = vec![
            entry(project_root.join("Cargo.toml"), FileKind::File, 20),
            entry(target.join("test.bin"), FileKind::File, 100),
        ];

        let detected = detect_project_roots_from_entries(&entries);

        assert_eq!(detected.len(), 1);
        let proj = &detected[0];
        assert!(proj.artifact_dirs.is_empty());
        assert_eq!(proj.total_size, 120);
        assert_eq!(proj.artifact_size, 0);
    }

    fn entry(path: PathBuf, kind: FileKind, logical_bytes: u64) -> FileEntry {
        FileEntry {
            path,
            kind,
            logical_bytes,
            allocated_bytes: logical_bytes,
            modified: Some(SystemTime::UNIX_EPOCH),
            depth: 0,
            device_id: None,
            inode: None,
            hardlink_count: None,
            symlink_target: None,
            ignored_by_git: false,
        }
    }
}
