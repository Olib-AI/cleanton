use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use cleanton_common::{Ecosystem, FileEntry, FileKind, ProjectRoot, paths::is_same_or_descendant};

/// Dependency, cache, and build-output directory components whose internal
/// manifest files (`node_modules/lodash/package.json`, `.cargo/registry/src/.../Cargo.toml`,
/// `.venv/lib/.../pyproject.toml`) are vendored dependencies rather than user projects.
const DEPENDENCY_SUBTREE_COMPONENTS: &[&str] = &[
    "node_modules",
    ".venv",
    "venv",
    "site-packages",
    ".tox",
    ".nox",
    ".cargo",
    ".rustup",
    ".gradle",
    ".m2",
    ".pub-cache",
    ".nuget",
    ".cabal",
    ".stack",
    ".stack-work",
    "dist-newstyle",
    "_build",
    "Pods",
    "DerivedData",
    ".cache",
    "Caches",
];

#[must_use]
pub fn detect_project_roots(paths: impl IntoIterator<Item = PathBuf>) -> Vec<ProjectRoot> {
    let mut seen = HashSet::new();
    paths
        .into_iter()
        .filter(|path| !is_inside_dependency_subtree(path))
        .filter_map(|path| marker_for(&path).map(|ecosystem| (path, ecosystem)))
        .filter_map(|(marker, ecosystem)| {
            let root = marker
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .to_path_buf();
            if !seen.insert((root.clone(), ecosystem)) {
                return None;
            }
            let artifact_dirs = artifact_dirs(ecosystem, &root);

            Some(ProjectRoot {
                path: root,
                ecosystem,
                artifact_dirs,
                total_size: 0,
                artifact_size: 0,
            })
        })
        .collect()
}

#[must_use]
pub fn detect_project_roots_from_entries(entries: &[FileEntry]) -> Vec<ProjectRoot> {
    let dirs_by_path = entries
        .iter()
        .filter(|entry| entry.kind == FileKind::Directory)
        .map(|entry| (entry.path.as_path(), entry))
        .collect::<HashMap<_, _>>();

    let mut seen = HashSet::new();
    entries
        .iter()
        .filter(|entry| !is_inside_dependency_subtree(&entry.path))
        .filter_map(|entry| marker_for(&entry.path).map(|ecosystem| (&entry.path, ecosystem)))
        .filter_map(|(marker, ecosystem)| {
            let root = marker
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .to_path_buf();
            if !seen.insert((root.clone(), ecosystem)) {
                return None;
            }
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

            Some(ProjectRoot {
                path: root,
                ecosystem,
                artifact_dirs,
                total_size,
                artifact_size,
            })
        })
        .collect()
}

fn is_inside_dependency_subtree(marker_path: &Path) -> bool {
    let Some(parent) = marker_path.parent() else {
        return false;
    };
    parent.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| DEPENDENCY_SUBTREE_COMPONENTS.contains(&name))
    })
}

fn scan_entry_size(
    path: &Path,
    entries: &[FileEntry],
    dirs_by_path: &HashMap<&Path, &FileEntry>,
) -> u64 {
    dirs_by_path.get(path).map_or_else(
        || {
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
        "pyproject.toml" | "setup.py" | "setup.cfg" => Some(Ecosystem::Python),
        "go.mod" => Some(Ecosystem::Go),
        "pom.xml"
        | "build.gradle"
        | "build.gradle.kts"
        | "build.sbt"
        | "deps.edn"
        | "project.clj" => Some(Ecosystem::Jvm),
        "CMakeLists.txt" | "meson.build" => Some(Ecosystem::CCpp),
        "pubspec.yaml" => Some(Ecosystem::Dart),
        "mix.exs" => Some(Ecosystem::Elixir),
        "stack.yaml" | "cabal.project" => Some(Ecosystem::Haskell),
        "build.zig" => Some(Ecosystem::Zig),
        "composer.json" => Some(Ecosystem::Php),
        "Gemfile" => Some(Ecosystem::Ruby),
        "Dockerfile" | "docker-compose.yml" | "compose.yml" | "compose.yaml" => {
            Some(Ecosystem::Docker)
        }
        ".git" => Some(Ecosystem::Git),
        _ if name.ends_with(".xcodeproj") || name.ends_with(".xcworkspace") => {
            Some(Ecosystem::Xcode)
        }
        _ if name.ends_with(".csproj")
            || name.ends_with(".fsproj")
            || name.ends_with(".sln")
            || name.ends_with(".slnx") =>
        {
            Some(Ecosystem::Dotnet)
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
            root.join(".nuxt"),
            root.join(".svelte-kit"),
            root.join(".astro"),
            root.join(".angular"),
            root.join(".turbo"),
            root.join(".parcel-cache"),
            root.join("dist"),
        ],
        Ecosystem::Python => vec![
            root.join("__pycache__"),
            root.join(".venv"),
            root.join("venv"),
            root.join(".tox"),
            root.join(".nox"),
            root.join(".pytest_cache"),
            root.join(".mypy_cache"),
            root.join(".ruff_cache"),
        ],
        Ecosystem::Swift | Ecosystem::Xcode => vec![root.join(".build"), root.join("DerivedData")],
        Ecosystem::Go => vec![root.join("bin")],
        Ecosystem::Jvm => vec![
            root.join("target"),
            root.join("build"),
            root.join(".gradle"),
            root.join(".bloop"),
            root.join(".cpcache"),
        ],
        Ecosystem::CCpp => vec![
            root.join("build"),
            root.join("cmake-build-debug"),
            root.join("cmake-build-release"),
            root.join("_build"),
        ],
        Ecosystem::Dotnet => vec![root.join("bin"), root.join("obj")],
        Ecosystem::Dart => vec![root.join("build"), root.join(".dart_tool")],
        Ecosystem::Elixir => vec![root.join("_build"), root.join("deps")],
        Ecosystem::Haskell => vec![root.join(".stack-work"), root.join("dist-newstyle")],
        Ecosystem::Zig => vec![root.join(".zig-cache"), root.join("zig-out")],
        Ecosystem::Php => vec![root.join("vendor"), root.join(".phpunit.cache")],
        Ecosystem::Ruby => vec![root.join("vendor")],
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

    #[test]
    fn skips_dependency_subtrees_and_detects_additional_ecosystems() {
        let paths = vec![
            PathBuf::from("/workspace/web/package.json"),
            PathBuf::from("/workspace/web/node_modules/lodash/package.json"),
            PathBuf::from("/Users/dev/.cargo/registry/src/index/serde-1.0/Cargo.toml"),
            PathBuf::from("/workspace/api/App.csproj"),
            PathBuf::from("/workspace/java/pom.xml"),
            PathBuf::from("/workspace/cpp/CMakeLists.txt"),
            PathBuf::from("/workspace/mobile/pubspec.yaml"),
        ];
        let detected = detect_project_roots(paths);
        assert_eq!(detected.len(), 5);
        assert!(detected.iter().any(|p| p.ecosystem == Ecosystem::Node && p.path == Path::new("/workspace/web")));
        assert!(detected.iter().any(|p| p.ecosystem == Ecosystem::Dotnet && p.path == Path::new("/workspace/api")));
        assert!(detected.iter().any(|p| p.ecosystem == Ecosystem::Jvm && p.path == Path::new("/workspace/java")));
        assert!(detected.iter().any(|p| p.ecosystem == Ecosystem::CCpp && p.path == Path::new("/workspace/cpp")));
        assert!(detected.iter().any(|p| p.ecosystem == Ecosystem::Dart && p.path == Path::new("/workspace/mobile")));
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
