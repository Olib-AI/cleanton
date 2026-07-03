use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{ActionType, CleantonError, Result, SafetyLevel};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CleantonConfig {
    pub general: GeneralConfig,
    pub scanning: ScanningConfig,
    pub safety: SafetyConfig,
    pub ml: MlConfig,
    pub ui: UiConfig,
}

impl CleantonConfig {
    #[must_use]
    pub fn config_dir() -> Option<PathBuf> {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config").join("cleanton"))
    }

    #[must_use]
    pub fn config_path() -> Option<PathBuf> {
        Self::config_dir().map(|dir| dir.join("config.toml"))
    }

    pub fn load() -> Result<Self> {
        let Some(path) = Self::config_path() else {
            return Ok(Self::default());
        };
        Self::load_from_path(&path)
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(source) => toml::from_str(&source)
                .map_err(|err| CleantonError::Config(format!("{}: {err}", path.display()))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(CleantonError::io(path, source)),
        }
    }

    /// Persist this configuration to the standard config path
    /// (`$HOME/.config/cleanton/config.toml`).
    ///
    /// Returns a clear error when the path cannot be determined (e.g. `HOME`
    /// is unset) rather than panicking. The write itself is atomic — see
    /// [`save_to_path`](Self::save_to_path).
    pub fn save(&self) -> Result<()> {
        let Some(path) = Self::config_path() else {
            return Err(CleantonError::Config(
                "cannot determine config path: HOME is not set".to_owned(),
            ));
        };
        self.save_to_path(&path)
    }

    /// Serialize this configuration to TOML and write it to `path` atomically.
    ///
    /// The parent directory is created when missing. The file is written to a
    /// process-unique temporary sibling and then renamed into place, so a
    /// concurrent reader never observes a partially written file.
    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let serialized = toml::to_string_pretty(self)
            .map_err(|err| CleantonError::Config(format!("failed to serialize config: {err}")))?;

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| CleantonError::io(parent, source))?;
        }

        // Atomic publish: write a process-unique sibling, then rename into place.
        // A failed rename (rare on the same filesystem) leaves the harmless temp
        // file behind rather than deleting through a non-executor path.
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        fs::write(&tmp, serialized.as_bytes()).map_err(|source| CleantonError::io(&tmp, source))?;
        fs::rename(&tmp, path).map_err(|source| CleantonError::io(path, source))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub default_root: PathBuf,
    pub auto_scan_on_launch: bool,
    pub theme: String,
    pub animation_speed: String,
    pub log_retention_days: u32,
    pub log_retention_count: usize,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            default_root: PathBuf::from("~"),
            // Off by default: auto-scanning the entire home directory on every
            // launch is expensive (walks all caches/hidden dirs) and makes the
            // UI look stuck. The user starts a scan explicitly instead.
            auto_scan_on_launch: false,
            theme: "dark".to_owned(),
            animation_speed: "normal".to_owned(),
            log_retention_days: 30,
            log_retention_count: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanningConfig {
    pub max_depth: usize,
    pub follow_symlinks: bool,
    pub respect_gitignore: bool,
    pub parallel_threads: usize,
    pub exclude_patterns: Vec<String>,
    pub exclude_cloud_roots: bool,
    pub exclude_external_volumes: bool,
}

impl Default for ScanningConfig {
    fn default() -> Self {
        Self {
            // Depth 10 from the home root reaches essentially every cleanable
            // cache / build directory (`node_modules`, `target`, `~/Library/
            // Caches/*`, `.venv`, ...) while keeping a full-home scan from
            // exploding into millions of entries held in memory. The whole
            // cleanable directory is matched and size-aggregated from what we
            // walk; users who want exhaustive depth can raise this.
            max_depth: 10,
            follow_symlinks: false,
            respect_gitignore: true,
            parallel_threads: 0,
            exclude_patterns: vec![
                ".Trash".to_owned(),
                ".Spotlight-*".to_owned(),
                ".fseventsd".to_owned(),
            ],
            exclude_cloud_roots: true,
            exclude_external_volumes: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SafetyConfig {
    pub default_action: ActionType,
    pub max_single_run_gb: u64,
    pub max_single_action_gb: u64,
    pub require_confirmation: bool,
    pub protected_paths: Vec<PathBuf>,
    pub require_full_path_review_for: Vec<SafetyLevel>,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            default_action: ActionType::Trash,
            // Headroom for real developer cleanups: a single Xcode DerivedData,
            // Docker, or node/Rust cache sweep routinely tops the old 50 GB /
            // 20 GB valves. These remain safety ceilings against a runaway plan
            // (and are user-configurable in Settings); the aggressive permanent-
            // delete hard cap in the executor is unchanged.
            max_single_run_gb: 250,
            max_single_action_gb: 100,
            require_confirmation: true,
            protected_paths: Vec::new(),
            require_full_path_review_for: vec![SafetyLevel::Cautious, SafetyLevel::Aggressive],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MlConfig {
    pub enabled: bool,
    pub model_path: PathBuf,
    pub confidence_threshold: f32,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_path: PathBuf::new(),
            confidence_threshold: 0.85,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    pub show_hidden_files: bool,
    pub sort_by: String,
    pub group_by: String,
    pub icon_mode: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            show_hidden_files: false,
            sort_by: "size".to_owned(),
            group_by: "category".to_owned(),
            icon_mode: "nerd-font".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn missing_config_loads_defaults() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = CleantonConfig::load_from_path(&temp.path().join("missing.toml"))
            .expect("missing config");
        assert_eq!(config, CleantonConfig::default());
    }

    #[test]
    fn partial_config_merges_with_defaults() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("config.toml");
        fs::write(
            &path,
            r#"
                [scanning]
                max_depth = 3

                [safety]
                protected_paths = ["/Users/example/critical"]
            "#,
        )
        .expect("write config");

        let config = CleantonConfig::load_from_path(&path).expect("load config");
        assert_eq!(config.scanning.max_depth, 3);
        assert!(!config.scanning.follow_symlinks);
        assert_eq!(config.safety.max_single_run_gb, 250);
        assert_eq!(
            config.safety.protected_paths,
            vec![PathBuf::from("/Users/example/critical")]
        );
    }

    #[test]
    fn save_then_load_round_trips() {
        let temp = tempfile::tempdir().expect("tempdir");
        // Nested path exercises parent-directory creation.
        let path = temp.path().join("nested").join("config.toml");

        let mut config = CleantonConfig::default();
        config.general.default_root = PathBuf::from("/Users/example/dev");
        config.general.theme = "light".to_owned();
        config.scanning.max_depth = 7;
        config.scanning.follow_symlinks = true;
        config.scanning.respect_gitignore = false;
        config.scanning.parallel_threads = 4;
        config.scanning.exclude_cloud_roots = false;
        config.scanning.exclude_external_volumes = false;
        config.ml.enabled = true;
        config.safety.protected_paths = vec![PathBuf::from("/Users/example/keep")];

        config.save_to_path(&path).expect("save config");
        assert!(path.exists(), "config file should exist after save");

        let loaded = CleantonConfig::load_from_path(&path).expect("load config");
        assert_eq!(loaded, config);
    }

    #[test]
    fn save_overwrites_existing_atomically() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("config.toml");

        let mut first = CleantonConfig::default();
        first.scanning.max_depth = 1;
        first.save_to_path(&path).expect("save first");

        let mut second = CleantonConfig::default();
        second.scanning.max_depth = 99;
        second.save_to_path(&path).expect("save second");

        let loaded = CleantonConfig::load_from_path(&path).expect("load config");
        assert_eq!(loaded.scanning.max_depth, 99);
        // No temp files should be left behind in the directory.
        let leftovers = fs::read_dir(temp.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("tmp"))
            .count();
        assert_eq!(leftovers, 0, "no temp files should remain");
    }

    #[test]
    fn invalid_config_is_an_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("config.toml");
        fs::write(&path, "[scanning]\nmax_depth = \"deep\"").expect("write config");

        let err = CleantonConfig::load_from_path(&path).expect_err("invalid config");
        assert!(err.to_string().contains("configuration error"));
    }
}
