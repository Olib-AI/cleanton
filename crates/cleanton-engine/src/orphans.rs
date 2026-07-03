//! Engine-side detection of orphaned application data — Library entries keyed by
//! a bundle id / app name with no matching installed `.app`.
//!
//! This supersedes the inert `recipes/apps-orphaned-*.toml` placeholders.
//!
//! SAFETY: orphan candidates are trash-only, require explicit confirmation
//! (surfaced at `SafetyLevel::Cautious`, which forces full-path review), are
//! min-age gated, skip Apple/system bundle ids, and are filtered through the
//! SAME primitives the recipe path uses — [`ProtectedPaths`] and the recipe
//! matcher's sensitive-basename floor (reused via a synthetic floor recipe).
//! The detector biases hard toward keeping: a candidate is only ever eligible
//! when its key looks like a reverse-DNS bundle identifier.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use cleanton_common::{
    ActionType, CleantonConfig, CleanupAction, Confidence, FileEntry, FileKind, ProtectedPaths,
    RecipeId, SafetyLevel,
};
use cleanton_recipes::{
    ActionSpec, MatchSpec, Recipe, RecipeDocument, RecipeTest, recipe_matches_entry,
};

use crate::ml::{ActionAnnotation, AnnotatedAction};

/// Category/group label shown in the CLI and both UIs.
pub const ORPHAN_CATEGORY: &str = "Orphaned application data";

/// Default minimum age before an orphan is even considered, in days. Conservative.
pub const DEFAULT_ORPHAN_MIN_AGE_DAYS: u64 = 30;

const ORPHAN_RECIPE_ID: &str = "engine-orphaned-app-data";

/// Per-user Library locations scanned for orphaned entries, with how the entry
/// name maps to a bundle-id / app-name key.
const LIBRARY_LOCATIONS: &[(&str, Keying)] = &[
    ("Application Support", Keying::Name),
    ("Preferences", Keying::PlistSuffix),
    ("Caches", Keying::Name),
    ("Containers", Keying::Name),
    ("Saved Application State", Keying::SavedStateSuffix),
    ("Logs", Keying::Name),
];

#[derive(Debug, Clone, Copy)]
enum Keying {
    /// The whole entry name is the key (e.g. `~/Library/Caches/<key>`).
    Name,
    /// `<key>.plist` — strip the `.plist` suffix.
    PlistSuffix,
    /// `<key>.savedState` — strip the `.savedState` suffix.
    SavedStateSuffix,
}

/// Detect orphaned application data on the real system, honouring `config`.
pub(crate) fn detect_orphans(config: &CleantonConfig) -> Vec<AnnotatedAction> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let detector = OrphanDetector::for_system(&home, config, DEFAULT_ORPHAN_MIN_AGE_DAYS);
    detector.detect()
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| !home.as_os_str().is_empty())
}

/// Orphan detection inspects `~/Library`. Only run it when the scan actually
/// reached there (i.e. the user scanned home or the whole disk). Scanning a
/// project directory like `~/code/app/target` must not trigger a `~/Library`
/// walk — that is both surprising and expensive.
#[must_use]
pub(crate) fn scan_reaches_home_library(scan: &cleanton_common::ScanResult) -> bool {
    let Some(library) = home_dir().map(|home| home.join("Library")) else {
        return false;
    };
    scan.entries
        .iter()
        .any(|entry| entry.path.starts_with(&library) || library.starts_with(&entry.path))
}

/// Configurable orphan detector. Roots are injectable so the detection logic is
/// fully unit-testable against fixtures without touching the real system.
#[derive(Debug)]
pub(crate) struct OrphanDetector {
    /// Roots scanned for installed `.app` bundles.
    app_roots: Vec<PathBuf>,
    /// The `Library` directory whose subfolders are scanned for orphan entries.
    library: PathBuf,
    /// Minimum age before an entry is considered (forwarded to the floor recipe).
    min_age_days: u64,
    /// User-configured + hardcoded protected paths.
    protected: ProtectedPaths,
}

impl OrphanDetector {
    fn for_system(home: &Path, config: &CleantonConfig, min_age_days: u64) -> Self {
        Self {
            app_roots: vec![
                PathBuf::from("/Applications"),
                home.join("Applications"),
                PathBuf::from("/System/Applications"),
            ],
            library: home.join("Library"),
            min_age_days: min_age_days.max(1),
            protected: ProtectedPaths::new(config.safety.protected_paths.clone()),
        }
    }

    #[cfg(test)]
    fn for_test(
        app_roots: Vec<PathBuf>,
        library: PathBuf,
        min_age_days: u64,
        protected: ProtectedPaths,
    ) -> Self {
        Self {
            app_roots,
            library,
            min_age_days: min_age_days.max(1),
            protected,
        }
    }

    fn detect(&self) -> Vec<AnnotatedAction> {
        let installed = self.installed_keys();
        let floor = floor_recipe(self.min_age_days);
        let mut out = Vec::new();

        for (subdir, keying) in LIBRARY_LOCATIONS {
            let dir = self.library.join(subdir);
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                let Some(key) = extract_key(file_name, *keying) else {
                    continue;
                };

                if let Some(annotated) = self.evaluate(&path, &key, &installed, &floor) {
                    out.push(annotated);
                }
            }
        }

        out.sort_by(|a, b| a.action.target.cmp(&b.action.target));
        out
    }

    /// Apply every safety gate to a single candidate. Returns `Some` only when
    /// it is, beyond reasonable doubt, orphaned and safe to *propose*.
    fn evaluate(
        &self,
        path: &Path,
        key: &str,
        installed: &BTreeSet<String>,
        floor: &RecipeDocument,
    ) -> Option<AnnotatedAction> {
        let lower = key.to_ascii_lowercase();

        // Gate 1: only ever consider reverse-DNS bundle-id-looking keys. Plain
        // folder names ("Google", "Code") are far too risky to flag.
        if !looks_like_bundle_id(&lower) {
            return None;
        }
        // Gate 2: never touch Apple / system bundle ids.
        if is_apple_id(&lower) {
            return None;
        }
        // Gate 3: keep anything whose key matches an installed app id or name.
        if installed.contains(&lower) {
            return None;
        }
        // Gate 4: user-configured + hardcoded protected paths (covers e.g.
        // ~/Library/Containers via the user-scoped protected set).
        if self.protected.is_protected(path) {
            return None;
        }

        let entry = entry_for_path(path)?;

        // Gate 5: reuse the recipe matcher's hard floor — ProtectedPaths::defaults
        // (sensitive system roots) + the sensitive-basename floor + min-age. An
        // empty-matcher floor recipe passes iff none of those reject the path.
        if !recipe_matches_entry(floor, &entry) {
            return None;
        }

        // Gate 6: nothing to reclaim (or a symlink) — skip silently.
        if entry.allocated_bytes == 0 && entry.kind != FileKind::Symlink {
            return None;
        }

        Some(candidate(&entry, key))
    }

    /// Collect installed bundle ids and app names (lowercased) across app roots.
    fn installed_keys(&self) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        for root in &self.app_roots {
            collect_apps(root, 0, &mut keys);
        }
        keys
    }
}

fn candidate(entry: &FileEntry, key: &str) -> AnnotatedAction {
    let action = CleanupAction {
        target: entry.path.clone(),
        logical_bytes: entry.logical_bytes,
        reclaimable_bytes: entry.allocated_bytes,
        recipe_id: RecipeId(ORPHAN_RECIPE_ID.to_owned()),
        category: "apps".to_owned(),
        // Trash-only; never a permanent delete.
        action_type: ActionType::Trash,
        // A conservative engine inference (not recipe- or ML-derived).
        confidence: Confidence::Medium,
        // Cautious => listed in `require_full_path_review_for` => explicit
        // confirmation with full-path review is required.
        safety_level: SafetyLevel::Cautious,
        reason: format!("{ORPHAN_CATEGORY}: \"{key}\" has no matching installed application"),
        fingerprint: entry.fingerprint(),
    };

    AnnotatedAction {
        action,
        annotation: ActionAnnotation::orphan(format!(
            "orphaned application data for \"{key}\"; explicit confirmation required"
        )),
    }
}

/// Recurse at most one level under an app root collecting `*.app` bundles. We do
/// not descend into a bundle (its nested helper apps are irrelevant here).
fn collect_apps(dir: &Path, depth: usize, keys: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
            continue;
        }

        let is_app = path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("app"));

        if is_app {
            // App name without the `.app` suffix.
            if let Some(app_name) = path.file_stem().and_then(|stem| stem.to_str())
                && !app_name.is_empty()
            {
                keys.insert(app_name.to_ascii_lowercase());
            }
            if let Some(bundle_id) = bundle_id_of(&path) {
                keys.insert(bundle_id.to_ascii_lowercase());
            }
        } else if depth == 0 {
            // A grouping folder such as `Utilities`; descend one level.
            collect_apps(&path, depth + 1, keys);
        }
    }
}

/// Read `CFBundleIdentifier` from an app bundle's `Contents/Info.plist`.
fn bundle_id_of(app_path: &Path) -> Option<String> {
    let info_plist = app_path.join("Contents").join("Info.plist");
    let value = plist::Value::from_file(&info_plist).ok()?;
    value
        .as_dictionary()
        .and_then(|dict| dict.get("CFBundleIdentifier"))
        .and_then(plist::Value::as_string)
        .map(str::to_owned)
}

fn extract_key(file_name: &str, keying: Keying) -> Option<String> {
    let key = match keying {
        Keying::Name => file_name,
        Keying::PlistSuffix => file_name.strip_suffix(".plist")?,
        Keying::SavedStateSuffix => file_name.strip_suffix(".savedState")?,
    };
    if key.is_empty() {
        None
    } else {
        Some(key.to_owned())
    }
}

/// A reverse-DNS bundle identifier: at least two dots, only `[A-Za-z0-9.-_]`,
/// no empty segments. Anything else is treated as a plain name and never flagged.
fn looks_like_bundle_id(key: &str) -> bool {
    if key.matches('.').count() < 2 {
        return false;
    }
    if !key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return false;
    }
    key.split('.').all(|segment| !segment.is_empty())
}

fn is_apple_id(key: &str) -> bool {
    key == "com.apple" || key.starts_with("com.apple.")
}

/// A synthetic, empty-matcher recipe whose only constraint is `min_age_days`.
/// `recipe_matches_entry` returns false if the path is protected (defaults),
/// has a sensitive basename, or is too recent — exactly the floor we want to
/// reuse rather than reimplement.
fn floor_recipe(min_age_days: u64) -> RecipeDocument {
    RecipeDocument {
        recipe: Recipe {
            id: "engine-orphan-floor".to_owned(),
            name: "Orphan floor".to_owned(),
            description: String::new(),
            category: ORPHAN_CATEGORY.to_owned(),
            icon: None,
            safety_level: SafetyLevel::Cautious,
            enabled: true,
            priority: 0,
        },
        matcher: MatchSpec {
            min_age_days: Some(min_age_days.max(1)),
            ..MatchSpec::default()
        },
        action: ActionSpec {
            action_type: ActionType::Trash,
            prompt: String::new(),
            group: false,
        },
        test: RecipeTest::default(),
    }
}

fn entry_for_path(path: &Path) -> Option<FileEntry> {
    let metadata = fs::symlink_metadata(path).ok()?;
    let file_type = metadata.file_type();
    let kind = if file_type.is_symlink() {
        FileKind::Symlink
    } else if file_type.is_dir() {
        FileKind::Directory
    } else if file_type.is_file() {
        FileKind::File
    } else {
        FileKind::Other
    };

    let modified = metadata.modified().ok();
    let bytes = match kind {
        FileKind::Directory => directory_size(path),
        FileKind::Symlink | FileKind::Other => 0,
        FileKind::File => metadata.len(),
    };

    Some(FileEntry {
        path: path.to_path_buf(),
        kind,
        logical_bytes: bytes,
        allocated_bytes: bytes,
        modified,
        depth: path.components().count(),
        device_id: None,
        inode: None,
        hardlink_count: None,
        symlink_target: None,
        ignored_by_git: false,
    })
}

/// Bounded so orphan sizing can never turn into an unbounded walk of a huge (or
/// actively-written) cache directory — that would stall every plan. We sum file
/// sizes until a cap, then stop: the figure is only used to confirm the candidate
/// is non-empty and to show an approximate reclaim size, and the trash action
/// removes the whole directory regardless of the displayed number.
const ORPHAN_SIZE_ENTRY_CAP: usize = 20_000;

fn directory_size(dir: &Path) -> u64 {
    let mut total = 0_u64;
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .flatten()
        .take(ORPHAN_SIZE_ENTRY_CAP)
    {
        if entry.file_type().is_file()
            && let Ok(metadata) = entry.metadata()
        {
            total = total.saturating_add(metadata.len());
        }
    }
    total
}

impl ActionAnnotation {
    /// Annotation for an orphan candidate (never ML-evaluated).
    pub(crate) fn orphan(note: impl Into<String>) -> Self {
        Self {
            ml_label: None,
            ml_confidence: None,
            adjustment: crate::ml::MlAdjustment::NotEvaluated,
            note: note.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing into expected results clearer.
    #![allow(clippy::indexing_slicing)]
    use std::{
        fs,
        time::{Duration, SystemTime},
    };

    use cleanton_common::ProtectedPaths;

    use super::*;

    /// Write an app bundle with the given `CFBundleIdentifier` (XML plist).
    fn write_app(apps: &Path, app_name: &str, bundle_id: &str) {
        let bundle = apps.join(format!("{app_name}.app")).join("Contents");
        fs::create_dir_all(&bundle).expect("create bundle");
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>{bundle_id}</string>\
             <key>CFBundleName</key><string>{app_name}</string>\
             </dict></plist>"
        );
        fs::write(bundle.join("Info.plist"), plist).expect("write Info.plist");
    }

    /// Create a non-empty support directory and backdate its mtime.
    fn write_support_dir(library: &Path, subdir: &str, name: &str, age: Duration) {
        let dir = library.join(subdir).join(name);
        fs::create_dir_all(&dir).expect("create support dir");
        fs::write(dir.join("data.bin"), vec![0_u8; 2048]).expect("write data");
        let when = SystemTime::now() - age;
        let file = fs::OpenOptions::new()
            .write(true)
            .open(dir.join("data.bin"))
            .expect("open data");
        file.set_modified(when).expect("set file mtime");
        let dir_handle = fs::File::open(&dir).expect("open dir");
        let _ = dir_handle.set_modified(when);
    }

    /// Create the fixture root under the crate directory, NOT `$TMPDIR`. On
    /// macOS `$TMPDIR` lives under `/var/folders`, which `ProtectedPaths`
    /// protects — putting fixtures there would make every assertion vacuous.
    fn temp_root() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("cleanton-orphans-")
            .tempdir_in(std::env::current_dir().expect("current dir"))
            .expect("tempdir")
    }

    fn detector(root: &Path) -> OrphanDetector {
        OrphanDetector::for_test(
            vec![root.join("Applications")],
            root.join("Library"),
            30,
            ProtectedPaths::new(Vec::new()),
        )
    }

    const OLD: Duration = Duration::from_hours(60 * 24);
    const RECENT: Duration = Duration::from_hours(2 * 24);

    #[test]
    fn flags_orphan_application_support_for_uninstalled_bundle_id() {
        let temp = temp_root();
        let root = temp.path();
        write_app(&root.join("Applications"), "Keeper", "com.installed.keeper");
        write_support_dir(
            &root.join("Library"),
            "Application Support",
            "com.ghost.removedapp",
            OLD,
        );

        let found = detector(root).detect();
        assert_eq!(found.len(), 1, "expected exactly one orphan");
        assert!(
            found[0]
                .action
                .target
                .ends_with("Application Support/com.ghost.removedapp")
        );
        assert_eq!(found[0].action.action_type, ActionType::Trash);
        assert_eq!(found[0].action.safety_level, SafetyLevel::Cautious);
        assert!(found[0].action.reclaimable_bytes >= 2048);
    }

    #[test]
    fn does_not_flag_data_for_an_installed_app() {
        let temp = temp_root();
        let root = temp.path();
        write_app(&root.join("Applications"), "Keeper", "com.installed.keeper");
        write_support_dir(
            &root.join("Library"),
            "Application Support",
            "com.installed.keeper",
            OLD,
        );

        assert!(detector(root).detect().is_empty());
    }

    #[test]
    fn does_not_flag_apple_bundle_ids() {
        let temp = temp_root();
        let root = temp.path();
        write_support_dir(&root.join("Library"), "Caches", "com.apple.Safari", OLD);

        assert!(detector(root).detect().is_empty());
    }

    #[test]
    fn does_not_flag_too_recent_entries() {
        let temp = temp_root();
        let root = temp.path();
        write_support_dir(
            &root.join("Library"),
            "Application Support",
            "com.ghost.removedapp",
            RECENT,
        );

        assert!(
            detector(root).detect().is_empty(),
            "min-age gate must reject recent entries"
        );
    }

    #[test]
    fn does_not_flag_protected_paths() {
        let temp = temp_root();
        let root = temp.path();
        write_support_dir(
            &root.join("Library"),
            "Application Support",
            "com.ghost.removedapp",
            OLD,
        );

        // Mark the whole Library as user-protected: nothing may be flagged.
        let protected = ProtectedPaths::new(vec![root.join("Library")]);
        let guarded = OrphanDetector::for_test(
            vec![root.join("Applications")],
            root.join("Library"),
            30,
            protected,
        );

        assert!(guarded.detect().is_empty());
    }

    #[test]
    fn plain_folder_names_are_never_flagged() {
        // "Code", "Google" etc. are not reverse-DNS bundle ids -> ignored.
        let temp = temp_root();
        let root = temp.path();
        write_support_dir(&root.join("Library"), "Application Support", "Code", OLD);
        write_support_dir(&root.join("Library"), "Application Support", "Google", OLD);

        assert!(detector(root).detect().is_empty());
    }

    #[test]
    fn floor_recipe_rejects_sensitive_basenames() {
        // Reused sensitive-basename floor: even an old, well-formed entry whose
        // basename is a credential file is refused by the shared matcher floor.
        let temp = temp_root();
        let sensitive = temp.path().join(".netrc");
        fs::write(&sensitive, "machine example").expect("write secret");
        let old = SystemTime::now() - OLD;
        fs::OpenOptions::new()
            .write(true)
            .open(&sensitive)
            .expect("open")
            .set_modified(old)
            .expect("mtime");

        let entry = entry_for_path(&sensitive).expect("entry");
        assert!(
            !recipe_matches_entry(&floor_recipe(30), &entry),
            "sensitive basename must be rejected by the reused floor"
        );
    }

    #[test]
    fn bundle_id_shape_is_strict() {
        assert!(looks_like_bundle_id("com.ghost.app"));
        assert!(looks_like_bundle_id("com.todesktop.230313mzl4w4u92"));
        assert!(!looks_like_bundle_id("code"));
        assert!(!looks_like_bundle_id("com.app"));
        assert!(!looks_like_bundle_id("com..app"));
        assert!(!looks_like_bundle_id("com.ghost app.thing"));
    }
}
