//! Application uninstall: inventory of installed `.app` bundles and discovery
//! of everything they leave behind (support dirs, caches, preferences, launch
//! items, containers, helpers).
//!
//! SAFETY: discovery is read-only and review-only — nothing here removes a
//! file. Removal happens exclusively through the executor's uninstall-scoped
//! trash path (see [`crate::executor::trash_uninstall_path`]) after an
//! explicit per-app user confirmation in the UI, moves items to the Trash
//! (never a permanent delete), and refuses Apple/system applications outright.
//! System-domain leftovers (`/Library/LaunchAgents`, `/Library/LaunchDaemons`,
//! `/Library/PrivilegedHelperTools`) are surfaced for review but marked
//! `admin_required` and are never touched by the engine: once the app bundle
//! is gone they become orphaned and can be removed through the Services tab's
//! audited, admin-elevated path.

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// An installed application bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledApp {
    /// Display name (the bundle's file stem, e.g. `"Slack"`).
    pub name: String,
    /// Absolute bundle path, e.g. `/Applications/Slack.app`.
    pub path: PathBuf,
    /// `CFBundleIdentifier` from `Contents/Info.plist`, when readable.
    pub bundle_id: Option<String>,
    /// `CFBundleShortVersionString`, when present.
    pub version: Option<String>,
    /// Approximate bundle size (bounded walk; display-only).
    pub bytes: u64,
    /// Apple/system application: listed for completeness, never uninstallable.
    pub protected: bool,
}

/// Where a leftover was found; drives grouping and labels in the UIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeftoverKind {
    AppBundle,
    AppSupport,
    Caches,
    Preferences,
    SavedState,
    Logs,
    CrashReports,
    WebKit,
    HttpStorage,
    Cookies,
    Container,
    GroupContainer,
    ApplicationScripts,
    /// A home-directory data/config location outside `~/Library` — a bare
    /// dotfolder (`~/.ollama`) or an XDG dir (`~/.cache/<app>`,
    /// `~/.config/<app>`, `~/.local/share|state/<app>`). Many CLI-style and
    /// Electron apps (Ollama, LM Studio, …) keep their big model/data caches
    /// here rather than under `~/Library`.
    HomeData,
    LaunchAgent,
    LaunchDaemon,
    PrivilegedHelper,
}

impl LeftoverKind {
    /// Human label used by both UIs (keep them identical).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AppBundle => "Application",
            Self::AppSupport => "Application Support",
            Self::Caches => "Caches",
            Self::Preferences => "Preferences",
            Self::SavedState => "Saved state",
            Self::Logs => "Logs",
            Self::CrashReports => "Crash reports",
            Self::WebKit => "WebKit data",
            Self::HttpStorage => "HTTP storage",
            Self::Cookies => "Cookies",
            Self::Container => "Container",
            Self::GroupContainer => "Group container",
            Self::ApplicationScripts => "Application scripts",
            Self::HomeData => "App data (home)",
            Self::LaunchAgent => "Launch agent",
            Self::LaunchDaemon => "Launch daemon",
            Self::PrivilegedHelper => "Privileged helper",
        }
    }
}

/// One on-disk item that belongs to the app being uninstalled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftoverItem {
    pub path: PathBuf,
    pub kind: LeftoverKind,
    /// Approximate size (bounded walk; display-only).
    pub bytes: u64,
    /// System-domain item requiring admin rights: review-only here. It becomes
    /// orphaned (and removable via the Services tab's elevated path) once the
    /// app bundle is gone.
    pub admin_required: bool,
    /// For launch items: the launchd label (plist file stem), so the UI can
    /// best-effort stop the job before the file is trashed.
    pub launchd_label: Option<String>,
}

/// The reviewable uninstall proposal for one app: the bundle itself plus every
/// discovered leftover, largest first (bundle always first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallPlan {
    pub app: InstalledApp,
    pub items: Vec<LeftoverItem>,
    /// Sum of `bytes` across `items`.
    pub total_bytes: u64,
}

/// List installed applications under `/Applications` (one grouping level deep,
/// e.g. `Utilities/`) and `~/Applications`, plus `/System/Applications` so the
/// inventory is complete — system apps come back `protected` and the UIs offer
/// no uninstall for them. Sorted by name, case-insensitively.
#[must_use]
pub fn list_installed_apps() -> Vec<InstalledApp> {
    let mut roots = vec![
        (PathBuf::from("/Applications"), false),
        (PathBuf::from("/System/Applications"), true),
    ];
    if let Some(home) = home_dir() {
        roots.push((home.join("Applications"), false));
    }

    let mut apps = Vec::new();
    for (root, system_root) in roots {
        collect_installed(&root, 0, system_root, &mut apps);
    }
    apps.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
            .then_with(|| a.path.cmp(&b.path))
    });
    apps
}

/// Watches the user-removable application folders (`/Applications`,
/// `~/Applications`) and reports bundles that disappear between polls — i.e.
/// apps the user removed *outside* Cleanton (dragged to the Trash in Finder,
/// or removed by another uninstaller). The UI uses this to deep-link into the
/// Applications tab and offer to clean up the app's leftovers.
///
/// Detection is a cheap `readdir` diff (no bundle sizing); an `Info.plist` is
/// read only for apps not seen before, so the identity of a removed app is
/// already cached by the time it vanishes.
#[derive(Debug, Default)]
pub struct AppRemovalWatcher {
    known: std::collections::HashMap<PathBuf, InstalledApp>,
    /// Injectable roots (tests); empty means "the real system roots".
    roots: Option<Vec<PathBuf>>,
}

impl AppRemovalWatcher {
    /// Seed with the apps installed right now, so the first poll reports
    /// nothing (only *subsequent* removals are surfaced).
    #[must_use]
    pub fn new() -> Self {
        let mut watcher = Self {
            known: std::collections::HashMap::new(),
            roots: None,
        };
        for app in watcher.scan() {
            watcher.known.insert(app.path.clone(), app);
        }
        watcher
    }

    #[cfg(test)]
    fn with_roots(roots: Vec<PathBuf>) -> Self {
        let mut watcher = Self {
            known: std::collections::HashMap::new(),
            roots: Some(roots),
        };
        for app in watcher.scan() {
            watcher.known.insert(app.path.clone(), app);
        }
        watcher
    }

    fn scan(&self) -> Vec<InstalledApp> {
        match &self.roots {
            Some(roots) => {
                let mut apps = Vec::new();
                for root in roots {
                    collect_app_identities(root, 0, &mut apps);
                }
                apps
            }
            None => current_app_identities(),
        }
    }

    /// Re-scan and return the identities of apps that disappeared since the
    /// previous poll. Newly-appeared apps are learned so a later removal is
    /// still detected.
    pub fn poll(&mut self) -> Vec<InstalledApp> {
        let current = self.scan();
        let current_paths: std::collections::HashSet<PathBuf> =
            current.iter().map(|app| app.path.clone()).collect();

        for app in current {
            self.known.entry(app.path.clone()).or_insert(app);
        }

        let removed_paths: Vec<PathBuf> = self
            .known
            .keys()
            .filter(|path| !current_paths.contains(*path))
            .cloned()
            .collect();
        let mut removed = Vec::new();
        for path in removed_paths {
            if let Some(app) = self.known.remove(&path) {
                removed.push(app);
            }
        }
        removed.sort_by(|a, b| a.name.cmp(&b.name));
        removed
    }
}

/// Lightweight inventory of user-removable apps: name, path, and bundle id, but
/// no size (readdir + a single `Info.plist` read each). Used by
/// [`AppRemovalWatcher`]; `/System/Applications` is intentionally excluded (its
/// apps are not user-removable, so they can't be "removed").
fn current_app_identities() -> Vec<InstalledApp> {
    let mut roots = vec![PathBuf::from("/Applications")];
    if let Some(home) = home_dir() {
        roots.push(home.join("Applications"));
    }
    let mut apps = Vec::new();
    for root in roots {
        collect_app_identities(&root, 0, &mut apps);
    }
    apps
}

fn collect_app_identities(dir: &Path, depth: usize, out: &mut Vec<InstalledApp>) {
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
            if let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) {
                let info = info_plist(&path);
                let bundle_id = info
                    .as_ref()
                    .and_then(|dict| dict.get("CFBundleIdentifier"))
                    .and_then(plist::Value::as_string)
                    .map(str::to_owned);
                let apple = bundle_id
                    .as_deref()
                    .is_some_and(|id| is_apple_bundle_id(&id.to_ascii_lowercase()));
                out.push(InstalledApp {
                    name: name.to_owned(),
                    path: path.clone(),
                    bundle_id,
                    version: None,
                    bytes: 0,
                    protected: apple,
                });
            }
        } else if depth == 0 {
            collect_app_identities(&path, depth + 1, out);
        }
    }
}

fn collect_installed(dir: &Path, depth: usize, system_root: bool, out: &mut Vec<InstalledApp>) {
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
            if let Some(app) = read_app(&path, system_root) {
                out.push(app);
            }
        } else if depth == 0 {
            // A grouping folder such as `Utilities`; descend one level.
            collect_installed(&path, depth + 1, system_root, out);
        }
    }
}

fn read_app(path: &Path, system_root: bool) -> Option<InstalledApp> {
    let name = path.file_stem()?.to_str()?.to_owned();
    let info = info_plist(path);
    let bundle_id = info
        .as_ref()
        .and_then(|dict| dict.get("CFBundleIdentifier"))
        .and_then(plist::Value::as_string)
        .map(str::to_owned);
    let version = info
        .as_ref()
        .and_then(|dict| dict.get("CFBundleShortVersionString"))
        .and_then(plist::Value::as_string)
        .map(str::to_owned);
    let apple = bundle_id
        .as_deref()
        .is_some_and(|id| is_apple_bundle_id(&id.to_ascii_lowercase()));
    Some(InstalledApp {
        name,
        bytes: bounded_size(path),
        protected: system_root || apple,
        bundle_id,
        version,
        path: path.to_path_buf(),
    })
}

fn info_plist(app_path: &Path) -> Option<plist::Dictionary> {
    let value = plist::Value::from_file(app_path.join("Contents").join("Info.plist")).ok()?;
    value.into_dictionary()
}

fn is_apple_bundle_id(id: &str) -> bool {
    id == "com.apple" || id.starts_with("com.apple.")
}

/// Lowercased slug candidates an app's home/XDG data folders might be named
/// after: the display name with separators stripped (`"LM Studio"` →
/// `"lmstudio"`), the name with spaces hyphenated (`"lm-studio"`), and the
/// bundle-id's last segment (`ai.x.lmstudio` → `"lmstudio"`). Slugs shorter
/// than three characters are dropped — too generic to match safely.
fn app_data_keys(app: &InstalledApp) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let mut push = |candidate: String| {
        if candidate.len() >= 3 && !keys.contains(&candidate) {
            keys.push(candidate);
        }
    };

    let name = app.name.to_ascii_lowercase();
    push(
        name.chars()
            .filter(|ch| !ch.is_whitespace() && *ch != '_' && *ch != '-')
            .collect(),
    );
    push(name.split_whitespace().collect::<Vec<_>>().join("-"));
    if let Some(id) = &app.bundle_id
        && let Some(last) = id.rsplit('.').next()
    {
        push(last.to_ascii_lowercase());
    }
    keys
}

/// Dotfolders under `$HOME` that are never a single app's disposable data:
/// credentials, shell/tool config, and shared toolchain roots. A `~/.<key>`
/// probe is skipped when `key` is one of these, and the executor refuses them
/// again as defense in depth.
pub(crate) fn is_reserved_home_key(key: &str) -> bool {
    const RESERVED: &[&str] = &[
        "ssh",
        "gnupg",
        "gpg",
        "aws",
        "azure",
        "gcloud",
        "kube",
        "docker",
        "config",
        "local",
        "cache",
        "cargo",
        "rustup",
        "npm",
        "gem",
        "bundle",
        "rbenv",
        "pyenv",
        "nvm",
        "git",
        "gitconfig",
        "vim",
        "vscode",
        "emacs",
        "nano",
        "zsh",
        "bash",
        "profile",
        "netrc",
        "npmrc",
        "pypirc",
        "trash",
        "oh-my-zsh",
        "cleanton",
    ];
    RESERVED.contains(&key)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| !home.as_os_str().is_empty())
}

/// The Homebrew cask token this app was installed under, if any, given the set
/// of installed cask tokens (from `brew list --cask`, fetched by the caller so
/// the engine performs no subprocess work). Matched by the same name/bundle-id
/// slugs used for leftover discovery, so `"LM Studio"` matches the `lm-studio`
/// cask and `"Ollama"` matches `ollama`. When a cask installed the app,
/// uninstalling should go through `brew uninstall --cask` so Homebrew's own
/// records stay consistent.
#[must_use]
pub fn cask_token_for(app: &InstalledApp, installed_cask_tokens: &[String]) -> Option<String> {
    let keys = app_data_keys(app);
    installed_cask_tokens
        .iter()
        .find(|token| {
            let lower = token.to_ascii_lowercase();
            // Compare against the slug set both directly and with the token's
            // own separators stripped (cask tokens are hyphenated).
            let compact: String = lower.chars().filter(|c| *c != '-' && *c != '_').collect();
            keys.iter().any(|key| key == &lower || key == &compact)
        })
        .cloned()
}

/// Discover everything the given app owns on disk. Read-only. Returns `None`
/// for protected (Apple/system) applications — there is nothing reviewable to
/// propose for them.
#[must_use]
pub fn find_leftovers(app: &InstalledApp) -> Option<UninstallPlan> {
    if app.protected {
        return None;
    }
    let home = home_dir()?;
    Some(find_leftovers_with_roots(app, &home, Path::new("/Library")))
}

/// Core discovery with injectable roots so tests can run against fixtures.
pub(crate) fn find_leftovers_with_roots(
    app: &InstalledApp,
    home: &Path,
    system_library: &Path,
) -> UninstallPlan {
    let library = home.join("Library");
    let bundle_id = app.bundle_id.as_deref();
    let mut items = Vec::new();
    // The bundle is listed only when it is still on disk. When discovery runs
    // *after* an external removal (the user dragged the app to the Trash), the
    // bundle is already gone — we then propose only the leftovers it left.
    if fs::symlink_metadata(&app.path).is_ok() {
        items.push(LeftoverItem {
            path: app.path.clone(),
            kind: LeftoverKind::AppBundle,
            bytes: app.bytes,
            admin_required: false,
            launchd_label: None,
        });
    }

    // Exact-name locations: only ever matched by the app's exact folder name.
    for (subdir, kind) in [
        ("Application Support", LeftoverKind::AppSupport),
        ("Caches", LeftoverKind::Caches),
        ("Logs", LeftoverKind::Logs),
    ] {
        push_if_exists(&library.join(subdir).join(&app.name), kind, &mut items);
    }

    // Bundle-id keyed locations (exact and helper-suffixed `<id>.*`).
    if let Some(id) = bundle_id {
        for (subdir, kind) in [
            ("Application Support", LeftoverKind::AppSupport),
            ("Caches", LeftoverKind::Caches),
            ("Containers", LeftoverKind::Container),
            ("WebKit", LeftoverKind::WebKit),
            ("HTTPStorages", LeftoverKind::HttpStorage),
            ("Application Scripts", LeftoverKind::ApplicationScripts),
        ] {
            push_prefix_matches(&library.join(subdir), id, kind, false, &mut items);
        }

        // Preferences: `<id>.plist` plus helper `<id>.<helper>.plist`.
        push_plist_prefix_matches(
            &library.join("Preferences"),
            id,
            LeftoverKind::Preferences,
            &mut items,
        );
        // Saved state: `<id>.savedState` (+ helpers).
        push_prefix_matches(
            &library.join("Saved Application State"),
            id,
            LeftoverKind::SavedState,
            false,
            &mut items,
        );
        // Cookies: `<id>.binarycookies`.
        push_if_exists(
            &library.join("Cookies").join(format!("{id}.binarycookies")),
            LeftoverKind::Cookies,
            &mut items,
        );
        // Group containers are `<TEAMID>.<group-id>`; the group id usually
        // embeds the bundle id. Substring match on the (long, reverse-DNS)
        // bundle id keeps this precise.
        push_containing_matches(
            &library.join("Group Containers"),
            id,
            LeftoverKind::GroupContainer,
            &mut items,
        );

        push_launch_and_helper_items(&library, system_library, id, &mut items);
    }

    // Crash reports are named `<ProcessName>-<timestamp>.ips`; the process
    // name is normally the app name.
    push_crash_reports(
        &library.join("Logs").join("DiagnosticReports"),
        &app.name,
        &mut items,
    );

    push_home_and_slug_locations(app, home, &library, &mut items);

    // A path may be reachable by more than one key/probe; keep the first hit.
    let mut seen = std::collections::HashSet::new();
    items.retain(|item| seen.insert(item.path.clone()));

    // The bundle (when present) stays first; everything else largest-first.
    let bundle_first = items
        .first()
        .is_some_and(|item| item.kind == LeftoverKind::AppBundle);
    let sort_from = usize::from(bundle_first);
    if let Some(rest) = items.get_mut(sort_from..) {
        rest.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    }
    let total_bytes = items
        .iter()
        .fold(0u64, |acc, item| acc.saturating_add(item.bytes));

    UninstallPlan {
        app: app.clone(),
        items,
        total_bytes,
    }
}

/// Launch items and privileged helpers keyed off the bundle id. User launch
/// agents are trashable; system-domain agents, daemons, and privileged helpers
/// are review-only (admin required, so removed via the Services tab once the
/// app is gone).
fn push_launch_and_helper_items(
    library: &Path,
    system_library: &Path,
    id: &str,
    items: &mut Vec<LeftoverItem>,
) {
    push_launch_items(
        &library.join("LaunchAgents"),
        id,
        LeftoverKind::LaunchAgent,
        false,
        items,
    );
    push_launch_items(
        &system_library.join("LaunchAgents"),
        id,
        LeftoverKind::LaunchAgent,
        true,
        items,
    );
    push_launch_items(
        &system_library.join("LaunchDaemons"),
        id,
        LeftoverKind::LaunchDaemon,
        true,
        items,
    );
    push_prefix_matches(
        &system_library.join("PrivilegedHelperTools"),
        id,
        LeftoverKind::PrivilegedHelper,
        true,
        items,
    );
}

/// Probe home-directory locations outside `~/Library` (bare dotfolders and XDG
/// dirs) plus slug-named Library folders, keyed off the app's name/bundle-id
/// slugs. This is where Ollama (`~/.ollama`), LM Studio (`~/.lmstudio`,
/// `~/.cache/lm-studio`), and many CLI/Electron apps keep their real data.
fn push_home_and_slug_locations(
    app: &InstalledApp,
    home: &Path,
    library: &Path,
    items: &mut Vec<LeftoverItem>,
) {
    for key in app_data_keys(app) {
        // A bare `~/.<key>` dotfolder (skip reserved system dotfolders).
        if !is_reserved_home_key(&key) {
            push_if_exists(&home.join(format!(".{key}")), LeftoverKind::HomeData, items);
        }
        push_if_exists(&home.join(".cache").join(&key), LeftoverKind::Caches, items);
        push_if_exists(
            &home.join(".config").join(&key),
            LeftoverKind::HomeData,
            items,
        );
        push_if_exists(
            &home.join(".local").join("share").join(&key),
            LeftoverKind::HomeData,
            items,
        );
        push_if_exists(
            &home.join(".local").join("state").join(&key),
            LeftoverKind::HomeData,
            items,
        );
        // Slug-named Library folders (e.g. `Application Support/LMStudio`).
        push_if_exists(
            &library.join("Application Support").join(&key),
            LeftoverKind::AppSupport,
            items,
        );
        push_if_exists(
            &library.join("Caches").join(&key),
            LeftoverKind::Caches,
            items,
        );
    }
}

fn push_if_exists(path: &Path, kind: LeftoverKind, items: &mut Vec<LeftoverItem>) {
    if fs::symlink_metadata(path).is_ok() {
        items.push(LeftoverItem {
            path: path.to_path_buf(),
            kind,
            bytes: bounded_size(path),
            admin_required: false,
            launchd_label: None,
        });
    }
}

/// Entries of `dir` named exactly `id` or starting with `id.` (helper bundles
/// like `com.foo.Bar.ShipIt`). Case-insensitive on the id.
fn push_prefix_matches(
    dir: &Path,
    id: &str,
    kind: LeftoverKind,
    admin_required: bool,
    items: &mut Vec<LeftoverItem>,
) {
    for (path, _name) in dir_entries_matching(dir, |name| {
        let lower = name.to_ascii_lowercase();
        let id = id.to_ascii_lowercase();
        lower == id || lower.starts_with(&format!("{id}."))
    }) {
        items.push(LeftoverItem {
            bytes: bounded_size(&path),
            path,
            kind,
            admin_required,
            launchd_label: None,
        });
    }
}

/// `<id>*.plist` preference files (exact and helper variants).
fn push_plist_prefix_matches(
    dir: &Path,
    id: &str,
    kind: LeftoverKind,
    items: &mut Vec<LeftoverItem>,
) {
    for (path, _name) in dir_entries_matching(dir, |name| {
        let lower = name.to_ascii_lowercase();
        let id = id.to_ascii_lowercase();
        lower
            .strip_suffix(".plist")
            .is_some_and(|stem| stem == id || stem.starts_with(&format!("{id}.")))
    }) {
        items.push(LeftoverItem {
            bytes: bounded_size(&path),
            path,
            kind,
            admin_required: false,
            launchd_label: None,
        });
    }
}

/// Entries whose name *contains* `id` (group containers: `<TEAMID>.<group>`).
fn push_containing_matches(
    dir: &Path,
    id: &str,
    kind: LeftoverKind,
    items: &mut Vec<LeftoverItem>,
) {
    for (path, _name) in dir_entries_matching(dir, |name| {
        name.to_ascii_lowercase().contains(&id.to_ascii_lowercase())
    }) {
        items.push(LeftoverItem {
            bytes: bounded_size(&path),
            path,
            kind,
            admin_required: false,
            launchd_label: None,
        });
    }
}

/// `<id>*.plist` launch items, carrying their launchd label (the file stem) so
/// the UI can stop the job before the plist is trashed.
fn push_launch_items(
    dir: &Path,
    id: &str,
    kind: LeftoverKind,
    admin_required: bool,
    items: &mut Vec<LeftoverItem>,
) {
    for (path, name) in dir_entries_matching(dir, |name| {
        let lower = name.to_ascii_lowercase();
        let id = id.to_ascii_lowercase();
        lower
            .strip_suffix(".plist")
            .is_some_and(|stem| stem == id || stem.starts_with(&format!("{id}.")))
    }) {
        let label = name.strip_suffix(".plist").map(str::to_owned);
        items.push(LeftoverItem {
            bytes: bounded_size(&path),
            path,
            kind,
            admin_required,
            launchd_label: label,
        });
    }
}

/// `<AppName>-*.ips` (and legacy `.crash`) diagnostic reports.
fn push_crash_reports(dir: &Path, app_name: &str, items: &mut Vec<LeftoverItem>) {
    let needle = format!("{}-", app_name.to_ascii_lowercase());
    for (path, _name) in dir_entries_matching(dir, |name| {
        let lower = name.to_ascii_lowercase();
        lower.starts_with(&needle)
            && std::path::Path::new(&lower).extension().is_some_and(|ext| {
                ext.eq_ignore_ascii_case("ips") || ext.eq_ignore_ascii_case("crash")
            })
    }) {
        items.push(LeftoverItem {
            bytes: bounded_size(&path),
            path,
            kind: LeftoverKind::CrashReports,
            admin_required: false,
            launchd_label: None,
        });
    }
}

fn dir_entries_matching(dir: &Path, matches: impl Fn(&str) -> bool) -> Vec<(PathBuf, String)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|name| name.to_str())
            && matches(name)
        {
            out.push((path.clone(), name.to_owned()));
        }
    }
    out.sort();
    out
}

/// Bounded on-disk size (same cap rationale as orphan sizing: display-only;
/// the trash action removes the whole item regardless of the number shown).
const SIZE_ENTRY_CAP: usize = 20_000;

fn bounded_size(path: &Path) -> u64 {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return 0;
    };
    if metadata.file_type().is_file() {
        return metadata.len();
    }
    if !metadata.file_type().is_dir() {
        return 0;
    }
    let mut total = 0_u64;
    for entry in walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .flatten()
        .take(SIZE_ENTRY_CAP)
    {
        if entry.file_type().is_file()
            && let Ok(metadata) = entry.metadata()
        {
            total = total.saturating_add(metadata.len());
        }
    }
    total
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing clearer.
    #![allow(clippy::indexing_slicing)]
    use std::fs;

    use super::*;

    fn temp_root() -> tempfile::TempDir {
        // Under the crate dir, NOT $TMPDIR (protected /var/folders on macOS).
        tempfile::Builder::new()
            .prefix("cleanton-uninstall-")
            .tempdir_in(std::env::current_dir().expect("current dir"))
            .expect("tempdir")
    }

    fn write_app(apps: &Path, app_name: &str, bundle_id: &str) -> PathBuf {
        let bundle = apps.join(format!("{app_name}.app"));
        let contents = bundle.join("Contents");
        fs::create_dir_all(&contents).expect("create bundle");
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>{bundle_id}</string>\
             <key>CFBundleShortVersionString</key><string>1.2.3</string>\
             </dict></plist>"
        );
        fs::write(contents.join("Info.plist"), plist).expect("write Info.plist");
        bundle
    }

    fn app_fixture(root: &Path) -> InstalledApp {
        let bundle = write_app(&root.join("Applications"), "Slacky", "com.tiny.slacky");
        InstalledApp {
            name: "Slacky".to_owned(),
            path: bundle,
            bundle_id: Some("com.tiny.slacky".to_owned()),
            version: Some("1.2.3".to_owned()),
            bytes: 0,
            protected: false,
        }
    }

    fn touch_dir(path: &Path) {
        fs::create_dir_all(path).expect("create dir");
        fs::write(path.join("payload.bin"), vec![0u8; 1024]).expect("write payload");
    }

    #[test]
    fn discovers_leftovers_across_the_user_library() {
        let temp = temp_root();
        let root = temp.path();
        let app = app_fixture(root);
        let library = root.join("home/Library");
        let system_library = root.join("Library");

        touch_dir(&library.join("Application Support/Slacky"));
        touch_dir(&library.join("Application Support/com.tiny.slacky.helper"));
        touch_dir(&library.join("Caches/com.tiny.slacky"));
        touch_dir(&library.join("Containers/com.tiny.slacky"));
        touch_dir(&library.join("Containers/com.tiny.slacky.QuickLook"));
        touch_dir(&library.join("Group Containers/ABCDE12345.com.tiny.slacky"));
        touch_dir(&library.join("Saved Application State/com.tiny.slacky.savedState"));
        touch_dir(&library.join("HTTPStorages/com.tiny.slacky"));
        fs::create_dir_all(library.join("Preferences")).expect("prefs dir");
        fs::write(library.join("Preferences/com.tiny.slacky.plist"), b"prefs")
            .expect("write prefs");
        fs::create_dir_all(library.join("LaunchAgents")).expect("agents dir");
        fs::write(
            library.join("LaunchAgents/com.tiny.slacky.helper.plist"),
            b"agent",
        )
        .expect("write agent");
        fs::create_dir_all(system_library.join("LaunchDaemons")).expect("daemons dir");
        fs::write(
            system_library.join("LaunchDaemons/com.tiny.slacky.daemon.plist"),
            b"daemon",
        )
        .expect("write daemon");
        fs::create_dir_all(library.join("Logs/DiagnosticReports")).expect("reports dir");
        fs::write(
            library.join("Logs/DiagnosticReports/Slacky-2026-06-01-120000.ips"),
            b"crash",
        )
        .expect("write crash report");

        let plan = find_leftovers_with_roots(&app, &root.join("home"), &system_library);

        // Bundle first.
        assert_eq!(plan.items[0].kind, LeftoverKind::AppBundle);
        assert_eq!(plan.items[0].path, app.path);

        let has = |kind: LeftoverKind, suffix: &str| {
            plan.items
                .iter()
                .any(|item| item.kind == kind && item.path.ends_with(suffix))
        };
        assert!(has(LeftoverKind::AppSupport, "Application Support/Slacky"));
        assert!(has(
            LeftoverKind::AppSupport,
            "Application Support/com.tiny.slacky.helper"
        ));
        assert!(has(LeftoverKind::Caches, "Caches/com.tiny.slacky"));
        assert!(has(LeftoverKind::Container, "Containers/com.tiny.slacky"));
        assert!(has(
            LeftoverKind::Container,
            "Containers/com.tiny.slacky.QuickLook"
        ));
        assert!(has(
            LeftoverKind::GroupContainer,
            "Group Containers/ABCDE12345.com.tiny.slacky"
        ));
        assert!(has(
            LeftoverKind::SavedState,
            "Saved Application State/com.tiny.slacky.savedState"
        ));
        assert!(has(
            LeftoverKind::HttpStorage,
            "HTTPStorages/com.tiny.slacky"
        ));
        assert!(has(
            LeftoverKind::Preferences,
            "Preferences/com.tiny.slacky.plist"
        ));
        assert!(has(
            LeftoverKind::CrashReports,
            "DiagnosticReports/Slacky-2026-06-01-120000.ips"
        ));

        // The user launch agent is trashable and carries its label.
        let agent = plan
            .items
            .iter()
            .find(|item| item.kind == LeftoverKind::LaunchAgent)
            .expect("agent found");
        assert!(!agent.admin_required);
        assert_eq!(
            agent.launchd_label.as_deref(),
            Some("com.tiny.slacky.helper")
        );

        // The system daemon is review-only.
        let daemon = plan
            .items
            .iter()
            .find(|item| item.kind == LeftoverKind::LaunchDaemon)
            .expect("daemon found");
        assert!(daemon.admin_required);

        assert!(plan.total_bytes >= 7 * 1024);
    }

    #[test]
    fn unrelated_entries_are_never_matched() {
        let temp = temp_root();
        let root = temp.path();
        let app = app_fixture(root);
        let library = root.join("home/Library");

        // Same vendor prefix but a different app; a name that merely contains
        // the app's name; an unrelated preference file.
        touch_dir(&library.join("Application Support/com.tiny.other"));
        touch_dir(&library.join("Application Support/Slacky Backup Tool"));
        touch_dir(&library.join("Caches/com.tiny.slackyx"));
        fs::create_dir_all(library.join("Preferences")).expect("prefs dir");
        fs::write(
            library.join("Preferences/com.tiny.slackyxtra.plist"),
            b"prefs",
        )
        .expect("write prefs");

        let plan = find_leftovers_with_roots(&app, &root.join("home"), &root.join("Library"));
        assert_eq!(
            plan.items.len(),
            1,
            "only the bundle itself may be proposed: {:?}",
            plan.items
        );
    }

    #[test]
    fn discovers_home_dotfolders_and_xdg_dirs() {
        let temp = temp_root();
        let root = temp.path();
        let home = root.join("home");
        // An Ollama-style app: bundle id slug "ollama", data in ~/.ollama and
        // ~/.cache/ollama, plus an XDG config dir.
        let app = InstalledApp {
            name: "Ollama".to_owned(),
            path: write_app(&root.join("Applications"), "Ollama", "com.electron.ollama"),
            bundle_id: Some("com.electron.ollama".to_owned()),
            version: Some("0.5.0".to_owned()),
            bytes: 0,
            protected: false,
        };
        touch_dir(&home.join(".ollama/models"));
        touch_dir(&home.join(".cache/ollama"));
        touch_dir(&home.join(".config/ollama"));
        touch_dir(&home.join(".local/share/ollama"));
        // A sensitive dotfolder that must never be proposed.
        touch_dir(&home.join(".ssh"));

        let plan = find_leftovers_with_roots(&app, &home, &root.join("Library"));
        let has = |suffix: &str| plan.items.iter().any(|item| item.path.ends_with(suffix));
        assert!(has(".ollama"), "bare ~/.ollama dotfolder must be found");
        assert!(has(".cache/ollama"), "~/.cache/ollama must be found");
        assert!(has(".config/ollama"), "~/.config/ollama must be found");
        assert!(
            has(".local/share/ollama"),
            "~/.local/share/ollama must be found"
        );
        assert!(
            plan.items.iter().all(|item| !item.path.ends_with(".ssh")),
            "a sensitive dotfolder must never be proposed"
        );
    }

    #[test]
    fn slug_keyed_home_folder_is_found_for_multiword_app() {
        let temp = temp_root();
        let root = temp.path();
        let home = root.join("home");
        // "LM Studio" → slugs "lmstudio" and "lm-studio".
        let app = InstalledApp {
            name: "LM Studio".to_owned(),
            path: write_app(
                &root.join("Applications"),
                "LM Studio",
                "ai.elementlabs.lmstudio",
            ),
            bundle_id: Some("ai.elementlabs.lmstudio".to_owned()),
            version: None,
            bytes: 0,
            protected: false,
        };
        touch_dir(&home.join(".lmstudio/models"));
        touch_dir(&home.join(".cache/lm-studio"));

        let plan = find_leftovers_with_roots(&app, &home, &root.join("Library"));
        assert!(
            plan.items
                .iter()
                .any(|item| item.path.ends_with(".lmstudio")),
            "~/.lmstudio (no-separator slug) must be found"
        );
        assert!(
            plan.items
                .iter()
                .any(|item| item.path.ends_with(".cache/lm-studio")),
            "~/.cache/lm-studio (hyphen slug) must be found"
        );
    }

    #[test]
    fn cask_token_matches_app_by_slug() {
        let lm = InstalledApp {
            name: "LM Studio".to_owned(),
            path: PathBuf::from("/Applications/LM Studio.app"),
            bundle_id: Some("ai.elementlabs.lmstudio".to_owned()),
            version: None,
            bytes: 0,
            protected: false,
        };
        let ollama = InstalledApp {
            name: "Ollama".to_owned(),
            path: PathBuf::from("/Applications/Ollama.app"),
            bundle_id: Some("com.electron.ollama".to_owned()),
            version: None,
            bytes: 0,
            protected: false,
        };
        let tokens = vec![
            "lm-studio".to_owned(),
            "ollama".to_owned(),
            "some-other-cask".to_owned(),
        ];
        assert_eq!(cask_token_for(&lm, &tokens).as_deref(), Some("lm-studio"));
        assert_eq!(cask_token_for(&ollama, &tokens).as_deref(), Some("ollama"));

        // An app not installed via a cask matches nothing.
        let other = InstalledApp {
            name: "Homegrown".to_owned(),
            path: PathBuf::from("/Applications/Homegrown.app"),
            bundle_id: Some("com.example.homegrown".to_owned()),
            version: None,
            bytes: 0,
            protected: false,
        };
        assert_eq!(cask_token_for(&other, &tokens), None);
    }

    #[test]
    fn watcher_reports_only_apps_removed_after_seeding() {
        let temp = temp_root();
        let apps_dir = temp.path().join("Applications");
        write_app(&apps_dir, "Keeper", "com.x.keeper");
        let ditched = write_app(&apps_dir, "Ditched", "com.x.ditched");

        let mut watcher = AppRemovalWatcher::with_roots(vec![apps_dir.clone()]);
        // Nothing removed yet.
        assert!(watcher.poll().is_empty());

        // Remove one app (simulating a Finder drag-to-Trash). A rename out of
        // the `.app` name makes the bundle vanish from the folder without using
        // the executor-only deletion primitives.
        fs::rename(&ditched, temp.path().join("Ditched.gone")).expect("move app away");
        let removed = watcher.poll();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].name, "Ditched");
        assert_eq!(removed[0].bundle_id.as_deref(), Some("com.x.ditched"));

        // A second poll does not re-report the same removal.
        assert!(watcher.poll().is_empty());
    }

    #[test]
    fn leftovers_found_for_a_removed_bundle_without_the_app() {
        let temp = temp_root();
        let root = temp.path();
        let home = root.join("home");
        // The bundle no longer exists on disk (already trashed), but its data
        // remains — discovery must still surface it, minus the bundle itself.
        let app = InstalledApp {
            name: "Ghosted".to_owned(),
            path: root.join("Applications/Ghosted.app"),
            bundle_id: Some("com.x.ghosted".to_owned()),
            version: None,
            bytes: 0,
            protected: false,
        };
        touch_dir(&home.join("Library/Application Support/com.x.ghosted"));
        touch_dir(&home.join(".ghosted"));

        let plan = find_leftovers_with_roots(&app, &home, &root.join("Library"));
        assert!(
            plan.items
                .iter()
                .all(|item| item.kind != LeftoverKind::AppBundle),
            "a removed bundle must not be listed as a leftover"
        );
        assert!(
            plan.items
                .iter()
                .any(|item| item.path.ends_with("Application Support/com.x.ghosted"))
        );
        assert!(
            plan.items
                .iter()
                .any(|item| item.path.ends_with(".ghosted"))
        );
    }

    #[test]
    fn protected_apps_yield_no_plan() {
        let app = InstalledApp {
            name: "Safari".to_owned(),
            path: PathBuf::from("/Applications/Safari.app"),
            bundle_id: Some("com.apple.Safari".to_owned()),
            version: None,
            bytes: 0,
            protected: true,
        };
        assert!(find_leftovers(&app).is_none());
    }

    #[test]
    fn installed_inventory_reads_bundle_metadata() {
        let temp = temp_root();
        let root = temp.path();
        write_app(&root.join("Applications"), "Slacky", "com.tiny.slacky");

        let mut apps = Vec::new();
        collect_installed(&root.join("Applications"), 0, false, &mut apps);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "Slacky");
        assert_eq!(apps[0].bundle_id.as_deref(), Some("com.tiny.slacky"));
        assert_eq!(apps[0].version.as_deref(), Some("1.2.3"));
        assert!(!apps[0].protected);
    }

    #[test]
    fn apple_bundles_are_marked_protected() {
        let temp = temp_root();
        let root = temp.path();
        write_app(
            &root.join("Applications"),
            "SafariLike",
            "com.apple.safari-like",
        );

        let mut apps = Vec::new();
        collect_installed(&root.join("Applications"), 0, false, &mut apps);
        assert_eq!(apps.len(), 1);
        assert!(apps[0].protected, "com.apple.* must be protected");
    }
}
