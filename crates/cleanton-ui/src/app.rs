use crate::animation::{AnimatedValue, EasingFunction};
use crate::capacity::{self, CapacityView};
use crate::theme::{DARK_THEME, Theme};
use crate::widgets::FileTreeState;
use cleanton_common::{CleantonConfig, CleanupPlan, ExecutionResult, ScanResult};
use cleanton_engine::{
    AnnotatedAction, DockerAnalysis, InstalledApp, Orchestrator, Suggestions, UninstallPlan,
};
use cleanton_packages::{Inventory, ManagerKind, RemovalPlan};
use cleanton_services::Service;
use std::collections::HashSet;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Package managers shown in the Packages screen selector, in display order.
/// Mirrors the Slint app's `PKG_MANAGER_ORDER`.
pub const PKG_MANAGER_ORDER: [ManagerKind; 5] = [
    ManagerKind::Homebrew,
    ManagerKind::HomebrewCask,
    ManagerKind::Npm,
    ManagerKind::Pip,
    ManagerKind::MacPorts,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveScreen {
    Dashboard,
    Results,
    Packages,
    Services,
    Applications,
    Settings,
    Execution,
}

/// A destructive package action awaiting explicit user confirmation. Mirrors the
/// app's gated uninstall / update / clean-cache flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageActionKind {
    /// Uninstall every package the keep-set marks removable (Homebrew only).
    RemoveUnkept,
    /// Update all outdated packages for the active manager.
    UpdateAll,
    /// Update a single named package.
    UpdateSelected(String),
    /// Clean the active manager's download/build cache.
    CleanCache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceActionKind {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingServiceConfirmation {
    pub action: ServiceActionKind,
    pub service_id: String,
}

pub struct App {
    pub active_screen: ActiveScreen,
    pub config: CleantonConfig,
    pub orchestrator: std::sync::Arc<Orchestrator>,
    pub is_scanning: bool,
    pub is_executing: bool,
    pub operation_id: u64,
    pub operation_cancelled: Arc<AtomicBool>,

    // Scanner state (scan is launched from the Dashboard; there is no separate
    // Scanner screen, matching the Slint app).
    pub scan_progress: Option<(u64, u64, u64)>, // (files, dirs, bytes)
    pub scan_result: Option<ScanResult>,

    // Review-only Results analysis surfaced alongside the cleanup plan: Docker
    // reclaimable accounting (independent of the scan root) and large-item /
    // duplicate suggestions. Both are populated by `analyze_full`.
    pub docker: Option<DockerAnalysis>,
    pub suggestions: Option<Suggestions>,

    // Packages screen state (mirrors the Slint app's two-phase package load).
    /// Index into [`PKG_MANAGER_ORDER`] for the active manager tab.
    pub package_manager_idx: usize,
    /// Monotonic load generation; stale background results are discarded.
    pub package_load_id: u64,
    pub package_inventory: Option<Inventory>,
    /// Keep-set: packages the user has chosen to retain. Defaults to ALL.
    pub package_keep: HashSet<String>,
    pub package_plan: Option<RemovalPlan>,
    pub package_selected_idx: usize,
    /// Phase 1 (inventory) in flight.
    pub package_loading: bool,
    /// Phase 2 (outdated + codebase-usage) in flight.
    pub package_phase2: bool,
    /// A mutating package action is running.
    pub package_acting: bool,
    /// Keep-set removal is only meaningful for Homebrew formulae.
    pub package_supports_keepset: bool,
    pub package_status: String,
    pub package_action_status: String,
    pub package_note: Option<String>,
    pub pending_package_confirmation: Option<PackageActionKind>,

    // Plan and tree state
    pub cleanup_plan: Option<CleanupPlan>,
    /// ML annotations for the planned (executable) actions, surfaced as badges.
    pub plan_annotations: Vec<AnnotatedAction>,
    /// Candidates ML demoted: NOT in `cleanup_plan`, require explicit confirmation.
    pub held_actions: Vec<AnnotatedAction>,
    pub file_tree_state: Option<FileTreeState>,
    pub pending_cleanup_confirmation: Option<Vec<usize>>,

    // Disk capacity + real usage history (no mock data)
    pub capacity_view: CapacityView,
    pub pending_empty_trash_confirmation: bool,

    // Services state
    pub services: Vec<Service>,
    /// Index into [`Self::visible_service_indices`] (the filtered list), not
    /// into `services` directly.
    pub selected_service_idx: usize,
    pub service_logs: Vec<String>,
    pub is_loading_services: bool,
    pub pending_service_confirmation: Option<PendingServiceConfirmation>,
    /// Hide system-protected (read-only) services from the list.
    pub service_hide_protected: bool,
    /// Show only startup items (services with `RunAtLoad`).
    pub service_startup_only: bool,

    // Suggestions interaction state (Results screen): which deletable
    // suggestion row is selected, and the path armed for a two-step trash.
    pub suggestion_selected: usize,
    pub pending_suggestion_trash: Option<std::path::PathBuf>,

    // Applications screen state (mirrors the Slint app's Applications tab).
    pub installed_apps: Vec<InstalledApp>,
    pub apps_loading: bool,
    /// Hide protected (Apple/system) applications from the list.
    pub apps_hide_system: bool,
    /// Whether the inventory has been loaded at least once, so entering the
    /// Applications screen auto-loads exactly once (via any navigation path)
    /// without re-triggering if the load legitimately returns nothing.
    pub apps_load_attempted: bool,
    /// Installed Homebrew cask tokens (`brew list --cask`), used to detect
    /// apps installed via Homebrew so uninstall also runs `brew uninstall`.
    pub apps_cask_tokens: Vec<String>,
    /// App-bundle paths the TUI itself just trashed, so the background removal
    /// watcher does not deep-link a removal Cleanton performed.
    pub uninstalled_by_us: Arc<std::sync::Mutex<HashSet<std::path::PathBuf>>>,
    /// Index into [`Self::visible_app_indices`] (the filtered list).
    pub selected_app_idx: usize,
    /// The reviewable uninstall plan for the loaded app (Enter loads it).
    pub app_uninstall_plan: Option<UninstallPlan>,
    /// Bundle path of the app whose leftovers are being loaded, so a background
    /// scan result can be matched to the current target even when the app is no
    /// longer in the inventory (external removal deep-link).
    pub leftover_target_path: Option<std::path::PathBuf>,
    pub leftover_loading: bool,
    /// Cursor within the loaded plan's items.
    pub leftover_selected: usize,
    /// Item indices the user deselected (admin items are implicitly excluded).
    pub leftover_excluded: HashSet<usize>,
    /// Two-step confirm armed for the loaded plan.
    pub pending_uninstall: bool,
    pub uninstalling: bool,

    // Execution state
    pub execution_progress: f32,
    pub execution_logs: Vec<String>,
    pub execution_result: Option<ExecutionResult>,

    // Animations
    pub donut_animation: AnimatedValue,

    // Settings Tab/Cursor
    pub active_setting_tab: usize, // 0: General, 1: Scanning, 2: Safety, 3: ML
    pub active_setting_idx: usize,
    pub theme: Theme,

    pub status_message: Option<String>,
}

impl App {
    pub fn new(config: CleantonConfig) -> Self {
        // Documented startup invariant: orchestrator construction only fails on a
        // fatal environment/config error, at which point the TUI cannot run at all.
        // `App::new` is infallible by design, so this is the sanctioned fail-fast.
        #[allow(clippy::expect_used)]
        let orchestrator = std::sync::Arc::new(
            Orchestrator::new(config.clone()).expect("Failed to initialize orchestrator"),
        );
        Self {
            active_screen: ActiveScreen::Dashboard,
            config,
            orchestrator,
            is_scanning: false,
            is_executing: false,
            operation_id: 0,
            operation_cancelled: Arc::new(AtomicBool::new(false)),
            scan_progress: None,
            scan_result: None,
            docker: None,
            suggestions: None,
            package_manager_idx: 0,
            package_load_id: 0,
            package_inventory: None,
            package_keep: HashSet::new(),
            package_plan: None,
            package_selected_idx: 0,
            package_loading: false,
            package_phase2: false,
            package_acting: false,
            package_supports_keepset: false,
            package_status: "No package manager loaded yet.".to_owned(),
            package_action_status: String::new(),
            package_note: None,
            pending_package_confirmation: None,
            cleanup_plan: None,
            plan_annotations: Vec::new(),
            held_actions: Vec::new(),
            file_tree_state: None,
            pending_cleanup_confirmation: None,
            capacity_view: CapacityView::default(),
            pending_empty_trash_confirmation: false,
            services: Vec::new(),
            selected_service_idx: 0,
            service_logs: Vec::new(),
            is_loading_services: false,
            pending_service_confirmation: None,
            service_hide_protected: false,
            service_startup_only: false,
            suggestion_selected: 0,
            pending_suggestion_trash: None,
            installed_apps: Vec::new(),
            apps_loading: false,
            apps_hide_system: false,
            apps_load_attempted: false,
            apps_cask_tokens: Vec::new(),
            uninstalled_by_us: Arc::new(std::sync::Mutex::new(HashSet::new())),
            selected_app_idx: 0,
            app_uninstall_plan: None,
            leftover_target_path: None,
            leftover_loading: false,
            leftover_selected: 0,
            leftover_excluded: HashSet::new(),
            pending_uninstall: false,
            uninstalling: false,
            execution_progress: 0.0,
            execution_logs: Vec::new(),
            execution_result: None,
            donut_animation: AnimatedValue::new(0.0, EasingFunction::Spring { stiffness: 80.0, damping: 10.0 }),
            active_setting_tab: 0,
            active_setting_idx: 0,
            theme: DARK_THEME,
            status_message: Some("Welcome to Cleanton! Press tab/number keys to navigate, Space/Enter to trigger actions.".to_owned()),
        }
    }

    pub fn set_status(&mut self, msg: &str) {
        self.status_message = Some(msg.to_owned());
    }

    /// Re-reads volume capacity + local snapshots for the configured scan root
    /// and records a real usage sample. Performs a small amount of blocking I/O
    /// (`statfs`, `tmutil`, a history write); call it at startup and after an
    /// operation completes, not every frame.
    pub fn refresh_capacity(&mut self) {
        let root = cleanton_common::paths::expand_tilde(&self.config.general.default_root);
        self.capacity_view = capacity::read(&root);
    }

    pub fn cycle_tab(&mut self) {
        self.active_screen = match self.active_screen {
            ActiveScreen::Dashboard => ActiveScreen::Results,
            ActiveScreen::Results => ActiveScreen::Packages,
            ActiveScreen::Packages => ActiveScreen::Services,
            ActiveScreen::Services => ActiveScreen::Applications,
            ActiveScreen::Applications => ActiveScreen::Settings,
            ActiveScreen::Settings => {
                if self.is_executing || self.execution_result.is_some() {
                    ActiveScreen::Execution
                } else {
                    ActiveScreen::Dashboard
                }
            }
            ActiveScreen::Execution => ActiveScreen::Dashboard,
        };
    }

    pub fn set_tab(&mut self, idx: usize) {
        self.active_screen = match idx {
            1 => ActiveScreen::Dashboard,
            2 => ActiveScreen::Results,
            3 => ActiveScreen::Packages,
            4 => ActiveScreen::Services,
            5 => ActiveScreen::Applications,
            6 => ActiveScreen::Settings,
            7 => ActiveScreen::Execution,
            _ => self.active_screen,
        };
    }

    /// The package manager backing the active Packages tab.
    #[must_use]
    pub fn current_package_manager(&self) -> ManagerKind {
        PKG_MANAGER_ORDER
            .get(self.package_manager_idx)
            .copied()
            .unwrap_or(ManagerKind::Homebrew)
    }

    /// Indices into [`Self::installed_apps`] shown after the hide-system
    /// filter, mirroring the Slint app's "Hide system apps" toggle.
    #[must_use]
    pub fn visible_app_indices(&self) -> Vec<usize> {
        self.installed_apps
            .iter()
            .enumerate()
            .filter(|(_, app)| !self.apps_hide_system || !app.protected)
            .map(|(idx, _)| idx)
            .collect()
    }

    /// Indices into [`Self::services`] that pass the active filters
    /// (hide-protected, startup-only), mirroring the Slint app's filter bar.
    #[must_use]
    pub fn visible_service_indices(&self) -> Vec<usize> {
        self.services
            .iter()
            .enumerate()
            .filter(|(_, svc)| {
                if self.service_hide_protected
                    && cleanton_services::is_protected(&svc.id, &svc.plist_path)
                {
                    return false;
                }
                if self.service_startup_only && !svc.run_at_load {
                    return false;
                }
                true
            })
            .map(|(idx, _)| idx)
            .collect()
    }

    /// How many deletable suggestion rows the Results screen exposes per
    /// category. Keeps rendering and key-handling agreed on the same list.
    pub const SUGGESTIONS_PER_CATEGORY: usize = 3;

    /// The deletable suggestion rows shown on the Results screen, flattened in
    /// display order: screenshots, installers, then large items, each capped at
    /// [`Self::SUGGESTIONS_PER_CATEGORY`]. Duplicate sets are reveal-only and
    /// excluded. Order MUST match `screens::results::render_suggestions`.
    #[must_use]
    pub fn deletable_suggestions(&self) -> Vec<&cleanton_engine::LargeItem> {
        let Some(sugg) = self.suggestions.as_ref() else {
            return Vec::new();
        };
        sugg.screenshots
            .iter()
            .take(Self::SUGGESTIONS_PER_CATEGORY)
            .chain(sugg.installers.iter().take(Self::SUGGESTIONS_PER_CATEGORY))
            .chain(sugg.large_items.iter().take(Self::SUGGESTIONS_PER_CATEGORY))
            .collect()
    }
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("active_screen", &self.active_screen)
            .field("config", &self.config)
            .field("is_scanning", &self.is_scanning)
            .field("is_executing", &self.is_executing)
            .field("operation_id", &self.operation_id)
            .field(
                "operation_cancelled",
                &self.operation_cancelled.load(Ordering::Relaxed),
            )
            .field("scan_progress", &self.scan_progress)
            .field("scan_result", &self.scan_result)
            .field("cleanup_plan", &self.cleanup_plan)
            .field("services", &self.services)
            .field("selected_service_idx", &self.selected_service_idx)
            .field("service_logs", &self.service_logs)
            .field("is_loading_services", &self.is_loading_services)
            .field(
                "pending_service_confirmation",
                &self.pending_service_confirmation,
            )
            .field("execution_progress", &self.execution_progress)
            .field("execution_logs", &self.execution_logs)
            .field("execution_result", &self.execution_result)
            .field("active_setting_tab", &self.active_setting_tab)
            .field("active_setting_idx", &self.active_setting_idx)
            .field("status_message", &self.status_message)
            .finish()
    }
}
