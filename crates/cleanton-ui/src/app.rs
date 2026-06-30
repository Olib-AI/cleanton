use crate::animation::{AnimatedValue, EasingFunction};
use crate::capacity::{self, CapacityView};
use crate::theme::{DARK_THEME, Theme};
use crate::widgets::FileTreeState;
use cleanton_common::{CleantonConfig, CleanupPlan, ExecutionResult, ScanResult};
use cleanton_engine::{AnnotatedAction, DockerAnalysis, Orchestrator, Suggestions};
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
    pub selected_service_idx: usize,
    pub service_logs: Vec<String>,
    pub is_loading_services: bool,
    pub pending_service_confirmation: Option<PendingServiceConfirmation>,

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
            ActiveScreen::Services => ActiveScreen::Settings,
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
            5 => ActiveScreen::Settings,
            6 => ActiveScreen::Execution,
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
