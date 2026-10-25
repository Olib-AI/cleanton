//! Cleanton — Native GUI Application (Slint)
//!
//! This binary provides a modern, SwiftUI-inspired native desktop interface
//! for Cleanton using the Slint UI framework. For the terminal-based interface,
//! use the `cleanton` (CLI/TUI) binary instead.

slint::include_modules!();

mod capacity;
mod fda;
mod trash_ops;

use std::{
    cell::RefCell,
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use cleanton_common::{
    ActionGroup, ActionType, CleantonConfig, CleanupAction, CleanupPlan, ExecutionResult,
    ExecutionStatus, SafetyLevel, display,
};
use cleanton_engine::{
    AnalyzedFull, AnalyzedPlan, AnnotatedAction, CleanupOffer, DockerAnalysis, DockerCleaner,
    DockerCleanupPlan, DuplicateSet, EngineEvent, InstalledApp, LargeItem, Orchestrator,
    ResourceStatus, SecurityRemoval, SnapshotAnalysis, SnapshotConfirmState, Suggestions,
    UninstallPlan, cask_token_for, delete_local_snapshots, find_leftovers, format_snapshot_date,
    list_installed_apps, snapshot_resource_status,
};
use cleanton_packages::{Inventory, ManagerKind, PackageManagers, plan_removal, scan_usage};
use cleanton_scanner::ScanOptions;
use cleanton_services::{Service, ServiceManager, ServiceStatus, ServiceType, is_protected};
use slint::{Model, ModelRc, SharedString, VecModel};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

const FA_PRO_SOLID: &[u8] =
    include_bytes!("../../../assets/fonts/Font Awesome 7 Pro-Solid-900.otf");
const FA_BRANDS_REGULAR: &[u8] =
    include_bytes!("../../../assets/fonts/Font Awesome 7 Brands-Regular-400.otf");

type CancellationToken = Arc<AtomicBool>;

/// Shared background worker runtime. Every UI callback used to build (and tear
/// down) a fresh current-thread Tokio runtime per click; one small multi-thread
/// runtime amortizes that setup across the app's lifetime. `block_on` on a
/// shared runtime is safe from any number of worker threads concurrently.
fn worker_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// One service mutation at a time: rapid clicks otherwise race concurrent
/// launchctl mutate-then-relist cycles, letting a stale relist overwrite the
/// newer list. Cleared when the completion closure lands on the UI thread.
static SERVICE_ACTION_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// One suggestion trash at a time (same double-fire concern as above).
static SUGGESTION_DELETE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// One snapshot deletion run at a time (deletion is permanent; a double-fire
/// must never race two tmutil runs against the same review).
static SNAPSHOT_DELETE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// One application-inventory load at a time.
static APPS_LOADING: AtomicBool = AtomicBool::new(false);

/// One security scan at a time (the scan itself is read-only; the guard just
/// prevents wasted duplicate work from rapid clicks). Because at most one scan
/// is ever in flight, its completion closure can never be stale.
static SECURITY_SCAN_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// One security removal at a time. Removal is the one destructive action on the
/// Security screen, so a double-click must never fire two uninstalls.
static SECURITY_REMOVE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// One uninstall at a time.
static UNINSTALL_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Monotonic generation counter for package-tab loads so stale responses from
/// an earlier manager tab never overwrite the newly selected tab.
static PACKAGE_LOAD_ID: AtomicU64 = AtomicU64::new(0);

/// User-dismissed resource pressure banners; automatically re-armed once usage
/// falls 5% below threshold so genuine new pressure spikes surface again.
static DISK_OFFER_DISMISSED: AtomicBool = AtomicBool::new(false);
static MEMORY_OFFER_DISMISSED: AtomicBool = AtomicBool::new(false);

/// App-bundle paths Cleanton itself just moved to the Trash. The background
/// app-removal watcher consults this so it does not re-trigger the "an app was
/// removed — clean its leftovers" deep-link for a removal Cleanton performed
/// (whose leftovers were already handled in the same uninstall).
static CLEANTON_REMOVED_BUNDLES: std::sync::LazyLock<Mutex<HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));
type CurrentOperation = Arc<Mutex<Option<CancellationToken>>>;
/// The live, mutable application config. Edited via the Settings screen and read
/// (snapshotted) by each scan/clean/services operation so changes take effect.
type SharedConfig = Arc<Mutex<CleantonConfig>>;

thread_local! {
    /// The full set of discovered services, retained on the UI thread so the
    /// Services page can filter and act on rows without re-querying launchd or
    /// Homebrew. Background workers hand back an owned `Vec<Service>` (Send);
    /// the store and every read happen inside the single-threaded Slint event
    /// loop, so an `Rc<RefCell<…>>` is sound here (no value crosses threads).
    static ALL_SERVICES: Rc<RefCell<Vec<Service>>> = Rc::new(RefCell::new(Vec::new()));

    /// Installed applications and the currently reviewed uninstall plan
    /// (Applications tab; UI-thread only, same reasoning as ALL_SERVICES).
    static ALL_APPS: Rc<RefCell<Vec<InstalledApp>>> = Rc::new(RefCell::new(Vec::new()));
    static APP_PLAN: RefCell<Option<UninstallPlan>> = const { RefCell::new(None) };
    /// Installed Homebrew cask tokens (from `brew list --cask`), used to detect
    /// which applications were installed via Homebrew so the uninstall can go
    /// through `brew uninstall --cask` as well.
    static ALL_CASK_TOKENS: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));

    /// The last finished security report, retained on the UI thread so the
    /// Security tab's "Trust" actions can update the baseline from the exact
    /// fingerprints that were scanned (UI-thread only, same reasoning as
    /// ALL_SERVICES). Trusting writes ONLY the baseline metadata file.
    static SECURITY_REPORT: RefCell<Option<cleanton_engine::SecurityReport>> =
        const { RefCell::new(None) };

    /// The live expandable cleanup-plan row model (group headers + item rows),
    /// retained so selection/expand callbacks can mutate single rows in place.
    static PLAN_ROWS: RefCell<Option<Rc<VecModel<PlanListItem>>>> = const { RefCell::new(None) };
    /// Per-row metadata, index-parallel to PLAN_ROWS, mapping each rendered row
    /// back to the underlying plan action(s).
    static PLAN_ROW_META: RefCell<Vec<RowMeta>> = const { RefCell::new(Vec::new()) };
    /// Indices (into the current plan's `actions`) currently selected for cleanup.
    static SELECTED_ACTIONS: RefCell<HashSet<usize>> = RefCell::new(HashSet::new());
    /// Reclaimable bytes per action index, for fast selected-total recomputation.
    static PLAN_ACTION_BYTES: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    /// The live Docker row model, retained for the same reason as PLAN_ROWS.
    static DOCKER_MODEL: RefCell<Option<Rc<VecModel<DockerRow>>>> = const { RefCell::new(None) };
    /// The live Time Machine snapshot row model (Results panel).
    static SNAPSHOT_MODEL: RefCell<Option<Rc<VecModel<SnapshotRow>>>> = const { RefCell::new(None) };
    /// Two-step arm → confirm state for the snapshot panel. Snapshot deletion
    /// is permanent (never Trash), so the armed dates live in the shared engine
    /// state machine and are handed out exactly once on confirm.
    static SNAPSHOT_CONFIRM: RefCell<SnapshotConfirmState> = const { RefCell::new(SnapshotConfirmState::Idle) };

    /// The active manager's inventory, the user's keep-set, and the live row
    /// model for the Packages tab (UI-thread only).
    static PKG_INVENTORY: RefCell<Option<Inventory>> = const { RefCell::new(None) };
    static PKG_KEEP: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
    static PKG_ROWS: RefCell<Option<Rc<VecModel<PackageRow>>>> = const { RefCell::new(None) };
}

/// The package managers shown in the Packages selector, in display order.
const PKG_MANAGER_ORDER: [ManagerKind; 5] = [
    ManagerKind::Homebrew,
    ManagerKind::HomebrewCask,
    ManagerKind::Npm,
    ManagerKind::Pip,
    ManagerKind::MacPorts,
];

/// Maps a rendered cleanup-plan row to the underlying action(s).
enum RowMeta {
    /// A recipe-group header. `action_indices` are ALL the group's actions (even
    /// beyond the shown cap); `first_item_row`/`item_row_count` cover its rendered
    /// child rows (item rows + an optional "+N more" note).
    Group {
        action_indices: Vec<usize>,
        first_item_row: usize,
        item_row_count: usize,
    },
    /// An individual item row under a group.
    Item {
        action_index: usize,
        group_row: usize,
    },
    /// A muted "+N more" note row (not selectable).
    Note,
}

/// Maximum number of service rows rendered at once. The metric-tile totals
/// always reflect the full discovered set; only the rendered list is capped.
const MAX_SERVICE_ROWS: usize = 80;

fn main() -> Result<(), slint::PlatformError> {
    // Initialise tracing (respects CLEANTON_LOG env var).
    let filter = EnvFilter::try_from_env("CLEANTON_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Load application config (uses defaults if file is absent).
    let config = CleantonConfig::load().unwrap_or_default();

    slint::BackendSelector::new().select()?;
    register_embedded_fonts();

    // Create the Slint window and populate immediate in-memory state so the
    // first frame renders without waiting on subprocesses (`tmutil`, `brew`,
    // `npm`, `pip`, `port`) or disk/memory probes.
    let ui = AppWindow::new()?;
    initialise_app_state(&ui, &config);
    apply_fda_state(&ui.global::<AppState>());
    // The config becomes shared + mutable so the Settings screen can edit it and
    // subsequent scans/cleans observe the updated values.
    let shared_config: SharedConfig = Arc::new(Mutex::new(config));
    spawn_startup_probes(ui.as_weak(), shared_config.clone());
    let latest_plan = Arc::new(Mutex::new(None::<CleanupPlan>));
    let current_operation = Arc::new(Mutex::new(None::<CancellationToken>));

    // ── Wire: Start Scan callback ──────────────────────────────────────────
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    let latest_plan_clone = latest_plan.clone();
    let current_operation_clone = current_operation.clone();
    ui.global::<AppCallbacks>().on_start_scan(move || {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        let cancel_token = begin_cancellable_operation(&current_operation_clone);
        state.set_scanning(true);
        state.set_scan_status("Scanning...".into());
        state.set_scan_warning_count("0".into());
        state.set_scan_coverage_status("Scanning".into());
        state.set_scan_progress(0.0);
        state.set_result_mode("Scanning".into());
        clear_plan_state(&state);
        store_latest_plan(&latest_plan_clone, None);

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        let latest_plan = latest_plan_clone.clone();
        let current_operation = current_operation_clone.clone();

        // Spawn the scan on a background thread so the UI stays responsive.
        std::thread::spawn(move || {
            worker_runtime().block_on(async move {
                let (event_tx, mut event_rx) = mpsc::channel::<EngineEvent>(128);

                // Spawn progress updates to the UI.
                let ui_progress = ui_weak.clone();
                let progress_cancel_token = cancel_token.clone();
                let progress_handle = tokio::spawn(async move {
                    while let Some(event) = event_rx.recv().await {
                        if progress_cancel_token.load(Ordering::Relaxed) {
                            break;
                        }
                        if let EngineEvent::ScanProgress {
                            files_scanned,
                            dirs_entered,
                            bytes_seen,
                        } = event
                        {
                            let ui_cancel_token = progress_cancel_token.clone();
                            let _ = ui_progress.upgrade_in_event_loop(move |ui| {
                                if ui_cancel_token.load(Ordering::Relaxed) {
                                    return;
                                }
                                let state = ui.global::<AppState>();
                                state.set_scan_files_count(format!("{files_scanned}").into());
                                state.set_scan_dirs_count(format!("{dirs_entered}").into());
                                state.set_scan_bytes(display::human_bytes(bytes_seen).into());
                            });
                        }
                    }
                });

                // Run the scan, then the ML-aware analysis (annotations, orphan
                // candidates, and the demoted/held set). The cancel token is
                // handed to the scanner so Cancel actually stops the walk
                // instead of letting it burn CPU to completion in the background.
                let engine_cancel = cancel_token.clone();
                let result = async {
                    let orchestrator = Orchestrator::new(config.clone())?;
                    let options = scan_options_from_config(&config);
                    let scan = orchestrator
                        .scan_only_with_cancel(options, event_tx, engine_cancel)
                        .await?;
                    let full = orchestrator.analyze_full(&scan).await;
                    Ok::<_, cleanton_common::CleantonError>((scan, full))
                }
                .await;
                progress_handle.abort();

                // Refresh real disk capacity + resource status (off the UI thread).
                let capacity_view = capacity::read(&capacity_root(&config));
                let resource_status = read_resource_status(&config);

                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    if cancel_token.load(Ordering::Relaxed) {
                        finish_cancellable_operation(&current_operation, &cancel_token);
                        return;
                    }
                    finish_cancellable_operation(&current_operation, &cancel_token);
                    let state = ui.global::<AppState>();
                    state.set_scanning(false);
                    apply_capacity_state(&state, &capacity_view);
                    apply_resource_status(&state, &resource_status);
                    match result {
                        Ok((scan, full)) => {
                            store_latest_plan(&latest_plan, Some(full.analyzed.plan.clone()));
                            apply_scan_result_state(&state, &scan);
                            state.set_scan_progress(1.0);
                            apply_analyzed_full(&state, &full);
                            // The scan is the action; surface the reviewable
                            // Results immediately instead of stranding the user
                            // on the Dashboard.
                            state.set_active_screen(1);
                        }
                        Err(err) => {
                            store_latest_plan(&latest_plan, None);
                            state.set_scan_status(format!("Error: {err}").into());
                            state.set_scan_coverage_status("Scan failed".into());
                            state.set_scan_progress(0.0);
                            state.set_total_reclaimable("Scan failed".into());
                            state.set_result_mode("Scan failed".into());
                        }
                    }
                });
            });
        });
    });

    // ── Wire: Start Clean callback ─────────────────────────────────────────
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    let latest_plan_clone = latest_plan.clone();
    let current_operation_clone = current_operation.clone();
    ui.global::<AppCallbacks>().on_start_clean(move || {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        let cancel_token = begin_cancellable_operation(&current_operation_clone);
        state.set_cleaning(true);
        state.set_clean_status("Preparing cleanup plan...".into());
        state.set_clean_progress(0.0);
        state.set_result_mode("Preparing review".into());
        state.set_scan_coverage_status("Scanning".into());
        state.set_scan_warning_count("0".into());
        clear_plan_state(&state);
        store_latest_plan(&latest_plan_clone, None);

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        let latest_plan = latest_plan_clone.clone();
        let current_operation = current_operation_clone.clone();
        std::thread::spawn(move || {
            worker_runtime().block_on(async move {
                let engine_cancel = cancel_token.clone();
                let result = async {
                    let orchestrator = Orchestrator::new(config.clone())?;
                    let options = scan_options_from_config(&config);
                    let (event_tx, _event_rx) = mpsc::channel::<EngineEvent>(128);
                    let scan = orchestrator
                        .scan_only_with_cancel(options, event_tx, engine_cancel)
                        .await?;
                    let full = orchestrator.analyze_full(&scan).await;
                    Ok::<_, cleanton_common::CleantonError>((scan, full))
                }
                .await;

                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    if cancel_token.load(Ordering::Relaxed) {
                        finish_cancellable_operation(&current_operation, &cancel_token);
                        return;
                    }
                    finish_cancellable_operation(&current_operation, &cancel_token);
                    let state = ui.global::<AppState>();
                    state.set_cleaning(false);
                    match result {
                        Ok((scan, full)) => {
                            store_latest_plan(&latest_plan, Some(full.analyzed.plan.clone()));
                            apply_scan_result_state(&state, &scan);
                            state.set_clean_progress(1.0);
                            let action_count = full.analyzed.plan.actions.len();
                            apply_analyzed_full(&state, &full);
                            state.set_clean_status(
                                format!("Cleanup plan ready for review: {action_count} actions.")
                                    .into(),
                            );
                        }
                        Err(err) => {
                            store_latest_plan(&latest_plan, None);
                            state.set_clean_progress(0.0);
                            state.set_clean_status(format!("Error: {err}").into());
                            state.set_scan_coverage_status("Scan failed".into());
                            state.set_total_reclaimable("Plan failed".into());
                            state.set_result_mode("Plan failed".into());
                        }
                    }
                });
            });
        });
    });

    // ── Wire: Request clean confirmation callback ─────────────────────────
    let ui_weak = ui.as_weak();
    let latest_plan_clone = latest_plan.clone();
    ui.global::<AppCallbacks>()
        .on_request_clean_confirmation(move || {
            let ui = ui_weak.unwrap();
            let state = ui.global::<AppState>();
            if state.get_scanning() || state.get_cleaning() {
                return;
            }

            match load_latest_plan(&latest_plan_clone) {
                Some(plan) if plan.incomplete_scan => {
                    state.set_confirmation_pending(false);
                    state.set_plan_ready(false);
                    state.set_clean_status(
                        "Execution refused: the latest plan was produced from an incomplete scan."
                            .into(),
                    );
                    state.set_result_mode("Incomplete scan".into());
                }
                Some(plan) if plan.actions.is_empty() => {
                    state.set_confirmation_pending(false);
                    state.set_plan_ready(false);
                    state.set_clean_status("Nothing to clean in the latest plan.".into());
                    state.set_result_mode("Empty plan".into());
                }
                Some(plan) => {
                    let selected = selected_action_indices();
                    let selected_bytes: u64 = selected
                        .iter()
                        .filter_map(|&i| plan.actions.get(i).map(|a| a.reclaimable_bytes))
                        .fold(0u64, u64::saturating_add);
                    state.set_confirmation_pending(true);
                    state.set_clean_status(
                        format!(
                            "Confirm cleanup: {} of {} action(s) ({}) selected; \
                             they will move to Trash.",
                            selected.len(),
                            plan.actions.len(),
                            display::human_bytes(selected_bytes)
                        )
                        .into(),
                    );
                    state.set_result_mode(
                        "Confirmation required. Review the actions before continuing.".into(),
                    );
                }
                None => {
                    state.set_confirmation_pending(false);
                    state.set_plan_ready(false);
                    state
                        .set_clean_status("Run a scan or refresh the plan before cleaning.".into());
                    state.set_result_mode("No plan ready".into());
                }
            }
        });

    // ── Wire: Confirm clean callback ──────────────────────────────────────
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    let latest_plan_clone = latest_plan.clone();
    let current_operation_clone = current_operation.clone();
    ui.global::<AppCallbacks>().on_confirm_clean(move || {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        if state.get_scanning() || state.get_cleaning() {
            return;
        }

        let Some(plan) = load_latest_plan(&latest_plan_clone) else {
            state.set_confirmation_pending(false);
            state.set_clean_status("Run a scan or refresh the plan before cleaning.".into());
            state.set_result_mode("No plan ready".into());
            return;
        };

        if plan.incomplete_scan {
            state.set_confirmation_pending(false);
            state.set_plan_ready(false);
            state.set_clean_status(
                "Execution refused: the latest plan was produced from an incomplete scan.".into(),
            );
            state.set_result_mode("Incomplete scan".into());
            return;
        }

        // Execute exactly the items the user ticked — never the whole plan.
        let plan = filter_plan_to_selected(plan, &selected_action_indices());

        if plan.actions.is_empty() {
            state.set_confirmation_pending(false);
            state.set_plan_ready(false);
            state.set_clean_status("Select at least one item to clean.".into());
            state.set_result_mode("Nothing selected".into());
            return;
        }

        state.set_confirmation_pending(false);
        state.set_cleaning(true);
        state.set_clean_progress(0.0);
        state.set_clean_status("Executing confirmed cleanup plan...".into());
        state.set_result_mode("Cleaning".into());
        reset_execution_state(&state);
        let cancel_token = begin_cancellable_operation(&current_operation_clone);

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        let current_operation = current_operation_clone.clone();
        let latest_plan_for_prune = latest_plan_clone.clone();
        std::thread::spawn(move || {
            worker_runtime().block_on(async move {
                let exec_cancel = cancel_token.clone();
                let result = async {
                    let orchestrator = Orchestrator::new(config.clone())?;
                    let total_actions = plan.actions.len() as u64;
                    let (event_tx, mut event_rx) = mpsc::channel::<EngineEvent>(128);

                    let ui_progress = ui_weak.clone();
                    let progress_cancel_token = cancel_token.clone();
                    let progress_handle = tokio::spawn(async move {
                        let mut started = 0_u64;
                        let mut completed = 0_u64;
                        let mut failed = 0_u64;
                        let mut freed = 0_u64;

                        while let Some(event) = event_rx.recv().await {
                            if progress_cancel_token.load(Ordering::Relaxed) {
                                break;
                            }
                            match event {
                                EngineEvent::ActionStarted { .. } => {
                                    started = started.saturating_add(1);
                                }
                                EngineEvent::ActionCompleted { freed: bytes, .. } => {
                                    completed = completed.saturating_add(1);
                                    freed = freed.saturating_add(bytes);
                                }
                                EngineEvent::ActionFailed { .. } => {
                                    completed = completed.saturating_add(1);
                                    failed = failed.saturating_add(1);
                                }
                                _ => {}
                            }

                            let progress = if total_actions == 0 {
                                0.0
                            } else {
                                completed as f32 / total_actions as f32
                            };
                            let ui_cancel_token = progress_cancel_token.clone();
                            let _ = ui_progress.upgrade_in_event_loop(move |ui| {
                                if ui_cancel_token.load(Ordering::Relaxed) {
                                    return;
                                }
                                let state = ui.global::<AppState>();
                                state.set_execution_attempted_count(started as i32);
                                state.set_execution_failed_count(failed as i32);
                                state.set_execution_freed(display::human_bytes(freed).into());
                                state.set_clean_progress(progress);
                            });
                        }
                    });

                    // Honour Cancel during execution: the current action
                    // finishes, the rest are skipped, and the partial result
                    // is reported instead of silently deleting on.
                    let execution =
                        orchestrator.execute_plan_with_cancel(&plan, &event_tx, &exec_cancel);
                    drop(event_tx);
                    let _ = progress_handle.await;
                    execution
                }
                .await;

                // Refresh capacity + resource status so the dashboard reflects freed space.
                let capacity_view = capacity::read(&capacity_root(&config));
                let resource_status = read_resource_status(&config);

                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    // Superseded by a newer operation: drop this result. A user
                    // cancel is different — execution genuinely stopped, and the
                    // partial result records what was already moved to Trash, so
                    // it is applied (and pruned from the list) rather than hidden.
                    let superseded = operation_superseded(&current_operation, &cancel_token);
                    let was_cancelled = cancel_token.load(Ordering::Relaxed);
                    finish_cancellable_operation(&current_operation, &cancel_token);
                    if superseded {
                        return;
                    }
                    let state = ui.global::<AppState>();
                    state.set_cleaning(false);
                    apply_capacity_state(&state, &capacity_view);
                    apply_resource_status(&state, &resource_status);
                    match result {
                        Ok(result) => {
                            apply_execution_result(&state, &result);
                            // Drop the just-cleaned entries so Results no longer
                            // lists them; unselected/failed items remain.
                            prune_executed_actions(&state, &latest_plan_for_prune, &result);
                            if was_cancelled {
                                state.set_clean_status(
                                    "Cleanup cancelled: remaining items were skipped; anything already moved to Trash stays out of the list."
                                        .into(),
                                );
                                state.set_result_mode("Cancelled".into());
                            }
                        }
                        Err(err) => {
                            if was_cancelled {
                                return;
                            }
                            state.set_clean_progress(0.0);
                            state.set_clean_status(
                                format!("Cleanup refused or failed: {err}").into(),
                            );
                            state.set_result_mode("Cleanup failed".into());
                        }
                    }
                });
            });
        });
    });

    // ── Wire: Cancel callback ──────────────────────────────────────────────
    let ui_weak = ui.as_weak();
    let current_operation_clone = current_operation.clone();
    ui.global::<AppCallbacks>().on_cancel_operation(move || {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        if cancel_current_operation(&current_operation_clone) {
            state.set_scanning(false);
            state.set_cleaning(false);
            state.set_confirmation_pending(false);
            state.set_plan_ready(false);
            state.set_scan_status("Cancelled".into());
            state.set_scan_coverage_status("Cancelled".into());
            state.set_clean_status(
                "Cancelling... the in-flight item finishes, remaining items are skipped.".into(),
            );
            state.set_result_mode("Cancelled".into());
        }
    });

    // ── Wire: Request Empty Trash confirmation callback ────────────────────
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_request_empty_trash_confirmation(move || {
            let ui = ui_weak.unwrap();
            let state = ui.global::<AppState>();
            if state.get_scanning() || state.get_cleaning() {
                return;
            }
            state.set_empty_trash_pending(true);
            state.set_trash_status(
                "Empty Trash now? This permanently deletes Trash contents to free space. Confirm to proceed."
                    .into(),
            );
        });

    // ── Wire: Empty Trash callback (user-confirmed; never automatic) ───────
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_empty_trash(move || {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        state.set_empty_trash_pending(false);
        state.set_trash_status("Emptying Trash...".into());

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        std::thread::spawn(move || {
            let result = trash_ops::empty_trash();
            // Re-read capacity + resource status so the dashboard reflects reclaimed space.
            let capacity_view = capacity::read(&capacity_root(&config));
            let resource_status = read_resource_status(&config);
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                let state = ui.global::<AppState>();
                apply_capacity_state(&state, &capacity_view);
                apply_resource_status(&state, &resource_status);
                refresh_trash_state(&state);
                match result {
                    Ok(()) => state.set_trash_status(
                        "Trash emptied. Disk capacity refreshed with reclaimed space.".into(),
                    ),
                    Err(err) => {
                        state.set_trash_status(format!("Could not empty Trash: {err}").into());
                    }
                }
            });
        });
    });

    // ── Wire: Memory reclaim + resource pressure callbacks ─────────────────
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_reclaim_memory(move || {
        let Some(ui) = ui_weak.upgrade() else {
            return;
        };
        let state = ui.global::<AppState>();
        state.set_memory_status(
            "Reclaiming unused allocator pages and refreshing memory...".into(),
        );

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        std::thread::spawn(move || {
            let reclaimed = cleanton_scanner::reclaim_process_memory();
            let status = read_resource_status(&config);
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                let state = ui.global::<AppState>();
                apply_resource_status(&state, &status);
                let note = if reclaimed {
                    "Reclaimed idle allocator pages. Review heavy processes or background services if memory stays elevated."
                } else {
                    "Memory snapshot refreshed. Review heavy processes or background services to free more RAM."
                };
                state.set_memory_status(note.into());
            });
        });
    });

    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_refresh_memory(move || {
        let ui_weak = ui_weak.clone();
        let config = config_snapshot(&config_clone);
        std::thread::spawn(move || {
            let capacity_view = capacity::read(&capacity_root(&config));
            let status = read_resource_status(&config);
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                let state = ui.global::<AppState>();
                apply_capacity_state(&state, &capacity_view);
                apply_resource_status(&state, &status);
            });
        });
    });

    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>().on_dismiss_disk_offer(move || {
        DISK_OFFER_DISMISSED.store(true, Ordering::Relaxed);
        if let Some(ui) = ui_weak.upgrade() {
            ui.global::<AppState>().set_disk_offer_active(false);
        }
    });

    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_dismiss_memory_offer(move || {
            MEMORY_OFFER_DISMISSED.store(true, Ordering::Relaxed);
            if let Some(ui) = ui_weak.upgrade() {
                ui.global::<AppState>().set_memory_offer_active(false);
            }
        });

    // ── Wire: Services refresh callback ────────────────────────────────────
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_refresh_services(move || {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        if state.get_loading_services() {
            return;
        }
        state.set_loading_services(true);
        state.set_services_status("Discovering services...".into());

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        std::thread::spawn(move || {
            worker_runtime().block_on(async move {
                let manager = ServiceManager::new(config);
                let result = manager.list_services().await;
                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    let state = ui.global::<AppState>();
                    state.set_loading_services(false);
                    match result {
                        Ok(services) => set_discovered_services(&state, services),
                        Err(err) => {
                            clear_discovered_services(&state);
                            state.set_services_status(
                                format!("Service discovery failed: {err}").into(),
                            );
                        }
                    }
                });
            });
        });
    });

    // ── Wire: Apply services filter callback ───────────────────────────────
    // Pure UI-thread work: rebuilds the displayed model from the retained full
    // set using the current filter. No background thread, no re-query.
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_apply_service_filter(move || {
            if let Some(ui) = ui_weak.upgrade() {
                refresh_services_view(&ui.global::<AppState>());
            }
        });

    // ── Wire: Disable service callback ─────────────────────────────────────
    // Two-step armed in the UI; the backend independently re-checks protection
    // (defense in depth) and refuses protected/system-critical services even if
    // the UI somehow asked. Mirrors the refresh worker-thread + runtime pattern.
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_disable_service(move |id| {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        let id = id.to_string();

        // Look up the real Service and re-check protection before doing anything.
        let lookup = ALL_SERVICES.with(|cell| {
            cell.borrow()
                .iter()
                .find(|service| service.id == id)
                .map(|service| is_protected(&service.id, &service.plist_path))
        });
        match lookup {
            None => {
                state.set_service_pending_disable_id(SharedString::new());
                state.set_services_status(format!("Service no longer available: {id}").into());
                return;
            }
            Some(true) => {
                state.set_service_pending_disable_id(SharedString::new());
                state.set_services_status(
                    format!("Refused: {id} is protected and cannot be disabled.").into(),
                );
                return;
            }
            Some(false) => {}
        }

        if SERVICE_ACTION_IN_FLIGHT.swap(true, Ordering::SeqCst) {
            state.set_services_status("Another service action is still running.".into());
            return;
        }
        state.set_services_status(format!("Disabling {id}...").into());

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        std::thread::spawn(move || {
            worker_runtime().block_on(async move {
                let disable_result = ServiceManager::new(config.clone())
                    .disable_service(&id)
                    .await;
                // Re-list so the row's status reflects the change without a
                // separate user-triggered refresh.
                let relisted = ServiceManager::new(config).list_services().await;
                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    SERVICE_ACTION_IN_FLIGHT.store(false, Ordering::SeqCst);
                    let state = ui.global::<AppState>();
                    state.set_service_pending_disable_id(SharedString::new());
                    if let Ok(services) = relisted {
                        ALL_SERVICES.with(|cell| *cell.borrow_mut() = services);
                    }
                    // Rebuild rows/totals first, then set the outcome message so
                    // the success/failure text is not overwritten.
                    rebuild_services_model(&state);
                    match disable_result {
                        Ok(()) => state.set_services_status(format!("Disabled {id}.").into()),
                        Err(err) => state
                            .set_services_status(format!("Could not disable {id}: {err}").into()),
                    }
                });
            });
        });
    });

    // ── Wire: Enable service callback ──────────────────────────────────────
    // Non-destructive (single click): re-enable a stopped/disabled startup item
    // so it starts at login/boot again. The backend still refuses protected
    // services as defense in depth.
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_enable_service(move |id| {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        let id = id.to_string();
        if SERVICE_ACTION_IN_FLIGHT.swap(true, Ordering::SeqCst) {
            state.set_services_status("Another service action is still running.".into());
            return;
        }
        state.set_services_status(format!("Enabling {id}...").into());

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        std::thread::spawn(move || {
            worker_runtime().block_on(async move {
                let enable_result = ServiceManager::new(config.clone())
                    .enable_service(&id)
                    .await;
                let relisted = ServiceManager::new(config).list_services().await;
                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    SERVICE_ACTION_IN_FLIGHT.store(false, Ordering::SeqCst);
                    let state = ui.global::<AppState>();
                    if let Ok(services) = relisted {
                        ALL_SERVICES.with(|cell| *cell.borrow_mut() = services);
                    }
                    rebuild_services_model(&state);
                    match enable_result {
                        Ok(()) => state.set_services_status(format!("Enabled {id}.").into()),
                        Err(err) => state
                            .set_services_status(format!("Could not enable {id}: {err}").into()),
                    }
                });
            });
        });
    });

    // ── Wire: Remove orphaned startup item callback ────────────────────────
    // Two-step armed in the UI; the backend permits deletion only when the
    // referenced executable is missing (orphaned leftover) and re-checks
    // protection, backing up the plist before removing it.
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_remove_service(move |id| {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        let id = id.to_string();
        if SERVICE_ACTION_IN_FLIGHT.swap(true, Ordering::SeqCst) {
            state.set_services_status("Another service action is still running.".into());
            return;
        }
        state.set_services_status(format!("Removing {id}...").into());

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        std::thread::spawn(move || {
            worker_runtime().block_on(async move {
                let remove_result = ServiceManager::new(config.clone())
                    .delete_orphaned_plist(&id)
                    .await;
                let relisted = ServiceManager::new(config).list_services().await;
                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    SERVICE_ACTION_IN_FLIGHT.store(false, Ordering::SeqCst);
                    let state = ui.global::<AppState>();
                    state.set_service_pending_remove_id(SharedString::new());
                    if let Ok(services) = relisted {
                        ALL_SERVICES.with(|cell| *cell.borrow_mut() = services);
                    }
                    if remove_result.is_ok() {
                        drop_service_locally(&id);
                    }
                    rebuild_services_model(&state);
                    match remove_result {
                        Ok(()) => state.set_services_status(format!("Removed {id}.").into()),
                        Err(err) => state
                            .set_services_status(format!("Could not remove {id}: {err}").into()),
                    }
                });
            });
        });
    });

    // ── Wire: Delete a disabled service callback ───────────────────────────
    // Two-step armed in the UI. The backend re-checks protection and refuses
    // anything that is still running, Homebrew-managed services, and services
    // whose startup item is already gone. A root-owned plist retries once with
    // the targeted administrator prompt the services adapter already uses.
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_delete_service(move |id| {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        let id = id.to_string();
        if SERVICE_ACTION_IN_FLIGHT.swap(true, Ordering::SeqCst) {
            state.set_services_status("Another service action is still running.".into());
            return;
        }
        state.set_services_status(format!("Deleting startup item for {id}...").into());

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        std::thread::spawn(move || {
            worker_runtime().block_on(async move {
                let manager = ServiceManager::new(config.clone());
                let mut delete_result = manager.delete_disabled_plist(&id).await;
                if matches!(
                    delete_result,
                    Err(cleanton_common::CleantonError::RootPrivilegesRequired(_))
                ) {
                    // Root-owned startup item: ask for admin once, then retry.
                    delete_result = manager.delete_disabled_plist_elevated(&id).await;
                }
                // Re-list so the row disappears without a manual refresh.
                let relisted = ServiceManager::new(config).list_services().await;
                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    SERVICE_ACTION_IN_FLIGHT.store(false, Ordering::SeqCst);
                    let state = ui.global::<AppState>();
                    state.set_service_pending_delete_id(SharedString::new());
                    if let Ok(services) = relisted {
                        ALL_SERVICES.with(|cell| *cell.borrow_mut() = services);
                    }
                    if delete_result.is_ok() {
                        drop_service_locally(&id);
                    }
                    rebuild_services_model(&state);
                    match delete_result {
                        Ok(()) => state.set_services_status(format!("Deleted {id}.").into()),
                        Err(err) => state
                            .set_services_status(format!("Could not delete {id}: {err}").into()),
                    }
                });
            });
        });
    });

    // ── Wire: Security tab (read-only supply-chain scan, baseline + diff) ──
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>().on_start_security_scan(move || {
        if let Some(ui) = ui_weak.upgrade() {
            start_security_scan(&ui, false);
        }
    });

    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_security_establish_baseline(move || {
            if let Some(ui) = ui_weak.upgrade() {
                start_security_scan(&ui, true);
            }
        });

    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_security_trust_package(move |index| {
            if let Some(ui) = ui_weak.upgrade() {
                security_trust(&ui, Some(index));
            }
        });

    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>().on_security_trust_all(move || {
        if let Some(ui) = ui_weak.upgrade() {
            security_trust(&ui, None);
        }
    });

    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_security_request_remove(move |index| {
            if let Some(ui) = ui_weak.upgrade() {
                arm_security_removal(&ui, index);
            }
        });

    let config_clone = shared_config.clone();
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_security_confirm_remove(move |index| {
            if let Some(ui) = ui_weak.upgrade() {
                run_security_removal(&ui, index, &config_clone);
            }
        });

    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_security_cancel_remove(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let state = ui.global::<AppState>();
                state.set_security_pending_remove_index(-1);
                state.set_security_remove_status(SharedString::new());
            }
        });

    // ── Wire: Applications tab ─────────────────────────────────────────────
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>().on_refresh_apps(move || {
        if let Some(ui) = ui_weak.upgrade() {
            start_apps_load(&ui);
        }
    });

    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>().on_apply_app_filter(move || {
        if let Some(ui) = ui_weak.upgrade() {
            rebuild_apps_model(&ui.global::<AppState>());
        }
    });

    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>().on_select_app(move |path| {
        if let Some(ui) = ui_weak.upgrade() {
            start_leftover_scan(&ui, path.as_str());
        }
    });

    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>().on_toggle_leftover(move |idx| {
        let Some(ui) = ui_weak.upgrade() else {
            return;
        };
        let state = ui.global::<AppState>();
        if state.get_uninstalling() {
            return;
        }
        let rows = state.get_leftover_rows();
        let Ok(index) = usize::try_from(idx) else {
            return;
        };
        if let Some(mut row) = rows.row_data(index)
            && !row.admin
        {
            row.selected = !row.selected;
            rows.set_row_data(index, row);
        }
    });

    // Uninstall: fires only from the two-step Confirm in the review panel.
    // Best-effort stops the app's user launch agents, then moves every
    // selected item through the executor's uninstall-scoped trash path.
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_confirm_uninstall(move || {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        state.set_uninstall_pending(false);
        if UNINSTALL_IN_FLIGHT.swap(true, Ordering::SeqCst) {
            state.set_apps_status("An uninstall is already running.".into());
            return;
        }

        // Selected paths in review order. Admin-owned items are included: the
        // executor asks for administrator rights once per run and still moves
        // them into the user's Trash, which is the only way an App Store bundle
        // (root-owned in /Applications) can actually be uninstalled here.
        let rows = state.get_leftover_rows();
        let selected_paths: HashSet<String> = rows
            .iter()
            .filter(|row| row.selected)
            .map(|row| row.path.to_string())
            .collect();
        let (paths, agent_labels) = APP_PLAN.with(|cell| {
            let plan = cell.borrow();
            let Some(plan) = plan.as_ref() else {
                return (Vec::new(), Vec::new());
            };
            let paths: Vec<PathBuf> = plan
                .items
                .iter()
                .filter(|item| selected_paths.contains(&item.path.display().to_string()))
                .map(|item| item.path.clone())
                .collect();
            // Only the app's user launch agents are stopped; a LaunchDaemon
            // needs administrator rights and dies when the uninstall removes it.
            let labels: Vec<String> = plan
                .items
                .iter()
                .filter(|item| {
                    !item.admin_required
                        && selected_paths.contains(&item.path.display().to_string())
                })
                .filter_map(|item| item.launchd_label.clone())
                .collect();
            (paths, labels)
        });
        if paths.is_empty() {
            UNINSTALL_IN_FLIGHT.store(false, Ordering::SeqCst);
            state.set_apps_status("Nothing selected to uninstall.".into());
            return;
        }

        // If this app was installed via a Homebrew cask, remove it through brew
        // too so Homebrew's records stay consistent (it also removes the app
        // bundle; our leftover pass then clears what brew leaves behind).
        let cask_token = APP_PLAN.with(|cell| {
            cell.borrow().as_ref().and_then(|plan| {
                // Record the bundle path so the removal watcher doesn't treat
                // this Cleanton-initiated removal as an external one.
                if let Ok(mut removed) = CLEANTON_REMOVED_BUNDLES.lock() {
                    removed.insert(plan.app.path.clone());
                }
                let tokens = ALL_CASK_TOKENS.with(|t| t.borrow().clone());
                cask_token_for(&plan.app, &tokens)
            })
        });

        let app_name = state.get_selected_app_name().to_string();
        state.set_uninstalling(true);
        state.set_apps_status(format!("Uninstalling {app_name}...").into());

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        std::thread::spawn(move || {
            worker_runtime().block_on(async move {
                // Best-effort: stop the app's user launch agents so trashing
                // their plists leaves no running job behind. Failures are
                // non-fatal (the job dies at next login regardless).
                for label in &agent_labels {
                    let _ = ServiceManager::new(config.clone())
                        .stop_service(label)
                        .await;
                }

                // Homebrew cask removal first (best-effort): brew moves the app
                // bundle to the Trash and drops its own records. A failure here
                // (app running, cask already gone) is non-fatal — the leftover
                // trash pass below still runs.
                let brew_note = if let Some(token) = &cask_token {
                    let outcome = PackageManagers::uninstall(
                        ManagerKind::HomebrewCask,
                        std::slice::from_ref(token),
                    )
                    .await;
                    if outcome.ok {
                        " (also removed via Homebrew)"
                    } else {
                        " (Homebrew removal failed; trashed directly)"
                    }
                } else {
                    ""
                };

                let result = async {
                    let orchestrator = Orchestrator::new(config)?;
                    let (event_tx, _event_rx) = mpsc::channel::<EngineEvent>(64);
                    orchestrator.uninstall_app_items(&paths, &event_tx)
                }
                .await;

                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    UNINSTALL_IN_FLIGHT.store(false, Ordering::SeqCst);
                    let state = ui.global::<AppState>();
                    state.set_uninstalling(false);
                    match result {
                        Ok(result) => {
                            let moved = result
                                .actions
                                .iter()
                                .filter(|a| a.status == ExecutionStatus::MovedToTrash)
                                .count();
                            let failed = result
                                .actions
                                .iter()
                                .filter(|a| a.status == ExecutionStatus::Failed)
                                .count();
                            let remaining = result
                                .actions
                                .iter()
                                .filter(|a| a.status == ExecutionStatus::Skipped)
                                .count();
                            // The first failure reason is the actionable part; the
                            // rest are usually the same cause (admin rights).
                            let first_failure = result
                                .actions
                                .iter()
                                .find(|a| a.status == ExecutionStatus::Failed)
                                .map(|a| a.message.clone())
                                .unwrap_or_default();

                            let mut status = format!(
                                "Moved {moved} item(s) of {app_name} to the Trash ({}){brew_note}.",
                                display::human_bytes(result.moved_to_trash_bytes),
                            );
                            if failed > 0 {
                                status.push_str(&format!(
                                    " {failed} item(s) could not be removed: {first_failure}"
                                ));
                            }
                            if remaining > 0 {
                                status.push_str(&format!(" {remaining} skipped."));
                            }
                            state.set_apps_status(status.as_str().into());

                            if moved == 0 || failed > 0 {
                                // Something is still on disk: keep the review
                                // panel (an empty panel looked like "nothing
                                // happened") and refresh the leftover list so the
                                // user sees exactly what remains.
                                start_apps_load(&ui);
                                let path = state.get_selected_app_path().to_string();
                                if !path.is_empty() {
                                    start_leftover_scan(&ui, path.as_str());
                                }
                            } else {
                                // Everything selected is gone: clear the review
                                // panel and reload the inventory.
                                state.set_selected_app_path(SharedString::new());
                                state.set_selected_app_name(SharedString::new());
                                state.set_leftover_count(0);
                                state.set_leftover_rows(ModelRc::from(Rc::new(VecModel::from(
                                    Vec::<LeftoverRow>::new(),
                                ))));
                                APP_PLAN.with(|cell| *cell.borrow_mut() = None);
                                start_apps_load(&ui);
                            }
                        }
                        Err(err) => {
                            state.set_apps_status(
                                format!("Uninstall refused or failed: {err}").into(),
                            );
                        }
                    }
                });
            });
        });
    });

    // ── Wire: Open Full Disk Access settings callback ──────────────────────
    // Gated behind an explicit user click. Deep-links to the correct pane.
    ui.global::<AppCallbacks>().on_open_fda_settings(move || {
        open_fda_settings();
    });

    // ── Wire: Dismiss Full Disk Access banner callback ─────────────────────
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>().on_dismiss_fda(move || {
        if let Some(ui) = ui_weak.upgrade() {
            ui.global::<AppState>().set_fda_needs_attention(false);
        }
    });

    // ── Wire: Save settings callback ───────────────────────────────────────
    // Reads the edited controls back into the live config, applies them to the
    // running app (so the next scan uses them), and persists to disk. Never
    // panics — a failed save surfaces in the status line.
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_save_settings(move || {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();

        let mut updated = config_snapshot(&config_clone);
        read_settings_into_config(&state, &mut updated);
        store_config(&config_clone, updated.clone());

        // Keep the dashboard's displayed scan root in sync with the new value.
        state.set_scan_root(updated.general.default_root.display().to_string().into());
        // Echo the normalized values back into the controls.
        populate_settings(&state, &updated);

        match updated.save() {
            Ok(()) => {
                let location = CleantonConfig::config_path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "config file".to_owned());
                state.set_setting_save_status(format!("Saved to {location}").into());
            }
            Err(err) => {
                state.set_setting_save_status(format!("Save failed: {err}").into());
            }
        }

        // Re-evaluate pressure offers immediately against the updated thresholds.
        DISK_OFFER_DISMISSED.store(false, Ordering::Relaxed);
        MEMORY_OFFER_DISMISSED.store(false, Ordering::Relaxed);
        let ui_weak = ui.as_weak();
        std::thread::spawn(move || {
            let status = read_resource_status(&updated);
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                apply_resource_status(&ui.global::<AppState>(), &status);
            });
        });
    });

    // ── Wire: Reset settings callback ──────────────────────────────────────
    // Restores built-in defaults in both the controls and the running config.
    // The change is not written to disk until Save is pressed.
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_reset_settings(move || {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();

        let defaults = CleantonConfig::default();
        store_config(&config_clone, defaults.clone());
        populate_settings(&state, &defaults);
        state.set_scan_root(defaults.general.default_root.display().to_string().into());
        state.set_setting_save_status("Defaults restored. Click Save to persist.".into());
    });

    // ── Wire: cleanup-plan expand / selection callbacks ────────────────────
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>().on_plan_row_expand(move |idx| {
        if let Some(ui) = ui_weak.upgrade() {
            plan_row_expand(&ui.global::<AppState>(), idx);
        }
    });
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>().on_plan_row_toggle(move |idx| {
        if let Some(ui) = ui_weak.upgrade() {
            plan_row_toggle(&ui.global::<AppState>(), idx);
        }
    });
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_set_all_plan_selection(move |all| {
            if let Some(ui) = ui_weak.upgrade() {
                set_all_plan_selection(&ui.global::<AppState>(), all);
            }
        });

    // ── Wire: Docker selection + clean ─────────────────────────────────────
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_toggle_docker_selection(move |idx| {
            if let Some(ui) = ui_weak.upgrade() {
                toggle_docker_selection(&ui.global::<AppState>(), idx);
            }
        });
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_clean_docker(move || {
        let ui = ui_weak.unwrap();
        let state = ui.global::<AppState>();
        if state.get_docker_cleaning() || state.get_scanning() || state.get_cleaning() {
            return;
        }
        let Some(plan) = selected_docker_plan(&state) else {
            state.set_docker_status("Select at least one Docker target to clean.".into());
            return;
        };
        state.set_docker_cleaning(true);
        state.set_docker_status("Cleaning Docker...".into());

        let ui_weak = ui.as_weak();
        let config = config_snapshot(&config_clone);
        std::thread::spawn(move || {
            worker_runtime().block_on(async move {
                let result = async {
                    let cleaner = DockerCleaner::new()?;
                    let cleaned = cleaner.clean(plan).await?;
                    let refreshed = cleaner.analyze().await.ok();
                    Ok::<_, cleanton_common::CleantonError>((cleaned, refreshed))
                }
                .await;
                let capacity_view = capacity::read(&capacity_root(&config));
                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    let state = ui.global::<AppState>();
                    state.set_docker_cleaning(false);
                    apply_capacity_state(&state, &capacity_view);
                    match result {
                        Ok((cleaned, refreshed)) => {
                            if let Some(analysis) = refreshed {
                                apply_docker_state(&state, &analysis);
                            }
                            state.set_docker_status(
                                format!(
                                    "Docker cleanup freed {}.",
                                    display::human_bytes(cleaned.total_freed)
                                )
                                .into(),
                            );
                        }
                        Err(err) => {
                            state.set_docker_status(format!("Docker cleanup failed: {err}").into());
                        }
                    }
                });
            });
        });
    });

    // ── Wire: Time Machine snapshot review + confirm-gated deletion ────────
    // Deleting an APFS snapshot is the one Cleanton flow that cannot go to the
    // Trash, so it is double-gated: select rows, arm with "Delete selected",
    // then explicitly confirm the permanent deletion.
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_toggle_snapshot_selection(move |idx| {
            if let Some(ui) = ui_weak.upgrade() {
                toggle_snapshot_selection(&ui.global::<AppState>(), idx);
            }
        });
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_request_snapshot_delete(move || {
            if let Some(ui) = ui_weak.upgrade() {
                request_snapshot_delete(&ui.global::<AppState>());
            }
        });
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_cancel_snapshot_delete(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let state = ui.global::<AppState>();
                SNAPSHOT_CONFIRM.with(|cell| cell.borrow_mut().cancel());
                state.set_snapshot_delete_pending(false);
                state.set_snapshot_status(
                    "Snapshot deletion cancelled. Nothing was removed.".into(),
                );
            }
        });
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>()
        .on_confirm_snapshot_delete(move || {
            let ui = ui_weak.unwrap();
            let state = ui.global::<AppState>();
            if state.get_snapshot_deleting() || state.get_scanning() || state.get_cleaning() {
                return;
            }
            // Second step of the two-step confirm: take the armed dates exactly
            // once. If nothing is armed this is a no-op.
            let Some(dates) = SNAPSHOT_CONFIRM.with(|cell| cell.borrow_mut().confirm()) else {
                state.set_snapshot_delete_pending(false);
                return;
            };
            if SNAPSHOT_DELETE_IN_FLIGHT.swap(true, Ordering::SeqCst) {
                state.set_snapshot_status("A snapshot deletion is still running.".into());
                return;
            }
            state.set_snapshot_delete_pending(false);
            state.set_snapshot_deleting(true);
            state.set_snapshot_status(
                format!("Deleting {} snapshot(s) via tmutil...", dates.len()).into(),
            );

            let ui_weak = ui.as_weak();
            let config = config_snapshot(&config_clone);
            std::thread::spawn(move || {
                // Runs only after the explicit two-step confirmation above; the
                // engine adapter re-validates every date and never retries.
                let result = delete_local_snapshots(&dates);
                // Re-read capacity + snapshot listing so the panel and the
                // purgeable figure reflect reality, not our expectation.
                let capacity_view = capacity::read(&capacity_root(&config));
                let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                    SNAPSHOT_DELETE_IN_FLIGHT.store(false, Ordering::SeqCst);
                    let state = ui.global::<AppState>();
                    state.set_snapshot_deleting(false);
                    apply_capacity_state(&state, &capacity_view);
                    state.set_snapshot_status(result.status_message().into());
                });
            });
        });

    // ── Wire: Reveal in Finder (review-only; never deletes) ────────────────
    ui.global::<AppCallbacks>()
        .on_reveal_in_finder(move |path| reveal_in_finder(path.as_str()));

    // ── Wire: Delete a single suggestion (user-confirmed Trash) ────────────
    // Suggestions are review-only and never auto-removed; this fires only after
    // the two-step Confirm. It reuses the engine executor's guards (protected
    // paths, Trash-by-default) via `Orchestrator::trash_suggestion`.
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>()
        .on_delete_suggestion(move |path| {
            let ui = ui_weak.unwrap();
            let state = ui.global::<AppState>();
            let path = path.to_string();
            if path.is_empty() {
                return;
            }
            if SUGGESTION_DELETE_IN_FLIGHT.swap(true, Ordering::SeqCst) {
                state.set_trash_status("A suggestion trash is still running.".into());
                return;
            }
            state.set_trash_status(format!("Moving {path} to the Trash...").into());

            let ui_weak = ui.as_weak();
            let config = config_snapshot(&config_clone);
            std::thread::spawn(move || {
                worker_runtime().block_on(async move {
                    let target = PathBuf::from(&path);
                    let result = async {
                        let orchestrator = Orchestrator::new(config)?;
                        let (event_tx, _event_rx) = mpsc::channel::<EngineEvent>(16);
                        orchestrator.trash_suggestion(&target, &event_tx)
                    }
                    .await;
                    let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                        SUGGESTION_DELETE_IN_FLIGHT.store(false, Ordering::SeqCst);
                        let state = ui.global::<AppState>();
                        match result {
                            Ok(_) => {
                                remove_suggestion_row(&state, &path);
                                state
                                    .set_trash_status(format!("Moved {path} to the Trash.").into());
                                state.set_trash_has_items(true);
                            }
                            Err(err) => state
                                .set_trash_status(format!("Could not trash {path}: {err}").into()),
                        }
                    });
                });
            });
        });

    // ── Wire: Packages tab ─────────────────────────────────────────────────
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_refresh_packages(move || {
        if let Some(ui) = ui_weak.upgrade() {
            let idx = ui.global::<AppState>().get_active_package_tab();
            start_package_load(&ui, idx, &config_clone);
        }
    });
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>()
        .on_select_package_manager(move |idx| {
            if let Some(ui) = ui_weak.upgrade() {
                ui.global::<AppState>().set_active_package_tab(idx);
                start_package_load(&ui, idx, &config_clone);
            }
        });
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_toggle_package_keep(move |idx| {
            if let Some(ui) = ui_weak.upgrade() {
                toggle_package_keep(&ui.global::<AppState>(), idx);
            }
        });
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_set_all_package_keep(move |keep_all| {
            if let Some(ui) = ui_weak.upgrade() {
                set_all_package_keep(&ui.global::<AppState>(), keep_all);
            }
        });
    let ui_weak = ui.as_weak();
    ui.global::<AppCallbacks>()
        .on_request_remove_packages(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let state = ui.global::<AppState>();
                if state.get_package_removable_count() > 0 && !state.get_package_acting() {
                    state.set_package_remove_pending(true);
                    state.set_package_action_status(
                        "Confirm to uninstall the unkept packages. This cannot be undone via Trash."
                            .into(),
                    );
                }
            }
        });
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>()
        .on_confirm_remove_packages(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let order = PKG_INVENTORY.with(|cell| {
                    let keep = PKG_KEEP.with(|k| k.borrow().clone());
                    cell.borrow()
                        .as_ref()
                        .map(|inv| plan_removal(inv, &keep).uninstall_order)
                        .unwrap_or_default()
                });
                ui.global::<AppState>().set_package_remove_pending(false);
                if !order.is_empty() {
                    run_package_action(&ui, &config_clone, PkgAction::Uninstall(order));
                }
            }
        });
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_update_package(move |name| {
        if let Some(ui) = ui_weak.upgrade() {
            run_package_action(
                &ui,
                &config_clone,
                PkgAction::Update(vec![name.to_string()]),
            );
        }
    });
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_update_all_packages(move || {
        if let Some(ui) = ui_weak.upgrade() {
            run_package_action(&ui, &config_clone, PkgAction::Update(Vec::new()));
        }
    });
    let ui_weak = ui.as_weak();
    let config_clone = shared_config.clone();
    ui.global::<AppCallbacks>().on_clean_package_cache(move || {
        if let Some(ui) = ui_weak.upgrade() {
            run_package_action(&ui, &config_clone, PkgAction::CleanCache);
        }
    });

    // ── Watch for apps removed outside Cleanton + resource pressure ───────
    // Light background polls for externally-removed apps and high disk/memory
    // usage so cleanup offers surface automatically even while idle.
    spawn_app_removal_watcher(ui.as_weak());
    spawn_resource_pressure_watcher(ui.as_weak(), shared_config.clone());

    // ── Run the event loop ─────────────────────────────────────────────────
    ui.run()
}

/// Offload startup probes (`PackageManagers::detect`, `capacity::read`,
/// `snapshot_resource_status`, and Trash check) from `main()` so the window
/// paints immediately.
fn spawn_startup_probes(ui_weak: slint::Weak<AppWindow>, shared_config: SharedConfig) {
    std::thread::spawn(move || {
        let config = config_snapshot(&shared_config);
        let has_trash = trash_ops::trash_has_items();
        let detected = PackageManagers::detect();
        let capacity_view = capacity::read(&capacity_root(&config));
        let resource_status = read_resource_status(&config);
        let _ = ui_weak.upgrade_in_event_loop(move |ui| {
            let state = ui.global::<AppState>();
            state.set_trash_has_items(has_trash);
            if !has_trash && !state.get_empty_trash_pending() {
                state.set_trash_status("Trash is empty: nothing to reclaim there.".into());
            }
            apply_detected_package_tabs(&state, &detected);
            apply_capacity_state(&state, &capacity_view);
            apply_resource_status(&state, &resource_status);
        });
    });
}

/// Periodic background monitor for high disk or memory usage.
fn spawn_resource_pressure_watcher(ui_weak: slint::Weak<AppWindow>, shared_config: SharedConfig) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(30));
            let config = config_snapshot(&shared_config);
            let status = read_resource_status(&config);
            if ui_weak
                .upgrade_in_event_loop(move |ui| {
                    apply_resource_status(&ui.global::<AppState>(), &status);
                })
                .is_err()
            {
                break;
            }
        }
    });
}

fn read_resource_status(config: &CleantonConfig) -> ResourceStatus {
    let (disk_pct, mem_pct) = if config.background.enabled {
        (
            config.background.disk_pressure_percent,
            config.background.memory_pressure_percent,
        )
    } else {
        (0, 0)
    };
    snapshot_resource_status(disk_pct, mem_pct)
}

fn apply_resource_status(state: &AppState, status: &ResourceStatus) {
    if status.memory_total_bytes > 0 {
        let total = status.memory_total_bytes;
        let available = status.memory_available_bytes;
        let pct = status.memory_used_percent;
        let used = total.saturating_sub(available);
        let ratio = (used as f64 / total as f64) as f32;
        state.set_memory_ready(true);
        state.set_memory_total(display::human_bytes(total).into());
        state.set_memory_used(format!("{} ({pct}%)", display::human_bytes(used)).into());
        state.set_memory_available(display::human_bytes(available).into());
        state.set_memory_used_ratio(ratio.clamp(0.0, 1.0));
    } else {
        state.set_memory_ready(false);
        state.set_memory_total("--".into());
        state.set_memory_used("Unavailable".into());
        state.set_memory_available("--".into());
        state.set_memory_used_ratio(0.0);
    }

    // Re-arm dismissed banners once usage drops comfortably below threshold.
    if status.disk_offer.is_none() {
        DISK_OFFER_DISMISSED.store(false, Ordering::Relaxed);
    }
    if status.memory_offer.is_none() {
        MEMORY_OFFER_DISMISSED.store(false, Ordering::Relaxed);
    }

    if let Some((advice, offer)) = &status.disk_offer
        && !DISK_OFFER_DISMISSED.load(Ordering::Relaxed)
    {
        let pct = status.disk_used_percent;
        let avail = display::human_bytes(status.disk_available_bytes);
        state.set_disk_offer_headline(
            format!("Disk usage is high ({pct}% used, {avail} free) - disk cleanup recommended")
                .into(),
        );
        let detail = match offer {
            CleanupOffer::Disk {
                estimated_reclaimable_bytes,
                candidates,
            } if *estimated_reclaimable_bytes > 0 => {
                let top = candidates
                    .iter()
                    .take(3)
                    .map(|c| format!("{} ({})", c.label, display::human_bytes(c.bytes)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "Detected ~{} in quick-relief targets ({top}). Run Scan & Review to move safe caches and build artifacts to the Trash.",
                    display::human_bytes(*estimated_reclaimable_bytes),
                )
            }
            _ => advice.clone(),
        };
        state.set_disk_offer_detail(detail.into());
        state.set_disk_offer_active(true);
    } else {
        state.set_disk_offer_active(false);
    }

    if let Some((advice, offer)) = &status.memory_offer
        && !MEMORY_OFFER_DISMISSED.load(Ordering::Relaxed)
    {
        let pct = status.memory_used_percent;
        let avail = display::human_bytes(status.memory_available_bytes);
        state.set_memory_offer_headline(
            format!(
                "Memory usage is high ({pct}% used, {avail} available) - memory cleanup recommended"
            )
            .into(),
        );
        let detail = match offer {
            CleanupOffer::Memory { top_processes, .. } if !top_processes.is_empty() => {
                let top = top_processes
                    .iter()
                    .take(4)
                    .map(|p| format!("{} ({})", p.name, display::human_bytes(p.rss_bytes)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "Top resident processes: {top}. Reclaim idle allocator pages or review running background services."
                )
            }
            _ => advice.clone(),
        };
        state.set_memory_offer_detail(detail.into());
        state.set_memory_offer_active(true);
    } else {
        state.set_memory_offer_active(false);
    }
}

/// Background thread that polls for externally-removed apps and, on detection,
/// deep-links the UI to review their leftovers. Runs for the app's lifetime.
fn spawn_app_removal_watcher(ui_weak: slint::Weak<AppWindow>) {
    std::thread::spawn(move || {
        let mut watcher = cleanton_engine::AppRemovalWatcher::new();
        loop {
            std::thread::sleep(Duration::from_secs(4));
            let removed = watcher.poll();
            if removed.is_empty() {
                continue;
            }
            // Deliver on the UI thread; handle the first non-self-initiated
            // removal (avoid clobbering the review panel with several at once).
            if ui_weak
                .upgrade_in_event_loop(move |ui| {
                    for app in removed {
                        handle_external_removal(&ui, app);
                    }
                })
                .is_err()
            {
                // The event loop is gone (app closing): stop watching.
                break;
            }
        }
    });
}

/// A mutating package action dispatched to a background runtime.
enum PkgAction {
    Uninstall(Vec<String>),
    Update(Vec<String>),
    CleanCache,
}

fn active_package_manager(idx: i32) -> ManagerKind {
    usize::try_from(idx)
        .ok()
        .and_then(|i| PKG_MANAGER_ORDER.get(i).copied())
        .unwrap_or(ManagerKind::Homebrew)
}

/// Dev roots scanned for codebase-usage of packages: the configured scan root
/// plus the usual project homes, de-duplicated to those that exist.
fn package_scan_roots(config: &CleantonConfig) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if p.is_dir() && !roots.contains(&p) {
            roots.push(p);
        }
    };
    push(cleanton_common::paths::expand_tilde(
        &config.general.default_root,
    ));
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        for sub in [
            "GitHub",
            "Projects",
            "Developer",
            "dev",
            "code",
            "src",
            "work",
        ] {
            push(home.join(sub));
        }
    }
    roots
}

/// Kick off a background inventory load (+ usage scan for Homebrew) for the
/// manager at `idx`, then apply it on the UI thread.
fn start_package_load(ui: &AppWindow, idx: i32, config: &SharedConfig) {
    let state = ui.global::<AppState>();
    if state.get_package_acting() {
        return;
    }
    let kind = active_package_manager(idx);
    state.set_package_loading(true);
    state.set_package_usage_scanning(false);
    state.set_package_remove_pending(false);
    state.set_package_action_status(String::new().into());
    state.set_package_note(String::new().into());
    state.set_package_status(format!("Reading {} inventory...", kind.label()).into());

    // Clear the previous manager's list immediately so it doesn't linger while
    // the new inventory loads.
    state.set_package_rows(ModelRc::from(Rc::new(VecModel::from(
        Vec::<PackageRow>::new(),
    ))));
    state.set_package_count(0);
    state.set_package_total_size("0 B".into());
    state.set_package_outdated_count(0);
    state.set_package_removable_count(0);
    state.set_package_reclaimable("0 B".into());
    state.set_package_kept_dep_count(0);
    PKG_ROWS.with(|cell| *cell.borrow_mut() = None);
    PKG_INVENTORY.with(|cell| *cell.borrow_mut() = None);
    PKG_KEEP.with(|cell| cell.borrow_mut().clear());

    let load_id = PACKAGE_LOAD_ID.fetch_add(1, Ordering::SeqCst) + 1;
    let ui_weak = ui.as_weak();
    let roots = package_scan_roots(&config_snapshot(config));
    std::thread::spawn(move || {
        worker_runtime().block_on(async move {
            // Phase 1 — read the inventory and SHOW it immediately. The slow,
            // network-bound update check runs separately in phase 2.
            let inventory = PackageManagers::inventory(kind).await;
            if PACKAGE_LOAD_ID.load(Ordering::SeqCst) != load_id {
                return;
            }
            let any = !inventory.packages.is_empty();
            let do_usage = matches!(kind, ManagerKind::Homebrew) && any;
            let names: Vec<String> = if do_usage {
                inventory.packages.iter().map(|p| p.name.clone()).collect()
            } else {
                Vec::new()
            };
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                if PACKAGE_LOAD_ID.load(Ordering::SeqCst) != load_id {
                    return;
                }
                let state = ui.global::<AppState>();
                state.set_package_loading(false);
                apply_inventory(&state, inventory);
                if any {
                    // Reuse the usage-scanning flag to drive the spinner and gate
                    // "Remove unkept" until the background probes finish.
                    state.set_package_usage_scanning(true);
                    state.set_package_action_status(
                        if do_usage {
                            "Checking for updates and which packages your codebases use..."
                        } else {
                            "Checking for available updates..."
                        }
                        .into(),
                    );
                }
            });

            if !any {
                return;
            }

            // Phase 2 — slow probes: update check (every manager) plus the
            // codebase-usage scan (Homebrew only). Fill the list in progressively.
            let outdated = PackageManagers::outdated(kind).await;
            if PACKAGE_LOAD_ID.load(Ordering::SeqCst) != load_id {
                return;
            }
            let usage = if do_usage {
                scan_usage(&names, &roots)
            } else {
                HashMap::new()
            };
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                if PACKAGE_LOAD_ID.load(Ordering::SeqCst) != load_id {
                    return;
                }
                let state = ui.global::<AppState>();
                let update_count = apply_outdated(&state, &outdated);
                if do_usage {
                    apply_usage(&state, &usage);
                }
                state.set_package_usage_scanning(false);
                let flagged = usage.values().filter(|v| !v.is_empty()).count();
                let updates = if update_count == 1 {
                    "1 update available".to_owned()
                } else {
                    format!("{update_count} updates available")
                };
                state.set_package_action_status(
                    if flagged > 0 {
                        format!("{updates} · {flagged} package(s) referenced by your codebases; see warnings.")
                    } else {
                        updates
                    }
                    .into(),
                );
            });
        });
    });
}

/// Fill in update targets on the already-displayed package list once the
/// (slow, network-bound) update check completes. Returns how many installed
/// packages have an update available, for the "Outdated" summary tile.
fn apply_outdated(state: &AppState, outdated: &HashMap<String, String>) -> usize {
    let mut count: usize = 0;
    PKG_INVENTORY.with(|cell| {
        if let Some(inv) = cell.borrow_mut().as_mut() {
            for pkg in &mut inv.packages {
                pkg.outdated_to = outdated.get(&pkg.name).cloned();
                if pkg.outdated_to.is_some() {
                    count = count.saturating_add(1);
                }
            }
        }
    });
    if let Some(model) = PKG_ROWS.with(|cell| cell.borrow().clone()) {
        for i in 0..model.row_count() {
            if let Some(mut row) = model.row_data(i) {
                let latest = outdated.get(row.name.as_str()).cloned().unwrap_or_default();
                row.outdated = SharedString::from(latest);
                model.set_row_data(i, row);
            }
        }
    }
    state.set_package_outdated_count(clamp_to_i32(count));
    count
}

/// Fill in codebase-usage warnings on the already-displayed package list.
fn apply_usage(state: &AppState, usage: &HashMap<String, Vec<PathBuf>>) {
    PKG_INVENTORY.with(|cell| {
        if let Some(inv) = cell.borrow_mut().as_mut() {
            for pkg in &mut inv.packages {
                if let Some(paths) = usage.get(&pkg.name) {
                    pkg.used_by = paths.iter().map(|p| p.display().to_string()).collect();
                }
            }
        }
    });
    let _ = state;
    if let Some(model) = PKG_ROWS.with(|cell| cell.borrow().clone()) {
        for i in 0..model.row_count() {
            if let Some(mut row) = model.row_data(i)
                && let Some(paths) = usage.get(row.name.as_str())
                && let Some(first) = paths.first()
            {
                row.used_by_count = clamp_to_i32(paths.len());
                row.used_by = SharedString::from(home_relative(&first.display().to_string()));
                model.set_row_data(i, row);
            }
        }
    }
}

/// Run a mutating package action on a background runtime, then reload inventory.
fn run_package_action(ui: &AppWindow, config: &SharedConfig, action: PkgAction) {
    let state = ui.global::<AppState>();
    if state.get_package_acting() || state.get_package_loading() {
        return;
    }
    let idx = state.get_active_package_tab();
    let kind = active_package_manager(idx);
    state.set_package_acting(true);
    let acting_msg = match &action {
        PkgAction::Uninstall(names) => format!("Uninstalling {} package(s)...", names.len()),
        PkgAction::Update(names) if names.is_empty() => {
            "Updating all outdated packages... (this can take a while)".to_owned()
        }
        PkgAction::Update(names) => {
            format!("Updating {}... (this can take a while)", names.join(", "))
        }
        PkgAction::CleanCache => "Cleaning cache...".to_owned(),
    };
    // Surface in both the action line (with spinner) and the header status.
    state.set_package_action_status(acting_msg.clone().into());
    state.set_package_status(acting_msg.into());

    let ui_weak = ui.as_weak();
    let config = config.clone();
    std::thread::spawn(move || {
        worker_runtime().block_on(async move {
            let outcome = match &action {
                PkgAction::Uninstall(names) => PackageManagers::uninstall(kind, names).await,
                PkgAction::Update(names) => PackageManagers::update(kind, names).await,
                PkgAction::CleanCache => PackageManagers::clean_cache(kind).await,
            };
            let summary = if outcome.freed_bytes > 0 {
                format!(
                    "{} (freed {})",
                    outcome.message,
                    display::human_bytes(outcome.freed_bytes)
                )
            } else {
                outcome.message.clone()
            };
            let capacity_view = capacity::read(&capacity_root(&config_snapshot(&config)));
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                let state = ui.global::<AppState>();
                state.set_package_acting(false);
                state.set_package_action_status(summary.into());
                apply_capacity_state(&state, &capacity_view);
                // Reload inventory so the list reflects the change.
                start_package_load(&ui, idx, &config);
            });
        });
    });
}

/// Apply a freshly loaded inventory: retain it, default the keep-set to ALL
/// packages, build the row model, and recompute the removal plan + summary.
fn apply_inventory(state: &AppState, inventory: Inventory) {
    let supports_keepset = matches!(inventory.manager, ManagerKind::Homebrew);
    let total_size: u64 = inventory.packages.iter().map(|p| p.size_bytes).sum();
    let outdated = inventory
        .packages
        .iter()
        .filter(|p| p.outdated_to.is_some())
        .count();
    state.set_package_count(clamp_to_i32(inventory.packages.len()));
    state.set_package_total_size(display::human_bytes(total_size).into());
    state.set_package_outdated_count(clamp_to_i32(outdated));
    state.set_package_supports_keepset(supports_keepset);
    state.set_package_status(package_status_text(&inventory));
    state.set_package_note(inventory.note.clone().unwrap_or_default().into());

    // Default: keep everything (so nothing is removable until the user unchecks).
    let keep: HashSet<String> = inventory.packages.iter().map(|p| p.name.clone()).collect();
    PKG_KEEP.with(|cell| *cell.borrow_mut() = keep);

    let rows: Vec<PackageRow> = inventory.packages.iter().map(package_row).collect();
    let model = Rc::new(VecModel::from(rows));
    PKG_ROWS.with(|cell| *cell.borrow_mut() = Some(model.clone()));
    state.set_package_rows(ModelRc::from(model));
    PKG_INVENTORY.with(|cell| *cell.borrow_mut() = Some(inventory));

    recompute_package_plan(state);
}

fn package_status_text(inventory: &Inventory) -> SharedString {
    if !inventory.available {
        SharedString::from(format!("{} not installed", inventory.manager.label()))
    } else {
        SharedString::from(format!(
            "{} · {} installed",
            inventory.manager.label(),
            inventory.packages.len()
        ))
    }
}

fn package_row(pkg: &cleanton_packages::Package) -> PackageRow {
    let size = if pkg.size_bytes > 0 {
        display::human_bytes(pkg.size_bytes)
    } else {
        "--".to_owned()
    };
    let used_by = pkg
        .used_by
        .first()
        .map(|p| home_relative(p))
        .unwrap_or_default();
    PackageRow {
        name: SharedString::from(pkg.name.clone()),
        version: SharedString::from(pkg.version.clone()),
        size: SharedString::from(size),
        kept: true,
        state: 0,
        outdated: SharedString::from(pkg.outdated_to.clone().unwrap_or_default()),
        used_by_count: clamp_to_i32(pkg.used_by.len()),
        used_by: SharedString::from(used_by),
    }
}

/// Tilde-shorten a path string for display.
fn home_relative(path: &str) -> String {
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() => match path.strip_prefix(&home) {
            Some(rest) => format!("~{rest}"),
            None => path.to_owned(),
        },
        _ => path.to_owned(),
    }
}

/// Recompute the keep-set removal plan and update each row's state + the summary.
fn recompute_package_plan(state: &AppState) {
    let Some(model) = PKG_ROWS.with(|cell| cell.borrow().clone()) else {
        return;
    };
    let keep = PKG_KEEP.with(|cell| cell.borrow().clone());
    let plan =
        PKG_INVENTORY.with(|cell| cell.borrow().as_ref().map(|inv| plan_removal(inv, &keep)));
    let Some(plan) = plan else {
        return;
    };
    let removable: HashSet<&str> = plan.removable.iter().map(String::as_str).collect();
    let kept_dep: HashSet<&str> = plan.kept_as_dependency.iter().map(String::as_str).collect();

    for i in 0..model.row_count() {
        if let Some(mut row) = model.row_data(i) {
            let name = row.name.as_str();
            let kept = keep.contains(name);
            let new_state = if kept {
                0
            } else if removable.contains(name) {
                1
            } else if kept_dep.contains(name) {
                2
            } else {
                // Not in the removal plan's uninstall set: show it as kept, not
                // removable — the confirm flow only uninstalls `plan.removable`,
                // so labeling anything else removable would lie to the user.
                0
            };
            if row.kept != kept || row.state != new_state {
                row.kept = kept;
                row.state = new_state;
                model.set_row_data(i, row);
            }
        }
    }

    state.set_package_removable_count(clamp_to_i32(plan.removable.len()));
    state.set_package_reclaimable(display::human_bytes(plan.reclaimable_bytes).into());
    state.set_package_kept_dep_count(clamp_to_i32(plan.kept_as_dependency.len()));
}

fn toggle_package_keep(state: &AppState, idx: i32) {
    let Some(model) = PKG_ROWS.with(|cell| cell.borrow().clone()) else {
        return;
    };
    let Ok(index) = usize::try_from(idx) else {
        return;
    };
    if let Some(row) = model.row_data(index) {
        let name = row.name.to_string();
        PKG_KEEP.with(|cell| {
            let mut keep = cell.borrow_mut();
            if keep.contains(&name) {
                keep.remove(&name);
            } else {
                keep.insert(name);
            }
        });
    }
    state.set_package_remove_pending(false);
    recompute_package_plan(state);
}

fn set_all_package_keep(state: &AppState, keep_all: bool) {
    PKG_INVENTORY.with(|inv_cell| {
        if let Some(inv) = inv_cell.borrow().as_ref() {
            PKG_KEEP.with(|cell| {
                let mut keep = cell.borrow_mut();
                keep.clear();
                if keep_all {
                    for pkg in &inv.packages {
                        keep.insert(pkg.name.clone());
                    }
                }
            });
        }
    });
    state.set_package_remove_pending(false);
    recompute_package_plan(state);
}

/// Reveal a path in Finder via `open -R`. Never panics; failure is logged.
fn reveal_in_finder(path: &str) {
    if path.is_empty() {
        return;
    }
    // Reviewed subprocess: `open -R <path>` only selects the item in Finder. No
    // deletion, no mutation. Gated behind an explicit user click on a row.
    #[allow(clippy::disallowed_methods)]
    let spawned = std::process::Command::new("open")
        .arg("-R")
        .arg(path)
        .spawn();
    match spawned {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(err) => tracing::error!("failed to reveal {path} in Finder: {err}"),
    }
}

/// Probe Full Disk Access and populate the first-run guidance banner state. The
/// banner is shown only when a probe positively observed a permission denial,
/// so a granted or indeterminate environment never sees a false alarm.
fn apply_fda_state(state: &AppState) {
    let context = fda::host_context();
    let status = fda::probe();
    state.set_fda_needs_attention(status.is_likely_missing());
    state.set_fda_lead(fda::lead(context).into());
    state.set_fda_note(fda::note(context).into());
    let steps: Vec<SharedString> = fda::steps(context).into_iter().map(Into::into).collect();
    state.set_fda_steps(ModelRc::from(Rc::new(VecModel::from(steps))));
}

/// Open System Settings → Privacy & Security → Full Disk Access via `open`.
/// Never panics; failure is logged and the UI stays responsive.
fn open_fda_settings() {
    // Reviewed subprocess: launches the system `open` tool with a fixed,
    // constant Settings URL. No user input, no filesystem mutation, no
    // deletion — it only deep-links System Settings to the FDA pane.
    #[allow(clippy::disallowed_methods)]
    let spawned = std::process::Command::new("open")
        .arg(fda::SETTINGS_FDA_URL)
        .spawn();
    match spawned {
        Ok(mut child) => {
            // Reap asynchronously so we never block the UI thread.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(err) => tracing::error!("failed to open Full Disk Access settings: {err}"),
    }
}

fn register_embedded_fonts() {
    use slint::fontique_010::fontique;

    let mut collection = slint::fontique_010::shared_collection();
    for (name, bytes) in [
        ("Font Awesome 7 Pro Solid", FA_PRO_SOLID),
        ("Font Awesome 7 Brands Regular", FA_BRANDS_REGULAR),
    ] {
        let blob = fontique::Blob::new(Arc::new(bytes.to_vec()));
        if collection.register_fonts(blob, None).is_empty() {
            tracing::warn!("Font registration returned no faces: {name}");
        }
    }
}

fn scan_options_from_config(config: &CleantonConfig) -> ScanOptions {
    ScanOptions {
        roots: vec![config.general.default_root.clone()],
        max_depth: config.scanning.max_depth,
        follow_symlinks: config.scanning.follow_symlinks,
        respect_gitignore: config.scanning.respect_gitignore,
        exclude_patterns: config.scanning.exclude_patterns.clone(),
        exclude_cloud_roots: config.scanning.exclude_cloud_roots,
        exclude_external_volumes: config.scanning.exclude_external_volumes,
        protected_paths: config.safety.protected_paths.clone(),
        parallel_threads: config.scanning.parallel_threads,
        ..ScanOptions::default()
    }
}

fn capacity_root(config: &CleantonConfig) -> std::path::PathBuf {
    cleanton_common::paths::expand_tilde(&config.general.default_root)
}

/// Surfaces honest capacity figures + the real usage-history sparkline. The
/// "available" figure is a conservative lower bound and is labelled approximate
/// in the UI; snapshots are disclosed, never deleted.
fn apply_capacity_state(state: &AppState, view: &capacity::CapacityView) {
    if let Some(cap) = &view.capacity {
        let used_ratio = if cap.total_bytes > 0 {
            (cap.used_bytes as f64 / cap.total_bytes as f64) as f32
        } else {
            0.0
        };
        state.set_capacity_ready(true);
        state.set_disk_total(display::human_bytes(cap.total_bytes).into());
        state.set_disk_used(
            format!(
                "{} ({:.1}%)",
                display::human_bytes(cap.used_bytes),
                used_ratio * 100.0
            )
            .into(),
        );
        state.set_disk_used_ratio(used_ratio.clamp(0.0, 1.0));
        state.set_disk_available(
            display::human_bytes(cap.available_for_important_usage_bytes).into(),
        );
        state.set_disk_purgeable(display::human_bytes(cap.purgeable_estimate_bytes).into());
    } else {
        let reason = view
            .error
            .clone()
            .unwrap_or_else(|| "capacity unavailable".to_owned());
        state.set_capacity_ready(false);
        state.set_disk_total("--".into());
        state.set_disk_used(reason.into());
        state.set_disk_used_ratio(0.0);
        state.set_disk_available("--".into());
        state.set_disk_purgeable("--".into());
    }

    let snapshot_count = view.snapshot_count();
    let query_failed = view
        .snapshots
        .as_ref()
        .is_some_and(|snapshots| !snapshots.query_succeeded);
    state.set_snapshot_note(
        if snapshot_count > 0 {
            format!(
                "{snapshot_count} local Time Machine snapshots may hold space until deleted or thinned (~24h). Review them on the Results tab."
            )
        } else if query_failed {
            // Distinguish "could not query" from "zero snapshots": never imply a
            // clean disk we did not actually observe.
            "Local snapshot state could not be queried (tmutil unavailable or denied); freed space may still be held by snapshots.".to_owned()
        } else {
            String::new()
        }
        .into(),
    );
    apply_snapshot_state(state, view);

    let bars = capacity::normalized_used_series(&view.history, 64);
    state.set_usage_history_ready(bars.len() >= 2);
    state.set_usage_history(ModelRc::from(Rc::new(VecModel::from(bars))));
}

/// Populate the Results-tab snapshot panel from a fresh capacity view. Every
/// refresh rebuilds the rows unselected and disarms any pending confirmation:
/// a confirmation must never survive a change of the underlying snapshot list.
fn apply_snapshot_state(state: &AppState, view: &capacity::CapacityView) {
    SNAPSHOT_CONFIRM.with(|cell| cell.borrow_mut().cancel());
    state.set_snapshot_delete_pending(false);
    state.set_snapshot_selected_count(0);

    let Some(listing) = view.snapshots.as_ref() else {
        SNAPSHOT_MODEL.with(|cell| *cell.borrow_mut() = None);
        state.set_snapshot_rows(ModelRc::from(Rc::new(VecModel::from(
            Vec::<SnapshotRow>::new(),
        ))));
        state.set_snapshot_available(false);
        state.set_snapshot_status("Not queried".into());
        return;
    };

    let purgeable = view
        .capacity
        .as_ref()
        .map_or(0, |cap| cap.purgeable_estimate_bytes);
    let analysis = SnapshotAnalysis::from_listing(listing, purgeable);

    let rows: Vec<SnapshotRow> = analysis
        .snapshots
        .iter()
        .map(|snapshot| SnapshotRow {
            date: SharedString::from(snapshot.date.as_str()),
            label: SharedString::from(format_snapshot_date(&snapshot.date)),
            identifier: SharedString::from(snapshot.identifier.as_str()),
            selected: false,
        })
        .collect();
    let available = !rows.is_empty();
    let model = Rc::new(VecModel::from(rows));
    SNAPSHOT_MODEL.with(|cell| *cell.borrow_mut() = Some(model.clone()));
    state.set_snapshot_rows(ModelRc::from(model));
    state.set_snapshot_available(available);
    state.set_snapshot_status(
        if available {
            format!(
                "{} local snapshot(s) pin purgeable space (volume purgeable estimate: ~{}). Deleting a snapshot cannot be undone; snapshots never go to the Trash.",
                analysis.snapshots.len(),
                display::human_bytes(analysis.purgeable_estimate_bytes)
            )
        } else if analysis.query_succeeded {
            "No local snapshots.".to_owned()
        } else {
            "Could not query local snapshots (tmutil unavailable or Full Disk Access denied)."
                .to_owned()
        }
        .into(),
    );
}

/// The raw tmutil date tokens of the ticked snapshot rows.
fn selected_snapshot_dates() -> Vec<String> {
    let Some(model) = SNAPSHOT_MODEL.with(|cell| cell.borrow().clone()) else {
        return Vec::new();
    };
    (0..model.row_count())
        .filter_map(|idx| model.row_data(idx))
        .filter(|row| row.selected)
        .map(|row| row.date.to_string())
        .collect()
}

/// Flip one snapshot row's selection. Any selection change disarms a pending
/// confirmation so the armed set always matches what the user last reviewed.
fn toggle_snapshot_selection(state: &AppState, idx: i32) {
    let Some(model) = SNAPSHOT_MODEL.with(|cell| cell.borrow().clone()) else {
        return;
    };
    let Ok(index) = usize::try_from(idx) else {
        return;
    };
    if let Some(mut row) = model.row_data(index) {
        row.selected = !row.selected;
        model.set_row_data(index, row);
    }
    SNAPSHOT_CONFIRM.with(|cell| cell.borrow_mut().cancel());
    state.set_snapshot_delete_pending(false);
    state.set_snapshot_selected_count(clamp_to_i32(selected_snapshot_dates().len()));
}

/// First step of the two-step delete: arm the confirmation for the ticked
/// rows and spell out — before anything runs — that the deletion is permanent.
fn request_snapshot_delete(state: &AppState) {
    if state.get_snapshot_deleting() {
        return;
    }
    let dates = selected_snapshot_dates();
    let armed = SNAPSHOT_CONFIRM.with(|cell| cell.borrow_mut().arm(dates));
    if !armed {
        state.set_snapshot_delete_pending(false);
        state.set_snapshot_status("Select at least one snapshot to delete.".into());
        return;
    }
    let count = SNAPSHOT_CONFIRM.with(|cell| cell.borrow().armed_count());
    state.set_snapshot_delete_pending(true);
    state.set_snapshot_status(
        format!(
            "Confirm to permanently delete {count} snapshot(s). This cannot be undone via Trash. Time Machine loses these restore points."
        )
        .into(),
    );
}

/// Refresh `trash-has-items` from the real Trash folders. Called at startup
/// and after anything that moves items into, or empties, the Trash so the
/// "Empty Trash now" button is never active against an empty Trash.
fn refresh_trash_state(state: &AppState) {
    let has_items = trash_ops::trash_has_items();
    state.set_trash_has_items(has_items);
    if !has_items && !state.get_empty_trash_pending() {
        state.set_trash_status("Trash is empty: nothing to reclaim there.".into());
    }
}

fn initialise_app_state(ui: &AppWindow, config: &CleantonConfig) {
    let state = ui.global::<AppState>();

    // Version of the build actually running (Settings > About).
    state.set_app_version(SharedString::from(env!("CARGO_PKG_VERSION")));
    state.set_scan_root(config.general.default_root.display().to_string().into());
    populate_settings(&state, config);
    state.set_result_mode("Not scanned".into());
    state.set_services(ModelRc::from(Rc::new(VecModel::from(
        Vec::<ServiceRow>::new(),
    ))));

    // Populate initial package-manager tabs synchronously without spawning
    // subprocesses; `spawn_startup_probes` updates availability off the UI thread.
    let tabs: Vec<PkgManagerTab> = PKG_MANAGER_ORDER
        .iter()
        .map(|kind| PkgManagerTab {
            id: SharedString::from(kind.id()),
            label: SharedString::from(kind.label()),
            available: true,
        })
        .collect();
    state.set_active_package_tab(0);
    state.set_package_tabs(ModelRc::from(Rc::new(VecModel::from(tabs))));
}

fn apply_detected_package_tabs(state: &AppState, detected: &[ManagerKind]) {
    let tabs: Vec<PkgManagerTab> = PKG_MANAGER_ORDER
        .iter()
        .map(|kind| PkgManagerTab {
            id: SharedString::from(kind.id()),
            label: SharedString::from(kind.label()),
            available: detected.contains(kind),
        })
        .collect();
    state.set_package_tabs(ModelRc::from(Rc::new(VecModel::from(tabs))));
    if state.get_package_count() == 0 && !state.get_package_loading() {
        let first_available = PKG_MANAGER_ORDER
            .iter()
            .position(|kind| detected.contains(kind))
            .unwrap_or(0);
        state.set_active_package_tab(clamp_to_i32(first_available));
    }
}

/// Read the current config snapshot, recovering the inner value if the lock was
/// poisoned so the UI never panics.
fn config_snapshot(shared: &SharedConfig) -> CleantonConfig {
    match shared.lock() {
        Ok(guard) => guard.clone(),
        Err(poison) => {
            tracing::error!("Config lock poisoned; recovering last value");
            poison.into_inner().clone()
        }
    }
}

/// Replace the live config, recovering from a poisoned lock.
fn store_config(shared: &SharedConfig, config: CleantonConfig) {
    match shared.lock() {
        Ok(mut guard) => *guard = config,
        Err(poison) => {
            tracing::error!("Config lock poisoned; overwriting recovered value");
            *poison.into_inner() = config;
        }
    }
}

/// Push config values into the typed Settings controls.
fn populate_settings(state: &AppState, config: &CleantonConfig) {
    state.set_setting_default_root(config.general.default_root.display().to_string().into());
    state.set_setting_max_depth(clamp_to_i32(config.scanning.max_depth));
    state.set_setting_threads(clamp_to_i32(config.scanning.parallel_threads));
    state.set_setting_follow_symlinks(config.scanning.follow_symlinks);
    state.set_setting_respect_gitignore(config.scanning.respect_gitignore);
    state.set_setting_exclude_cloud(config.scanning.exclude_cloud_roots);
    state.set_setting_exclude_volumes(config.scanning.exclude_external_volumes);
    state.set_setting_ml(config.ml.enabled);
    state
        .set_setting_max_run_gb(i32::try_from(config.safety.max_single_run_gb).unwrap_or(i32::MAX));
    state.set_setting_max_action_gb(
        i32::try_from(config.safety.max_single_action_gb).unwrap_or(i32::MAX),
    );
    state.set_setting_disk_pressure_percent(i32::from(config.background.disk_pressure_percent));
    state.set_setting_memory_pressure_percent(i32::from(config.background.memory_pressure_percent));
}

/// Read the edited Settings controls back into `config`.
fn read_settings_into_config(state: &AppState, config: &mut CleantonConfig) {
    let root = state.get_setting_default_root().to_string();
    let root = root.trim();
    if !root.is_empty() {
        config.general.default_root = PathBuf::from(root);
    }
    config.scanning.max_depth = state.get_setting_max_depth().max(0) as usize;
    config.scanning.parallel_threads = state.get_setting_threads().max(0) as usize;
    config.scanning.follow_symlinks = state.get_setting_follow_symlinks();
    config.scanning.respect_gitignore = state.get_setting_respect_gitignore();
    config.scanning.exclude_cloud_roots = state.get_setting_exclude_cloud();
    config.scanning.exclude_external_volumes = state.get_setting_exclude_volumes();
    config.ml.enabled = state.get_setting_ml();
    // Safety ceilings: keep at least 1 GB so a stray 0 can never wedge every
    // cleanup with a refusal.
    config.safety.max_single_run_gb = u64::try_from(state.get_setting_max_run_gb().max(1))
        .unwrap_or(config.safety.max_single_run_gb);
    config.safety.max_single_action_gb = u64::try_from(state.get_setting_max_action_gb().max(1))
        .unwrap_or(config.safety.max_single_action_gb);
    let disk_pct = state.get_setting_disk_pressure_percent().clamp(0, 99);
    config.background.disk_pressure_percent = u8::try_from(disk_pct).unwrap_or(0);
    let mem_pct = state.get_setting_memory_pressure_percent().clamp(0, 99);
    config.background.memory_pressure_percent = u8::try_from(mem_pct).unwrap_or(0);
}

fn clamp_to_i32(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

fn begin_cancellable_operation(current_operation: &CurrentOperation) -> CancellationToken {
    let token = Arc::new(AtomicBool::new(false));
    match current_operation.lock() {
        Ok(mut current) => {
            if let Some(existing) = current.as_ref() {
                existing.store(true, Ordering::Relaxed);
            }
            *current = Some(token.clone());
        }
        Err(err) => tracing::error!("Current operation lock poisoned: {err}"),
    }
    token
}

fn cancel_current_operation(current_operation: &CurrentOperation) -> bool {
    match current_operation.lock() {
        Ok(mut current) => {
            let Some(token) = current.take() else {
                return false;
            };
            token.store(true, Ordering::Relaxed);
            true
        }
        Err(err) => {
            tracing::error!("Current operation lock poisoned: {err}");
            false
        }
    }
}

/// True when a *different* operation replaced this token as current. A user
/// cancel clears the slot instead (see [`cancel_current_operation`]), so a
/// cancelled-but-not-superseded operation may still report its partial result.
fn operation_superseded(current_operation: &CurrentOperation, token: &CancellationToken) -> bool {
    match current_operation.lock() {
        Ok(current) => current
            .as_ref()
            .is_some_and(|current_token| !Arc::ptr_eq(current_token, token)),
        Err(err) => {
            tracing::error!("Current operation lock poisoned: {err}");
            false
        }
    }
}

fn finish_cancellable_operation(current_operation: &CurrentOperation, token: &CancellationToken) {
    match current_operation.lock() {
        Ok(mut current) => {
            if current
                .as_ref()
                .is_some_and(|current_token| Arc::ptr_eq(current_token, token))
            {
                *current = None;
            }
        }
        Err(err) => tracing::error!("Current operation lock poisoned: {err}"),
    }
}

fn clear_plan_state(state: &AppState) {
    state.set_total_reclaimable("Scanning...".into());
    state.set_plan_action_count(0);
    state.set_plan_rows(ModelRc::from(Rc::new(VecModel::from(
        Vec::<PlanListItem>::new(),
    ))));
    PLAN_ROWS.with(|cell| *cell.borrow_mut() = None);
    PLAN_ROW_META.with(|cell| cell.borrow_mut().clear());
    SELECTED_ACTIONS.with(|cell| cell.borrow_mut().clear());
    PLAN_ACTION_BYTES.with(|cell| cell.borrow_mut().clear());
    state.set_plan_selected_count(0);
    state.set_plan_selected_reclaimable("0 B".into());
    state.set_plan_all_selected(false);
    state.set_plan_ready(false);
    state.set_confirmation_pending(false);
    state.set_plan_review_status("Scan or refresh a plan to review cleanup actions.".into());
    state.set_held_count(0);
    state.set_held_actions(ModelRc::from(Rc::new(VecModel::from(
        Vec::<PlanActionRow>::new(),
    ))));

    // Docker + suggestions reset.
    state.set_docker_available(false);
    state.set_docker_reclaimable("0 B".into());
    state.set_docker_status("Not scanned".into());
    state.set_docker_rows(ModelRc::from(Rc::new(VecModel::from(
        Vec::<DockerRow>::new(),
    ))));
    DOCKER_MODEL.with(|cell| *cell.borrow_mut() = None);
    state.set_duplicate_count(0);
    state.set_duplicate_reclaimable("0 B".into());
    state.set_duplicate_rows(ModelRc::from(Rc::new(VecModel::from(
        Vec::<SuggestionRow>::new(),
    ))));
    state.set_large_item_count(0);
    state.set_large_item_rows(ModelRc::from(Rc::new(VecModel::from(
        Vec::<SuggestionRow>::new(),
    ))));
    state.set_screenshot_count(0);
    state.set_screenshot_reclaimable("0 B".into());
    state.set_screenshot_rows(ModelRc::from(Rc::new(VecModel::from(
        Vec::<SuggestionRow>::new(),
    ))));
    state.set_installer_count(0);
    state.set_installer_reclaimable("0 B".into());
    state.set_installer_rows(ModelRc::from(Rc::new(VecModel::from(
        Vec::<SuggestionRow>::new(),
    ))));
    state.set_suggestion_pending_delete_path(SharedString::new());

    reset_execution_state(state);
    apply_category_totals(state, CategoryTotals::default(), 0);
}

fn apply_scan_result_state(state: &AppState, scan: &cleanton_common::ScanResult) {
    let warnings = scan.errors.len();
    state.set_scan_status(scan_status(scan).into());
    state.set_scan_coverage_status(scan_coverage_status(scan).into());
    state.set_scan_warning_count(warnings.to_string().into());
    state.set_scan_files_count(format!("{}", scan.total_files).into());
    state.set_scan_dirs_count(format!("{}", scan.total_dirs).into());
    state.set_scan_bytes(display::human_bytes(scan.allocated_bytes).into());
}

fn scan_status(scan: &cleanton_common::ScanResult) -> String {
    match (scan.incomplete, scan.errors.len()) {
        (true, 0) => "Scan incomplete".to_owned(),
        (true, warnings) => format!("Scan incomplete: {warnings} warnings"),
        (false, 0) => "Scan complete".to_owned(),
        (false, warnings) => format!("Scan complete with {warnings} warnings"),
    }
}

fn scan_coverage_status(scan: &cleanton_common::ScanResult) -> String {
    match (scan.incomplete, scan.errors.len()) {
        (true, 0) => "Incomplete coverage".to_owned(),
        (true, 1) => "Incomplete coverage: 1 skipped path".to_owned(),
        (true, warnings) => format!("Incomplete coverage: {warnings} skipped paths"),
        (false, 0) => "Complete coverage".to_owned(),
        (false, 1) => "Complete with 1 warning".to_owned(),
        (false, warnings) => format!("Complete with {warnings} warnings"),
    }
}

fn apply_analyzed_state(state: &AppState, analyzed: &AnalyzedPlan) {
    let plan = &analyzed.plan;
    // Present the plan grouped by recipe: the granular `plan.actions` (often tens
    // of thousands) stay intact for execution, but the Results list shows one row
    // per recipe group so it is actually reviewable.
    let groups = plan.grouped();
    let safety = safety_by_recipe(&plan.actions);
    state.set_total_reclaimable(display::human_bytes(plan.total_reclaimable).into());
    state.set_plan_action_count(clamp_to_i32(groups.len()));
    state.set_plan_file_count(clamp_to_i32(plan.actions.len()));
    build_plan_model(state, plan, &groups, &safety);
    state.set_plan_ready(!plan.incomplete_scan && !plan.actions.is_empty());
    state.set_confirmation_pending(false);
    state.set_plan_review_status(plan_review_status(plan).into());
    state.set_result_mode(plan_result_mode(plan).into());
    reset_execution_state(state);
    apply_category_totals(state, category_totals(plan), plan.total_reclaimable);

    // Held / demoted candidates are surfaced separately and are NOT part of the
    // executable plan, so the one-click cleanup flow can never act on them.
    state.set_held_count(analyzed.held.len() as i32);
    state.set_held_actions(held_action_rows(&analyzed.held));
}

/// Apply the complete Results analysis: the filesystem plan/held set, Docker
/// (root-independent) accounting, and review-only suggestions.
fn apply_analyzed_full(state: &AppState, full: &AnalyzedFull) {
    apply_analyzed_state(state, &full.analyzed);
    apply_docker_state(state, &full.docker);
    apply_suggestions_state(state, &full.suggestions);

    // The Dashboard Docker tile is driven by real Docker accounting (independent
    // of the filesystem scan root), not by the ~0 filesystem docker actions.
    let docker_bytes = full.docker.total_reclaimable;
    let combined = full
        .analyzed
        .plan
        .total_reclaimable
        .saturating_add(docker_bytes);
    state.set_docker_size(display::human_bytes(docker_bytes).into());
    state.set_docker_ratio(ratio(docker_bytes, combined.max(1)));
}

/// Populate the Docker section (rows + reclaimable + availability). The four
/// categories are always listed; only those with reclaimable bytes are
/// pre-ticked and selectable. The panel is shown only when something is
/// reclaimable, so an absent/idle daemon adds no clutter.
fn apply_docker_state(state: &AppState, docker: &DockerAnalysis) {
    let rows = docker_rows_vec(docker);
    let model = Rc::new(VecModel::from(rows));
    DOCKER_MODEL.with(|cell| *cell.borrow_mut() = Some(model.clone()));
    state.set_docker_rows(ModelRc::from(model));

    let available = docker.total_reclaimable > 0;
    state.set_docker_available(available);
    state.set_docker_reclaimable(display::human_bytes(docker.total_reclaimable).into());
    state.set_docker_status(
        if available {
            format!(
                "{} reclaimable inside the Docker VM.",
                display::human_bytes(docker.total_reclaimable)
            )
        } else {
            "No reclaimable Docker space (or Docker is not running).".to_owned()
        }
        .into(),
    );
}

fn docker_rows_vec(docker: &DockerAnalysis) -> Vec<DockerRow> {
    let images_bytes: u64 = docker.dangling_images.iter().map(|image| image.size).sum();
    let containers_bytes: u64 = docker
        .stopped_containers
        .iter()
        .map(|container| container.size)
        .sum();
    let volumes_bytes: u64 = docker.unused_volumes.iter().map(|volume| volume.size).sum();
    let cache_bytes = docker.build_cache.size;

    vec![
        docker_row(
            "build-cache",
            "Build cache",
            "Reclaimable build cache layers",
            cache_bytes,
        ),
        docker_row(
            "dangling-images",
            "Dangling images",
            &format!("{} untagged image(s)", docker.dangling_images.len()),
            images_bytes,
        ),
        docker_row(
            "stopped-containers",
            "Stopped containers",
            &format!("{} stopped container(s)", docker.stopped_containers.len()),
            containers_bytes,
        ),
        docker_row(
            "unused-volumes",
            "Unused volumes",
            &format!("{} unused volume(s)", docker.unused_volumes.len()),
            volumes_bytes,
        ),
    ]
}

fn docker_row(key: &str, label: &str, detail: &str, bytes: u64) -> DockerRow {
    let has_reclaimable = bytes > 0;
    DockerRow {
        key: SharedString::from(key),
        label: SharedString::from(label),
        detail: SharedString::from(detail),
        size: SharedString::from(display::human_bytes(bytes)),
        selected: has_reclaimable,
        has_reclaimable,
    }
}

/// Flip one Docker category's selection (skipping empty categories).
fn toggle_docker_selection(_state: &AppState, idx: i32) {
    let Some(model) = DOCKER_MODEL.with(|cell| cell.borrow().clone()) else {
        return;
    };
    let Ok(index) = usize::try_from(idx) else {
        return;
    };
    if let Some(mut row) = model.row_data(index)
        && row.has_reclaimable
    {
        row.selected = !row.selected;
        model.set_row_data(index, row);
    }
}

/// Build a [`DockerCleanupPlan`] from the ticked Docker categories, or `None`
/// when nothing is selected.
fn selected_docker_plan(_state: &AppState) -> Option<DockerCleanupPlan> {
    let model = DOCKER_MODEL.with(|cell| cell.borrow().clone())?;
    let mut plan = DockerCleanupPlan {
        clean_dangling_images: false,
        clean_stopped_containers: false,
        clean_unused_volumes: false,
        clean_build_cache: false,
    };
    let mut any = false;
    for i in 0..model.row_count() {
        if let Some(row) = model.row_data(i)
            && row.selected
        {
            any = true;
            match row.key.as_str() {
                "build-cache" => plan.clean_build_cache = true,
                "dangling-images" => plan.clean_dangling_images = true,
                "stopped-containers" => plan.clean_stopped_containers = true,
                "unused-volumes" => plan.clean_unused_volumes = true,
                _ => {}
            }
        }
    }
    if any { Some(plan) } else { None }
}

/// Maximum suggestion rows rendered per subsection.
const MAX_SUGGESTION_ROWS: usize = 50;
/// Maximum duplicate sets rendered (each set also renders one row per copy).
const MAX_DUPLICATE_SETS: usize = 25;
/// Maximum copies rendered under a single duplicate set. `DuplicateSet.paths`
/// is already capped by the engine; this keeps one pathological set from
/// flooding the Results list.
const MAX_DUPLICATE_COPIES: usize = 12;

/// Populate the review-only Suggestions section (duplicate sets + large items).
fn apply_suggestions_state(state: &AppState, suggestions: &Suggestions) {
    let dup_rows = duplicate_rows(&suggestions.duplicates);
    state.set_duplicate_count(clamp_to_i32(suggestions.duplicates.len()));
    state.set_duplicate_reclaimable(display::human_bytes(suggestions.duplicate_reclaimable).into());
    state.set_duplicate_rows(ModelRc::from(Rc::new(VecModel::from(dup_rows))));

    let large_rows = suggestions
        .large_items
        .iter()
        .take(MAX_SUGGESTION_ROWS)
        .map(large_item_row)
        .collect::<Vec<_>>();
    state.set_large_item_count(clamp_to_i32(suggestions.large_items.len()));
    state.set_large_item_rows(ModelRc::from(Rc::new(VecModel::from(large_rows))));

    let screenshot_rows = suggestions
        .screenshots
        .iter()
        .take(MAX_SUGGESTION_ROWS)
        .map(screenshot_row)
        .collect::<Vec<_>>();
    state.set_screenshot_count(clamp_to_i32(suggestions.screenshots.len()));
    state.set_screenshot_reclaimable(
        display::human_bytes(suggestions.screenshot_reclaimable).into(),
    );
    state.set_screenshot_rows(ModelRc::from(Rc::new(VecModel::from(screenshot_rows))));

    let installer_rows = suggestions
        .installers
        .iter()
        .take(MAX_SUGGESTION_ROWS)
        .map(installer_row)
        .collect::<Vec<_>>();
    state.set_installer_count(clamp_to_i32(suggestions.installers.len()));
    state.set_installer_reclaimable(display::human_bytes(suggestions.installer_reclaimable).into());
    state.set_installer_rows(ModelRc::from(Rc::new(VecModel::from(installer_rows))));
}

/// One duplicate set renders as a header row plus one row per copy, so the
/// user can see (and trash) every file in the set instead of only the first.
///
/// Layout kinds match `SuggestionListRow.kind` in `widgets.slint`:
/// `1` = set header, `0` = an individual copy, `2` = a muted "+N more" note.
/// Every row carries the set index in `group`, which is what lets
/// [`prune_duplicate_row`] collapse a set once it drops below two copies.
fn duplicate_rows(sets: &[DuplicateSet]) -> Vec<SuggestionRow> {
    let mut rows: Vec<SuggestionRow> = Vec::new();
    for (index, set) in sets.iter().take(MAX_DUPLICATE_SETS).enumerate() {
        let group = i32::try_from(index).unwrap_or(0);
        let listed = set.paths.len().min(MAX_DUPLICATE_COPIES);
        let name = set
            .paths
            .first()
            .and_then(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "duplicate".to_owned());

        rows.push(SuggestionRow {
            kind: 1,
            group,
            title: SharedString::from(format!(
                "{} identical copies of {} ({} each)",
                set.count,
                name,
                display::human_bytes(set.file_bytes)
            )),
            detail: SharedString::new(),
            size: SharedString::from(display::human_bytes(set.reclaimable_bytes)),
            icon: SharedString::from("\u{f0c5}"),
            // A set is a label, not a target: nothing to reveal or trash here.
            path: SharedString::new(),
            deletable: false,
        });

        for copy in set.paths.iter().take(listed) {
            let path = copy.display().to_string();
            rows.push(SuggestionRow {
                kind: 0,
                group,
                title: SharedString::from(
                    copy.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path.clone()),
                ),
                detail: SharedString::from(path.clone()),
                size: SharedString::from(display::human_bytes(set.file_bytes)),
                icon: SharedString::from("\u{f15b}"),
                path: SharedString::from(path),
                // Each copy is one concrete file, so it can go to the Trash
                // after the row's own two-step confirmation.
                deletable: true,
            });
        }

        if set.count > listed {
            rows.push(SuggestionRow {
                kind: 2,
                group,
                title: SharedString::from(format!(
                    "+{} more {} not listed",
                    set.count.saturating_sub(listed),
                    if set.count.saturating_sub(listed) == 1 {
                        "copy"
                    } else {
                        "copies"
                    }
                )),
                detail: SharedString::new(),
                size: SharedString::new(),
                icon: SharedString::new(),
                path: SharedString::new(),
                deletable: false,
            });
        }
    }
    rows
}

/// Drop a trashed duplicate copy from the rendered model. When its set falls
/// below two remaining copies it is no longer a duplicate, so the whole group
/// (header, surviving copy, note) is removed and the set count goes down.
///
/// Returns the surviving rows and the new number of duplicate sets.
fn prune_duplicate_row(rows: Vec<SuggestionRow>, trashed: &str) -> (Vec<SuggestionRow>, usize) {
    let Some(group) = rows
        .iter()
        .find(|row| row.kind == 0 && row.path.as_str() == trashed)
        .map(|row| row.group)
    else {
        let sets = rows.iter().filter(|row| row.kind == 1).count();
        return (rows, sets);
    };

    let mut kept: Vec<SuggestionRow> = rows
        .into_iter()
        .filter(|row| !(row.kind == 0 && row.path.as_str() == trashed))
        .collect();
    let survivors = kept
        .iter()
        .filter(|row| row.group == group && row.kind == 0)
        .count();
    if survivors < 2 {
        kept.retain(|row| row.group != group);
    }
    let sets = kept.iter().filter(|row| row.kind == 1).count();
    (kept, sets)
}

fn large_item_row(item: &LargeItem) -> SuggestionRow {
    let path = item.path.display().to_string();
    let name = item
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.clone());
    // Re-downloadable git repos carry a note (remote + clean/dirty status); show
    // it as the secondary line and use a branch icon so they read as reclaimable.
    // The advisory ML badge (display only) rides alongside the note.
    let detail = match (item.note.is_empty(), item.ml_note.is_empty()) {
        (true, true) => path.clone(),
        (false, true) => format!("{} · {}", item.note, path),
        (true, false) => format!("{} · {}", item.ml_note, path),
        (false, false) => format!("{} · {} · {}", item.note, item.ml_note, path),
    };
    let icon = if item.redownloadable {
        "\u{f126}" // code-branch
    } else if item.is_dir {
        "\u{f07b}" // folder
    } else {
        "\u{f15b}" // file
    };
    SuggestionRow {
        kind: 0,
        group: -1,
        title: SharedString::from(name),
        detail: SharedString::from(detail),
        size: SharedString::from(display::human_bytes(item.bytes)),
        icon: SharedString::from(icon),
        path: SharedString::from(path),
        // A large file/folder or re-clonable repo is a single clear target, so
        // it can be moved to the Trash after explicit confirmation.
        deletable: true,
    }
}

/// Drop a just-trashed suggestion from the displayed models so it disappears
/// immediately without a full rescan. Duplicate copies, large items,
/// screenshots and installers all carry a Trash affordance, so all four are
/// pruned; a duplicate set that falls below two copies is dropped with it.
fn remove_suggestion_row(state: &AppState, path: &str) {
    let current: Vec<SuggestionRow> = state.get_duplicate_rows().iter().collect();
    let (duplicates, sets) = prune_duplicate_row(current, path);
    state.set_duplicate_count(clamp_to_i32(sets));
    state.set_duplicate_rows(ModelRc::from(Rc::new(VecModel::from(duplicates))));

    let large: Vec<SuggestionRow> = state
        .get_large_item_rows()
        .iter()
        .filter(|row| row.path.as_str() != path)
        .collect();
    state.set_large_item_count(clamp_to_i32(large.len()));
    state.set_large_item_rows(ModelRc::from(Rc::new(VecModel::from(large))));

    let shots: Vec<SuggestionRow> = state
        .get_screenshot_rows()
        .iter()
        .filter(|row| row.path.as_str() != path)
        .collect();
    state.set_screenshot_count(clamp_to_i32(shots.len()));
    state.set_screenshot_rows(ModelRc::from(Rc::new(VecModel::from(shots))));

    let installers: Vec<SuggestionRow> = state
        .get_installer_rows()
        .iter()
        .filter(|row| row.path.as_str() != path)
        .collect();
    state.set_installer_count(clamp_to_i32(installers.len()));
    state.set_installer_rows(ModelRc::from(Rc::new(VecModel::from(installers))));

    state.set_suggestion_pending_delete_path(SharedString::new());
}

/// An installer image/package in ~/Downloads (single file, re-downloadable,
/// deletable after explicit confirmation).
fn installer_row(item: &LargeItem) -> SuggestionRow {
    let path = item.path.display().to_string();
    let name = item
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.clone());
    // Advisory ML badge (display only) on the secondary line.
    let detail = if item.ml_note.is_empty() {
        path.clone()
    } else {
        format!("{} · {}", item.ml_note, path)
    };
    SuggestionRow {
        kind: 0,
        group: -1,
        title: SharedString::from(name),
        detail: SharedString::from(detail),
        size: SharedString::from(display::human_bytes(item.bytes)),
        icon: SharedString::from("\u{f187}"), // box-archive
        path: SharedString::from(path),
        deletable: true,
    }
}

/// A screenshot / screen-recording suggestion row (single file, deletable).
fn screenshot_row(item: &LargeItem) -> SuggestionRow {
    let path = item.path.display().to_string();
    let name = item
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.clone());
    let icon = if item.note == "screen recording" {
        "\u{f03d}" // video
    } else {
        "\u{f03e}" // image
    };
    // Advisory ML badge (display only) on the secondary line.
    let detail = if item.ml_note.is_empty() {
        path.clone()
    } else {
        format!("{} · {}", item.ml_note, path)
    };
    SuggestionRow {
        kind: 0,
        group: -1,
        title: SharedString::from(name),
        detail: SharedString::from(detail),
        size: SharedString::from(display::human_bytes(item.bytes)),
        icon: SharedString::from(icon),
        path: SharedString::from(path),
        deletable: true,
    }
}

fn store_latest_plan(latest_plan: &Arc<Mutex<Option<CleanupPlan>>>, plan: Option<CleanupPlan>) {
    match latest_plan.lock() {
        Ok(mut latest) => *latest = plan,
        Err(err) => tracing::error!("Latest cleanup plan lock poisoned: {err}"),
    }
}

fn load_latest_plan(latest_plan: &Arc<Mutex<Option<CleanupPlan>>>) -> Option<CleanupPlan> {
    match latest_plan.lock() {
        Ok(latest) => latest.clone(),
        Err(err) => {
            tracing::error!("Latest cleanup plan lock poisoned: {err}");
            None
        }
    }
}

fn reset_execution_state(state: &AppState) {
    state.set_execution_attempted_count(0);
    state.set_execution_skipped_count(0);
    state.set_execution_failed_count(0);
    state.set_execution_freed("0 B".into());
    state.set_execution_moved("0 B".into());
}

fn plan_review_status(plan: &CleanupPlan) -> String {
    if plan.incomplete_scan {
        "Latest scan was incomplete. Execution is refused until a complete plan is available."
            .to_owned()
    } else if plan.actions.is_empty() {
        "No cleanup actions were found in the latest plan.".to_owned()
    } else {
        format!(
            "{} actions found. Nothing is selected yet: tick the items or groups you want to \
             clean, then press \"Clean selected\".",
            plan.actions.len()
        )
    }
}

fn plan_result_mode(plan: &CleanupPlan) -> &'static str {
    if plan.incomplete_scan {
        "Incomplete scan"
    } else if plan.actions.is_empty() {
        "No actions"
    } else {
        "Review required before cleaning"
    }
}

fn apply_execution_result(state: &AppState, result: &ExecutionResult) {
    state.set_clean_progress(1.0);
    state.set_execution_attempted_count(result.attempted_actions as i32);
    state.set_execution_skipped_count(result.skipped_actions as i32);
    state.set_execution_failed_count(execution_failed_count(result) as i32);
    state.set_execution_freed(display::human_bytes(result.freed_bytes).into());
    state.set_execution_moved(display::human_bytes(result.moved_to_trash_bytes).into());
    state.set_clean_status(
        format!(
            "Cleanup complete: {} attempted, {} skipped.",
            result.attempted_actions, result.skipped_actions
        )
        .into(),
    );
    state.set_result_mode("Cleanup complete".into());

    refresh_trash_state(state);
    // Distinguish Moved-to-Trash (not yet freed) from Freed (reclaimed).
    if result.moved_to_trash_bytes > 0 {
        let moved_actions = result
            .actions
            .iter()
            .filter(|action| action.status == ExecutionStatus::MovedToTrash)
            .count();
        state.set_trash_status(
            format!(
                "Moved {moved_actions} items to Trash ({}). Empty Trash to reclaim.",
                display::human_bytes(result.moved_to_trash_bytes)
            )
            .into(),
        );
    } else if result.freed_bytes > 0 {
        state.set_trash_status(
            format!(
                "Freed {} (permanently deleted).",
                display::human_bytes(result.freed_bytes)
            )
            .into(),
        );
    }
}

/// After a successful cleanup, drop the actions that were actually removed
/// (moved to Trash or deleted) from the retained plan and rebuild the Results
/// list, so cleaned entries no longer linger. Actions the user did not select
/// (or that were skipped/failed) stay in the list. Leaves the execution-result
/// summary and suggestions untouched — only the plan list is pruned.
fn prune_executed_actions(
    state: &AppState,
    latest_plan: &Arc<Mutex<Option<CleanupPlan>>>,
    result: &ExecutionResult,
) {
    let removed: HashSet<PathBuf> = result
        .actions
        .iter()
        .filter(|action| {
            matches!(
                action.status,
                ExecutionStatus::MovedToTrash | ExecutionStatus::Deleted
            )
        })
        .map(|action| action.target.clone())
        .collect();
    if removed.is_empty() {
        return;
    }

    let reduced = {
        let Ok(mut guard) = latest_plan.lock() else {
            return;
        };
        let Some(plan) = guard.as_mut() else {
            return;
        };
        plan.actions
            .retain(|action| !removed.contains(&action.target));
        plan.total_reclaimable = plan
            .actions
            .iter()
            .map(|action| action.reclaimable_bytes)
            .fold(0u64, u64::saturating_add);
        if plan.actions.is_empty() {
            *guard = None;
            None
        } else {
            Some(plan.clone())
        }
    };

    match reduced {
        None => clear_plan_list_only(state),
        Some(plan) => {
            let groups = plan.grouped();
            let safety = safety_by_recipe(&plan.actions);
            state.set_total_reclaimable(display::human_bytes(plan.total_reclaimable).into());
            state.set_plan_action_count(clamp_to_i32(groups.len()));
            state.set_plan_file_count(clamp_to_i32(plan.actions.len()));
            build_plan_model(state, &plan, &groups, &safety);
            state.set_plan_ready(!plan.actions.is_empty());
        }
    }
}

/// Clear just the cleanup-plan list + selection (used when a cleanup removed
/// every listed action). Unlike [`clear_plan_state`], this preserves the
/// execution-result summary, capacity, docker, and suggestions.
fn clear_plan_list_only(state: &AppState) {
    state.set_total_reclaimable("0 B".into());
    state.set_plan_action_count(0);
    state.set_plan_file_count(0);
    state.set_plan_rows(ModelRc::from(Rc::new(VecModel::from(
        Vec::<PlanListItem>::new(),
    ))));
    PLAN_ROWS.with(|cell| *cell.borrow_mut() = None);
    PLAN_ROW_META.with(|cell| cell.borrow_mut().clear());
    SELECTED_ACTIONS.with(|cell| cell.borrow_mut().clear());
    PLAN_ACTION_BYTES.with(|cell| cell.borrow_mut().clear());
    state.set_plan_selected_count(0);
    state.set_plan_selected_reclaimable("0 B".into());
    state.set_plan_all_selected(false);
    state.set_plan_ready(false);
}

fn execution_failed_count(result: &ExecutionResult) -> u64 {
    result
        .actions
        .iter()
        .filter(|action| action.status == ExecutionStatus::Failed)
        .count() as u64
}

/// Maximum recipe-group rows rendered in the Results / Held lists. Grouping
/// collapses tens of thousands of per-file actions into a handful of recipe
/// rows, so this cap is generous and rarely reached.
const MAX_PLAN_GROUP_ROWS: usize = 60;

/// Map each `recipe_id` to a representative safety level (its first action's), so
/// grouped rows can still show a safety badge even though [`ActionGroup`] — a
/// presentation aggregate — carries no safety field.
fn safety_by_recipe(actions: &[CleanupAction]) -> HashMap<&str, SafetyLevel> {
    let mut map = HashMap::new();
    for action in actions {
        map.entry(action.recipe_id.0.as_str())
            .or_insert(action.safety_level);
    }
    map
}

/// Build a [`PlanActionRow`] from a recipe [`ActionGroup`]. `safety` is the
/// group's representative safety level, looked up from the granular actions.
/// Safe groups are pre-selected; cautious/aggressive groups start unticked so a
/// one-click Clean only touches the unambiguously-safe set unless the user opts in.
fn group_row(group: &ActionGroup, safety: SafetyLevel) -> PlanActionRow {
    let detail = group
        .sample_targets
        .first()
        .map(|target| target.display().to_string())
        .unwrap_or_else(|| group.recipe_id.clone());
    PlanActionRow {
        name: SharedString::from(group.label.clone()),
        size: SharedString::from(display::human_bytes(group.total_reclaimable)),
        safety: SharedString::from(safety_label(safety)),
        action_type: SharedString::from(action_type_label(group.action_type)),
        action_icon: SharedString::from(action_type_icon(group.action_type)),
        recipe_id: SharedString::from(group.recipe_id.clone()),
        // Nothing is pre-selected, even "safe" groups: Cleanton is a deleter
        // and a scan must never end in a state where one click removes every
        // target. The user opts in by ticking rows or the master checkbox.
        selected: false,
        count: clamp_to_i32(group.action_count),
        detail: SharedString::from(detail),
    }
}

/// Build the grouped row vector, capped, with each group's representative safety.
fn plan_rows_vec(
    groups: &[ActionGroup],
    safety: &HashMap<&str, SafetyLevel>,
) -> Vec<PlanActionRow> {
    groups
        .iter()
        .take(MAX_PLAN_GROUP_ROWS)
        .map(|group| {
            let level = safety
                .get(group.recipe_id.as_str())
                .copied()
                .unwrap_or(SafetyLevel::Safe);
            group_row(group, level)
        })
        .collect()
}

/// A non-retained grouped-rows model (used by the read-only Held list).
fn grouped_rows(
    groups: &[ActionGroup],
    safety: &HashMap<&str, SafetyLevel>,
) -> ModelRc<PlanActionRow> {
    ModelRc::from(Rc::new(VecModel::from(plan_rows_vec(groups, safety))))
}

/// Maximum individual item rows rendered per expanded group (the group's
/// "select all" still acts on every underlying action, shown or not).
const MAX_ITEMS_PER_GROUP: usize = 100;

/// `$HOME` as a String (empty if unset), for tilde-shortening item paths.
fn home_string() -> String {
    std::env::var("HOME").unwrap_or_default()
}

/// (display name = last two path components, detail = tilde-shortened full path).
fn item_display(target: &Path, home: &Path) -> (String, String) {
    let detail = match target.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => target.display().to_string(),
    };
    let mut comps = target.components().rev();
    let last = comps
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned());
    let prev = comps
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned());
    let name = match (prev, last) {
        (Some(p), Some(l)) => format!("{p}/{l}"),
        (None, Some(l)) => l,
        _ => detail.clone(),
    };
    (name, detail)
}

/// Build and RETAIN the expandable cleanup-plan model: a recipe-group header
/// per group, followed by its (initially hidden) individual item rows. Selection
/// truth lives in `SELECTED_ACTIONS` (by action index); safe groups start
/// selected. The retained model + parallel `PLAN_ROW_META` let expand/select
/// callbacks mutate single rows in place.
fn build_plan_model(
    state: &AppState,
    plan: &CleanupPlan,
    groups: &[ActionGroup],
    safety: &HashMap<&str, SafetyLevel>,
) {
    // Bucket action indices by recipe, and record per-action bytes for totals.
    let mut idx_by_recipe: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut action_bytes: Vec<u64> = Vec::with_capacity(plan.actions.len());
    // Selection is empty after a fresh scan: every action must be ticked
    // explicitly. (`selected` is only ever populated by the user's toggles.)
    let selected: HashSet<usize> = HashSet::new();
    for (i, action) in plan.actions.iter().enumerate() {
        idx_by_recipe
            .entry(action.recipe_id.0.as_str())
            .or_default()
            .push(i);
        action_bytes.push(action.reclaimable_bytes);
    }

    let home = home_string();
    let home_path = Path::new(&home);
    let mut rows: Vec<PlanListItem> = Vec::new();
    let mut meta: Vec<RowMeta> = Vec::new();

    for group in groups.iter().take(MAX_PLAN_GROUP_ROWS) {
        let recipe = group.recipe_id.as_str();
        let level = safety.get(recipe).copied().unwrap_or(SafetyLevel::Safe);
        let mut indices = idx_by_recipe.get(recipe).cloned().unwrap_or_default();
        indices.sort_by_key(|&i| std::cmp::Reverse(action_bytes.get(i).copied().unwrap_or(0)));

        let sel_count = indices.iter().filter(|&&i| selected.contains(&i)).count();
        let group_row_index = rows.len();
        rows.push(PlanListItem {
            kind: 0,
            name: SharedString::from(group.label.clone()),
            detail: SharedString::new(),
            size: SharedString::from(display::human_bytes(group.total_reclaimable)),
            safety: SharedString::from(safety_label(level)),
            count: clamp_to_i32(group.action_count),
            selected: !indices.is_empty() && sel_count == indices.len(),
            partial: sel_count > 0 && sel_count < indices.len(),
            expanded: false,
            row_visible: true,
        });
        meta.push(RowMeta::Group {
            action_indices: Vec::new(),
            first_item_row: 0,
            item_row_count: 0,
        });

        let first_item_row = rows.len();
        let shown = indices.len().min(MAX_ITEMS_PER_GROUP);
        for &ai in indices.iter().take(shown) {
            let Some(action) = plan.actions.get(ai) else {
                continue;
            };
            let (name, detail) = item_display(&action.target, home_path);
            rows.push(PlanListItem {
                kind: 1,
                name: SharedString::from(name),
                detail: SharedString::from(detail),
                size: SharedString::from(display::human_bytes(action.reclaimable_bytes)),
                safety: SharedString::new(),
                count: 0,
                selected: selected.contains(&ai),
                partial: false,
                expanded: false,
                row_visible: false,
            });
            meta.push(RowMeta::Item {
                action_index: ai,
                group_row: group_row_index,
            });
        }
        if indices.len() > shown {
            rows.push(PlanListItem {
                kind: 2,
                name: SharedString::from(format!(
                    "+ {} more folders (cleaned with the group)",
                    indices.len() - shown
                )),
                detail: SharedString::new(),
                size: SharedString::new(),
                safety: SharedString::new(),
                count: 0,
                selected: false,
                partial: false,
                expanded: false,
                row_visible: false,
            });
            meta.push(RowMeta::Note);
        }

        let item_row_count = rows.len() - first_item_row;
        if let Some(slot) = meta.get_mut(group_row_index) {
            *slot = RowMeta::Group {
                action_indices: indices,
                first_item_row,
                item_row_count,
            };
        }
    }

    let model = Rc::new(VecModel::from(rows));
    PLAN_ROWS.with(|cell| *cell.borrow_mut() = Some(model.clone()));
    PLAN_ROW_META.with(|cell| *cell.borrow_mut() = meta);
    PLAN_ACTION_BYTES.with(|cell| *cell.borrow_mut() = action_bytes);
    SELECTED_ACTIONS.with(|cell| *cell.borrow_mut() = selected);
    state.set_plan_rows(ModelRc::from(model));
    recompute_plan_selection(state);
}

/// Recompute selected item count + reclaimable bytes + master-checkbox state.
fn recompute_plan_selection(state: &AppState) {
    let bytes = PLAN_ACTION_BYTES.with(|cell| cell.borrow().clone());
    let (count, total_bytes) = SELECTED_ACTIONS.with(|cell| {
        let selected = cell.borrow();
        let sum = selected
            .iter()
            .filter_map(|&i| bytes.get(i).copied())
            .fold(0u64, u64::saturating_add);
        (selected.len(), sum)
    });
    state.set_plan_selected_count(clamp_to_i32(count));
    state.set_plan_selected_reclaimable(display::human_bytes(total_bytes).into());
    state.set_plan_all_selected(!bytes.is_empty() && count == bytes.len());
}

/// Refresh a group header row's tri-state (selected / partial) and its visible
/// child item rows from the current selection.
fn refresh_group_row(model: &Rc<VecModel<PlanListItem>>, group_row: usize) {
    let (action_indices, first_item_row, item_row_count) =
        PLAN_ROW_META.with(|cell| match cell.borrow().get(group_row) {
            Some(RowMeta::Group {
                action_indices,
                first_item_row,
                item_row_count,
            }) => (action_indices.clone(), *first_item_row, *item_row_count),
            _ => (Vec::new(), 0, 0),
        });
    let sel_count = SELECTED_ACTIONS.with(|cell| {
        let selected = cell.borrow();
        action_indices
            .iter()
            .filter(|&&i| selected.contains(&i))
            .count()
    });
    if let Some(mut row) = model.row_data(group_row) {
        row.selected = !action_indices.is_empty() && sel_count == action_indices.len();
        row.partial = sel_count > 0 && sel_count < action_indices.len();
        model.set_row_data(group_row, row);
    }
    // Sync the shown item rows' checkboxes.
    for r in first_item_row..first_item_row + item_row_count {
        let action_index = PLAN_ROW_META.with(|cell| match cell.borrow().get(r) {
            Some(RowMeta::Item { action_index, .. }) => Some(*action_index),
            _ => None,
        });
        if let Some(ai) = action_index
            && let Some(mut row) = model.row_data(r)
        {
            row.selected = SELECTED_ACTIONS.with(|cell| cell.borrow().contains(&ai));
            model.set_row_data(r, row);
        }
    }
}

/// Expand or collapse a group row, toggling visibility of its child rows.
fn plan_row_expand(state: &AppState, idx: i32) {
    let _ = state;
    let Some(model) = PLAN_ROWS.with(|cell| cell.borrow().clone()) else {
        return;
    };
    let Ok(index) = usize::try_from(idx) else {
        return;
    };
    let range = PLAN_ROW_META.with(|cell| match cell.borrow().get(index) {
        Some(RowMeta::Group {
            first_item_row,
            item_row_count,
            ..
        }) => Some((*first_item_row, *item_row_count)),
        _ => None,
    });
    let Some((first_item_row, item_row_count)) = range else {
        return;
    };
    let expanded = match model.row_data(index) {
        Some(mut row) => {
            row.expanded = !row.expanded;
            let now = row.expanded;
            model.set_row_data(index, row);
            now
        }
        None => return,
    };
    for r in first_item_row..first_item_row + item_row_count {
        if let Some(mut row) = model.row_data(r) {
            row.row_visible = expanded;
            model.set_row_data(r, row);
        }
    }
}

/// Toggle a row's selection: a group toggles all its actions; an item toggles
/// just itself; a note does nothing.
fn plan_row_toggle(state: &AppState, idx: i32) {
    let Some(model) = PLAN_ROWS.with(|cell| cell.borrow().clone()) else {
        return;
    };
    let Ok(index) = usize::try_from(idx) else {
        return;
    };
    enum Action {
        Group {
            indices: Vec<usize>,
        },
        Item {
            action_index: usize,
            group_row: usize,
        },
        Ignore,
    }
    let action = PLAN_ROW_META.with(|cell| match cell.borrow().get(index) {
        Some(RowMeta::Group { action_indices, .. }) => Action::Group {
            indices: action_indices.clone(),
        },
        Some(RowMeta::Item {
            action_index,
            group_row,
        }) => Action::Item {
            action_index: *action_index,
            group_row: *group_row,
        },
        _ => Action::Ignore,
    });

    match action {
        Action::Group { indices } => {
            let all_selected =
                SELECTED_ACTIONS.with(|cell| indices.iter().all(|i| cell.borrow().contains(i)));
            SELECTED_ACTIONS.with(|cell| {
                let mut selected = cell.borrow_mut();
                for &i in &indices {
                    if all_selected {
                        selected.remove(&i);
                    } else {
                        selected.insert(i);
                    }
                }
            });
            refresh_group_row(&model, index);
        }
        Action::Item {
            action_index,
            group_row,
        } => {
            SELECTED_ACTIONS.with(|cell| {
                let mut selected = cell.borrow_mut();
                if selected.contains(&action_index) {
                    selected.remove(&action_index);
                } else {
                    selected.insert(action_index);
                }
            });
            refresh_group_row(&model, group_row);
        }
        Action::Ignore => return,
    }
    recompute_plan_selection(state);
}

/// Select or deselect every action at once, syncing all rows.
fn set_all_plan_selection(state: &AppState, all: bool) {
    let total = PLAN_ACTION_BYTES.with(|cell| cell.borrow().len());
    SELECTED_ACTIONS.with(|cell| {
        let mut selected = cell.borrow_mut();
        selected.clear();
        if all {
            selected.extend(0..total);
        }
    });
    if let Some(model) = PLAN_ROWS.with(|cell| cell.borrow().clone()) {
        let group_rows: Vec<usize> = PLAN_ROW_META.with(|cell| {
            cell.borrow()
                .iter()
                .enumerate()
                .filter_map(|(i, m)| matches!(m, RowMeta::Group { .. }).then_some(i))
                .collect()
        });
        for g in group_rows {
            refresh_group_row(&model, g);
        }
    }
    recompute_plan_selection(state);
}

/// The set of action indices currently selected for cleanup.
fn selected_action_indices() -> HashSet<usize> {
    SELECTED_ACTIONS.with(|cell| cell.borrow().clone())
}

/// Narrow a plan to exactly the actions at the selected indices.
fn filter_plan_to_selected(plan: CleanupPlan, selected: &HashSet<usize>) -> CleanupPlan {
    let actions: Vec<CleanupAction> = plan
        .actions
        .into_iter()
        .enumerate()
        .filter_map(|(i, action)| selected.contains(&i).then_some(action))
        .collect();
    let total_reclaimable = actions.iter().map(|action| action.reclaimable_bytes).sum();
    CleanupPlan {
        actions,
        total_reclaimable,
        scan_duration: plan.scan_duration,
        analysis_duration: plan.analysis_duration,
        incomplete_scan: plan.incomplete_scan,
        created_at: plan.created_at,
    }
}

/// Group the ML-demoted held candidates by recipe so the held list shows a
/// handful of rows rather than thousands. A throwaway [`CleanupPlan`] reuses the
/// shared [`CleanupPlan::grouped`] aggregation; it is never executed.
fn held_action_rows(held: &[AnnotatedAction]) -> ModelRc<PlanActionRow> {
    let actions = held
        .iter()
        .map(|annotated| annotated.action.clone())
        .collect::<Vec<_>>();
    let total_reclaimable = actions.iter().map(|action| action.reclaimable_bytes).sum();
    let plan = CleanupPlan {
        actions,
        total_reclaimable,
        scan_duration: Duration::ZERO,
        analysis_duration: Duration::ZERO,
        incomplete_scan: false,
        created_at: SystemTime::now(),
    };
    let safety = safety_by_recipe(&plan.actions);
    grouped_rows(&plan.grouped(), &safety)
}

/// Store a freshly discovered service set as the retained full list and render
/// it through the active filter. Totals reflect the FULL set; only the rendered
/// list is filtered/capped.
fn set_discovered_services(state: &AppState, services: Vec<Service>) {
    ALL_SERVICES.with(|cell| *cell.borrow_mut() = services);
    refresh_services_view(state);
}

/// Drop the retained service set and reset the Services page to its empty state
/// (used when discovery fails).
fn clear_discovered_services(state: &AppState) {
    ALL_SERVICES.with(|cell| cell.borrow_mut().clear());
    state.set_services(ModelRc::from(Rc::new(VecModel::from(
        Vec::<ServiceRow>::new(),
    ))));
    state.set_service_count(0);
    state.set_service_running_count(0);
}

/// Drop a deleted/removed service from the retained set. A successful
/// delete is ground truth; the follow-up re-list can be stale (or fail),
/// and previously the row stayed on screen until a manual Refresh.
fn drop_service_locally(id: &str) {
    ALL_SERVICES.with(|cell| cell.borrow_mut().retain(|service| service.id != id));
}

/// Rebuild the displayed model from the retained full set and set the status
/// line to a "Showing N of M" summary. Shared by refresh and filter.
fn refresh_services_view(state: &AppState) {
    let (total, shown) = rebuild_services_model(state);
    state.set_services_status(services_status_text(total, shown).into());
}

/// Rebuild the displayed services model (rows + metric-tile totals) from the
/// retained full set, honouring the active filter. Returns `(total, shown)`
/// where `total` is the full discovered count and `shown` is the number of
/// rows that matched the filter. Does NOT touch `services-status`, so callers
/// that need a bespoke status message (e.g. a disable result) can set it
/// afterwards without it being clobbered.
fn rebuild_services_model(state: &AppState) -> (usize, usize) {
    let needle = state.get_service_filter().to_lowercase();
    let running_only = state.get_service_running_only();
    let hide_protected = state.get_service_hide_protected();
    let startup_only = state.get_service_startup_only();

    ALL_SERVICES.with(|cell| {
        let services = cell.borrow();
        let total = services.len();
        let running_total = services
            .iter()
            .filter(|service| matches!(service.status, ServiceStatus::Running { .. }))
            .count();

        let matched = services
            .iter()
            .filter(|service| {
                service_matches_filter(service, &needle, running_only, hide_protected, startup_only)
            })
            .collect::<Vec<_>>();
        let shown = matched.len();
        let rows = matched
            .into_iter()
            .take(MAX_SERVICE_ROWS)
            .map(service_row)
            .collect::<Vec<_>>();

        state.set_service_count(total as i32);
        state.set_service_running_count(running_total as i32);
        state.set_services(ModelRc::from(Rc::new(VecModel::from(rows))));
        (total, shown)
    })
}

/// Case-insensitive substring match against the service name OR plist path,
/// optionally constrained to running services, non-protected services, and/or
/// startup (RunAtLoad) items. An empty needle matches all.
fn service_matches_filter(
    service: &Service,
    needle: &str,
    running_only: bool,
    hide_protected: bool,
    startup_only: bool,
) -> bool {
    if running_only && !matches!(service.status, ServiceStatus::Running { .. }) {
        return false;
    }
    if hide_protected && is_protected(&service.id, &service.plist_path) {
        return false;
    }
    if startup_only && !service.run_at_load {
        return false;
    }
    if needle.is_empty() {
        return true;
    }
    service.name.to_lowercase().contains(needle)
        || service
            .plist_path
            .display()
            .to_string()
            .to_lowercase()
            .contains(needle)
}

/// Status-line summary conveying the filtered subset against the full total.
fn services_status_text(total: usize, shown: usize) -> String {
    if total == 0 {
        "No services discovered.".to_owned()
    } else {
        format!(
            "Showing {} of {total} services",
            shown.min(MAX_SERVICE_ROWS)
        )
    }
}

fn service_row(service: &Service) -> ServiceRow {
    ServiceRow {
        id: SharedString::from(service.id.clone()),
        name: SharedString::from(service.name.clone()),
        kind: SharedString::from(service_type_label(service.service_type)),
        status: SharedString::from(service_status_label(&service.status)),
        path: SharedString::from(service.plist_path.display().to_string()),
        running: matches!(service.status, ServiceStatus::Running { .. }),
        protected_service: is_protected(&service.id, &service.plist_path),
        run_at_load: service.run_at_load,
        orphaned: service_is_orphaned(service),
    }
}

/// A launchd service whose referenced executable no longer exists: its plist is
/// a safe-to-remove leftover. Mirrors the backend `delete_orphaned_plist`
/// eligibility (Homebrew services are never treated as orphaned here — they are
/// managed by `brew`, not by a removable plist).
fn service_is_orphaned(service: &Service) -> bool {
    if service.service_type == ServiceType::BrewService {
        return false;
    }
    if let Some(program) = &service.program {
        return !program.exists();
    }
    if let Some(first_arg) = service.program_arguments.first() {
        return !PathBuf::from(first_arg).exists();
    }
    true
}

fn service_type_label(service_type: ServiceType) -> &'static str {
    match service_type {
        ServiceType::UserLaunchAgent => "Agent",
        ServiceType::SystemLaunchAgent => "System agent",
        ServiceType::SystemLaunchDaemon => "Daemon",
        ServiceType::BrewService => "Brew",
        ServiceType::SystemdUserService => "systemd",
    }
}

/// Start the read-only security scan of installed packages on a background
/// worker thread (the static analyzer is CPU-bound and must never block the
/// UI). Detection + notification only: findings never become cleanup actions,
/// and nothing on this path removes, quarantines, or modifies a package. With
/// `establish` the current package set is recorded as the trusted baseline —
/// a write to the baseline metadata file only.
fn start_security_scan(ui: &AppWindow, establish: bool) {
    if SECURITY_SCAN_IN_FLIGHT.swap(true, Ordering::SeqCst) {
        return;
    }
    let state = ui.global::<AppState>();
    state.set_security_scanning(true);
    state.set_security_has_report(false);
    state.set_security_progress("discovering packages...".into());
    state.set_security_progress_ratio(0.0);
    state.set_security_rows(ModelRc::from(Rc::new(VecModel::from(
        Vec::<SecurityRow>::new(),
    ))));

    let ui_weak = ui.as_weak();
    std::thread::spawn(move || {
        let progress_ui = ui_weak.clone();
        let progress = move |progress: cleanton_engine::SecurityProgress| {
            // Throttle: pushing every package through the event loop is noise;
            // every 10th (plus the final one) keeps the counter live.
            if !progress.scanned.is_multiple_of(10) && progress.scanned != progress.total {
                return;
            }
            let label = format!("{} of {} packages", progress.scanned, progress.total);
            #[allow(clippy::cast_precision_loss)]
            let ratio = if progress.total == 0 {
                0.0f32
            } else {
                progress.scanned as f32 / progress.total as f32
            };
            let _ = progress_ui.upgrade_in_event_loop(move |ui| {
                let state = ui.global::<AppState>();
                state.set_security_progress(label.into());
                state.set_security_progress_ratio(ratio);
            });
        };
        let options = cleanton_engine::SecurityScanOptions {
            establish_baseline: establish,
            ..cleanton_engine::SecurityScanOptions::with_default_baseline()
        };
        let report =
            cleanton_engine::run_security_scan_with_options(&[], &options, None, &progress);
        let _ = ui_weak.upgrade_in_event_loop(move |ui| {
            SECURITY_SCAN_IN_FLIGHT.store(false, Ordering::SeqCst);
            apply_security_report(&ui.global::<AppState>(), &report);
            SECURITY_REPORT.with(|slot| *slot.borrow_mut() = Some(report));
        });
    });
}

/// Mark one flagged package (`Some(index)`) or every flagged package (`None`)
/// as reviewed/trusted. Updates ONLY the baseline metadata file — the package
/// itself is never touched — then re-projects the report into the tab state.
fn security_trust(ui: &AppWindow, index: Option<i32>) {
    let Some(baseline_path) = cleanton_engine::default_baseline_path() else {
        return;
    };
    SECURITY_REPORT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(report) = slot.as_mut() else {
            return;
        };
        let result = match index {
            Some(index) => usize::try_from(index)
                .ok()
                .and_then(|index| report.trust_flagged(index, &baseline_path).ok())
                .map(|_| ()),
            None => report.trust_all_flagged(&baseline_path).ok().map(|_| ()),
        };
        if result.is_some() {
            apply_security_report(&ui.global::<AppState>(), report);
        }
    });
}

/// Project a finished [`cleanton_engine::SecurityReport`] into the Security
/// tab state. Uses the engine's shared copy helpers so the Slint app, the TUI,
/// and the CLI all render identical summary/finding/change strings.
fn apply_security_report(state: &AppState, report: &cleanton_engine::SecurityReport) {
    let count = |value: usize| i32::try_from(value).unwrap_or(i32::MAX);
    state.set_security_scanning(false);
    state.set_security_has_report(true);
    state.set_security_summary(report.summary_message().into());
    state.set_security_headline(report.banner_headline().into());
    state.set_security_banner_tone(report.banner_tone().into());
    state.set_security_baseline_established(report.baseline_established);
    state.set_security_worst(
        cleanton_engine::security::verdict_label(report.worst_verdict()).into(),
    );
    state.set_security_known_count(count(report.known_unchanged));
    state.set_security_new_count(count(report.new_packages));
    state.set_security_updated_count(count(report.updated_packages));
    state.set_security_tamper_count(count(report.changed_same_version));
    state.set_security_critical_count(count(report.critical_packages));
    state.set_security_flagged_count(count(report.flagged.len()));
    let rows: Vec<SecurityRow> = report.flagged.iter().map(security_row).collect();
    state.set_security_rows(ModelRc::from(Rc::new(VecModel::from(rows))));
}

fn security_row(package: &cleanton_engine::PackageReport) -> SecurityRow {
    use cleanton_engine::security::{severity_label, verdict_label};
    SecurityRow {
        name: SharedString::from(package.name.as_str()),
        version: SharedString::from(package.version.as_deref().unwrap_or("")),
        verdict: SharedString::from(verdict_label(package.verdict)),
        // The badge label + tone come from the ASSESSMENT: notice rows show
        // a neutral "notice" chip, never the raw heuristic verdict.
        assessment_label: SharedString::from(package.assessment_label()),
        alert: package.is_alert(),
        heuristic: SharedString::from(package.heuristic_note().unwrap_or_default()),
        severity: SharedString::from(package.worst_severity().map_or("-", severity_label)),
        score: i32::try_from(package.score).unwrap_or(100),
        path: SharedString::from(package.path.display().to_string()),
        source: SharedString::from(package.source.label()),
        findings: SharedString::from(package.finding_lines().join("\n")),
        change: SharedString::from(package.change_label()),
        notice: SharedString::from(package.change.notice()),
        // Recommended review-only next steps (shared engine copy). Advisory —
        // the "Trust" button updates the baseline; nothing here deletes.
        action_label: SharedString::from(package.action_label()),
        actions: SharedString::from(package.action_lines().join("\n")),
        tamper: package.is_tampered(),
        critical: package.is_critical_alert(),
        // A persistence file is the user's own file (a `.zshrc`, a LaunchAgent
        // they installed), and the fix is to edit one line, not to delete it.
        // Only installed packages get the Remove button.
        removable: package.is_removable(),
        remove_label: SharedString::from(package.removal().verb()),
    }
}

/// Package managers detected once per process. Probing `PATH` for every row
/// would spawn a process per package, so the result is cached.
fn security_managers() -> &'static [ManagerKind] {
    static MANAGERS: std::sync::OnceLock<Vec<ManagerKind>> = std::sync::OnceLock::new();
    MANAGERS.get_or_init(PackageManagers::detect).as_slice()
}

/// The `cleanton-packages` manager that will perform a removal, when one can.
///
/// The POLICY (which packages are removable at all, and how) lives in
/// `PackageReport::removal()` so the TUI and this app cannot disagree. This only
/// maps that decision onto the facade that runs it, and returns `None` when the
/// required manager is not installed on this machine.
fn removal_manager(removal: SecurityRemoval) -> Option<ManagerKind> {
    let wanted = match removal {
        SecurityRemoval::Npm => ManagerKind::Npm,
        SecurityRemoval::Pip => ManagerKind::Pip,
        SecurityRemoval::Trash | SecurityRemoval::NotRemovable => return None,
    };
    security_managers()
        .iter()
        .find(|kind| **kind == wanted)
        .copied()
}

/// Arm (or re-arm) the two-step removal for one flagged package row. Nothing
/// runs here: the panel describes the action and the user confirms.
fn arm_security_removal(ui: &AppWindow, index: i32) {
    let state = ui.global::<AppState>();
    if state.get_security_acting() {
        return;
    }
    let Ok(slot) = usize::try_from(index) else {
        return;
    };
    let explanation = SECURITY_REPORT.with(|cell| {
        cell.borrow()
            .as_ref()
            .and_then(|report| report.flagged.get(slot))
            .map(cleanton_engine::PackageReport::removal_explanation)
    });
    let Some(explanation) = explanation else {
        return;
    };
    state.set_security_remove_status(explanation.into());
    state.set_security_pending_remove_index(index);
}

/// Run the confirmed removal for one flagged package row.
///
/// Two shapes, both user-confirmed and both safe-by-default: a package manager
/// uninstall (npm / pip, which keeps the manager's metadata consistent) or a
/// Trash move of the package directory through the engine executor, which
/// re-checks protected paths before anything is touched. The Security report is
/// refreshed afterwards so the row does not linger as a stale finding.
fn run_security_removal(ui: &AppWindow, index: i32, config: &SharedConfig) {
    if SECURITY_REMOVE_IN_FLIGHT.swap(true, Ordering::SeqCst) {
        return;
    }
    let state = ui.global::<AppState>();
    let Ok(slot) = usize::try_from(index) else {
        SECURITY_REMOVE_IN_FLIGHT.store(false, Ordering::SeqCst);
        return;
    };
    let plan = SECURITY_REPORT.with(|cell| {
        cell.borrow()
            .as_ref()
            .and_then(|report| report.flagged.get(slot))
            .map(|package| {
                (
                    package.name.clone(),
                    package.path.clone(),
                    package.removal(),
                )
            })
    });
    // Defence in depth: a row Cleanton must not remove (a host persistence
    // file) has no Remove button, so reaching here means the index came from
    // somewhere other than the UI. Refuse rather than trash a user's own file.
    if let Some((_, _, SecurityRemoval::NotRemovable)) = plan {
        SECURITY_REMOVE_IN_FLIGHT.store(false, Ordering::SeqCst);
        return;
    }
    let plan = plan.map(|(name, path, removal)| (name, path, removal_manager(removal)));
    let Some((name, path, manager)) = plan else {
        SECURITY_REMOVE_IN_FLIGHT.store(false, Ordering::SeqCst);
        return;
    };

    state.set_security_pending_remove_index(-1);
    state.set_security_acting(true);
    state.set_security_remove_status(format!("Removing {name}...").into());

    let ui_weak = ui.as_weak();
    let config = config_snapshot(config);
    std::thread::spawn(move || {
        // The manager's own uninstaller when one owns the package; the
        // executor's single-path Trash move otherwise. Both are reviewed,
        // timeout-bounded paths that already back the Packages tab.
        let outcome: Result<String, String> = worker_runtime().block_on(async move {
            match manager {
                Some(kind) => {
                    let outcome =
                        PackageManagers::uninstall(kind, std::slice::from_ref(&name)).await;
                    if outcome.ok {
                        Ok(match kind {
                            ManagerKind::Npm => format!("`npm uninstall -g {name}` finished."),
                            ManagerKind::Pip => format!("`pip uninstall -y {name}` finished."),
                            _ => format!("Uninstalled {name}."),
                        })
                    } else {
                        Err(outcome.message)
                    }
                }
                None => {
                    let orchestrator = match Orchestrator::new(config) {
                        Ok(orchestrator) => orchestrator,
                        Err(err) => return Err(err.to_string()),
                    };
                    let (event_tx, _event_rx) = mpsc::channel::<EngineEvent>(16);
                    let execution = match orchestrator.trash_suggestion(&path, &event_tx) {
                        Ok(execution) => execution,
                        Err(err) => return Err(err.to_string()),
                    };
                    if execution_failed_count(&execution) > 0 {
                        return Err("the item could not be moved to the Trash".to_owned());
                    }
                    Ok(format!("Moved {} to the Trash.", path.display()))
                }
            }
        });

        let _ = ui_weak.upgrade_in_event_loop(move |ui| {
            SECURITY_REMOVE_IN_FLIGHT.store(false, Ordering::SeqCst);
            let state = ui.global::<AppState>();
            state.set_security_acting(false);
            match outcome {
                Ok(detail) => {
                    state.set_security_remove_status(detail.into());
                    // Refresh so the removed package stops showing as a
                    // finding, and the baseline diff reflects the new set.
                    start_security_scan(&ui, false);
                }
                Err(err) => {
                    state.set_security_remove_status(format!("Could not remove: {err}").into());
                }
            }
        });
    });
}

/// Load (or reload) the installed-application inventory on a background
/// worker; bundle sizing walks every app bundle, so this never runs on the UI
/// thread.
fn start_apps_load(ui: &AppWindow) {
    if APPS_LOADING.swap(true, Ordering::SeqCst) {
        return;
    }
    let state = ui.global::<AppState>();
    state.set_apps_loading(true);
    state.set_apps_status("Loading applications...".into());

    let ui_weak = ui.as_weak();
    std::thread::spawn(move || {
        worker_runtime().block_on(async move {
            let apps = tokio::task::spawn_blocking(list_installed_apps)
                .await
                .unwrap_or_default();
            // Which of these were installed via Homebrew? `brew list --cask`
            // tokens let us route the uninstall through brew too. A missing or
            // slow brew degrades to "no casks" — the trash path still works.
            let cask_tokens: Vec<String> = PackageManagers::inventory(ManagerKind::HomebrewCask)
                .await
                .packages
                .into_iter()
                .map(|pkg| pkg.name)
                .collect();
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                APPS_LOADING.store(false, Ordering::SeqCst);
                let state = ui.global::<AppState>();
                state.set_apps_loading(false);
                ALL_APPS.with(|cell| *cell.borrow_mut() = apps);
                ALL_CASK_TOKENS.with(|cell| *cell.borrow_mut() = cask_tokens);
                rebuild_apps_model(&state);
            });
        });
    });
}

/// Rebuild the visible application rows from ALL_APPS through the filter box.
fn rebuild_apps_model(state: &AppState) {
    let filter = state.get_app_filter().to_lowercase();
    let hide_system = state.get_apps_hide_system();
    let tokens = ALL_CASK_TOKENS.with(|cell| cell.borrow().clone());
    let (rows, total) = ALL_APPS.with(|cell| {
        let apps = cell.borrow();
        let rows: Vec<AppListRow> = apps
            .iter()
            .filter(|app| !hide_system || !app.protected)
            .filter(|app| {
                filter.is_empty()
                    || app.name.to_lowercase().contains(&filter)
                    || app
                        .bundle_id
                        .as_deref()
                        .is_some_and(|id| id.to_lowercase().contains(&filter))
            })
            .map(|app| app_list_row(app, &tokens))
            .collect();
        (rows, apps.len())
    });
    state.set_apps_status(format!("Showing {} of {} applications", rows.len(), total).into());
    state.set_app_rows(ModelRc::from(Rc::new(VecModel::from(rows))));
}

fn app_list_row(app: &InstalledApp, cask_tokens: &[String]) -> AppListRow {
    AppListRow {
        name: SharedString::from(app.name.as_str()),
        version: SharedString::from(app.version.as_deref().unwrap_or("")),
        bundle_id: SharedString::from(app.bundle_id.as_deref().unwrap_or("")),
        path: SharedString::from(app.path.display().to_string()),
        size: SharedString::from(display::human_bytes(app.bytes)),
        protected: app.protected,
        brew: cask_token_for(app, cask_tokens).is_some(),
        app_store: app.app_store,
    }
}

fn leftover_row(item: &cleanton_engine::LeftoverItem) -> LeftoverRow {
    let name = item
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| item.path.display().to_string());
    LeftoverRow {
        name: SharedString::from(name),
        path: SharedString::from(item.path.display().to_string()),
        kind: SharedString::from(item.kind.label()),
        size: SharedString::from(display::human_bytes(item.bytes)),
        admin: item.admin_required,
        // Everything starts selected. Admin-owned items are included too: the
        // executor asks for the administrator password once per run and still
        // moves them into the Trash, so an App Store bundle can actually be
        // uninstalled instead of being review-only.
        selected: true,
    }
}

/// Populate the leftover review panel for the app at `path` (background
/// discovery; sizes require walking each leftover).
fn start_leftover_scan(ui: &AppWindow, path: &str) {
    let Some(app) = ALL_APPS.with(|cell| {
        cell.borrow()
            .iter()
            .find(|app| app.path.display().to_string() == path)
            .cloned()
    }) else {
        return;
    };
    start_leftover_scan_for_app(ui, app);
}

/// Deep-link handler for an app removed *outside* Cleanton: jump to the
/// Applications tab and load the (now-gone) app's leftovers for review.
/// Removals Cleanton performed itself are ignored (their leftovers were already
/// handled in the same uninstall).
fn handle_external_removal(ui: &AppWindow, app: InstalledApp) {
    let self_initiated = CLEANTON_REMOVED_BUNDLES
        .lock()
        .map(|mut removed| removed.remove(&app.path))
        .unwrap_or(false);
    if self_initiated || app.protected {
        return;
    }
    // Don't yank focus while another uninstall is mid-flight.
    if UNINSTALL_IN_FLIGHT.load(Ordering::SeqCst) {
        return;
    }
    let state = ui.global::<AppState>();
    state.set_active_screen(5);
    state.set_apps_status(
        format!("\"{}\" was removed; reviewing its leftovers...", app.name).into(),
    );
    // Refresh the inventory so the removed app drops off the list, then load
    // its leftovers from the retained identity.
    start_apps_load(ui);
    start_leftover_scan_for_app(ui, app);
}

/// Populate the leftover review panel for a specific app (used both by list
/// selection and by the external-removal deep-link, where the app is no longer
/// in the inventory).
fn start_leftover_scan_for_app(ui: &AppWindow, app: InstalledApp) {
    let state = ui.global::<AppState>();
    let path = app.path.display().to_string();

    state.set_selected_app_path(SharedString::from(path.as_str()));
    state.set_selected_app_name(SharedString::from(app.name.as_str()));
    state.set_uninstall_pending(false);
    APP_PLAN.with(|cell| *cell.borrow_mut() = None);

    if app.protected {
        state.set_leftover_loading(false);
        state.set_leftover_count(0);
        state.set_leftover_total("0 B".into());
        state.set_leftover_rows(ModelRc::from(Rc::new(VecModel::from(
            Vec::<LeftoverRow>::new(),
        ))));
        state.set_apps_status(
            format!(
                "{} is a system application and cannot be uninstalled.",
                app.name
            )
            .into(),
        );
        return;
    }

    state.set_leftover_loading(true);
    let ui_weak = ui.as_weak();
    std::thread::spawn(move || {
        worker_runtime().block_on(async move {
            let plan = tokio::task::spawn_blocking(move || find_leftovers(&app))
                .await
                .ok()
                .flatten();
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                let state = ui.global::<AppState>();
                state.set_leftover_loading(false);
                let Some(plan) = plan else {
                    state.set_leftover_count(0);
                    state.set_leftover_rows(ModelRc::from(Rc::new(VecModel::from(Vec::<
                        LeftoverRow,
                    >::new(
                    )))));
                    return;
                };
                // Only show what still belongs to the currently selected app —
                // the user may have clicked another row while we were scanning.
                if state.get_selected_app_path().as_str() != plan.app.path.display().to_string() {
                    return;
                }
                let rows: Vec<LeftoverRow> = plan.items.iter().map(leftover_row).collect();
                state.set_leftover_count(clamp_to_i32(rows.len()));
                state.set_leftover_total(display::human_bytes(plan.total_bytes).into());
                state.set_leftover_rows(ModelRc::from(Rc::new(VecModel::from(rows))));
                APP_PLAN.with(|cell| *cell.borrow_mut() = Some(plan));
            });
        });
    });
}

fn service_status_label(status: &ServiceStatus) -> String {
    match status {
        ServiceStatus::Running { pid, .. } => format!("Running {pid}"),
        ServiceStatus::Stopped => "Stopped".to_owned(),
        ServiceStatus::Loaded => "Loaded".to_owned(),
        ServiceStatus::Error(err) => format!("Error: {err}"),
    }
}

#[derive(Default)]
struct CategoryTotals {
    rust: u64,
    swift: u64,
    node: u64,
    python: u64,
    docker: u64,
    ml: u64,
    jvm: u64,
    ai_tools: u64,
    other: u64,
}

fn category_totals(plan: &CleanupPlan) -> CategoryTotals {
    let mut totals = CategoryTotals::default();
    for action in &plan.actions {
        match action_category(action) {
            ActionCategory::Rust => totals.rust += action.reclaimable_bytes,
            ActionCategory::Swift => totals.swift += action.reclaimable_bytes,
            ActionCategory::Node => totals.node += action.reclaimable_bytes,
            ActionCategory::Python => totals.python += action.reclaimable_bytes,
            ActionCategory::Docker => totals.docker += action.reclaimable_bytes,
            ActionCategory::Ml => totals.ml += action.reclaimable_bytes,
            ActionCategory::Jvm => totals.jvm += action.reclaimable_bytes,
            ActionCategory::AiTools => totals.ai_tools += action.reclaimable_bytes,
            ActionCategory::Other => totals.other += action.reclaimable_bytes,
        }
    }
    totals
}

fn apply_category_totals(state: &AppState, totals: CategoryTotals, total_reclaimable: u64) {
    state.set_rust_size(display::human_bytes(totals.rust).into());
    state.set_rust_ratio(ratio(totals.rust, total_reclaimable));
    state.set_swift_size(display::human_bytes(totals.swift).into());
    state.set_swift_ratio(ratio(totals.swift, total_reclaimable));
    state.set_node_size(display::human_bytes(totals.node).into());
    state.set_node_ratio(ratio(totals.node, total_reclaimable));
    state.set_python_size(display::human_bytes(totals.python).into());
    state.set_python_ratio(ratio(totals.python, total_reclaimable));
    state.set_docker_size(display::human_bytes(totals.docker).into());
    state.set_docker_ratio(ratio(totals.docker, total_reclaimable));
    state.set_ml_size(display::human_bytes(totals.ml).into());
    state.set_ml_ratio(ratio(totals.ml, total_reclaimable));
    state.set_jvm_size(display::human_bytes(totals.jvm).into());
    state.set_jvm_ratio(ratio(totals.jvm, total_reclaimable));
    state.set_aitools_size(display::human_bytes(totals.ai_tools).into());
    state.set_aitools_ratio(ratio(totals.ai_tools, total_reclaimable));
    state.set_other_size(display::human_bytes(totals.other).into());
    state.set_other_ratio(ratio(totals.other, total_reclaimable));
}

fn ratio(bytes: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        bytes as f32 / total as f32
    }
}

enum ActionCategory {
    Rust,
    Swift,
    Node,
    Python,
    Docker,
    Ml,
    Jvm,
    AiTools,
    Other,
}

fn action_category(action: &CleanupAction) -> ActionCategory {
    // Recipes carry their category since it was added to `CleanupAction`; the
    // string heuristic below only handles plans persisted before that field
    // existed (deserialized with an empty category).
    match action.category.as_str() {
        "rust" => return ActionCategory::Rust,
        "swift" => return ActionCategory::Swift,
        "node" => return ActionCategory::Node,
        "python" => return ActionCategory::Python,
        "docker" => return ActionCategory::Docker,
        "ml" => return ActionCategory::Ml,
        "jvm" | "android" => return ActionCategory::Jvm,
        "ai-tools" => return ActionCategory::AiTools,
        "" => {}
        _ => return ActionCategory::Other,
    }

    let recipe_id = action.recipe_id.0.to_lowercase();
    let target = action.target.to_string_lossy().to_lowercase();
    let haystack = format!("{recipe_id} {target}");

    if haystack.contains("rust") || haystack.contains("cargo") || haystack.contains("target") {
        ActionCategory::Rust
    } else if haystack.contains("swift")
        || haystack.contains("xcode")
        || haystack.contains("deriveddata")
    {
        ActionCategory::Swift
    } else if haystack.contains("node") || haystack.contains("npm") {
        ActionCategory::Node
    } else if haystack.contains("docker") {
        ActionCategory::Docker
    } else if haystack.contains("huggingface")
        || haystack.contains("model")
        || haystack.contains("checkpoint")
    {
        ActionCategory::Ml
    } else if haystack.contains("python") || haystack.contains("pip") {
        ActionCategory::Python
    } else {
        ActionCategory::Other
    }
}

fn safety_label(safety: SafetyLevel) -> &'static str {
    match safety {
        SafetyLevel::Safe => "safe",
        SafetyLevel::Cautious => "cautious",
        SafetyLevel::Aggressive => "aggressive",
    }
}

fn action_type_label(action_type: ActionType) -> &'static str {
    match action_type {
        ActionType::Trash => "Trash",
        ActionType::Delete => "Delete",
        ActionType::Archive => "Archive",
    }
}

fn action_type_icon(action_type: ActionType) -> &'static str {
    match action_type {
        ActionType::Trash => "\u{f2ed}",
        ActionType::Delete => "\u{f1f8}",
        ActionType::Archive => "\u{f187}",
    }
}
