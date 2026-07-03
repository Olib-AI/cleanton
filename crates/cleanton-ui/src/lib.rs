#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::explicit_counter_loop,
    clippy::if_not_else,
    clippy::ignored_unit_patterns,
    clippy::items_after_statements,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::semicolon_if_nothing_returned,
    clippy::should_implement_trait,
    clippy::single_match_else,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::unused_async,
    clippy::collapsible_if,
    // Presentation-only crate: indexing here is into fixed-size `ratatui`
    // `Layout::split` results (N constraints -> N rects), a documented layout
    // invariant, never attacker-influenced filesystem data. The strict
    // `indexing_slicing` deny remains in force in the safety-critical crates
    // (common/scanner/engine/recipes/services) where paths are processed.
    clippy::indexing_slicing
)]

pub mod animation;
pub mod app;
pub mod capacity;
pub mod event;
pub mod screens;
pub mod theme;
pub mod trash_ops;
pub mod widgets;

use crossterm::event::KeyEvent;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use cleanton_common::{ActionType, CleantonConfig, CleanupPlan, ExecutionResult, ScanResult};
use cleanton_engine::{AnalyzedFull, EngineEvent};
use cleanton_packages::{
    ActionOutcome, Inventory, ManagerKind, PackageManagers, plan_removal, scan_usage,
};
use cleanton_services::{Service, ServiceManager};

use crate::app::{
    ActiveScreen, App, PackageActionKind, PendingServiceConfirmation, ServiceActionKind,
};
use crate::event::Event;
use crate::widgets::FileTreeState;

#[derive(Debug)]
pub enum ServiceUpdate {
    List(Vec<Service>),
    StatusMessage(String),
}

/// A background package-manager result delivered to the TUI event loop. The
/// two-phase load (inventory first, then the slow outdated/usage probes) is
/// modelled by [`PackageUpdate::Inventory`] followed by [`PackageUpdate::Enriched`].
#[derive(Debug)]
pub enum PackageUpdate {
    /// Phase 1: the inventory list, shown immediately. Boxed to keep the enum small.
    Inventory {
        load_id: u64,
        manager_idx: usize,
        inventory: Box<Inventory>,
    },
    /// Phase 2: outdated targets (network-bound) plus Homebrew codebase-usage.
    Enriched {
        load_id: u64,
        manager_idx: usize,
        outdated: HashMap<String, String>,
        usage: HashMap<String, Vec<PathBuf>>,
    },
    /// A mutating action (uninstall / update / clean cache) finished.
    ActionFinished { outcome: Box<ActionOutcome> },
}

/// A mutating package action dispatched to a background task. Mirrors the app's
/// `PkgAction`.
#[derive(Debug, Clone)]
enum PkgAction {
    Uninstall(Vec<String>),
    Update(Vec<String>),
    CleanCache,
}

#[derive(Debug)]
pub enum TuiEvent {
    Engine {
        operation_id: u64,
        event: EngineEvent,
    },
    /// Result of the ML-aware full analysis path: the executable plan plus its ML
    /// annotations and the demoted/held candidates, the Docker reclaimable
    /// accounting, and the review-only suggestions. Boxed to keep the enum small.
    AnalysisReady {
        operation_id: u64,
        analyzed: Box<AnalyzedFull>,
    },
    Crossterm(Event),
    Service(ServiceUpdate),
    Package(PackageUpdate),
    ExecutionFinished {
        operation_id: u64,
        result: Result<ExecutionResult, cleanton_common::CleantonError>,
    },
    TrashEmptied {
        result: Result<(), String>,
    },
    /// Result of a single user-confirmed suggestion trash (Results screen).
    SuggestionTrashed {
        path: std::path::PathBuf,
        result: Result<(), String>,
    },
    /// Installed-application inventory finished loading (Applications screen).
    AppsLoaded {
        apps: Vec<cleanton_engine::InstalledApp>,
        cask_tokens: Vec<String>,
    },
    /// An application was removed outside Cleanton (dragged to Trash, etc.);
    /// deep-link to the Applications screen and load its leftovers.
    AppRemovedExternally(cleanton_engine::InstalledApp),
    /// Leftover discovery finished for one app. `None` when the app is a
    /// protected system application (nothing reviewable).
    AppLeftoversLoaded {
        app_path: std::path::PathBuf,
        plan: Option<Box<cleanton_engine::UninstallPlan>>,
    },
    /// A user-confirmed application uninstall finished.
    AppUninstallFinished {
        app_name: String,
        result: Result<ExecutionResult, cleanton_common::CleantonError>,
    },
}

#[must_use]
pub fn render_plan_summary(plan: &CleanupPlan) -> String {
    use std::fmt::Write;
    let mut output = String::new();
    output.push_str("Cleanton plan\n");
    let _ = writeln!(output, "Actions: {}", plan.actions.len());
    let _ = writeln!(
        output,
        "Reclaimable: {}\n",
        cleanton_common::display::human_bytes(plan.total_reclaimable)
    );
    if plan.incomplete_scan {
        output.push_str(
            "Coverage: incomplete scan; execution is refused until permissions are resolved\n",
        );
    }
    for action in &plan.actions {
        let _ = writeln!(
            output,
            "- {:?} {} ({})\n",
            action.action_type,
            action.target.display(),
            cleanton_common::display::human_bytes(action.reclaimable_bytes)
        );
    }
    output
}

pub async fn run_tui(config: &CleantonConfig) -> cleanton_common::Result<()> {
    setup_panic_hook();

    crossterm::terminal::enable_raw_mode().map_err(|e| {
        cleanton_common::CleantonError::Scan(format!("Failed to enable raw mode: {e}"))
    })?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::cursor::Hide
    )
    .map_err(|e| cleanton_common::CleantonError::Scan(format!("Failed to setup terminal: {e}")))?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend).map_err(|e| {
        cleanton_common::CleantonError::Scan(format!("Failed to create terminal: {e}"))
    })?;

    // Already running inside the CLI's Tokio runtime; await directly rather than
    // calling block_on (which panics when invoked from within a runtime).
    let run_res = run_tui_async(&mut terminal, config.clone()).await;

    // Restore terminal state
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::cursor::Show
    );

    run_res
}

fn setup_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let mut stdout = std::io::stdout();
        let _ = crossterm::execute!(
            stdout,
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::cursor::Show
        );
        original_hook(panic_info);
    }));
}

async fn run_tui_async<B: ratatui::backend::Backend>(
    terminal: &mut ratatui::Terminal<B>,
    config: CleantonConfig,
) -> cleanton_common::Result<()> {
    let mut app = App::new(config);
    let (tui_tx, mut tui_rx) = mpsc::channel::<TuiEvent>(128);
    let (service_tx, mut service_rx) = mpsc::channel::<ServiceUpdate>(100);

    // Forward Crossterm events
    let crossterm_tx = tui_tx.clone();
    tokio::spawn(async move {
        let tick_rate = Duration::from_millis(33);
        let mut last_tick = Instant::now();
        loop {
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or(Duration::from_secs(0));
            // On a transient read error (rare after a successful poll) skip this
            // iteration rather than panic — the input thread keeps the TUI alive.
            if crossterm::event::poll(timeout).unwrap_or(false)
                && let Ok(event) = crossterm::event::read()
            {
                match event {
                    crossterm::event::Event::Key(key) => {
                        let _ = crossterm_tx
                            .send(TuiEvent::Crossterm(Event::Key(key)))
                            .await;
                    }
                    crossterm::event::Event::Resize(w, h) => {
                        let _ = crossterm_tx
                            .send(TuiEvent::Crossterm(Event::Resize(w, h)))
                            .await;
                    }
                    _ => {}
                }
            }
            if last_tick.elapsed() >= tick_rate {
                let _ = crossterm_tx.send(TuiEvent::Crossterm(Event::Tick)).await;
                last_tick = Instant::now();
            }
        }
    });

    // Forward Service events
    let service_tui_tx = tui_tx.clone();
    tokio::spawn(async move {
        while let Some(update) = service_rx.recv().await {
            let _ = service_tui_tx.send(TuiEvent::Service(update)).await;
        }
    });

    // Watch for apps removed outside Cleanton (Finder drag-to-Trash, another
    // uninstaller). On detection we deep-link to the Applications screen and
    // load the removed app's leftovers. A light readdir-diff poll, on a
    // dedicated blocking thread; removals Cleanton performed itself are
    // suppressed via the shared `uninstalled_by_us` set.
    let removal_tx = tui_tx.clone();
    let removal_suppress = app.uninstalled_by_us.clone();
    std::thread::spawn(move || {
        let mut watcher = cleanton_engine::AppRemovalWatcher::new();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(4));
            let removed = watcher.poll();
            for removed_app in removed {
                let self_initiated = removal_suppress
                    .lock()
                    .map(|mut set| set.remove(&removed_app.path))
                    .unwrap_or(false);
                if self_initiated || removed_app.protected {
                    continue;
                }
                if removal_tx
                    .blocking_send(TuiEvent::AppRemovedExternally(removed_app))
                    .is_err()
                {
                    return; // receiver gone: stop watching.
                }
            }
        }
    });

    // Read real disk capacity + usage history once at startup (no mock data).
    app.refresh_capacity();

    // Load services initially
    load_services(&mut app, &service_tx);

    // Trigger auto scan if configured
    if app.config.general.auto_scan_on_launch {
        trigger_scan(&mut app, &tui_tx);
    }

    let mut should_quit = false;
    let mut last_time = Instant::now();
    // Redraw only when something actually changed. An idle TUI then uses ~no CPU
    // instead of re-rendering the whole screen on every tick.
    let mut needs_redraw = true;

    while !should_quit {
        if needs_redraw {
            terminal
                .draw(|f| {
                    let main_layout = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Length(3), // Header / Tabs
                            Constraint::Min(10),   // Content area
                            Constraint::Length(3), // Status Bar
                        ])
                        .split(f.area());

                    // Paint the app background across the whole frame so the UI is
                    // readable on any terminal — light or dark — instead of relying
                    // on the terminal's own background color showing through.
                    f.render_widget(
                        Block::default().style(Style::default().bg(app.theme.bg).fg(app.theme.fg)),
                        f.area(),
                    );

                    draw_header(f, &app, main_layout[0]);

                    match app.active_screen {
                        ActiveScreen::Dashboard => {
                            screens::dashboard::render(f, &mut app, main_layout[1])
                        }
                        ActiveScreen::Results => {
                            screens::results::render(f, &mut app, main_layout[1])
                        }
                        ActiveScreen::Packages => {
                            screens::packages::render(f, &app, main_layout[1])
                        }
                        ActiveScreen::Services => {
                            screens::services::render(f, &app, main_layout[1])
                        }
                        ActiveScreen::Applications => {
                            screens::applications::render(f, &app, main_layout[1])
                        }
                        ActiveScreen::Settings => {
                            screens::settings::render(f, &app, main_layout[1])
                        }
                        ActiveScreen::Execution => {
                            screens::execution::render(f, &app, main_layout[1])
                        }
                    }

                    draw_status_bar(f, &app, main_layout[2]);
                })
                .map_err(|e| {
                    cleanton_common::CleantonError::Scan(format!("Failed to draw TUI frame: {e}"))
                })?;
            needs_redraw = false;
        }

        // Handle events
        if let Some(event) = tui_rx.recv().await {
            // Any event may change the UI, so redraw — except a bare Tick that
            // produced no visible change (decided in the Tick arm below).
            needs_redraw = true;
            match event {
                TuiEvent::Crossterm(Event::Key(key)) => {
                    handle_key_event(key, &mut app, &tui_tx, &service_tx, &mut should_quit).await;
                    // Auto-load the app inventory the first time the user lands
                    // on the Applications screen, however they navigated there
                    // (number key, Tab cycle, or deep-link).
                    if app.active_screen == ActiveScreen::Applications
                        && !app.apps_load_attempted
                        && !app.apps_loading
                    {
                        load_installed_apps(&mut app, &tui_tx);
                    }
                }
                TuiEvent::Crossterm(Event::Resize(_, _)) => {
                    // ratatui handles resizes automatically, we just redraw on the next loop
                }
                TuiEvent::Crossterm(Event::Tick) => {
                    // Update animation values
                    let dt = last_time.elapsed().as_secs_f32();
                    last_time = Instant::now();
                    app.donut_animation.tick(dt);
                    // Only keep redrawing while a scan/clean/execution is in
                    // flight or the spring animation is still settling. Otherwise
                    // an idle dashboard would re-render at the tick rate forever.
                    needs_redraw = app.is_scanning
                        || app.is_executing
                        || (app.donut_animation.current() - app.donut_animation.target()).abs()
                            > f32::EPSILON;
                }
                TuiEvent::Engine {
                    operation_id,
                    event,
                } => {
                    if is_current_operation(&app, operation_id) {
                        let final_event = matches!(
                            event,
                            EngineEvent::AnalysisCompleted { .. }
                                | EngineEvent::PipelineCompleted { .. }
                                | EngineEvent::PipelineFailed { .. }
                        );
                        handle_engine_event(event, &mut app);
                        if final_event {
                            finish_operation(&mut app, operation_id);
                        }
                    }
                }
                TuiEvent::AnalysisReady {
                    operation_id,
                    analyzed,
                } => {
                    if is_current_operation(&app, operation_id) {
                        apply_analyzed_full(&mut app, *analyzed);
                        finish_operation(&mut app, operation_id);
                    }
                }
                TuiEvent::Service(svc_update) => match svc_update {
                    ServiceUpdate::List(services) => {
                        app.services = services;
                        app.is_loading_services = false;
                        app.pending_service_confirmation = None;
                        // Keep the selection inside the (filtered) list after a
                        // reload shrinks it.
                        let visible = app.visible_service_indices().len();
                        if app.selected_service_idx >= visible {
                            app.selected_service_idx = visible.saturating_sub(1);
                        }
                    }
                    ServiceUpdate::StatusMessage(msg) => {
                        app.service_logs.push(msg.clone());
                        app.set_status(&msg);
                    }
                },
                TuiEvent::Package(pkg_update) => {
                    handle_package_update(&mut app, &tui_tx, pkg_update);
                }
                TuiEvent::ExecutionFinished {
                    operation_id,
                    result,
                } => {
                    // A different id means a newer operation superseded this one:
                    // drop it. A matching id is applied even after cancellation —
                    // execution now genuinely stops on cancel, and the partial
                    // result records which items were already moved to Trash.
                    if app.operation_id != operation_id {
                        continue;
                    }
                    let was_cancelled = app.operation_cancelled.load(Ordering::Relaxed);
                    finish_operation(&mut app, operation_id);
                    app.is_executing = false;
                    match result {
                        Ok(exec_res) => {
                            let moved = exec_res.moved_to_trash_bytes;
                            let moved_actions = exec_res
                                .actions
                                .iter()
                                .filter(|a| {
                                    a.status == cleanton_common::ExecutionStatus::MovedToTrash
                                })
                                .count();

                            // Drop the just-cleaned entries from the plan so the
                            // Results tree no longer lists them; skipped/failed
                            // items remain for another attempt.
                            let removed: std::collections::HashSet<std::path::PathBuf> = exec_res
                                .actions
                                .iter()
                                .filter(|a| {
                                    matches!(
                                        a.status,
                                        cleanton_common::ExecutionStatus::MovedToTrash
                                            | cleanton_common::ExecutionStatus::Deleted
                                    )
                                })
                                .map(|a| a.target.clone())
                                .collect();
                            if !removed.is_empty() {
                                let mut now_empty = false;
                                if let Some(plan) = app.cleanup_plan.as_mut() {
                                    plan.actions.retain(|a| !removed.contains(&a.target));
                                    plan.total_reclaimable = plan
                                        .actions
                                        .iter()
                                        .map(|a| a.reclaimable_bytes)
                                        .fold(0u64, u64::saturating_add);
                                    now_empty = plan.actions.is_empty();
                                }
                                if now_empty {
                                    app.cleanup_plan = None;
                                    app.file_tree_state = None;
                                } else if let Some(plan) = app.cleanup_plan.as_ref() {
                                    app.file_tree_state =
                                        Some(FileTreeState::new(plan, &app.plan_annotations));
                                }
                            }

                            app.execution_result = Some(exec_res);
                            app.execution_progress = 1.0;
                            // Refresh capacity so the dashboard reflects any bytes
                            // actually freed (deletes), and records a usage sample.
                            app.refresh_capacity();
                            if was_cancelled {
                                app.set_status(&format!(
                                    "Cleanup cancelled — {} item(s) ({}) were already moved to Trash before stopping.",
                                    moved_actions,
                                    cleanton_common::display::human_bytes(moved)
                                ));
                            } else if moved > 0 {
                                app.set_status(&format!(
                                    "Moved {} items to Trash ({}) — press E to Empty Trash and reclaim.",
                                    moved_actions,
                                    cleanton_common::display::human_bytes(moved)
                                ));
                            } else {
                                app.set_status("Cleanup completed successfully!");
                            }
                        }
                        Err(err) => {
                            app.set_status(&format!("Cleanup failed: {}", err));
                        }
                    }
                }
                TuiEvent::TrashEmptied { result } => {
                    app.pending_empty_trash_confirmation = false;
                    match result {
                        Ok(()) => {
                            app.refresh_capacity();
                            app.set_status(
                                "Trash emptied. Disk capacity refreshed with reclaimed space.",
                            );
                        }
                        Err(err) => {
                            app.set_status(&format!("Could not empty Trash: {err}"));
                        }
                    }
                }
                TuiEvent::SuggestionTrashed { path, result } => match result {
                    Ok(()) => {
                        remove_suggestion_item(&mut app, &path);
                        app.set_status(&format!("Moved {} to Trash.", path.display()));
                    }
                    Err(err) => {
                        app.set_status(&format!("Could not trash {}: {err}", path.display()));
                    }
                },
                TuiEvent::AppsLoaded { apps, cask_tokens } => {
                    app.apps_loading = false;
                    app.installed_apps = apps;
                    app.apps_cask_tokens = cask_tokens;
                    let visible = app.visible_app_indices().len();
                    if app.selected_app_idx >= visible {
                        app.selected_app_idx = visible.saturating_sub(1);
                    }
                    app.app_uninstall_plan = None;
                    app.leftover_excluded.clear();
                    app.leftover_selected = 0;
                    app.set_status(&format!(
                        "{} applications found. Press Enter to review one.",
                        app.installed_apps.len()
                    ));
                }
                TuiEvent::AppLeftoversLoaded { app_path, plan } => {
                    app.leftover_loading = false;
                    // Ignore stale results if the target changed (matched by the
                    // path we recorded when the scan started, so it works for an
                    // externally-removed app not in the inventory).
                    if app.leftover_target_path.as_deref() != Some(app_path.as_path()) {
                        continue;
                    }
                    match plan {
                        Some(plan) => {
                            app.set_status(&format!(
                                "{}: {} item(s), {} — [ and ] move, Space toggles, u uninstalls.",
                                plan.app.name,
                                plan.items.len(),
                                cleanton_common::display::human_bytes(plan.total_bytes)
                            ));
                            app.app_uninstall_plan = Some(*plan);
                            app.leftover_selected = 0;
                            app.leftover_excluded.clear();
                        }
                        None => {
                            app.set_status("This application cannot be uninstalled.");
                        }
                    }
                }
                TuiEvent::AppRemovedExternally(removed_app) => {
                    // Deep-link to the Applications screen and load the removed
                    // app's leftovers (its bundle is already gone).
                    app.set_tab(5);
                    app.pending_uninstall = false;
                    app.set_status(&format!(
                        "\"{}\" was removed — reviewing its leftovers…",
                        removed_app.name
                    ));
                    load_leftovers_for_app(&mut app, removed_app, &tui_tx);
                    // Refresh the inventory so the removed app drops off the list.
                    load_installed_apps(&mut app, &tui_tx);
                }
                TuiEvent::AppUninstallFinished { app_name, result } => {
                    app.uninstalling = false;
                    app.app_uninstall_plan = None;
                    app.leftover_excluded.clear();
                    app.leftover_selected = 0;
                    match result {
                        Ok(result) => {
                            let moved = result
                                .actions
                                .iter()
                                .filter(|a| {
                                    a.status == cleanton_common::ExecutionStatus::MovedToTrash
                                })
                                .count();
                            app.set_status(&format!(
                                "Moved {moved} item(s) ({}) of {app_name} to the Trash{}.",
                                cleanton_common::display::human_bytes(result.moved_to_trash_bytes),
                                if result.skipped_actions > 0 {
                                    format!("; {} skipped", result.skipped_actions)
                                } else {
                                    String::new()
                                }
                            ));
                            // Refresh the inventory (the bundle is gone).
                            load_installed_apps(&mut app, &tui_tx);
                            app.refresh_capacity();
                        }
                        Err(err) => {
                            app.set_status(&format!(
                                "Uninstall of {app_name} refused or failed: {err}"
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(20)])
        .split(area);

    let logo_para = Paragraph::new(Line::from(vec![
        Span::styled(
            " ⚡ CLEANTON ",
            Style::default()
                .fg(app.theme.success)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            concat!("v", env!("CARGO_PKG_VERSION"), " "),
            Style::default().fg(app.theme.muted),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
    );
    f.render_widget(logo_para, header_chunks[0]);

    let screens = [
        (ActiveScreen::Dashboard, " [1] Dashboard "),
        (ActiveScreen::Results, " [2] Results "),
        (ActiveScreen::Packages, " [3] Packages "),
        (ActiveScreen::Services, " [4] Services "),
        (ActiveScreen::Applications, " [5] Apps "),
        (ActiveScreen::Settings, " [6] Settings "),
        (ActiveScreen::Execution, " [7] Execution "),
    ];

    let mut tab_spans = Vec::new();
    for (scr, name) in &screens {
        if app.active_screen == *scr {
            tab_spans.push(Span::styled(
                *name,
                Style::default()
                    .fg(Color::Rgb(15, 15, 25))
                    .bg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            tab_spans.push(Span::styled(*name, Style::default().fg(app.theme.fg)));
        }
        tab_spans.push(Span::raw("  "));
    }

    let tabs_para = Paragraph::new(Line::from(tab_spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
    );
    f.render_widget(tabs_para, header_chunks[1]);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let status_text = app.status_message.as_deref().unwrap_or("Ready.");
    let status_para = Paragraph::new(Line::from(vec![
        Span::styled(" Status: ", Style::default().fg(app.theme.muted)),
        Span::styled(status_text, Style::default().fg(app.theme.fg)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
    );
    f.render_widget(status_para, area);
}

async fn handle_key_event(
    key: KeyEvent,
    app: &mut App,
    tui_tx: &mpsc::Sender<TuiEvent>,
    service_tx: &mpsc::Sender<ServiceUpdate>,
    should_quit: &mut bool,
) {
    match key.code {
        crossterm::event::KeyCode::Tab => {
            clear_pending_confirmations(app);
            app.cycle_tab();
        }
        crossterm::event::KeyCode::Char('1') => {
            clear_pending_confirmations(app);
            app.set_tab(1);
        }
        crossterm::event::KeyCode::Char('2') => {
            clear_pending_confirmations(app);
            app.set_tab(2);
        }
        crossterm::event::KeyCode::Char('3') => {
            clear_pending_confirmations(app);
            app.set_tab(3);
        }
        crossterm::event::KeyCode::Char('4') => {
            clear_pending_confirmations(app);
            app.set_tab(4);
        }
        crossterm::event::KeyCode::Char('5') => {
            clear_pending_confirmations(app);
            app.set_tab(5);
            // The inventory auto-loads on entering the Applications screen (see
            // the post-key-handling check in the event loop).
        }
        crossterm::event::KeyCode::Char('6') => {
            clear_pending_confirmations(app);
            app.set_tab(6);
        }
        crossterm::event::KeyCode::Char('7') => {
            clear_pending_confirmations(app);
            app.set_tab(7);
        }
        crossterm::event::KeyCode::Char('y') if app.pending_empty_trash_confirmation => {
            trigger_empty_trash(app, tui_tx);
        }
        crossterm::event::KeyCode::Char('n') if app.pending_empty_trash_confirmation => {
            app.pending_empty_trash_confirmation = false;
            app.set_status("Empty Trash cancelled. Trashed items still occupy disk space.");
        }
        crossterm::event::KeyCode::Esc if app.pending_empty_trash_confirmation => {
            app.pending_empty_trash_confirmation = false;
            app.set_status("Empty Trash cancelled. Trashed items still occupy disk space.");
        }
        crossterm::event::KeyCode::Char('E') => {
            request_empty_trash_confirmation(app);
        }
        crossterm::event::KeyCode::Esc if app.pending_cleanup_confirmation.is_some() => {
            app.pending_cleanup_confirmation = None;
            app.set_status("Cleanup confirmation cancelled.");
        }
        crossterm::event::KeyCode::Esc if app.pending_service_confirmation.is_some() => {
            app.pending_service_confirmation = None;
            app.set_status("Service action confirmation cancelled.");
        }
        crossterm::event::KeyCode::Esc if app.pending_package_confirmation.is_some() => {
            app.pending_package_confirmation = None;
            app.set_status("Package action confirmation cancelled.");
        }
        crossterm::event::KeyCode::Char('x') if app.is_scanning || app.is_executing => {
            cancel_current_operation(app);
        }
        crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc => {
            *should_quit = true;
        }
        _ => match app.active_screen {
            ActiveScreen::Dashboard => {
                clear_pending_confirmations(app);
                if key.code == crossterm::event::KeyCode::Char('s')
                    || key.code == crossterm::event::KeyCode::Char(' ')
                {
                    trigger_scan(app, tui_tx);
                }
            }
            ActiveScreen::Packages => handle_packages_key(key, app, tui_tx),
            ActiveScreen::Results => match key.code {
                crossterm::event::KeyCode::Up => {
                    clear_pending_confirmations(app);
                    if let Some(ref mut tree_state) = app.file_tree_state {
                        tree_state.select_prev();
                    }
                }
                crossterm::event::KeyCode::Down => {
                    clear_pending_confirmations(app);
                    if let Some(ref mut tree_state) = app.file_tree_state {
                        tree_state.select_next();
                    }
                }
                crossterm::event::KeyCode::Left
                | crossterm::event::KeyCode::Right
                | crossterm::event::KeyCode::Enter => {
                    clear_pending_confirmations(app);
                    if let Some(ref mut tree_state) = app.file_tree_state {
                        tree_state.toggle_expand_selected();
                    }
                }
                crossterm::event::KeyCode::Char(' ') => {
                    clear_pending_confirmations(app);
                    if let Some(ref mut tree_state) = app.file_tree_state {
                        tree_state.toggle_select_selected();
                    }
                }
                crossterm::event::KeyCode::Char('c') => {
                    arm_cleanup_confirmation(app);
                }
                crossterm::event::KeyCode::Char('[') => {
                    app.pending_suggestion_trash = None;
                    let count = app.deletable_suggestions().len();
                    if count > 0 {
                        app.suggestion_selected =
                            app.suggestion_selected.checked_sub(1).unwrap_or(count - 1);
                    }
                }
                crossterm::event::KeyCode::Char(']') => {
                    app.pending_suggestion_trash = None;
                    let count = app.deletable_suggestions().len();
                    if count > 0 {
                        app.suggestion_selected = (app.suggestion_selected + 1) % count;
                    }
                }
                crossterm::event::KeyCode::Char('t') => {
                    arm_suggestion_trash(app);
                }
                crossterm::event::KeyCode::Char('y') => {
                    if app.pending_suggestion_trash.is_some() {
                        trigger_suggestion_trash(app, tui_tx);
                    } else {
                        trigger_cleanup(app, tui_tx);
                    }
                }
                crossterm::event::KeyCode::Char('n') => {
                    if app.pending_suggestion_trash.take().is_some() {
                        app.set_status("Suggestion trash cancelled.");
                    } else {
                        app.pending_cleanup_confirmation = None;
                        app.set_status("Cleanup confirmation cancelled.");
                    }
                }
                _ => {}
            },
            ActiveScreen::Services => match key.code {
                crossterm::event::KeyCode::Up => {
                    clear_pending_confirmations(app);
                    if app.selected_service_idx > 0 {
                        app.selected_service_idx -= 1;
                    }
                }
                crossterm::event::KeyCode::Down => {
                    clear_pending_confirmations(app);
                    if app.selected_service_idx + 1 < app.visible_service_indices().len() {
                        app.selected_service_idx += 1;
                    }
                }
                crossterm::event::KeyCode::Char('p') => {
                    clear_pending_confirmations(app);
                    app.service_hide_protected = !app.service_hide_protected;
                    app.selected_service_idx = 0;
                    app.set_status(if app.service_hide_protected {
                        "Hiding system-protected services."
                    } else {
                        "Showing all services."
                    });
                }
                crossterm::event::KeyCode::Char('o') => {
                    clear_pending_confirmations(app);
                    app.service_startup_only = !app.service_startup_only;
                    app.selected_service_idx = 0;
                    app.set_status(if app.service_startup_only {
                        "Showing startup items (RunAtLoad) only."
                    } else {
                        "Showing all services."
                    });
                }
                crossterm::event::KeyCode::Char('s') => {
                    arm_service_confirmation(app, ServiceActionKind::Start);
                }
                crossterm::event::KeyCode::Char('d') => {
                    arm_service_confirmation(app, ServiceActionKind::Stop);
                }
                crossterm::event::KeyCode::Char('r') => {
                    arm_service_confirmation(app, ServiceActionKind::Restart);
                }
                crossterm::event::KeyCode::Char('e') => {
                    arm_service_confirmation(app, ServiceActionKind::Enable);
                }
                crossterm::event::KeyCode::Char('x') => {
                    arm_service_confirmation(app, ServiceActionKind::Disable);
                }
                crossterm::event::KeyCode::Delete => {
                    arm_service_confirmation(app, ServiceActionKind::Delete);
                }
                crossterm::event::KeyCode::Char('y') => {
                    trigger_service_action(app, service_tx);
                }
                crossterm::event::KeyCode::Char('n') => {
                    app.pending_service_confirmation = None;
                    app.set_status("Service action confirmation cancelled.");
                }
                crossterm::event::KeyCode::Char('l') => {
                    clear_pending_confirmations(app);
                    load_services(app, service_tx);
                }
                _ => {}
            },
            ActiveScreen::Applications => match key.code {
                crossterm::event::KeyCode::Up => {
                    app.pending_uninstall = false;
                    if app.selected_app_idx > 0 {
                        app.selected_app_idx -= 1;
                    }
                }
                crossterm::event::KeyCode::Down => {
                    app.pending_uninstall = false;
                    if app.selected_app_idx + 1 < app.visible_app_indices().len() {
                        app.selected_app_idx += 1;
                    }
                }
                crossterm::event::KeyCode::Enter => {
                    app.pending_uninstall = false;
                    load_app_leftovers(app, tui_tx);
                }
                crossterm::event::KeyCode::Char('l') => {
                    app.pending_uninstall = false;
                    load_installed_apps(app, tui_tx);
                }
                crossterm::event::KeyCode::Char('h') => {
                    app.pending_uninstall = false;
                    app.apps_hide_system = !app.apps_hide_system;
                    app.selected_app_idx = 0;
                    app.app_uninstall_plan = None;
                    app.set_status(if app.apps_hide_system {
                        "Hiding system applications."
                    } else {
                        "Showing all applications."
                    });
                }
                crossterm::event::KeyCode::Char('[') => {
                    app.pending_uninstall = false;
                    let count = app
                        .app_uninstall_plan
                        .as_ref()
                        .map_or(0, |plan| plan.items.len());
                    if count > 0 {
                        app.leftover_selected =
                            app.leftover_selected.checked_sub(1).unwrap_or(count - 1);
                    }
                }
                crossterm::event::KeyCode::Char(']') => {
                    app.pending_uninstall = false;
                    let count = app
                        .app_uninstall_plan
                        .as_ref()
                        .map_or(0, |plan| plan.items.len());
                    if count > 0 {
                        app.leftover_selected = (app.leftover_selected + 1) % count;
                    }
                }
                crossterm::event::KeyCode::Char(' ') => {
                    app.pending_uninstall = false;
                    toggle_leftover_selected(app);
                }
                crossterm::event::KeyCode::Char('u') => {
                    arm_app_uninstall(app);
                }
                crossterm::event::KeyCode::Char('y') => {
                    trigger_app_uninstall(app, tui_tx);
                }
                crossterm::event::KeyCode::Char('n') if app.pending_uninstall => {
                    app.pending_uninstall = false;
                    app.set_status("Uninstall cancelled.");
                }
                _ => {}
            },
            ActiveScreen::Settings => match key.code {
                crossterm::event::KeyCode::Up => {
                    clear_pending_confirmations(app);
                    if app.active_setting_idx > 0 {
                        app.active_setting_idx -= 1;
                    }
                }
                crossterm::event::KeyCode::Down => {
                    clear_pending_confirmations(app);
                    let count = screens::settings::get_settings_items(app).len();
                    if app.active_setting_idx + 1 < count {
                        app.active_setting_idx += 1;
                    }
                }
                crossterm::event::KeyCode::Left => {
                    clear_pending_confirmations(app);
                    modify_setting(app, false);
                }
                crossterm::event::KeyCode::Right => {
                    clear_pending_confirmations(app);
                    modify_setting(app, true);
                }
                crossterm::event::KeyCode::Char(' ') => {
                    clear_pending_confirmations(app);
                    modify_setting(app, true);
                }
                crossterm::event::KeyCode::Enter => {
                    clear_pending_confirmations(app);
                    save_config(app);
                }
                crossterm::event::KeyCode::Char('[') => {
                    clear_pending_confirmations(app);
                    app.active_setting_tab = if app.active_setting_tab == 0 {
                        3
                    } else {
                        app.active_setting_tab - 1
                    };
                    app.active_setting_idx = 0;
                }
                crossterm::event::KeyCode::Char(']') => {
                    clear_pending_confirmations(app);
                    app.active_setting_tab = (app.active_setting_tab + 1) % 4;
                    app.active_setting_idx = 0;
                }
                _ => {}
            },
            ActiveScreen::Execution => {
                clear_pending_confirmations(app);
                if !app.is_executing
                    && (key.code == crossterm::event::KeyCode::Enter
                        || key.code == crossterm::event::KeyCode::Char(' '))
                {
                    app.active_screen = ActiveScreen::Dashboard;
                }
            }
        },
    }

    // Lazily load the active manager's inventory the first time the Packages
    // screen is shown (cheap, guarded — re-entry while loaded is a no-op).
    maybe_load_packages(app, tui_tx);
}

fn begin_operation(app: &mut App) -> (u64, Arc<AtomicBool>) {
    app.operation_cancelled.store(true, Ordering::Relaxed);
    app.operation_id = app.operation_id.wrapping_add(1);
    app.operation_cancelled = Arc::new(AtomicBool::new(false));
    (app.operation_id, app.operation_cancelled.clone())
}

fn cancel_current_operation(app: &mut App) {
    app.operation_cancelled.store(true, Ordering::Relaxed);
    app.pending_cleanup_confirmation = None;

    if app.is_scanning {
        app.is_scanning = false;
        app.scan_result = None;
        app.cleanup_plan = None;
        app.plan_annotations.clear();
        app.held_actions.clear();
        app.file_tree_state = None;
        app.docker = None;
        app.suggestions = None;
        app.set_status("Scan cancelled. Any in-flight background result will be ignored.");
    } else if app.is_executing {
        app.is_executing = false;
        app.set_status(
            "Cleanup cancellation requested. In-flight file work may finish; results will be ignored.",
        );
    }
}

fn is_current_operation(app: &App, operation_id: u64) -> bool {
    app.operation_id == operation_id && !app.operation_cancelled.load(Ordering::Relaxed)
}

fn finish_operation(app: &mut App, operation_id: u64) {
    if app.operation_id == operation_id {
        app.operation_cancelled.store(true, Ordering::Relaxed);
    }
}

fn handle_engine_event(event: EngineEvent, app: &mut App) {
    match event {
        EngineEvent::ScanStarted { root } => {
            app.is_scanning = true;
            app.set_status(&format!("Scan started on {}", root.display()));
        }
        EngineEvent::ScanProgress {
            files_scanned,
            dirs_entered,
            bytes_seen,
        } => {
            app.scan_progress = Some((files_scanned, dirs_entered, bytes_seen));
        }
        EngineEvent::ScanCompleted { result } => {
            app.scan_result = Some(result);
        }
        EngineEvent::AnalysisStarted => {
            app.set_status("Analyzing scan results against cleanup recipes...");
        }
        EngineEvent::AnalysisProgress {
            items_analyzed,
            total,
        } => {
            app.set_status(&format!("Analyzing: {} / {}", items_analyzed, total));
        }
        EngineEvent::AnalysisCompleted { plan } => {
            // Recipe-only fallback path (no ML annotations). The scan pipeline
            // now uses `TuiEvent::AnalysisReady`; this remains for completeness.
            let status = app.scan_result.as_ref().map_or_else(
                || "Analysis complete! Switch to the Results tab (2) to review.".to_owned(),
                scan_status,
            );
            app.is_scanning = false;
            app.file_tree_state = Some(FileTreeState::new(&plan, &[]));
            app.cleanup_plan = Some(plan);
            app.plan_annotations.clear();
            app.held_actions.clear();
            app.pending_cleanup_confirmation = None;
            app.donut_animation.set_target(1.0);
            app.set_status(&status);
        }
        EngineEvent::ActionStarted { action } => {
            app.execution_logs.push(format!(
                "Starting action: Trashing {}",
                action.target.display()
            ));
        }
        EngineEvent::ActionCompleted { action, freed } => {
            app.execution_logs.push(format!(
                "Completed: {} (Freed {})",
                action.target.display(),
                cleanton_common::display::human_bytes(freed)
            ));

            // Advance progress bar proportionally
            if let Some(ref plan) = app.cleanup_plan {
                let total = plan.actions.len() as f32;
                if total > 0.0 {
                    app.execution_progress = (app.execution_progress + (1.0 / total)).min(1.0);
                }
            }
        }
        EngineEvent::ActionFailed { action, error } => {
            app.execution_logs.push(format!(
                "Failed action: {} - {}",
                action.target.display(),
                error
            ));
        }
        EngineEvent::PipelineCompleted {
            total_reclaimable,
            duration,
        } => {
            app.is_scanning = false;
            app.set_status(&format!(
                "Pipeline complete! Found {} in {:?}",
                cleanton_common::display::human_bytes(total_reclaimable),
                duration
            ));
        }
        EngineEvent::PipelineFailed { error } => {
            app.is_scanning = false;
            app.is_executing = false;
            app.set_status(&format!("Pipeline failed: {}", error));
        }
    }
}

/// Commit an [`AnalyzedFull`] into app state: the executable plan, its ML
/// annotations (badges), and the demoted/held candidates, plus the review-only
/// Docker accounting and large-item / duplicate suggestions. Held items are
/// stored separately and never enter the file tree, so they can only ever be
/// executed by explicit user action against the plan.
fn apply_analyzed_full(app: &mut App, full: AnalyzedFull) {
    let status = app.scan_result.as_ref().map_or_else(
        || "Analysis complete! Switch to the Results tab (2) to review.".to_owned(),
        scan_status,
    );

    let AnalyzedFull {
        analyzed,
        docker,
        suggestions,
    } = full;

    app.is_scanning = false;
    app.file_tree_state = Some(FileTreeState::new(&analyzed.plan, &analyzed.annotations));
    app.cleanup_plan = Some(analyzed.plan);
    app.plan_annotations = analyzed.annotations;
    app.held_actions = analyzed.held;
    app.docker = Some(docker);
    app.suggestions = Some(suggestions);
    app.suggestion_selected = 0;
    app.pending_suggestion_trash = None;
    app.pending_cleanup_confirmation = None;
    app.donut_animation.set_target(1.0);
    app.set_status(&status);
}

fn scan_status(scan: &ScanResult) -> String {
    match (scan.incomplete, scan.errors.len()) {
        (true, 0) => "Analysis complete, but scan coverage is incomplete.".to_owned(),
        (true, 1) => {
            "Analysis complete, but scan coverage is incomplete: 1 skipped path.".to_owned()
        }
        (true, warnings) => {
            format!("Analysis complete, but scan coverage is incomplete: {warnings} skipped paths.")
        }
        (false, 0) => "Analysis complete! Switch to the Results tab (2) to review.".to_owned(),
        (false, 1) => "Analysis complete with 1 scan warning.".to_owned(),
        (false, warnings) => format!("Analysis complete with {warnings} scan warnings."),
    }
}

fn trigger_scan(app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    if app.is_scanning {
        return;
    }
    let (operation_id, cancel_token) = begin_operation(app);
    app.is_scanning = true;
    // Scanning is launched and shown on the Dashboard; there is no separate
    // Scanner screen. Keep the user on whatever screen they triggered it from.
    app.scan_progress = Some((0, 0, 0));
    app.scan_result = None;
    app.cleanup_plan = None;
    app.plan_annotations.clear();
    app.held_actions.clear();
    app.file_tree_state = None;
    app.docker = None;
    app.suggestions = None;
    app.pending_cleanup_confirmation = None;
    app.donut_animation.set_target(0.0);

    let orchestrator = app.orchestrator.clone();
    let config = app.config.clone();
    let tx = tx.clone();

    tokio::spawn(async move {
        let root_path = cleanton_common::paths::expand_tilde(&config.general.default_root);

        let options = cleanton_scanner::ScanOptions {
            roots: vec![root_path],
            max_depth: config.scanning.max_depth,
            follow_symlinks: config.scanning.follow_symlinks,
            respect_gitignore: config.scanning.respect_gitignore,
            exclude_patterns: config.scanning.exclude_patterns.clone(),
            exclude_cloud_roots: config.scanning.exclude_cloud_roots,
            exclude_external_volumes: config.scanning.exclude_external_volumes,
            protected_paths: config.safety.protected_paths.clone(),
            parallel_threads: config.scanning.parallel_threads,
            ..cleanton_scanner::ScanOptions::default()
        };

        let _ = tx
            .send(TuiEvent::Engine {
                operation_id,
                event: EngineEvent::ScanStarted {
                    root: options.roots[0].clone(),
                },
            })
            .await;

        // Custom progress pipeline forwarding
        let (scan_progress_tx, mut scan_progress_rx) =
            mpsc::channel::<cleanton_scanner::ScanProgress>(64);
        let progress_tx = tx.clone();
        let progress_cancel_token = cancel_token.clone();
        tokio::spawn(async move {
            while let Some(prog) = scan_progress_rx.recv().await {
                if progress_cancel_token.load(Ordering::Relaxed) {
                    break;
                }
                let _ = progress_tx
                    .send(TuiEvent::Engine {
                        operation_id,
                        event: EngineEvent::ScanProgress {
                            files_scanned: prog.files_scanned,
                            dirs_entered: prog.dirs_entered,
                            bytes_seen: prog.bytes_seen,
                        },
                    })
                    .await;
            }
        });

        match cleanton_scanner::scan_with_cancel(options, scan_progress_tx, cancel_token.clone())
            .await
        {
            Ok(scan_res) => {
                if cancel_token.load(Ordering::Relaxed) {
                    return;
                }
                let _ = tx
                    .send(TuiEvent::Engine {
                        operation_id,
                        event: EngineEvent::ScanCompleted {
                            result: scan_res.clone(),
                        },
                    })
                    .await;
                let _ = tx
                    .send(TuiEvent::Engine {
                        operation_id,
                        event: EngineEvent::AnalysisStarted,
                    })
                    .await;
                // ML-aware full analysis: per-action annotations, orphaned-app
                // candidates, the demoted/held set, plus root-independent Docker
                // accounting and review-only large-item / duplicate suggestions.
                if !cancel_token.load(Ordering::Relaxed) {
                    let analyzed = orchestrator.analyze_full(&scan_res).await;
                    if !cancel_token.load(Ordering::Relaxed) {
                        let _ = tx
                            .send(TuiEvent::AnalysisReady {
                                operation_id,
                                analyzed: Box::new(analyzed),
                            })
                            .await;
                    }
                }
            }
            Err(e) => {
                if !cancel_token.load(Ordering::Relaxed) {
                    let _ = tx
                        .send(TuiEvent::Engine {
                            operation_id,
                            event: EngineEvent::PipelineFailed {
                                error: e.to_string(),
                            },
                        })
                        .await;
                }
            }
        }
    });
}

fn selected_cleanup_indices(app: &App) -> Option<Vec<usize>> {
    app.file_tree_state
        .as_ref()
        .map(FileTreeState::get_selected_action_indices)
}

fn clear_pending_confirmations(app: &mut App) {
    app.pending_cleanup_confirmation = None;
    app.pending_service_confirmation = None;
    app.pending_empty_trash_confirmation = false;
    app.pending_package_confirmation = None;
    app.pending_suggestion_trash = None;
}

fn request_empty_trash_confirmation(app: &mut App) {
    app.pending_cleanup_confirmation = None;
    app.pending_service_confirmation = None;
    app.pending_empty_trash_confirmation = true;
    app.set_status(
        "Empty Trash now? This permanently deletes Trash contents to free space. Press y to confirm, n to cancel.",
    );
}

fn trigger_empty_trash(app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    app.pending_empty_trash_confirmation = false;
    app.set_status("Emptying Trash…");
    let tx = tx.clone();
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(crate::trash_ops::empty_trash)
            .await
            .unwrap_or_else(|join_err| Err(format!("empty-trash task failed: {join_err}")));
        let _ = tx.send(TuiEvent::TrashEmptied { result }).await;
    });
}

/// Arm the two-step trash for the selected deletable suggestion row. Mirrors
/// the Slint app's per-row Trash → Confirm flow: nothing is removed until the
/// user presses `y`, and execution goes through the same executor guards.
fn arm_suggestion_trash(app: &mut App) {
    let suggestions = app.deletable_suggestions();
    let Some(item) = suggestions.get(app.suggestion_selected) else {
        app.set_status("No deletable suggestion selected. Navigate with [ and ].");
        return;
    };
    let path = item.path.clone();
    let bytes = item.bytes;
    app.pending_cleanup_confirmation = None;
    app.pending_suggestion_trash = Some(path.clone());
    app.set_status(&format!(
        "Move {} ({}) to Trash? Press y to confirm, n to cancel.",
        path.display(),
        cleanton_common::display::human_bytes(bytes)
    ));
}

/// Execute a user-confirmed suggestion trash on a blocking worker. The
/// engine-side `trash_suggestion` re-checks protected paths and logs the
/// action exactly like a plan execution.
fn trigger_suggestion_trash(app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    let Some(path) = app.pending_suggestion_trash.take() else {
        return;
    };
    app.set_status(&format!("Moving {} to Trash…", path.display()));
    let orchestrator = app.orchestrator.clone();
    let tx = tx.clone();
    tokio::spawn(async move {
        let target = path.clone();
        let result = tokio::task::spawn_blocking(move || {
            // The engine event stream is unused here: the single-action result
            // is reported back through `SuggestionTrashed` instead.
            let (event_tx, _event_rx) = mpsc::channel(8);
            orchestrator
                .trash_suggestion(&target, &event_tx)
                .map(|_| ())
                .map_err(|err| err.to_string())
        })
        .await
        .unwrap_or_else(|join_err| Err(format!("suggestion-trash task failed: {join_err}")));
        let _ = tx.send(TuiEvent::SuggestionTrashed { path, result }).await;
    });
}

/// Drop a just-trashed suggestion from the in-memory suggestion lists so it
/// disappears immediately without a rescan (mirrors the Slint app).
fn remove_suggestion_item(app: &mut App, path: &std::path::Path) {
    let Some(sugg) = app.suggestions.as_mut() else {
        return;
    };
    sugg.screenshots.retain(|item| item.path != path);
    sugg.screenshot_reclaimable = sugg
        .screenshots
        .iter()
        .fold(0u64, |acc, item| acc.saturating_add(item.bytes));
    sugg.installers.retain(|item| item.path != path);
    sugg.installer_reclaimable = sugg
        .installers
        .iter()
        .fold(0u64, |acc, item| acc.saturating_add(item.bytes));
    sugg.large_items.retain(|item| item.path != path);
    let count = app.deletable_suggestions().len();
    if app.suggestion_selected >= count {
        app.suggestion_selected = count.saturating_sub(1);
    }
}

fn arm_cleanup_confirmation(app: &mut App) {
    let Some(ref plan) = app.cleanup_plan else {
        return;
    };
    if plan.incomplete_scan {
        app.pending_cleanup_confirmation = None;
        app.set_status("Execution refused: incomplete scan. Resolve permissions and scan again.");
        return;
    }

    let Some(selected_idxs) = selected_cleanup_indices(app) else {
        return;
    };
    if selected_idxs.is_empty() {
        app.pending_cleanup_confirmation = None;
        app.set_status("No cleanable items selected! Spacebar toggles checkboxes.");
        return;
    }

    let selected_bytes = selected_idxs
        .iter()
        .map(|idx| plan.actions[*idx].reclaimable_bytes)
        .sum();
    app.pending_cleanup_confirmation = Some(selected_idxs);
    app.set_status(&format!(
        "Confirm cleanup: press y to execute {} selected items ({}) or n to cancel.",
        app.pending_cleanup_confirmation
            .as_ref()
            .map_or(0, std::vec::Vec::len),
        cleanton_common::display::human_bytes(selected_bytes)
    ));
}

fn trigger_cleanup(app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    if app.is_executing {
        return;
    }
    let Some(ref plan) = app.cleanup_plan else {
        return;
    };
    let plan = plan.clone();
    if plan.incomplete_scan {
        app.pending_cleanup_confirmation = None;
        app.set_status("Execution refused: incomplete scan. Resolve permissions and scan again.");
        return;
    }

    let Some(selected_idxs) = selected_cleanup_indices(app) else {
        return;
    };
    if selected_idxs.is_empty() {
        app.pending_cleanup_confirmation = None;
        app.set_status("No cleanable items selected! Spacebar toggles checkboxes.");
        return;
    }

    if app.pending_cleanup_confirmation.as_ref() != Some(&selected_idxs) {
        app.pending_cleanup_confirmation = None;
        app.set_status("Press c to review and arm cleanup confirmation first.");
        return;
    }
    app.pending_cleanup_confirmation = None;
    let (operation_id, cancel_token) = begin_operation(app);

    app.is_executing = true;
    app.active_screen = ActiveScreen::Execution;
    app.execution_progress = 0.0;
    app.execution_logs.clear();
    app.execution_result = None;

    let mut filtered_plan = plan.clone();
    filtered_plan.actions = selected_idxs
        .into_iter()
        .map(|idx| plan.actions[idx].clone())
        .collect();
    filtered_plan.total_reclaimable = filtered_plan
        .actions
        .iter()
        .map(|a| a.reclaimable_bytes)
        .sum();

    let orchestrator = app.orchestrator.clone();
    let tx = tx.clone();

    tokio::spawn(async move {
        // Forward executor events
        let (exec_event_tx, mut exec_event_rx) = mpsc::channel(64);
        let event_tx = tx.clone();
        let event_cancel_token = cancel_token.clone();
        tokio::spawn(async move {
            while let Some(evt) = exec_event_rx.recv().await {
                if event_cancel_token.load(Ordering::Relaxed) {
                    break;
                }
                let _ = event_tx
                    .send(TuiEvent::Engine {
                        operation_id,
                        event: evt,
                    })
                    .await;
            }
        });

        // Run the blocking executor on a blocking worker (it performs thousands
        // of filesystem operations) and honour the cancel token: cancellation
        // stops the remaining actions, not just the reporting. The terminal
        // event is ALWAYS sent — the executor may have partially run, and the
        // UI must settle on the real (possibly partial) result.
        let exec_orchestrator = orchestrator.clone();
        let exec_cancel = cancel_token.clone();
        let res = tokio::task::spawn_blocking(move || {
            exec_orchestrator.execute_plan_with_cancel(&filtered_plan, &exec_event_tx, &exec_cancel)
        })
        .await
        .unwrap_or_else(|join_err| {
            Err(cleanton_common::CleantonError::Scan(format!(
                "execution task failed: {join_err}"
            )))
        });
        let _ = tx
            .send(TuiEvent::ExecutionFinished {
                operation_id,
                result: res,
            })
            .await;
    });
}

/// Load (or reload) the installed-application inventory on a blocking worker.
fn load_installed_apps(app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    if app.apps_loading {
        return;
    }
    app.apps_loading = true;
    app.apps_load_attempted = true;
    app.set_status("Loading applications…");
    let tx = tx.clone();
    tokio::spawn(async move {
        let apps = tokio::task::spawn_blocking(cleanton_engine::list_installed_apps)
            .await
            .unwrap_or_default();
        // Homebrew cask tokens, so uninstall can also run `brew uninstall`.
        // A missing/slow brew degrades to no casks; the trash path still works.
        let cask_tokens: Vec<String> = cleanton_packages::PackageManagers::inventory(
            cleanton_packages::ManagerKind::HomebrewCask,
        )
        .await
        .packages
        .into_iter()
        .map(|pkg| pkg.name)
        .collect();
        let _ = tx.send(TuiEvent::AppsLoaded { apps, cask_tokens }).await;
    });
}

/// The installed app under the cursor, resolved through the hide-system filter.
fn selected_installed_app(app: &App) -> Option<&cleanton_engine::InstalledApp> {
    let visible = app.visible_app_indices();
    visible
        .get(app.selected_app_idx)
        .and_then(|&idx| app.installed_apps.get(idx))
}

/// Discover the selected app's leftovers on a blocking worker (sizes walk disk).
fn load_app_leftovers(app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    let Some(selected) = selected_installed_app(app).cloned() else {
        return;
    };
    load_leftovers_for_app(app, selected, tx);
}

/// Discover a specific app's leftovers. Used by list selection and by the
/// external-removal deep-link (where the app is no longer in the inventory).
fn load_leftovers_for_app(
    app: &mut App,
    target: cleanton_engine::InstalledApp,
    tx: &mpsc::Sender<TuiEvent>,
) {
    if target.protected {
        app.set_status(&format!(
            "{} is a system application and cannot be uninstalled.",
            target.name
        ));
        return;
    }
    if app.leftover_loading {
        return;
    }
    app.leftover_loading = true;
    app.app_uninstall_plan = None;
    app.leftover_target_path = Some(target.path.clone());
    app.leftover_selected = 0;
    app.leftover_excluded.clear();
    app.set_status(&format!("Scanning leftovers of {}…", target.name));
    let tx = tx.clone();
    tokio::spawn(async move {
        let app_path = target.path.clone();
        let plan = tokio::task::spawn_blocking(move || cleanton_engine::find_leftovers(&target))
            .await
            .ok()
            .flatten();
        let _ = tx
            .send(TuiEvent::AppLeftoversLoaded {
                app_path,
                plan: plan.map(Box::new),
            })
            .await;
    });
}

/// Toggle include/exclude for the leftover row under the cursor. Admin-required
/// items are never includable (they are review-only in the engine as well).
fn toggle_leftover_selected(app: &mut App) {
    let Some(plan) = app.app_uninstall_plan.as_ref() else {
        return;
    };
    let idx = app.leftover_selected;
    let Some(item) = plan.items.get(idx) else {
        return;
    };
    if item.admin_required {
        app.set_status(
            "This item needs admin rights: once the app is gone it appears as orphaned on the Services tab and can be removed there.",
        );
        return;
    }
    if !app.leftover_excluded.remove(&idx) {
        app.leftover_excluded.insert(idx);
    }
}

fn arm_app_uninstall(app: &mut App) {
    let Some(plan) = app.app_uninstall_plan.as_ref() else {
        app.set_status("Press Enter on an application first to review its leftovers.");
        return;
    };
    if app.uninstalling {
        return;
    }
    let (count, bytes) = included_leftovers(app, plan);
    if count == 0 {
        app.set_status("Nothing selected: every item is excluded.");
        return;
    }
    app.pending_cleanup_confirmation = None;
    let name = plan.app.name.clone();
    app.pending_uninstall = true;
    app.set_status(&format!(
        "Uninstall {name}: move {count} item(s) ({}) to Trash? Press y to confirm, n to cancel.",
        cleanton_common::display::human_bytes(bytes)
    ));
}

fn included_leftovers(app: &App, plan: &cleanton_engine::UninstallPlan) -> (usize, u64) {
    plan.items
        .iter()
        .enumerate()
        .filter(|(idx, item)| !item.admin_required && !app.leftover_excluded.contains(idx))
        .fold((0usize, 0u64), |(count, bytes), (_, item)| {
            (count + 1, bytes.saturating_add(item.bytes))
        })
}

/// Execute the confirmed uninstall: best-effort stop of the app's user launch
/// agents, then everything included goes through the executor's
/// uninstall-scoped trash path on a blocking worker.
fn trigger_app_uninstall(app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    if !app.pending_uninstall || app.uninstalling {
        return;
    }
    app.pending_uninstall = false;
    let Some(plan) = app.app_uninstall_plan.as_ref() else {
        return;
    };
    let paths: Vec<std::path::PathBuf> = plan
        .items
        .iter()
        .enumerate()
        .filter(|(idx, item)| !item.admin_required && !app.leftover_excluded.contains(idx))
        .map(|(_, item)| item.path.clone())
        .collect();
    let agent_labels: Vec<String> = plan
        .items
        .iter()
        .enumerate()
        .filter(|(idx, item)| !item.admin_required && !app.leftover_excluded.contains(idx))
        .filter_map(|(_, item)| item.launchd_label.clone())
        .collect();
    if paths.is_empty() {
        return;
    }

    // If installed via a Homebrew cask, remove it through brew too.
    let cask_token = cleanton_engine::cask_token_for(&plan.app, &app.apps_cask_tokens);

    // Record the bundle path so the removal watcher treats trashing it as a
    // Cleanton-initiated removal, not an external one to deep-link again.
    if let Ok(mut set) = app.uninstalled_by_us.lock() {
        set.insert(plan.app.path.clone());
    }

    let app_name = plan.app.name.clone();
    app.uninstalling = true;
    app.set_status(&format!("Uninstalling {app_name}…"));
    let orchestrator = app.orchestrator.clone();
    let config = app.config.clone();
    let tx = tx.clone();
    tokio::spawn(async move {
        // Best-effort: stop user launch agents before their plists are trashed.
        for label in &agent_labels {
            let _ = ServiceManager::new(config.clone())
                .stop_service(label)
                .await;
        }
        // Homebrew cask removal first (best-effort): brew moves the bundle to
        // the Trash and drops its records; the leftover pass clears the rest.
        if let Some(token) = &cask_token {
            let _ = cleanton_packages::PackageManagers::uninstall(
                cleanton_packages::ManagerKind::HomebrewCask,
                std::slice::from_ref(token),
            )
            .await;
        }
        let name = app_name.clone();
        let result = tokio::task::spawn_blocking(move || {
            let (event_tx, _event_rx) = mpsc::channel(64);
            orchestrator.uninstall_app_items(&paths, &event_tx)
        })
        .await
        .unwrap_or_else(|join_err| {
            Err(cleanton_common::CleantonError::Scan(format!(
                "uninstall task failed: {join_err}"
            )))
        });
        let _ = tx
            .send(TuiEvent::AppUninstallFinished {
                app_name: name,
                result,
            })
            .await;
    });
}

fn load_services(app: &mut App, tx: &mpsc::Sender<ServiceUpdate>) {
    app.is_loading_services = true;
    app.pending_service_confirmation = None;
    let config = app.config.clone();
    let tx = tx.clone();
    tokio::spawn(async move {
        let manager = ServiceManager::new(config);
        match manager.list_services().await {
            Ok(list) => {
                let _ = tx.send(ServiceUpdate::List(list)).await;
            }
            Err(e) => {
                let _ = tx
                    .send(ServiceUpdate::StatusMessage(format!(
                        "Failed to query services: {}",
                        e
                    )))
                    .await;
            }
        }
    });
}

impl ServiceActionKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Delete => "delete",
        }
    }

    const fn gerund(self) -> &'static str {
        match self {
            Self::Start => "starting",
            Self::Stop => "stopping",
            Self::Restart => "restarting",
            Self::Enable => "enabling",
            Self::Disable => "disabling",
            Self::Delete => "deleting",
        }
    }

    const fn confirmation_phrase(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Enable => "enable auto-load for",
            Self::Disable => "disable auto-load for",
            Self::Delete => "delete the orphaned plist for",
        }
    }
}

fn selected_service(app: &App) -> Option<&Service> {
    let visible = app.visible_service_indices();
    visible
        .get(app.selected_service_idx)
        .and_then(|&idx| app.services.get(idx))
}

fn service_protected_message(svc: &Service) -> String {
    format!(
        "Action refused: {} is a system-protected, read-only service.",
        svc.name
    )
}

fn arm_service_confirmation(app: &mut App, action: ServiceActionKind) {
    if app.services.is_empty() {
        return;
    }
    let Some(svc) = selected_service(app) else {
        app.pending_service_confirmation = None;
        return;
    };
    let service_id = svc.id.clone();
    let service_name = svc.name.clone();

    if cleanton_services::is_protected(&svc.id, &svc.plist_path) {
        let msg = service_protected_message(svc);
        app.pending_service_confirmation = None;
        app.service_logs.push(msg.clone());
        app.set_status(&msg);
        return;
    }

    app.pending_cleanup_confirmation = None;
    app.pending_service_confirmation = Some(PendingServiceConfirmation { action, service_id });
    app.set_status(&format!(
        "Confirm service action: press y to {} '{}' or n to cancel.",
        action.confirmation_phrase(),
        service_name
    ));
}

fn trigger_service_action(app: &mut App, tx: &mpsc::Sender<ServiceUpdate>) {
    let Some(svc) = selected_service(app) else {
        app.pending_service_confirmation = None;
        return;
    };
    let Some(pending) = app.pending_service_confirmation.clone() else {
        app.set_status("Press a service action key first, then y to confirm.");
        return;
    };
    if pending.service_id != svc.id {
        app.pending_service_confirmation = None;
        app.set_status("Service selection changed. Press the action key again to confirm.");
        return;
    }
    if cleanton_services::is_protected(&svc.id, &svc.plist_path) {
        let msg = service_protected_message(svc);
        app.pending_service_confirmation = None;
        app.service_logs.push(msg.clone());
        app.set_status(&msg);
        return;
    }

    let action = pending.action;
    let service_id = pending.service_id;
    app.pending_service_confirmation = None;

    let config = app.config.clone();
    let tx = tx.clone();

    tokio::spawn(async move {
        let manager = ServiceManager::new(config);
        let _ = tx
            .send(ServiceUpdate::StatusMessage(format!(
                "Service {} ...",
                action.gerund()
            )))
            .await;

        let res = match action {
            ServiceActionKind::Start => manager.start_service(&service_id).await,
            ServiceActionKind::Stop => manager.stop_service(&service_id).await,
            ServiceActionKind::Restart => manager.restart_service(&service_id).await,
            ServiceActionKind::Enable => manager.enable_service(&service_id).await,
            ServiceActionKind::Disable => manager.disable_service(&service_id).await,
            ServiceActionKind::Delete => manager.delete_orphaned_plist(&service_id).await,
        };

        match res {
            Ok(_) => {
                let _ = tx
                    .send(ServiceUpdate::StatusMessage(format!(
                        "Service {} completed successfully.",
                        action.as_str()
                    )))
                    .await;
                // reload list
                if let Ok(list) = manager.list_services().await {
                    let _ = tx.send(ServiceUpdate::List(list)).await;
                }
            }
            Err(e) => {
                let _ = tx
                    .send(ServiceUpdate::StatusMessage(format!(
                        "Service {} failed: {}",
                        action.as_str(),
                        e
                    )))
                    .await;
            }
        }
    });
}

fn modify_setting(app: &mut App, increase: bool) {
    match app.active_setting_tab {
        0 => match app.active_setting_idx {
            0 => {
                let current = &app.config.general.default_root;
                app.config.general.default_root = if current.to_string_lossy() == "~" {
                    PathBuf::from("/")
                } else if current.to_string_lossy() == "/" {
                    PathBuf::from("/tmp")
                } else {
                    PathBuf::from("~")
                };
            }
            1 => {
                app.config.general.auto_scan_on_launch = !app.config.general.auto_scan_on_launch;
            }
            2 => {
                let current = &app.config.general.theme;
                app.config.general.theme = if current == "dark" {
                    "light".to_owned()
                } else {
                    "dark".to_owned()
                };
            }
            3 => {
                let current = &app.config.general.animation_speed;
                app.config.general.animation_speed = if current == "normal" {
                    "fast".to_owned()
                } else if current == "fast" {
                    "slow".to_owned()
                } else {
                    "normal".to_owned()
                };
            }
            4 => {
                let current = app.config.general.log_retention_days;
                app.config.general.log_retention_days = if increase {
                    current.saturating_add(5)
                } else {
                    current.saturating_sub(5).max(1)
                };
            }
            5 => {
                let current = app.config.general.log_retention_count;
                app.config.general.log_retention_count = if increase {
                    current.saturating_add(5)
                } else {
                    current.saturating_sub(5).max(1)
                };
            }
            _ => {}
        },
        1 => match app.active_setting_idx {
            0 => {
                let current = app.config.scanning.max_depth;
                app.config.scanning.max_depth = if increase {
                    current.saturating_add(1)
                } else {
                    current.saturating_sub(1).max(1)
                };
            }
            1 => {
                app.config.scanning.respect_gitignore = !app.config.scanning.respect_gitignore;
            }
            2 => {
                app.config.scanning.follow_symlinks = !app.config.scanning.follow_symlinks;
            }
            3 => {
                let current = app.config.scanning.parallel_threads;
                app.config.scanning.parallel_threads = if increase {
                    current.saturating_add(1)
                } else {
                    current.saturating_sub(1)
                };
            }
            4 => {
                app.config.scanning.exclude_cloud_roots = !app.config.scanning.exclude_cloud_roots;
            }
            5 => {
                app.config.scanning.exclude_external_volumes =
                    !app.config.scanning.exclude_external_volumes;
            }
            _ => {}
        },
        2 => match app.active_setting_idx {
            0 => {
                app.config.safety.default_action = match app.config.safety.default_action {
                    ActionType::Trash => ActionType::Delete,
                    ActionType::Delete => ActionType::Archive,
                    ActionType::Archive => ActionType::Trash,
                };
            }
            1 => {
                let current = app.config.safety.max_single_run_gb;
                app.config.safety.max_single_run_gb = if increase {
                    current.saturating_add(5)
                } else {
                    current.saturating_sub(5).max(1)
                };
            }
            2 => {
                let current = app.config.safety.max_single_action_gb;
                app.config.safety.max_single_action_gb = if increase {
                    current.saturating_add(5)
                } else {
                    current.saturating_sub(5).max(1)
                };
            }
            3 => {
                app.config.safety.require_confirmation = !app.config.safety.require_confirmation;
            }
            _ => {}
        },
        3 => match app.active_setting_idx {
            0 => {
                app.config.ml.enabled = !app.config.ml.enabled;
            }
            1 => {
                let current = app.config.ml.confidence_threshold;
                app.config.ml.confidence_threshold = if increase {
                    (current + 0.05).min(1.0)
                } else {
                    (current - 0.05).max(0.0)
                };
            }
            _ => {}
        },
        _ => {}
    }
}

fn save_config(app: &mut App) {
    let config = app.config.clone();
    tokio::spawn(async move {
        if let Some(path) = CleantonConfig::config_path() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(toml_str) = toml::to_string_pretty(&config) {
                let _ = std::fs::write(&path, toml_str);
            }
        }
    });
    app.set_status("Configuration successfully saved to config.toml.");
}

// ───────────────────────────── Packages screen ──────────────────────────────

/// Lazily kick off the first inventory load when the Packages screen is shown.
/// Guarded so re-entry while a manager is already loaded/loading does nothing.
fn maybe_load_packages(app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    if app.active_screen == ActiveScreen::Packages
        && app.package_inventory.is_none()
        && !app.package_loading
        && !app.package_acting
    {
        trigger_package_load(app, tx);
    }
}

/// Dev roots scanned for codebase-usage of packages: the configured scan root
/// plus the usual project homes, de-duplicated to those that exist. Mirrors the
/// app's `package_scan_roots`.
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

/// Begin a two-phase load for the active manager. Phase 1 reads the inventory
/// (shown immediately); phase 2 runs the slow outdated check plus the Homebrew
/// codebase-usage scan in the background. A monotonic `load_id` lets the event
/// loop discard results from a superseded manager selection.
fn trigger_package_load(app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    if app.package_acting {
        return;
    }
    app.package_load_id = app.package_load_id.wrapping_add(1);
    let load_id = app.package_load_id;
    let manager_idx = app.package_manager_idx;
    let kind = app.current_package_manager();

    app.package_loading = true;
    app.package_phase2 = false;
    app.pending_package_confirmation = None;
    app.package_inventory = None;
    app.package_plan = None;
    app.package_keep.clear();
    app.package_selected_idx = 0;
    app.package_note = None;
    app.package_action_status.clear();
    let status = format!("Reading {} inventory…", kind.label());
    app.set_status(&status);
    app.package_status = status;

    let roots = package_scan_roots(&app.config);
    let tx = tx.clone();
    tokio::spawn(async move {
        // Phase 1 — inventory, shown immediately.
        let inventory = PackageManagers::inventory(kind).await;
        let any = !inventory.packages.is_empty();
        let do_usage = matches!(kind, ManagerKind::Homebrew) && any;
        let names: Vec<String> = if do_usage {
            inventory.packages.iter().map(|p| p.name.clone()).collect()
        } else {
            Vec::new()
        };
        let _ = tx
            .send(TuiEvent::Package(PackageUpdate::Inventory {
                load_id,
                manager_idx,
                inventory: Box::new(inventory),
            }))
            .await;
        if !any {
            return;
        }

        // Phase 2 — slow probes: update check (every manager) plus the codebase
        // usage scan (Homebrew only). `scan_usage` is blocking std-fs work, so it
        // runs on the blocking pool to avoid stalling an async worker.
        let outdated = PackageManagers::outdated(kind).await;
        let usage = if do_usage {
            tokio::task::spawn_blocking(move || scan_usage(&names, &roots))
                .await
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        let _ = tx
            .send(TuiEvent::Package(PackageUpdate::Enriched {
                load_id,
                manager_idx,
                outdated,
                usage,
            }))
            .await;
    });
}

fn handle_package_update(app: &mut App, tx: &mpsc::Sender<TuiEvent>, update: PackageUpdate) {
    match update {
        PackageUpdate::Inventory {
            load_id,
            manager_idx,
            inventory,
        } => apply_package_inventory(app, load_id, manager_idx, *inventory),
        PackageUpdate::Enriched {
            load_id,
            manager_idx,
            outdated,
            usage,
        } => apply_package_enriched(app, load_id, manager_idx, &outdated, &usage),
        PackageUpdate::ActionFinished { outcome } => {
            apply_package_action_finished(app, tx, &outcome);
        }
    }
}

/// Returns `true` if a background package result is still for the manager the
/// user is currently looking at (not superseded by a newer selection/load).
fn package_result_current(app: &App, load_id: u64, manager_idx: usize) -> bool {
    app.package_load_id == load_id && app.package_manager_idx == manager_idx
}

/// Apply phase-1 inventory: retain it, default the keep-set to ALL packages, and
/// recompute the removal plan. Mirrors the app's `apply_inventory`.
fn apply_package_inventory(app: &mut App, load_id: u64, manager_idx: usize, inventory: Inventory) {
    if !package_result_current(app, load_id, manager_idx) {
        return;
    }
    app.package_loading = false;
    app.package_supports_keepset = matches!(inventory.manager, ManagerKind::Homebrew);
    app.package_note.clone_from(&inventory.note);
    let any = !inventory.packages.is_empty();
    let status = package_status_text(&inventory);

    // Default: keep everything (so nothing is removable until the user unchecks).
    app.package_keep = inventory.packages.iter().map(|p| p.name.clone()).collect();
    app.package_inventory = Some(inventory);
    recompute_package_plan(app);

    if any {
        app.package_phase2 = true;
        app.package_action_status = if app.package_supports_keepset {
            "Checking for updates and which packages your codebases use…".to_owned()
        } else {
            "Checking for available updates…".to_owned()
        };
    }
    app.set_status(&status);
    app.package_status = status;
}

/// Apply phase-2 results: fill in `outdated_to` and `used_by` on the retained
/// inventory and summarise. Mirrors the app's `apply_outdated` + `apply_usage`.
fn apply_package_enriched(
    app: &mut App,
    load_id: u64,
    manager_idx: usize,
    outdated: &HashMap<String, String>,
    usage: &HashMap<String, Vec<PathBuf>>,
) {
    if !package_result_current(app, load_id, manager_idx) {
        return;
    }
    app.package_phase2 = false;
    let mut update_count: usize = 0;
    if let Some(inv) = app.package_inventory.as_mut() {
        for pkg in &mut inv.packages {
            pkg.outdated_to = outdated.get(&pkg.name).cloned();
            if pkg.outdated_to.is_some() {
                update_count = update_count.saturating_add(1);
            }
            if let Some(paths) = usage.get(&pkg.name) {
                pkg.used_by = paths.iter().map(|p| p.display().to_string()).collect();
            }
        }
    }
    let flagged = usage.values().filter(|v| !v.is_empty()).count();
    let updates = if update_count == 1 {
        "1 update available".to_owned()
    } else {
        format!("{update_count} updates available")
    };
    app.package_action_status = if flagged > 0 {
        format!("{updates} · {flagged} package(s) referenced by your codebases — see warnings.")
    } else {
        updates
    };
}

/// A mutating action finished: report it, refresh disk capacity, and reload the
/// inventory so the list reflects the change. Mirrors the app's flow.
fn apply_package_action_finished(
    app: &mut App,
    tx: &mpsc::Sender<TuiEvent>,
    outcome: &ActionOutcome,
) {
    app.package_acting = false;
    let summary = if outcome.freed_bytes > 0 {
        format!(
            "{} (freed {})",
            outcome.message,
            cleanton_common::display::human_bytes(outcome.freed_bytes)
        )
    } else {
        outcome.message.clone()
    };
    app.set_status(&summary);
    app.package_action_status = summary;
    app.refresh_capacity();
    // Reload so the list reflects the change (also re-runs the outdated probe).
    trigger_package_load(app, tx);
}

/// Recompute the keep-set removal plan from the retained inventory + keep-set.
fn recompute_package_plan(app: &mut App) {
    let Some(inv) = app.package_inventory.as_ref() else {
        app.package_plan = None;
        return;
    };
    app.package_plan = Some(plan_removal(inv, &app.package_keep));
}

fn package_status_text(inventory: &Inventory) -> String {
    if inventory.available {
        format!(
            "{} · {} installed",
            inventory.manager.label(),
            inventory.packages.len()
        )
    } else {
        format!("{} not installed", inventory.manager.label())
    }
}

/// Per-screen key handling for the Packages tab.
fn handle_packages_key(key: KeyEvent, app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    use crossterm::event::KeyCode;
    match key.code {
        KeyCode::Left | KeyCode::Char('[') => switch_package_manager(app, tx, false),
        KeyCode::Right | KeyCode::Char(']') => switch_package_manager(app, tx, true),
        KeyCode::Up => {
            app.pending_package_confirmation = None;
            app.package_selected_idx = app.package_selected_idx.saturating_sub(1);
        }
        KeyCode::Down => {
            app.pending_package_confirmation = None;
            let count = app
                .package_inventory
                .as_ref()
                .map_or(0, |inv| inv.packages.len());
            if app.package_selected_idx + 1 < count {
                app.package_selected_idx += 1;
            }
        }
        KeyCode::Char(' ') => toggle_package_keep_selected(app),
        KeyCode::Char('a') => set_all_package_keep(app, true),
        KeyCode::Char('z') => set_all_package_keep(app, false),
        KeyCode::Char('r') => arm_package_confirmation(app, PackageActionKind::RemoveUnkept),
        KeyCode::Char('u') => {
            if let Some(name) = selected_package_name(app) {
                arm_package_confirmation(app, PackageActionKind::UpdateSelected(name));
            }
        }
        KeyCode::Char('U') => arm_package_confirmation(app, PackageActionKind::UpdateAll),
        KeyCode::Char('c') => arm_package_confirmation(app, PackageActionKind::CleanCache),
        KeyCode::Char('y') => confirm_package_action(app, tx),
        KeyCode::Char('n') => {
            if app.pending_package_confirmation.take().is_some() {
                app.set_status("Package action confirmation cancelled.");
            }
        }
        KeyCode::Char('l') => trigger_package_load(app, tx),
        _ => {}
    }
}

fn selected_package_name(app: &App) -> Option<String> {
    app.package_inventory
        .as_ref()
        .and_then(|inv| inv.packages.get(app.package_selected_idx))
        .map(|pkg| pkg.name.clone())
}

fn switch_package_manager(app: &mut App, tx: &mpsc::Sender<TuiEvent>, forward: bool) {
    if app.package_acting {
        return;
    }
    let count = crate::app::PKG_MANAGER_ORDER.len();
    app.package_manager_idx = if forward {
        (app.package_manager_idx + 1) % count
    } else {
        (app.package_manager_idx + count - 1) % count
    };
    trigger_package_load(app, tx);
}

fn toggle_package_keep_selected(app: &mut App) {
    if !app.package_supports_keepset {
        app.set_status("Keep-set removal is only available for Homebrew formulae.");
        return;
    }
    let Some(name) = selected_package_name(app) else {
        return;
    };
    if app.package_keep.contains(&name) {
        app.package_keep.remove(&name);
    } else {
        app.package_keep.insert(name);
    }
    app.pending_package_confirmation = None;
    recompute_package_plan(app);
}

fn set_all_package_keep(app: &mut App, keep_all: bool) {
    if !app.package_supports_keepset {
        return;
    }
    app.package_keep.clear();
    if keep_all {
        if let Some(inv) = app.package_inventory.as_ref() {
            for pkg in &inv.packages {
                app.package_keep.insert(pkg.name.clone());
            }
        }
    }
    app.pending_package_confirmation = None;
    recompute_package_plan(app);
}

/// Validate a destructive package action and, if sound, arm it for an explicit
/// `y` confirmation. Mirrors the app's gating (Homebrew-only keep-set removal,
/// availability checks, non-empty targets).
fn arm_package_confirmation(app: &mut App, action: PackageActionKind) {
    if app.package_loading || app.package_acting {
        return;
    }
    let available = app
        .package_inventory
        .as_ref()
        .is_some_and(|inv| inv.available);
    if !available {
        app.set_status("This package manager is not installed.");
        return;
    }
    let manager = app.current_package_manager().label();

    let prompt = match &action {
        PackageActionKind::RemoveUnkept => {
            if !app.package_supports_keepset {
                app.set_status("Keep-set removal is only available for Homebrew formulae.");
                return;
            }
            let Some(plan) = app.package_plan.as_ref() else {
                return;
            };
            if plan.removable.is_empty() {
                app.set_status(
                    "Nothing to remove — press Space to uncheck packages and mark them removable.",
                );
                return;
            }
            format!(
                "Confirm: uninstall {} unkept package(s) (~{})? This cannot be undone via Trash. Press y to proceed, n to cancel.",
                plan.removable.len(),
                cleanton_common::display::human_bytes(plan.reclaimable_bytes)
            )
        }
        PackageActionKind::UpdateAll => format!(
            "Confirm: update all outdated {manager} packages? This can take a while. Press y to proceed, n to cancel."
        ),
        PackageActionKind::UpdateSelected(name) => {
            format!("Confirm: update '{name}'? Press y to proceed, n to cancel.")
        }
        PackageActionKind::CleanCache => format!(
            "Confirm: clean the {manager} download/build cache? Press y to proceed, n to cancel."
        ),
    };
    app.pending_package_confirmation = Some(action);
    app.set_status(&prompt);
}

/// Execute the armed package action on a background task. The result returns via
/// [`PackageUpdate::ActionFinished`], which reports it and reloads the inventory.
fn confirm_package_action(app: &mut App, tx: &mpsc::Sender<TuiEvent>) {
    let Some(action) = app.pending_package_confirmation.take() else {
        return;
    };
    if app.package_acting {
        return;
    }
    let kind = app.current_package_manager();

    let (pkg_action, acting_msg) = match action {
        PackageActionKind::RemoveUnkept => {
            let order = app
                .package_plan
                .as_ref()
                .map(|p| p.uninstall_order.clone())
                .unwrap_or_default();
            if order.is_empty() {
                return;
            }
            let msg = format!("Uninstalling {} package(s)…", order.len());
            (PkgAction::Uninstall(order), msg)
        }
        PackageActionKind::UpdateAll => (
            PkgAction::Update(Vec::new()),
            "Updating all outdated packages… (this can take a while)".to_owned(),
        ),
        PackageActionKind::UpdateSelected(name) => {
            let msg = format!("Updating {name}… (this can take a while)");
            (PkgAction::Update(vec![name]), msg)
        }
        PackageActionKind::CleanCache => (PkgAction::CleanCache, "Cleaning cache…".to_owned()),
    };

    app.package_acting = true;
    app.set_status(&acting_msg);
    app.package_action_status = acting_msg;

    let tx = tx.clone();
    tokio::spawn(async move {
        let outcome = match &pkg_action {
            PkgAction::Uninstall(names) => PackageManagers::uninstall(kind, names).await,
            PkgAction::Update(names) => PackageManagers::update(kind, names).await,
            PkgAction::CleanCache => PackageManagers::clean_cache(kind).await,
        };
        let _ = tx
            .send(TuiEvent::Package(PackageUpdate::ActionFinished {
                outcome: Box::new(outcome),
            }))
            .await;
    });
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    fn test_app() -> App {
        App::new(CleantonConfig::default())
    }

    #[test]
    fn beginning_new_operation_cancels_previous_token() {
        let mut app = test_app();
        let (first_id, first_token) = begin_operation(&mut app);
        assert!(is_current_operation(&app, first_id));
        assert!(!first_token.load(Ordering::Relaxed));

        let (second_id, second_token) = begin_operation(&mut app);

        assert_ne!(first_id, second_id);
        assert!(first_token.load(Ordering::Relaxed));
        assert!(!second_token.load(Ordering::Relaxed));
        assert!(!is_current_operation(&app, first_id));
        assert!(is_current_operation(&app, second_id));
    }

    #[test]
    fn cancelled_scan_clears_pending_results_and_ignores_stale_operation() {
        let mut app = test_app();
        let (operation_id, token) = begin_operation(&mut app);
        app.is_scanning = true;
        app.pending_cleanup_confirmation = Some(Vec::new());

        cancel_current_operation(&mut app);

        assert!(token.load(Ordering::Relaxed));
        assert!(!app.is_scanning);
        assert!(app.scan_result.is_none());
        assert!(app.cleanup_plan.is_none());
        assert!(app.file_tree_state.is_none());
        assert!(app.pending_cleanup_confirmation.is_none());
        assert!(!is_current_operation(&app, operation_id));
    }

    #[test]
    fn finishing_stale_operation_does_not_cancel_current_operation() {
        let mut app = test_app();
        let (old_id, old_token) = begin_operation(&mut app);
        let (current_id, current_token) = begin_operation(&mut app);

        finish_operation(&mut app, old_id);

        assert!(old_token.load(Ordering::Relaxed));
        assert!(!current_token.load(Ordering::Relaxed));
        assert!(is_current_operation(&app, current_id));
    }

    /// Numeric jumps and Tab cycling must map onto Dashboard / Results /
    /// Packages / Services / Applications / Settings with no off-by-one gap.
    #[test]
    fn tab_navigation_matches_app_screen_order() {
        let mut app = test_app();
        for (idx, expected) in [
            (1, ActiveScreen::Dashboard),
            (2, ActiveScreen::Results),
            (3, ActiveScreen::Packages),
            (4, ActiveScreen::Services),
            (5, ActiveScreen::Applications),
            (6, ActiveScreen::Settings),
        ] {
            app.set_tab(idx);
            assert_eq!(app.active_screen, expected, "numeric jump {idx}");
        }

        app.set_tab(1);
        let cycle = [
            ActiveScreen::Results,
            ActiveScreen::Packages,
            ActiveScreen::Services,
            ActiveScreen::Applications,
            ActiveScreen::Settings,
            ActiveScreen::Dashboard,
        ];
        for expected in cycle {
            app.cycle_tab();
            assert_eq!(app.active_screen, expected);
        }
    }

    fn brew_pkg(name: &str, deps: &[&str], size: u64) -> cleanton_packages::Package {
        cleanton_packages::Package {
            manager: ManagerKind::Homebrew,
            name: name.to_owned(),
            version: "1.0".to_owned(),
            size_bytes: size,
            is_leaf: true,
            explicitly_installed: true,
            outdated_to: None,
            deps: deps.iter().map(|d| (*d).to_owned()).collect(),
            used_by: Vec::new(),
        }
    }

    fn homebrew_app() -> App {
        let mut app = test_app();
        app.package_supports_keepset = true;
        app.package_inventory = Some(Inventory {
            manager: ManagerKind::Homebrew,
            available: true,
            packages: vec![
                brew_pkg("a", &["b"], 10),
                brew_pkg("b", &[], 20),
                brew_pkg("c", &[], 40),
            ],
            note: None,
        });
        // Default keep-set is ALL, matching `apply_package_inventory`.
        app.package_keep = ["a", "b", "c"].iter().map(|s| (*s).to_owned()).collect();
        recompute_package_plan(&mut app);
        app
    }

    #[test]
    fn keeping_all_packages_makes_nothing_removable() {
        let app = homebrew_app();
        let plan = app.package_plan.expect("plan recomputed");
        assert!(plan.removable.is_empty());
        assert_eq!(plan.reclaimable_bytes, 0);
    }

    #[test]
    fn unkeeping_a_leaf_marks_it_removable_and_recomputes_reclaimable() {
        let mut app = homebrew_app();
        // Select and unkeep "c" (a leaf nothing depends on).
        app.package_selected_idx = 2;
        toggle_package_keep_selected(&mut app);

        let plan = app.package_plan.as_ref().expect("plan recomputed");
        assert_eq!(plan.removable, vec!["c".to_owned()]);
        assert_eq!(plan.reclaimable_bytes, 40);

        // Unkeeping "a" keeps "b" as a dependency of nothing kept → b also removable.
        app.package_selected_idx = 0;
        toggle_package_keep_selected(&mut app);
        let plan = app.package_plan.as_ref().expect("plan recomputed");
        assert!(plan.removable.contains(&"a".to_owned()));
    }

    #[test]
    fn keep_toggle_is_ignored_for_non_homebrew_managers() {
        let mut app = homebrew_app();
        app.package_supports_keepset = false;
        app.package_selected_idx = 0;
        toggle_package_keep_selected(&mut app);
        // Keep-set untouched: still keeping everything.
        assert!(app.package_keep.contains("a"));
    }
}
