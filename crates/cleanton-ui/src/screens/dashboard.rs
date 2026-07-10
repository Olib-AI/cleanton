use crate::app::App;
use crate::widgets::{DonutChart, DonutSector, Sparkline};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(4)])
        .split(chunks[0]);

    // Donut Chart Pane (Left)
    let sectors = get_sectors(app);
    let chart_title = if app.is_scanning {
        "Scanning... (Press [x] to Cancel)"
    } else if app.cleanup_plan.is_some() {
        "Reclaimable Space Distribution"
    } else {
        "Scan Needed (Press [s] to Scan)"
    };

    let donut_block = Block::default()
        .title(Span::styled(
            chart_title,
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(app.theme.accent),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border));

    let donut_inner = donut_block.inner(left_chunks[0]);
    f.render_widget(donut_block, left_chunks[0]);

    if !sectors.is_empty() {
        f.render_widget(
            DonutChart::new(sectors, app.donut_animation.current()),
            donut_inner,
        );
    } else {
        // Render a big nice prompt to scan
        let prompt_para = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "   C L E A N T O N",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("   Welcome to your macOS Disk Cleaner."),
            Line::from("   No scan results available yet."),
            Line::from(""),
            Line::from(Span::styled(
                "   Press [s] or [Space] to start scanning.",
                Style::default().fg(app.theme.success),
            )),
        ]);
        f.render_widget(prompt_para, donut_inner);
    }

    // Legend at the bottom left
    let legend_lines = get_legend(app);
    let legend_para = Paragraph::new(legend_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Legend"),
    );
    f.render_widget(legend_para, left_chunks[1]);

    // Stats, Capacity, Sparkline and Help Pane (Right)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9), // Statistics
            Constraint::Length(9), // Disk capacity (honest)
            Constraint::Length(6), // Real usage-history sparkline
            Constraint::Min(3),    // Control center / help
        ])
        .split(chunks[1]);

    // Stats
    let total_reclaimable = app
        .cleanup_plan
        .as_ref()
        .map(|p| p.total_reclaimable)
        .unwrap_or(0);
    let total_reclaimable_str = cleanton_common::display::human_bytes(total_reclaimable);

    let total_files = app.scan_result.as_ref().map(|r| r.total_files).unwrap_or(0);
    let total_dirs = app.scan_result.as_ref().map(|r| r.total_dirs).unwrap_or(0);
    let duration = app
        .scan_result
        .as_ref()
        .map(|r| r.duration)
        .unwrap_or(std::time::Duration::ZERO);
    let scan_warnings = app.scan_result.as_ref().map_or(0, |r| r.errors.len());
    let coverage_status = app.scan_result.as_ref().map_or("Not scanned", |r| {
        if r.incomplete {
            "Incomplete"
        } else {
            "Complete"
        }
    });

    let stats_text = vec![
        Line::from(vec![
            Span::styled("  Total Reclaimable: ", Style::default().fg(app.theme.fg)),
            Span::styled(
                total_reclaimable_str,
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Files Scanned:     ", Style::default().fg(app.theme.fg)),
            Span::styled(
                total_files.to_string(),
                Style::default().fg(app.theme.highlight),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Directories:       ", Style::default().fg(app.theme.fg)),
            Span::styled(
                total_dirs.to_string(),
                Style::default().fg(app.theme.highlight),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Scan Duration:     ", Style::default().fg(app.theme.fg)),
            Span::styled(
                format!("{:.2?}", duration),
                Style::default().fg(app.theme.muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Scan Warnings:     ", Style::default().fg(app.theme.fg)),
            Span::styled(
                format!("{scan_warnings} ({coverage_status})"),
                Style::default().fg(if scan_warnings > 0 {
                    app.theme.warning
                } else {
                    app.theme.muted
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Protected Paths:   ", Style::default().fg(app.theme.fg)),
            Span::styled(
                app.config.safety.protected_paths.len().to_string(),
                Style::default().fg(app.theme.warning),
            ),
        ]),
    ];

    // While a scan is in flight the same panel shows live counters (files /
    // dirs / accumulated bytes), folding the old standalone Scanner screen's
    // progress view into the Dashboard, mirroring the Slint app.
    let (stats_title, stats_lines) = if app.is_scanning {
        ("Live Scanning", live_scan_lines(app))
    } else {
        ("Statistics", stats_text)
    };
    let stats_para = Paragraph::new(stats_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title(Span::styled(
                stats_title,
                Style::default().add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(stats_para, right_chunks[0]);

    // Honest disk capacity (total / used / available approx / purgeable / snapshots)
    let capacity_para = Paragraph::new(get_capacity_lines(app)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title(Span::styled(
                "Disk Capacity",
                Style::default().add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(capacity_para, right_chunks[1]);

    // Sparkline of REAL disk-usage history (used bytes per recorded sample).
    let spark_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title("Disk Usage History (used bytes per sample)");
    let spark_inner = spark_block.inner(right_chunks[2]);
    f.render_widget(spark_block, right_chunks[2]);

    let used_series = app.capacity_view.history.used_series();
    if used_series.len() >= 2 {
        f.render_widget(Sparkline::new(used_series, app.theme.success), spark_inner);
    } else {
        // Never synthesize data: show a clean "collecting" state instead.
        let collecting = Paragraph::new(Line::from(Span::styled(
            "  Collecting usage history... (need ≥2 samples)",
            Style::default().fg(app.theme.muted),
        )));
        f.render_widget(collecting, spark_inner);
    }

    // Help Panel (Quick instructions)
    let help_text = vec![
        Line::from(vec![
            Span::styled(
                "  [Tab]  ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Next Screen          ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "  [1..6] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Jump to Screen", Style::default().fg(app.theme.fg)),
        ]),
        Line::from(vec![
            Span::styled(
                "  [s]    ",
                Style::default()
                    .fg(app.theme.success)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Trigger Filesystem Scan", Style::default().fg(app.theme.fg)),
        ]),
        Line::from(vec![
            Span::styled(
                "  [x]    ",
                Style::default()
                    .fg(app.theme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Cancel Scan/Cleanup     ",
                Style::default().fg(app.theme.fg),
            ),
            Span::styled(
                "[E] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Empty Trash (reclaim)", Style::default().fg(app.theme.fg)),
        ]),
        Line::from(vec![
            Span::styled(
                "  [q/Esc]",
                Style::default()
                    .fg(app.theme.danger)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Quit App", Style::default().fg(app.theme.fg)),
        ]),
    ];
    let help_para = Paragraph::new(help_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Control Center"),
    );
    f.render_widget(help_para, right_chunks[3]);
}

/// Live scan counters shown on the Dashboard while a scan is running. Replaces
/// the deleted standalone Scanner screen's progress view.
fn live_scan_lines(app: &App) -> Vec<Line<'static>> {
    let (files, dirs, bytes) = app.scan_progress.unwrap_or((0, 0, 0));
    let value = Style::default()
        .fg(app.theme.accent)
        .add_modifier(Modifier::BOLD);
    let label = |t: &str| Span::styled(format!("  {t:<20}"), Style::default().fg(app.theme.fg));
    vec![
        Line::from(""),
        Line::from(vec![
            label("Files scanned:"),
            Span::styled(files.to_string(), value),
        ]),
        Line::from(vec![
            label("Directories entered:"),
            Span::styled(dirs.to_string(), value),
        ]),
        Line::from(vec![
            label("Accumulated size:"),
            Span::styled(cleanton_common::display::human_bytes(bytes), value),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Walking the filesystem... press [x] to cancel.",
            Style::default().fg(app.theme.muted),
        )),
    ]
}

/// Builds the honest disk-capacity readout. Distinguishes the three numbers a
/// user cares about — Reclaimable (plan target), Moved to Trash (not yet freed),
/// Freed (actually reclaimed) — and labels the OS-approximate figures as such.
fn get_capacity_lines(app: &App) -> Vec<Line<'static>> {
    use cleanton_common::display::human_bytes;

    let label =
        |text: &str| Span::styled(format!("  {text:<20}"), Style::default().fg(app.theme.fg));

    let Some(cap) = app.capacity_view.capacity else {
        let reason = app
            .capacity_view
            .error
            .clone()
            .unwrap_or_else(|| "capacity unavailable".to_owned());
        return vec![Line::from(Span::styled(
            format!("  Disk capacity unavailable: {reason}"),
            Style::default().fg(app.theme.warning),
        ))];
    };

    let used_pct = if cap.total_bytes > 0 {
        cap.used_bytes as f64 / cap.total_bytes as f64 * 100.0
    } else {
        0.0
    };

    let mut lines = vec![
        Line::from(vec![
            label("Total:"),
            Span::styled(
                human_bytes(cap.total_bytes),
                Style::default().fg(app.theme.highlight),
            ),
        ]),
        Line::from(vec![
            label("Used:"),
            Span::styled(
                format!("{} ({used_pct:.1}%)", human_bytes(cap.used_bytes)),
                Style::default().fg(app.theme.fg),
            ),
        ]),
        Line::from(vec![
            label("Available (approx):"),
            Span::styled(
                human_bytes(cap.available_for_important_usage_bytes),
                Style::default().fg(app.theme.success),
            ),
        ]),
        Line::from(vec![
            label("Purgeable (est):"),
            Span::styled(
                human_bytes(cap.purgeable_estimate_bytes),
                Style::default().fg(app.theme.muted),
            ),
        ]),
    ];

    // Trash vs Freed vs Reclaimable.
    if let Some(result) = &app.execution_result {
        if result.moved_to_trash_bytes > 0 {
            lines.push(Line::from(vec![
                label("Moved to Trash:"),
                Span::styled(
                    format!(
                        "{} (press E to empty)",
                        human_bytes(result.moved_to_trash_bytes)
                    ),
                    Style::default().fg(app.theme.warning),
                ),
            ]));
        }
        if result.freed_bytes > 0 {
            lines.push(Line::from(vec![
                label("Freed (reclaimed):"),
                Span::styled(
                    human_bytes(result.freed_bytes),
                    Style::default().fg(app.theme.success),
                ),
            ]));
        }
    } else if let Some(plan) = &app.cleanup_plan {
        lines.push(Line::from(vec![
            label("Reclaimable (plan):"),
            Span::styled(
                human_bytes(plan.total_reclaimable),
                Style::default().fg(app.theme.accent),
            ),
        ]));
    }

    // Docker reclaimable accounting is root-independent; surface it here when a
    // scan has produced a full analysis and the daemon reported reclaimable space.
    if let Some(docker) = &app.docker {
        if docker.total_reclaimable > 0 {
            lines.push(Line::from(vec![
                label("Docker (reclaimable):"),
                Span::styled(
                    human_bytes(docker.total_reclaimable),
                    Style::default().fg(app.theme.highlight),
                ),
            ]));
        }
    }

    // Non-alarming local-snapshot disclosure. Distinguish "could not query"
    // from "zero snapshots": never imply a clean disk we did not observe.
    let snapshot_count = app.capacity_view.snapshot_count();
    let snapshot_query_failed = app
        .capacity_view
        .snapshots
        .as_ref()
        .is_some_and(|snapshots| !snapshots.query_succeeded);
    if snapshot_count > 0 {
        lines.push(Line::from(Span::styled(
            format!(
                "  ⓘ {snapshot_count} local snapshots may hold space until deleted or thinned (~24h). Review on Results (2)."
            ),
            Style::default().fg(app.theme.muted),
        )));
    } else if snapshot_query_failed {
        lines.push(Line::from(Span::styled(
            "  ⓘ Local snapshot state could not be queried (tmutil unavailable or denied).",
            Style::default().fg(app.theme.muted),
        )));
    }

    lines
}

fn get_sectors(app: &App) -> Vec<DonutSector> {
    let mut sectors = Vec::new();
    let Some(plan) = &app.cleanup_plan else {
        return sectors;
    };
    if plan.total_reclaimable == 0 {
        return sectors;
    }

    // Group sizes by the recipe category carried on each action; the string
    // heuristic only handles plans persisted before that field existed.
    let mut category_sizes = std::collections::HashMap::new();
    for action in &plan.actions {
        let cat = match action.category.as_str() {
            "rust" => "Rust",
            "node" => "Node",
            "python" => "Python",
            "swift" => "Swift",
            "docker" => "Docker",
            "ml" => "ML / AI",
            "jvm" | "android" => "JVM",
            "ai-tools" => "AI Tools",
            "system" => "System",
            "apps" => "Apps",
            "go" => "Go",
            "ide" => "IDEs",
            "" => {
                let cat_name = action.recipe_id.0.to_lowercase();
                if cat_name.contains("rust") || cat_name.contains("cargo") {
                    "Rust"
                } else if cat_name.contains("node") || cat_name.contains("npm") {
                    "Node"
                } else if cat_name.contains("python")
                    || cat_name.contains("pip")
                    || cat_name.contains("cache")
                {
                    "Python"
                } else if cat_name.contains("swift")
                    || cat_name.contains("xcode")
                    || cat_name.contains("derived")
                {
                    "Swift"
                } else if cat_name.contains("docker") {
                    "Docker"
                } else if cat_name.contains("brew") {
                    "Homebrew"
                } else {
                    "Other"
                }
            }
            _ => "Other",
        };
        *category_sizes.entry(cat).or_insert(0) += action.reclaimable_bytes;
    }

    let colors = [
        Color::Rgb(99, 102, 241),  // Indigo
        Color::Rgb(34, 197, 94),   // Emerald
        Color::Rgb(250, 204, 21),  // Amber
        Color::Rgb(239, 68, 68),   // Rose
        Color::Rgb(14, 165, 233),  // Sky
        Color::Rgb(168, 85, 247),  // Purple
        Color::Rgb(100, 116, 139), // Slate
    ];

    let mut color_idx = 0;
    for (cat, size) in category_sizes {
        sectors.push(DonutSector {
            label: cat.to_string(),
            value: size as f32 / plan.total_reclaimable as f32,
            color: colors[color_idx % colors.len()],
        });
        color_idx += 1;
    }

    sectors
}

fn get_legend(app: &App) -> Vec<Line<'static>> {
    let sectors = get_sectors(app);
    if sectors.is_empty() {
        return vec![Line::from("  No data available. Trigger a scan first.")];
    }

    let mut line = Vec::new();
    for sector in sectors {
        let percent = sector.value * 100.0;
        line.push(Span::styled(
            format!("■ {} ({:.1}%)  ", sector.label, percent),
            Style::default().fg(sector.color),
        ));
    }
    vec![Line::from(line)]
}
