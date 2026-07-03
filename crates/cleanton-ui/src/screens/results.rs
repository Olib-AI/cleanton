use crate::app::App;
use crate::widgets::FileTree;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let has_held = !app.held_actions.is_empty();
    let constraints: Vec<Constraint> = if has_held {
        vec![
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(7),
            Constraint::Length(4),
        ]
    } else {
        vec![
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(4),
        ]
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);
    // The control pane is always last; the optional held panel sits before it.
    let controls_chunk = chunks[chunks.len() - 1];
    let held_chunk = if has_held { Some(chunks[2]) } else { None };

    // 1. Top status summary
    let plan_text = if let Some(ref plan) = app.cleanup_plan {
        let total_size = plan.total_reclaimable;
        let total_size_str = cleanton_common::display::human_bytes(total_size);
        let items_count = plan.actions.len();

        let mut selected_size = 0;
        let mut selected_count = 0;
        if let Some(ref tree_state) = app.file_tree_state {
            let selected_idxs = tree_state.get_selected_action_indices();
            selected_count = selected_idxs.len();
            for idx in selected_idxs {
                selected_size += plan.actions[idx].reclaimable_bytes;
            }
        }
        let selected_size_str = cleanton_common::display::human_bytes(selected_size);
        let warning_count = app.scan_result.as_ref().map_or(0, |r| r.errors.len());
        let coverage = if plan.incomplete_scan {
            "Incomplete"
        } else {
            "Complete"
        };

        vec![Line::from(vec![
            Span::styled("Targets Found: ", Style::default().fg(app.theme.fg)),
            Span::styled(
                format!("{} (Total {})", items_count, total_size_str),
                Style::default().fg(app.theme.highlight),
            ),
            Span::styled("   Selected: ", Style::default().fg(app.theme.fg)),
            Span::styled(
                format!("{} (Total {})", selected_count, selected_size_str),
                Style::default()
                    .fg(app.theme.success)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Coverage: ", Style::default().fg(app.theme.fg)),
            Span::styled(
                format!("{coverage}, {warning_count} warnings"),
                Style::default().fg(if plan.incomplete_scan || warning_count > 0 {
                    app.theme.warning
                } else {
                    app.theme.muted
                }),
            ),
        ])]
    } else {
        vec![Line::from(
            "No scan results. Start a filesystem scan first.",
        )]
    };

    let summary_para = Paragraph::new(plan_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Plan Summary"),
    );
    f.render_widget(summary_para, chunks[0]);

    // 2. Main content: cleanable-items tree (left) + review-only Docker and
    //    Suggestions panels (right). The review panel is rendered first (it only
    //    borrows `app` immutably) so the tree can then take a mutable borrow.
    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(chunks[1]);
    let tree_area = mid[0];
    render_review_panel(f, app, mid[1]);

    let tree_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            "Cleanable Items Hierarchy",
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let tree_inner = tree_block.inner(tree_area);
    f.render_widget(tree_block, tree_area);

    if let Some(ref mut tree_state) = app.file_tree_state {
        f.render_stateful_widget(FileTree::new(app.theme.accent), tree_inner, tree_state);
    } else {
        let empty_para = Paragraph::new(vec![
            Line::from(""),
            Line::from("   Switch to the Dashboard (1) and press [s] to start a scan."),
        ]);
        f.render_widget(empty_para, tree_inner);
    }

    // 3. Held-back panel (ML-demoted / needs explicit confirmation). These items
    // are NOT part of the executable plan and never appear in the selectable
    // tree, so they cannot ride along with a confirmed cleanup.
    if let Some(held_area) = held_chunk {
        let mut held_lines = Vec::new();
        for annotated in app.held_actions.iter().take(4) {
            let badge = crate::widgets::file_tree::ml_badge(&annotated.annotation)
                .map(|badge| format!("  [{badge}]"))
                .unwrap_or_default();
            held_lines.push(Line::from(vec![
                Span::styled(
                    format!(
                        "  {} ",
                        cleanton_common::display::human_bytes(annotated.action.reclaimable_bytes)
                    ),
                    Style::default().fg(app.theme.warning),
                ),
                Span::styled(
                    annotated.action.target.display().to_string(),
                    Style::default().fg(app.theme.fg),
                ),
                Span::styled(badge, Style::default().fg(app.theme.muted)),
            ]));
        }
        if app.held_actions.len() > 4 {
            held_lines.push(Line::from(Span::styled(
                format!("  … {} more held items", app.held_actions.len() - 4),
                Style::default().fg(app.theme.muted),
            )));
        }
        let held_para = Paragraph::new(held_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.theme.warning))
                .title(Span::styled(
                    format!(
                        " Held back / needs explicit confirmation ({}) ",
                        app.held_actions.len()
                    ),
                    Style::default()
                        .fg(app.theme.warning)
                        .add_modifier(Modifier::BOLD),
                )),
        );
        f.render_widget(held_para, held_area);
    }

    // 4. Actions Panel
    let cleanup_control = if app.pending_cleanup_confirmation.is_some() {
        (
            "[y]          ",
            "CONFIRM AND EXECUTE CLEANUP",
            app.theme.success,
        )
    } else {
        (
            "[c]          ",
            "Review cleanup selection",
            app.theme.accent,
        )
    };
    let cancel_control = if app.pending_cleanup_confirmation.is_some() {
        "[n] Cancel confirmation"
    } else {
        ""
    };

    let actions_text = vec![
        Line::from(vec![
            Span::styled(
                "  [Up/Down] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Navigate Targets   ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "[Left/Right] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Collapse/Expand Node", Style::default().fg(app.theme.fg)),
        ]),
        Line::from(vec![
            Span::styled(
                "  [Space]   ",
                Style::default()
                    .fg(app.theme.highlight)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Toggle Selection   ", Style::default().fg(app.theme.fg)),
            Span::styled(
                cleanup_control.0,
                Style::default()
                    .fg(cleanup_control.2)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(cleanup_control.1, Style::default().fg(app.theme.fg)),
            Span::styled("   ", Style::default().fg(app.theme.fg)),
            Span::styled(cancel_control, Style::default().fg(app.theme.muted)),
        ]),
    ];
    let actions_para = Paragraph::new(actions_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Control Pane"),
    );
    f.render_widget(actions_para, controls_chunk);
}

/// Render the review-only panel: Docker reclaimable accounting (top) and
/// large-item / duplicate suggestions (bottom). Both are advisory — they are
/// never part of the executable cleanup plan and offer no delete affordance.
fn render_review_panel(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(3)])
        .split(area);

    render_docker(f, app, rows[0]);
    render_suggestions(f, app, rows[1]);
}

fn render_docker(f: &mut Frame, app: &App, area: Rect) {
    use cleanton_common::display::human_bytes;

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            "Docker (review only)",
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = match app.docker.as_ref() {
        Some(docker) if docker.total_reclaimable > 0 => {
            let images: u64 = docker.dangling_images.iter().map(|i| i.size).sum();
            let containers: u64 = docker.stopped_containers.iter().map(|c| c.size).sum();
            let volumes: u64 = docker.unused_volumes.iter().map(|v| v.size).sum();
            vec![
                Line::from(vec![
                    Span::styled("  Reclaimable: ", Style::default().fg(app.theme.fg)),
                    Span::styled(
                        human_bytes(docker.total_reclaimable),
                        Style::default()
                            .fg(app.theme.accent)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                docker_line(app, "Build cache", docker.build_cache.size, ""),
                docker_line(
                    app,
                    "Dangling images",
                    images,
                    &format!(" ({})", docker.dangling_images.len()),
                ),
                docker_line(
                    app,
                    "Stopped containers",
                    containers,
                    &format!(" ({})", docker.stopped_containers.len()),
                ),
                docker_line(
                    app,
                    "Unused volumes",
                    volumes,
                    &format!(" ({})", docker.unused_volumes.len()),
                ),
                Line::from(Span::styled(
                    "  clean via: cleanton docker clean",
                    Style::default().fg(app.theme.muted),
                )),
            ]
        }
        _ => vec![Line::from(Span::styled(
            "  No reclaimable Docker space (or Docker is not running).",
            Style::default().fg(app.theme.muted),
        ))],
    };
    f.render_widget(Paragraph::new(lines), inner);
}

fn docker_line(app: &App, label: &str, bytes: u64, suffix: &str) -> Line<'static> {
    use cleanton_common::display::human_bytes;
    Line::from(vec![
        Span::styled(
            format!("  {label:<20}{suffix} "),
            Style::default().fg(app.theme.fg),
        ),
        Span::styled(human_bytes(bytes), Style::default().fg(app.theme.highlight)),
    ])
}

fn render_suggestions(f: &mut Frame, app: &App, area: Rect) {
    use cleanton_common::display::human_bytes;

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            "Suggestions (review only)",
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(sugg) = app.suggestions.as_ref() else {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  Run a scan to surface duplicates and large items.",
                Style::default().fg(app.theme.muted),
            ))),
            inner,
        );
        return;
    };
    if sugg.duplicates.is_empty()
        && sugg.large_items.is_empty()
        && sugg.screenshots.is_empty()
        && sugg.installers.is_empty()
    {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  No duplicate sets, large items, screenshots, or installers found.",
                Style::default().fg(app.theme.muted),
            ))),
            inner,
        );
        return;
    }

    // Budget the visible rows to the panel height so nothing overflows.
    let capacity = inner.height as usize;
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(capacity);

    // Running index over the deletable rows, in the exact order of
    // `App::deletable_suggestions` (screenshots, installers, large items).
    // The selected row gets a marker and can be trashed with [t] → [y].
    let mut deletable_idx = 0usize;
    let selected = app.suggestion_selected;
    let armed = app.pending_suggestion_trash.as_deref();
    let mut selectable_prefix = |path: &std::path::Path| -> (String, Style) {
        let is_selected = deletable_idx == selected;
        let is_armed = armed.is_some_and(|armed| armed == path);
        deletable_idx += 1;
        if is_armed {
            (
                "  ▸ ".to_owned(),
                Style::default()
                    .fg(app.theme.danger)
                    .add_modifier(Modifier::BOLD),
            )
        } else if is_selected {
            (
                "  ▸ ".to_owned(),
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            ("    ".to_owned(), Style::default().fg(app.theme.fg))
        }
    };

    if !sugg.duplicates.is_empty() {
        let sampled = if sugg.truncated { " (sampled)" } else { "" };
        lines.push(Line::from(Span::styled(
            format!(
                "  Duplicates: {} set(s), {} reclaimable{}",
                sugg.duplicates.len(),
                human_bytes(sugg.duplicate_reclaimable),
                sampled
            ),
            Style::default()
                .fg(app.theme.warning)
                .add_modifier(Modifier::BOLD),
        )));
        for set in sugg.duplicates.iter().take(3) {
            let name = set.paths.first().and_then(|p| p.file_name()).map_or_else(
                || "duplicate".to_owned(),
                |n| n.to_string_lossy().into_owned(),
            );
            lines.push(Line::from(Span::styled(
                format!(
                    "    {}× {} ({} each) — save {}",
                    set.count,
                    name,
                    human_bytes(set.file_bytes),
                    human_bytes(set.reclaimable_bytes)
                ),
                Style::default().fg(app.theme.fg),
            )));
        }
    }

    if !sugg.screenshots.is_empty() {
        lines.push(Line::from(Span::styled(
            format!(
                "  Screenshots & recordings: {} file(s), {}",
                sugg.screenshots.len(),
                human_bytes(sugg.screenshot_reclaimable)
            ),
            Style::default()
                .fg(app.theme.highlight)
                .add_modifier(Modifier::BOLD),
        )));
        for item in sugg
            .screenshots
            .iter()
            .take(crate::app::App::SUGGESTIONS_PER_CATEGORY)
        {
            let (prefix, style) = selectable_prefix(&item.path);
            lines.push(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(
                    format!("{} ", human_bytes(item.bytes)),
                    Style::default()
                        .fg(app.theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(path_tail(&item.path), style),
            ]));
        }
    }

    if !sugg.installers.is_empty() {
        lines.push(Line::from(Span::styled(
            format!(
                "  Old installers in Downloads: {} file(s), {} (re-downloadable)",
                sugg.installers.len(),
                human_bytes(sugg.installer_reclaimable)
            ),
            Style::default()
                .fg(app.theme.highlight)
                .add_modifier(Modifier::BOLD),
        )));
        for item in sugg
            .installers
            .iter()
            .take(crate::app::App::SUGGESTIONS_PER_CATEGORY)
        {
            let (prefix, style) = selectable_prefix(&item.path);
            lines.push(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(
                    format!("{} ", human_bytes(item.bytes)),
                    Style::default()
                        .fg(app.theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(path_tail(&item.path), style),
            ]));
        }
    }

    if !sugg.large_items.is_empty() {
        lines.push(Line::from(Span::styled(
            "  Largest files & folders:",
            Style::default()
                .fg(app.theme.highlight)
                .add_modifier(Modifier::BOLD),
        )));
        for item in sugg
            .large_items
            .iter()
            .take(crate::app::App::SUGGESTIONS_PER_CATEGORY)
        {
            let kind = if item.is_dir { " (folder)" } else { "" };
            let tag = if item.redownloadable {
                " · re-clonable"
            } else {
                ""
            };
            let (prefix, style) = selectable_prefix(&item.path);
            lines.push(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(
                    format!("{} ", human_bytes(item.bytes)),
                    Style::default()
                        .fg(app.theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{}{}{}", path_tail(&item.path), kind, tag), style),
            ]));
        }
    }

    if lines.len() < capacity {
        lines.push(Line::from(Span::styled(
            "  [ / ] select · [t] Trash selected · duplicates are reveal-only",
            Style::default().fg(app.theme.muted),
        )));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

/// Compact a path to its last two components for the narrow review panel.
fn path_tail(path: &std::path::Path) -> String {
    let comps: Vec<_> = path.components().collect();
    let tail: std::path::PathBuf = comps
        .iter()
        .rev()
        .take(2)
        .rev()
        .map(|c| c.as_os_str())
        .collect();
    let s = tail.display().to_string();
    if comps.len() > 2 {
        format!("…/{s}")
    } else {
        path.display().to_string()
    }
}
