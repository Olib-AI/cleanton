use crate::app::App;
use crate::widgets::ProgressBar;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Progress Bar
            Constraint::Min(6),    // Realtime logs
            Constraint::Length(8), // Results overview
        ])
        .split(area);

    // 1. Progress Bar
    let title = if app.is_executing {
        "CLEANUP IN PROGRESS..."
    } else if app.execution_result.is_some() {
        "CLEANUP COMPLETED SUCCESSFULLY"
    } else {
        "CLEANUP SCHEDULER IDLE"
    };

    let prog_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            title,
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        ));
    let prog_inner = prog_block.inner(chunks[0]);
    f.render_widget(prog_block, chunks[0]);

    f.render_widget(
        ProgressBar::new(
            app.execution_progress,
            "Freeing up disk space".to_string(),
            app.theme.success,
        ),
        prog_inner,
    );

    // 2. Realtime Execution logs
    let log_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title("Deletion Log Output");

    let list_items: Vec<ListItem> = app
        .execution_logs
        .iter()
        .rev()
        .take(15)
        .map(|log| {
            let symbol = if log.contains("failed") || log.contains("error") {
                Span::styled("❌ ", Style::default().fg(app.theme.danger))
            } else if log.contains("skipped") {
                Span::styled("⚠️ ", Style::default().fg(app.theme.warning))
            } else {
                Span::styled("✓ ", Style::default().fg(app.theme.success))
            };
            ListItem::new(Line::from(vec![
                symbol,
                Span::styled(log.clone(), Style::default().fg(app.theme.fg)),
            ]))
        })
        .collect();

    let logs_list = List::new(list_items).block(log_block);
    f.render_widget(logs_list, chunks[1]);

    // 3. Results Summary (Free space cleared)
    let summary_title = Span::styled(
        "Execution Results Overview",
        Style::default()
            .fg(app.theme.highlight)
            .add_modifier(Modifier::BOLD),
    );
    let summary_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(summary_title);

    let summary_para = if let Some(ref res) = app.execution_result {
        let freed_str = cleanton_common::display::human_bytes(res.freed_bytes);
        let trash_str = cleanton_common::display::human_bytes(res.moved_to_trash_bytes);
        let log_path_str = res
            .log_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "Not saved".to_string());

        let mut lines = vec![
            Line::from(vec![
                Span::styled("  Freed (reclaimed): ", Style::default().fg(app.theme.fg)),
                Span::styled(
                    freed_str,
                    Style::default()
                        .fg(app.theme.success)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("   Moved to Trash: ", Style::default().fg(app.theme.fg)),
                Span::styled(trash_str, Style::default().fg(app.theme.highlight)),
            ]),
            Line::from(vec![
                Span::styled("  Actions Taken:    ", Style::default().fg(app.theme.fg)),
                Span::styled(
                    res.attempted_actions.to_string(),
                    Style::default().fg(app.theme.fg),
                ),
                Span::styled("   Skipped:        ", Style::default().fg(app.theme.fg)),
                Span::styled(
                    res.skipped_actions.to_string(),
                    Style::default().fg(app.theme.warning),
                ),
            ]),
        ];

        // Trash is not freed space until emptied (PLATFORM.md §1.1).
        if res.moved_to_trash_bytes > 0 {
            lines.push(Line::from(Span::styled(
                "  ⚠ Trash space is reclaimed only after you empty the Trash. Press [E] to Empty Trash now.",
                Style::default().fg(app.theme.warning),
            )));
        }

        // Non-alarming local-snapshot disclosure (PLATFORM.md §1.2).
        let snapshot_count = app.capacity_view.snapshot_count();
        if snapshot_count > 0 {
            lines.push(Line::from(Span::styled(
                format!(
                    "  ⓘ {snapshot_count} local snapshots may hold ~space until thinned (~24h)."
                ),
                Style::default().fg(app.theme.muted),
            )));
        }

        lines.push(Line::from(vec![
            Span::styled("  Log Saved To:     ", Style::default().fg(app.theme.muted)),
            Span::styled(log_path_str, Style::default().fg(app.theme.muted)),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  [Enter]/[Space] Dashboard   ·   [E] Empty Trash now (reclaim)",
            Style::default().fg(app.theme.accent),
        )));
        Paragraph::new(lines)
    } else {
        let wait_prompt = vec![
            Line::from("  Waiting for cleanup process to initiate."),
            Line::from(vec![
                Span::styled("  To start: ", Style::default().fg(app.theme.warning)),
                Span::styled(
                    "Go to Results tab (3) and press [c] to run target deletion.",
                    Style::default().fg(app.theme.fg),
                ),
            ]),
        ];
        Paragraph::new(wait_prompt)
    };

    f.render_widget(summary_para.block(summary_block), chunks[2]);
}
