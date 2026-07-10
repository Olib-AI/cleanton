use crate::app::App;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    render_app_list(f, app, chunks[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(7)])
        .split(chunks[1]);
    render_leftovers(f, app, right[0]);
    render_help(f, app, right[1]);
}

fn render_app_list(f: &mut Frame, app: &App, area: Rect) {
    use cleanton_common::display::human_bytes;

    let visible = app.visible_app_indices();
    let title = if app.apps_loading {
        "Installed Applications (loading...)".to_string()
    } else if app.apps_hide_system {
        format!(
            "Installed Applications ({} of {}, system hidden)",
            visible.len(),
            app.installed_apps.len()
        )
    } else {
        format!("Installed Applications ({})", app.installed_apps.len())
    };

    let items: Vec<ListItem> = visible
        .iter()
        .filter_map(|&app_idx| app.installed_apps.get(app_idx))
        .enumerate()
        .map(|(idx, installed)| {
            let is_selected = idx == app.selected_app_idx;
            let style = if is_selected {
                Style::default()
                    .bg(app.theme.accent)
                    .fg(Color::Rgb(15, 15, 25))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(app.theme.fg)
            };
            let tag = if installed.protected {
                "  (system)"
            } else if cleanton_engine::cask_token_for(installed, &app.apps_cask_tokens).is_some() {
                "  (brew)"
            } else {
                ""
            };
            let line = Line::from(vec![
                Span::styled(format!("{:<34}", truncate(&installed.name, 33)), style),
                Span::styled(
                    format!("{:>10}", human_bytes(installed.bytes)),
                    Style::default().fg(app.theme.highlight),
                ),
                Span::styled(tag, Style::default().fg(app.theme.muted)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title(Span::styled(
                title,
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(app.theme.accent),
            )),
    );
    f.render_widget(list, area);
}

fn render_leftovers(f: &mut Frame, app: &App, area: Rect) {
    use cleanton_common::display::human_bytes;

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            "Uninstall Review",
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.leftover_loading {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  Scanning leftovers...",
                Style::default().fg(app.theme.muted),
            ))),
            inner,
        );
        return;
    }
    let Some(plan) = app.app_uninstall_plan.as_ref() else {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Select an application and press Enter to review everything",
                    Style::default().fg(app.theme.muted),
                )),
                Line::from(Span::styled(
                    "  it would leave behind: support files, caches, preferences,",
                    Style::default().fg(app.theme.muted),
                )),
                Line::from(Span::styled(
                    "  launch items, containers, and helpers.",
                    Style::default().fg(app.theme.muted),
                )),
            ]),
            inner,
        );
        return;
    };

    let capacity = inner.height as usize;
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(capacity);
    lines.push(Line::from(vec![
        Span::styled(
            format!("  {} ", plan.app.name),
            Style::default()
                .fg(app.theme.fg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "· {} across {} item(s)",
                human_bytes(plan.total_bytes),
                plan.items.len()
            ),
            Style::default().fg(app.theme.highlight),
        ),
    ]));

    let visible = capacity.saturating_sub(2).max(1);
    // Keep the cursor in view for long item lists.
    let first = app
        .leftover_selected
        .saturating_sub(visible.saturating_sub(1));
    for (idx, item) in plan.items.iter().enumerate().skip(first).take(visible) {
        let cursor = if idx == app.leftover_selected {
            "▸"
        } else {
            " "
        };
        let (mark, mark_style) = if item.admin_required {
            ("[⚿]", Style::default().fg(app.theme.warning))
        } else if app.leftover_excluded.contains(&idx) {
            ("[ ]", Style::default().fg(app.theme.muted))
        } else {
            ("[x]", Style::default().fg(app.theme.success))
        };
        let row_style = if idx == app.leftover_selected {
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.fg)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {cursor} "), row_style),
            Span::styled(mark.to_owned(), mark_style),
            Span::styled(
                format!(" {:<18}", item.kind.label()),
                Style::default().fg(app.theme.muted),
            ),
            Span::styled(
                format!("{:>9} ", human_bytes(item.bytes)),
                Style::default().fg(app.theme.highlight),
            ),
            Span::styled(path_tail(&item.path), row_style),
        ]));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

fn render_help(f: &mut Frame, app: &App, area: Rect) {
    let confirm = if app.pending_uninstall {
        Line::from(vec![
            Span::styled(
                "  [y] ",
                Style::default()
                    .fg(app.theme.success)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "CONFIRM: MOVE TO TRASH   ",
                Style::default().fg(app.theme.danger),
            ),
            Span::styled("[n] Cancel", Style::default().fg(app.theme.muted)),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                "  [u] ",
                Style::default()
                    .fg(app.theme.danger)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Uninstall (two-step confirm)",
                Style::default().fg(app.theme.fg),
            ),
        ])
    };

    let help = vec![
        Line::from(vec![
            Span::styled(
                "  [Up/Down] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Select app   ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "[Enter] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Review leftovers   ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "[l] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Reload list   ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "[h] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if app.apps_hide_system {
                    "Show system apps"
                } else {
                    "Hide system apps"
                },
                Style::default().fg(app.theme.fg),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  [ [ / ] ] ",
                Style::default()
                    .fg(app.theme.highlight)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Move in review   ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "[Space] ",
                Style::default()
                    .fg(app.theme.highlight)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Include/exclude item (⚿ needs admin; see Services)",
                Style::default().fg(app.theme.fg),
            ),
        ]),
        confirm,
    ];

    let para = Paragraph::new(help).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Control Keys"),
    );
    f.render_widget(para, area);
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_owned()
    } else {
        let head: String = text.chars().take(max.saturating_sub(3)).collect();
        format!("{head}...")
    }
}

/// Compact a path to its last two components (same as the Results panel).
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
        format!(".../{s}")
    } else {
        path.display().to_string()
    }
}
