use crate::app::App;
use cleanton_services::{ServiceStatus, ServiceType};
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
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(6)])
        .split(chunks[0]);

    // 1. Left side: Services List
    let list_title = if app.is_loading_services {
        "Discovered Background Services (Loading...)"
    } else {
        "Discovered Background Services"
    };

    let items: Vec<ListItem> = app
        .services
        .iter()
        .enumerate()
        .map(|(idx, svc)| {
            let is_selected = idx == app.selected_service_idx;

            let status_str = match &svc.status {
                ServiceStatus::Running { .. } => "RUNNING",
                ServiceStatus::Stopped => "STOPPED",
                ServiceStatus::Loaded => "LOADED",
                ServiceStatus::Error(_) => "ERROR",
            };

            let status_color = match &svc.status {
                ServiceStatus::Running { .. } => app.theme.success,
                ServiceStatus::Stopped => app.theme.muted,
                ServiceStatus::Loaded => app.theme.highlight,
                ServiceStatus::Error(_) => app.theme.danger,
            };

            let mutable = !cleanton_services::is_protected(&svc.id, &svc.plist_path);
            let mutable_str = if mutable { "mutable" } else { "read-only" };
            let mut_color = if mutable {
                app.theme.warning
            } else {
                app.theme.muted
            };

            let style = if is_selected {
                Style::default()
                    .bg(app.theme.accent)
                    .fg(Color::Rgb(15, 15, 25))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(app.theme.fg)
            };

            let line = Line::from(vec![
                Span::styled(format!("{:<30} ", svc.name), style),
                Span::styled(
                    format!(" [{:<7}] ", status_str),
                    Style::default()
                        .fg(status_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" ({})", mutable_str),
                    Style::default().fg(mut_color),
                ),
            ]);

            ListItem::new(line)
        })
        .collect();

    let list_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            list_title,
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(app.theme.accent),
        ));

    let services_list = List::new(items)
        .block(list_block)
        .highlight_style(Style::default().bg(app.theme.accent));

    f.render_widget(services_list, left_chunks[0]);

    // 2. Left bottom: Action execution logs
    let log_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title("Service Action Console Logs");
    let logs_to_show: Vec<ListItem> = app
        .service_logs
        .iter()
        .rev()
        .take(5)
        .map(|log| {
            ListItem::new(Line::from(vec![
                Span::styled("⚡ ", Style::default().fg(app.theme.highlight)),
                Span::styled(log.clone(), Style::default().fg(app.theme.fg)),
            ]))
        })
        .collect();
    let logs_list = List::new(logs_to_show).block(log_block);
    f.render_widget(logs_list, left_chunks[1]);

    // 3. Right side: Selected Service Details & Help Pane
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(8)])
        .split(chunks[1]);

    // Detail Pane
    let detail_para = if let Some(svc) = app.services.get(app.selected_service_idx) {
        let svc_type = match svc.service_type {
            ServiceType::UserLaunchAgent => "User LaunchAgent (~/Library/LaunchAgents)",
            ServiceType::SystemLaunchAgent => "System LaunchAgent (/Library/LaunchAgents)",
            ServiceType::SystemLaunchDaemon => "System LaunchDaemon (/Library/LaunchDaemons)",
            ServiceType::BrewService => "Homebrew Managed Service",
        };

        let detail_text = vec![
            Line::from(vec![
                Span::styled("Name:       ", Style::default().fg(app.theme.muted)),
                Span::styled(
                    &svc.name,
                    Style::default()
                        .fg(app.theme.fg)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("ID/Label:   ", Style::default().fg(app.theme.muted)),
                Span::styled(&svc.id, Style::default().fg(app.theme.fg)),
            ]),
            Line::from(vec![
                Span::styled("Type:       ", Style::default().fg(app.theme.muted)),
                Span::styled(svc_type, Style::default().fg(app.theme.fg)),
            ]),
            Line::from(vec![
                Span::styled("Plist:      ", Style::default().fg(app.theme.muted)),
                Span::styled(
                    svc.plist_path.display().to_string(),
                    Style::default().fg(app.theme.fg),
                ),
            ]),
            Line::from(vec![
                Span::styled("Program:    ", Style::default().fg(app.theme.muted)),
                Span::styled(
                    svc.program
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Not specified".to_string()),
                    Style::default().fg(app.theme.fg),
                ),
            ]),
            Line::from(vec![
                Span::styled("RunAtLoad:  ", Style::default().fg(app.theme.muted)),
                Span::styled(
                    svc.run_at_load.to_string(),
                    Style::default().fg(app.theme.fg),
                ),
            ]),
        ];
        Paragraph::new(detail_text)
    } else {
        Paragraph::new("No background service selected or discovered.")
    }
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Service Detail Panel"),
    );

    f.render_widget(detail_para, right_chunks[0]);

    // Help Pane
    let help_text = vec![
        Line::from(vec![
            Span::styled(
                "  [s]  ",
                Style::default()
                    .fg(app.theme.success)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Start Service      ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "  [d]  ",
                Style::default()
                    .fg(app.theme.danger)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Stop (Deactivate)", Style::default().fg(app.theme.fg)),
        ]),
        Line::from(vec![
            Span::styled(
                "  [r]  ",
                Style::default()
                    .fg(app.theme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Restart Service    ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "  [e]  ",
                Style::default()
                    .fg(app.theme.highlight)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Enable Auto-load", Style::default().fg(app.theme.fg)),
        ]),
        Line::from(vec![
            Span::styled(
                "  [x]  ",
                Style::default()
                    .fg(app.theme.danger)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Disable Auto-load  ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "  [l]  ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Reload Service list", Style::default().fg(app.theme.fg)),
        ]),
    ];

    let help_para = Paragraph::new(help_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Control Keys"),
    );
    f.render_widget(help_para, right_chunks[1]);
}
