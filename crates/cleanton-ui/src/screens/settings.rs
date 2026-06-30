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
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Settings Tabs
            Constraint::Min(5),    // Settings items list
            Constraint::Length(4), // Controls instruction
        ])
        .split(area);

    // 1. Settings Tabs (General, Scanning, Safety, ML)
    let tabs = ["General", "Scanning", "Safety", "ML / AI"];
    let tab_spans: Vec<Span> = tabs
        .iter()
        .enumerate()
        .map(|(idx, name)| {
            if idx == app.active_setting_tab {
                Span::styled(
                    format!("  [{}]  ", name),
                    Style::default()
                        .fg(app.theme.accent)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    format!("   {}   ", name),
                    Style::default().fg(app.theme.muted),
                )
            }
        })
        .collect();

    let tab_para = Paragraph::new(Line::from(tab_spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Settings Categories"),
    );
    f.render_widget(tab_para, chunks[0]);

    // 2. Settings Items List
    let items = get_settings_items(app);
    let list_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(idx, (label, val_str))| {
            let is_selected = idx == app.active_setting_idx;

            let style = if is_selected {
                Style::default()
                    .bg(app.theme.border)
                    .fg(Color::Rgb(220, 220, 235))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(app.theme.fg)
            };

            let indicator = if is_selected { "▶ " } else { "  " };

            ListItem::new(Line::from(vec![
                Span::styled(indicator, Style::default().fg(app.theme.accent)),
                Span::styled(format!("{:<30}", label), style),
                Span::styled(" :  ", Style::default().fg(app.theme.muted)),
                Span::styled(val_str.clone(), Style::default().fg(app.theme.highlight)),
            ]))
        })
        .collect();

    let list_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            format!("Configuring: {}", tabs[app.active_setting_tab]),
            Style::default().add_modifier(Modifier::BOLD),
        ));

    let settings_list = List::new(list_items).block(list_block);
    f.render_widget(settings_list, chunks[1]);

    // 3. Instruction Pane
    let inst_text = vec![
        Line::from(vec![
            Span::styled(
                "  [Tab]       ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Next Screen        ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "  [Left/Right] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Modify setting value", Style::default().fg(app.theme.fg)),
        ]),
        Line::from(vec![
            Span::styled(
                "  [Up/Down]   ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Navigate options   ", Style::default().fg(app.theme.fg)),
            Span::styled(
                "  [Enter]      ",
                Style::default()
                    .fg(app.theme.success)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "SAVE CONFIGURATION AND RE-APPLY",
                Style::default().fg(app.theme.fg),
            ),
        ]),
    ];

    let inst_para = Paragraph::new(inst_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Controls"),
    );
    f.render_widget(inst_para, chunks[2]);
}

pub fn get_settings_items(app: &App) -> Vec<(String, String)> {
    match app.active_setting_tab {
        0 => vec![
            (
                "Default Root Path".to_owned(),
                app.config.general.default_root.display().to_string(),
            ),
            (
                "Auto Scan on Launch".to_owned(),
                app.config.general.auto_scan_on_launch.to_string(),
            ),
            ("Theme Style".to_owned(), app.config.general.theme.clone()),
            (
                "Animation Speed".to_owned(),
                app.config.general.animation_speed.clone(),
            ),
            (
                "Log Retention Days".to_owned(),
                app.config.general.log_retention_days.to_string(),
            ),
            (
                "Log Retention Count".to_owned(),
                app.config.general.log_retention_count.to_string(),
            ),
        ],
        1 => vec![
            (
                "Max Scan Depth".to_owned(),
                app.config.scanning.max_depth.to_string(),
            ),
            (
                "Respect .gitignore".to_owned(),
                app.config.scanning.respect_gitignore.to_string(),
            ),
            (
                "Follow Symlinks".to_owned(),
                app.config.scanning.follow_symlinks.to_string(),
            ),
            (
                "Parallel Threads".to_owned(),
                if app.config.scanning.parallel_threads == 0 {
                    "Auto".to_owned()
                } else {
                    app.config.scanning.parallel_threads.to_string()
                },
            ),
            (
                "Exclude Cloud Roots".to_owned(),
                app.config.scanning.exclude_cloud_roots.to_string(),
            ),
            (
                "Exclude External Volumes".to_owned(),
                app.config.scanning.exclude_external_volumes.to_string(),
            ),
        ],
        2 => vec![
            (
                "Default Cleanup Action".to_owned(),
                format!("{:?}", app.config.safety.default_action),
            ),
            (
                "Max Single Run (GB)".to_owned(),
                app.config.safety.max_single_run_gb.to_string(),
            ),
            (
                "Max Single Action (GB)".to_owned(),
                app.config.safety.max_single_action_gb.to_string(),
            ),
            (
                "Require Confirmation".to_owned(),
                app.config.safety.require_confirmation.to_string(),
            ),
        ],
        3 => vec![
            (
                "ML Engine Enabled".to_owned(),
                app.config.ml.enabled.to_string(),
            ),
            (
                "ML Confidence Threshold".to_owned(),
                format!("{:.2}", app.config.ml.confidence_threshold),
            ),
            (
                "ML Model File Path".to_owned(),
                app.config.ml.model_path.display().to_string(),
            ),
        ],
        _ => Vec::new(),
    }
}
