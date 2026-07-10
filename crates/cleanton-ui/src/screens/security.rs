//! Security screen: read-only supply-chain scan diffed against the trusted
//! baseline.
//!
//! Mirrors the Slint app's Security tab: an idle state explaining the
//! baseline + diff model, a progress state with a packages-scanned counter,
//! and a results state with a tone-colored summary banner plus the surfaced
//! packages (new / updated / changed-without-version-bump) sorted worst-first
//! — known unchanged packages are collapsed into a count. Detection and
//! notification only — this screen offers NO destructive action; trusting a
//! package updates the baseline metadata file, never the package.

use crate::app::App;
use cleanton_engine::security::{Verdict, severity_label};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Summary banner
            Constraint::Min(8),    // Flagged packages + findings
            Constraint::Length(5), // Control keys
        ])
        .split(area);

    render_banner(f, app, chunks[0]);

    if app
        .security_report
        .as_ref()
        .is_some_and(|r| !r.flagged.is_empty())
    {
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(chunks[1]);
        render_flagged_list(f, app, body[0]);
        render_findings(f, app, body[1]);
    } else {
        render_empty_body(f, app, chunks[1]);
    }

    render_help(f, app, chunks[2]);
}

/// Banner color for the shared `SecurityReport::banner_tone` string, so the
/// TUI and the Slint app always agree on how alarming a result looks. The
/// `"info"` tone (updates/new packages with no corroborated threats) is the
/// neutral accent — never amber or red.
fn tone_color(app: &App, tone: &str) -> Color {
    match tone {
        "danger" => app.theme.danger,
        "warning" => app.theme.warning,
        "info" => app.theme.accent,
        _ => app.theme.success,
    }
}

fn render_banner(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            "Security — baseline + diff supply-chain scan (read-only)",
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(app.theme.accent),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines: Vec<Line> = if app.security_scanning {
        let (scanned, total) = app.security_progress;
        vec![
            Line::from(Span::styled(
                format!("  Scanning… {scanned} of {total} packages"),
                Style::default().fg(app.theme.highlight),
            )),
            Line::from(Span::styled(
                "  Nothing is removed or modified during the scan.",
                Style::default().fg(app.theme.muted),
            )),
        ]
    } else if let Some(report) = app.security_report.as_ref() {
        // Shared status copy: identical wording in the Slint app and the CLI.
        let color = tone_color(app, report.banner_tone());
        let mut lines = vec![Line::from(Span::styled(
            format!("  {}", report.banner_headline()),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))];
        lines.push(Line::from(Span::styled(
            format!("  {}", report.summary_message()),
            Style::default().fg(app.theme.fg),
        )));
        lines
    } else {
        vec![
            Line::from(Span::styled(
                "  Not scanned yet. Press [s] to scan installed packages.",
                Style::default().fg(app.theme.muted),
            )),
            Line::from(Span::styled(
                "  First scan records your packages as a trusted baseline; later scans flag only changes.",
                Style::default().fg(app.theme.muted),
            )),
        ]
    };
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_empty_body(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = if app.security_scanning {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Fingerprinting and analyzing your installed packages…",
                Style::default().fg(app.theme.fg),
            )),
        ]
    } else if let Some(report) = app.security_report.as_ref() {
        let (headline, detail) = if report.baseline_established {
            (
                format!(
                    "  ✓ Baseline established: {} packages",
                    report.packages_scanned
                ),
                "  Your installed packages are now the trusted reference. Future scans flag only new, updated, or tampered packages.",
            )
        } else {
            (
                "  ✓ No changes since last baseline".to_owned(),
                "  Every package is byte-identical to the set you trusted. Rescan any time — for example after installing or updating packages.",
            )
        };
        vec![
            Line::from(""),
            Line::from(Span::styled(
                headline,
                Style::default()
                    .fg(app.theme.success)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(detail, Style::default().fg(app.theme.muted))),
            Line::from(""),
            Line::from(Span::styled(
                format!(
                    "  {} known package(s) unchanged and suppressed from alerts.",
                    report.known_unchanged
                ),
                Style::default().fg(app.theme.muted),
            )),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  How the baseline model works:",
                Style::default().fg(app.theme.fg),
            )),
            Line::from(Span::styled(
                "  Your first scan records every installed package (global npm/pnpm/bun/yarn,",
                Style::default().fg(app.theme.muted),
            )),
            Line::from(Span::styled(
                "  Python site-packages, VS Code/Cursor extensions) as a trusted baseline —",
                Style::default().fg(app.theme.muted),
            )),
            Line::from(Span::styled(
                "  legitimate tools like npm and pip are not treated as threats.",
                Style::default().fg(app.theme.muted),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Later scans flag only what changed: NEW packages, UPDATED packages, and —",
                Style::default().fg(app.theme.muted),
            )),
            Line::from(Span::styled(
                "  the highest signal — packages whose contents changed WITHOUT a version",
                Style::default().fg(app.theme.muted),
            )),
            Line::from(Span::styled(
                "  bump (the npm-worm injection signature).",
                Style::default().fg(app.theme.muted),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Read-only: Cleanton only reports — it never removes or changes a package.",
                Style::default().fg(app.theme.muted),
            )),
        ]
    };
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_flagged_list(f: &mut Frame, app: &App, area: Rect) {
    let Some(report) = app.security_report.as_ref() else {
        return;
    };
    let items: Vec<ListItem> = report
        .flagged
        .iter()
        .enumerate()
        .map(|(idx, package)| {
            let is_selected = idx == app.security_selected;
            let row_style = if is_selected {
                Style::default()
                    .bg(app.theme.accent)
                    .fg(Color::Rgb(15, 15, 25))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(app.theme.fg)
            };
            // The ASSESSMENT drives the badge: tamper is the red alarm,
            // corroborated alerts are red/amber, and notice rows keep the
            // neutral change-kind badge ("UPDATED"/"NEW") in the accent
            // color — never a red verdict.
            let badge_color = if package.is_critical_alert() {
                app.theme.danger
            } else if package.is_alert() {
                match package.verdict {
                    Verdict::Malicious => app.theme.danger,
                    Verdict::Suspicious => app.theme.warning,
                    Verdict::Clean => app.theme.accent,
                }
            } else {
                app.theme.accent
            };
            let badge = if package.is_tampered() {
                "TAMPERED?".to_owned()
            } else {
                package.change_label().to_uppercase()
            };
            let status_style = if is_selected {
                row_style
            } else if package.is_alert() {
                Style::default().fg(app.theme.highlight)
            } else {
                Style::default().fg(app.theme.muted)
            };
            let line = Line::from(vec![
                Span::styled(
                    format!(" {badge:<10} "),
                    if is_selected {
                        row_style
                    } else {
                        Style::default()
                            .fg(badge_color)
                            .add_modifier(Modifier::BOLD)
                    },
                ),
                Span::styled(format!("{:<30} ", package.display_name()), row_style),
                Span::styled(format!("{:>10}", package.assessment_label()), status_style),
            ]);
            ListItem::new(line)
        })
        .collect();

    let title = format!(
        "Flagged ({}) — worst first · {} known unchanged",
        report.flagged.len(),
        report.known_unchanged
    );
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title(Span::styled(
                title,
                Style::default().add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(list, area);
}

fn render_findings(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            "Findings — review this package",
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(package) = app
        .security_report
        .as_ref()
        .and_then(|report| report.flagged.get(app.security_selected))
    else {
        return;
    };

    let change_color = if package.is_tampered() {
        app.theme.danger
    } else {
        app.theme.highlight
    };
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(
                format!("  {} ", package.display_name()),
                Style::default()
                    .fg(app.theme.fg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("— {}", package.headline()),
                Style::default().fg(app.theme.highlight),
            ),
        ]),
        Line::from(Span::styled(
            format!("  {} · {}", package.source.label(), package.path.display()),
            Style::default().fg(app.theme.muted),
        )),
        Line::from(""),
        // Shared change-kind copy (identical wording in the Slint app).
        Line::from(Span::styled(
            format!("  [{}] {}", package.change_label(), package.change.notice()),
            Style::default()
                .fg(change_color)
                .add_modifier(if package.is_tampered() {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        )),
        Line::from(""),
    ];
    // Notice rows keep the raw verdict visible only as muted secondary
    // detail (shared engine copy, identical in the Slint app).
    if let Some(note) = package.heuristic_note() {
        lines.push(Line::from(Span::styled(
            format!("  {note}"),
            Style::default().fg(app.theme.muted),
        )));
        lines.push(Line::from(""));
    }
    // The shared finding copy (identical lines in the Slint app). Severity
    // lines go red only on ALERT rows — notice rows stay neutral.
    for text in package.finding_lines() {
        let style = if text.starts_with("    ") {
            Style::default().fg(app.theme.muted)
        } else if package.is_alert()
            && (text.starts_with("[critical]") || text.starts_with("[high]"))
        {
            Style::default().fg(app.theme.danger)
        } else {
            Style::default().fg(app.theme.fg)
        };
        lines.push(Line::from(Span::styled(format!("  {text}"), style)));
    }
    if package.top_findings.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No static-analysis findings — flagged only because it changed.",
            Style::default().fg(app.theme.muted),
        )));
    }
    if package.finding_count > package.top_findings.len() {
        lines.push(Line::from(Span::styled(
            format!(
                "  … {} more finding(s); worst severity {}",
                package.finding_count - package.top_findings.len(),
                package.worst_severity().map_or("-", severity_label)
            ),
            Style::default().fg(app.theme.muted),
        )));
    }
    // Recommended next steps (shared engine copy; identical in the Slint app
    // and the CLI). Advisory only — pressing [t] trusts; nothing here deletes.
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  Recommended: {}", package.action_label()),
        Style::default()
            .fg(if package.is_alert() {
                app.theme.warning
            } else {
                app.theme.accent
            })
            .add_modifier(Modifier::BOLD),
    )));
    for step in package.action_lines() {
        // The copy-paste command line stands out; prose stays neutral.
        let style = if step.starts_with('$') {
            Style::default()
                .fg(app.theme.highlight)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.fg)
        };
        lines.push(Line::from(Span::styled(format!("  {step}"), style)));
    }
    lines.push(Line::from(Span::styled(
        "  Or press [t] to trust it (updates the baseline only; the package is never touched).",
        Style::default().fg(app.theme.muted),
    )));

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_help(f: &mut Frame, app: &App, area: Rect) {
    let scan_label = if app.security_scanning {
        "Scanning…   [x] Cancel scan"
    } else if app.security_report.is_some() {
        "Rescan for changes"
    } else {
        "Scan installed packages"
    };
    let help = vec![
        Line::from(vec![
            Span::styled(
                "  [s] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(scan_label, Style::default().fg(app.theme.fg)),
            Span::styled(
                "   [b] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Re-establish baseline (trust current state)",
                Style::default().fg(app.theme.fg),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  [t] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Trust selected package   ",
                Style::default().fg(app.theme.fg),
            ),
            Span::styled(
                "[T] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Trust all shown   (baseline metadata only)",
                Style::default().fg(app.theme.fg),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "  [Up/Down] ",
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Browse flagged packages   (read-only: nothing here deletes)",
                Style::default().fg(app.theme.fg),
            ),
        ]),
    ];
    let para = Paragraph::new(help).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Control Keys"),
    );
    f.render_widget(para, area);
}
