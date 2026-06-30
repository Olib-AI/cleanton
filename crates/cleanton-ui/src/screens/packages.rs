//! Packages screen — mirrors the Slint app's Packages tab.
//!
//! Shows the active OS package manager's inventory (Homebrew / Homebrew Cask /
//! npm / pip / `MacPorts`), summary tiles, and a keep-set removal model. The
//! two-phase load lives in `lib.rs`: this module only renders the current
//! [`App`] state. Destructive actions are armed here and confirmed via `y`.

use std::collections::HashSet;

use crate::app::{App, PKG_MANAGER_ORDER};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use cleanton_common::display::human_bytes;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // manager selector
            Constraint::Length(4), // summary tiles
            Constraint::Min(5),    // package list
            Constraint::Length(5), // controls + status
        ])
        .split(area);

    render_manager_tabs(f, app, chunks[0]);
    render_summary(f, app, chunks[1]);
    render_list(f, app, chunks[2]);
    render_controls(f, app, chunks[3]);
}

fn render_manager_tabs(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = Vec::new();
    for (idx, kind) in PKG_MANAGER_ORDER.iter().enumerate() {
        let label = format!(" {} ", kind.label());
        if idx == app.package_manager_idx {
            spans.push(Span::styled(
                label,
                Style::default()
                    .fg(app.theme.bg)
                    .bg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(label, Style::default().fg(app.theme.fg)));
        }
        spans.push(Span::raw("  "));
    }
    let para = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title(Span::styled(
                "Package Managers  ([←/→] switch)",
                Style::default().add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(para, area);
}

fn render_summary(f: &mut Frame, app: &App, area: Rect) {
    let Some(inv) = app.package_inventory.as_ref() else {
        let msg = if app.package_loading {
            "Loading inventory…"
        } else {
            "No inventory loaded."
        };
        let para = Paragraph::new(Line::from(Span::styled(
            format!("  {msg}"),
            Style::default().fg(app.theme.muted),
        )))
        .block(summary_block(app));
        f.render_widget(para, area);
        return;
    };

    let total_size: u64 = inv.packages.iter().map(|p| p.size_bytes).sum();
    let outdated = inv
        .packages
        .iter()
        .filter(|p| p.outdated_to.is_some())
        .count();
    let (removable, reclaimable, kept_dep) = app
        .package_plan
        .as_ref()
        .map_or((0, 0, 0), |p| {
            (p.removable.len(), p.reclaimable_bytes, p.kept_as_dependency.len())
        });

    let tile = |label: &str, value: String, color| {
        vec![
            Span::styled(format!("  {label}: "), Style::default().fg(app.theme.fg)),
            Span::styled(
                value,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
        ]
    };

    let mut top_tiles = tile("Installed", inv.packages.len().to_string(), app.theme.highlight);
    top_tiles.extend(tile("Total size", human_bytes(total_size), app.theme.accent));
    top_tiles.extend(tile(
        "Outdated",
        if app.package_phase2 {
            "checking…".to_owned()
        } else {
            outdated.to_string()
        },
        if outdated > 0 { app.theme.warning } else { app.theme.muted },
    ));

    let mut lines = vec![Line::from(top_tiles)];
    if app.package_supports_keepset {
        let mut bottom_tiles = tile("Removable", removable.to_string(), if removable > 0 { app.theme.danger } else { app.theme.muted });
        bottom_tiles.extend(tile("Reclaimable", human_bytes(reclaimable), app.theme.success));
        bottom_tiles.extend(tile("Kept as dependency", kept_dep.to_string(), app.theme.muted));
        lines.push(Line::from(bottom_tiles));
    } else {
        lines.push(Line::from(Span::styled(
            "  Keep-set removal applies to Homebrew formulae; here only update / clean-cache are offered.",
            Style::default().fg(app.theme.muted),
        )));
    }

    f.render_widget(Paragraph::new(lines).block(summary_block(app)), area);
}

fn summary_block(app: &App) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            "Summary",
            Style::default().add_modifier(Modifier::BOLD),
        ))
}

fn render_list(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.border))
        .title(Span::styled(
            "Installed Packages",
            Style::default().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(inv) = app.package_inventory.as_ref() else {
        let para = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "   Loading package inventory…",
                Style::default().fg(app.theme.muted),
            )),
        ]);
        f.render_widget(para, inner);
        return;
    };

    if inv.packages.is_empty() {
        let note = app
            .package_note
            .clone()
            .unwrap_or_else(|| "No packages reported by this manager.".to_owned());
        let para = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("   {note}"),
                Style::default().fg(app.theme.muted),
            )),
        ]);
        f.render_widget(para, inner);
        return;
    }

    let removable: HashSet<&str> = app
        .package_plan
        .as_ref()
        .map(|p| p.removable.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let kept_dep: HashSet<&str> = app
        .package_plan
        .as_ref()
        .map(|p| p.kept_as_dependency.iter().map(String::as_str).collect())
        .unwrap_or_default();

    // Simple viewport so the selected row stays visible without a stateful list.
    let height = inner.height as usize;
    let total = inv.packages.len();
    let sel = app.package_selected_idx.min(total.saturating_sub(1));
    let start = if height > 0 && sel >= height {
        sel - height + 1
    } else {
        0
    };

    let mut lines = Vec::with_capacity(height);
    for (offset, pkg) in inv.packages.iter().skip(start).take(height).enumerate() {
        let idx = start + offset;
        let is_selected = idx == sel;
        let name = pkg.name.as_str();
        let kept = app.package_keep.contains(name);

        let (marker, marker_color) = if !app.package_supports_keepset {
            ("•", app.theme.fg)
        } else if kept {
            ("[x]", app.theme.success)
        } else if removable.contains(name) {
            ("[ ]", app.theme.danger)
        } else if kept_dep.contains(name) {
            ("[~]", app.theme.warning)
        } else {
            ("[ ]", app.theme.danger)
        };

        let size = if pkg.size_bytes > 0 {
            human_bytes(pkg.size_bytes)
        } else {
            "—".to_owned()
        };

        let base = if is_selected {
            Style::default()
                .fg(app.theme.bg)
                .bg(app.theme.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.fg)
        };

        let mut spans = vec![
            Span::styled(format!(" {marker} "), Style::default().fg(marker_color)),
            Span::styled(format!("{name:<28} "), base),
            Span::styled(
                format!("{:<12} ", trunc(&pkg.version, 11)),
                Style::default().fg(app.theme.muted),
            ),
            Span::styled(format!("{size:>9}  "), Style::default().fg(app.theme.highlight)),
        ];

        if let Some(latest) = pkg.outdated_to.as_ref() {
            spans.push(Span::styled(
                format!("↑ {latest}  "),
                Style::default().fg(app.theme.warning),
            ));
        }
        if !pkg.used_by.is_empty() {
            let first = pkg.used_by.first().map(String::as_str).unwrap_or_default();
            spans.push(Span::styled(
                format!("used by {} ({}) ", pkg.used_by.len(), home_relative(first)),
                Style::default().fg(app.theme.warning),
            ));
        }
        if kept_dep.contains(name) {
            spans.push(Span::styled(
                "(kept as dependency)",
                Style::default().fg(app.theme.muted),
            ));
        }

        lines.push(Line::from(spans));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

fn render_controls(f: &mut Frame, app: &App, area: Rect) {
    let key = |k: &str| {
        Span::styled(
            k.to_owned(),
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        )
    };
    let txt = |t: &str| Span::styled(t.to_owned(), Style::default().fg(app.theme.fg));

    let nav = Line::from(vec![
        key("  [←/→] "),
        txt("Manager  "),
        key("[↑/↓] "),
        txt("Navigate  "),
        key("[Space] "),
        txt("Keep/Unkeep  "),
        key("[a] "),
        txt("Keep all  "),
        key("[z] "),
        txt("Unkeep all"),
    ]);
    let actions = Line::from(vec![
        key("  [r] "),
        txt("Remove unkept  "),
        key("[u] "),
        txt("Update selected  "),
        key("[U] "),
        txt("Update all  "),
        key("[c] "),
        txt("Clean cache  "),
        key("[l] "),
        txt("Reload"),
    ]);

    let status_line = if app.pending_package_confirmation.is_some() {
        Line::from(vec![
            key("  [y] "),
            Span::styled(
                "Confirm action  ",
                Style::default()
                    .fg(app.theme.success)
                    .add_modifier(Modifier::BOLD),
            ),
            key("[n] "),
            txt("Cancel"),
        ])
    } else {
        let mut spans = Vec::new();
        if app.package_acting || app.package_loading || app.package_phase2 {
            spans.push(Span::styled(
                "  ⟳ ",
                Style::default().fg(app.theme.warning),
            ));
        } else {
            spans.push(Span::raw("  "));
        }
        let status = if app.package_action_status.is_empty() {
            app.package_status.clone()
        } else {
            app.package_action_status.clone()
        };
        spans.push(Span::styled(status, Style::default().fg(app.theme.muted)));
        Line::from(spans)
    };

    let para = Paragraph::new(vec![nav, actions, status_line]).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border))
            .title("Controls"),
    );
    f.render_widget(para, area);
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

/// Truncate a string to `max` chars, appending `…` when shortened.
fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
