use cleanton_common::CleanupPlan;
use cleanton_engine::{ActionAnnotation, AnnotatedAction, ORPHAN_CATEGORY};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::StatefulWidget,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A compact ML badge ("ML <label> <confidence>") for display, or `None` when
/// the action was never ML-evaluated (e.g. orphaned-app candidates).
pub fn ml_badge(annotation: &ActionAnnotation) -> Option<String> {
    let label = annotation.ml_label?;
    let confidence = annotation.ml_confidence?;
    Some(format!("ML {label:?} {confidence:.2}"))
}

#[derive(Debug, Clone)]
pub struct TreeItem {
    pub label: String,
    pub path: Option<PathBuf>,
    pub bytes: u64,
    pub selected: bool,
    pub expanded: bool,
    pub action_index: Option<usize>,
    /// Compact ML badge shown after the row, empty when not ML-evaluated.
    pub badge: String,
    pub children: Vec<TreeItem>,
}

impl TreeItem {
    pub fn new(
        label: String,
        path: Option<PathBuf>,
        bytes: u64,
        action_index: Option<usize>,
    ) -> Self {
        Self {
            label,
            path,
            bytes,
            selected: true,
            expanded: true,
            action_index,
            badge: String::new(),
            children: Vec::new(),
        }
    }

    pub fn toggle_expanded(&mut self) {
        self.expanded = !self.expanded;
    }

    pub fn set_selected_recursive(&mut self, selected: bool) {
        self.selected = selected;
        for child in &mut self.children {
            child.set_selected_recursive(selected);
        }
    }

    pub fn update_from_children(&mut self) {
        for child in &mut self.children {
            child.update_from_children();
        }
        if !self.children.is_empty() {
            self.selected = self.children.iter().all(|c| c.selected);
        }
    }
}

#[derive(Debug)]
pub struct FileTreeState {
    pub root: TreeItem,
    pub selected_idx: usize,
}

impl FileTreeState {
    pub fn new(plan: &CleanupPlan, annotations: &[AnnotatedAction]) -> Self {
        let mut root = TreeItem::new(
            "Cleanable Targets".to_string(),
            None,
            plan.total_reclaimable,
            None,
        );

        // Annotation lookup by target so each row can show its ML badge.
        let annotation_by_target: HashMap<&Path, &ActionAnnotation> = annotations
            .iter()
            .map(|annotated| (annotated.action.target.as_path(), &annotated.annotation))
            .collect();

        // Group actions by category
        for (action_idx, action) in plan.actions.iter().enumerate() {
            let cat_name = format!("{:?}", action.recipe_id.0).to_lowercase();
            let is_orphan = cat_name.contains("orphan");
            // Let's clean up recipe category names (e.g. RecipeId("rust-target") -> rust)
            let cat_label = if is_orphan {
                ORPHAN_CATEGORY
            } else if cat_name.contains("rust") || cat_name.contains("cargo") {
                "Rust / Cargo"
            } else if cat_name.contains("node") || cat_name.contains("npm") {
                "Node / npm"
            } else if cat_name.contains("python")
                || cat_name.contains("pip")
                || cat_name.contains("cache")
            {
                "Python"
            } else if cat_name.contains("swift")
                || cat_name.contains("xcode")
                || cat_name.contains("derived")
            {
                "Swift / Xcode"
            } else if cat_name.contains("docker") {
                "Docker"
            } else if cat_name.contains("brew") {
                "Homebrew"
            } else {
                "Other Junk"
            };

            let cat_idx = match root.children.iter().position(|c| c.label == cat_label) {
                Some(idx) => idx,
                None => {
                    root.children
                        .push(TreeItem::new(cat_label.to_string(), None, 0, None));
                    root.children.len() - 1
                }
            };

            root.children[cat_idx].bytes += action.reclaimable_bytes;
            let display_path = action.target.clone();
            let label = display_path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| action.target.display().to_string());

            let mut leaf = TreeItem::new(
                label,
                Some(display_path),
                action.reclaimable_bytes,
                Some(action_idx),
            );
            if let Some(annotation) = annotation_by_target.get(action.target.as_path()) {
                leaf.badge = ml_badge(annotation).unwrap_or_default();
            }
            // Orphaned-app candidates are Cautious: never auto-selected, so the
            // user must explicitly opt them in before they can be executed.
            if is_orphan {
                leaf.selected = false;
            }
            root.children[cat_idx].children.push(leaf);
        }

        // Reconcile category checkboxes with their (possibly unselected) leaves.
        root.update_from_children();

        Self {
            root,
            selected_idx: 0,
        }
    }

    // Get flat list of currently visible nodes (respecting expanded states)
    pub fn get_visible_nodes(&self) -> Vec<(&TreeItem, usize)> {
        let mut visible = Vec::new();
        fn traverse<'a>(
            item: &'a TreeItem,
            depth: usize,
            visible: &mut Vec<(&'a TreeItem, usize)>,
        ) {
            visible.push((item, depth));
            if item.expanded {
                for child in &item.children {
                    traverse(child, depth + 1, visible);
                }
            }
        }

        for child in &self.root.children {
            traverse(child, 0, &mut visible);
        }
        visible
    }

    pub fn get_visible_node_path(&self, target_idx: usize) -> Option<Vec<usize>> {
        let mut current_idx = 0;
        fn traverse(
            item: &TreeItem,
            target_idx: usize,
            current_idx: &mut usize,
            path: &mut Vec<usize>,
        ) -> bool {
            if *current_idx == target_idx {
                return true;
            }
            *current_idx += 1;
            if item.expanded {
                for (idx, child) in item.children.iter().enumerate() {
                    path.push(idx);
                    if traverse(child, target_idx, current_idx, path) {
                        return true;
                    }
                    path.pop();
                }
            }
            false
        }

        for (idx, child) in self.root.children.iter().enumerate() {
            let mut path = vec![idx];
            if traverse(child, target_idx, &mut current_idx, &mut path) {
                return Some(path);
            }
        }
        None
    }

    pub fn get_node_mut(&mut self, path: &[usize]) -> Option<&mut TreeItem> {
        let mut current = &mut self.root;
        for &idx in path {
            current = current.children.get_mut(idx)?;
        }
        Some(current)
    }

    pub fn select_next(&mut self) {
        let max = self.get_visible_nodes().len();
        if max > 0 {
            self.selected_idx = (self.selected_idx + 1) % max;
        }
    }

    pub fn select_prev(&mut self) {
        let max = self.get_visible_nodes().len();
        if max > 0 {
            self.selected_idx = if self.selected_idx == 0 {
                max - 1
            } else {
                self.selected_idx - 1
            };
        }
    }

    pub fn toggle_expand_selected(&mut self) {
        if let Some(path) = self.get_visible_node_path(self.selected_idx) {
            if let Some(item) = self.get_node_mut(&path) {
                if !item.children.is_empty() {
                    item.toggle_expanded();
                }
            }
        }
    }

    pub fn toggle_select_selected(&mut self) {
        if let Some(path) = self.get_visible_node_path(self.selected_idx) {
            if let Some(item) = self.get_node_mut(&path) {
                let new_sel = !item.selected;
                item.set_selected_recursive(new_sel);
            }
        }
        self.root.update_from_children();
    }

    pub fn get_selected_action_indices(&self) -> Vec<usize> {
        let mut indices = Vec::new();
        fn collect(item: &TreeItem, indices: &mut Vec<usize>) {
            if item.selected {
                if let Some(idx) = item.action_index {
                    indices.push(idx);
                }
            }
            for child in &item.children {
                collect(child, indices);
            }
        }
        collect(&self.root, &mut indices);
        indices
    }
}

#[derive(Debug)]
pub struct FileTree {
    theme_accent: Color,
}

impl FileTree {
    pub fn new(theme_accent: Color) -> Self {
        Self { theme_accent }
    }
}

impl StatefulWidget for FileTree {
    type State = FileTreeState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        if area.height == 0 || area.width == 0 {
            return;
        }

        let visible = state.get_visible_nodes();
        let display_start = 0; // Pagination can be added later if needed
        let max_lines = area.height as usize;

        for line_idx in 0..max_lines {
            let y = area.y + line_idx as u16;
            if y >= area.y + area.height {
                break;
            }

            let visible_idx = display_start + line_idx;
            if visible_idx >= visible.len() {
                // Clear remaining lines
                for x in area.x..(area.x + area.width) {
                    if let Some(cell) = buf.cell_mut((x, y)) {
                        cell.reset();
                        cell.set_char(' ');
                    }
                }
                continue;
            }

            let (item, depth) = &visible[visible_idx];
            let is_cursor = visible_idx == state.selected_idx;

            // Prefix/indentation
            let indent = "  ".repeat(*depth);
            let expand_indicator = if item.children.is_empty() {
                "  "
            } else if item.expanded {
                "▼ "
            } else {
                "▶ "
            };

            let checkbox = if item.selected { "[x] " } else { "[ ] " };

            let size_str = cleanton_common::display::human_bytes(item.bytes);
            let mut text = format!(
                "{}{}{}{} ({})",
                indent, expand_indicator, checkbox, item.label, size_str
            );

            if let Some(p) = &item.path {
                let badge = if item.badge.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", item.badge)
                };
                text = format!(
                    "{}{}{}{} ({}){} - {}",
                    indent,
                    expand_indicator,
                    checkbox,
                    item.label,
                    size_str,
                    badge,
                    p.display()
                );
            }

            // Stylize the line
            let mut style = if is_cursor {
                Style::default()
                    .bg(self.theme_accent)
                    .fg(Color::Rgb(15, 15, 25))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Rgb(220, 220, 235))
            };

            if !is_cursor && item.children.is_empty() {
                style = style.fg(Color::Rgb(170, 170, 190)); // mute files a bit
            }

            let truncated_text: String = text.chars().take(area.width as usize).collect();
            let text_len = truncated_text.len();

            for x_offset in 0..area.width {
                let x = area.x + x_offset;
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.reset();
                    if let Some(ch) = ((x_offset as usize) < text_len)
                        .then(|| truncated_text.chars().nth(x_offset as usize))
                        .flatten()
                    {
                        cell.set_char(ch);
                    } else {
                        cell.set_char(' ');
                    }
                    cell.set_style(style);
                }
            }
        }
    }
}
