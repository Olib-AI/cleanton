use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

#[derive(Debug)]
pub struct ProgressBar {
    progress: f32, // 0.0 to 1.0
    label: String,
    color: Color,
}

impl ProgressBar {
    pub fn new(progress: f32, label: String, color: Color) -> Self {
        Self {
            progress: progress.clamp(0.0, 1.0),
            label,
            color,
        }
    }
}

impl Widget for ProgressBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 || area.width == 0 {
            return;
        }

        let total_width = area.width;
        let filled_width = (self.progress * total_width as f32).round() as u16;

        // Draw track
        for col in 0..total_width {
            let cell_col = area.x + col;
            let symbol = if col < filled_width { '█' } else { '░' };
            let style = if col < filled_width {
                Style::default().fg(self.color)
            } else {
                Style::default().fg(Color::Rgb(30, 30, 50))
            };

            for row in area.y..(area.y + area.height) {
                if let Some(cell) = buf.cell_mut((cell_col, row)) {
                    cell.set_char(symbol);
                    cell.set_style(style);
                }
            }
        }

        // Overlay text label centered
        let label_text = format!("{} ({:.1}%)", self.label, self.progress * 100.0);
        let text_len = label_text.len() as u16;
        if text_len < total_width {
            let start_x = area.x + (total_width - text_len) / 2;
            let text_y = area.y + area.height / 2;

            for (i, ch) in label_text.chars().enumerate() {
                let cell_x = start_x + i as u16;
                if let Some(cell) = buf.cell_mut((cell_x, text_y)) {
                    cell.set_char(ch);
                    // Determine contrasting style
                    let in_filled = (cell_x - area.x) < filled_width;
                    if in_filled {
                        cell.set_style(Style::default().fg(Color::Rgb(15, 15, 25)).bg(self.color));
                    } else {
                        cell.set_style(Style::default().fg(Color::Rgb(220, 220, 235)));
                    }
                }
            }
        }
    }
}
