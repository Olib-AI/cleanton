use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

#[derive(Debug)]
pub struct Sparkline {
    data: Vec<u64>,
    color: Color,
}

impl Sparkline {
    pub fn new(data: Vec<u64>, color: Color) -> Self {
        Self { data, color }
    }
}

const BAR_SYMBOLS: &[char] = &[' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

impl Widget for Sparkline {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 || area.width == 0 || self.data.is_empty() {
            return;
        }

        let max_val = *self.data.iter().max().unwrap_or(&1).max(&1) as f32;
        let data_len = self.data.len();
        let display_count = (area.width as usize).min(data_len);
        let start_idx = data_len - display_count;

        for (col, &val) in self.data.iter().skip(start_idx).enumerate() {
            let x = area.x + col as u16;
            let ratio = val as f32 / max_val;

            // Calculate how many rows should be completely or partially filled
            let total_height = area.height as f32;
            let filled_height = ratio * total_height;
            let full_rows = filled_height.floor() as u16;
            let remainder = filled_height - full_rows as f32;

            let remainder_symbol_idx =
                (remainder * (BAR_SYMBOLS.len() - 1) as f32).round() as usize;
            let remainder_char = BAR_SYMBOLS[remainder_symbol_idx];

            for row_idx in 0..area.height {
                let y = area.y + area.height - 1 - row_idx;
                if let Some(cell) = buf.cell_mut((x, y)) {
                    if row_idx < full_rows {
                        cell.set_char('█');
                        cell.set_style(Style::default().fg(self.color));
                    } else if row_idx == full_rows && full_rows < area.height {
                        cell.set_char(remainder_char);
                        cell.set_style(Style::default().fg(self.color));
                    } else {
                        cell.set_char(' ');
                    }
                }
            }
        }
    }
}
