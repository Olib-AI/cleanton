use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

#[derive(Debug, Clone)]
pub struct SizeBarSegment {
    pub value: f32, // percentage of total (0.0 to 1.0)
    pub color: Color,
}

#[derive(Debug)]
pub struct SizeBar {
    pub segments: Vec<SizeBarSegment>,
}

impl SizeBar {
    pub fn new(segments: Vec<SizeBarSegment>) -> Self {
        Self { segments }
    }
}

impl Widget for SizeBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 || area.width == 0 {
            return;
        }

        let mut current_col = area.x;
        let total_width = area.width as f32;

        for (idx, segment) in self.segments.iter().enumerate() {
            let seg_width_f = segment.value * total_width;
            let mut seg_width = seg_width_f.round() as u16;

            // Adjust last segment to match boundary
            if idx == self.segments.len() - 1 {
                let remaining = (area.x + area.width).saturating_sub(current_col);
                seg_width = remaining;
            }

            let end_col = (current_col + seg_width).min(area.x + area.width);

            for col in current_col..end_col {
                for row in area.y..(area.y + area.height) {
                    if let Some(cell) = buf.cell_mut((col, row)) {
                        cell.set_char('█');
                        cell.set_style(Style::default().fg(segment.color));
                    }
                }
            }
            current_col = end_col;
        }
    }
}
