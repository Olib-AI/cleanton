use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Widget,
};

#[derive(Debug)]
pub struct Badge {
    text: String,
    color: Color,
}

impl Badge {
    pub fn new(text: &str, color: Color) -> Self {
        Self {
            text: text.to_uppercase(),
            color,
        }
    }
}

impl Widget for Badge {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 || area.width == 0 {
            return;
        }

        let formatted = format!(" {} ", self.text);
        let len = formatted.len() as u16;
        let end_x = (area.x + len).min(area.x + area.width);

        for (i, ch) in formatted
            .chars()
            .take((end_x - area.x) as usize)
            .enumerate()
        {
            let x = area.x + i as u16;
            if let Some(cell) = buf.cell_mut((x, area.y)) {
                cell.set_char(ch);
                cell.set_style(
                    Style::default()
                        .fg(Color::Rgb(15, 15, 25))
                        .bg(self.color)
                        .add_modifier(Modifier::BOLD),
                );
            }
        }
    }
}
