use ratatui::style::Color;

#[derive(Debug)]
pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub accent: Color,
    pub success: Color,
    pub warning: Color,
    pub danger: Color,
    pub muted: Color,
    pub border: Color,
    pub highlight: Color,
    pub gradient: (Color, Color),
}

pub const DARK_THEME: Theme = Theme {
    bg: Color::Rgb(15, 15, 25),          // Deep midnight blue
    fg: Color::Rgb(220, 220, 235),       // Soft white
    accent: Color::Rgb(99, 102, 241),    // Indigo
    success: Color::Rgb(34, 197, 94),    // Emerald
    warning: Color::Rgb(250, 204, 21),   // Amber
    danger: Color::Rgb(239, 68, 68),     // Rose
    muted: Color::Rgb(100, 100, 130),    // Slate
    border: Color::Rgb(55, 55, 85),      // Subtle border
    highlight: Color::Rgb(139, 92, 246), // Violet
    gradient: (
        Color::Rgb(99, 102, 241), // Indigo start
        Color::Rgb(168, 85, 247), // Purple end
    ),
};
