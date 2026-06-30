use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Color,
    widgets::{
        Widget,
        canvas::{Canvas, Circle, Line},
    },
};
use std::f32::consts::PI;

#[derive(Debug, Clone)]
pub struct DonutSector {
    pub label: String,
    pub value: f32, // fraction (0.0 to 1.0)
    pub color: Color,
}

#[derive(Debug)]
pub struct DonutChart {
    sectors: Vec<DonutSector>,
    animation_progress: f32, // 0.0 to 1.0
}

impl DonutChart {
    pub fn new(sectors: Vec<DonutSector>, animation_progress: f32) -> Self {
        Self {
            sectors,
            animation_progress,
        }
    }
}

impl Widget for DonutChart {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let sectors = &self.sectors;
        let progress = self.animation_progress;

        let canvas = Canvas::default()
            .x_bounds([-20.0, 20.0])
            .y_bounds([-20.0, 20.0])
            .paint(move |ctx| {
                // Draw inner and outer ring guide lines
                ctx.draw(&Circle {
                    x: 0.0,
                    y: 0.0,
                    radius: 12.0,
                    color: Color::Rgb(35, 35, 55),
                });
                ctx.draw(&Circle {
                    x: 0.0,
                    y: 0.0,
                    radius: 7.0,
                    color: Color::Rgb(35, 35, 55),
                });

                let mut current_angle = 0.0_f32;
                for sector in sectors {
                    let target_sweep = sector.value * 2.0 * PI;
                    let sweep = target_sweep * progress;

                    // Draw filled sector lines to simulate thickness
                    let steps = 40;
                    for i in 0..=steps {
                        let angle = current_angle + (sweep * (i as f32 / steps as f32));
                        let cos = angle.cos() as f64;
                        let sin = angle.sin() as f64;

                        // Line from inner radius to outer radius
                        ctx.draw(&Line {
                            x1: 7.5_f64 * cos,
                            y1: 7.5_f64 * sin,
                            x2: 11.5_f64 * cos,
                            y2: 11.5_f64 * sin,
                            color: sector.color,
                        });
                    }

                    current_angle += target_sweep;
                }
            });

        canvas.render(area, buf);
    }
}
