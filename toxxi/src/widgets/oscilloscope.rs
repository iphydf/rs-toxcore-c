use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

pub struct Oscilloscope {
    pub data: Vec<f32>, // Normalized values -1.0 to 1.0
    pub style: Style,
    pub fill: bool,
    pub show_zero_line: bool,
    pub zero_line_style: Style,
}

impl Default for Oscilloscope {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            style: Style::default().fg(Color::Green),
            fill: true,
            show_zero_line: true,
            zero_line_style: Style::default().fg(Color::DarkGray),
        }
    }
}

impl Widget for Oscilloscope {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 || area.width == 0 {
            return;
        }

        let width_dots = area.width as usize * 2;
        let height_dots = area.height as usize * 4;
        let zero_y_dot = height_dots / 2;

        let mut cell_bits = vec![0u8; (area.width * area.height) as usize];
        let mut cell_is_waveform = vec![false; (area.width * area.height) as usize];

        // Draw zero line
        if self.show_zero_line {
            for dx in 0..width_dots {
                let dy = zero_y_dot;
                let cell_x = dx / 2;
                let cell_y = dy / 4;
                if cell_x < area.width as usize && cell_y < area.height as usize {
                    let bit = get_dot_bit(dx, dy);
                    cell_bits[cell_y * area.width as usize + cell_x] |= bit;
                }
            }
        }

        if !self.data.is_empty() {
            // Map data to dots with linear interpolation
            for dx in 0..width_dots {
                let val = if self.data.len() > 1 {
                    let t = dx as f32 / (width_dots as f32 - 1.0).max(1.0);
                    let data_pos = t * (self.data.len() as f32 - 1.0);
                    let i = data_pos.floor() as usize;
                    let f = data_pos.fract();
                    if i + 1 < self.data.len() {
                        self.data[i] * (1.0 - f) + self.data[i + 1] * f
                    } else {
                        self.data[i]
                    }
                } else {
                    self.data[0]
                };

                // Normalize value (-1.0 to 1.0) to dot height (0 to height_dots-1)
                // 1.0 is top (0), -1.0 is bottom (height_dots-1)
                let dy_float = (1.0 - val) / 2.0 * (height_dots as f32 - 1.0);
                let dy_target = dy_float.round() as usize;
                let dy_target = dy_target.min(height_dots - 1);

                let (start_y, end_y) = if self.fill {
                    if dy_target < zero_y_dot {
                        (dy_target, zero_y_dot)
                    } else {
                        (zero_y_dot, dy_target)
                    }
                } else {
                    (dy_target, dy_target)
                };

                for dy in start_y..=end_y {
                    let cell_x = dx / 2;
                    let cell_y = dy / 4;
                    if cell_x < area.width as usize && cell_y < area.height as usize {
                        let idx = cell_y * area.width as usize + cell_x;
                        cell_bits[idx] |= get_dot_bit(dx, dy);
                        cell_is_waveform[idx] = true;
                    }
                }
            }
        }

        // Write to buffer
        for y in 0..area.height {
            for x in 0..area.width {
                let idx = (y as usize) * (area.width as usize) + (x as usize);
                let bits = cell_bits[idx];
                let symbol = if bits == 0 {
                    " ".to_string()
                } else {
                    std::char::from_u32(0x2800 + bits as u32)
                        .unwrap_or(' ')
                        .to_string()
                };

                let style = if cell_is_waveform[idx] {
                    self.style
                } else if bits != 0 {
                    self.zero_line_style
                } else {
                    Style::default()
                };

                buf[(area.x + x, area.y + y)]
                    .set_symbol(&symbol)
                    .set_style(style);
            }
        }
    }
}

fn get_dot_bit(dx: usize, dy: usize) -> u8 {
    let dot_x = dx % 2;
    let dot_y = dy % 4;
    match (dot_x, dot_y) {
        (0, 0) => 0x01,
        (0, 1) => 0x02,
        (0, 2) => 0x04,
        (1, 0) => 0x08,
        (1, 1) => 0x10,
        (1, 2) => 0x20,
        (0, 3) => 0x40,
        (1, 3) => 0x80,
        _ => 0,
    }
}
