use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Widget,
};
use std::collections::VecDeque;
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone)]
pub struct StatusWindow {
    pub name: String,
    pub index: usize,
    pub unread: usize,
    pub is_active: bool,
}

pub struct StatusBar {
    pub profile_name: String,
    pub status: String,
    pub dht_health: Vec<u64>, // Values for sparkline
    pub tox_id: String,
    pub sparkline_width: u16,
    pub max_health: Option<u64>,

    // Extended fields
    pub time: Option<String>,
    pub connection_status: Option<(String, Style)>,
    pub pending_count: usize,
    pub multi_line: bool,
    pub windows: Vec<StatusWindow>,
}

impl StatusBar {
    pub fn new(profile_name: String, status: String, tox_id: String) -> Self {
        Self {
            profile_name,
            status,
            dht_health: Vec::new(),
            tox_id,
            sparkline_width: 10,
            max_health: None,
            time: None,
            connection_status: None,
            pending_count: 0,
            multi_line: false,
            windows: Vec::new(),
        }
    }

    pub fn dht_health(mut self, dht_health: Vec<u64>) -> Self {
        self.dht_health = dht_health;
        self
    }

    pub fn max_health(mut self, max: u64) -> Self {
        self.max_health = Some(max);
        self
    }

    pub fn sparkline_width(mut self, width: u16) -> Self {
        self.sparkline_width = width;
        self
    }

    pub fn time(mut self, time: String) -> Self {
        self.time = Some(time);
        self
    }

    pub fn connection_status(mut self, status: String, style: Style) -> Self {
        self.connection_status = Some((status, style));
        self
    }

    pub fn pending_count(mut self, count: usize) -> Self {
        self.pending_count = count;
        self
    }

    pub fn multi_line(mut self, multi: bool) -> Self {
        self.multi_line = multi;
        self
    }

    pub fn windows(mut self, windows: Vec<StatusWindow>) -> Self {
        self.windows = windows;
        self
    }
}

impl Widget for StatusBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 {
            return;
        }

        let bg_style = Style::default().bg(Color::Blue);
        let bracket_style = Style::default().fg(Color::LightBlue).bg(Color::Blue);
        let text_style = Style::default().fg(Color::White).bg(Color::Blue);
        let active_style = Style::default()
            .fg(Color::Yellow)
            .bg(Color::Blue)
            .add_modifier(Modifier::BOLD);

        buf.set_style(area, bg_style);

        let mut x = area.x;
        let y = area.y;

        // 1. Time
        if let Some(time) = self.time {
            x = draw_bracketed_at(buf, x, y, &time, bracket_style, text_style);
        }

        // 2. Connection
        if let Some((conn, style)) = self.connection_status {
            x = draw_bracketed_at(buf, x, y, &conn, bracket_style, style);
        }

        // 3. Profile Name
        x = draw_bracketed_custom_at(BracketedParams {
            buf,
            x,
            y,
            text: &self.profile_name,
            left_style: bracket_style.fg(Color::LightBlue),
            right_style: bracket_style.fg(Color::LightBlue),
            content_style: active_style,
            left_sym: "<",
            right_sym: "> ",
        });

        // 4. Status
        x = draw_bracketed_at(buf, x, y, &self.status, bracket_style, active_style);

        // 5. Multi-line indicator
        if self.multi_line {
            let s = "[Multi: Ctrl+D to send] ";
            buf.set_string(
                x,
                y,
                s,
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            );
            x += s.width() as u16;
        }

        // 6. Pending
        if self.pending_count > 0 {
            buf.set_string(x, y, "[", bracket_style);
            x += 1;
            let p_text = format!("PENDING: {}", self.pending_count);
            let p_style = Style::default()
                .bg(Color::Red)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD);
            buf.set_string(x, y, &p_text, p_style);
            x += p_text.width() as u16;
            buf.set_string(x, y, "] ", bracket_style);
            x += 2;
        }

        // 7. Sparkline (Health)
        if !self.dht_health.is_empty() && area.width > 60 {
            let sparkline_text = render_sparkline(
                &self.dht_health,
                self.sparkline_width as usize,
                self.max_health,
            );
            let nodes_text = format!("Nodes: [{}] ", sparkline_text);

            // Check if it fits
            if x + nodes_text.width() as u16 + 2 < area.right() {
                buf.set_string(x, y, &nodes_text, text_style);
                x += nodes_text.width() as u16;
            }
        }

        // 8. Window List
        let remaining_width = area.right().saturating_sub(x);
        if remaining_width > 5 && !self.windows.is_empty() {
            draw_window_list(buf, x, y, remaining_width, self.windows);
        }
    }
}

fn draw_bracketed_at(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    text: &str,
    bracket_style: Style,
    content_style: Style,
) -> u16 {
    draw_bracketed_custom_at(BracketedParams {
        buf,
        x,
        y,
        text,
        left_style: bracket_style,
        right_style: bracket_style,
        content_style,
        left_sym: "[",
        right_sym: "] ",
    })
}

struct BracketedParams<'a> {
    buf: &'a mut Buffer,
    x: u16,
    y: u16,
    text: &'a str,
    left_style: Style,
    right_style: Style,
    content_style: Style,
    left_sym: &'a str,
    right_sym: &'a str,
}

fn draw_bracketed_custom_at(params: BracketedParams<'_>) -> u16 {
    let mut current_x = params.x;
    params
        .buf
        .set_string(current_x, params.y, params.left_sym, params.left_style);
    current_x += params.left_sym.width() as u16;
    params
        .buf
        .set_string(current_x, params.y, params.text, params.content_style);
    current_x += params.text.width() as u16;
    params
        .buf
        .set_string(current_x, params.y, params.right_sym, params.right_style);
    current_x += params.right_sym.width() as u16;
    current_x
}

fn draw_window_list(buf: &mut Buffer, x: u16, y: u16, width: u16, windows: Vec<StatusWindow>) {
    let active_idx = windows.iter().position(|w| w.is_active).unwrap_or(0);

    // Calculate total widths and visible range
    let mut visible_indices = VecDeque::new();
    visible_indices.push_back(active_idx);

    // Calculate width of active item
    let get_width = |w: &StatusWindow| -> u16 {
        let base = format!("[{}:{}] ", w.index, w.name).width() as u16;
        if w.unread > 0 {
            base + format!("({})", w.unread).width() as u16
        } else {
            base
        }
    };

    let mut current_width = get_width(&windows[active_idx]);
    let effective_width = width.saturating_sub(4); // Space for arrows

    let mut left = active_idx;
    let mut right = active_idx;

    loop {
        let mut expanded = false;
        // Try expand right
        if right + 1 < windows.len() {
            let w = get_width(&windows[right + 1]);
            if current_width + w <= effective_width {
                current_width += w;
                right += 1;
                visible_indices.push_back(right);
                expanded = true;
            }
        }
        // Try expand left
        if left > 0 {
            let w = get_width(&windows[left - 1]);
            if current_width + w <= effective_width {
                current_width += w;
                left -= 1;
                visible_indices.push_front(left);
                expanded = true;
            }
        }
        if !expanded {
            break;
        }
    }

    let mut current_x = x;

    if left > 0 {
        let arrow = "< ";
        buf.set_string(
            current_x,
            y,
            arrow,
            Style::default().fg(Color::Yellow).bg(Color::Blue),
        );
        current_x += arrow.width() as u16;
    }

    for idx in visible_indices {
        let w = &windows[idx];
        let mut style = Style::default().bg(Color::Blue).fg(Color::White);
        if w.is_active {
            style = style.fg(Color::Cyan).add_modifier(Modifier::BOLD);
        } else if w.unread > 0 {
            style = style.fg(Color::Magenta);
        }

        let display = if w.unread > 0 {
            format!("[{}:{}({})] ", w.index, w.name, w.unread)
        } else {
            format!("[{}:{}] ", w.index, w.name)
        };

        buf.set_string(current_x, y, &display, style);
        current_x += display.width() as u16;
    }

    if right < windows.len() - 1 {
        let arrow = " >";
        buf.set_string(
            current_x,
            y,
            arrow,
            Style::default().fg(Color::Yellow).bg(Color::Blue),
        );
    }
}

fn render_sparkline(values: &[u64], width: usize, max_val_override: Option<u64>) -> String {
    if values.is_empty() {
        return " ".repeat(width);
    }

    let mut s = String::new();
    let data_points = width * 2;
    let max_val = max_val_override.unwrap_or_else(|| {
        *values
            .iter()
            .rev()
            .take(data_points)
            .max()
            .unwrap_or(&1)
            .max(&1)
    });

    for i in 0..width {
        let idx_left = values
            .len()
            .saturating_sub(data_points)
            .saturating_add(i * 2);
        let idx_right = idx_left + 1;

        let val_left = values.get(idx_left).unwrap_or(&0);
        let val_right = values.get(idx_right).unwrap_or(&0);

        let bits = get_braille_column_bits(*val_left, max_val, false)
            | get_braille_column_bits(*val_right, max_val, true);

        if bits == 0 {
            s.push(' ');
        } else {
            s.push(std::char::from_u32(0x2800 + bits as u32).unwrap_or(' '));
        }
    }
    s
}

fn get_braille_column_bits(val: u64, max: u64, is_right: bool) -> u8 {
    if val == 0 {
        return 0;
    }

    let dots = ((val as f32 / max as f32) * 4.0).ceil() as u8;
    let dots = dots.min(4);

    let mut bits = 0;
    if is_right {
        if dots >= 1 {
            bits |= 0x80;
        } // Dot 8
        if dots >= 2 {
            bits |= 0x20;
        } // Dot 6
        if dots >= 3 {
            bits |= 0x10;
        } // Dot 5
        if dots >= 4 {
            bits |= 0x08;
        } // Dot 4
    } else {
        if dots >= 1 {
            bits |= 0x40;
        } // Dot 7
        if dots >= 2 {
            bits |= 0x04;
        } // Dot 3
        if dots >= 3 {
            bits |= 0x02;
        } // Dot 2
        if dots >= 4 {
            bits |= 0x01;
        } // Dot 1
    }
    bits
}
