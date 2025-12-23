use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub struct Card<'a> {
    pub title: String,
    pub icon: &'a str,
    pub style: Style,
    pub border_style: Style,
    pub focused: bool,
}

impl<'a> Card<'a> {
    pub fn new(title: String, icon: &'a str) -> Self {
        Self {
            title,
            icon,
            style: Style::default().fg(Color::White),
            border_style: Style::default().fg(Color::DarkGray),
            focused: false,
        }
    }

    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    pub fn border_style(mut self, style: Style) -> Self {
        self.border_style = style;
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn render_line<F>(
        &self,
        line_idx: usize,
        area: Rect,
        buf: &mut Buffer,
        content_renderer: F,
        footer_hints: Option<&str>,
    ) where
        F: FnOnce(Rect, &mut Buffer),
    {
        if area.height == 0 || area.width < 10 {
            return;
        }

        let x = area.x;
        let y = area.y;
        let width = area.width;

        // Pre-fill the line with background style to prevent leakage
        for x_offset in 0..width {
            buf[(x + x_offset, y)].set_symbol(" ").set_style(self.style);
        }

        match line_idx {
            0 => {
                // Top border
                let prefix = "╭─ ";
                buf.set_string(x, y, prefix, self.border_style);
                buf.set_string(x + 3, y, self.icon, self.border_style);
                let icon_w = self.icon.width() as u16;
                buf.set_string(x + 3 + icon_w, y, " ", self.border_style);

                let prefix_width = 4 + icon_w;
                let mut title = self.title.clone();
                let max_title_width = width.saturating_sub(prefix_width).saturating_sub(2);

                if title.width() > max_title_width as usize {
                    let mut truncated = String::new();
                    let mut cur_w = 0;
                    for g in title.graphemes(true) {
                        let gw = g.width();
                        if cur_w + gw + 1 > max_title_width as usize {
                            truncated.push('…');
                            break;
                        }
                        truncated.push_str(g);
                        cur_w += gw;
                    }
                    title = truncated;
                }

                buf.set_string(
                    x + prefix_width,
                    y,
                    &title,
                    self.style.add_modifier(Modifier::BOLD),
                );

                let current_pos = prefix_width + title.width() as u16;
                if width > current_pos {
                    let remaining = width.saturating_sub(current_pos).saturating_sub(1);
                    let line = "─".repeat(remaining as usize);
                    buf.set_string(x + current_pos, y, &line, self.border_style);
                    buf.set_string(x + width - 1, y, "╮", self.border_style);
                }
            }
            1 => {
                // Middle line
                buf.set_string(x, y, "│ ", self.border_style);
                buf.set_string(x + width - 1, y, "│", self.border_style);

                let inner_area = Rect::new(x + 2, y, width.saturating_sub(3), 1);
                // Background already filled with spaces above
                content_renderer(inner_area, buf);
            }
            2 => {
                // Bottom border
                buf.set_string(x, y, "╰", self.border_style);
                if width > 2 {
                    let line = "─".repeat(width as usize - 2);
                    buf.set_string(x + 1, y, &line, self.border_style);
                }
                buf.set_string(x + width - 1, y, "╯", self.border_style);

                if let Some(hints) = footer_hints {
                    let hint_style = if self.focused {
                        self.style.fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };

                    if hints.width() < (width as usize).saturating_sub(4) {
                        buf.set_string(x + 2, y, hints, hint_style);
                    }
                }
            }
            _ => {}
        }
    }
}
