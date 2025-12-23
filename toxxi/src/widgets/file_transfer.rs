use crate::widgets::Card;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub struct FileTransferCard {
    pub name: String,
    pub size: u64,
    pub progress: f64,
    pub speed: String,
    pub eta: String,
    pub is_incoming: bool,
    pub paused: bool,
    pub focused: bool,
    pub style: Style,
    pub border_style: Style,
}

impl FileTransferCard {
    pub fn new(name: String, size: u64, progress: f64, speed: String) -> Self {
        Self {
            name,
            size,
            progress,
            speed,
            eta: String::new(),
            is_incoming: true,
            paused: false,
            focused: false,
            style: Style::default().fg(Color::White),
            border_style: Style::default().fg(Color::DarkGray),
        }
    }

    pub fn eta(mut self, eta: String) -> Self {
        self.eta = eta;
        self
    }

    pub fn is_incoming(mut self, is_incoming: bool) -> Self {
        self.is_incoming = is_incoming;
        self
    }

    pub fn paused(mut self, paused: bool) -> Self {
        self.paused = paused;
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        if focused {
            self.border_style = Style::default().fg(Color::Cyan);
        }
        self
    }

    pub fn render_line(&self, line_idx: usize, area: Rect, buf: &mut Buffer) {
        let title_icon = if self.is_incoming { "📥" } else { "📤" };
        let mut title = format!("{} [{:.1} MB]", self.name, self.size as f64 / 1_048_576.0);
        if self.paused {
            title.push_str(" (PAUSED)");
        }

        let card = Card::new(title, title_icon)
            .style(self.style)
            .border_style(self.border_style)
            .focused(self.focused);

        let hints = if self.focused {
            Some(if self.is_incoming {
                "[ (a) Accept (p) Pause/Res (o) Dest (x) Cancel ]"
            } else {
                "[ (p) Pause/Res (x) Cancel ]"
            })
        } else {
            None
        };

        card.render_line(
            line_idx,
            area,
            buf,
            |inner_area, buf| {
                let bar_width = (inner_area.width as usize).saturating_sub(23).max(5);
                let progress_bar = render_progress_bar(self.progress, bar_width);
                let mut progress_text = format!(
                    "{} {:>3.0}% ({})",
                    progress_bar,
                    self.progress * 100.0,
                    self.speed
                );
                if !self.eta.is_empty() {
                    progress_text.push_str(&format!(" ETA: {}", self.eta));
                }

                // Ensure progress text doesn't overflow
                if progress_text.width() > inner_area.width as usize {
                    let mut truncated = String::new();
                    let mut cur_w = 0;
                    for g in progress_text.graphemes(true) {
                        if cur_w + g.width() > (inner_area.width as usize).saturating_sub(1) {
                            break;
                        }
                        truncated.push_str(g);
                        cur_w += g.width();
                    }
                    progress_text = truncated;
                }

                buf.set_string(inner_area.x, inner_area.y, &progress_text, self.style);
            },
            hints,
        );
    }
}

impl Widget for FileTransferCard {
    fn render(self, area: Rect, buf: &mut Buffer) {
        for i in 0..area.height {
            self.render_line(
                i as usize,
                Rect::new(area.x, area.y + i, area.width, 1),
                buf,
            );
        }
    }
}

fn render_progress_bar(progress: f64, width: usize) -> String {
    let filled = (progress * width as f64).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}
