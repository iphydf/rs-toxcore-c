use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Widget,
};

pub struct ProfileTabs {
    pub profiles: Vec<String>,
    pub selected_index: usize,
}

impl ProfileTabs {
    pub fn new(profiles: Vec<String>, selected_index: usize) -> Self {
        Self {
            profiles,
            selected_index,
        }
    }
}

impl Widget for ProfileTabs {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 {
            return;
        }

        let mut x = area.x;
        for (i, name) in self.profiles.iter().enumerate() {
            let is_selected = i == self.selected_index;
            let style = if is_selected {
                Style::default()
                    .bg(Color::Blue)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().bg(Color::DarkGray).fg(Color::Gray)
            };

            let text = format!(" [{}: {}] ", i + 1, name);
            let text_width = text.len() as u16;

            if x + text_width > area.right() {
                break;
            }

            buf.set_string(x, area.y, &text, style);
            x += text_width;
        }
    }
}
