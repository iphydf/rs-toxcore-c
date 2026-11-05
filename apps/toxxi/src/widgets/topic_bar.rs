use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::{Paragraph, Widget},
};

pub struct TopicBar {
    text: String,
    style: Style,
}

impl TopicBar {
    pub fn new(text: String) -> Self {
        Self {
            text,
            style: Style::default().bg(Color::Blue).fg(Color::White),
        }
    }

    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

impl Widget for TopicBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        Paragraph::new(self.text)
            .style(self.style)
            .render(area, buf);
    }
}
