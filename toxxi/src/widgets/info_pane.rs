use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Span,
    widgets::{Block, Borders, Widget},
};
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, PartialEq)]
pub struct Participant {
    pub name: String,
    pub style: Style,
    pub role_symbol: String,
    pub role_style: Style,
}

impl Participant {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            style: Style::default(),
            role_symbol: "•".to_string(),
            role_style: Style::default(),
        }
    }

    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    pub fn role(mut self, symbol: impl Into<String>, style: Style) -> Self {
        self.role_symbol = symbol.into();
        self.role_style = style;
        self
    }
}

pub struct InfoPane<'a> {
    block: Option<Block<'a>>,
    details: Vec<(String, String)>,
    participants: Vec<Participant>,
}

impl<'a> InfoPane<'a> {
    pub fn new(title: String) -> Self {
        Self {
            block: Some(
                Block::default()
                    .borders(Borders::LEFT | Borders::TOP)
                    .title(title),
            ),
            details: Vec::new(),
            participants: Vec::new(),
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn details(mut self, details: Vec<(String, String)>) -> Self {
        self.details = details;
        self
    }

    pub fn participants(mut self, participants: Vec<Participant>) -> Self {
        self.participants = participants;
        self
    }
}

impl<'a> Widget for InfoPane<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let block = self.block.unwrap_or_default();
        let inner_area = block.inner(area);
        block.render(area, buf);

        if inner_area.width == 0 || inner_area.height == 0 {
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(self.details.len() as u16), // Details
                Constraint::Length(if self.details.is_empty() { 0 } else { 1 }), // Spacer if details exist
                Constraint::Min(0), // Participants list
            ])
            .split(inner_area);

        // Details
        for (i, (key, value)) in self.details.iter().enumerate() {
            let y = chunks[0].y + i as u16;
            if y >= chunks[0].bottom() {
                break;
            }
            let key_str = format!("{}: ", key);
            buf.set_string(
                chunks[0].x,
                y,
                &key_str,
                Style::default().fg(Color::DarkGray),
            );
            buf.set_string(
                chunks[0].x + key_str.width() as u16,
                y,
                value,
                Style::default(),
            );
        }

        // Participants
        if !self.participants.is_empty() {
            for (i, p) in self.participants.iter().enumerate() {
                let y = chunks[2].y + i as u16;
                if y >= chunks[2].bottom() {
                    break;
                }

                let role_span = Span::styled(&p.role_symbol, p.role_style);
                let name_span = Span::styled(&p.name, p.style);

                buf.set_span(chunks[2].x, y, &role_span, chunks[2].width);
                buf.set_span(
                    chunks[2].x + p.role_symbol.width() as u16 + 1,
                    y,
                    &name_span,
                    chunks[2].width,
                );
            }
        }
    }
}
