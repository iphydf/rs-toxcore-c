use crate::widgets::Card;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

pub struct GameCard {
    pub game_type: String,
    pub challenger: String,
    pub focused: bool,
    pub style: Style,
    pub border_style: Style,
}

impl GameCard {
    pub fn new(game_type: String, challenger: String) -> Self {
        Self {
            game_type,
            challenger,
            focused: false,
            style: Style::default().fg(Color::White),
            border_style: Style::default().fg(Color::Green),
        }
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        if focused {
            self.border_style = Style::default()
                .fg(Color::Yellow)
                .add_modifier(ratatui::style::Modifier::BOLD);
        }
        self
    }

    pub fn render_line(&self, line_idx: usize, area: Rect, buf: &mut Buffer) {
        let title = format!("{} Challenge", self.game_type);
        let card = Card::new(title, "🎮")
            .style(self.style)
            .border_style(self.border_style)
            .focused(self.focused);

        let hints = " [ (j) Join Game ] [ (n) No thanks ] ";

        card.render_line(
            line_idx,
            area,
            buf,
            |inner_area, buf| {
                let challenge_text = format!("{} wants to play!", self.challenger);
                buf.set_string(inner_area.x, inner_area.y, &challenge_text, self.style);
            },
            Some(hints),
        );
    }
}

impl Widget for GameCard {
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
