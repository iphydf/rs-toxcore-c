use crate::widgets::{EmojiGrid, EmojiGridState, InputBox, InputBoxState};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Clear, StatefulWidget, Widget},
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct EmojiPickerState {
    pub input_state: InputBoxState,
    pub grid_state: EmojiGridState,
    pub selected_index: usize,
    pub showing_hidden: bool,
    /// The emoji Backspace would hide, shown framed on its own first: if the
    /// terminal draws it badly, the frame breaks.
    pub confirming: Option<String>,
}

impl EmojiPickerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next(&mut self, cols: usize, hidden: &[String]) {
        let count = self.filtered_emojis(hidden).len();
        if count == 0 {
            return;
        }
        if self.selected_index + cols < count {
            self.selected_index += cols;
        } else if self.selected_index + 1 < count {
            self.selected_index += 1;
        } else {
            self.selected_index = 0;
        }
    }

    pub fn previous(&mut self, cols: usize, hidden: &[String]) {
        let count = self.filtered_emojis(hidden).len();
        if count == 0 {
            return;
        }
        if self.selected_index >= cols {
            self.selected_index -= cols;
        } else if self.selected_index > 0 {
            self.selected_index -= 1;
        } else {
            self.selected_index = count.saturating_sub(1);
        }
    }

    pub fn next_item(&mut self, hidden: &[String]) {
        let count = self.filtered_emojis(hidden).len();
        if count == 0 {
            return;
        }
        self.selected_index = (self.selected_index + 1) % count;
    }

    pub fn previous_item(&mut self, hidden: &[String]) {
        let count = self.filtered_emojis(hidden).len();
        if count == 0 {
            return;
        }
        if self.selected_index == 0 {
            self.selected_index = count.saturating_sub(1);
        } else {
            self.selected_index -= 1;
        }
    }

    /// Returns the emojis the search finds in the tab shown: those not
    /// `hidden`, or those that are.
    pub fn filtered_emojis(&self, hidden: &[String]) -> Vec<String> {
        let query = self.input_state.text.to_lowercase();
        let mut seen = std::collections::HashSet::new();
        crate::emojis::EMOJIS
            .iter()
            .filter(|(name, emoji)| {
                hidden.iter().any(|h| h == emoji) == self.showing_hidden
                    && (query.is_empty() || name.to_lowercase().contains(&query))
                    && seen.insert(*emoji)
            })
            .map(|(_, emoji)| emoji.to_string())
            .collect()
    }

    pub fn get_selected_emoji(&self, hidden: &[String]) -> Option<String> {
        let filtered = self.filtered_emojis(hidden);
        filtered.get(self.selected_index).cloned()
    }
}

pub struct EmojiPicker<'a> {
    block: Option<Block<'a>>,
    width_percent: u16,
    height_percent: u16,
    hidden: &'a [String],
}

impl<'a> EmojiPicker<'a> {
    /// A picker that leaves out the `hidden` emojis, except in its Hidden tab.
    pub fn new(hidden: &'a [String]) -> Self {
        Self {
            block: Some(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Emoji Picker "),
            ),
            width_percent: 50,
            height_percent: 50,
            hidden,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }
}

impl<'a> StatefulWidget for EmojiPicker<'a> {
    type State = EmojiPickerState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        // Dim the background
        for x in area.left()..area.right() {
            for y in area.top()..area.bottom() {
                let cell = &mut buf[(x, y)];
                cell.set_style(cell.style().add_modifier(Modifier::DIM));
            }
        }

        let modal_area = centered_rect(self.width_percent, self.height_percent, area);
        Clear.render(modal_area, buf);

        let block = self.block.unwrap_or_default();
        let inner_area = block.inner(modal_area);
        block.render(modal_area, buf);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Search box
                Constraint::Min(1),    // Grid
                Constraint::Length(1), // Hints
            ])
            .split(inner_area);

        let input = InputBox::default()
            .focused(true)
            .prompt("Search: ❯ ")
            .block(Block::default().borders(Borders::BOTTOM));
        StatefulWidget::render(input, chunks[0], buf, &mut state.input_state);

        let emojis = state.filtered_emojis(self.hidden);

        if state.selected_index >= emojis.len() && !emojis.is_empty() {
            state.selected_index = 0;
        }

        let (title, hints) = if state.showing_hidden {
            (
                format!(" Hidden ({}) ", self.hidden.len()),
                "⏎ Pick  ⌫ Put back  Tab All  Esc Close",
            )
        } else {
            (
                " Emojis ".to_owned(),
                "⏎ Pick  ⌫ Hide  Tab Hidden  Esc Close",
            )
        };
        let grid = EmojiGrid::new(&emojis, state.selected_index).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(title, Style::default().fg(Color::LightBlue))),
        );
        StatefulWidget::render(grid, chunks[1], buf, &mut state.grid_state);

        buf.set_stringn(
            chunks[2].x,
            chunks[2].y,
            hints,
            chunks[2].width as usize,
            Style::default().add_modifier(Modifier::DIM),
        );

        if let Some(emoji) = &state.confirming {
            render_confirmation(emoji, modal_area, buf);
        }
    }
}

/// A box with the emoji alone on a line of its frame, which shows whether the
/// terminal draws it at the width toxxi thinks.
fn render_confirmation(emoji: &str, area: Rect, buf: &mut Buffer) {
    const LINES: [&str; 2] = ["Hide it from the picker?", "⌫ Hide  Esc Keep"];
    let width = LINES
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0) as u16
        + 4;
    let height = 6;
    let box_area = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width.min(area.width),
        height.min(area.height),
    );
    Clear.render(box_area, buf);
    let block = Block::default().borders(Borders::ALL).title(" Hide ");
    let inner = block.inner(box_area);
    block.render(box_area, buf);
    let centred = |text: &str, y: u16, buf: &mut Buffer| {
        let len = ratatui::text::Line::from(text).width() as u16;
        let x = inner.x + inner.width.saturating_sub(len) / 2;
        buf.set_stringn(x, y, text, inner.width as usize, Style::default());
    };
    if inner.height >= 4 {
        centred(emoji, inner.y, buf);
        centred(LINES[0], inner.y + 2, buf);
        centred(LINES[1], inner.y + 3, buf);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
