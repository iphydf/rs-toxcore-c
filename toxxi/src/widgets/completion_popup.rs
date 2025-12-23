use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{
        Block, Borders, List, ListItem, ListState, Scrollbar, ScrollbarOrientation, ScrollbarState,
        StatefulWidget,
    },
};

#[derive(Debug, Clone, Default)]
pub struct CompletionPopupState {
    pub list_state: ListState,
}

pub struct CompletionPopup<'a> {
    candidates: &'a [String],
    selected_index: usize,
    block: Option<Block<'a>>,
}

impl<'a> CompletionPopup<'a> {
    pub fn new(candidates: &'a [String], selected_index: usize) -> Self {
        Self {
            candidates,
            selected_index,
            block: Some(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(Span::styled(
                        " Candidates ",
                        Style::default().fg(Color::LightBlue),
                    )),
            ),
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }
}

impl<'a> StatefulWidget for CompletionPopup<'a> {
    type State = CompletionPopupState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        state.list_state.select(Some(self.selected_index));

        let items: Vec<_> = self
            .candidates
            .iter()
            .map(|c| ListItem::new(c.clone()))
            .collect();

        let list = List::new(items)
            .block(self.block.unwrap_or_default())
            .highlight_style(
                Style::default()
                    .bg(Color::Rgb(50, 50, 50))
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        StatefulWidget::render(list, area, buf, &mut state.list_state);

        let candidate_count = self.candidates.len();
        let display_height = area.height.saturating_sub(2) as usize;

        if candidate_count > display_height {
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"))
                .track_symbol(Some("│"))
                .thumb_symbol("█");

            let mut scrollbar_state =
                ScrollbarState::new(candidate_count.saturating_sub(display_height))
                    .position(self.selected_index.saturating_sub(display_height / 2));

            scrollbar.render(area, buf, &mut scrollbar_state);
        }
    }
}
