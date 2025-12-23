use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{
        Block, Borders, Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget, Widget,
    },
};

#[derive(Debug, Clone, Default)]
pub struct EmojiGridState {
    pub scroll: usize,
    pub cols: usize,
    pub rows: usize,
}

pub struct EmojiGrid<'a> {
    candidates: &'a [String],
    selected_index: usize,
    block: Option<Block<'a>>,
    selected_style: Style,
    unselected_style: Style,
    item_width: u16,
}

impl<'a> EmojiGrid<'a> {
    pub fn new(candidates: &'a [String], selected_index: usize) -> Self {
        Self {
            candidates,
            selected_index,
            block: Some(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(Span::styled(
                        " Emojis ",
                        Style::default().fg(Color::LightBlue),
                    )),
            ),
            selected_style: Style::default()
                .bg(Color::Rgb(80, 80, 80))
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            unselected_style: Style::default(),
            item_width: 3,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn selected_style(mut self, style: Style) -> Self {
        self.selected_style = style;
        self
    }

    pub fn unselected_style(mut self, style: Style) -> Self {
        self.unselected_style = style;
        self
    }

    pub fn item_width(mut self, width: u16) -> Self {
        self.item_width = width;
        self
    }
}

impl<'a> StatefulWidget for EmojiGrid<'a> {
    type State = EmojiGridState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let block = self.block.unwrap_or_default();
        let inner_area = block.inner(area);
        block.render(area, buf);

        if inner_area.width < self.item_width
            || inner_area.height == 0
            || self.candidates.is_empty()
        {
            // Update state with theoretical values to avoid stale data logic in controller
            state.cols = (inner_area.width / self.item_width).max(1) as usize;
            state.rows = inner_area.height as usize;
            return;
        }

        // Calculate actual layout metrics
        let cols = (inner_area.width / self.item_width).max(1) as usize;
        let rows_visible = inner_area.height as usize;

        // Expose metrics to state for the controller
        state.cols = cols;
        state.rows = rows_visible;

        let selected_row = self.selected_index / cols;

        // Ensure selected row is visible (Scroll into view)
        if selected_row < state.scroll {
            state.scroll = selected_row;
        } else if selected_row >= state.scroll + rows_visible {
            state.scroll = selected_row.saturating_sub(rows_visible) + 1;
        }

        let total_items = self.candidates.len();
        let total_rows = total_items.div_ceil(cols);

        for r in 0..rows_visible {
            let row_idx = state.scroll + r;
            if row_idx >= total_rows {
                break;
            }

            for c in 0..cols {
                let idx = (row_idx * cols) + c;
                if idx >= total_items {
                    break;
                }

                let x = inner_area.x + (c as u16 * self.item_width);
                let y = inner_area.y + r as u16;

                // Stop if we run out of horizontal space
                if x + self.item_width > inner_area.right() {
                    break;
                }

                let style = if idx == self.selected_index {
                    self.selected_style
                } else {
                    self.unselected_style
                };

                // Direct buffer write is more efficient than Paragraph widget for simple cells
                buf.set_string(x, y, &self.candidates[idx], style);
            }
        }

        if total_rows > rows_visible {
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"))
                .track_symbol(Some("│"))
                .thumb_symbol("█");

            let mut scrollbar_state =
                ScrollbarState::new(total_rows.saturating_sub(rows_visible)).position(state.scroll);

            scrollbar.render(area, buf, &mut scrollbar_state);
        }
    }
}
