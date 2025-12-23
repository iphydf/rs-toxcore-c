use crate::widgets::{InputBox, InputBoxState};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, StatefulWidget, Widget},
};

#[derive(Debug, Clone, PartialEq)]
pub struct QuickSwitcherItem {
    pub name: String,
    pub description: String,
    pub prefix: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct QuickSwitcherState {
    pub input_state: InputBoxState,
    pub list_state: ListState,
    pub items: Vec<QuickSwitcherItem>,
}

impl QuickSwitcherState {
    pub fn new(items: Vec<QuickSwitcherItem>) -> Self {
        let mut state = Self {
            items,
            ..Default::default()
        };
        if !state.items.is_empty() {
            state.list_state.select(Some(0));
        }
        state
    }

    pub fn next(&mut self) {
        let (prefix, query) = parse_query(&self.input_state.text);
        let count = get_filtered_items(&self.items, prefix, query).len();
        if count == 0 {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= count.saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let (prefix, query) = parse_query(&self.input_state.text);
        let count = get_filtered_items(&self.items, prefix, query).len();
        if count == 0 {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    count.saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    pub fn filtered_items(&self) -> Vec<&QuickSwitcherItem> {
        let (prefix, query) = parse_query(&self.input_state.text);
        get_filtered_items(&self.items, prefix, query)
    }
}

fn get_filtered_items<'a>(
    items: &'a [QuickSwitcherItem],
    prefix: Option<&str>,
    query: &str,
) -> Vec<&'a QuickSwitcherItem> {
    let query_chars_count = query.chars().filter(|c| !c.is_whitespace()).count();

    items
        .iter()
        .filter(|item| {
            if let Some(p) = prefix
                && item.prefix != p
            {
                return false;
            }
            if query.is_empty() {
                return true;
            }
            let indices = find_fuzzy_indices(&item.name, query);
            if !indices.is_empty() && indices.len() == query_chars_count {
                return true;
            }
            if item.prefix == "h"
                && item
                    .description
                    .to_lowercase()
                    .contains(&query.to_lowercase())
            {
                return true;
            }
            false
        })
        .collect()
}

pub struct QuickSwitcher<'a> {
    block: Option<Block<'a>>,
    width_percent: u16,
    height_percent: u16,
}

impl<'a> Default for QuickSwitcher<'a> {
    fn default() -> Self {
        Self {
            block: Some(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Quick Switcher"),
            ),
            width_percent: 60,
            height_percent: 40,
        }
    }
}

impl<'a> QuickSwitcher<'a> {
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn width_percent(mut self, width: u16) -> Self {
        self.width_percent = width;
        self
    }

    pub fn height_percent(mut self, height: u16) -> Self {
        self.height_percent = height;
        self
    }
}

impl<'a> StatefulWidget for QuickSwitcher<'a> {
    type State = QuickSwitcherState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        // Dim the background
        for x in area.left()..area.right() {
            for y in area.top()..area.bottom() {
                let cell = &mut buf[(x, y)];
                cell.set_style(cell.style().add_modifier(Modifier::DIM));
            }
        }

        // Center the modal
        let modal_area = centered_rect(self.width_percent, self.height_percent, area);

        // Dim the background (Clear and then re-render over it)
        Clear.render(modal_area, buf);

        let block = self.block.unwrap_or_default();
        let inner_area = block.inner(modal_area);
        block.render(modal_area, buf);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Input box
                Constraint::Min(1),    // Results
                Constraint::Length(1), // Hints
            ])
            .split(inner_area);

        // Input Box
        let input = InputBox::default()
            .focused(true)
            .prompt("Go to: ❯ ")
            .block(Block::default().borders(Borders::BOTTOM));
        StatefulWidget::render(input, chunks[0], buf, &mut state.input_state);

        // Results
        let (_prefix_filter, search_query) = parse_query(&state.input_state.text);
        let filtered_items = get_filtered_items(&state.items, _prefix_filter, search_query);
        let filtered_count = filtered_items.len();

        // Ensure selection is valid
        if let Some(selected) = state.list_state.selected() {
            if selected >= filtered_count {
                state
                    .list_state
                    .select(if filtered_count > 0 { Some(0) } else { None });
            }
        } else if filtered_count > 0 {
            state.list_state.select(Some(0));
        }

        let list_items: Vec<ListItem> = filtered_items
            .iter()
            .map(|item| {
                let mut spans = Vec::new();
                spans.push(Span::styled(
                    format!("{}: ", item.prefix),
                    Style::default().fg(Color::DarkGray),
                ));

                let highlight_indices = find_fuzzy_indices(&item.name, search_query);
                let mut last_idx = 0;
                for &idx in &highlight_indices {
                    if idx > last_idx {
                        spans.push(Span::raw(&item.name[last_idx..idx]));
                    }
                    let char_len = item.name[idx..].chars().next().unwrap().len_utf8();
                    spans.push(Span::styled(
                        &item.name[idx..idx + char_len],
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ));
                    last_idx = idx + char_len;
                }
                if last_idx < item.name.len() {
                    spans.push(Span::raw(&item.name[last_idx..]));
                }

                spans.push(Span::styled(
                    format!(" - {}", item.description),
                    Style::default().fg(Color::DarkGray),
                ));

                ListItem::new(Line::from(spans))
            })
            .collect();

        let list = List::new(list_items)
            .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
            .highlight_symbol("> ");
        StatefulWidget::render(list, chunks[1], buf, &mut state.list_state);

        // Hints
        let hints = "[↑↓] Navigate [Enter] Jump [Esc] Close";
        buf.set_string(
            chunks[2].x,
            chunks[2].y,
            hints,
            Style::default().add_modifier(Modifier::DIM),
        );
    }
}

fn find_fuzzy_indices(name: &str, query: &str) -> Vec<usize> {
    let mut indices = Vec::new();
    let query_chars: Vec<char> = query
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_lowercase().next().unwrap())
        .collect();

    if query_chars.is_empty() {
        return indices;
    }

    let mut query_idx = 0;
    for (idx, c) in name.char_indices() {
        if query_idx < query_chars.len()
            && c.to_lowercase().next().unwrap() == query_chars[query_idx]
        {
            indices.push(idx);
            query_idx += 1;
        }
    }
    indices
}

fn parse_query(query: &str) -> (Option<&str>, &str) {
    if let Some((prefix, rest)) = query.split_once(':') {
        let prefix = prefix.trim();
        if ["f", "g", "h", ">"].contains(&prefix) {
            return (Some(prefix), rest.trim_start());
        }
    }
    (None, query)
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
