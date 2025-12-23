use crate::widgets::{FileTransferCard, GameCard};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget, Widget},
};
use std::borrow::Cow;
use std::collections::HashMap;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, PartialEq)]
pub enum MessageStatus {
    Sending,
    Delivered,
    Read,
    Failed,
    System,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MessageContent {
    Text(String),
    FileTransfer {
        name: String,
        size: u64,
        progress: f64,
        speed: String,
        is_incoming: bool,
        paused: bool,
        eta: String,
    },
    GameInvite {
        game_type: String,
        challenger: String,
    },
    System(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChatMessage {
    pub sender: String,
    pub timestamp: String,
    pub unix_timestamp: u64,
    pub content: MessageContent,
    pub status: MessageStatus,
    pub is_me: bool,
    pub highlighted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MessageListState {
    /// Scroll offset in lines from the bottom
    pub scroll: usize,
    /// Currently selected message index
    pub selected_index: Option<usize>,
    /// Number of messages that were rendered in the last frame
    pub last_rendered_count: usize,
    /// Total height of all messages in lines
    pub total_height: usize,
    /// If true, the next render will adjust scroll to make selected_index visible
    pub(crate) ensure_selected_visible: bool,
}

impl PartialEq for MessageListState {
    fn eq(&self, other: &Self) -> bool {
        self.scroll == other.scroll
            && self.selected_index == other.selected_index
            && self.last_rendered_count == other.last_rendered_count
            && self.total_height == other.total_height
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LayoutCacheEntry {
    pub lines: HashMap<usize, Vec<WrappedLine>>,
    pub usage_count: usize,
    pub last_use: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChatLayout {
    // Key is wrap_width
    pub cache: HashMap<u16, LayoutCacheEntry>,
    pub total_height: usize,
    pub last_width: u16,
    pub max_sender_width: u16,
    pub processed_count: usize,
    pub tick: u64,
}

impl ChatLayout {
    pub fn invalidate(&mut self) {
        self.cache.clear();
        self.total_height = 0;
        self.last_width = 0;
        self.max_sender_width = 0;
        self.processed_count = 0;
        self.tick = 0;
    }

    pub fn update(&mut self, messages: &[ChatMessage], width: u16) {
        self.tick += 1;

        // Edge case: history was cleared or replaced with fewer items
        if messages.len() < self.processed_count {
            self.invalidate();
        }

        let is_append = self.last_width == width
            && self.processed_count > 0
            && messages.len() >= self.processed_count;

        let start_index = if is_append { self.processed_count } else { 0 };

        // Scan for sender width in the new range
        let new_range_max_width = messages[start_index..]
            .iter()
            .map(|m| m.sender.width())
            .max()
            .unwrap_or(0)
            .clamp(5, 12) as u16;

        let mut must_rebuild_all = false;

        if is_append {
            if new_range_max_width > self.max_sender_width {
                // Sender column grew, decreasing content width. Must rebuild all.
                must_rebuild_all = true;
                self.max_sender_width = new_range_max_width;
            }
        } else {
            // Full rebuild or first run
            must_rebuild_all = true;
            // Scan everything for max width
            self.max_sender_width = messages
                .iter()
                .map(|m| m.sender.width())
                .max()
                .unwrap_or(8)
                .clamp(5, 12) as u16;
        }

        let actual_start_index = if must_rebuild_all {
            self.total_height = 0;
            self.last_width = width;
            0
        } else {
            start_index
        };

        let wide_mode = width > 50;
        let time_width = 8;
        let status_width = 2;
        let separator_width = 3;

        let content_width = if wide_mode {
            width
                .saturating_sub(time_width + status_width + self.max_sender_width + separator_width)
        } else {
            width
        };
        let wrap_width = content_width.saturating_sub(1);

        // LFU Cache Logic
        if !self.cache.contains_key(&wrap_width) {
            if self.cache.len() >= 10 {
                // Evict least frequently used, tie-break with LRU
                if let Some((&k, _)) = self.cache.iter().min_by(|(_, a), (_, b)| {
                    a.usage_count
                        .cmp(&b.usage_count)
                        .then_with(|| a.last_use.cmp(&b.last_use))
                }) {
                    self.cache.remove(&k);
                }
            }
            self.cache.insert(wrap_width, LayoutCacheEntry::default());
        }

        let entry = self.cache.get_mut(&wrap_width).unwrap();
        entry.usage_count += 1;
        entry.last_use = self.tick;

        for (idx, msg) in messages.iter().enumerate().skip(actual_start_index) {
            let lines_count = match &msg.content {
                MessageContent::Text(text) | MessageContent::System(text) => {
                    if let Some(cached_lines) = entry.lines.get(&idx) {
                        cached_lines.len()
                    } else {
                        let lines = wrap_text(text, wrap_width as usize);
                        let len = lines.len();
                        entry.lines.insert(idx, lines);
                        len
                    }
                }
                MessageContent::FileTransfer { .. } | MessageContent::GameInvite { .. } => 3,
            };

            let is_grouped = if idx > 0 {
                let prev_msg = &messages[idx - 1];
                prev_msg.sender == msg.sender
                    && msg.unix_timestamp.saturating_sub(prev_msg.unix_timestamp) < 120
            } else {
                false
            };

            let header_height = if !wide_mode && !is_grouped { 1 } else { 0 };
            self.total_height += lines_count + header_height;
        }

        self.processed_count = messages.len();
    }

    pub fn update_message(&mut self, index: usize, msg: &ChatMessage, width: u16) {
        if width != self.last_width {
            return;
        }

        let wide_mode = width > 50;
        let time_width = 8;
        let status_width = 2;
        let separator_width = 3;

        let content_width = if wide_mode {
            width
                .saturating_sub(time_width + status_width + self.max_sender_width + separator_width)
        } else {
            width
        };
        let wrap_width = content_width.saturating_sub(1);

        let lines_count = match &msg.content {
            MessageContent::Text(text) | MessageContent::System(text) => {
                let lines = wrap_text(text, wrap_width as usize);
                let count = lines.len();

                // Update cache if exists for this width
                if let Some(entry) = self.cache.get_mut(&wrap_width) {
                    if let Some(old_lines) = entry.lines.insert(index, lines) {
                        self.total_height = self.total_height.saturating_sub(old_lines.len());
                    } else {
                        // Message not in cache; treat as new addition to height.
                    }
                }
                count
            }
            MessageContent::FileTransfer { .. } | MessageContent::GameInvite { .. } => 3,
        };

        self.total_height += lines_count;
    }
}

impl MessageListState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn select(&mut self, index: Option<usize>) {
        self.selected_index = index;
        self.ensure_selected_visible = true;
    }

    pub fn select_next(&mut self, count: usize) {
        if count == 0 {
            self.selected_index = None;
            return;
        }
        self.selected_index = Some(match self.selected_index {
            Some(i) => (i + 1).min(count.saturating_sub(1)),
            None => count.saturating_sub(1),
        });
        self.ensure_selected_visible = true;
    }

    pub fn select_previous(&mut self) {
        self.selected_index = self.selected_index.map(|i| i.saturating_sub(1));
        self.ensure_selected_visible = true;
    }

    pub fn jump_to_timestamp(&mut self, timestamp: u64, messages: &[ChatMessage]) {
        if let Some(idx) = messages.iter().position(|m| m.unix_timestamp >= timestamp) {
            self.selected_index = Some(idx);
            self.ensure_selected_visible = true;
        }
    }

    pub fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_add(1);
    }

    pub fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub fn scroll_to_bottom(&mut self) {
        self.scroll = 0;
    }
}

pub struct MessageList<'a> {
    block: Option<Block<'a>>,
    messages: &'a [ChatMessage],
    wide_mode: bool,
    sender_width: u16,
    grouping_threshold: u64,
    show_scrollbar: bool,
    focused: bool,
    explicit_total_height: Option<usize>,
    layout: Option<&'a ChatLayout>,
}

impl<'a> MessageList<'a> {
    pub fn new(messages: &'a [ChatMessage]) -> Self {
        Self {
            block: None,
            messages,
            wide_mode: true,
            sender_width: 8,
            grouping_threshold: 120,
            show_scrollbar: true,
            focused: false,
            explicit_total_height: None,
            layout: None,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn layout(mut self, layout: &'a ChatLayout) -> Self {
        self.layout = Some(layout);
        // If layout provides sender_width and total_height, use them implicitly?
        // Let's use them explicitly in render, but updating sender_width here is fine too.
        self.sender_width = layout.max_sender_width;
        self.explicit_total_height = Some(layout.total_height);
        self
    }

    pub fn explicit_total_height(mut self, height: usize) -> Self {
        self.explicit_total_height = Some(height);
        self
    }

    pub fn wide_mode(mut self, wide_mode: bool) -> Self {
        self.wide_mode = wide_mode;
        self
    }

    pub fn sender_width(mut self, width: u16) -> Self {
        self.sender_width = width;
        self
    }

    pub fn grouping_threshold(mut self, threshold: u64) -> Self {
        self.grouping_threshold = threshold;
        self
    }

    pub fn show_scrollbar(mut self, show: bool) -> Self {
        self.show_scrollbar = show;
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn get_sender_width(&self) -> u16 {
        self.sender_width
    }
}

impl<'a> StatefulWidget for MessageList<'a> {
    type State = MessageListState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let inner_area = if let Some(block) = self.block {
            let inner = block.inner(area);
            block.render(area, buf);
            inner
        } else {
            area
        };

        if inner_area.width == 0 || inner_area.height == 0 {
            return;
        }

        let scrollbar_adjustment =
            if self.show_scrollbar && state.total_height > inner_area.height as usize {
                1
            } else {
                0
            };

        let mut y = inner_area.y + inner_area.height;
        let mut rendered_count = 0;

        // Status symbols from UX design
        let get_status_symbol = |status: &MessageStatus| match status {
            MessageStatus::Sending => "○",
            MessageStatus::Delivered => "●",
            MessageStatus::Read => "✓",
            MessageStatus::Failed => "!",
            MessageStatus::System => "⚙",
        };

        let mut total_lines = 0;
        let mut lines_to_skip = state.scroll;

        // Inverting index because we iterate rev() but want stable keys for cache
        let messages_len = self.messages.len();
        let selected_index = state.selected_index;

        if state.ensure_selected_visible {
            if let Some(selected) = selected_index {
                let mut current_line_offset = 0;
                for (rev_idx, msg) in self.messages.iter().rev().enumerate() {
                    let idx = messages_len.saturating_sub(rev_idx + 1);

                    let content_width = if self.wide_mode {
                        let time_width = 8;
                        let status_width = 2;
                        let separator_width = 3;
                        inner_area.width.saturating_sub(
                            time_width
                                + status_width
                                + self.sender_width
                                + separator_width
                                + scrollbar_adjustment,
                        )
                    } else {
                        inner_area.width.saturating_sub(scrollbar_adjustment)
                    };

                    let lines_count = match &msg.content {
                        MessageContent::Text(text) | MessageContent::System(text) => {
                            let wrap_width = content_width.saturating_sub(1);
                            if let Some(layout) = self.layout {
                                if let Some(entry) = layout.cache.get(&wrap_width) {
                                    if let Some(cached) = entry.lines.get(&idx) {
                                        cached.len()
                                    } else {
                                        wrap_text(text, wrap_width as usize).len()
                                    }
                                } else {
                                    wrap_text(text, wrap_width as usize).len()
                                }
                            } else {
                                wrap_text(text, wrap_width as usize).len()
                            }
                        }
                        _ => 3,
                    };

                    let is_grouped = if idx > 0 {
                        let prev_msg = &self.messages[idx - 1];
                        prev_msg.sender == msg.sender
                            && msg.unix_timestamp.saturating_sub(prev_msg.unix_timestamp)
                                < self.grouping_threshold
                    } else {
                        false
                    };

                    let header_height = if !self.wide_mode && !is_grouped { 1 } else { 0 };
                    let msg_height = lines_count + header_height;

                    if idx == selected {
                        if current_line_offset < state.scroll {
                            state.scroll = current_line_offset;
                        } else if current_line_offset + msg_height
                            > state.scroll + inner_area.height as usize
                        {
                            state.scroll = (current_line_offset + msg_height)
                                .saturating_sub(inner_area.height as usize);
                        }
                        break;
                    }
                    current_line_offset += msg_height;
                }
            }
            state.ensure_selected_visible = false;
        }

        // Render visible messages from bottom up
        for (rev_idx, msg) in self.messages.iter().rev().enumerate() {
            let idx = messages_len.saturating_sub(rev_idx + 1);

            let is_grouped = if idx > 0 {
                let prev_msg = &self.messages[idx - 1];
                prev_msg.sender == msg.sender
                    && msg.unix_timestamp.saturating_sub(prev_msg.unix_timestamp)
                        < self.grouping_threshold
            } else {
                false
            };

            let status_symbol = get_status_symbol(&msg.status);
            let time_width = 8; // "[HH:MM] "
            let status_width = 2; // "● "
            let separator_width = 3; // " | "

            let content_width = if self.wide_mode {
                inner_area.width.saturating_sub(
                    time_width
                        + status_width
                        + self.sender_width
                        + separator_width
                        + scrollbar_adjustment,
                )
            } else {
                inner_area.width.saturating_sub(scrollbar_adjustment)
            };

            let lines: Cow<'_, [WrappedLine]> = match &msg.content {
                MessageContent::Text(text) | MessageContent::System(text) => {
                    let wrap_width = content_width.saturating_sub(1);

                    if let Some(layout) = self.layout {
                        if let Some(entry) = layout.cache.get(&wrap_width) {
                            if let Some(cached) = entry.lines.get(&idx) {
                                Cow::Borrowed(cached)
                            } else {
                                Cow::Owned(wrap_text(text, wrap_width as usize))
                            }
                        } else {
                            Cow::Owned(wrap_text(text, wrap_width as usize))
                        }
                    } else {
                        Cow::Owned(wrap_text(text, wrap_width as usize))
                    }
                }
                MessageContent::FileTransfer { .. } | MessageContent::GameInvite { .. } => {
                    // Cards are always 3 lines high. We use a placeholder for lines count.
                    Cow::Owned(vec![
                        WrappedLine {
                            text: String::new(),
                            is_soft_wrap: false
                        };
                        3
                    ])
                }
            };

            let header_height = if !self.wide_mode && !is_grouped { 1 } else { 0 };
            let msg_height = lines.len() + header_height;
            total_lines += msg_height;

            // Handle scrolling at line level
            let mut lines_to_render = Vec::new();
            for (line_idx, line) in lines.iter().enumerate().rev() {
                if lines_to_skip > 0 {
                    lines_to_skip -= 1;
                } else {
                    lines_to_render.push((line_idx, line));
                }
            }

            let mut header_visible = false;
            if header_height > 0 {
                if lines_to_skip > 0 {
                    lines_to_skip -= 1;
                } else {
                    header_visible = true;
                }
            }

            if lines_to_render.is_empty() && !header_visible {
                if y <= inner_area.y && self.explicit_total_height.is_some() {
                    // Optimization: If we have pre-calculated total height and we've filled the screen,
                    // we can stop iterating.
                    break;
                }
                continue;
            }

            if y <= inner_area.y {
                if self.explicit_total_height.is_some() {
                    break;
                }
                continue;
            }

            rendered_count += 1;

            if self.wide_mode {
                let content_x =
                    inner_area.x + time_width + status_width + self.sender_width + separator_width;
                let content_width = inner_area
                    .width
                    .saturating_sub(content_x - inner_area.x)
                    .saturating_sub(scrollbar_adjustment);

                match &msg.content {
                    MessageContent::Text(_) | MessageContent::System(_) => {
                        let mut style = if let MessageContent::System(_) = msg.content {
                            Style::default()
                                .fg(Color::Blue)
                                .add_modifier(Modifier::ITALIC)
                        } else {
                            Style::default()
                        };

                        if self.focused && selected_index == Some(idx) {
                            style = style.bg(Color::Indexed(236)); // Subtle highlight
                        }

                        for (line_idx, line) in lines_to_render {
                            y = y.saturating_sub(1);
                            if y < inner_area.y {
                                break;
                            }
                            // Clear line background for highlight
                            if selected_index == Some(idx) {
                                for x in content_x..inner_area.right() {
                                    buf[(x, y)].set_style(style);
                                }
                            }
                            buf.set_string(content_x, y, &line.text, style);
                            if line.is_soft_wrap {
                                buf.set_string(
                                    content_x + content_width - 1,
                                    y,
                                    "↳",
                                    Style::default().fg(Color::DarkGray),
                                );
                            }
                            render_gutter(GutterParams {
                                buf,
                                x: inner_area.x,
                                y,
                                msg,
                                status_symbol,
                                is_first_line: line_idx == 0,
                                is_grouped,
                                sender_width: self.sender_width,
                                highlighted: msg.highlighted,
                            });
                        }
                    }
                    MessageContent::FileTransfer {
                        name,
                        size,
                        progress,
                        speed,
                        paused,
                        eta,
                        is_incoming,
                    } => {
                        let card =
                            FileTransferCard::new(name.clone(), *size, *progress, speed.clone())
                                .is_incoming(*is_incoming)
                                .paused(*paused)
                                .eta(eta.clone())
                                .focused(self.focused && selected_index == Some(idx));

                        for (line_idx, _) in lines_to_render {
                            y = y.saturating_sub(1);
                            if y < inner_area.y {
                                break;
                            }

                            card.render_line(
                                line_idx,
                                Rect::new(content_x, y, content_width.saturating_sub(1), 1),
                                buf,
                            );
                            render_gutter(GutterParams {
                                buf,
                                x: inner_area.x,
                                y,
                                msg,
                                status_symbol,
                                is_first_line: line_idx == 0,
                                is_grouped,
                                sender_width: self.sender_width,
                                highlighted: msg.highlighted,
                            });
                        }
                    }
                    MessageContent::GameInvite {
                        game_type,
                        challenger,
                    } => {
                        let card = GameCard::new(game_type.clone(), challenger.clone())
                            .focused(self.focused && selected_index == Some(idx));

                        for (line_idx, _) in lines_to_render {
                            y = y.saturating_sub(1);
                            if y < inner_area.y {
                                break;
                            }

                            card.render_line(
                                line_idx,
                                Rect::new(content_x, y, content_width.saturating_sub(1), 1),
                                buf,
                            );
                            render_gutter(GutterParams {
                                buf,
                                x: inner_area.x,
                                y,
                                msg,
                                status_symbol,
                                is_first_line: line_idx == 0,
                                is_grouped,
                                sender_width: self.sender_width,
                                highlighted: msg.highlighted,
                            });
                        }
                    }
                }
            } else {
                // Narrow mode implementation (Stacked layout)
                match &msg.content {
                    MessageContent::Text(_) | MessageContent::System(_) => {
                        let mut style = if let MessageContent::System(_) = msg.content {
                            Style::default()
                                .fg(Color::Blue)
                                .add_modifier(Modifier::ITALIC)
                        } else {
                            Style::default()
                        };

                        if self.focused && selected_index == Some(idx) {
                            style = style.bg(Color::Indexed(236));
                        }

                        for (_, line) in lines_to_render {
                            y = y.saturating_sub(1);
                            if y < inner_area.y {
                                break;
                            }
                            if selected_index == Some(idx) {
                                for x in inner_area.left()..inner_area.right() {
                                    buf[(x, y)].set_style(style);
                                }
                            }
                            buf.set_string(inner_area.x, y, &line.text, style);
                            if line.is_soft_wrap {
                                buf.set_string(
                                    inner_area.x + inner_area.width - 1 - scrollbar_adjustment,
                                    y,
                                    "↳",
                                    Style::default().fg(Color::DarkGray),
                                );
                            }
                        }
                    }
                    MessageContent::FileTransfer {
                        name,
                        size,
                        progress,
                        speed,
                        paused,
                        eta,
                        is_incoming,
                    } => {
                        let card =
                            FileTransferCard::new(name.clone(), *size, *progress, speed.clone())
                                .is_incoming(*is_incoming)
                                .paused(*paused)
                                .eta(eta.clone())
                                .focused(self.focused && selected_index == Some(idx));

                        for (line_idx, _) in lines_to_render {
                            y = y.saturating_sub(1);
                            if y < inner_area.y {
                                break;
                            }
                            card.render_line(
                                line_idx,
                                Rect::new(inner_area.x, y, inner_area.width.saturating_sub(1), 1),
                                buf,
                            );
                        }
                    }
                    MessageContent::GameInvite {
                        game_type,
                        challenger,
                    } => {
                        let card = GameCard::new(game_type.clone(), challenger.clone())
                            .focused(self.focused && selected_index == Some(idx));

                        for (line_idx, _) in lines_to_render {
                            y = y.saturating_sub(1);
                            if y < inner_area.y {
                                break;
                            }
                            card.render_line(
                                line_idx,
                                Rect::new(inner_area.x, y, inner_area.width.saturating_sub(1), 1),
                                buf,
                            );
                        }
                    }
                }

                if header_visible {
                    y = y.saturating_sub(1);
                    if y >= inner_area.y {
                        let mut header_style = Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::BOLD);
                        if msg.highlighted {
                            header_style = header_style.bg(Color::Red).fg(Color::White);
                        }
                        let header = format!("{} {} {}", msg.timestamp, msg.sender, status_symbol);
                        buf.set_string(inner_area.x, y, &header, header_style);
                    }
                }
            }
        }

        state.last_rendered_count = rendered_count;
        state.total_height = self.explicit_total_height.unwrap_or(total_lines);

        // Render Scrollbar
        if self.show_scrollbar && state.total_height > inner_area.height as usize {
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"))
                .track_symbol(Some("│"))
                .thumb_symbol("█");

            let max_scroll = state
                .total_height
                .saturating_sub(inner_area.height as usize);
            let scrollbar_pos = max_scroll.saturating_sub(state.scroll);

            let mut scrollbar_state = ScrollbarState::new(max_scroll).position(scrollbar_pos);

            scrollbar.render(area, buf, &mut scrollbar_state);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedLine {
    pub text: String,
    pub is_soft_wrap: bool,
}

pub fn wrap_text(text: &str, width: usize) -> Vec<WrappedLine> {
    if width == 0 {
        return vec![WrappedLine {
            text: text.to_string(),
            is_soft_wrap: false,
        }];
    }
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        if paragraph.is_empty() {
            lines.push(WrappedLine {
                text: String::new(),
                is_soft_wrap: false,
            });
            continue;
        }

        let mut current_line = String::new();
        let mut current_width = 0;

        let graphemes: Vec<&str> = paragraph.graphemes(true).collect();
        let mut i = 0;
        while i < graphemes.len() {
            let g = graphemes[i];
            let w = g.width();

            if g.chars().all(|c| c.is_whitespace()) {
                current_line.push_str(g);
                current_width += w;
                i += 1;
                continue;
            }

            let mut word_end = i;
            let mut word_width = 0;

            while word_end < graphemes.len() {
                let next_g = graphemes[word_end];
                if next_g.chars().all(|c| c.is_whitespace()) {
                    break;
                }
                let next_w = next_g.width();
                if next_w > 1 && word_end > i {
                    break;
                }
                word_width += next_w;
                word_end += 1;
                if next_w > 1 {
                    break;
                }
            }

            let word = graphemes[i..word_end].join("");

            if current_width + word_width > width {
                if !current_line.is_empty() {
                    lines.push(WrappedLine {
                        text: current_line.trim_end().to_string(),
                        is_soft_wrap: true,
                    });
                    current_line = String::new();
                    current_width = 0;
                }

                if word_width > width {
                    for g in word.graphemes(true) {
                        let gw = g.width();
                        if current_width + gw > width {
                            lines.push(WrappedLine {
                                text: current_line.to_string(),
                                is_soft_wrap: true,
                            });
                            current_line = String::new();
                            current_width = 0;
                        }
                        current_line.push_str(g);
                        current_width += gw;
                    }
                } else {
                    current_line = word;
                    current_width = word_width;
                }
            } else {
                current_line.push_str(&word);
                current_width += word_width;
            }
            i = word_end;
        }

        if !current_line.is_empty() || lines.is_empty() {
            lines.push(WrappedLine {
                text: current_line.trim_end().to_string(),
                is_soft_wrap: false,
            });
        }
    }
    lines
}

struct GutterParams<'a> {
    buf: &'a mut Buffer,
    x: u16,
    y: u16,
    msg: &'a ChatMessage,
    status_symbol: &'a str,
    is_first_line: bool,
    is_grouped: bool,
    sender_width: u16,
    highlighted: bool,
}

fn render_gutter(params: GutterParams<'_>) {
    if params.is_first_line && !params.is_grouped {
        let time_str = format!("[{:>5}] ", params.msg.timestamp);
        params.buf.set_string(
            params.x,
            params.y,
            &time_str,
            Style::default().fg(Color::DarkGray),
        );

        let mut sender_style = if params.msg.is_me {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Cyan)
        };

        if params.highlighted {
            sender_style = sender_style.bg(Color::Red).add_modifier(Modifier::BOLD);
        }

        let mut display_name = params.msg.sender.clone();
        if display_name.width() > params.sender_width as usize {
            let mut truncated = String::new();
            let mut current_width = 0;
            for g in display_name.graphemes(true) {
                let gw = g.width();
                if current_width + gw + 1 > params.sender_width as usize {
                    truncated.push('…');
                    break;
                }
                truncated.push_str(g);
                current_width += gw;
            }
            display_name = truncated;
        }

        let current_width = display_name.width();
        if current_width < params.sender_width as usize {
            let padding = " ".repeat(params.sender_width as usize - current_width);
            display_name = format!("{}{}", padding, display_name);
        }

        params
            .buf
            .set_string(params.x + 10, params.y, &display_name, sender_style);
    }

    if params.is_first_line {
        params.buf.set_string(
            params.x + 8,
            params.y,
            params.status_symbol,
            Style::default().fg(Color::DarkGray),
        );
    }
    params.buf.set_string(
        params.x + 10 + params.sender_width,
        params.y,
        " | ",
        Style::default().fg(Color::DarkGray),
    );
}
