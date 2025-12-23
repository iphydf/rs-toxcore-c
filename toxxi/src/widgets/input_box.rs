use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, StatefulWidget, Widget},
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    None,
    Changed,
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Enter sends, Shift+Enter inserts newline
    SendOnEnter,
    /// Enter inserts newline, Shift+Enter sends
    NewlineOnEnter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputGrapheme {
    pub byte_idx: usize,
    pub len: usize,
    pub width: usize,
    pub screen_x: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputLine {
    pub graphemes: Vec<InputGrapheme>,
    pub is_soft_wrap: bool,
    pub y_offset: u16,
}

#[derive(Debug, Clone, PartialEq)]
struct UndoEntry {
    text: String,
    cursor_pos: usize,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct InputBoxState {
    // --- Logical State ---
    pub text: String,
    pub cursor_pos: usize, // absolute byte offset
    pub selection: Option<(usize, usize)>,
    pub mode: Option<InputMode>,
    pub clipboard: String,
    undo_stack: Vec<UndoEntry>,
    redo_stack: Vec<UndoEntry>,

    // --- Visual Cache (derived from logical state + width) ---
    pub lines: Vec<InputLine>,
    pub(crate) cursor_display_pos: (u16, u16), // relative to inner area (0,0)
    pub(crate) last_width: u16,
    pub(crate) prompt: String,
    pub scroll: usize,
}

impl InputBoxState {
    pub fn new() -> Self {
        Self {
            mode: Some(InputMode::SendOnEnter),
            ..Default::default()
        }
    }

    /// Internal method to ensure the layout cache is up-to-date.
    pub fn ensure_layout(&mut self, width: u16, prompt: &str) {
        if self.last_width == width && self.prompt == prompt && !self.lines.is_empty() {
            // We'll assume the text hasn't changed if this is called between renders.
            return;
        }

        self.last_width = width;
        self.prompt = prompt.to_string();
        if width == 0 {
            self.lines = vec![InputLine {
                graphemes: Vec::new(),
                is_soft_wrap: false,
                y_offset: 0,
            }];
            return;
        }

        let prompt_width = prompt.width();
        let mut lines = Vec::new();
        let mut current_graphemes = Vec::new();
        let mut current_line_width = prompt_width;
        let mut found_cursor = false;
        let mut cursor_line = 0;
        let mut cursor_col = 0;

        for (i, g) in self.text.grapheme_indices(true) {
            if i == self.cursor_pos {
                cursor_line = lines.len();
                cursor_col = current_line_width;
                found_cursor = true;
            }

            if g == "\n" {
                lines.push(InputLine {
                    graphemes: current_graphemes,
                    is_soft_wrap: false,
                    y_offset: lines.len() as u16,
                });
                current_graphemes = Vec::new();
                current_line_width = prompt_width;
                continue;
            }

            let w = g.width();
            // Wrap check: -1 for the wrap indicator space
            if current_line_width + w > (width as usize).saturating_sub(1) {
                lines.push(InputLine {
                    graphemes: current_graphemes,
                    is_soft_wrap: true,
                    y_offset: lines.len() as u16,
                });
                current_graphemes = Vec::new();
                current_line_width = prompt_width;
            }

            current_graphemes.push(InputGrapheme {
                byte_idx: i,
                len: g.len(),
                width: w,
                screen_x: current_line_width as u16,
            });
            current_line_width += w;
        }

        if !found_cursor {
            cursor_line = lines.len();
            cursor_col = current_line_width;
        }

        lines.push(InputLine {
            graphemes: current_graphemes,
            is_soft_wrap: false,
            y_offset: lines.len() as u16,
        });

        self.lines = lines;
        self.cursor_display_pos = (cursor_col as u16, cursor_line as u16);
    }

    fn invalidate_cache(&mut self) {
        self.last_width = 0;
    }

    pub fn handle_event(&mut self, event: &ratatui::crossterm::event::Event) -> Outcome {
        use ratatui::crossterm::event::{Event, KeyCode, KeyModifiers};

        if let Event::Key(key) = event {
            let extend_selection = key.modifiers.contains(KeyModifiers::SHIFT);

            match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.copy();
                    return Outcome::Unchanged;
                }
                KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.paste();
                    return Outcome::Changed;
                }
                KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.cut();
                    return Outcome::Changed;
                }
                KeyCode::Char('z') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.undo();
                    return Outcome::Changed;
                }
                KeyCode::Char('y') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.redo();
                    return Outcome::Changed;
                }
                KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.move_to_start(false);
                    self.selection = Some((0, self.text.len()));
                    self.cursor_pos = self.text.len();
                    self.invalidate_cache();
                    return Outcome::Unchanged;
                }
                KeyCode::Char(c) => {
                    if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT {
                        self.insert_char(c);
                        return Outcome::Changed;
                    }
                    if key.modifiers.contains(KeyModifiers::CONTROL) {
                        match c {
                            'w' => {
                                self.delete_word_left();
                                return Outcome::Changed;
                            }
                            'u' => {
                                self.delete_to_start();
                                return Outcome::Changed;
                            }
                            'k' => {
                                self.delete_to_end();
                                return Outcome::Changed;
                            }
                            _ => {}
                        }
                    }
                }
                KeyCode::Enter => {
                    let send = match self.mode() {
                        InputMode::SendOnEnter => !extend_selection,
                        InputMode::NewlineOnEnter => extend_selection,
                    };
                    if send {
                        return Outcome::None; // Let the caller handle sending
                    } else {
                        self.insert_newline();
                        return Outcome::Changed;
                    }
                }
                KeyCode::Backspace => {
                    if key.modifiers.contains(KeyModifiers::CONTROL) {
                        self.delete_word_left();
                    } else {
                        self.delete_prev_char();
                    }
                    return Outcome::Changed;
                }
                KeyCode::Delete => {
                    if key.modifiers.contains(KeyModifiers::CONTROL) {
                        self.delete_word_right();
                    } else {
                        self.delete_next_char();
                    }
                    return Outcome::Changed;
                }
                KeyCode::Left => {
                    if key.modifiers.contains(KeyModifiers::CONTROL) {
                        self.move_cursor_word_left(extend_selection);
                    } else {
                        self.move_cursor_left(extend_selection);
                    }
                    return Outcome::Unchanged;
                }
                KeyCode::Right => {
                    if key.modifiers.contains(KeyModifiers::CONTROL) {
                        self.move_cursor_word_right(extend_selection);
                    } else {
                        self.move_cursor_right(extend_selection);
                    }
                    return Outcome::Unchanged;
                }
                KeyCode::Up => {
                    self.move_cursor_up(extend_selection);
                    return Outcome::Unchanged;
                }
                KeyCode::Down => {
                    self.move_cursor_down(extend_selection);
                    return Outcome::Unchanged;
                }
                KeyCode::Home => {
                    self.move_to_start(extend_selection);
                    return Outcome::Unchanged;
                }
                KeyCode::End => {
                    self.move_to_end(extend_selection);
                    return Outcome::Unchanged;
                }
                _ => {}
            }
        }
        Outcome::None
    }

    /// Emits an OSC 52 escape sequence to set the system clipboard.
    /// This works over SSH and inside Tmux.
    pub fn copy_to_system_clipboard(&self, text: &str) -> String {
        let b64 = BASE64.encode(text);
        // OSC 52 sequence: \x1b]52;c;<base64>\x07
        // If inside tmux, we might need a double-wrap, but most modern tmux
        // versions handle the standard OSC 52 if 'set -s set-clipboard on' is set.
        format!("\x1b]52;c;{}\x07", b64)
    }

    /// Finds the closest byte offset for a given (x, y) coordinate relative to the
    /// inner area of the widget.
    pub fn hit_test(&self, x: u16, y: u16, _prompt_width: u16) -> usize {
        if self.lines.is_empty() {
            return 0;
        }

        // Find the line at the given Y offset (accounting for scroll)
        let line_idx = (y as usize + self.scroll).min(self.lines.len().saturating_sub(1));
        let line = &self.lines[line_idx];

        if line.graphemes.is_empty() {
            // Find start of this line by looking at previous lines
            let mut offset = 0;
            for i in 0..line_idx {
                for g in &self.lines[i].graphemes {
                    offset += g.len;
                }
                if !self.lines[i].is_soft_wrap {
                    offset += 1; // \n
                }
            }
            return offset;
        }

        // Search for the grapheme at the given X
        for g in &line.graphemes {
            if x >= g.screen_x && x < g.screen_x + g.width as u16 {
                return g.byte_idx;
            }
            if x < g.screen_x {
                return g.byte_idx;
            }
        }

        // If we are past the last grapheme on the line
        let last = line.graphemes.last().unwrap();
        last.byte_idx + last.len
    }

    pub fn mode(&self) -> InputMode {
        self.mode.unwrap_or(InputMode::SendOnEnter)
    }

    pub fn toggle_mode(&mut self) {
        self.mode = Some(match self.mode() {
            InputMode::SendOnEnter => InputMode::NewlineOnEnter,
            InputMode::NewlineOnEnter => InputMode::SendOnEnter,
        });
    }

    fn record_undo(&mut self) {
        self.undo_stack.push(UndoEntry {
            text: self.text.clone(),
            cursor_pos: self.cursor_pos,
        });
        self.redo_stack.clear();
        if self.undo_stack.len() > 100 {
            self.undo_stack.remove(0);
        }
        self.invalidate_cache();
    }

    pub fn undo(&mut self) {
        if let Some(entry) = self.undo_stack.pop() {
            self.redo_stack.push(UndoEntry {
                text: self.text.clone(),
                cursor_pos: self.cursor_pos,
            });
            self.text = entry.text;
            self.cursor_pos = entry.cursor_pos;
            self.selection = None;
            self.invalidate_cache();
        }
    }

    pub fn redo(&mut self) {
        if let Some(entry) = self.redo_stack.pop() {
            self.undo_stack.push(UndoEntry {
                text: self.text.clone(),
                cursor_pos: self.cursor_pos,
            });
            self.text = entry.text;
            self.cursor_pos = entry.cursor_pos;
            self.selection = None;
            self.invalidate_cache();
        }
    }

    pub fn copy(&mut self) {
        if let Some((start, end)) = self.selection {
            let (low, high) = if start < end {
                (start, end)
            } else {
                (end, start)
            };
            self.clipboard = self.text[low..high].to_string();
        }
    }

    pub fn cut(&mut self) {
        if let Some((start, end)) = self.selection {
            self.copy();
            self.record_undo();
            self.delete_selection(start, end);
            self.invalidate_cache();
        }
    }

    pub fn paste(&mut self) {
        if !self.clipboard.is_empty() {
            self.record_undo();
            if let Some((start, end)) = self.selection {
                self.delete_selection(start, end);
            }
            self.text.insert_str(self.cursor_pos, &self.clipboard);
            self.cursor_pos += self.clipboard.len();
            self.invalidate_cache();
        }
    }

    pub fn insert_str(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        let normalized = s.replace("\r\n", "\n").replace('\r', "\n");
        self.record_undo();
        if let Some((start, end)) = self.selection {
            self.delete_selection(start, end);
        }
        self.text.insert_str(self.cursor_pos, &normalized);
        self.cursor_pos += normalized.len();
        self.invalidate_cache();
    }

    pub fn clear(&mut self) {
        if self.text.is_empty() {
            return;
        }
        self.record_undo();
        self.text.clear();
        self.cursor_pos = 0;
        self.selection = None;
        self.scroll = 0;
        self.invalidate_cache();
    }

    pub fn set_value(&mut self, text: String) {
        self.record_undo();
        self.text = text;
        self.cursor_pos = self.text.len();
        self.selection = None;
        self.scroll = 0;
        self.invalidate_cache();
    }

    pub fn cursor(&self) -> (usize, usize) {
        if let Some((line_idx, col)) = self.find_cursor_2d() {
            (col as usize, line_idx)
        } else {
            (0, 0)
        }
    }

    pub fn set_cursor(&mut self, line: usize, col: usize) {
        if self.last_width == 0 {
            // Fallback for logic-only usage (like tests)
            if line == 0 && col == 0 {
                self.cursor_pos = 0;
            } else {
                self.cursor_pos = self.text.len();
            }
            return;
        }
        let prompt = self.prompt.clone();
        self.ensure_layout(self.last_width, &prompt);
        if line >= self.lines.len() {
            self.cursor_pos = self.text.len();
            return;
        }
        let target_line = &self.lines[line];
        self.cursor_pos = self.find_closest_pos(target_line, col as u16);
    }

    pub fn insert_char(&mut self, c: char) {
        self.record_undo();
        if let Some((start, end)) = self.selection {
            self.delete_selection(start, end);
        }
        self.text.insert(self.cursor_pos, c);
        self.cursor_pos += c.len_utf8();
        self.invalidate_cache();
    }

    pub fn insert_newline(&mut self) {
        self.insert_char('\n');
    }

    pub fn delete_prev_char(&mut self) {
        self.record_undo();
        if let Some((start, end)) = self.selection {
            self.delete_selection(start, end);
            return;
        }
        if self.cursor_pos > 0 {
            let mut graphemes = self.text[..self.cursor_pos].grapheme_indices(true).rev();
            if let Some((idx, _)) = graphemes.next() {
                self.text.replace_range(idx..self.cursor_pos, "");
                self.cursor_pos = idx;
                self.invalidate_cache();
            }
        }
    }

    pub fn delete_next_char(&mut self) {
        self.record_undo();
        if let Some((start, end)) = self.selection {
            self.delete_selection(start, end);
            return;
        }
        if self.cursor_pos < self.text.len() {
            let mut graphemes = self.text[self.cursor_pos..].grapheme_indices(true);
            if let Some((_, g)) = graphemes.next() {
                let end = self.cursor_pos + g.len();
                self.text.replace_range(self.cursor_pos..end, "");
                self.invalidate_cache();
            }
        }
    }

    fn delete_selection(&mut self, start: usize, end: usize) {
        let (low, high) = if start < end {
            (start, end)
        } else {
            (end, start)
        };
        self.text.replace_range(low..high, "");
        self.cursor_pos = low;
        self.selection = None;
    }

    pub fn move_cursor_left(&mut self, extend_selection: bool) {
        let prev_pos = self.cursor_pos;
        if self.cursor_pos > 0 {
            let mut graphemes = self.text[..self.cursor_pos].grapheme_indices(true).rev();
            if let Some((idx, _)) = graphemes.next() {
                self.cursor_pos = idx;
            }
        }
        self.handle_selection_movement(prev_pos, extend_selection);
        self.invalidate_cache();
    }

    pub fn move_cursor_right(&mut self, extend_selection: bool) {
        let prev_pos = self.cursor_pos;
        if self.cursor_pos < self.text.len() {
            let mut graphemes = self.text[self.cursor_pos..].grapheme_indices(true);
            if let Some((_, g)) = graphemes.next() {
                self.cursor_pos += g.len();
            }
        }
        self.handle_selection_movement(prev_pos, extend_selection);
        self.invalidate_cache();
    }

    fn handle_selection_movement(&mut self, prev_pos: usize, extend: bool) {
        if extend {
            match self.selection {
                Some((start, _)) => {
                    if self.cursor_pos == start {
                        self.selection = None;
                    } else {
                        self.selection = Some((start, self.cursor_pos));
                    }
                }
                None => {
                    if self.cursor_pos != prev_pos {
                        self.selection = Some((prev_pos, self.cursor_pos));
                    }
                }
            }
        } else {
            self.selection = None;
        }
    }

    pub fn move_to_start(&mut self, extend_selection: bool) {
        let prev_pos = self.cursor_pos;
        self.cursor_pos = 0;
        self.handle_selection_movement(prev_pos, extend_selection);
    }

    pub fn move_to_end(&mut self, extend_selection: bool) {
        let prev_pos = self.cursor_pos;
        self.cursor_pos = self.text.len();
        self.handle_selection_movement(prev_pos, extend_selection);
    }

    pub fn move_cursor_up(&mut self, extend_selection: bool) {
        let prev_pos = self.cursor_pos;
        if self.last_width > 0 {
            let prompt = self.prompt.clone();
            self.ensure_layout(self.last_width, &prompt);
            if let Some((line_idx, col)) = self.find_cursor_2d() {
                if line_idx > 0 {
                    let target_line = &self.lines[line_idx - 1];
                    self.cursor_pos = self.find_closest_pos(target_line, col);
                } else {
                    self.cursor_pos = 0;
                }
            }
        } else {
            self.cursor_pos = 0;
        }
        self.handle_selection_movement(prev_pos, extend_selection);
    }

    pub fn move_cursor_down(&mut self, extend_selection: bool) {
        let prev_pos = self.cursor_pos;
        if self.last_width > 0 {
            let prompt = self.prompt.clone();
            self.ensure_layout(self.last_width, &prompt);
            if let Some((line_idx, col)) = self.find_cursor_2d() {
                if line_idx < self.lines.len().saturating_sub(1) {
                    let target_line = &self.lines[line_idx + 1];
                    self.cursor_pos = self.find_closest_pos(target_line, col);
                } else {
                    self.cursor_pos = self.text.len();
                }
            }
        } else {
            self.cursor_pos = self.text.len();
        }
        self.handle_selection_movement(prev_pos, extend_selection);
    }

    fn find_cursor_2d(&self) -> Option<(usize, u16)> {
        for (line_idx, line) in self.lines.iter().enumerate() {
            for g in &line.graphemes {
                if g.byte_idx == self.cursor_pos {
                    return Some((line_idx, g.screen_x));
                }
            }
            // Check if cursor is at the end of this line
            let line_end_pos = if line.graphemes.is_empty() {
                // Approximate position for empty lines
                return Some((
                    line_idx,
                    line.graphemes.first().map(|g| g.screen_x).unwrap_or(0),
                ));
            } else {
                let last = line.graphemes.last().unwrap();
                last.byte_idx + last.len
            };

            if self.cursor_pos == line_end_pos {
                return Some((
                    line_idx,
                    line.graphemes
                        .last()
                        .map(|l| l.screen_x + l.width as u16)
                        .unwrap_or(0),
                ));
            }
        }
        None
    }

    fn find_closest_pos(&self, line: &InputLine, target_x: u16) -> usize {
        if line.graphemes.is_empty() {
            // Find start of this line (approximate)
            return self.cursor_pos;
        }

        let mut closest_pos = line.graphemes[0].byte_idx;
        let mut min_diff = (line.graphemes[0].screen_x as i32 - target_x as i32).abs();

        for g in &line.graphemes {
            let diff = (g.screen_x as i32 - target_x as i32).abs();
            if diff < min_diff {
                min_diff = diff;
                closest_pos = g.byte_idx;
            }
            let end_x = g.screen_x + g.width as u16;
            let end_diff = (end_x as i32 - target_x as i32).abs();
            if end_diff < min_diff {
                min_diff = end_diff;
                closest_pos = g.byte_idx + g.len;
            }
        }
        closest_pos
    }

    pub fn delete_to_start(&mut self) {
        self.record_undo();
        if self.cursor_pos > 0 {
            self.text.replace_range(0..self.cursor_pos, "");
            self.cursor_pos = 0;
        }
    }

    pub fn delete_to_end(&mut self) {
        self.record_undo();
        if self.cursor_pos < self.text.len() {
            self.text.replace_range(self.cursor_pos.., "");
        }
    }

    pub fn move_cursor_word_left(&mut self, extend_selection: bool) {
        let prev_pos = self.cursor_pos;
        if self.cursor_pos == 0 {
            return;
        }
        let mut index = self.cursor_pos;
        let graphemes: Vec<(usize, &str)> = self.text[..index].grapheme_indices(true).collect();
        let mut i = graphemes.len();

        // 1. Skip trailing whitespace
        while i > 0 && graphemes[i - 1].1.chars().all(|c| c.is_whitespace()) {
            i -= 1;
            index = graphemes.get(i).map(|(idx, _)| *idx).unwrap_or(0);
        }

        if i == 0 {
            self.cursor_pos = 0;
        } else {
            let last_char = graphemes[i - 1].1.chars().next().unwrap();
            let is_alphanumeric = last_char.is_alphanumeric();

            // 2. Skip same category (alphanumeric or punctuation/emoji)
            while i > 0 {
                let current_char = graphemes[i - 1].1.chars().next().unwrap();
                if current_char.is_whitespace() || current_char.is_alphanumeric() != is_alphanumeric
                {
                    break;
                }
                i -= 1;
                index = graphemes[i].0;
            }
            self.cursor_pos = index;
        }
        self.handle_selection_movement(prev_pos, extend_selection);
    }

    pub fn move_cursor_word_right(&mut self, extend_selection: bool) {
        let prev_pos = self.cursor_pos;
        if self.cursor_pos >= self.text.len() {
            return;
        }
        let mut index = self.cursor_pos;
        let graphemes: Vec<(usize, &str)> = self.text[index..].grapheme_indices(true).collect();
        let mut i = 0;

        // 1. Skip leading whitespace
        while i < graphemes.len() && graphemes[i].1.chars().all(|c| c.is_whitespace()) {
            i += 1;
        }

        if i >= graphemes.len() {
            index = self.text.len();
        } else {
            let first_char = graphemes[i].1.chars().next().unwrap();
            let is_alphanumeric = first_char.is_alphanumeric();

            // 2. Skip same category
            while i < graphemes.len() {
                let current_char = graphemes[i].1.chars().next().unwrap();
                if current_char.is_whitespace() || current_char.is_alphanumeric() != is_alphanumeric
                {
                    break;
                }
                i += 1;
            }
            index += if i < graphemes.len() {
                graphemes[i].0
            } else {
                self.text.len() - self.cursor_pos
            };
        }
        self.cursor_pos = index;
        self.handle_selection_movement(prev_pos, extend_selection);
    }

    pub fn delete_word_left(&mut self) {
        self.record_undo();
        if let Some((start, end)) = self.selection {
            self.delete_selection(start, end);
            return;
        }
        let end = self.cursor_pos;
        self.move_cursor_word_left(false);
        let start = self.cursor_pos;
        self.text.replace_range(start..end, "");
    }

    pub fn delete_word_right(&mut self) {
        self.record_undo();
        if let Some((start, end)) = self.selection {
            self.delete_selection(start, end);
            return;
        }
        let start = self.cursor_pos;
        self.move_cursor_word_right(false);
        let end = self.cursor_pos;
        self.text.replace_range(start..end, "");
        self.cursor_pos = start;
    }

    pub fn get_screen_x(&self, byte_idx: usize) -> Option<u16> {
        for line in &self.lines {
            for g in &line.graphemes {
                if g.byte_idx == byte_idx {
                    return Some(g.screen_x);
                }
            }
            if let Some(last) = line
                .graphemes
                .last()
                .filter(|l| l.byte_idx + l.len == byte_idx)
            {
                return Some(last.screen_x + last.width as u16);
            }
        }
        None
    }
}

pub struct InputBox<'a> {
    block: Option<Block<'a>>,
    style: Style,
    focused_style: Style,
    focused: bool,
    max_height: u16,
    prompt: String,
}

impl<'a> Default for InputBox<'a> {
    fn default() -> Self {
        Self {
            block: Some(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(ratatui::widgets::BorderType::Rounded)
                    .title(""),
            ),
            style: Style::default(),
            focused_style: Style::default().fg(Color::Cyan),
            focused: false,
            max_height: 10,
            prompt: "> ".to_string(),
        }
    }
}

impl<'a> InputBox<'a> {
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn max_height(mut self, max_height: u16) -> Self {
        self.max_height = max_height;
        self
    }

    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = prompt.into();
        self
    }

    /// Returns the height required to display the widget given a total width.
    /// This follows the Ratatui constraint-based layout principle by accounting
    /// for borders and max_height.
    pub fn height(&self, state: &mut InputBoxState, width: u16) -> u16 {
        let area = Rect::new(0, 0, width, 0);
        let inner_width = if let Some(block) = &self.block {
            block.inner(area).width
        } else {
            width
        };

        if inner_width == 0 {
            return 3;
        }

        state.ensure_layout(inner_width, &self.prompt);

        let border_height = if let Some(block) = &self.block {
            let inner = block.inner(Rect::new(0, 0, width, 100));
            100 - inner.height
        } else {
            0
        };

        (state.lines.len() as u16 + border_height)
            .min(self.max_height)
            .max(3)
    }
}

impl<'a> StatefulWidget for InputBox<'a> {
    type State = InputBoxState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let block = if let Some(block) = self.block {
            if self.focused {
                block.style(self.focused_style)
            } else {
                block.style(self.style)
            }
        } else {
            Block::default()
        };

        let inner_area = block.inner(area);
        block.render(area, buf);

        if inner_area.width == 0 || inner_area.height == 0 {
            return;
        }

        // Use the modern "Ratatui Way": Ensure layout is up-to-date
        state.ensure_layout(inner_area.width, &self.prompt);

        let cursor_line = state
            .lines
            .iter()
            .enumerate()
            .find(|(_, l)| {
                l.graphemes.iter().any(|g| g.byte_idx == state.cursor_pos)
                    || (l.graphemes.is_empty() && state.cursor_pos == 0)
                    || (!l.is_soft_wrap
                        && l.graphemes
                            .last()
                            .map(|g| g.byte_idx + g.len == state.cursor_pos)
                            .unwrap_or(false))
            })
            .map(|(i, _)| i)
            .unwrap_or(state.lines.len().saturating_sub(1));

        // Adjust scroll to keep cursor visible
        if cursor_line < state.scroll {
            state.scroll = cursor_line;
        } else if cursor_line >= state.scroll + inner_area.height as usize {
            state.scroll = cursor_line - inner_area.height as usize + 1;
        }

        // Render visible lines
        for (y_offset, line) in state
            .lines
            .iter()
            .skip(state.scroll)
            .take(inner_area.height as usize)
            .enumerate()
        {
            let line_idx = y_offset + state.scroll;
            let y = inner_area.y + y_offset as u16;

            // Draw prompt only on first line, but every line is indented by prompt width
            if line_idx == 0 {
                buf.set_string(
                    inner_area.x,
                    y,
                    &self.prompt,
                    Style::default().fg(Color::DarkGray),
                );
            }

            for g_info in &line.graphemes {
                let g = &state.text[g_info.byte_idx..g_info.byte_idx + g_info.len];
                let mut style = self.style;

                // Syntax highlighting
                if state.text.starts_with('/') {
                    let first_space = state.text.find(' ').unwrap_or(state.text.len());
                    if g_info.byte_idx < first_space {
                        style = style.fg(Color::Yellow);
                    }
                }

                // Mention highlighting
                if g == "@" || (g_info.byte_idx > 0 && is_mention_at(&state.text, g_info.byte_idx))
                {
                    style = style.fg(Color::Magenta);
                }

                if let Some((start, end)) = state.selection {
                    let (low, high) = if start < end {
                        (start, end)
                    } else {
                        (end, start)
                    };
                    if g_info.byte_idx >= low && g_info.byte_idx < high {
                        style = style.bg(Color::Blue).fg(Color::White);
                    }
                }

                buf.set_string(inner_area.x + g_info.screen_x, y, g, style);
            }

            if line.is_soft_wrap {
                buf[(inner_area.x + inner_area.width - 1, y)]
                    .set_symbol("↳")
                    .set_style(Style::default().fg(Color::DarkGray));
            }

            if line_idx == cursor_line {
                // Find column within the current line
                let col = if line.graphemes.is_empty() {
                    self.prompt.width()
                } else {
                    line.graphemes
                        .iter()
                        .find(|g| g.byte_idx == state.cursor_pos)
                        .map(|g| g.screen_x as usize)
                        .unwrap_or_else(|| {
                            let last = line.graphemes.last().unwrap();
                            (last.screen_x + last.width as u16) as usize
                        })
                };
                state.cursor_display_pos = (inner_area.x + col as u16, y);
            }
        }
    }
}

fn is_mention_at(text: &str, pos: usize) -> bool {
    if pos == 0 {
        return false;
    }
    let mut i = pos;
    let bytes = text.as_bytes();

    // Look back for '@'
    while i > 0 {
        i -= 1;
        if bytes[i] == b'@' {
            // Check if it was at start of word
            if i == 0
                || bytes[i - 1].is_ascii_whitespace()
                || bytes[i - 1] == b'('
                || bytes[i - 1] == b'['
            {
                return true;
            }
            return false;
        }
        if bytes[i].is_ascii_whitespace() {
            return false;
        }
    }
    false
}
