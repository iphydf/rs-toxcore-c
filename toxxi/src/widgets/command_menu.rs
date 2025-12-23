use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, StatefulWidget, Widget},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Debug, Clone, PartialEq)]
pub struct Command {
    pub name: String,
    pub aliases: Vec<String>,
    pub description: String,
    pub short_description: Option<String>,
    pub args: String,
    pub short_args: Option<String>,
    pub subcommands: Vec<Command>,
    pub is_dynamic: bool,
}

impl Command {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            aliases: Vec::new(),
            description: description.into(),
            short_description: None,
            args: String::new(),
            short_args: None,
            subcommands: Vec::new(),
            is_dynamic: false,
        }
    }

    pub fn dynamic(mut self, is_dynamic: bool) -> Self {
        self.is_dynamic = is_dynamic;
        self
    }

    pub fn alias(mut self, alias: impl Into<String>) -> Self {
        self.aliases.push(alias.into());
        self
    }

    pub fn args(mut self, args: impl Into<String>) -> Self {
        self.args = args.into();
        self
    }

    pub fn short_args(mut self, args: impl Into<String>) -> Self {
        self.short_args = Some(args.into());
        self
    }

    pub fn short_description(mut self, desc: impl Into<String>) -> Self {
        self.short_description = Some(desc.into());
        self
    }

    pub fn subcommands(mut self, subcommands: Vec<Command>) -> Self {
        self.subcommands = subcommands;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CommandMenuState {
    pub list_state: ListState,
    pub commands: Vec<Command>,
    /// The original top-level commands (needed to reconstruct tree when moving up)
    pub root_commands: Vec<Command>,
    pub filter: String,
    /// The path of parent commands if we are in a subcommand menu
    pub parent_path: Vec<String>,
    /// Transient commands (e.g. arguments)
    pub dynamic_commands: Vec<Command>,
}

impl CommandMenuState {
    pub fn new(commands: Vec<Command>) -> Self {
        let mut state = Self {
            commands: commands.clone(),
            root_commands: commands,
            ..Default::default()
        };
        state.refresh_selection();
        state
    }

    pub fn set_dynamic_commands(&mut self, commands: Vec<Command>) {
        self.dynamic_commands = commands;
        self.refresh_selection();
    }

    pub fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        self.resolve_path();
        self.refresh_selection();
    }

    fn resolve_path(&mut self) {
        // If filter starts with '/', ignore it for path resolution
        let clean_filter = self.filter.strip_prefix('/').unwrap_or(&self.filter);
        let parts: Vec<&str> = clean_filter.split_whitespace().collect();

        // Start from root
        let mut current_commands = self.root_commands.clone();
        let mut new_path = Vec::new();
        let mut final_filter = clean_filter.to_string();

        // If the user has typed "cmd subcmd ", we want to be in "subcmd"'s menu
        // with an empty filter. If they typed "cmd sub", we want to be in "cmd"'s
        // menu with a filter of "sub".
        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;
            let has_trailing_space = self.filter.ends_with(' ');
            let part_lower = part.to_lowercase();

            if let Some(cmd) = current_commands.iter().find(|c| {
                c.name.to_lowercase() == part_lower
                    || c.aliases.iter().any(|a| a.to_lowercase() == part_lower)
            }) {
                if !is_last || has_trailing_space {
                    if !cmd.subcommands.is_empty() {
                        new_path.push(cmd.name.clone());
                        current_commands = cmd.subcommands.clone();
                        final_filter = if is_last {
                            String::new()
                        } else {
                            parts[i + 1..].join(" ")
                        };
                    } else {
                        // Leaf command reached
                        new_path.push(cmd.name.clone());
                        current_commands = Vec::new(); // Arguments stage
                        final_filter = if is_last {
                            String::new()
                        } else {
                            parts[i + 1..].join(" ")
                        };
                        // We do NOT break here anymore because we might have arguments following
                    }
                } else {
                    // We are still typing the command name
                    final_filter = part.to_string();
                    break;
                }
            } else {
                // No match
                if !is_last || has_trailing_space {
                    // Treat as argument
                    new_path.push(part.to_string());
                    // Clear current commands as we are now in argument territory
                    current_commands = Vec::new();

                    if is_last {
                        final_filter = String::new();
                    }
                    // Continue to next part
                } else {
                    // This is the active filter
                    final_filter = parts[i..].join(" ");
                    break;
                }
            }
        }

        self.commands = current_commands;
        self.parent_path = new_path;
        self.filter = final_filter;
    }

    pub fn complete(&self) -> Option<String> {
        self.selected_command().map(|cmd| {
            if cmd.is_dynamic {
                // If it's a dynamic candidate (argument), we replace the current argument
                let mut path = self.parent_path.clone();
                path.push(cmd.name.clone());
                format!("/{} ", path.join(" "))
            } else {
                let mut path = self.parent_path.clone();
                path.push(cmd.name.clone());
                let mut result = format!("/{}", path.join(" "));
                if !cmd.subcommands.is_empty() || !cmd.args.is_empty() {
                    result.push(' ');
                }
                result
            }
        })
    }

    fn refresh_selection(&mut self) {
        if !self.filtered_commands().is_empty() {
            if self.list_state.selected().is_none() {
                self.list_state.select(Some(0));
            } else {
                let count = self.filtered_commands().len();
                if self.list_state.selected().unwrap() >= count {
                    self.list_state.select(Some(0));
                }
            }
        } else {
            self.list_state.select(None);
        }
    }

    pub fn filtered_commands(&self) -> Vec<&Command> {
        let mut cmds = get_ranked_commands(&self.commands, &self.filter);
        if !self.dynamic_commands.is_empty() {
            cmds.extend(get_ranked_commands(&self.dynamic_commands, &self.filter));
        }
        cmds
    }

    pub fn next(&mut self) {
        let count = self.filtered_commands().len();
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
        if count > 0 {
            self.list_state.select(Some(i));
        }
    }

    pub fn previous(&mut self) {
        let count = self.filtered_commands().len();
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
        if count > 0 {
            self.list_state.select(Some(i));
        }
    }

    pub fn selected_command(&self) -> Option<&Command> {
        let filtered = self.filtered_commands();
        self.list_state
            .selected()
            .and_then(|i| filtered.get(i).copied())
    }
}

fn get_ranked_commands<'a>(commands: &'a [Command], filter: &str) -> Vec<&'a Command> {
    if filter.is_empty() {
        return commands.iter().collect();
    }

    let filter_lower = filter.to_lowercase();
    let mut scored: Vec<(i64, &'a Command)> = commands
        .iter()
        .filter_map(|cmd| {
            let mut best_score = -1;

            // Score name
            if let Some(score) = calculate_score(&cmd.name, &filter_lower) {
                best_score = best_score.max(score);
            }

            // Score aliases
            for alias in &cmd.aliases {
                if let Some(score) = calculate_score(alias, &filter_lower) {
                    // Slight penalty for alias match vs name match
                    best_score = best_score.max(score - 10);
                }
            }

            if best_score >= 0 {
                Some((best_score, cmd))
            } else {
                None
            }
        })
        .collect();

    // Sort descending by score
    scored.sort_by(|a, b| b.0.cmp(&a.0));

    scored.into_iter().map(|(_, cmd)| cmd).collect()
}

fn calculate_score(text: &str, query: &str) -> Option<i64> {
    let text_lower = text.to_lowercase();

    // 1. Exact match (Highest priority)
    if text_lower == query {
        return Some(1000);
    }

    // 2. Prefix match (High priority)
    if text_lower.starts_with(query) {
        return Some(500 - text.len() as i64); // Prefer shorter matches
    }

    // 3. Fuzzy/Subsequence match
    let indices = find_fuzzy_indices(text, query);
    if indices.is_empty() {
        return None;
    }

    // Calculate score based on compactness of match
    let mut score = 100;

    // Penalty for start position
    score -= indices[0] as i64 * 5;

    // Penalty for gaps
    let mut gaps = 0;
    for i in 0..indices.len() - 1 {
        gaps += (indices[i + 1] - indices[i] - 1) as i64;
    }
    score -= gaps * 10;

    Some(score)
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

    if query_idx < query_chars.len() {
        indices.clear();
    }
    indices
}

pub struct CommandMenu<'a> {
    block: Option<Block<'a>>,
    style: Style,
    max_height: u16,
}

impl<'a> Default for CommandMenu<'a> {
    fn default() -> Self {
        Self {
            block: Some(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(ratatui::widgets::BorderType::Rounded),
            ),
            style: Style::default(),
            max_height: 10,
        }
    }
}

impl<'a> CommandMenu<'a> {
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn max_height(mut self, max_height: u16) -> Self {
        self.max_height = max_height;
        self
    }

    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

impl<'a> StatefulWidget for CommandMenu<'a> {
    type State = CommandMenuState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let filtered: Vec<Command> = state.filtered_commands().into_iter().cloned().collect();
        let filtered_count = filtered.len();
        if filtered_count == 0 {
            return;
        }

        // Constraints for the command list
        // We want it to be tall enough for items or the number of items available
        let height = (filtered_count as u16 + 2)
            .min(self.max_height)
            .min(area.height);
        if height < 3 {
            return;
        }

        // The menu usually appears above the input box, so we'll assume 'area'
        // is the space designated for it.
        let menu_area = Rect {
            x: area.x,
            y: area.y + area.height.saturating_sub(height),
            width: area.width,
            height,
        };

        buf.set_style(menu_area, self.style);
        Clear.render(menu_area, buf);

        let block = self.block.unwrap_or_default();
        let list_area = block.inner(menu_area);
        block.render(menu_area, buf);

        // Show current parent path if any
        if !state.parent_path.is_empty() {
            let path_str = format!(" /{} ", state.parent_path.join(" "));
            buf.set_string(
                menu_area.x + 2,
                menu_area.y,
                path_str,
                Style::default().fg(Color::Yellow),
            );
        }

        // Determine layout mode (Full vs Compact)
        let name_col_width = 12;
        let min_desc_width = 20;
        let min_gap = 2;

        let calculate_max_width = |use_short: bool| -> usize {
            filtered
                .iter()
                .map(|cmd| {
                    let name_len = cmd.name.width();
                    let effective_name_len = name_len.max(name_col_width);
                    let alias_len = if cmd.aliases.is_empty() {
                        0
                    } else {
                        3 + cmd.aliases.join(", ").width()
                    };

                    let args_str = if use_short {
                        cmd.short_args.as_ref().unwrap_or(&cmd.args)
                    } else {
                        &cmd.args
                    };

                    let args_len = if args_str.is_empty() {
                        0
                    } else {
                        1 + args_str.width()
                    };
                    2 + effective_name_len + alias_len + args_len
                })
                .max()
                .unwrap_or(0)
        };

        let max_full_width = calculate_max_width(false);
        let available_width = list_area.width as usize;

        // Check if full mode fits
        let use_short_mode = if max_full_width + min_gap + min_desc_width > available_width {
            // Full mode is too wide, try short mode
            let max_short_width = calculate_max_width(true);
            max_short_width + min_gap + min_desc_width <= available_width
                || max_short_width < max_full_width
        } else {
            false
        };

        // Account for list highlight symbol (">") which takes 1 char
        let item_width = (list_area.width as usize).saturating_sub(1);

        let items: Vec<ListItem> = filtered
            .iter()
            .enumerate()
            .map(|(i, cmd)| {
                let is_selected = state.list_state.selected() == Some(i);

                let mut spans = Vec::new();

                // Prefix: Use '/' only for top-level, space for subcommands
                let prefix = if state.parent_path.is_empty() {
                    "/"
                } else {
                    " "
                };

                // Command Name with Highlight
                let mut name_spans = Vec::new();
                let highlight_indices = find_fuzzy_indices(&cmd.name, &state.filter);

                let mut last_idx = 0;
                for &idx in &highlight_indices {
                    if idx > last_idx {
                        name_spans.push(Span::raw(&cmd.name[last_idx..idx]));
                    }
                    let char_len = cmd.name[idx..].chars().next().unwrap().len_utf8();
                    name_spans.push(Span::styled(
                        &cmd.name[idx..idx + char_len],
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ));
                    last_idx = idx + char_len;
                }
                if last_idx < cmd.name.len() {
                    name_spans.push(Span::raw(&cmd.name[last_idx..]));
                }

                let name_style = if is_selected {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                spans.push(Span::styled(format!(" {}", prefix), name_style));
                let mut name_width = 0;
                for s in name_spans {
                    name_width += s.content.width();
                    spans.push(s.patch_style(name_style));
                }

                // Add padding to reach a fixed width for the name column
                if name_width < name_col_width {
                    spans.push(Span::styled(
                        " ".repeat(name_col_width - name_width),
                        name_style,
                    ));
                }

                // Aliases
                if !cmd.aliases.is_empty() {
                    spans.push(Span::styled(
                        format!(" ({})", cmd.aliases.join(", ")),
                        Style::default().fg(Color::DarkGray),
                    ));
                }

                // Args Hint
                let args_str = if use_short_mode {
                    cmd.short_args.as_ref().unwrap_or(&cmd.args)
                } else {
                    &cmd.args
                };

                if !args_str.is_empty() {
                    spans.push(Span::styled(
                        format!(" {}", args_str),
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    ));
                }

                // Description - Columnar Alignment
                let current_content_width = 2
                    + name_width.max(name_col_width)
                    + if cmd.aliases.is_empty() {
                        0
                    } else {
                        3 + cmd.aliases.join(", ").width()
                    }
                    + if args_str.is_empty() {
                        0
                    } else {
                        1 + args_str.width()
                    };

                let min_gap = 2;
                let mut desc = cmd.description.clone();
                let mut desc_width = desc.width();

                // Calculate max available width for description
                let max_desc_width = item_width.saturating_sub(current_content_width + min_gap);

                if desc_width > max_desc_width {
                    let mut end_idx = 0;
                    let mut current_width = 0;
                    for (idx, c) in desc.char_indices() {
                        if current_width + c.width().unwrap_or(0) > max_desc_width.saturating_sub(1)
                        {
                            // -1 for ellipsis
                            break;
                        }
                        current_width += c.width().unwrap_or(0);
                        end_idx = idx + c.len_utf8();
                    }
                    desc = format!("{}…", &desc[..end_idx]);
                    desc_width = desc.width();
                }

                let gap = item_width.saturating_sub(current_content_width + desc_width);

                if gap > 0 {
                    spans.push(Span::raw(" ".repeat(gap)));
                    spans.push(Span::styled(desc, Style::default().fg(Color::DarkGray)));
                }

                ListItem::new(Line::from(spans))
            })
            .collect();

        let list = List::new(items)
            .highlight_style(Style::default().bg(Color::Indexed(236))) // Dark gray highlight
            .highlight_symbol(">");

        let selected_index = state.list_state.selected();
        StatefulWidget::render(list, list_area, buf, &mut state.list_state);

        // Footer info
        if menu_area.width > 30 {
            let footer = format!(
                " ({}/{}) [Tab] to complete ",
                selected_index.map(|i| i + 1).unwrap_or(0),
                filtered_count
            );
            buf.set_string(
                menu_area.x + menu_area.width.saturating_sub(footer.width() as u16 + 2),
                menu_area.y + menu_area.height - 1,
                footer,
                Style::default().fg(Color::DarkGray),
            );
        }
    }
}
