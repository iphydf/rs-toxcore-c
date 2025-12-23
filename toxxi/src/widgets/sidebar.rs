use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, StatefulWidget, Widget},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactStatus {
    Online,
    Away,
    Busy,
    Offline,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SidebarItem {
    pub name: String,
    pub status: ContactStatus,
    pub unread_count: u32,
    pub item_type: SidebarItemType,
    pub is_typing: bool,
    pub status_message: Option<String>,
}

impl SidebarItem {
    pub fn new(name: impl Into<String>, item_type: SidebarItemType) -> Self {
        Self {
            name: name.into(),
            status: ContactStatus::Offline,
            unread_count: 0,
            item_type,
            is_typing: false,
            status_message: None,
        }
    }

    pub fn status(mut self, status: ContactStatus) -> Self {
        self.status = status;
        self
    }

    pub fn unread(mut self, count: u32) -> Self {
        self.unread_count = count;
        self
    }

    pub fn typing(mut self, is_typing: bool) -> Self {
        self.is_typing = is_typing;
        self
    }

    pub fn status_message(mut self, msg: impl Into<String>) -> Self {
        self.status_message = Some(msg.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidebarItemType {
    Friend,
    Group,
    Conference,
    Category,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SidebarState {
    pub list_state: ListState,
    pub items: Vec<SidebarItem>,
    pub collapsed_categories: Vec<SidebarItemType>,
}

impl SidebarState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn toggle_category(&mut self, item_type: SidebarItemType) {
        if let Some(pos) = self
            .collapsed_categories
            .iter()
            .position(|&t| t == item_type)
        {
            self.collapsed_categories.remove(pos);
        } else {
            self.collapsed_categories.push(item_type);
        }
    }

    pub fn is_collapsed(&self, item_type: SidebarItemType) -> bool {
        self.collapsed_categories.contains(&item_type)
    }
}

pub struct Sidebar<'a> {
    block: Option<Block<'a>>,
    focused: bool,
    narrow_mode: bool,
}

impl<'a> Default for Sidebar<'a> {
    fn default() -> Self {
        Self {
            block: Some(Block::default().borders(Borders::RIGHT).title("Contacts")),
            focused: false,
            narrow_mode: false,
        }
    }
}

impl<'a> Sidebar<'a> {
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn narrow_mode(mut self, narrow_mode: bool) -> Self {
        self.narrow_mode = narrow_mode;
        self
    }
}

impl<'a> StatefulWidget for Sidebar<'a> {
    type State = SidebarState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let block = self.block.unwrap_or_default();
        let inner_area = block.inner(area);
        block.render(area, buf);

        if inner_area.width == 0 || inner_area.height == 0 {
            return;
        }

        let mut list_items = Vec::new();
        let mut current_category = None;

        for (idx, item) in state.items.iter().enumerate() {
            if item.item_type == SidebarItemType::Category {
                current_category = Some(match item.name.as_str() {
                    "Friends" => SidebarItemType::Friend,
                    "Groups" => SidebarItemType::Group,
                    "Conferences" => SidebarItemType::Conference,
                    _ => SidebarItemType::Category,
                });

                let is_collapsed = current_category
                    .map(|t| state.is_collapsed(t))
                    .unwrap_or(false);
                let symbol = if is_collapsed { "▶" } else { "▼" };

                if !self.narrow_mode {
                    // Add a small gap before categories (except the first one)
                    if idx > 0 {
                        list_items.push(ListItem::new(""));
                    }

                    let label = match current_category {
                        Some(SidebarItemType::Friend) => format!("{} 👤 Friends", symbol),
                        Some(SidebarItemType::Group) => format!("{} 👥 Groups", symbol),
                        Some(SidebarItemType::Conference) => format!("{} 🧑‍🤝‍🧑 Conferences", symbol),
                        _ => format!("{} {}", symbol, item.name),
                    };
                    list_items.push(
                        ListItem::new(label).style(
                            Style::default()
                                .add_modifier(Modifier::BOLD)
                                .fg(Color::Indexed(245)),
                        ),
                    );
                }
                continue;
            }

            if let Some(cat) = current_category
                && state.is_collapsed(cat)
            {
                continue;
            }

            let status_symbol = match item.status {
                ContactStatus::Online => "●",
                ContactStatus::Away => "◑",
                ContactStatus::Busy => "●",
                ContactStatus::Offline => "○",
            };
            let status_color = match item.status {
                ContactStatus::Online => Color::Green,
                ContactStatus::Away => Color::Yellow,
                ContactStatus::Busy => Color::Red,
                ContactStatus::Offline => Color::Indexed(240),
            };

            let mut style = Style::default().fg(status_color);
            if item.unread_count > 0 {
                style = style.add_modifier(Modifier::BOLD);
            }

            if self.narrow_mode {
                let symbol = if item.is_typing { "…" } else { status_symbol };
                list_items.push(ListItem::new(symbol).style(style));
            } else {
                use ratatui::text::{Line, Span};
                let mut spans = Vec::new();
                spans.push(Span::raw("  "));

                // Icon/Status
                let icon = match item.item_type {
                    SidebarItemType::Friend => status_symbol,
                    SidebarItemType::Group => "#",
                    SidebarItemType::Conference => "&",
                    _ => status_symbol,
                };
                spans.push(Span::styled(icon, style));
                spans.push(Span::raw(" "));

                // Name
                spans.push(Span::styled(&item.name, style));

                // Typing indicator
                if item.is_typing {
                    spans.push(Span::styled(
                        " ...",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::ITALIC),
                    ));
                }

                // Unread count
                if item.unread_count > 0 {
                    spans.push(Span::styled(
                        format!(" ({})", item.unread_count),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ));
                }

                list_items.push(ListItem::new(Line::from(spans)));
            }
        }

        let list = List::new(list_items)
            .highlight_style(if self.focused {
                Style::default()
                    .bg(Color::Indexed(236)) // Subtle dark gray highlight
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            })
            .highlight_symbol(if self.narrow_mode { "" } else { "┃ " });

        StatefulWidget::render(list, inner_area, buf, &mut state.list_state);
    }
}
