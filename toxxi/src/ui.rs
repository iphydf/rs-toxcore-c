use crate::model::{MessageContent, MessageStatus, Model, TransferStatus, WindowId};
use crate::widgets::info_pane::Participant;
use crate::widgets::message_list::{
    ChatMessage, MessageContent as WidgetContent, MessageStatus as WidgetStatus,
};
use crate::widgets::{
    CommandMenu, CompletionPopup, EmojiGrid, InfoPane, InputBox, MessageList, QrCodeModal,
    QuickSwitcher, Sidebar, SidebarItem, SidebarItemType, SidebarState, StatusBar, StatusWindow,
    TopicBar,
};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Clear},
};

use toxcore::tox::{ToxConnection, ToxUserStatus};
use toxcore::types::ToxLogLevel;
use unicode_width::UnicodeWidthStr;

pub fn draw(f: &mut Frame, model: &mut Model) {
    let mut show_popup = false;

    if model.ui.completion.active {
        show_popup = true;
    }

    // 1. Calculate Input Height first as it determines the bottom anchor
    let input_box = InputBox::default().focused(true).prompt("> ");
    let input_height = input_box.height(&mut model.ui.input_state, f.area().width);

    // 2. Global Vertical Split: Main Area vs Status/Input
    let main_vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),               // Content (Sidebar + Messages + Info)
            Constraint::Length(1),            // Status Bar
            Constraint::Length(input_height), // Input Box
        ])
        .split(f.area());

    // Ensure layout is calculated so we have accurate cursor position for popups
    model
        .ui
        .input_state
        .ensure_layout(main_vertical[2].width, "> ");

    // 3. Main Horizontal Split: Sidebar | Chat Area | Info Pane
    let mut constraints = vec![
        Constraint::Length(25), // Sidebar width
        Constraint::Min(1),     // Chat Area
    ];

    // Check if we need the Info Pane (Right sidebar for groups/conferences)
    let current_window_id = model.active_window_id();
    let show_info_pane = matches!(
        current_window_id,
        WindowId::Group(_) | WindowId::Conference(_)
    ) && model
        .ui
        .window_state
        .get(&current_window_id)
        .map(|s| s.show_peers)
        .unwrap_or(true);

    if show_info_pane {
        constraints.push(Constraint::Length(25)); // Info Pane width
    }

    let main_horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(main_vertical[0]);

    let sidebar_area = main_horizontal[0];
    let chat_area = main_horizontal[1];
    let info_area = if show_info_pane {
        Some(main_horizontal[2])
    } else {
        None
    };

    // 4. Chat Area Vertical Split: Topic | Messages
    let chat_vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Topic Bar
            Constraint::Min(1),    // Messages
        ])
        .split(chat_area);

    let topic_area = chat_vertical[0];
    let messages_area = chat_vertical[1];

    // --- Render Widgets ---

    // A. Sidebar
    draw_sidebar(f, sidebar_area, model);

    // B. Topic Bar
    draw_topic_bar(f, topic_area, model);

    // C. Messages / Files
    if current_window_id == WindowId::Files {
        draw_files(f, messages_area, model);
    } else {
        draw_messages(f, messages_area, model);
    }

    // D. Info Pane (if active)
    if let Some(area) = info_area {
        draw_peers(f, area, model);
    }

    // E. Popups (Overlays)
    let cursor_x = model.ui.input_state.cursor_display_pos.0;

    if show_popup {
        let is_emoji_grid = !model.ui.completion.candidates.is_empty()
            && model
                .ui
                .completion
                .candidates
                .iter()
                .all(|c| crate::emojis::is_emoji(c));

        if is_emoji_grid {
            let candidate_count = model.ui.completion.candidates.len();
            let cols = 10;
            let rows = candidate_count.div_ceil(cols);
            let popup_height = (rows as u16 + 2).min(12);
            let popup_width = (cols as u16 * 3 + 2).max(20);

            // Anchored to Input Box
            let anchor = main_vertical[2];
            let popup_area = Rect {
                x: cursor_x.min(f.area().width.saturating_sub(popup_width)),
                y: anchor.y.saturating_sub(popup_height),
                width: popup_width,
                height: popup_height,
            };
            f.render_widget(Clear, popup_area);

            let widget = EmojiGrid::new(&model.ui.completion.candidates, model.ui.completion.index);
            f.render_stateful_widget(
                widget,
                popup_area,
                &mut model.ui.completion.emoji_grid_state,
            );
        } else {
            let candidate_count = model.ui.completion.candidates.len();
            let popup_height = (candidate_count as u16 + 2).min(12);
            let max_width = model
                .ui
                .completion
                .candidates
                .iter()
                .map(|c| c.width())
                .max()
                .unwrap_or(0) as u16;
            let popup_width = (max_width + 4).max(20);

            let anchor = main_vertical[2];

            // Align with start of word
            let start_byte_idx =
                crate::completion::get_start_position(&model.ui.completion.original_input);
            let completion_start_x = model
                .ui
                .input_state
                .get_screen_x(start_byte_idx)
                .map(|x| anchor.x + 1 + x)
                .unwrap_or(cursor_x);

            let popup_area = Rect {
                x: completion_start_x.min(f.area().width.saturating_sub(popup_width)),
                y: anchor.y.saturating_sub(popup_height),
                width: popup_width,
                height: popup_height,
            };
            f.render_widget(Clear, popup_area);
            draw_completion_popup(f, popup_area, model);
        }
    }

    // F. Status Bar / Hint
    draw_status_bar(f, main_vertical[1], model);

    // G. Input Box
    let is_chat_focused = model.ui.ui_mode == crate::model::UiMode::Chat;
    let input_widget = InputBox::default().focused(is_chat_focused).prompt("> ");
    f.render_stateful_widget(input_widget, main_vertical[2], &mut model.ui.input_state);
    if is_chat_focused {
        f.set_cursor_position(model.ui.input_state.cursor_display_pos);
    }

    // H. Command Menu (Overlay)
    if let Some(state) = &mut model.ui.command_menu {
        let menu = CommandMenu::default();
        // Render above input box, spanning full width to not be confined to message window
        // and to be closer to where the user is typing (left side).
        // main_vertical[0] is content, main_vertical[1] is status bar.
        // We want to cover both so the menu sits right on top of the input box (main_vertical[2]).
        let menu_area = Rect {
            x: main_vertical[0].x,
            y: main_vertical[0].y,
            width: main_vertical[0].width,
            height: main_vertical[0].height + main_vertical[1].height,
        };
        f.render_stateful_widget(menu, menu_area, state);
    }

    // I. Quick Switcher (Modal)
    if let Some(state) = &mut model.ui.quick_switcher {
        let switcher = QuickSwitcher::default();
        f.render_stateful_widget(switcher, f.area(), state);
    }

    if model.ui.show_qr {
        draw_qr_modal(f, model);
    }
}

fn draw_qr_modal(f: &mut Frame, model: &Model) {
    let tox_id = model.domain.tox_id.to_string();
    let modal = QrCodeModal::new(tox_id);
    let (width, height) = modal.required_size();

    let area = centered_rect(width, height, f.area());
    f.render_widget(Clear, area);
    f.render_widget(modal, area);
}

fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((r.height.saturating_sub(height)) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((r.width.saturating_sub(width)) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(popup_layout[1])[1]
}

fn draw_topic_bar(f: &mut Frame, area: Rect, model: &Model) {
    let id = model.active_window_id();
    let topic_text = match id {
        WindowId::Console => format!("Tox ID: {}", model.domain.tox_id),
        WindowId::Logs => "Tox Logs".to_owned(),
        WindowId::Files => "File Manager".to_owned(),
        WindowId::Friend(pk) => {
            let mut text = if let Some(conv) = model.domain.conversations.get(&id) {
                conv.name.clone()
            } else {
                format!("Friend {}", crate::utils::encode_hex(&pk.0[0..4]))
            };

            if let Some(info) = model.domain.friends.get(&pk) {
                if info.is_typing {
                    text.push_str(" (Typing...)");
                } else if !info.status_message.is_empty() {
                    text.push_str(&format!(" - {}", info.status_message));
                }
            }
            text
        }
        _ => {
            if let Some(conv) = model.domain.conversations.get(&id) {
                if let Some(t) = &conv.topic {
                    t.clone()
                } else {
                    conv.name.clone()
                }
            } else {
                "Conversation".to_owned()
            }
        }
    };
    f.render_widget(TopicBar::new(topic_text), area);
}

fn draw_messages(f: &mut Frame, area: Rect, model: &mut Model) {
    let id = model.active_window_id();

    // Split borrow to allow mutating state while reading domain
    let ui = &mut model.ui;
    let domain = &model.domain;
    let state = ui.window_state.entry(id).or_default();

    // Ensure cache vector exists
    if state.cached_messages.is_none() {
        state.cached_messages = Some(Vec::new());
    }
    let cache = state.cached_messages.as_mut().unwrap();

    match id {
        WindowId::Console => {
            let source = &domain.console_messages;

            // Handle truncation (clear/pop)
            if cache.len() > source.len() {
                cache.truncate(source.len());
            }

            // Append new
            for msg in source.iter().skip(cache.len()) {
                let content = match &msg.content {
                    MessageContent::Text(t) => WidgetContent::Text(t.clone()),
                    MessageContent::List(items) => WidgetContent::Text(items.join("\n")),
                    MessageContent::FileTransfer { name, .. } => {
                        WidgetContent::Text(format!("[File Transfer: {}]", name))
                    }
                    MessageContent::GameInvite { game_type, .. } => {
                        WidgetContent::Text(format!("[Game Invite: {}]", game_type))
                    }
                };
                cache.push(ChatMessage {
                    sender: format!("{:?}", msg.msg_type).to_uppercase(),
                    timestamp: msg.timestamp.format("%H:%M").to_string(),
                    unix_timestamp: msg.timestamp.timestamp() as u64,
                    content,
                    status: WidgetStatus::System,
                    is_me: false,
                    highlighted: false,
                });
            }
            // Console doesn't use dirty_indices usually
        }
        WindowId::Logs => {
            // Logs are complex due to filtering/flattening.
            // For now, we rebuild if length changed to be safe, or just rebuild always if filtering changed.
            // But we can try to optimize:
            // `all_tox_logs` rebuilds the vector anyway.
            // So we can just rebuild cache from it.
            // Optimization: if filter didn't change and count increased, we could just append?
            // But `all_tox_logs` returns a fresh Vec.
            // Let's just rebuild cache for logs to avoid complexity, as they are not the main bottleneck.
            // But we should avoid re-layout if possible.

            // We need to implement `all_tox_logs` logic here because we split the borrow
            // and can't call `model.all_tox_logs()`.
            let mut all_logs: Vec<_> = domain
                .tox_logs
                .values()
                .flatten()
                .filter(|log| ui.log_filters.matches(log))
                .collect();
            all_logs.sort_by_key(|l| l.timestamp);

            if cache.len() != all_logs.len() || !state.dirty_indices.is_empty() {
                cache.clear();
                for log in all_logs {
                    let content = WidgetContent::Text(format!(
                        "{} {}:{}:{} {}",
                        match log.level {
                            ToxLogLevel::TOX_LOG_LEVEL_TRACE => "TRACE",
                            ToxLogLevel::TOX_LOG_LEVEL_DEBUG => "DEBUG",
                            ToxLogLevel::TOX_LOG_LEVEL_INFO => "INFO",
                            ToxLogLevel::TOX_LOG_LEVEL_WARNING => "WARN",
                            ToxLogLevel::TOX_LOG_LEVEL_ERROR => "ERROR",
                        },
                        log.file,
                        log.line,
                        log.func,
                        log.message
                    ));
                    cache.push(ChatMessage {
                        sender: "LOG".to_string(),
                        timestamp: log.timestamp.format("%H:%M:%S").to_string(),
                        unix_timestamp: log.timestamp.timestamp() as u64,
                        content,
                        status: WidgetStatus::System,
                        is_me: false,
                        highlighted: false,
                    });
                }
                // If we rebuilt, layout update will handle it (since processed_count > len will trigger invalidate)
            }
        }
        WindowId::Files => {
            // Handled by draw_files, this branch shouldn't be reached usually due to if/else in draw()
        }
        _ => {
            if let Some(conv) = domain.conversations.get(&id) {
                let source = &conv.messages;

                // Handle truncation
                if cache.len() > source.len() {
                    cache.truncate(source.len());
                }

                // Helper to convert a single message
                let convert = |msg: &crate::model::Message| -> ChatMessage {
                    let content = match &msg.content {
                        MessageContent::Text(t) => WidgetContent::Text(t.clone()),
                        MessageContent::List(items) => WidgetContent::Text(items.join("\n")),
                        MessageContent::FileTransfer {
                            file_id,
                            name,
                            size,
                            progress,
                            speed,
                            is_incoming,
                        } => {
                            let (paused, eta) = if let Some(fid) = file_id {
                                domain
                                    .file_transfers
                                    .get(fid)
                                    .map(|p| {
                                        let remaining = p.total_size.saturating_sub(p.transferred);
                                        let eta = if p.speed > 0.0 {
                                            crate::utils::format_duration(
                                                remaining as f64 / p.speed,
                                            )
                                        } else {
                                            String::new()
                                        };
                                        (p.status == TransferStatus::Paused, eta)
                                    })
                                    .unwrap_or((false, String::new()))
                            } else {
                                (false, String::new())
                            };
                            WidgetContent::FileTransfer {
                                name: name.clone(),
                                size: *size,
                                progress: *progress,
                                speed: speed.clone(),
                                is_incoming: *is_incoming,
                                paused,
                                eta,
                            }
                        }
                        MessageContent::GameInvite {
                            game_type,
                            challenger,
                        } => WidgetContent::GameInvite {
                            game_type: game_type.clone(),
                            challenger: challenger.clone(),
                        },
                    };

                    let status = if msg.sender == "System" {
                        WidgetStatus::System
                    } else {
                        match msg.status {
                            MessageStatus::Pending | MessageStatus::Sending => {
                                WidgetStatus::Sending
                            }
                            MessageStatus::Sent(_) | MessageStatus::Received => {
                                WidgetStatus::Delivered
                            }
                            MessageStatus::Incoming => WidgetStatus::Delivered,
                            MessageStatus::Failed => WidgetStatus::Failed,
                        }
                    };

                    ChatMessage {
                        sender: msg.sender.clone(),
                        timestamp: msg.timestamp.format("%H:%M").to_string(),
                        unix_timestamp: msg.timestamp.timestamp() as u64,
                        content,
                        status,
                        is_me: msg.is_self,
                        highlighted: msg.highlighted,
                    }
                };

                // Append new messages
                for msg in source.iter().skip(cache.len()) {
                    cache.push(convert(msg));
                }

                // Update dirty messages
                for &idx in &state.dirty_indices {
                    if idx < cache.len() && idx < source.len() {
                        let new_msg = convert(&source[idx]);
                        let scrollbar_width =
                            if state.msg_list_state.total_height > area.height as usize {
                                1
                            } else {
                                0
                            };
                        state.layout.update_message(
                            idx,
                            &new_msg,
                            area.width.saturating_sub(scrollbar_width as u16),
                        );
                        cache[idx] = new_msg;
                    }
                }
                state.dirty_indices.clear();
            }
        }
    }

    // Update layout incrementally (ChatLayout handles the logic)
    // We pass area.width. If it changed, ChatLayout invalidates.
    // If messages appended, ChatLayout processes only new ones.
    let scrollbar_width = if state.msg_list_state.total_height > area.height as usize {
        1
    } else {
        0
    };
    state
        .layout
        .update(cache, area.width.saturating_sub(scrollbar_width as u16));
    state.last_height = area.height as usize;

    let is_nav = ui.ui_mode == crate::model::UiMode::Navigation;
    let widget = MessageList::new(cache)
        .wide_mode(area.width > 50)
        .focused(is_nav)
        .layout(&state.layout);

    f.render_stateful_widget(widget, area, &mut state.msg_list_state);
}

fn draw_status_bar(f: &mut Frame, area: Rect, model: &Model) {
    let time_str = model.time_provider.now_local().format("%H:%M").to_string();
    let (conn_str, conn_style) = match model.domain.self_connection_status {
        ToxConnection::TOX_CONNECTION_NONE => {
            ("Offline", Style::default().fg(Color::White).bg(Color::Blue))
        }
        ToxConnection::TOX_CONNECTION_TCP => (
            "TCP",
            Style::default()
                .fg(Color::Green)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        ToxConnection::TOX_CONNECTION_UDP => (
            "UDP",
            Style::default()
                .fg(Color::Green)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let status_type_str = match model.domain.self_status_type {
        ToxUserStatus::TOX_USER_STATUS_NONE => "Online",
        ToxUserStatus::TOX_USER_STATUS_AWAY => "Away",
        ToxUserStatus::TOX_USER_STATUS_BUSY => "Busy",
    };

    let active_id = model.active_window_id();
    let mut self_name = if model.domain.self_name.is_empty() {
        "Anonymous".to_owned()
    } else {
        model.domain.self_name.clone()
    };

    if let WindowId::Group(g) = active_id
        && let Some(conv) = model.domain.conversations.get(&WindowId::Group(g))
        && let Some(group_nick) = &conv.self_name
    {
        self_name = format!("{} ({})", group_nick, self_name);
    }

    let mut windows = Vec::new();
    for (i, &win_id) in model.ui.window_ids.iter().enumerate() {
        let unread = model
            .ui
            .window_state
            .get(&win_id)
            .map(|s| s.unread_count)
            .unwrap_or(0);

        let name = match win_id {
            WindowId::Console => "Status".to_owned(),
            WindowId::Logs => "Logs".to_owned(),
            WindowId::Files => "Files".to_owned(),
            _ => model
                .domain
                .conversations
                .get(&win_id)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| format!("{:?}", win_id)),
        };

        windows.push(StatusWindow {
            name,
            index: i,
            unread,
            is_active: i == model.ui.active_window_index,
        });
    }

    let status_bar = StatusBar::new(
        self_name,
        status_type_str.to_string(),
        model.domain.tox_id.to_string(),
    )
    .time(time_str)
    .connection_status(conn_str.to_string(), conn_style)
    .pending_count(model.domain.pending_items.len())
    .multi_line(model.ui.input_mode == crate::model::InputMode::MultiLine)
    .windows(windows);
    // .dht_health(...) // TODO: Add DHT health history to Model

    f.render_widget(status_bar, area);
}

fn draw_peers(f: &mut Frame, area: Rect, model: &Model) {
    let id = model.active_window_id();
    if let Some(conv) = model.domain.conversations.get(&id) {
        let mut peers: Vec<_> = conv
            .peers
            .iter()
            .map(|p| {
                (
                    p.name.clone(),
                    p.role,
                    p.status,
                    p.is_ignored,
                    false,
                    p.seen_online,
                )
            })
            .collect();
        let self_name = conv
            .self_name
            .clone()
            .unwrap_or_else(|| model.domain.self_name.clone());
        peers.push((
            self_name,
            conv.self_role,
            model.domain.self_status_type,
            false,
            true,
            true,
        ));

        use toxcore::types::ToxGroupRole;

        peers.sort_by(|a, b| {
            get_role_weight(a.1)
                .cmp(&get_role_weight(b.1))
                .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
        });

        let participants: Vec<Participant> = peers
            .into_iter()
            .map(|(name, role, status, is_ignored, is_self, seen_online)| {
                use toxcore::tox::ToxUserStatus;

                let (sig, sig_color) = match role {
                    Some(ToxGroupRole::TOX_GROUP_ROLE_FOUNDER) => ("&", Color::Blue),
                    Some(ToxGroupRole::TOX_GROUP_ROLE_MODERATOR) => ("+", Color::Green),
                    Some(ToxGroupRole::TOX_GROUP_ROLE_OBSERVER) => ("-", Color::Red),
                    _ => (" ", Color::Reset),
                };

                let name_color = if seen_online {
                    match status {
                        ToxUserStatus::TOX_USER_STATUS_NONE => Color::White,
                        ToxUserStatus::TOX_USER_STATUS_AWAY => Color::Yellow,
                        ToxUserStatus::TOX_USER_STATUS_BUSY => Color::Red,
                    }
                } else {
                    Color::DarkGray
                };

                let mut name_style = if is_self {
                    Style::default().fg(name_color).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(name_color)
                };

                if is_ignored {
                    name_style = name_style
                        .fg(Color::Red)
                        .add_modifier(Modifier::CROSSED_OUT);
                }

                let mut sig_style = Style::default().fg(sig_color);
                if sig != " " {
                    sig_style = sig_style.add_modifier(Modifier::BOLD);
                }

                Participant::new(name)
                    .style(name_style)
                    .role(sig, sig_style)
            })
            .collect();

        f.render_widget(
            InfoPane::new(format!("Participants ({})", participants.len()))
                .participants(participants),
            area,
        );
    }
}

fn draw_completion_popup(f: &mut Frame, area: Rect, model: &Model) {
    let mut state = crate::widgets::CompletionPopupState::default();
    let widget = CompletionPopup::new(&model.ui.completion.candidates, model.ui.completion.index);
    f.render_stateful_widget(widget, area, &mut state);
}

fn draw_files(f: &mut Frame, area: Rect, model: &mut Model) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " File Manager ",
            Style::default().fg(Color::Cyan),
        ));
    let inner_area = block.inner(area);
    f.render_widget(block, area);

    if inner_area.width == 0 || inner_area.height == 0 {
        return;
    }

    let mut transfers: Vec<_> = model.domain.file_transfers.iter().collect();
    transfers.sort_by_key(|(file_id, _)| file_id.0);

    let item_height = 4;
    let visible_items = inner_area.height / item_height;

    let state = model.ui.window_state.entry(WindowId::Files).or_default();
    let scroll = state.msg_list_state.scroll;

    for (i, progress) in transfers.iter().skip(scroll).map(|(_, p)| p).enumerate() {
        if i >= visible_items as usize {
            break;
        }

        let y = inner_area.y + i as u16 * item_height;
        let area = Rect::new(inner_area.x, y, inner_area.width, item_height - 1);

        let remaining = progress.total_size.saturating_sub(progress.transferred);
        let eta = if progress.speed > 0.0 {
            crate::utils::format_duration(remaining as f64 / progress.speed)
        } else {
            String::new()
        };

        let card = crate::widgets::FileTransferCard::new(
            progress.filename.clone(),
            progress.total_size,
            if progress.total_size > 0 {
                progress.transferred as f64 / progress.total_size as f64
            } else {
                0.0
            },
            crate::utils::format_speed(progress.speed),
        )
        .is_incoming(progress.is_receiving)
        .paused(progress.status == TransferStatus::Paused)
        .eta(eta)
        .focused(state.msg_list_state.selected_index == Some(i + scroll));

        f.render_widget(card, area);
    }
}

fn draw_sidebar(f: &mut Frame, area: Rect, model: &mut Model) {
    if model.ui.sidebar_cache.is_none() {
        let mut items = Vec::new();

        // 1. Static Categories (System)
        items.push(SidebarItem::new("System", SidebarItemType::Category));

        // Status (Console)
        let status_unread = model
            .ui
            .window_state
            .get(&WindowId::Console)
            .map(|s| s.unread_count as u32)
            .unwrap_or(0);
        items.push(
            SidebarItem::new("Status", SidebarItemType::Friend)
                .status(match model.domain.self_connection_status {
                    ToxConnection::TOX_CONNECTION_NONE => {
                        crate::widgets::sidebar::ContactStatus::Offline
                    }
                    _ => crate::widgets::sidebar::ContactStatus::Online,
                })
                .unread(status_unread),
        );

        // Logs
        let logs_unread = model
            .ui
            .window_state
            .get(&WindowId::Logs)
            .map(|s| s.unread_count as u32)
            .unwrap_or(0);
        items.push(SidebarItem::new("Logs", SidebarItemType::Friend).unread(logs_unread));

        // Files
        let files_unread = model
            .ui
            .window_state
            .get(&WindowId::Files)
            .map(|s| s.unread_count as u32)
            .unwrap_or(0);
        items.push(SidebarItem::new("Files", SidebarItemType::Friend).unread(files_unread));

        // 2. Friends
        items.push(SidebarItem::new("Friends", SidebarItemType::Category));

        let mut friend_ids: Vec<_> = model.domain.friends.keys().collect();
        friend_ids.sort_by_key(|k| k.0);

        for pk in friend_ids {
            if let Some(friend) = model.domain.friends.get(pk) {
                let win_id = WindowId::Friend(*pk);
                let unread = model
                    .ui
                    .window_state
                    .get(&win_id)
                    .map(|s| s.unread_count as u32)
                    .unwrap_or(0);

                // FriendInfo currently doesn't store UserStatus (Away/Busy), only Connection.
                // We'll map connection to Online/Offline for now.
                let status = match friend.connection {
                    ToxConnection::TOX_CONNECTION_NONE => {
                        crate::widgets::sidebar::ContactStatus::Offline
                    }
                    _ => crate::widgets::sidebar::ContactStatus::Online,
                };

                let name = if let Some(conv) = model.domain.conversations.get(&win_id) {
                    conv.name.clone()
                } else {
                    friend.name.clone()
                };

                items.push(
                    SidebarItem::new(name, SidebarItemType::Friend)
                        .status(status)
                        .unread(unread)
                        .typing(friend.is_typing)
                        .status_message(friend.status_message.clone()),
                );
            }
        }

        // 3. Groups
        items.push(SidebarItem::new("Groups", SidebarItemType::Category));
        let mut group_ids: Vec<_> = model
            .domain
            .conversations
            .keys()
            .filter_map(|k| match k {
                WindowId::Group(g) => Some(g),
                _ => None,
            })
            .collect();
        group_ids.sort_by_key(|k| k.0);

        for gid in group_ids {
            let win_id = WindowId::Group(*gid);
            let unread = model
                .ui
                .window_state
                .get(&win_id)
                .map(|s| s.unread_count as u32)
                .unwrap_or(0);
            let name = if let Some(conv) = model.domain.conversations.get(&win_id) {
                conv.name.clone()
            } else {
                format!("Group {}", crate::utils::encode_hex(&gid.0[0..4]))
            };

            items.push(
                SidebarItem::new(name, SidebarItemType::Group)
                    .status(crate::widgets::sidebar::ContactStatus::Online) // Groups are always "online" if we are
                    .unread(unread),
            );
        }

        // 4. Conferences
        items.push(SidebarItem::new("Conferences", SidebarItemType::Category));
        let mut conf_ids: Vec<_> = model
            .domain
            .conversations
            .keys()
            .filter_map(|k| match k {
                WindowId::Conference(c) => Some(c),
                _ => None,
            })
            .collect();
        conf_ids.sort_by_key(|k| k.0);

        for cid in conf_ids {
            let win_id = WindowId::Conference(*cid);
            let unread = model
                .ui
                .window_state
                .get(&win_id)
                .map(|s| s.unread_count as u32)
                .unwrap_or(0);
            let name = if let Some(conv) = model.domain.conversations.get(&win_id) {
                conv.name.clone()
            } else {
                format!("Conference {}", crate::utils::encode_hex(&cid.0[0..4]))
            };

            items.push(
                SidebarItem::new(name, SidebarItemType::Conference)
                    .status(crate::widgets::sidebar::ContactStatus::Online)
                    .unread(unread),
            );
        }

        model.ui.sidebar_cache = Some(items);
    }

    let mut state = SidebarState::default();
    if let Some(cached) = &model.ui.sidebar_cache {
        state.items = cached.clone();
    }

    let active_id = model.active_window_id();
    let mut selected_index = None;
    let mut visual_index = 0;
    let mut current_category = None;
    let narrow_mode = false; // Default for Sidebar

    for (idx, item) in state.items.iter().enumerate() {
        if item.item_type == SidebarItemType::Category {
            current_category = Some(match item.name.as_str() {
                "Friends" => SidebarItemType::Friend,
                "Groups" => SidebarItemType::Group,
                "Conferences" => SidebarItemType::Conference,
                _ => SidebarItemType::Category,
            });

            if !narrow_mode {
                if idx > 0 {
                    visual_index += 1; // Spacer
                }
                visual_index += 1; // Header
            }
            continue;
        }

        if let Some(cat) = current_category
            && state.is_collapsed(cat)
        {
            continue;
        }

        let is_match = match active_id {
            WindowId::Console => item.name == "Status",
            WindowId::Logs => item.name == "Logs",
            WindowId::Files => item.name == "Files",
            WindowId::Friend(pk) => {
                if item.item_type != SidebarItemType::Friend {
                    false
                } else {
                    let name =
                        if let Some(conv) = model.domain.conversations.get(&WindowId::Friend(pk)) {
                            conv.name.clone()
                        } else if let Some(info) = model.domain.friends.get(&pk) {
                            info.name.clone()
                        } else {
                            format!("Friend {}", crate::utils::encode_hex(&pk.0[0..4]))
                        };
                    item.name == name
                }
            }
            WindowId::Group(g) => {
                if item.item_type != SidebarItemType::Group {
                    false
                } else {
                    let name =
                        if let Some(conv) = model.domain.conversations.get(&WindowId::Group(g)) {
                            conv.name.clone()
                        } else {
                            format!("Group {}", crate::utils::encode_hex(&g.0[0..4]))
                        };
                    item.name == name
                }
            }
            WindowId::Conference(c) => {
                if item.item_type != SidebarItemType::Conference {
                    false
                } else {
                    let name = if let Some(conv) =
                        model.domain.conversations.get(&WindowId::Conference(c))
                    {
                        conv.name.clone()
                    } else {
                        format!("Conference {}", crate::utils::encode_hex(&c.0[0..4]))
                    };
                    item.name == name
                }
            }
        };

        if is_match {
            selected_index = Some(visual_index);
            break;
        }

        visual_index += 1;
    }

    state.list_state.select(selected_index);

    let is_focused = model.ui.ui_mode == crate::model::UiMode::Navigation;
    let widget = Sidebar::default().focused(is_focused);

    f.render_stateful_widget(widget, area, &mut state);
}

fn get_role_weight(role: Option<toxcore::types::ToxGroupRole>) -> u8 {
    use toxcore::types::ToxGroupRole;
    match role {
        Some(ToxGroupRole::TOX_GROUP_ROLE_FOUNDER) => 0,
        Some(ToxGroupRole::TOX_GROUP_ROLE_MODERATOR) => 1,
        Some(ToxGroupRole::TOX_GROUP_ROLE_USER) | None => 2,
        Some(ToxGroupRole::TOX_GROUP_ROLE_OBSERVER) => 3,
    }
}
