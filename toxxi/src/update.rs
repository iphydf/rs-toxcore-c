use crate::commands;
use crate::completion;
use crate::config::SystemMessageType;
use crate::model::{
    ConsoleMessageType, FileTransferProgress, FriendInfo, InputMode, MessageStatus, Model, PeerId,
    PeerInfo, PendingItem, TransferStatus, WindowId,
};
use crate::msg::{AppCmd, Cmd, IOAction, IOEvent, Msg, SystemEvent, ToxAction, ToxEvent};
use crate::utils::split_message;
use crate::widgets::{InputBoxState, Outcome, QuickSwitcherItem, QuickSwitcherState};
use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyModifiers};
use std::time::Duration;
use toxcore::types::{
    GROUP_MAX_MESSAGE_LENGTH, MAX_MESSAGE_LENGTH, MessageType, ToxFileControl, ToxUserStatus,
};

fn get_text_string(input: &InputBoxState) -> String {
    input.text.clone()
}

fn set_cursor_to_end(input: &mut InputBoxState) {
    input.cursor_pos = input.text.len();
}

pub fn update(model: &mut Model, msg: Msg) -> Vec<Cmd> {
    let mut cmds = Vec::new();

    match msg {
        Msg::Input(CrosstermEvent::Key(key)) => {
            cmds.extend(handle_key_event(model, key));
        }
        Msg::Input(CrosstermEvent::Paste(text)) => {
            model.ui.input_state.insert_str(&text);
            cmds.extend(update_typing_status(model));
        }
        Msg::Tox(event) => {
            cmds.extend(handle_tox_event(model, event));
        }
        Msg::IO(event) => {
            cmds.extend(handle_io_event(model, event));
        }
        Msg::System(event) => {
            cmds.extend(handle_system_event(model, event));
        }
        _ => {}
    }

    cmds
}

fn handle_key_event(model: &mut Model, key: crossterm::event::KeyEvent) -> Vec<Cmd> {
    if model.ui.show_qr {
        model.ui.show_qr = false;
        return vec![];
    }

    if key.code == KeyCode::Esc {
        if model.ui.command_menu.is_some() {
            model.ui.command_menu = None;
        } else if model.ui.quick_switcher.is_some() {
            model.ui.quick_switcher = None;
        } else if model.ui.completion.active {
            model.ui.completion.active = false;
        } else {
            model.ui.ui_mode = match model.ui.ui_mode {
                crate::model::UiMode::Chat => crate::model::UiMode::Navigation,
                crate::model::UiMode::Navigation => crate::model::UiMode::Chat,
            };
            if model.ui.ui_mode == crate::model::UiMode::Navigation {
                let id = model.active_window_id();
                let count = model.total_messages_for(id);
                let state = model.ui.window_state.entry(id).or_default();
                if state.msg_list_state.selected_index.is_none() && count > 0 {
                    state.msg_list_state.selected_index = Some(count - 1);
                }
            }
        }
        return vec![];
    }

    if let Some(state) = &mut model.ui.quick_switcher {
        match key.code {
            KeyCode::Up => {
                state.previous();
                return vec![];
            }
            KeyCode::Down => {
                state.next();
                return vec![];
            }
            KeyCode::Enter => {
                if let Some(selected_idx) = state.list_state.selected() {
                    let filtered = state.filtered_items();
                    if let Some(item) = filtered.get(selected_idx) {
                        let target_name = &item.name;
                        let mut target_idx = None;

                        // Check System windows first
                        if target_name == "Status" {
                            target_idx = Some(0);
                        }
                        // Console is 0
                        else if target_name == "Logs"
                            && let Some(pos) = model
                                .ui
                                .window_ids
                                .iter()
                                .position(|w| *w == WindowId::Logs)
                        {
                            target_idx = Some(pos);
                        } else if target_name == "Files"
                            && let Some(pos) = model
                                .ui
                                .window_ids
                                .iter()
                                .position(|w| *w == WindowId::Files)
                        {
                            target_idx = Some(pos);
                        }

                        if target_idx.is_none() {
                            for (i, win_id) in model.ui.window_ids.iter().enumerate() {
                                let name = match win_id {
                                    WindowId::Friend(pk) => {
                                        if let Some(c) = model.domain.conversations.get(win_id) {
                                            c.name.clone()
                                        } else if let Some(f) = model.domain.friends.get(pk) {
                                            f.name.clone()
                                        } else {
                                            format!(
                                                "Friend {}",
                                                crate::utils::encode_hex(&pk.0[0..4])
                                            )
                                        }
                                    }
                                    WindowId::Group(g) => {
                                        if let Some(c) = model.domain.conversations.get(win_id) {
                                            c.name.clone()
                                        } else {
                                            format!(
                                                "Group {}",
                                                crate::utils::encode_hex(&g.0[0..4])
                                            )
                                        }
                                    }
                                    WindowId::Conference(c) => {
                                        if let Some(conv) = model.domain.conversations.get(win_id) {
                                            conv.name.clone()
                                        } else {
                                            format!(
                                                "Conference {}",
                                                crate::utils::encode_hex(&c.0[0..4])
                                            )
                                        }
                                    }
                                    _ => String::new(),
                                };
                                if &name == target_name {
                                    target_idx = Some(i);
                                    break;
                                }
                            }
                        }

                        if let Some(idx) = target_idx {
                            model.set_active_window(idx);
                        }
                    }
                }
                model.ui.quick_switcher = None;
                return vec![];
            }
            _ => {
                // Pass to input box
                state
                    .input_state
                    .handle_event(&ratatui::crossterm::event::Event::Key(key));
                // Reset selection to top on filter change
                if matches!(
                    key.code,
                    KeyCode::Char(_) | KeyCode::Backspace | KeyCode::Delete
                ) {
                    state.list_state.select(Some(0));
                }
                return vec![];
            }
        }
    }

    if let Some(state) = &mut model.ui.command_menu {
        match key.code {
            KeyCode::Up => {
                state.previous();
                return vec![];
            }
            KeyCode::Down => {
                state.next();
                return vec![];
            }
            KeyCode::Tab => {
                if let Some(completion) = state.complete() {
                    model.ui.input_state.set_value(completion);
                    set_cursor_to_end(&mut model.ui.input_state);
                    // Filter will be updated by Outcome::Changed
                }
                return vec![];
            }
            _ => {}
        }
    }

    use ratatui::crossterm::event::Event;

    let mut cmds = Vec::new();

    if model.ui.ui_mode == crate::model::UiMode::Navigation {
        let id = model.active_window_id();

        if id == WindowId::Files {
            let mut transfers: Vec<_> = model.domain.file_transfers.iter().collect();
            // Sort by friend PK for stability
            transfers.sort_by_key(|(_, p)| p.friend_pk.0);
            let count = transfers.len();
            let state = model.ui.window_state.entry(id).or_default();

            match key.code {
                KeyCode::Up => {
                    state.msg_list_state.select_previous();
                }
                KeyCode::Down => {
                    state.msg_list_state.select_next(count);
                }
                KeyCode::Char('a') => {
                    if let Some(idx) = state.msg_list_state.selected_index
                        && let Some(&(file_id, progress)) = transfers.get(idx)
                        && progress.is_receiving
                    {
                        cmds.push(Cmd::IO(IOAction::OpenFileForReceiving(
                            progress.friend_pk,
                            *file_id,
                            progress.filename.clone(),
                            progress.total_size,
                        )));
                        cmds.push(Cmd::Tox(ToxAction::FileControl(
                            progress.friend_pk,
                            *file_id,
                            toxcore::types::ToxFileControl::TOX_FILE_CONTROL_RESUME,
                        )));
                    }
                }
                KeyCode::Char('x') => {
                    if let Some(idx) = state.msg_list_state.selected_index
                        && let Some(&(file_id, progress)) = transfers.get(idx)
                    {
                        cmds.push(Cmd::Tox(ToxAction::FileControl(
                            progress.friend_pk,
                            *file_id,
                            toxcore::types::ToxFileControl::TOX_FILE_CONTROL_CANCEL,
                        )));
                    }
                }
                KeyCode::Char('p') => {
                    if let Some(idx) = state.msg_list_state.selected_index
                        && let Some(&(file_id, progress)) = transfers.get(idx)
                    {
                        let control = if progress.status == TransferStatus::Paused {
                            toxcore::types::ToxFileControl::TOX_FILE_CONTROL_RESUME
                        } else {
                            toxcore::types::ToxFileControl::TOX_FILE_CONTROL_PAUSE
                        };
                        cmds.push(Cmd::Tox(ToxAction::FileControl(
                            progress.friend_pk,
                            *file_id,
                            control,
                        )));
                    }
                }
                KeyCode::Char('o') => {
                    if let Some(idx) = state.msg_list_state.selected_index
                        && let Some(&(file_id, progress)) = transfers.get(idx)
                    {
                        // Need to resolve PK to FriendNumber for the command string
                        let mut friend_num = None;
                        for (num, p) in &model.session.friend_numbers {
                            if p == &progress.friend_pk {
                                friend_num = Some(*num);
                                break;
                            }
                        }

                        if progress.is_receiving {
                            if let Some(f) = friend_num {
                                model.ui.input_state.set_value(format!(
                                    "/file accept {} {} {}",
                                    f.0, file_id, progress.filename
                                ));
                                set_cursor_to_end(&mut model.ui.input_state);
                                model.ui.ui_mode = crate::model::UiMode::Chat;
                            } else {
                                model.add_console_message(
                                    ConsoleMessageType::Error,
                                    "Friend number not found for file transfer (needed for command)".to_owned(),
                                );
                            }
                        }
                    }
                }
                KeyCode::Enter | KeyCode::Char('i') => {
                    model.ui.ui_mode = crate::model::UiMode::Chat;
                }
                _ => {}
            }
            return cmds;
        }

        let count = model.total_messages_for(id);
        let state = model.ui.window_state.entry(id).or_default();

        match key.code {
            KeyCode::Up => {
                state.msg_list_state.select_previous();
            }
            KeyCode::Down => {
                state.msg_list_state.select_next(count);
            }
            KeyCode::Char('a') => {
                if let Some(idx) = state.msg_list_state.selected_index
                    && let Some(conv) = model.domain.conversations.get(&id)
                    && let Some(msg) = conv.messages.get(idx)
                    && let crate::model::MessageContent::FileTransfer {
                        file_id: Some(file),
                        name,
                        size,
                        is_incoming,
                        ..
                    } = &msg.content
                    && *is_incoming
                    && msg.status != MessageStatus::Received
                    && let WindowId::Friend(pk) = id
                {
                    cmds.push(Cmd::IO(IOAction::OpenFileForReceiving(
                        pk,
                        *file,
                        name.clone(),
                        *size,
                    )));
                    cmds.push(Cmd::Tox(ToxAction::FileControl(
                        pk,
                        *file,
                        toxcore::types::ToxFileControl::TOX_FILE_CONTROL_RESUME,
                    )));
                }
            }
            KeyCode::Char('x') => {
                if let Some(idx) = state.msg_list_state.selected_index
                    && let Some(conv) = model.domain.conversations.get(&id)
                    && let Some(msg) = conv.messages.get(idx)
                    && let crate::model::MessageContent::FileTransfer {
                        file_id: Some(file),
                        ..
                    } = &msg.content
                    && matches!(msg.status, MessageStatus::Incoming | MessageStatus::Pending)
                    && let WindowId::Friend(pk) = id
                {
                    cmds.push(Cmd::Tox(ToxAction::FileControl(
                        pk,
                        *file,
                        toxcore::types::ToxFileControl::TOX_FILE_CONTROL_CANCEL,
                    )));
                }
            }
            KeyCode::Char('p') => {
                if let Some(idx) = state.msg_list_state.selected_index
                    && let Some(conv) = model.domain.conversations.get(&id)
                    && let Some(msg) = conv.messages.get(idx)
                    && let crate::model::MessageContent::FileTransfer {
                        file_id: Some(file),
                        ..
                    } = &msg.content
                    && matches!(msg.status, MessageStatus::Incoming | MessageStatus::Pending)
                    && let WindowId::Friend(pk) = id
                {
                    let is_paused = model
                        .domain
                        .file_transfers
                        .get(file)
                        .map(|p| p.status == TransferStatus::Paused)
                        .unwrap_or(false);
                    let control = if is_paused {
                        toxcore::types::ToxFileControl::TOX_FILE_CONTROL_RESUME
                    } else {
                        toxcore::types::ToxFileControl::TOX_FILE_CONTROL_PAUSE
                    };
                    cmds.push(Cmd::Tox(ToxAction::FileControl(pk, *file, control)));
                }
            }
            KeyCode::Char('o') => {
                if let Some(idx) = state.msg_list_state.selected_index
                    && let Some(conv) = model.domain.conversations.get(&id)
                    && let Some(msg) = conv.messages.get(idx)
                    && let crate::model::MessageContent::FileTransfer {
                        file_id: Some(file),
                        name,
                        is_incoming,
                        ..
                    } = &msg.content
                    && *is_incoming
                    && let WindowId::Friend(pk) = id
                {
                    // Find friend number for command
                    let mut friend_num = None;
                    for (num, p) in &model.session.friend_numbers {
                        if p == &pk {
                            friend_num = Some(*num);
                            break;
                        }
                    }

                    if let Some(f) = friend_num {
                        model
                            .ui
                            .input_state
                            .set_value(format!("/file accept {} {} {}", f.0, file, name));
                        set_cursor_to_end(&mut model.ui.input_state);
                        model.ui.ui_mode = crate::model::UiMode::Chat;
                    }
                }
            }
            KeyCode::Enter | KeyCode::Char('i') => {
                model.ui.ui_mode = crate::model::UiMode::Chat;
            }
            _ => {}
        }
        return cmds;
    }

    // Intercept specific keys before TextArea
    match key.code {
        KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.ui.input_mode = match model.ui.input_mode {
                InputMode::SingleLine => InputMode::MultiLine,
                InputMode::MultiLine => InputMode::SingleLine,
            };
            return cmds;
        }
        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if model.ui.input_mode == InputMode::MultiLine {
                model.ui.completion.active = false;
                model.ui.command_menu = None;
                let input_line = get_text_string(&model.ui.input_state);
                if !input_line.is_empty() {
                    model.ui.input_state.clear();
                    model.ui.history_index = None;
                    if model.ui.input_history.last() != Some(&input_line) {
                        model.ui.input_history.push(input_line.clone());
                    }
                    cmds.extend(handle_enter(model, &input_line));
                }
                return cmds;
            }
        }
        KeyCode::Enter => {
            let send_msg = match model.ui.input_mode {
                InputMode::SingleLine => !key.modifiers.contains(KeyModifiers::ALT),
                InputMode::MultiLine => {
                    key.modifiers.contains(KeyModifiers::CONTROL)
                        || key.modifiers.contains(KeyModifiers::ALT)
                }
            };

            if !send_msg {
                model.ui.completion.active = false;
                model.ui.command_menu = None;
                model.ui.input_state.insert_char('\n');
                cmds.extend(update_typing_status(model));
                return cmds;
            } else {
                model.ui.completion.active = false;
                model.ui.command_menu = None;
                let input_line = get_text_string(&model.ui.input_state);
                if !input_line.is_empty() {
                    model.ui.input_state.clear();
                    model.ui.history_index = None;
                    if model.ui.input_history.last() != Some(&input_line) {
                        model.ui.input_history.push(input_line.clone());
                    }
                    cmds.extend(handle_enter(model, &input_line));
                }
                return cmds;
            }
        }
        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let next = (model.ui.active_window_index + 1) % model.ui.window_ids.len();
            model.set_active_window(next);
            return cmds;
        }
        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let prev = if model.ui.active_window_index > 0 {
                model.ui.active_window_index - 1
            } else {
                model.ui.window_ids.len() - 1
            };
            model.set_active_window(prev);
            return cmds;
        }
        KeyCode::BackTab | KeyCode::Char(' ')
            if key.code == KeyCode::BackTab || key.modifiers.contains(KeyModifiers::CONTROL) =>
        {
            let mut items = Vec::new();

            // System
            items.push(QuickSwitcherItem {
                name: "Status".to_owned(),
                description: "System Status & Console".to_owned(),
                prefix: ">".to_owned(),
            });
            items.push(QuickSwitcherItem {
                name: "Logs".to_owned(),
                description: "Tox Core Logs".to_owned(),
                prefix: ">".to_owned(),
            });
            items.push(QuickSwitcherItem {
                name: "Files".to_owned(),
                description: "File Manager".to_owned(),
                prefix: ">".to_owned(),
            });

            // Friends
            let mut friend_pks: Vec<_> = model.domain.friends.keys().collect();
            friend_pks.sort();
            for pk in friend_pks {
                let name =
                    if let Some(conv) = model.domain.conversations.get(&WindowId::Friend(*pk)) {
                        conv.name.clone()
                    } else if let Some(info) = model.domain.friends.get(pk) {
                        info.name.clone()
                    } else {
                        format!("Friend {}", crate::utils::encode_hex(&pk.0[0..4]))
                    };

                let status = if let Some(info) = model.domain.friends.get(pk) {
                    format!("{:?}", info.connection)
                } else {
                    "Offline".to_owned()
                };

                items.push(QuickSwitcherItem {
                    name,
                    description: status,
                    prefix: "f".to_owned(),
                });
            }

            // Groups
            let mut conv_ids: Vec<_> = model.domain.conversations.keys().collect();
            // Sort by variant and inner ID
            conv_ids.sort_by(|a, b| {
                match (a, b) {
                    (WindowId::Group(ga), WindowId::Group(gb)) => ga.0.cmp(&gb.0),
                    (WindowId::Conference(ca), WindowId::Conference(cb)) => ca.0.cmp(&cb.0),
                    // Put Groups before Conferences
                    (WindowId::Group(_), WindowId::Conference(_)) => std::cmp::Ordering::Less,
                    (WindowId::Conference(_), WindowId::Group(_)) => std::cmp::Ordering::Greater,
                    // Other types shouldn't be here based on filter below, but for completeness:
                    (a, b) => format!("{:?}", a).cmp(&format!("{:?}", b)),
                }
            });

            for id in conv_ids {
                if let Some(conv) = model.domain.conversations.get(id) {
                    if let WindowId::Group(_) = id {
                        items.push(QuickSwitcherItem {
                            name: conv.name.clone(),
                            description: conv.topic.clone().unwrap_or_default(),
                            prefix: "g".to_owned(),
                        });
                    }
                    if let WindowId::Conference(_) = id {
                        items.push(QuickSwitcherItem {
                            name: conv.name.clone(),
                            description: conv.topic.clone().unwrap_or_default(),
                            prefix: "c".to_owned(),
                        });
                    }
                }
            }

            model.ui.quick_switcher = Some(QuickSwitcherState::new(items));
            return cmds;
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if model.ui.input_state.selection.is_none() {
                model.ui.input_state.clear();
                model.ui.completion.active = false;
                model.ui.command_menu = None;
                return cmds;
            }
        }
        KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.ui.input_state.delete_word_left();
            cmds.extend(update_typing_status(model));
            return cmds;
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.ui.input_state.delete_to_start();
            cmds.extend(update_typing_status(model));
            return cmds;
        }
        KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            cmds.push(Cmd::App(AppCmd::Redraw));
            return cmds;
        }
        KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let window_id = WindowId::Files;
            if !model.ui.window_ids.contains(&window_id) {
                model.ui.window_ids.push(window_id);
            }
            if let Some(pos) = model.ui.window_ids.iter().position(|&w| w == window_id) {
                model.set_active_window(pos);
            }
            return cmds;
        }
        KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.ui.completion.active = false;
            model.ui.input_state.insert_newline();
            cmds.extend(update_typing_status(model));
            return cmds;
        }
        KeyCode::Char('b') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let id = model.active_window_id();
            if matches!(id, WindowId::Group(_) | WindowId::Conference(_)) {
                let state = model.ui.window_state.entry(id).or_default();
                state.show_peers = !state.show_peers;
            }
            return cmds;
        }
        KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::ALT) => {
            if let Some(d) = c.to_digit(10) {
                model.set_active_window(d as usize);
            }
            return cmds;
        }
        KeyCode::Tab => {
            if !model.ui.completion.active {
                let val = get_text_string(&model.ui.input_state);
                if !val.starts_with('/') {
                    let candidates = completion::complete_text(&val, model);
                    if !candidates.is_empty() {
                        model.ui.completion.active = true;
                        model.ui.completion.candidates = candidates;
                        model.ui.completion.index = 0;
                        model.ui.completion.original_input = val;
                        apply_completion(model);
                    }
                }
            } else {
                model.ui.completion.index =
                    (model.ui.completion.index + 1) % model.ui.completion.candidates.len();
                apply_completion(model);
            }
            return cmds;
        }
        KeyCode::Up => {
            if model.ui.completion.active {
                let is_emoji_grid = !model.ui.completion.candidates.is_empty()
                    && model
                        .ui
                        .completion
                        .candidates
                        .iter()
                        .all(|c| crate::emojis::is_emoji(c));

                if is_emoji_grid {
                    let cols = 10;
                    if model.ui.completion.index >= cols {
                        model.ui.completion.index -= cols;
                    }
                } else {
                    model.ui.completion.index = if model.ui.completion.index > 0 {
                        model.ui.completion.index - 1
                    } else {
                        model.ui.completion.candidates.len() - 1
                    };
                }
                apply_completion(model);
                return cmds;
            } else {
                let is_multiline = model.ui.input_mode == crate::model::InputMode::MultiLine;
                let (_cursor_x, cursor_y) = model.ui.input_state.cursor();

                if is_multiline && cursor_y > 0 {
                    model
                        .ui
                        .input_state
                        .move_cursor_up(key.modifiers.contains(KeyModifiers::SHIFT));
                    cmds.extend(update_typing_status(model));
                    return cmds;
                } else {
                    history_up(model);
                    return cmds;
                }
            }
        }
        KeyCode::Down => {
            if model.ui.completion.active {
                let is_emoji_grid = !model.ui.completion.candidates.is_empty()
                    && model
                        .ui
                        .completion
                        .candidates
                        .iter()
                        .all(|c| crate::emojis::is_emoji(c));

                if is_emoji_grid {
                    let cols = 10;
                    if model.ui.completion.index + cols < model.ui.completion.candidates.len() {
                        model.ui.completion.index += cols;
                    }
                } else {
                    model.ui.completion.index =
                        (model.ui.completion.index + 1) % model.ui.completion.candidates.len();
                }
                apply_completion(model);
                return cmds;
            } else {
                let is_multiline = model.ui.input_mode == crate::model::InputMode::MultiLine;
                let (_cursor_x, cursor_y) = model.ui.input_state.cursor();
                let line_count = model.ui.input_state.lines.len();
                let last_line_idx = line_count.saturating_sub(1);

                if is_multiline && cursor_y < last_line_idx {
                    model
                        .ui
                        .input_state
                        .move_cursor_down(key.modifiers.contains(KeyModifiers::SHIFT));
                    cmds.extend(update_typing_status(model));
                    return cmds;
                } else {
                    history_down(model);
                    return cmds;
                }
            }
        }
        KeyCode::Left if model.ui.completion.active => {
            let is_emoji_grid = !model.ui.completion.candidates.is_empty()
                && model
                    .ui
                    .completion
                    .candidates
                    .iter()
                    .all(|c| crate::emojis::is_emoji(c));
            if is_emoji_grid {
                if model.ui.completion.index > 0 {
                    model.ui.completion.index -= 1;
                    apply_completion(model);
                }
                return cmds;
            }
        }
        KeyCode::Right => {
            if model.ui.completion.active {
                let is_emoji_grid = !model.ui.completion.candidates.is_empty()
                    && model
                        .ui
                        .completion
                        .candidates
                        .iter()
                        .all(|c| crate::emojis::is_emoji(c));
                if is_emoji_grid
                    && model.ui.completion.index + 1 < model.ui.completion.candidates.len()
                {
                    model.ui.completion.index += 1;
                    apply_completion(model);
                }
                return cmds;
            } else {
                // Prevent wrapping to next line in SingleLine mode
                if model.ui.input_mode == crate::model::InputMode::SingleLine
                    && !model.ui.input_state.lines.is_empty()
                {
                    let (cursor_x, cursor_y) = model.ui.input_state.cursor();
                    let line_len = model
                        .ui
                        .input_state
                        .lines
                        .get(cursor_y)
                        .map(|l| {
                            l.graphemes
                                .last()
                                .map(|g| (g.screen_x + g.width as u16) as usize)
                                .unwrap_or(0)
                        })
                        .unwrap_or(0);
                    if cursor_x >= line_len {
                        return cmds;
                    }
                }
            }
        }
        KeyCode::PageUp => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                model.scroll_top();
            } else {
                let id = model.active_window_id();
                let height = model
                    .ui
                    .window_state
                    .get(&id)
                    .map(|s| s.last_height)
                    .unwrap_or(10);
                model.scroll_up(height);
            }
            return cmds;
        }
        KeyCode::PageDown => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                model.scroll_bottom();
            } else {
                let id = model.active_window_id();
                let height = model
                    .ui
                    .window_state
                    .get(&id)
                    .map(|s| s.last_height)
                    .unwrap_or(10);
                model.scroll_down(height);
            }
            return cmds;
        }
        KeyCode::Home if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.scroll_top();
            return cmds;
        }
        KeyCode::End if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.scroll_bottom();
            return cmds;
        }
        _ => {}
    }

    // Pass event to InputBox if not intercepted
    let event = Event::Key(key);
    let outcome = model.ui.input_state.handle_event(&event);

    if key.code != KeyCode::Enter {
        model.ui.input_blocked_indices.clear();
    }

    if matches!(outcome, Outcome::Changed) {
        if model.ui.completion.active {
            model.ui.completion.active = false;
        }

        let input = get_text_string(&model.ui.input_state);
        if input.starts_with('/') && model.ui.input_mode == InputMode::SingleLine {
            let candidates = completion::complete_command_arguments(&input, model);

            if model.ui.command_menu.is_none() {
                let widget_cmds: Vec<_> = commands::COMMANDS
                    .iter()
                    .map(|c| c.to_widget_command())
                    .collect();
                model.ui.command_menu = Some(crate::widgets::CommandMenuState::new(widget_cmds));
            }

            if let Some(state) = &mut model.ui.command_menu {
                state.set_filter(input.clone());

                // If we are at arguments stage, get dynamic candidates from Model
                if !candidates.is_empty() {
                    let dynamic_cmds = candidates
                        .into_iter()
                        .map(|(val, desc)| crate::widgets::Command::new(val, desc).dynamic(true))
                        .collect();
                    state.set_dynamic_commands(dynamic_cmds);
                } else {
                    state.set_dynamic_commands(vec![]);
                }

                if state.filtered_commands().is_empty() && !state.parent_path.is_empty() {
                    // If we have a parent path but no filtered commands, it might be arguments
                    // We keep the menu open but it might be empty or show parent info
                }
            }
        } else {
            model.ui.command_menu = None;
        }

        cmds.extend(update_typing_status(model));
    }

    cmds
}

fn apply_completion(model: &mut Model) {
    let replacement = completion::get_replacement(
        &model.ui.completion.original_input,
        &model.ui.completion.candidates[model.ui.completion.index],
    );
    model.ui.input_state.set_value(replacement);
    set_cursor_to_end(&mut model.ui.input_state);
}

fn history_up(model: &mut Model) {
    if model.ui.input_history.is_empty() {
        return;
    }
    if model.ui.history_index.is_none() {
        model.ui.saved_input_before_history = get_text_string(&model.ui.input_state);
        model.ui.history_index = Some(model.ui.input_history.len() - 1);
    } else if let Some(i) = model.ui.history_index
        && i > 0
    {
        model.ui.history_index = Some(i - 1);
    }
    if let Some(i) = model.ui.history_index {
        let val = model.ui.input_history[i].clone();
        model.ui.input_state.set_value(val);
        set_cursor_to_end(&mut model.ui.input_state);
    }
}

fn history_down(model: &mut Model) {
    if let Some(i) = model.ui.history_index {
        if i + 1 < model.ui.input_history.len() {
            let next = i + 1;
            model.ui.history_index = Some(next);
            let val = model.ui.input_history[next].clone();
            model.ui.input_state.set_value(val);
        } else {
            model.ui.history_index = None;
            model
                .ui
                .input_state
                .set_value(model.ui.saved_input_before_history.clone());
        }
        set_cursor_to_end(&mut model.ui.input_state);
    }
}

fn handle_tox_event(model: &mut Model, event: ToxEvent) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    match event {
        ToxEvent::Message(friend_number, message_type, content) => {
            if let Some(pk) = model.session.friend_numbers.get(&friend_number).cloned()
                && let Some(msg) = model.add_friend_message(pk, message_type, content)
            {
                cmds.push(Cmd::IO(IOAction::LogMessage(WindowId::Friend(pk), msg)));
            }
        }
        ToxEvent::Log(level, file, line, func, message) => {
            model.add_tox_log(level, file, line, func, message);
        }
        ToxEvent::ConnectionStatus(status) => {
            model.domain.self_connection_status = status;
            model.invalidate_sidebar_cache();
        }
        ToxEvent::FriendStatus(friend, status, pk_opt) => {
            // Update session mapping if PK is provided
            if let Some(pk) = pk_opt {
                model.session.friend_numbers.insert(friend, pk);
            }

            // Get PK from session if we didn't get it in event (fallback)
            let pk_resolved = pk_opt.or_else(|| model.session.friend_numbers.get(&friend).cloned());

            if let Some(pk) = pk_resolved {
                let info = model
                    .domain
                    .friends
                    .entry(pk)
                    .or_insert_with(|| FriendInfo {
                        name: format!("Friend {}", crate::utils::encode_hex(&pk.0[0..4])),
                        public_key: Some(pk),
                        status_message: String::new(),
                        connection: status,
                        last_sent_message_id: None,
                        last_read_receipt: None,
                        is_typing: false,
                    });
                info.connection = status;
                model.invalidate_sidebar_cache();
            }
        }
        ToxEvent::FriendName(friend, name) => {
            if let Some(pk) = model.session.friend_numbers.get(&friend) {
                if let Some(info) = model.domain.friends.get_mut(pk) {
                    info.name = name.clone();
                }
                if let Some(conv) = model.domain.conversations.get_mut(&WindowId::Friend(*pk)) {
                    conv.name = name;
                }
                model.invalidate_sidebar_cache();
            }
        }
        ToxEvent::FriendStatusMessage(friend, msg) => {
            if let Some(pk) = model.session.friend_numbers.get(&friend) {
                if let Some(info) = model.domain.friends.get_mut(pk) {
                    info.status_message = msg;
                }
                model.invalidate_sidebar_cache();
            }
        }
        ToxEvent::FriendTyping(friend, is_typing) => {
            if let Some(pk) = model.session.friend_numbers.get(&friend) {
                if let Some(info) = model.domain.friends.get_mut(pk) {
                    info.is_typing = is_typing;
                }
                model.invalidate_sidebar_cache();
            }
        }
        ToxEvent::MessageSent(friend, msg_id, internal_id) => {
            if let Some(pk) = model.session.friend_numbers.get(&friend) {
                model.mark_message_status(
                    WindowId::Friend(*pk),
                    internal_id,
                    MessageStatus::Sent(msg_id.0),
                );
            }
        }
        ToxEvent::GroupMessageSent(group, internal_id) => {
            if let Some(chat_id) = model.session.group_numbers.get(&group) {
                model.mark_message_status(
                    WindowId::Group(*chat_id),
                    internal_id,
                    MessageStatus::Received,
                );
            }
        }
        ToxEvent::ConferenceMessageSent(conference, internal_id) => {
            if let Some(conf_id) = model.session.conference_numbers.get(&conference) {
                model.mark_message_status(
                    WindowId::Conference(*conf_id),
                    internal_id,
                    MessageStatus::Received,
                );
            }
        }
        ToxEvent::MessageSendFailed(window_id, internal_id) => {
            model.mark_message_status(window_id, internal_id, MessageStatus::Pending);
        }
        ToxEvent::ReadReceipt(friend, msg_id) => {
            if let Some(pk) = model.session.friend_numbers.get(&friend)
                && let Some(conv) = model.domain.conversations.get_mut(&WindowId::Friend(*pk))
            {
                for m in conv.messages.iter_mut() {
                    if let MessageStatus::Sent(id) = m.status
                        && id <= msg_id.0
                    {
                        m.status = MessageStatus::Received;
                    }
                }
            }
        }
        ToxEvent::GroupCreated(g, chat_id, n) => {
            model.session.group_numbers.insert(g, chat_id);
            let window_id = WindowId::Group(chat_id);
            let is_new = !model.domain.conversations.contains_key(&window_id);
            model.ensure_group_window(chat_id);
            if let Some(conv) = model.domain.conversations.get_mut(&window_id)
                && let Some(name) = n
            {
                conv.name = name;
            }
            if is_new && let Some(pos) = model.ui.window_ids.iter().position(|&w| w == window_id) {
                model.set_active_window(pos);
            }
            model.invalidate_sidebar_cache();
        }
        ToxEvent::ConferenceCreated(c, cid) => {
            model.session.conference_numbers.insert(c, cid);
            let window_id = WindowId::Conference(cid);
            let is_new = !model.domain.conversations.contains_key(&window_id);
            model.ensure_conference_window(cid);
            if is_new && let Some(pos) = model.ui.window_ids.iter().position(|&w| w == window_id) {
                model.set_active_window(pos);
            }
            model.invalidate_sidebar_cache();
        }
        ToxEvent::GroupMessage(group_number, t, s, m, pk) => {
            if let Some(chat_id) = model.session.group_numbers.get(&group_number).cloned()
                && let Some(msg) = model.add_group_message(chat_id, t, s, m, pk)
            {
                cmds.push(Cmd::IO(IOAction::LogMessage(WindowId::Group(chat_id), msg)));
            }
        }
        ToxEvent::ConferenceMessage(conf_number, t, s, m, pk) => {
            if let Some(conf_id) = model.session.conference_numbers.get(&conf_number).cloned()
                && let Some(msg) = model.add_conference_message(conf_id, t, s, m, pk)
            {
                cmds.push(Cmd::IO(IOAction::LogMessage(
                    WindowId::Conference(conf_id),
                    msg,
                )));
            }
        }
        ToxEvent::FriendRequest(pk, msg) => {
            model
                .domain
                .pending_items
                .push(PendingItem::FriendRequest { pk, message: msg });
        }
        ToxEvent::GroupInvite(f, d, n) => {
            if let Some(pk) = model.session.friend_numbers.get(&f) {
                model.domain.pending_items.push(PendingItem::GroupInvite {
                    friend: *pk,
                    invite_data: d,
                    group_name: n,
                });
            }
        }
        ToxEvent::ConferenceInvite(f, t, c) => {
            if let Some(pk) = model.session.friend_numbers.get(&f) {
                model
                    .domain
                    .pending_items
                    .push(PendingItem::ConferenceInvite {
                        friend: *pk,
                        conference_type: t,
                        cookie: c,
                    });
            }
        }
        ToxEvent::GroupTopic(g, t) => {
            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                model.ensure_group_window(chat_id);
                if let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Group(chat_id))
                {
                    conv.topic = Some(t);
                }
            }
        }
        ToxEvent::GroupName(g, n) => {
            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                model.ensure_group_window(chat_id);
                if let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Group(chat_id))
                    && !n.is_empty()
                {
                    conv.name = n;
                }
                model.invalidate_sidebar_cache();
            }
        }
        ToxEvent::GroupSelfJoin(g) => {
            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                model.ensure_group_window(chat_id);
            }
        }
        ToxEvent::GroupSelfRole(g, r) => {
            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                model.ensure_group_window(chat_id);
                if let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Group(chat_id))
                {
                    conv.self_role = Some(r);
                }
            }
        }
        ToxEvent::ConferenceTitle(c, t) => {
            if let Some(cid) = model.session.conference_numbers.get(&c).cloned() {
                model.ensure_conference_window(cid);
                if let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Conference(cid))
                {
                    if !t.is_empty() {
                        conv.name = t.clone();
                    }
                    conv.topic = Some(t);
                }
                model.invalidate_sidebar_cache();
            }
        }
        ToxEvent::GroupPeerJoin(g, p, n, r, pk) => {
            if pk == model.domain.self_public_key {
                return vec![];
            }
            model.session.group_peer_numbers.insert((g, p), pk);

            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                if model
                    .config
                    .enabled_system_messages
                    .contains(&SystemMessageType::Join)
                {
                    let window_id = WindowId::Group(chat_id);
                    if let Some(msg) = model.add_system_message_to(
                        window_id,
                        ConsoleMessageType::Info,
                        crate::model::MessageContent::Text(format!("* {} joined the group", n)),
                    ) {
                        cmds.push(Cmd::IO(IOAction::LogMessage(window_id, msg)));
                    }
                }
                if let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Group(chat_id))
                {
                    let is_ignored = conv.ignored_peers.contains(&pk);
                    if let Some(peer) = conv.peers.iter_mut().find(|pinfo| pinfo.id == PeerId(pk)) {
                        peer.name = n;
                        peer.role = Some(r);
                        peer.is_ignored = is_ignored;
                        peer.seen_online = true;
                    } else {
                        conv.peers.push(PeerInfo {
                            id: PeerId(pk),
                            name: n,
                            role: Some(r),
                            status: ToxUserStatus::TOX_USER_STATUS_NONE,
                            is_ignored,
                            seen_online: true,
                        });
                    }
                }
            }
        }
        ToxEvent::GroupPeerLeave(g, p) => {
            let pk_opt = model.session.group_peer_numbers.remove(&(g, p));
            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                let mut peer_name = None;
                if let Some(conv) = model.domain.conversations.get(&WindowId::Group(chat_id))
                    && let Some(pk) = pk_opt
                    && let Some(peer) = conv.peers.iter().find(|pinfo| pinfo.id == PeerId(pk))
                {
                    peer_name = Some(peer.name.clone());
                }

                if let Some(name) = peer_name
                    && model
                        .config
                        .enabled_system_messages
                        .contains(&SystemMessageType::Leave)
                {
                    let window_id = WindowId::Group(chat_id);
                    if let Some(msg) = model.add_system_message_to(
                        window_id,
                        ConsoleMessageType::Info,
                        crate::model::MessageContent::Text(format!("* {} left the group", name)),
                    ) {
                        cmds.push(Cmd::IO(IOAction::LogMessage(window_id, msg)));
                    }
                }

                if let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Group(chat_id))
                    && let Some(pk) = pk_opt
                {
                    conv.peers.retain(|pinfo| pinfo.id != PeerId(pk));
                }
            }
        }
        ToxEvent::GroupPeerName(g, p, n, r, pk) => {
            model.session.group_peer_numbers.insert((g, p), pk);

            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                let mut old_name = None;
                if pk == model.domain.self_public_key {
                    if let Some(conv) = model
                        .domain
                        .conversations
                        .get_mut(&WindowId::Group(chat_id))
                    {
                        let current_nick =
                            conv.self_name.as_ref().unwrap_or(&model.domain.self_name);
                        if current_nick != &n {
                            old_name = Some(current_nick.clone());
                            conv.self_name = Some(n.clone());
                        }
                        conv.self_role = Some(r);
                    }
                } else if let Some(conv) = model.domain.conversations.get(&WindowId::Group(chat_id))
                    && let Some(peer) = conv.peers.iter().find(|pinfo| pinfo.id == PeerId(pk))
                    && peer.name != n
                {
                    old_name = Some(peer.name.clone());
                }

                if let Some(old) = old_name
                    && model
                        .config
                        .enabled_system_messages
                        .contains(&SystemMessageType::NickChange)
                {
                    let window_id = WindowId::Group(chat_id);
                    if let Some(msg) = model.add_system_message_to(
                        window_id,
                        ConsoleMessageType::Info,
                        crate::model::MessageContent::Text(format!(
                            "* {} is now known as {}",
                            old, n
                        )),
                    ) {
                        cmds.push(Cmd::IO(IOAction::LogMessage(window_id, msg)));
                    }
                }

                if pk != model.domain.self_public_key
                    && let Some(conv) = model
                        .domain
                        .conversations
                        .get_mut(&WindowId::Group(chat_id))
                    && let Some(peer) = conv.peers.iter_mut().find(|pinfo| pinfo.id == PeerId(pk))
                {
                    peer.name = n;
                    peer.role = Some(r);
                    peer.seen_online = true;
                }
                model.invalidate_sidebar_cache();
            }
        }
        ToxEvent::GroupPeerStatus(g, p, s) => {
            let pk_opt = model.session.group_peer_numbers.get(&(g, p)).cloned();
            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned()
                && let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Group(chat_id))
                && let Some(pk) = pk_opt
                && let Some(peer) = conv.peers.iter_mut().find(|pinfo| pinfo.id == PeerId(pk))
            {
                peer.status = s;
                peer.seen_online = true;
            }
        }
        ToxEvent::GroupModeration(g, _s, t, m) => {
            // We could log this or update role immediately, but worker usually sends peer info update too.
            // For now, let's just log it if it was a role change.
            model.add_console_message(
                ConsoleMessageType::Info,
                format!("Group {}: Moderation event {:?} on peer {}", g.0, m, t.0),
            );
        }
        ToxEvent::ConferencePeerJoin(c, _p, n, pk) => {
            if pk == model.domain.self_public_key {
                return vec![];
            }
            if let Some(cid) = model.session.conference_numbers.get(&c).cloned()
                && let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Conference(cid))
            {
                if let Some(peer) = conv.peers.iter_mut().find(|pinfo| pinfo.id == PeerId(pk)) {
                    peer.name = n;
                    peer.seen_online = true;
                } else {
                    conv.peers.push(PeerInfo {
                        id: PeerId(pk),
                        name: n,
                        role: None,
                        status: ToxUserStatus::TOX_USER_STATUS_NONE,
                        is_ignored: false,
                        seen_online: true,
                    });
                }
            }
        }
        ToxEvent::ConferencePeerLeave(c, _p, pk) => {
            if let Some(cid) = model.session.conference_numbers.get(&c).cloned()
                && let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Conference(cid))
            {
                conv.peers.retain(|pinfo| pinfo.id != PeerId(pk));
            }
        }
        ToxEvent::ConferencePeerName(c, _p, n, pk) => {
            if let Some(cid) = model.session.conference_numbers.get(&c).cloned()
                && let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Conference(cid))
                && let Some(peer) = conv.peers.iter_mut().find(|pinfo| pinfo.id == PeerId(pk))
            {
                peer.name = n;
                peer.seen_online = true;
            }
        }
        ToxEvent::FileRecv(friend, file_id, kind, size, filename) => {
            // We need PK to index friends.
            let pk_opt = model.session.friend_numbers.get(&friend).cloned();

            if kind != 0 {
                model.add_console_message(
                    ConsoleMessageType::Info,
                    format!(
                        "Ignored file transfer of kind {} from friend {}: {}",
                        kind, friend.0, filename
                    ),
                );
                if let Some(pk) = pk_opt {
                    cmds.push(Cmd::Tox(ToxAction::FileControl(
                        pk,
                        file_id,
                        ToxFileControl::TOX_FILE_CONTROL_CANCEL,
                    )));
                }
                return cmds;
            }

            model.add_console_message(
                ConsoleMessageType::Info,
                format!(
                    "File offer from friend {}: {} ({} bytes)",
                    friend.0, filename, size
                ),
            );

            if let Some(pk) = pk_opt {
                model.domain.file_transfers.insert(
                    file_id,
                    FileTransferProgress {
                        filename: filename.clone(),
                        total_size: size,
                        transferred: 0,
                        is_receiving: true,
                        status: TransferStatus::Active,
                        file_kind: kind,
                        file_path: None,
                        speed: 0.0,
                        last_update: model.time_provider.now(),
                        last_transferred: 0,
                        friend_pk: pk,
                    },
                );

                // Add inline message
                let window_id = WindowId::Friend(pk);
                if let Some(msg) =
                    model.add_file_transfer_message(window_id, false, file_id, filename, size, true)
                {
                    cmds.push(Cmd::IO(IOAction::LogMessage(window_id, msg)));
                }
            } else {
                model.add_console_message(
                    ConsoleMessageType::Error,
                    format!("Received file from friend {} but public key not found. Transfer tracking might fail.", friend.0),
                );
            }
        }
        ToxEvent::FileRecvControl(friend, file_id, control) => {
            model.add_console_message(
                ConsoleMessageType::Info,
                format!(
                    "File control from {}: ID {}, {:?}",
                    friend.0, file_id, control
                ),
            );

            let pk_opt = model.session.friend_numbers.get(&friend).cloned();

            match control {
                ToxFileControl::TOX_FILE_CONTROL_CANCEL => {
                    if let Some(pk) = pk_opt {
                        model.domain.file_transfers.remove(&file_id);
                        cmds.push(Cmd::IO(IOAction::CloseFile(pk, file_id)));
                        model.update_file_status(pk, file_id, MessageStatus::Failed);
                    }
                }
                ToxFileControl::TOX_FILE_CONTROL_PAUSE => {
                    if let Some(_pk) = pk_opt
                        && let Some(p) = model.domain.file_transfers.get_mut(&file_id)
                    {
                        p.status = TransferStatus::Paused;
                    }
                }
                ToxFileControl::TOX_FILE_CONTROL_RESUME => {
                    if let Some(_pk) = pk_opt
                        && let Some(p) = model.domain.file_transfers.get_mut(&file_id)
                    {
                        p.status = TransferStatus::Active;
                    }
                }
            }
        }
        ToxEvent::FileChunkSent(friend, file_id, position, len) => {
            let mut update = None;
            let pk_opt = model.session.friend_numbers.get(&friend).cloned();

            if let Some(pk) = pk_opt
                && let Some(p) = model.domain.file_transfers.get_mut(&file_id)
            {
                p.update_speed(model.time_provider.now(), position + len as u64);
                p.transferred = position + len as u64;
                update = Some((
                    p.transferred,
                    p.total_size,
                    crate::utils::format_speed(p.speed),
                ));
                if p.transferred >= p.total_size {
                    cmds.push(Cmd::IO(IOAction::CloseFile(pk, file_id)));
                }
            }
            if let Some((transferred, total_size, speed)) = update
                && let Some(pk) = pk_opt
            {
                model.update_file_progress(pk, file_id, transferred, total_size, speed);
            }
        }
        ToxEvent::FileChunkRequest(friend, file, position, len) => {
            if let Some(pk) = model.session.friend_numbers.get(&friend).cloned() {
                cmds.push(Cmd::IO(IOAction::ReadChunk(pk, file, position, len)));
            }
        }
        ToxEvent::Address(addr) => {
            model.domain.tox_id = addr;
        }
        _ => {}
    }
    cmds
}

fn handle_io_event(model: &mut Model, event: IOEvent) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    match event {
        IOEvent::ProfileSaved => {
            model.add_console_message(
                ConsoleMessageType::Status,
                "Profile saved successfully.".to_owned(),
            );
        }
        IOEvent::Error(e) => {
            model.add_console_message(ConsoleMessageType::Error, format!("I/O Error: {}", e));
        }
        IOEvent::FileStarted(pk, file_id, path, size) => {
            let filename = std::path::Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&path)
                .to_owned();

            model.domain.file_transfers.insert(
                file_id,
                FileTransferProgress {
                    filename: filename.clone(),
                    total_size: size,
                    transferred: 0,
                    is_receiving: false,
                    status: TransferStatus::Active,
                    file_kind: 0,
                    file_path: Some(path.clone()),
                    speed: 0.0,
                    last_update: model.time_provider.now(),
                    last_transferred: 0,
                    friend_pk: pk,
                },
            );

            // Add inline message for outgoing transfer
            let window_id = WindowId::Friend(pk);
            if let Some(msg) =
                model.add_file_transfer_message(window_id, true, file_id, filename, size, false)
            {
                cmds.push(Cmd::IO(IOAction::LogMessage(window_id, msg)));
            }

            cmds.push(Cmd::IO(IOAction::OpenFileForSending(pk, file_id, path)));
        }
        IOEvent::FileChunkRead(pk, file_id, position, len) => {
            let mut update = None;
            if let Some(p) = model.domain.file_transfers.get_mut(&file_id) {
                p.update_speed(model.time_provider.now(), position + len as u64);
                p.transferred = position + len as u64;
                update = Some((
                    p.transferred,
                    p.total_size,
                    crate::utils::format_speed(p.speed),
                ));
            }
            if let Some((transferred, total_size, speed)) = update {
                model.update_file_progress(pk, file_id, transferred, total_size, speed);
            }
        }
        IOEvent::FileChunkWritten(pk, file_id, position, len) => {
            let mut update = None;
            if let Some(p) = model.domain.file_transfers.get_mut(&file_id) {
                p.update_speed(model.time_provider.now(), position + len as u64);
                p.transferred = position + len as u64;
                update = Some((
                    p.transferred,
                    p.total_size,
                    crate::utils::format_speed(p.speed),
                ));
                if p.transferred >= p.total_size {
                    cmds.push(Cmd::IO(IOAction::CloseFile(pk, file_id)));
                }
            }
            if let Some((transferred, total_size, speed)) = update {
                model.update_file_progress(pk, file_id, transferred, total_size, speed);
            }
        }
        IOEvent::FileFinished(pk, file_id) => {
            let is_receiving = model
                .domain
                .file_transfers
                .get(&file_id)
                .map(|p| p.is_receiving)
                .unwrap_or(true);

            model.domain.file_transfers.remove(&file_id);

            let status = if is_receiving {
                MessageStatus::Received
            } else {
                // For outgoing, we don't have a specific ID here but we can mark it as Sent
                MessageStatus::Sent(0) // 0 is a placeholder
            };

            model.update_file_status(pk, file_id, status);

            model.add_console_message(
                ConsoleMessageType::Status,
                format!("File transfer finished: ID {}", file_id),
            );
        }
        IOEvent::FileError(pk, file_id, err) => {
            model.add_console_message(ConsoleMessageType::Error, format!("File error: {}", err));
            model.domain.file_transfers.remove(&file_id);
            model.update_file_status(pk, file_id, MessageStatus::Failed);
        }
        _ => {}
    }
    cmds
}

fn handle_system_event(model: &mut Model, event: SystemEvent) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    match event {
        SystemEvent::Tick => {
            if model.ui.is_typing_sent
                && let Some(last) = model.ui.last_typing_activity
                && last.elapsed() > Duration::from_secs(3)
            {
                model.ui.is_typing_sent = false;
                if let WindowId::Friend(pk) = model.active_window_id() {
                    cmds.push(Cmd::Tox(ToxAction::SetTyping(pk, false)));
                }
            }
            model.tick_count += 1;
            if model.tick_count.is_multiple_of(25) {
                // ~5 seconds
                let mut resends = Vec::new();
                for (&window_id, conv) in &model.domain.conversations {
                    for msg in &conv.messages {
                        if msg.status == MessageStatus::Pending
                            && let Some(content) = msg.content.as_text()
                        {
                            resends.push((
                                window_id,
                                msg.internal_id,
                                msg.message_type,
                                content.to_owned(),
                            ));
                        }
                    }
                }

                for (window_id, internal_id, message_type, content) in resends {
                    model.mark_message_status(window_id, internal_id, MessageStatus::Sending);
                    match window_id {
                        WindowId::Friend(pk) => {
                            cmds.push(Cmd::Tox(ToxAction::SendMessage(
                                pk,
                                message_type,
                                content,
                                internal_id,
                            )));
                        }
                        WindowId::Group(chat_id) => {
                            cmds.push(Cmd::Tox(ToxAction::SendGroupMessage(
                                chat_id,
                                message_type,
                                content,
                                internal_id,
                            )));
                        }
                        WindowId::Conference(conf_id) => {
                            cmds.push(Cmd::Tox(ToxAction::SendConferenceMessage(
                                conf_id,
                                message_type,
                                content,
                                internal_id,
                            )));
                        }
                        _ => {}
                    }
                }
            }
        }
        SystemEvent::Log {
            severity,
            context,
            message,
        } => {
            let console_type = match severity {
                crate::msg::LogSeverity::Info => ConsoleMessageType::Info,
                crate::msg::LogSeverity::Warning => ConsoleMessageType::Status,
                crate::msg::LogSeverity::Error => ConsoleMessageType::Error,
            };
            model.add_console_message(console_type, message.clone());

            if severity == crate::msg::LogSeverity::Error {
                let window_id = match context {
                    crate::msg::LogContext::Global => None,
                    crate::msg::LogContext::Friend(pk) => Some(WindowId::Friend(pk)),
                    crate::msg::LogContext::Group(chat_id) => Some(WindowId::Group(chat_id)),
                };

                if let Some(wid) = window_id
                    && let Some(msg) = model.add_system_message_to(
                        wid,
                        ConsoleMessageType::Error,
                        crate::model::MessageContent::Text(message),
                    )
                {
                    cmds.push(Cmd::IO(IOAction::LogMessage(wid, msg)));
                }
            }
        }
        _ => {}
    }
    cmds
}

pub fn handle_enter(model: &mut Model, input_line: &str) -> Vec<Cmd> {
    if input_line.starts_with('/') {
        handle_command(model, input_line)
    } else {
        let mut blocked_indices = Vec::new();
        let input_lower = input_line.to_lowercase();
        for blocked in &model.config.blocked_strings {
            let blocked_lower = blocked.to_lowercase();
            let mut start = 0;
            while let Some(idx) = input_lower[start..].find(&blocked_lower) {
                let actual_idx = start + idx;
                // Find char index for actual_idx
                let char_start = input_line[..actual_idx].chars().count();
                let char_len = blocked.chars().count();
                blocked_indices.push((char_start, char_start + char_len));
                start = actual_idx + blocked.len();
            }
        }

        if !blocked_indices.is_empty() {
            model.ui.input_state.set_value(input_line.to_owned());
            // Move cursor to end
            set_cursor_to_end(&mut model.ui.input_state);
            model.ui.input_blocked_indices = blocked_indices;
            model.add_console_message(
                ConsoleMessageType::Error,
                "Message contains blocked strings and was not sent.".to_owned(),
            );
            return vec![];
        }

        let window_id = model.active_window_id();
        if window_id == WindowId::Console || window_id == WindowId::Files {
            model.add_console_message(ConsoleMessageType::Info, format!("> {}", input_line));
            model.add_console_message(
                ConsoleMessageType::Info,
                "Unknown command. Type /help for help.".to_owned(),
            );
            vec![]
        } else {
            let limit = match window_id {
                WindowId::Group(_) => GROUP_MAX_MESSAGE_LENGTH,
                _ => MAX_MESSAGE_LENGTH,
            };

            let parts = split_message(input_line, limit);
            let mut cmds = Vec::new();

            for part in parts {
                let (internal_id, msg) = model.add_outgoing_message(
                    window_id,
                    MessageType::TOX_MESSAGE_TYPE_NORMAL,
                    part.to_string(),
                );
                cmds.push(Cmd::IO(IOAction::LogMessage(window_id, msg)));
                model.mark_message_status(window_id, internal_id, MessageStatus::Sending);
                match window_id {
                    WindowId::Friend(pk) => {
                        cmds.push(Cmd::Tox(ToxAction::SendMessage(
                            pk,
                            MessageType::TOX_MESSAGE_TYPE_NORMAL,
                            part,
                            internal_id,
                        )));
                    }
                    WindowId::Group(chat_id) => {
                        cmds.push(Cmd::Tox(ToxAction::SendGroupMessage(
                            chat_id,
                            MessageType::TOX_MESSAGE_TYPE_NORMAL,
                            part,
                            internal_id,
                        )));
                    }
                    WindowId::Conference(conf_id) => {
                        cmds.push(Cmd::Tox(ToxAction::SendConferenceMessage(
                            conf_id,
                            MessageType::TOX_MESSAGE_TYPE_NORMAL,
                            part,
                            internal_id,
                        )));
                    }
                    _ => {
                        model.add_console_message(
                            ConsoleMessageType::Error,
                            "Cannot send message: Invalid window type.".to_owned(),
                        );
                    }
                }
            }
            cmds
        }
    }
}

pub fn handle_command(model: &mut Model, cmd: &str) -> Vec<Cmd> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return vec![];
    }
    let cmd_name = parts[0].trim_start_matches('/');
    for c in commands::COMMANDS.iter() {
        if c.name == cmd_name {
            return (c.exec)(model, &parts[1..]);
        }
    }
    model.add_console_message(
        ConsoleMessageType::Error,
        format!("Unknown command: /{}", cmd_name),
    );
    vec![]
}

fn update_typing_status(model: &mut Model) -> Vec<Cmd> {
    let active_id = model.active_window_id();
    if let WindowId::Friend(pk) = active_id {
        model.ui.last_typing_activity = Some(model.time_provider.now());
        if !model.ui.is_typing_sent
            && let Some(pk) = model
                .domain
                .friends
                .get(&pk)
                .and_then(|info| info.public_key)
        {
            model.ui.is_typing_sent = true;
            return vec![Cmd::Tox(ToxAction::SetTyping(pk, true))];
        }
    }
    vec![]
}
