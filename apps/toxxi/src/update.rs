use crate::commands;
use crate::completion;
use crate::model::{
    ConsoleMessageType, FileTransferProgress, FriendInfo, InputMode, InternalMessageId,
    MAX_PENDING_ITEMS, MessageStatus, Model, PeerId, PeerInfo, PendingItem, TransferStatus,
    WindowId,
};
use crate::msg::{
    AppCmd, Cmd, IOAction, IOEvent, Msg, SendFailure, SystemEvent, ToxAction, ToxEvent,
};
use crate::sync::event::{Content, EventId};
use crate::sync::files;
use crate::sync::pairing::PairingCode;
use crate::sync::protocol::BLOB_FILE_KIND;
use crate::text;
use crate::utils::split_message;
use crate::widgets::{
    EmojiPickerState, InputBoxState, Outcome, QuickSwitcherItem, QuickSwitcherState,
};
use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyModifiers, MouseEventKind};
use std::time::Duration;
use toxcore::tox::Connection;
use toxcore::types::{
    FileControl, FileId, FileKind, GROUP_MAX_MESSAGE_LENGTH, GroupJoinFail, MAX_MESSAGE_LENGTH,
    MessageType, PublicKey, UserStatus,
};

pub fn accept_file(model: &mut Model, pk: PublicKey, file_id: FileId) -> Vec<Cmd> {
    let Some(progress) = model.domain.file_transfers.get_mut(&file_id) else {
        return Vec::new();
    };
    progress.status = TransferStatus::Active;
    receive_file(pk, file_id, progress.filename.clone(), progress.total_size)
}

/// The I/O thread starts the transfer, resuming where an earlier one with this
/// file ID stopped.
fn receive_file(pk: PublicKey, file_id: FileId, filename: String, size: u64) -> Vec<Cmd> {
    vec![Cmd::IO(IOAction::OpenFileForReceiving(
        pk, file_id, filename, size,
    ))]
}

struct SelectedFile {
    pk: PublicKey,
    file_id: FileId,
    name: String,
    size: u64,
    incoming: bool,
    acceptable: bool,
    /// Whether it can still be paused or cancelled.
    open: bool,
}

/// Handles the navigation keys the Files window and chats share.
fn navigate_files(
    model: &mut Model,
    id: WindowId,
    code: KeyCode,
    count: usize,
    selected: Option<SelectedFile>,
) -> Vec<Cmd> {
    let list = &mut model.ui.window_state.entry(id).or_default().msg_list_state;
    let (file, control) = match (code, selected) {
        (KeyCode::Up, _) => {
            list.select_previous();
            return Vec::new();
        }
        (KeyCode::Down, _) => {
            list.select_next(count);
            return Vec::new();
        }
        (KeyCode::Enter | KeyCode::Char('i'), _) => {
            model.ui.ui_mode = crate::model::UiMode::Chat;
            return Vec::new();
        }
        (KeyCode::Char('x'), Some(file)) if file.open => {
            return cancel_transfer(model, file.pk, file.file_id);
        }
        (KeyCode::Char('p'), Some(file)) if file.open => {
            let is_paused = model
                .domain
                .file_transfers
                .get(&file.file_id)
                .is_some_and(|p| p.status == TransferStatus::Paused);
            let control = if is_paused {
                FileControl::Resume
            } else {
                FileControl::Pause
            };
            (file, control)
        }
        _ => return Vec::new(),
    };
    vec![Cmd::Tox(ToxAction::FileControl(
        file.pk,
        file.file_id,
        control,
    ))]
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "other mouse events do nothing"
)]
fn handle_mouse(model: &mut Model, kind: MouseEventKind) -> Vec<Cmd> {
    match kind {
        MouseEventKind::ScrollUp => {
            model.scroll_up(1);
            scrolled_up(model)
        }
        MouseEventKind::ScrollDown => {
            model.scroll_down(1);
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// On a linked profile, scrolling to the top of a chat fetches older messages
/// from the home.
fn scrolled_up(model: &mut Model) -> Vec<Cmd> {
    let id = model.active_window_id();
    match model.config.home {
        Some(home) if model.at_top(id) => crate::sync::linked::older(model, home, id),
        _ => Vec::new(),
    }
}

/// Tox only sends an event when the friend cancels, so we end our own
/// cancelled transfers here.
pub fn cancel_transfer(model: &mut Model, pk: PublicKey, file_id: FileId) -> Vec<Cmd> {
    let mut cmds = vec![Cmd::Tox(ToxAction::FileControl(
        pk,
        file_id,
        FileControl::Cancel,
    ))];
    cmds.extend(transfer_cancelled(model, pk, file_id));
    cmds
}

fn transfer_cancelled(model: &mut Model, pk: PublicKey, file_id: FileId) -> Vec<Cmd> {
    model.domain.file_transfers.remove(&file_id);
    let mut cmds = vec![Cmd::IO(IOAction::CancelFile(pk, file_id))];
    if let Some(msg) = model.update_file_status(pk, file_id, MessageStatus::Failed) {
        cmds.extend(model.record(WindowId::Friend(pk), &msg));
    }
    cmds
}

fn prefill_file_accept(model: &mut Model, file: &SelectedFile) {
    model.ui.input_state.set_value(format!(
        "/file accept {} {} {}",
        crate::utils::short_key(&file.pk),
        file.file_id,
        file.name
    ));
    set_cursor_to_end(&mut model.ui.input_state);
    model.ui.ui_mode = crate::model::UiMode::Chat;
}

/// Carries out a device's answer to the file offered by event `file`. A file
/// no longer offered ends, as if declined.
pub fn answer_file(
    model: &mut Model,
    window_id: WindowId,
    file: &EventId,
    accepted: bool,
) -> Vec<Cmd> {
    let (
        WindowId::Friend(pk),
        Some(Content::File {
            file_id: Some(file_id),
            incoming: true,
            ..
        }),
    ) = (
        window_id,
        model.events.get(file).map(|event| &event.content),
    )
    else {
        return Vec::new();
    };
    let file_id = *file_id;
    let offered = model
        .domain
        .file_transfers
        .get(&file_id)
        .is_some_and(|progress| progress.friend_pk == pk && progress.is_receiving);
    if accepted && offered {
        return accept_file(model, pk, file_id);
    }
    let mut cmds = Vec::new();
    if offered {
        model.domain.file_transfers.remove(&file_id);
        cmds.push(Cmd::Tox(ToxAction::FileControl(
            pk,
            file_id,
            FileControl::Cancel,
        )));
    }
    model.ensure_friend_window(pk);
    if let Some(msg) = model.update_file_status(pk, file_id, MessageStatus::Failed) {
        cmds.extend(model.record(window_id, &msg));
    }
    cmds
}

fn get_text_string(input: &InputBoxState) -> String {
    input.text.clone()
}

fn set_cursor_to_end(input: &mut InputBoxState) {
    input.cursor_pos = input.text.len();
}

/// Whether `msg` can change what the screen shows: Tox's logs show only in
/// the Logs window.
pub fn shows(model: &Model, msg: &Msg) -> bool {
    !matches!(msg, Msg::Tox(ToxEvent::Log { .. })) || model.active_window_id() == WindowId::Logs
}

#[cfg_attr(tokstyle, tokstyle::pure)]
pub fn update(model: &mut Model, msg: Msg) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    let tick = matches!(msg, Msg::System(SystemEvent::Tick));

    match msg {
        Msg::Input(CrosstermEvent::Key(key)) => {
            model.read_active();
            cmds.extend(handle_key_event(model, key));
        }
        Msg::Input(CrosstermEvent::Mouse(mouse)) => cmds.extend(handle_mouse(model, mouse.kind)),
        Msg::Input(CrosstermEvent::Paste(text)) => {
            model.read_active();
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
    // Only record account changes on ticks, as messages come many times a
    // second.
    if !tick {
        model.session.account_dirty = true;
    } else if model.session.account_dirty {
        cmds.extend(model.record_account());
    }

    cmds
}
fn handle_key_event(model: &mut Model, key: crossterm::event::KeyEvent) -> Vec<Cmd> {
    if model.ui.qr.take().is_some() {
        return vec![];
    }

    if key.code == KeyCode::Esc {
        if model.ui.command_menu.is_some() {
            model.ui.command_menu = None;
        } else if model.ui.quick_switcher.is_some() {
            model.ui.quick_switcher = None;
        } else if let Some(state) = &mut model.ui.emoji_picker {
            // Esc cancels hiding an emoji, else closes the picker.
            if state.confirming.take().is_none() {
                model.ui.emoji_picker = None;
            }
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
        #[expect(clippy::wildcard_enum_match_arm, reason = "other keys do nothing")]
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
                    if let Some(item) = filtered.get(selected_idx)
                        && let Some(pos) =
                            model.ui.window_ids.iter().position(|w| *w == item.window)
                    {
                        model.set_active_window(pos);
                    }
                }
                model.ui.quick_switcher = None;
                return vec![];
            }
            _ => {
                state
                    .input_state
                    .handle_event(&ratatui::crossterm::event::Event::Key(key));
                // Reset the selection when the filter changes.
                if matches!(
                    key.code,
                    KeyCode::Char(_) | KeyCode::Backspace | KeyCode::Delete
                ) {
                    state.list_state.select(Some(0));
                }
                return vec![];
            }
        };
    }

    if let Some(state) = &mut model.ui.emoji_picker {
        let hidden = &model.config.hidden_emojis;
        if let Some(emoji) = state.confirming.take() {
            #[expect(clippy::wildcard_enum_match_arm, reason = "other keys do nothing")]
            return match key.code {
                KeyCode::Backspace | KeyCode::Enter => set_emojis_hidden(model, &[&emoji], true),
                _ => vec![],
            };
        }
        #[expect(clippy::wildcard_enum_match_arm, reason = "other keys do nothing")]
        match key.code {
            KeyCode::Up => {
                state.previous(state.grid_state.cols, hidden);
                return vec![];
            }
            KeyCode::Down => {
                state.next(state.grid_state.cols, hidden);
                return vec![];
            }
            KeyCode::Left => {
                state.previous_item(hidden);
                return vec![];
            }
            KeyCode::Right => {
                state.next_item(hidden);
                return vec![];
            }
            KeyCode::Enter => {
                if let Some(emoji) = state.get_selected_emoji(hidden) {
                    model.ui.input_state.insert_str(&emoji);
                }
                model.ui.emoji_picker = None;
                return vec![];
            }
            KeyCode::Tab => {
                state.showing_hidden = !state.showing_hidden;
                state.selected_index = 0;
                return vec![];
            }
            KeyCode::Backspace if state.input_state.text.is_empty() => {
                let Some(emoji) = state.get_selected_emoji(hidden) else {
                    return vec![];
                };
                if state.showing_hidden {
                    return set_emojis_hidden(model, &[&emoji], false);
                }
                state.confirming = Some(emoji);
                return vec![];
            }
            _ => {
                state
                    .input_state
                    .handle_event(&ratatui::crossterm::event::Event::Key(key));
                if matches!(
                    key.code,
                    KeyCode::Char(_) | KeyCode::Backspace | KeyCode::Delete
                ) {
                    state.selected_index = 0;
                }
                return vec![];
            }
        };
    }

    if let Some(state) = &mut model.ui.command_menu {
        #[expect(clippy::wildcard_enum_match_arm, reason = "other keys do nothing")]
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
                    // Outcome::Changed updates the filter.
                }
                return vec![];
            }
            _ => {}
        };
    }

    use ratatui::crossterm::event::Event;

    let mut cmds = Vec::new();

    if model.ui.ui_mode == crate::model::UiMode::Navigation {
        let id = model.active_window_id();

        let selected_index = model
            .ui
            .window_state
            .entry(id)
            .or_default()
            .msg_list_state
            .selected_index;

        if id == WindowId::Files {
            let transfers = model.domain.file_transfers_listed();
            let count = transfers.len();
            let selected =
                selected_index
                    .and_then(|idx| transfers.get(idx))
                    .map(|&(file_id, progress)| SelectedFile {
                        pk: progress.friend_pk,
                        file_id: *file_id,
                        name: progress.filename.clone(),
                        size: progress.total_size,
                        incoming: progress.is_receiving,
                        acceptable: progress.is_receiving,
                        open: true,
                    });

            match (key.code, selected) {
                (KeyCode::Char('a'), Some(file)) if file.acceptable => {
                    cmds.extend(accept_file(model, file.pk, file.file_id));
                }
                (KeyCode::Char('o'), Some(file)) if file.incoming => {
                    prefill_file_accept(model, &file);
                }
                (code, selected) => cmds.extend(navigate_files(model, id, code, count, selected)),
            }
            return cmds;
        }

        let count = model.total_messages_for(id);
        let selected = selected_index
            .and_then(|idx| model.domain.conversations.get(&id)?.messages.get(idx))
            .and_then(|msg| match (id, &msg.content) {
                (
                    WindowId::Friend(pk),
                    crate::model::MessageContent::FileTransfer {
                        file_id: Some(file_id),
                        name,
                        size,
                        is_incoming,
                        ..
                    },
                ) => Some(SelectedFile {
                    pk,
                    file_id: *file_id,
                    name: name.clone(),
                    size: *size,
                    incoming: *is_incoming,
                    acceptable: *is_incoming && msg.status != MessageStatus::Received,
                    open: matches!(msg.status, MessageStatus::Incoming | MessageStatus::Pending),
                }),
                _ => None,
            });

        match (key.code, selected) {
            (KeyCode::Char('a'), Some(file)) if file.acceptable => {
                cmds.extend(receive_file(file.pk, file.file_id, file.name, file.size));
            }
            (KeyCode::Char('o'), Some(file)) if file.incoming => {
                prefill_file_accept(model, &file);
            }
            (code, selected) => cmds.extend(navigate_files(model, id, code, count, selected)),
        }
        return cmds;
    }

    #[expect(clippy::wildcard_enum_match_arm, reason = "other keys do nothing")]
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

            for (window, description) in [
                (WindowId::Console, "System Status & Console"),
                (WindowId::Logs, "Tox Core Logs"),
                (WindowId::Files, "File Manager"),
            ] {
                items.push(QuickSwitcherItem {
                    window,
                    name: model.window_name(window),
                    description: description.to_owned(),
                    prefix: ">".to_owned(),
                });
            }

            let friends = model.domain.friends.keys().map(|pk| WindowId::Friend(*pk));
            let chats = |group: bool| {
                model
                    .domain
                    .conversations
                    .keys()
                    .filter(move |id| match id {
                        WindowId::Group(_) => group,
                        WindowId::Conference(_) => !group,
                        WindowId::Console
                        | WindowId::Friend(_)
                        | WindowId::Logs
                        | WindowId::Files => false,
                    })
                    .copied()
            };
            let windows = [
                model.by_name(friends.collect()),
                model.by_name(chats(true).collect()),
                model.by_name(chats(false).collect()),
            ];
            let topic = |window| {
                model
                    .domain
                    .conversations
                    .get(&window)
                    .and_then(|conv| conv.topic.clone())
                    .unwrap_or_default()
            };
            for window in windows.into_iter().flatten() {
                let (prefix, description) = match window {
                    WindowId::Friend(pk) => {
                        ("f", format!("{:?}", model.domain.friends[&pk].connection))
                    }
                    WindowId::Group(_) => ("g", topic(window)),
                    WindowId::Console
                    | WindowId::Conference(_)
                    | WindowId::Logs
                    | WindowId::Files => ("c", topic(window)),
                };
                items.push(QuickSwitcherItem {
                    window,
                    name: model.window_name(window),
                    description,
                    prefix: prefix.to_owned(),
                });
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
        KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.ui.emoji_picker = Some(EmojiPickerState::new());
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
                // Don't wrap to the next line in single-line mode.
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
            cmds.extend(scrolled_up(model));
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
            cmds.extend(scrolled_up(model));
            return cmds;
        }
        KeyCode::End if key.modifiers.contains(KeyModifiers::CONTROL) => {
            model.scroll_bottom();
            return cmds;
        }
        _ => {}
    }

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

                if !candidates.is_empty() {
                    let dynamic_cmds = candidates
                        .into_iter()
                        .map(|(val, desc)| crate::widgets::Command::new(val, desc).dynamic(true))
                        .collect();
                    state.set_dynamic_commands(dynamic_cmds);
                } else {
                    state.set_dynamic_commands(vec![]);
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

fn pend(model: &mut Model, item: PendingItem) {
    if !model.add_pending(item) {
        model.add_console_message(
            ConsoleMessageType::Error,
            format!("Ignored a request: {MAX_PENDING_ITEMS} are waiting already"),
        );
    }
}

fn handle_tox_event(model: &mut Model, event: ToxEvent) -> Vec<Cmd> {
    if let Some(home) = model.config.home
        && !matches!(event, ToxEvent::Log { .. })
    {
        return crate::sync::linked::tox_event(model, home, event);
    }
    let mut cmds = Vec::new();
    match event {
        ToxEvent::Message(pk, message_type, bytes) => {
            if let Some(msg) = model.add_friend_message(pk, message_type, text::of(&bytes)) {
                cmds.extend(model.record_received(WindowId::Friend(pk), &msg, bytes));
            }
        }
        ToxEvent::Log {
            level,
            file,
            line,
            func,
            message,
        } => {
            model.add_tox_log(level, file, line, func, message);
        }
        ToxEvent::ConnectionStatus(status) => {
            model.domain.self_connection_status = status;
            model.invalidate_sidebar_cache();
        }
        ToxEvent::FriendStatus(pk, status) => {
            let was_offline = model
                .domain
                .friends
                .get(&pk)
                .is_none_or(|info| info.connection == Connection::None);
            let info = model
                .domain
                .friends
                .entry(pk)
                .or_insert_with(|| FriendInfo::new(pk, status));
            info.connection = status;
            model.domain.pending_items.retain(
                |item| !matches!(item, PendingItem::FriendRequest { pk: from, .. } if *from == pk),
            );
            model.invalidate_sidebar_cache();
            cmds.extend(crate::sync::friend_status(model, pk, status));
            if was_offline && status != Connection::None {
                cmds.extend(send_undelivered(model, pk));
            }
        }
        ToxEvent::ChatMade(intent, chat) => {
            cmds.extend(model.record_in_account(vec![Content::ChatJoined { intent, chat }]));
        }
        ToxEvent::InviteJoined(invite, chat) => {
            cmds.extend(crate::sync::invites::joined(model, invite, chat));
        }
        ToxEvent::GroupJoinFail(group, fail) => {
            if let Some(chat_id) = model.session.group_numbers.get(&group).copied() {
                model.add_console_message(
                    ConsoleMessageType::Error,
                    format!("Couldn't join group {}: {:?}", chat_id, fail),
                );
                cmds.extend(crate::sync::invites::refused(
                    model,
                    chat_id,
                    fail == GroupJoinFail::InvalidPassword,
                ));
            }
        }
        ToxEvent::CallRinging { friend, video } => {
            cmds.extend(crate::sync::calls::ringing(model, friend, video));
        }
        ToxEvent::CallConnected(pk) => {
            cmds.extend(crate::sync::calls::connected(model, pk));
        }
        ToxEvent::CallEnded(pk) => {
            cmds.extend(crate::sync::calls::ended(model, pk));
        }
        ToxEvent::SyncMessage(pk, message) => {
            cmds.extend(crate::sync::received(model, pk, &message));
        }
        ToxEvent::FriendName(pk, name) => {
            if let Some(info) = model.domain.friends.get_mut(&pk) {
                info.name = name.clone();
            }
            if let Some(conv) = model.domain.conversations.get_mut(&WindowId::Friend(pk)) {
                conv.name = name.clone();
            }
            model.invalidate_sidebar_cache();
            // Devices are named as they name themselves.
            if model
                .account
                .devices
                .get(&pk)
                .is_some_and(|known| *known != name)
            {
                cmds.extend(model.record_in_account(vec![Content::Device { pk, name }]));
            }
        }
        ToxEvent::FriendStatusMessage(pk, msg) => {
            if let Some(info) = model.domain.friends.get_mut(&pk) {
                info.status_message = msg;
            }
            model.invalidate_sidebar_cache();
        }
        ToxEvent::FriendUserStatus(pk, status) => {
            model.session.friend_statuses.insert(pk, status);
        }
        ToxEvent::FriendTyping(pk, is_typing) => {
            if let Some(info) = model.domain.friends.get_mut(&pk) {
                info.is_typing = is_typing;
            }
            model.invalidate_sidebar_cache();
        }
        ToxEvent::MessageSent(pk, msg_id, internal_id) => {
            if let Some(msg) = model.mark_message_status(
                WindowId::Friend(pk),
                internal_id,
                MessageStatus::Sent(Some(msg_id)),
            ) {
                cmds.extend(model.record(WindowId::Friend(pk), &msg));
            }
        }
        ToxEvent::GroupMessageSent(group, internal_id) => {
            if let Some(chat_id) = model.session.group_numbers.get(&group).copied()
                && let Some(msg) = model.mark_message_status(
                    WindowId::Group(chat_id),
                    internal_id,
                    MessageStatus::Received,
                )
            {
                cmds.extend(model.record(WindowId::Group(chat_id), &msg));
            }
        }
        ToxEvent::ConferenceMessageSent(conference, internal_id) => {
            if let Some(conf_id) = model.session.conference_numbers.get(&conference).copied()
                && let Some(msg) = model.mark_message_status(
                    WindowId::Conference(conf_id),
                    internal_id,
                    MessageStatus::Received,
                )
            {
                cmds.extend(model.record(WindowId::Conference(conf_id), &msg));
            }
        }
        ToxEvent::MessageSendFailed(window_id, internal_id, failure) => {
            let status = match failure {
                SendFailure::Later => MessageStatus::Pending,
                SendFailure::Never => MessageStatus::Failed,
            };
            if let Some(msg) = model.mark_message_status(window_id, internal_id, status) {
                cmds.extend(model.record(window_id, &msg));
            }
        }
        ToxEvent::ReadReceipt(pk, msg_id) => {
            if let Some(conv) = model.domain.conversations.get_mut(&WindowId::Friend(pk)) {
                let mut delivered = Vec::new();
                for m in conv.messages.iter_mut() {
                    if m.status == MessageStatus::Sent(Some(msg_id)) {
                        m.status = MessageStatus::Received;
                        delivered.push(m.clone());
                    }
                }
                for m in delivered {
                    cmds.extend(model.record(WindowId::Friend(pk), &m));
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
        ToxEvent::GroupMessage(group_number, peer, t, m, pk) => {
            if let Some(chat_id) = model.session.group_numbers.get(&group_number).cloned() {
                let s = sender_name(model, WindowId::Group(chat_id), pk, peer.0);
                if let Some(msg) = model.add_group_message(chat_id, t, s, text::of(&m), pk) {
                    cmds.extend(model.record_received(WindowId::Group(chat_id), &msg, m));
                }
            }
        }
        ToxEvent::GroupPrivateMessage(group_number, peer, t, m, pk) => {
            if let Some(chat_id) = model.session.group_numbers.get(&group_number).cloned() {
                let s = sender_name(model, WindowId::Group(chat_id), Some(pk), peer.0);
                if let Some(msg) = model.add_private_group_message(chat_id, t, s, text::of(&m), pk)
                {
                    cmds.extend(model.record_received(WindowId::Group(chat_id), &msg, m));
                }
            }
        }
        ToxEvent::ConferenceMessage(conf_number, peer, t, m, pk) => {
            if let Some(conf_id) = model.session.conference_numbers.get(&conf_number).cloned() {
                let s = sender_name(model, WindowId::Conference(conf_id), pk, peer.0);
                if let Some(msg) = model.add_conference_message(conf_id, t, s, text::of(&m), pk) {
                    cmds.extend(model.record_received(WindowId::Conference(conf_id), &msg, m));
                }
            }
        }
        ToxEvent::FriendRequest(pk, msg) => {
            let now = model.time_provider.now();
            if let Some(code) = PairingCode::from_request(&msg)
                && model.session.pairing.redeem(code, now)
            {
                model.add_status_message(crate::model::MessageContent::Text(format!(
                    "Paired a new device: {}",
                    pk
                )));
                cmds.push(Cmd::Tox(ToxAction::AcceptFriend(pk)));
                cmds.extend(crate::sync::set_device(model, pk, true));
            } else {
                pend(model, PendingItem::FriendRequest { pk, message: msg });
            }
        }
        ToxEvent::GroupInvite {
            friend: pk,
            invite: d,
            name: n,
        } => {
            model.add_console_message(
                ConsoleMessageType::Info,
                format!(
                    "Received group invite for '{}' from {}",
                    n,
                    model.friend_name(&pk)
                ),
            );
            pend(
                model,
                PendingItem::GroupInvite {
                    friend: pk,
                    invite_data: d,
                    group_name: n,
                },
            );
        }
        ToxEvent::ConferenceInvite {
            friend: pk,
            kind: t,
            cookie: c,
        } => {
            pend(
                model,
                PendingItem::ConferenceInvite {
                    friend: pk,
                    conference_type: t,
                    cookie: c,
                },
            );
        }
        ToxEvent::GroupTopic(g, t, setter) => {
            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                model.ensure_group_window(chat_id);
                let window_id = WindowId::Group(chat_id);

                let mut changed = false;
                if let Some(conv) = model.domain.conversations.get_mut(&window_id)
                    && conv.topic.as_ref() != Some(&t)
                {
                    conv.topic = Some(t.clone());
                    changed = true;
                }

                if changed {
                    let name = setter
                        .and_then(|pk| model.member_name(window_id, pk))
                        .unwrap_or_default();
                    cmds.extend(model.add_notice(
                        window_id,
                        Content::TopicSet {
                            by: setter,
                            name,
                            topic: t,
                        },
                    ));
                }
            }
        }
        ToxEvent::GroupName(g, n) => {
            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                model.ensure_group_window(chat_id);
                let window_id = WindowId::Group(chat_id);

                // The first name isn't a rename.
                let mut renamed = false;
                if let Some(conv) = model.domain.conversations.get_mut(&window_id)
                    && !n.is_empty()
                    && conv.name != n
                {
                    renamed = !conv.name.is_empty();
                    conv.name = n.clone();
                }

                if renamed {
                    cmds.extend(model.add_notice(
                        window_id,
                        Content::TitleSet {
                            by: None,
                            name: String::new(),
                            title: n,
                        },
                    ));
                }
                model.invalidate_sidebar_cache();
            }
        }
        ToxEvent::GroupSelfJoin(g) => {
            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                model.ensure_group_window(chat_id);
            }
        }
        ToxEvent::GroupSettings(g, settings) => {
            if let Some(chat_id) = model.session.group_numbers.get(&g) {
                model.session.group_settings.insert(*chat_id, settings);
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
        ToxEvent::ConferenceTitle(c, t, setter) => {
            if let Some(cid) = model.session.conference_numbers.get(&c).cloned() {
                model.ensure_conference_window(cid);
                let window_id = WindowId::Conference(cid);

                // A conference's title is its name. It's empty while the
                // conference reconnects. The first title isn't a rename unless
                // someone set it.
                let mut renamed = false;
                if let Some(conv) = model.domain.conversations.get_mut(&window_id)
                    && !t.is_empty()
                    && conv.name != t
                {
                    renamed = setter.is_some() || !conv.name.is_empty();
                    conv.name = t.clone();
                }

                if renamed {
                    let name = setter
                        .and_then(|pk| model.member_name(window_id, pk))
                        .unwrap_or_default();
                    cmds.extend(model.add_notice(
                        window_id,
                        Content::TitleSet {
                            by: setter,
                            name,
                            title: t,
                        },
                    ));
                }
                model.invalidate_sidebar_cache();
            }
        }
        ToxEvent::GroupPeerJoin(g, p, n, r, pk) => {
            if pk == model.domain.self_public_key() {
                return vec![];
            }
            model.session.group_peer_numbers.insert((g, p), pk);

            if let Some(chat_id) = model.session.group_numbers.get(&g).cloned() {
                let window_id = WindowId::Group(chat_id);
                // Tox reports everyone already in a group as joining when we
                // join, so only peers we don't know yet count as joining.
                let mut joined = false;
                if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
                    let is_ignored = conv.ignored_peers.contains(&pk);
                    if let Some(peer) = conv.peers.iter_mut().find(|pinfo| pinfo.id == PeerId(pk)) {
                        peer.name = n.clone();
                        peer.role = Some(r);
                        peer.is_ignored = is_ignored;
                        peer.seen_online = true;
                    } else {
                        conv.peers.push(PeerInfo {
                            id: PeerId(pk),
                            name: n.clone(),
                            role: Some(r),
                            status: UserStatus::None,
                            is_ignored,
                            seen_online: true,
                        });
                        joined = true;
                    }
                }
                if joined {
                    cmds.extend(
                        model.add_notice(window_id, Content::PeerJoined { peer: pk, name: n }),
                    );
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
                    peer_name = Some((pk, peer.name.clone()));
                }

                if let Some((peer, name)) = peer_name {
                    cmds.extend(
                        model
                            .add_notice(WindowId::Group(chat_id), Content::PeerLeft { peer, name }),
                    );
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
                if pk == model.domain.self_public_key() {
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
                } else if let Some(conv) = model
                    .domain
                    .conversations
                    .get_mut(&WindowId::Group(chat_id))
                    && let Some(peer) = conv.peers.iter_mut().find(|pinfo| pinfo.id == PeerId(pk))
                {
                    if peer.name != n {
                        old_name = Some(peer.name.clone());
                        peer.name = n.clone();
                    }
                    peer.role = Some(r);
                    peer.seen_online = true;
                }

                if let Some(old) = old_name {
                    cmds.extend(model.add_notice(
                        WindowId::Group(chat_id),
                        Content::PeerRenamed {
                            peer: pk,
                            old,
                            name: n.clone(),
                        },
                    ));
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
        ToxEvent::GroupModeration {
            group,
            target,
            event,
            ..
        } => {
            model.add_console_message(
                ConsoleMessageType::Info,
                format!(
                    "Group {}: Moderation event {:?} on peer {}",
                    group.0, event, target.0
                ),
            );
        }
        ToxEvent::ConferencePeerJoin(c, _p, n, pk) => {
            if pk == model.domain.self_public_key() {
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
                        status: UserStatus::None,
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
        ToxEvent::FileRecv(pk, file_id, kind, size, filename) => {
            if kind == BLOB_FILE_KIND {
                return files::offered(model, pk, file_id, size);
            }
            if kind == crate::sync::avatars::FILE_KIND {
                return crate::sync::avatars::offered(model, pk, file_id, size);
            }

            let from = model.friend_name(&pk);
            if kind != FileKind::DATA {
                model.add_console_message(
                    ConsoleMessageType::Info,
                    format!(
                        "Ignored file transfer of kind {} from {}: {}",
                        kind.0, from, filename
                    ),
                );
                cmds.push(Cmd::Tox(ToxAction::FileControl(
                    pk,
                    file_id,
                    FileControl::Cancel,
                )));
                return cmds;
            }

            model.add_console_message(
                ConsoleMessageType::Info,
                format!("File offer from {}: {} ({} bytes)", from, filename, size),
            );
            model.domain.file_transfers.insert(
                file_id,
                FileTransferProgress {
                    filename: filename.clone(),
                    total_size: size,
                    transferred: 0,
                    is_receiving: true,
                    status: TransferStatus::Active,
                    speed: 0.0,
                    last_update: model.time_provider.now(),
                    last_transferred: 0,
                    friend_pk: pk,
                },
            );

            let window_id = WindowId::Friend(pk);
            model.ensure_friend_window(pk);
            if let Some(msg) =
                model.add_file_transfer_message(window_id, false, file_id, filename, size, true)
            {
                cmds.extend(model.record(window_id, &msg));
            }
        }
        ToxEvent::FileRecvControl(pk, file_id, control) => {
            model.add_console_message(
                ConsoleMessageType::Info,
                format!(
                    "File control from {}: ID {}, {:?}",
                    model.friend_name(&pk),
                    file_id,
                    control
                ),
            );

            if control == FileControl::Cancel
                && let Some(stopped) = files::stopped(model, pk, file_id)
            {
                return stopped;
            }

            match control {
                FileControl::Cancel => cmds.extend(transfer_cancelled(model, pk, file_id)),
                FileControl::Pause => {
                    if let Some(p) = model.domain.file_transfers.get_mut(&file_id) {
                        p.status = TransferStatus::Paused;
                    }
                }
                FileControl::Resume => {
                    if let Some(p) = model.domain.file_transfers.get_mut(&file_id) {
                        p.status = TransferStatus::Active;
                    }
                }
            }
        }
        ToxEvent::FileChunkSent(pk, file_id, position, len) => {
            let mut update = None;
            if let Some(progressed) = files::progressed(model, pk, file_id, position + len as u64) {
                return progressed;
            }

            if let Some(p) = model.domain.file_transfers.get_mut(&file_id) {
                p.update_speed(model.time_provider.now(), position + len as u64);
                p.transferred = position + len as u64;
                update = Some((
                    p.transferred,
                    p.total_size,
                    crate::utils::format_speed(p.speed),
                ));
                if p.transferred >= p.total_size {
                    model.session.finishing.insert(file_id);
                    cmds.push(Cmd::IO(IOAction::FinishFile(pk, file_id)));
                }
            }
            if let Some((transferred, total_size, speed)) = update {
                model.update_file_progress(pk, file_id, transferred, total_size, speed);
            }
        }
        // Tox asks for 0 bytes at position 0 only for an empty file.
        ToxEvent::FileChunkRequest(friend, file, 0, 0) => {
            cmds.extend(handle_tox_event(
                model,
                ToxEvent::FileChunkSent(friend, file, 0, 0),
            ));
        }
        ToxEvent::FileChunkRequest(pk, file, position, len) if len > 0 => {
            cmds.push(Cmd::IO(IOAction::ReadChunk(pk, file, position, len)));
        }
        ToxEvent::Started => {
            // A new Tox numbers messages from 0 again, so receipts for earlier
            // messages never come.
            for conv in model.domain.conversations.values_mut() {
                for m in &mut conv.messages {
                    if let MessageStatus::Sent(_) = m.status {
                        m.status = MessageStatus::Sent(None);
                    }
                }
            }
            cmds.extend(crate::sync::started(model));
        }
        ToxEvent::Address(addr) => {
            model.domain.tox_id = addr;
        }
        ToxEvent::DhtId(_) | ToxEvent::FileChunkRequest(..) => {}
    }
    cmds
}

fn handle_io_event(model: &mut Model, event: IOEvent) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    match event {
        IOEvent::Error(e) => {
            model.add_console_message(ConsoleMessageType::Error, format!("I/O Error: {}", e));
        }
        IOEvent::FileStarted(pk, file_id, path, size) => {
            if let Some(started) = files::started(model, pk, file_id, path.clone(), size) {
                return started;
            }
            if crate::sync::avatars::is_none_file(&file_id, size) {
                return cmds;
            }
            let filename = path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
                .into_owned();

            model.domain.file_transfers.insert(
                file_id,
                FileTransferProgress {
                    filename: filename.clone(),
                    total_size: size,
                    transferred: 0,
                    is_receiving: false,
                    status: TransferStatus::Active,
                    speed: 0.0,
                    last_update: model.time_provider.now(),
                    last_transferred: 0,
                    friend_pk: pk,
                },
            );

            // Add a message for an outgoing file, unless a device's message
            // already shows it. A file sent again after it ended (e.g. resumed)
            // gets a new message.
            let window_id = WindowId::Friend(pk);
            if model.file_message(pk, file_id).is_none_or(|msg| {
                matches!(
                    msg.status,
                    MessageStatus::Failed | MessageStatus::Sent(_) | MessageStatus::Received
                )
            }) && let Some(msg) =
                model.add_file_transfer_message(window_id, true, file_id, filename, size, false)
            {
                cmds.extend(model.record(window_id, &msg));
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
            if let Some(progressed) = files::progressed(model, pk, file_id, position + len as u64) {
                return progressed;
            }
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
                    model.session.finishing.insert(file_id);
                    cmds.push(Cmd::IO(IOAction::FinishFile(pk, file_id)));
                }
            }
            if let Some((transferred, total_size, speed)) = update {
                model.update_file_progress(pk, file_id, transferred, total_size, speed);
            }
        }
        IOEvent::FileFinished(pk, file_id, blob) => {
            model.session.finishing.remove(&file_id);
            if let Some(blob) = blob {
                model.blobs.insert(blob);
                if let Some(crate::model::MessageContent::FileTransfer { blob: held, .. }) =
                    model.file_message(pk, file_id).map(|msg| &mut msg.content)
                {
                    *held = Some(blob);
                }
            }
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
                MessageStatus::Sent(None)
            };

            if let Some(msg) = model.update_file_status(pk, file_id, status) {
                cmds.extend(model.record(WindowId::Friend(pk), &msg));
            }

            model.add_console_message(
                ConsoleMessageType::Status,
                format!("File transfer finished: ID {}", file_id),
            );
        }
        IOEvent::FileError(pk, file_id, err) => {
            model.add_console_message(ConsoleMessageType::Error, format!("File error: {}", err));
            if let Some(stopped) = files::stopped(model, pk, file_id) {
                return stopped;
            }
            model.domain.file_transfers.remove(&file_id);
            if let Some(msg) = model.update_file_status(pk, file_id, MessageStatus::Failed) {
                cmds.extend(model.record(WindowId::Friend(pk), &msg));
            }
        }
        IOEvent::BlobMissing(pk, blob) => cmds.extend(files::missing(model, pk, blob)),
        IOEvent::BlobStored(pk, blob, ok) => cmds.extend(files::stored(model, pk, blob, ok)),
    }
    cmds
}

fn handle_system_event(model: &mut Model, event: SystemEvent) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    match event {
        SystemEvent::Tick => {
            let paused = model.ui.last_typing_activity.is_none_or(|last| {
                model.time_provider.now().duration_since(last) > Duration::from_secs(3)
            });
            if let Some(pk) = model.ui.typing_to
                && (paused || model.active_window_id() != WindowId::Friend(pk))
            {
                cmds.extend(stop_typing(model));
            }
            model.tick_count += 1;
            if model.tick_count.is_multiple_of(25) {
                // Every 5 seconds.
                let mut resends = Vec::new();
                for (&window_id, conv) in &model.domain.conversations {
                    for msg in &conv.messages {
                        if msg.status == MessageStatus::Pending
                            && let Some(bytes) = model.tox_bytes(window_id, msg)
                        {
                            resends.push((window_id, msg.internal_id, msg.message_type, bytes));
                        }
                    }
                }

                for (window_id, internal_id, message_type, content) in resends {
                    cmds.extend(send_pending(
                        model,
                        window_id,
                        internal_id,
                        message_type,
                        content,
                    ));
                }
                cmds.extend(files::send_pending(model));
            }
        }
        SystemEvent::Quit => cmds.push(Cmd::App(AppCmd::Quit)),
        SystemEvent::Show(window) => {
            if let Some(pos) = model.ui.window_ids.iter().position(|w| *w == window) {
                model.ui.quick_switcher = None;
                model.set_active_window(pos);
            }
        }
        SystemEvent::Save => cmds.extend([Cmd::Tox(ToxAction::Save), Cmd::App(AppCmd::SaveState)]),
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
                    cmds.extend(model.record(wid, &msg));
                }
            }
        }
    }
    cmds
}

pub fn handle_enter(model: &mut Model, input_line: &str) -> Vec<Cmd> {
    // Handle /me here, not as a command, so its text keeps its spaces.
    if let Some(action) = input_line.strip_prefix("/me ") {
        send_line(model, "/me ", action, MessageType::Action)
    } else if input_line.starts_with('/') {
        handle_command(model, input_line)
    } else {
        send_line(model, "", input_line, MessageType::Normal)
    }
}

/// Sends a line typed in the active window, split into parts Tox takes.
/// A line with blocked strings goes back in the input, after `prefix`.
pub fn send_line(
    model: &mut Model,
    prefix: &str,
    input_line: &str,
    message_type: MessageType,
) -> Vec<Cmd> {
    if refuse_blocked(model, prefix, input_line) {
        return vec![];
    }

    let window_id = model.active_window_id();
    if !matches!(
        window_id,
        WindowId::Friend(_) | WindowId::Group(_) | WindowId::Conference(_)
    ) {
        model.add_console_message(ConsoleMessageType::Info, format!("> {}", input_line));
        model.add_console_message(
            ConsoleMessageType::Info,
            "Unknown command. Type /help for help.".to_owned(),
        );
        return vec![];
    }
    let mut cmds = Vec::new();
    for part in split_message(input_line, message_limit(window_id)) {
        let (internal_id, msg) = model.add_outgoing_message(window_id, message_type, part.clone());
        cmds.extend(model.record(window_id, &msg));
        cmds.extend(send_pending(
            model,
            window_id,
            internal_id,
            message_type,
            part.into_bytes(),
        ));
    }
    cmds
}

/// Returns true if `text` has blocked strings, and puts it back in the input
/// after `prefix`, with them marked.
pub fn refuse_blocked(model: &mut Model, prefix: &str, text: &str) -> bool {
    let shift = prefix.chars().count();
    let blocked_indices: Vec<_> = model
        .config
        .blocked_strings
        .iter()
        .flat_map(|blocked| find_ignoring_case(text, blocked))
        .map(|(start, end)| (shift + start, shift + end))
        .collect();
    if blocked_indices.is_empty() {
        return false;
    }
    model.ui.input_state.set_value(format!("{prefix}{text}"));
    set_cursor_to_end(&mut model.ui.input_state);
    model.ui.input_blocked_indices = blocked_indices;
    model.add_console_message(
        ConsoleMessageType::Error,
        "Message contains blocked strings and was not sent.".to_owned(),
    );
    true
}

/// Returns the character ranges (not byte ranges) where `pattern` is in
/// `text`, ignoring case. They don't overlap.
fn find_ignoring_case(text: &str, pattern: &str) -> Vec<(usize, usize)> {
    let pattern: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let text: Vec<char> = text.chars().collect();
    // The number of characters from `start` that match the pattern.
    let match_at = |start: usize| {
        let mut want = pattern.iter();
        for (n, c) in text[start..].iter().enumerate() {
            for lower in c.to_lowercase() {
                if want.next() != Some(&lower) {
                    return None;
                }
            }
            if want.len() == 0 {
                return Some(n + 1);
            }
        }
        None
    };
    let mut found = Vec::new();
    let mut start = 0;
    while start < text.len() {
        match match_at(start) {
            Some(len) => {
                found.push((start, start + len));
                start += len;
            }
            None => start += 1,
        }
    }
    found
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
    let WindowId::Friend(pk) = model.active_window_id() else {
        return vec![];
    };
    model.ui.last_typing_activity = Some(model.time_provider.now());
    if model.ui.typing_to == Some(pk) || !model.domain.friends.contains_key(&pk) {
        return vec![];
    }
    let mut cmds = stop_typing(model);
    model.ui.typing_to = Some(pk);
    cmds.push(Cmd::Tox(ToxAction::SetTyping(pk, true)));
    cmds
}

fn stop_typing(model: &mut Model) -> Vec<Cmd> {
    model
        .ui
        .typing_to
        .take()
        .map(|pk| Cmd::Tox(ToxAction::SetTyping(pk, false)))
        .into_iter()
        .collect()
}

pub fn set_emojis_hidden(model: &mut Model, emojis: &[&str], hidden: bool) -> Vec<Cmd> {
    for config in [&mut model.config, &mut model.saved_config] {
        config
            .hidden_emojis
            .retain(|e| !emojis.contains(&e.as_str()));
        if hidden {
            config
                .hidden_emojis
                .extend(emojis.iter().map(|e| e.to_string()));
        }
    }
    vec![Cmd::IO(IOAction::SaveConfig(model.saved_config.clone()))]
}

/// Sends again what this Tox sent a friend without getting a receipt: Tox
/// drops it when they go offline. Messages from before a restart may well have
/// arrived, so we don't resend those.
fn send_undelivered(model: &mut Model, pk: PublicKey) -> Vec<Cmd> {
    let window_id = WindowId::Friend(pk);
    let Some(conv) = model.domain.conversations.get(&window_id) else {
        return Vec::new();
    };
    let undelivered: Vec<_> = conv
        .messages
        .iter()
        .filter(|msg| msg.is_self && matches!(msg.status, MessageStatus::Sent(Some(_))))
        .filter_map(|msg| {
            let bytes = model.tox_bytes(window_id, msg)?;
            Some((msg.internal_id, msg.message_type, bytes))
        })
        .collect();
    undelivered
        .into_iter()
        .flat_map(|(internal_id, message_type, bytes)| {
            send_pending(model, window_id, internal_id, message_type, bytes)
        })
        .collect()
}

fn message_limit(window_id: WindowId) -> usize {
    match window_id {
        WindowId::Group(_) => GROUP_MAX_MESSAGE_LENGTH,
        WindowId::Console
        | WindowId::Friend(_)
        | WindowId::Conference(_)
        | WindowId::Logs
        | WindowId::Files => MAX_MESSAGE_LENGTH,
    }
}

/// Sends a pending message, which stays `Sending` until Tox takes it.
pub fn send_pending(
    model: &mut Model,
    window_id: WindowId,
    internal_id: InternalMessageId,
    message_type: MessageType,
    content: Vec<u8>,
) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    let mut privately = None;
    if let Some(msg) = model.mark_message_status(window_id, internal_id, MessageStatus::Sending) {
        privately = msg.privately;
        cmds.extend(model.record(window_id, &msg));
    }
    // A device's message can be longer than Tox allows, so we split it. It's
    // delivered once the last part is.
    let limit = message_limit(window_id);
    let parts: Vec<Vec<u8>> = match String::from_utf8(content) {
        Ok(text) => split_message(&text, limit)
            .into_iter()
            .map(String::into_bytes)
            .collect(),
        Err(e) => e.into_bytes().chunks(limit).map(<[u8]>::to_vec).collect(),
    };
    for part in parts {
        cmds.push(Cmd::Tox(match window_id {
            WindowId::Friend(pk) => ToxAction::SendMessage(pk, message_type, part, internal_id),
            WindowId::Group(chat_id) => match privately {
                Some(pk) => {
                    ToxAction::SendGroupPrivateMessage(chat_id, pk, message_type, part, internal_id)
                }
                None => ToxAction::SendGroupMessage(chat_id, message_type, part, internal_id),
            },
            WindowId::Conference(conf_id) => {
                ToxAction::SendConferenceMessage(conf_id, message_type, part, internal_id)
            }
            WindowId::Console | WindowId::Logs | WindowId::Files => return cmds,
        }));
    }
    cmds
}

/// Returns the peer's name in the member list, or "Peer N" if they're not in
/// it.
fn sender_name(model: &Model, window_id: WindowId, pk: Option<PublicKey>, number: u32) -> String {
    pk.and_then(|pk| model.member_name(window_id, pk))
        .unwrap_or_else(|| format!("Peer {number}"))
}
