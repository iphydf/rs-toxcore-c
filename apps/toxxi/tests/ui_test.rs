use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::FriendMessageId;
use toxcore::types::{MessageType, PublicKey};
use toxxi::model::{ConsoleMessageType, WindowId};
use toxxi::msg::{Msg, ToxEvent};
use toxxi::ui::draw;
use toxxi::update::update;
use toxxi_testing::create_test_model;

#[test]
fn test_ui_read_receipt_suffix() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);

    let (internal_id, _) =
        model.add_outgoing_friend_message(pk, MessageType::Normal, "msg 1".to_string());
    update(
        &mut model,
        Msg::Tox(ToxEvent::MessageSent(pk, FriendMessageId(1), internal_id)),
    );

    model.set_active_window(1);

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    // In a 20-row terminal, with 1-line topic and 3-line input + 1-line status,
    // the message area is 15 lines high, starting at row 1.
    // The message is rendered at the bottom: row 15.
    let row_15: String = (0..80).map(|x| buffer[(x, 15)].symbol()).collect();
    assert!(
        row_15.contains("●"),
        "Row 15 should contain '●' (Delivered) after message sent, got: {}",
        row_15
    );

    update(
        &mut model,
        Msg::Tox(ToxEvent::ReadReceipt(pk, FriendMessageId(1))),
    );

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let row_15_after: String = (0..80).map(|x| buffer[(x, 15)].symbol()).collect();

    assert!(
        row_15_after.contains("msg 1"),
        "Row 15 should contain 'msg 1', got: {}",
        row_15_after
    );
}

#[test]
fn test_ui_sidebar_default_visibility_groups() {
    let mut model = create_test_model();
    let gid = toxcore::tox::GroupNumber(1);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);

    model.add_group_message(
        chat_id,
        toxcore::types::MessageType::Normal,
        "System".to_string(),
        "init".to_string(),
        None,
    );

    let window_id = WindowId::Group(chat_id);
    let window_index = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == window_id)
        .expect("Group window should exist");

    model.set_active_window(window_index);

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // The peer list is the last 25 columns:
    // sidebar (25) | messages (30) | peers (25).
    // Info Pane starts at 55. Border at 55.
    let border_cell = &buffer[(55, 1)];
    assert_eq!(
        border_cell.symbol(),
        "│",
        "Column 55 should contain the peer list left border"
    );

    // InfoPane layout: Border(TOP) + Item 1 -> Item 1 at Row 1 (y=1).
    let row_1_content: String = (56..80).map(|x| buffer[(x, 1)].symbol()).collect();
    assert!(
        row_1_content.contains("Tester"),
        "Peer list should contain self name 'Tester' at row 1, got: '{}'",
        row_1_content
    );
}

#[test]
fn test_ui_sidebar_default_visibility_conferences() {
    let mut model = create_test_model();
    let cid = toxcore::tox::ConferenceNumber(1);
    let conf_id = toxcore::types::ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    model.add_conference_message(
        conf_id,
        toxcore::types::MessageType::Normal,
        "System".to_string(),
        "init".to_string(),
        None,
    );

    let window_id = WindowId::Conference(conf_id);
    let window_index = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == window_id)
        .expect("Conference window should exist");

    model.set_active_window(window_index);

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let border_cell = &buffer[(55, 1)];
    assert_eq!(
        border_cell.symbol(),
        "│",
        "Column 55 should contain the peer list left border for conferences"
    );
}

#[test]
fn test_ui_sidebar_not_shown_for_console() {
    let mut model = create_test_model();
    model.set_active_window(0); // Console is always 0

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let border_cell = &buffer[(55, 1)];
    // The console has no peer list border.
    assert_ne!(
        border_cell.symbol(),
        "│",
        "Column 55 should NOT contain the peer list border for console"
    );
}

#[test]
fn test_ui_group_message_status() {
    let mut model = create_test_model();
    let gnum = toxcore::tox::GroupNumber(0);
    let chat_id = toxcore::types::GroupChatId([0u8; 32]);
    model.session.group_numbers.insert(gnum, chat_id);

    let (internal_id, _) = model.add_outgoing_message(
        WindowId::Group(chat_id),
        MessageType::Normal,
        "group msg".to_string(),
    );

    let window_id = WindowId::Group(chat_id);
    model.set_active_window(1); // Group is window 1

    model
        .ui
        .window_state
        .entry(window_id)
        .or_default()
        .show_peers = false;

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    // Message area is rows 1..16 (height 15). Last row is 15.
    let row_15: String = (0..80).map(|x| buffer[(x, 15)].symbol()).collect();
    assert!(
        row_15.contains("○"),
        "Row 15 should contain '○' for pending group message, got: {}",
        row_15
    );

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupMessageSent(gnum, internal_id)),
    );

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let row_15_after: String = (0..80).map(|x| buffer[(x, 15)].symbol()).collect();

    assert!(row_15_after.contains("group msg"));
    assert!(!row_15_after.contains("○"));
    assert!(row_15_after.contains("●"));
}

#[test]
fn test_ui_scrollbar_visibility() {
    let mut model = create_test_model();

    // Fewer messages than the area's height (5).
    for i in 0..3 {
        model.add_console_message(ConsoleMessageType::Info, format!("log {}", i));
    }

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let col_79_content: String = (1..6).map(|y| buffer[(79, y)].symbol()).collect();
    assert!(!col_79_content.contains('↑'));
    assert!(!col_79_content.contains('↓'));
    assert!(!col_79_content.contains('█'));

    for i in 3..20 {
        model.add_console_message(ConsoleMessageType::Info, format!("log {}", i));
    }

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let col_79_content_many: String = (1..6).map(|y| buffer[(79, y)].symbol()).collect();
    assert!(
        col_79_content_many.contains('↑')
            || col_79_content_many.contains('↓')
            || col_79_content_many.contains('█')
            || col_79_content_many.contains('│'),
        "Scrollbar should be visible when many messages, got: {}",
        col_79_content_many
    );
}

#[test]
fn test_ui_cursor_position_with_emojis() {
    let mut model = create_test_model();

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    // An emoji (2 columns wide), with the cursor after it.
    model.ui.input_state.set_value("😊".to_string());
    model.ui.input_state.set_cursor(0, 1);

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let cursor = terminal.get_cursor_position().unwrap();
    // Prompt is width 2. Emoji is width 2. Cursor should be at 1 (border) + 2 (prompt) + 2 (emoji) = 5.
    assert_eq!(cursor.x, 5);
    assert_eq!(cursor.y, 8); // Row 8 is text line

    // An emoji and a letter, with the cursor after them.
    model.ui.input_state.set_value("😊a".to_string());
    model.ui.input_state.set_cursor(0, 2);

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let cursor = terminal.get_cursor_position().unwrap();
    // 1 (border) + 2 (prompt) + 2 (emoji) + 1 (a) = 6.
    assert_eq!(cursor.x, 6);
    assert_eq!(cursor.y, 8);
}

#[test]
fn test_ui_floating_completion_popup() {
    let mut model = create_test_model();

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();

    let text = "Hello 😊 Alice";
    model.ui.input_state.set_value(text.to_string());

    // InputBox uses visual width columns for the cursor.
    // "Hello " (6) + "😊" (2) + " Alice" (6) = 14 columns.
    model.ui.input_state.set_cursor(0, 14);

    model.ui.completion.active = true;
    model.ui.completion.candidates = vec!["Alice".to_string(), "Bob 😎".to_string()];
    model.ui.completion.original_input = "Hello 😊 Al".to_string();

    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // We only check that the popup is drawn.
    let popup_row_14: String = (0..80).map(|x| buffer[(x, 14)].symbol()).collect();
    let popup_row_15: String = (0..80).map(|x| buffer[(x, 15)].symbol()).collect();

    assert!(
        popup_row_14.contains("> Alice"),
        "Row 14 should contain '> Alice', got: '{}'",
        popup_row_14
    );
    assert!(
        popup_row_15.contains("Bob 😎"),
        "Row 15 should contain 'Bob 😎', got: '{}'",
        popup_row_15
    );
}

#[test]
fn test_ui_paste_multiline_input_rendering() {
    let mut model = create_test_model();

    // A multi-line input, as from a paste.
    model.ui.input_state.set_value("Line 1\nLine 2".to_string());
    // Set cursor to end of second line.
    model.ui.input_state.set_cursor(1, 6);

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    {
        let buffer = terminal.backend().buffer();
        // Input area starts at y=6 (10 - 4). Lines are at y=7, y=8.
        let input_row_1: String = (0..80).map(|x| buffer[(x, 7)].symbol()).collect();
        let input_row_2: String = (0..80).map(|x| buffer[(x, 8)].symbol()).collect();

        assert!(
            input_row_1.contains("Line 1") && input_row_2.contains("Line 2"),
            "Input row should display content, got: '{}' and '{}'",
            input_row_1,
            input_row_2
        );
    }

    let text = "Pasted Content";
    model.ui.input_state.set_value(text.to_string());
    model.ui.input_state.set_cursor(0, text.len());
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    // 1 line -> input height 3. Starts at y=7. Line at y=8.
    let input_row_single: String = (0..80).map(|x| buffer[(x, 8)].symbol()).collect();
    assert!(input_row_single.contains("Pasted Content"));
}

#[test]
fn test_ui_scrollbar_consistency() {
    let mut model = create_test_model();
    model.set_active_window(0); // Console

    // 800 messages.
    // Viewport ~55 lines. 800 items.
    // Thumb ratio = 55/800 = 0.068.
    // Thumb size = 55 * 0.068 = ~3.7 lines.
    for i in 0..800 {
        model.add_console_message(ConsoleMessageType::Info, format!("log {}", i));
    }

    let height = 60;
    let backend = TestBackend::new(80, height);
    let mut terminal = Terminal::new(backend).unwrap();

    let get_thumb_info = |term: &Terminal<TestBackend>| -> (usize, usize) {
        let buffer = term.backend().buffer();
        let mut thumb_start = None;
        let mut thumb_size = 0;

        for y in 0..60 {
            if buffer[(79, y)].symbol() == "█" {
                if thumb_start.is_none() {
                    thumb_start = Some(y as usize);
                }
                thumb_size += 1;
            }
        }
        (thumb_start.unwrap_or(0), thumb_size)
    };

    // Top.
    {
        let state = model.ui.window_state.entry(WindowId::Console).or_default();
        state.msg_list_state.select(Some(0));
    }
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let (top_pos, top_size) = get_thumb_info(&terminal);

    assert!(
        top_size >= 2,
        "Thumb size should be at least 2 lines, got {}",
        top_size
    );
    assert!(top_pos < 10, "Thumb should be near top, got {}", top_pos);

    // Middle.
    {
        let state = model.ui.window_state.entry(WindowId::Console).or_default();
        state.msg_list_state.select(Some(400));
    }
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let (mid_pos, mid_size) = get_thumb_info(&terminal);

    assert!(
        (mid_size as i32 - top_size as i32).abs() <= 2,
        "Thumb size should remain consistent (roughly). Top: {}, Mid: {}",
        top_size,
        mid_size
    );
    assert!(
        mid_pos > top_pos,
        "Thumb should move down (mid {} > top {})",
        mid_pos,
        top_pos
    );

    // Bottom.
    {
        let state = model.ui.window_state.entry(WindowId::Console).or_default();
        state.msg_list_state.select(Some(799));
    }
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let (bot_pos, bot_size) = get_thumb_info(&terminal);

    assert!(
        (bot_size as i32 - top_size as i32).abs() <= 2,
        "Thumb size should remain consistent (roughly). Top: {}, Bot: {}",
        top_size,
        bot_size
    );
    assert!(
        bot_pos > mid_pos,
        "Thumb should move down (bot {} > mid {})",
        bot_pos,
        mid_pos
    );
}

#[test]
fn test_ui_sidebar_friend_name_fallback() {
    let mut model = create_test_model();
    let pk = PublicKey([99u8; 32]);

    // A friend without a window, as when friends are loaded before windows open.
    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "green_potato".to_string(),
            public_key: Some(pk),
            status_message: "I am a potato".to_string(),
            connection: toxcore::tox::Connection::Tcp,
            is_typing: false,
        },
    );

    model.invalidate_sidebar_cache();

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();

    // The sidebar is the first 25 columns.
    let mut found_name = false;
    for y in 0..20 {
        let row_str: String = (0..25).map(|x| buffer[(x, y)].symbol()).collect();
        if row_str.contains("green_potato") {
            found_name = true;
            break;
        }
    }

    assert!(
        found_name,
        "Sidebar should display 'green_potato' even if conversation window is missing"
    );

    // The old fallback name isn't shown.
    let mut found_generic = false;
    for y in 0..20 {
        let row_str: String = (0..25).map(|x| buffer[(x, y)].symbol()).collect();
        if row_str.contains("Friend 99") {
            found_generic = true;
            break;
        }
    }

    assert!(
        !found_generic,
        "Sidebar should NOT display generic 'Friend 99' fallback"
    );
}

#[test]
fn test_ui_sidebar_selection_highlight() {
    let mut model = create_test_model();

    let pk = PublicKey([1u8; 32]);
    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "FriendA".to_string(),
            public_key: Some(pk),
            status_message: "".into(),
            connection: toxcore::tox::Connection::Tcp,
            is_typing: false,
        },
    );

    let gid = toxcore::tox::GroupNumber(1);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    model.add_group_message(
        chat_id,
        MessageType::Normal,
        "Sys".into(),
        "Init".into(),
        None,
    );
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Group(chat_id))
    {
        conv.name = "GroupB".to_string();
    }

    let cid = toxcore::tox::ConferenceNumber(2);
    let conf_id = toxcore::types::ConferenceId([2u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);
    model.add_conference_message(
        conf_id,
        MessageType::Normal,
        "Sys".into(),
        "Init".into(),
        None,
    );
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Conference(conf_id))
    {
        conv.name = "ConfC".to_string();
    }

    model.invalidate_sidebar_cache();

    let backend = TestBackend::new(80, 40); // Tall enough to show all
    let mut terminal = Terminal::new(backend).unwrap();

    model.ensure_friend_window(pk);
    let fid_idx = model
        .ui
        .window_ids
        .iter()
        .position(|&w| w == WindowId::Friend(pk))
        .unwrap();
    model.set_active_window(fid_idx);

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();

    let mut found = false;
    for y in 0..40 {
        let row: String = (0..25).map(|x| buffer[(x, y)].symbol()).collect();
        // The selection marker is "┃".
        if row.contains("┃") && row.contains("FriendA") {
            found = true;
            break;
        }
    }
    assert!(found, "FriendA should be highlighted with '┃'");

    let gid_idx = model
        .ui
        .window_ids
        .iter()
        .position(|&w| w == WindowId::Group(chat_id))
        .unwrap();
    model.set_active_window(gid_idx);

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();

    found = false;
    for y in 0..40 {
        let row: String = (0..25).map(|x| buffer[(x, y)].symbol()).collect();
        if row.contains("┃") && row.contains("GroupB") {
            found = true;
            break;
        }
    }
    assert!(found, "GroupB should be highlighted with '┃'");

    let cid_idx = model
        .ui
        .window_ids
        .iter()
        .position(|&w| w == WindowId::Conference(conf_id))
        .unwrap();
    model.set_active_window(cid_idx);

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();

    found = false;
    for y in 0..40 {
        let row: String = (0..25).map(|x| buffer[(x, y)].symbol()).collect();
        if row.contains("┃") && row.contains("ConfC") {
            found = true;
            break;
        }
    }
    assert!(found, "ConfC should be highlighted with '┃'");
}
