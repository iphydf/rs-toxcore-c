use ratatui::{Terminal, backend::TestBackend};
use toxcore::types::{LogLevel, MessageType};
use toxxi::model::{ConsoleMessageType, WindowId};
use toxxi::ui::draw;
use toxxi_testing::create_test_model;

#[test]
fn test_scroll_up_at_top_keeps_messages_visible() {
    let mut model = create_test_model();

    for i in 1..=10 {
        model.add_console_message(ConsoleMessageType::Info, format!("message {}", i));
    }

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();

    let mut found_msg10 = false;
    for y in 0..10 {
        let row_content: String = (0..80).map(|x| buffer[(x, y)].symbol()).collect();
        if row_content.contains("message 10") {
            found_msg10 = true;
            break;
        }
    }
    assert!(found_msg10, "message 10 should be visible initially");

    // Scroll up past 1 message.
    model.scroll_up(1);

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();

    let mut found_msg10_after = false;
    for y in 0..10 {
        let row_content: String = (0..80).map(|x| buffer[(x, y)].symbol()).collect();
        if row_content.contains("message 10") {
            found_msg10_after = true;
            break;
        }
    }

    assert!(
        !found_msg10_after,
        "message 10 should NOT be visible after scrolling up (it should be skipped). scroll is {}",
        model
            .ui
            .window_state
            .get(&WindowId::Console)
            .unwrap()
            .msg_list_state
            .scroll
    );
}

#[test]
fn test_scroll_up_does_not_overscroll() {
    let mut model = create_test_model();

    // 20 messages, each 1 line high.
    for i in 1..=20 {
        model.add_console_message(ConsoleMessageType::Info, format!("message {}", i));
    }

    let height = 10;
    let backend = TestBackend::new(80, height as u16);
    let mut terminal = Terminal::new(backend).unwrap();

    // Render once to fill in total_height and last_height.
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let state = model.ui.window_state.get(&WindowId::Console).unwrap();
    let total_height = state.msg_list_state.total_height;
    let last_height = state.last_height;

    assert!(
        total_height >= 20,
        "Total height should be at least 20 lines"
    );
    assert!(last_height > 0, "Last height should be greater than 0");

    // Scrolling stops at total_height - last_height.
    model.scroll_up(total_height);

    let scroll = model
        .ui
        .window_state
        .get(&WindowId::Console)
        .unwrap()
        .msg_list_state
        .scroll;
    assert!(
        scroll <= total_height.saturating_sub(last_height),
        "Should not scroll past the top of the content. scroll={}, max_valid={}",
        scroll,
        total_height.saturating_sub(last_height)
    );
}

#[test]
fn test_logs_scrolling_with_filters() {
    let mut model = create_test_model();

    for i in 0..10 {
        model.add_tox_log(
            LogLevel::Info,
            "file.c".to_string(),
            i,
            "func".to_string(),
            format!("message {}", i),
        );
    }

    model.ui.log_filters.levels = vec![LogLevel::Info];

    model
        .ui
        .window_state
        .entry(WindowId::Logs)
        .or_default()
        .msg_list_state
        .scroll = 1;

    // A log the filter hides (TRACE)
    model.add_tox_log(
        LogLevel::Trace,
        "file.c".to_string(),
        10,
        "func".to_string(),
        "trace message".to_string(),
    );

    // doesn't move the scroll position.
    assert_eq!(
        model
            .ui
            .window_state
            .get(&WindowId::Logs)
            .unwrap()
            .msg_list_state
            .scroll,
        1,
        "scroll incremented for filtered log!"
    );
}

#[test]
fn test_scroll_stability_group_conference() {
    let mut model = create_test_model();
    let gid = toxcore::tox::GroupNumber(1);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    let cid = toxcore::tox::ConferenceNumber(1);
    let conf_id = toxcore::types::ConferenceId([2u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    // A group.
    model.ensure_group_window(chat_id);
    let g_win = WindowId::Group(chat_id);
    for i in 0..5 {
        model.add_group_message(
            chat_id,
            MessageType::Normal,
            "System".to_string(),
            format!("msg {}", i),
            None,
        );
    }
    model.set_active_window(1);
    let backend = TestBackend::new(80, 2);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    model.scroll_up(1);
    assert_eq!(
        model
            .ui
            .window_state
            .get(&g_win)
            .unwrap()
            .msg_list_state
            .scroll,
        1
    );

    model.add_group_message(
        chat_id,
        MessageType::Normal,
        "System".to_string(),
        "new msg".to_string(),
        None,
    );
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    assert_eq!(
        model
            .ui
            .window_state
            .get(&g_win)
            .unwrap()
            .msg_list_state
            .scroll,
        1,
        "Group scroll should NOT increment when new message arrives (it stays fixed on history)"
    );

    // A conference.
    model.ensure_conference_window(conf_id);
    let c_win = WindowId::Conference(conf_id);
    for i in 0..5 {
        model.add_conference_message(
            conf_id,
            MessageType::Normal,
            "System".to_string(),
            format!("msg {}", i),
            None,
        );
    }
    model.set_active_window(2);
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    model.scroll_up(1);
    assert_eq!(
        model
            .ui
            .window_state
            .get(&c_win)
            .unwrap()
            .msg_list_state
            .scroll,
        1
    );

    model.add_conference_message(
        conf_id,
        MessageType::Normal,
        "System".to_string(),
        "new msg".to_string(),
        None,
    );
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    assert_eq!(
        model
            .ui
            .window_state
            .get(&c_win)
            .unwrap()
            .msg_list_state
            .scroll,
        1,
        "Conference scroll should NOT increment when new message arrives"
    );
}
