use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, ToxUserStatus};
use toxcore::types::{MessageType, PublicKey, ToxLogLevel};
use toxxi::config::Config;
use toxxi::model::{ConsoleMessageType, DomainState, Model, WindowId};
use toxxi::ui::draw;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "I am a test".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

#[test]
fn test_scroll_up_at_top_keeps_messages_visible() {
    let mut model = create_test_model();

    // Add 10 messages
    for i in 1..=10 {
        model.add_console_message(ConsoleMessageType::Log, format!("message {}", i));
    }

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    // 1. Initial state (scroll = 0)
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

    // 2. Scroll up (skip 1 message from bottom)
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
fn test_scroll_bottom_resets_offset() {
    let mut model = create_test_model();

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    for i in 0..100 {
        model.add_console_message(ConsoleMessageType::Log, format!("message {}", i));
    }

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    model.scroll_up(1);
    model.scroll_up(1);
    assert_eq!(
        model
            .ui
            .window_state
            .get(&WindowId::Console)
            .unwrap()
            .msg_list_state
            .scroll,
        2
    );

    model.scroll_bottom();
    assert_eq!(
        model
            .ui
            .window_state
            .get(&WindowId::Console)
            .unwrap()
            .msg_list_state
            .scroll,
        0
    );
}

#[test]
fn test_scroll_top_sets_max_offset() {
    let mut model = create_test_model();

    for i in 0..100 {
        model.add_console_message(ConsoleMessageType::Log, format!("message {}", i));
    }

    let backend = TestBackend::new(80, 13);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    // Scroll to top
    model.scroll_top();
    let state = model.ui.window_state.get(&WindowId::Console).unwrap();
    assert_eq!(
        state.msg_list_state.scroll,
        state
            .msg_list_state
            .total_height
            .saturating_sub(state.last_height)
    );
}

#[test]
fn test_scroll_up_does_not_overscroll() {
    let mut model = create_test_model();

    // Add 20 messages, each 1 line high
    for i in 1..=20 {
        model.add_console_message(ConsoleMessageType::Log, format!("message {}", i));
    }

    let height = 10;
    let backend = TestBackend::new(80, height as u16);
    let mut terminal = Terminal::new(backend).unwrap();

    // Render once to populate state.total_height and state.last_height
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let state = model.ui.window_state.get(&WindowId::Console).unwrap();
    let total_height = state.msg_list_state.total_height;
    let last_height = state.last_height;

    assert!(
        total_height >= 20,
        "Total height should be at least 20 lines"
    );
    assert!(last_height > 0, "Last height should be greater than 0");

    // Try to scroll up beyond (total_height - last_height)
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

    // 1. Add some initial logs
    for i in 0..10 {
        model.add_tox_log(
            ToxLogLevel::TOX_LOG_LEVEL_INFO,
            "file.c".to_string(),
            i,
            "func".to_string(),
            format!("message {}", i),
        );
    }

    // 2. Set filter to only show INFO (which we have)
    model.ui.log_filters.levels = vec![ToxLogLevel::TOX_LOG_LEVEL_INFO];
    assert_eq!(model.all_tox_logs().len(), 10);

    // 3. Scroll up
    model
        .ui
        .window_state
        .entry(WindowId::Logs)
        .or_default()
        .msg_list_state
        .scroll = 1;

    // 4. Add a log that is FILTERED OUT (e.g. TRACE)
    model.add_tox_log(
        ToxLogLevel::TOX_LOG_LEVEL_TRACE,
        "file.c".to_string(),
        10,
        "func".to_string(),
        "trace message".to_string(),
    );

    // 5. Total visible logs should still be 10
    assert_eq!(model.all_tox_logs().len(), 10);

    // 6. scroll SHOULD NOT have incremented
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
    let chat_id = toxcore::types::ChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    let cid = toxcore::tox::ConferenceNumber(1);
    let conf_id = toxcore::types::ConferenceId([2u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    // 1. Test Group
    model.ensure_group_window(chat_id);
    let g_win = WindowId::Group(chat_id);
    for i in 0..5 {
        model.add_group_message(
            chat_id,
            MessageType::TOX_MESSAGE_TYPE_NORMAL,
            "System".to_string(),
            format!("msg {}", i),
            None,
        );
    }
    model.set_active_window(1);
    let backend = TestBackend::new(80, 2);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    model.scroll_up(1); // Scroll up 1 line // Scroll up 1 line, height 2
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
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
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

    // 2. Test Conference
    model.ensure_conference_window(conf_id);
    let c_win = WindowId::Conference(conf_id);
    for i in 0..5 {
        model.add_conference_message(
            conf_id,
            MessageType::TOX_MESSAGE_TYPE_NORMAL,
            "System".to_string(),
            format!("msg {}", i),
            None,
        );
    }
    model.set_active_window(2);
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    model.scroll_up(1); // Scroll up 1 line
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
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
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

// end of tests
