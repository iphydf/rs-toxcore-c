use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use toxcore::types::PublicKey;
use toxxi::model::WindowId;
use toxxi::ui::draw;
use toxxi_testing::{create_test_model, send_key};

#[test]
fn test_ui_quick_switcher() {
    let mut model = create_test_model();

    // One friend (Bob) and one group (Rust).
    let bob_pk = PublicKey([2u8; 32]);
    model.domain.friends.insert(
        bob_pk,
        toxxi::model::FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(bob_pk),
            status_message: "".to_string(),
            connection: toxcore::tox::Connection::None,
            is_typing: false,
        },
    );
    model.ensure_friend_window(bob_pk);
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Friend(bob_pk))
    {
        conv.name = "Bob".to_string();
    }

    let g_chat_id = toxcore::types::GroupChatId([3u8; 32]);
    model.ensure_group_window(g_chat_id);
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Group(g_chat_id))
    {
        conv.name = "Rust Group".to_string();
    }

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();

    send_key(&mut model, KeyCode::Char(' '), KeyModifiers::CONTROL);
    assert!(
        model.ui.quick_switcher.is_some(),
        "Quick Switcher should be open"
    );

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let mut found_title = false;
    for y in 0..30 {
        let row: String = (0..100).map(|x| buffer[(x, y)].symbol()).collect();
        if row.contains("Quick Switcher") {
            found_title = true;
            break;
        }
    }
    assert!(
        found_title,
        "Quick Switcher title not found in render output"
    );

    // 'B' shows Bob, not Rust.
    send_key(&mut model, KeyCode::Char('B'), KeyModifiers::SHIFT);
    send_key(&mut model, KeyCode::Char('o'), KeyModifiers::NONE);

    if let Some(state) = &model.ui.quick_switcher {
        let filtered = state.filtered_items();
        assert_eq!(
            filtered.len(),
            1,
            "Should filter to 1 item. Text was: '{}'",
            state.input_state.text
        );
        assert_eq!(filtered[0].name, "Bob");
    } else {
        panic!("Switcher closed unexpectedly");
    }

    send_key(&mut model, KeyCode::Enter, KeyModifiers::NONE);

    assert!(
        model.ui.quick_switcher.is_none(),
        "Switcher should close after selection"
    );
    assert_eq!(
        model.active_window_id(),
        WindowId::Friend(bob_pk),
        "Should switch to Bob"
    );

    // Filter by prefix (g: Rust).
    send_key(&mut model, KeyCode::Char(' '), KeyModifiers::CONTROL);

    let query = "g: Rust";
    for c in query.chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::NONE);
    }

    if let Some(state) = &model.ui.quick_switcher {
        let filtered = state.filtered_items();
        assert_eq!(
            filtered.len(),
            1,
            "Should filter to 1 item. Text was: '{}'",
            state.input_state.text
        );
        assert_eq!(filtered[0].name, "Rust Group");
    }

    send_key(&mut model, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(
        model.active_window_id(),
        WindowId::Group(g_chat_id),
        "Should switch to Rust Group"
    );

    // A system window (Files).
    model.ui.window_ids.push(WindowId::Files);

    send_key(&mut model, KeyCode::Char(' '), KeyModifiers::CONTROL);

    let query = "Files";
    for c in query.chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::NONE);
    }

    send_key(&mut model, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(
        model.active_window_id(),
        WindowId::Files,
        "Should switch to Files window"
    );

    // Shift+Tab also opens it.
    send_key(&mut model, KeyCode::BackTab, KeyModifiers::SHIFT);
    assert!(
        model.ui.quick_switcher.is_some(),
        "Quick Switcher should be open via Shift+Tab"
    );
}

#[test]
fn test_same_named_friends_select_by_window() {
    let mut model = create_test_model();
    let first = PublicKey([2u8; 32]);
    let second = PublicKey([4u8; 32]);
    for pk in [first, second] {
        model.domain.friends.insert(
            pk,
            toxxi::model::FriendInfo {
                name: "Bob".to_string(),
                public_key: Some(pk),
                status_message: "".to_string(),
                connection: toxcore::tox::Connection::None,
                is_typing: false,
            },
        );
        model.ensure_friend_window(pk);
    }

    send_key(&mut model, KeyCode::Char(' '), KeyModifiers::CONTROL);
    for c in "Bob".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::NONE);
    }
    send_key(&mut model, KeyCode::Down, KeyModifiers::NONE);
    send_key(&mut model, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(model.active_window_id(), WindowId::Friend(second));

    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let bob_rows: Vec<String> = (0..30)
        .map(|y| (0..25).map(|x| buffer[(x, y)].symbol()).collect::<String>())
        .filter(|row| row.contains("Bob"))
        .collect();
    assert_eq!(bob_rows.len(), 2);
    assert!(!bob_rows[0].contains('┃'));
    assert!(bob_rows[1].contains('┃'));
}
