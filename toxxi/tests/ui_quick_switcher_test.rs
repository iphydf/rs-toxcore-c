use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, WindowId};
use toxxi::msg::Msg;
use toxxi::ui::draw;
use toxxi::update::update;

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

fn create_key_event(code: KeyCode, modifiers: KeyModifiers) -> Event {
    Event::Key(KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    })
}

#[test]
fn test_ui_quick_switcher() {
    let mut model = create_test_model();

    // Setup: 1 Friend (Bob), 1 Group (Rust)
    let bob_pk = PublicKey([2u8; 32]);
    model.domain.friends.insert(
        bob_pk,
        toxxi::model::FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(bob_pk),
            status_message: "".to_string(),
            connection: toxcore::tox::ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.ensure_friend_window(bob_pk);
    // Update name
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Friend(bob_pk))
    {
        conv.name = "Bob".to_string();
    }

    let g_chat_id = toxcore::types::ChatId([3u8; 32]);
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

    // 1. Open Switcher (Ctrl+Space)
    update(
        &mut model,
        Msg::Input(create_key_event(KeyCode::Char(' '), KeyModifiers::CONTROL)),
    );
    assert!(
        model.ui.quick_switcher.is_some(),
        "Quick Switcher should be open"
    );

    // 2. Render Check
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    // Verify modal is drawn (check for border or title)
    // The Quick Switcher title is "Quick Switcher"
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

    // 3. Filtering
    // Type 'B' -> Should show Bob, not Rust
    update(
        &mut model,
        Msg::Input(create_key_event(KeyCode::Char('B'), KeyModifiers::SHIFT)),
    );
    update(
        &mut model,
        Msg::Input(create_key_event(KeyCode::Char('o'), KeyModifiers::NONE)),
    );

    // Check internal state of filtered items
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

    // 4. Selection
    update(
        &mut model,
        Msg::Input(create_key_event(KeyCode::Enter, KeyModifiers::NONE)),
    );

    assert!(
        model.ui.quick_switcher.is_none(),
        "Switcher should close after selection"
    );
    assert_eq!(
        model.active_window_id(),
        WindowId::Friend(bob_pk),
        "Should switch to Bob"
    );

    // 5. Prefix filtering (g: Rust)
    update(
        &mut model,
        Msg::Input(create_key_event(KeyCode::Char(' '), KeyModifiers::CONTROL)),
    );

    let query = "g: Rust";
    for c in query.chars() {
        update(
            &mut model,
            Msg::Input(create_key_event(KeyCode::Char(c), KeyModifiers::NONE)),
        );
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

    update(
        &mut model,
        Msg::Input(create_key_event(KeyCode::Enter, KeyModifiers::NONE)),
    );
    assert_eq!(
        model.active_window_id(),
        WindowId::Group(g_chat_id),
        "Should switch to Rust Group"
    );

    // 6. System Window (Files)
    // Ensure Files window is open
    model.ui.window_ids.push(WindowId::Files);

    update(
        &mut model,
        Msg::Input(create_key_event(KeyCode::Char(' '), KeyModifiers::CONTROL)),
    );

    let query = "Files";
    for c in query.chars() {
        update(
            &mut model,
            Msg::Input(create_key_event(KeyCode::Char(c), KeyModifiers::NONE)),
        );
    }

    // Select
    update(
        &mut model,
        Msg::Input(create_key_event(KeyCode::Enter, KeyModifiers::NONE)),
    );
    assert_eq!(
        model.active_window_id(),
        WindowId::Files,
        "Should switch to Files window"
    );

    // 7. Open Switcher with Shift+Tab (BackTab)
    update(
        &mut model,
        Msg::Input(create_key_event(KeyCode::BackTab, KeyModifiers::SHIFT)),
    );
    assert!(
        model.ui.quick_switcher.is_some(),
        "Quick Switcher should be open via Shift+Tab"
    );
}
