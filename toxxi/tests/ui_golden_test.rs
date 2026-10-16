use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};
use toxcore::tox::{Address, ToxConnection, ToxUserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, InputMode, Model};
use toxxi::msg::Msg;
use toxxi::testing::{buffer_to_string, configure_insta};
use toxxi::time::FakeTimeProvider;
use toxxi::ui::draw;
use toxxi::update::update;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        "Tester".to_string(),
        "I am a test".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );

    // Fixed time: 2023-01-01 12:00:00 UTC (1672574400)
    let fixed_system_time = UNIX_EPOCH + Duration::from_secs(1672574400);
    // Use actual Instant::now() as base, it doesn't matter for display as long as it's consistent within run
    let fixed_instant = Instant::now();

    let tp = Arc::new(FakeTimeProvider::new(fixed_instant, fixed_system_time));

    Model::new(domain, config.clone(), config).with_time_provider(tp)
}

#[test]
fn test_ui_initial_state_snapshot() {
    let mut model = create_test_model();

    // Use a fixed size for consistent snapshots
    let width = 80;
    let height = 24;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let rendered = buffer_to_string(buffer);

    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("initial_state", rendered);
    });
}

#[test]
fn test_ui_chat_interaction_snapshot() {
    let mut model = create_test_model();
    let fid = toxcore::tox::FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk);

    // 1. Receive a friend message from "Alice"
    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk),
            status_message: "Happy".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            is_typing: false,
        },
    );
    model.add_friend_message(
        pk,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "Hello there!".to_string(),
    );

    // 2. Switch to that window (Index 1)
    model.set_active_window(1);

    // 3. Type a reply
    model.ui.input_state.insert_str("General Kenobi!");

    // Draw
    let width = 80;
    let height = 24;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let rendered = buffer_to_string(buffer);

    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("chat_interaction", rendered);
    });
}

#[test]
fn test_ui_input_lorem_ipsum_snapshot() {
    let mut model = create_test_model();
    let fid = toxcore::tox::FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk);

    // 1. Add a friend so we have a window to talk in
    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(pk),
            status_message: "Reading".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            is_typing: false,
        },
    );
    // Ensure window exists
    model.ensure_friend_window(pk);
    model.set_active_window(1);

    let lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";
    model.ui.input_state.insert_str(lorem);

    // Draw
    let width = 80;
    let height = 24;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let rendered = buffer_to_string(buffer);

    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("input_lorem_ipsum", rendered);
    });

    // 4. Send the message (Press Enter)
    let key_event = KeyEvent {
        code: KeyCode::Enter,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(key_event)));

    // Draw again
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let rendered_sent = buffer_to_string(buffer);

    settings.bind(|| {
        insta::assert_snapshot!("input_lorem_ipsum_sent", rendered_sent);
    });
}

#[test]
fn test_ui_multiline_mode_snapshot() {
    let mut model = create_test_model();
    let fid = toxcore::tox::FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk);

    // 1. Add friend "Bob"
    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(pk),
            status_message: "Reading".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
    model.set_active_window(1);

    // 2. Switch to MultiLine mode (Ctrl+T)
    let key_event = KeyEvent {
        code: KeyCode::Char('t'),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(key_event)));

    // 3. Enter multiline text
    model.ui.input_state.insert_str("Line 1");
    // Enter (newline)
    let enter_event = KeyEvent {
        code: KeyCode::Enter,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(enter_event)));
    model.ui.input_state.insert_str("Line 2");

    // Draw
    let width = 80;
    let height = 24;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let rendered = buffer_to_string(buffer);

    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("input_multiline", rendered);
    });

    // 4. Send (Ctrl+Enter)
    let send_event = KeyEvent {
        code: KeyCode::Enter,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(send_event)));

    // Draw again
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let rendered_sent = buffer_to_string(buffer);

    settings.bind(|| {
        insta::assert_snapshot!("input_multiline_sent", rendered_sent);
    });
}

#[test]
fn test_ui_multiple_friends_snapshot() {
    let mut model = create_test_model();

    // Add Bob (1)
    let fid_bob = toxcore::tox::FriendNumber(1);
    let pk_bob = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid_bob, pk_bob);
    model.domain.friends.insert(
        pk_bob,
        toxxi::model::FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(pk_bob),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_bob);

    // Add Charlie (2)
    let fid_charlie = toxcore::tox::FriendNumber(2);
    let pk_charlie = PublicKey([2u8; 32]);
    model.session.friend_numbers.insert(fid_charlie, pk_charlie);
    model.domain.friends.insert(
        pk_charlie,
        toxxi::model::FriendInfo {
            name: "Charlie".to_string(),
            public_key: Some(pk_charlie),
            status_message: "Busy".to_string(),
            connection: ToxConnection::TOX_CONNECTION_UDP,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_charlie);

    // Add Dave (3)
    let fid_dave = toxcore::tox::FriendNumber(3);
    let pk_dave = PublicKey([3u8; 32]);
    model.session.friend_numbers.insert(fid_dave, pk_dave);
    model.domain.friends.insert(
        pk_dave,
        toxxi::model::FriendInfo {
            name: "Dave".to_string(),
            public_key: Some(pk_dave),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_dave);

    // Add Eve (4)
    let fid_eve = toxcore::tox::FriendNumber(4);
    let pk_eve = PublicKey([4u8; 32]);
    model.session.friend_numbers.insert(fid_eve, pk_eve);
    model.domain.friends.insert(
        pk_eve,
        toxxi::model::FriendInfo {
            name: "Eve".to_string(),
            public_key: Some(pk_eve),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_eve);

    // Add Frank (5)
    let fid_frank = toxcore::tox::FriendNumber(5);
    let pk_frank = PublicKey([5u8; 32]);
    model.session.friend_numbers.insert(fid_frank, pk_frank);
    model.domain.friends.insert(
        pk_frank,
        toxxi::model::FriendInfo {
            name: "Frank".to_string(),
            public_key: Some(pk_frank),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_frank);

    // Receive message from Charlie (should mark as unread since we are not on his window)
    model.add_friend_message(
        pk_charlie,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "Hey everyone!".to_string(),
    );

    // Set active window to Bob
    model.set_active_window(1);

    // Draw
    let width = 80; // Standard width
    let height = 24;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let rendered = buffer_to_string(buffer);

    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("multiple_friends", rendered);
    });
}

#[test]
fn test_ui_emoji_completion_snapshot() {
    let mut model = create_test_model();

    // Helper for key events
    let key_event_fn = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };

    // 1. Go into multi-line edit mode (Ctrl+T)
    let ctrl_t = KeyEvent {
        code: KeyCode::Char('t'),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(ctrl_t)));
    assert_eq!(model.ui.input_mode, InputMode::MultiLine);

    // 2. Type "hello", press enter
    for c in "hello".chars() {
        update(
            &mut model,
            Msg::Input(Event::Key(key_event_fn(KeyCode::Char(c)))),
        );
    }
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Enter))),
    );

    // 3. Type "how are you :"
    for c in "how are you :".chars() {
        update(
            &mut model,
            Msg::Input(Event::Key(key_event_fn(KeyCode::Char(c)))),
        );
    }

    // 4. Press tab (trigger completion)
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Tab))),
    );
    assert!(model.ui.completion.active, "Completion should be active");

    // 5. Navigate grid
    // Right (index + 1)
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Right))),
    );
    // Down (index + cols) -> default cols=10
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Down))),
    );
    // Down (index + cols)
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Down))),
    );

    // 6. Press enter (select)
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Enter))),
    );
    assert!(!model.ui.completion.active, "Completion should be closed");

    // 7. Take snapshot
    let width = 80;
    let height = 24;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let rendered = buffer_to_string(buffer);

    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("emoji_completion", rendered);
    });
}

#[test]
fn test_ui_command_menu_popup_snapshot() {
    let mut model = create_test_model();
    let fid = toxcore::tox::FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk);

    // 1. Add a friend to have a sidebar
    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk),
            status_message: "Happy".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
    model.set_active_window(1);

    // 2. Type "/" to open command menu
    let slash = KeyEvent {
        code: KeyCode::Char('/'),
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(slash)));

    // 3. Draw
    let width = 80;
    let height = 24;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let rendered = buffer_to_string(buffer);

    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("command_menu_popup", rendered);
    });
}

#[test]
fn test_ui_popup_completion_position_snapshot() {
    let mut model = create_test_model();

    let key_event_fn = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };

    // 1. Add a friend (sidebar visible)
    let fid = toxcore::tox::FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk);
    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk),
            status_message: "Happy".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
    model.set_active_window(1);

    // 2. Type "Hello A"
    for c in "Hello A".chars() {
        update(
            &mut model,
            Msg::Input(Event::Key(key_event_fn(KeyCode::Char(c)))),
        );
    }

    // 3. Trigger completion
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Tab))),
    );

    // 4. Draw
    let width = 80;
    let height = 24;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let rendered = buffer_to_string(buffer);

    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("popup_completion_position", rendered);
    });
}

#[test]
fn test_ui_emoji_picker_modal_snapshot() {
    let mut model = create_test_model();

    let key_event_fn = |code, modifiers| KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };

    // 1. Open Emoji Picker (Ctrl+E)
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(
            KeyCode::Char('e'),
            KeyModifiers::CONTROL,
        ))),
    );
    assert!(
        model.ui.emoji_picker.is_some(),
        "Emoji picker should be open"
    );

    // Draw initial picker
    let width = 80;
    let height = 24;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let rendered_initial = buffer_to_string(terminal.backend().buffer());

    let settings = configure_insta();
    settings.bind(|| {
        insta::assert_snapshot!("emoji_picker_initial", rendered_initial);
    });

    // 2. Type "heart" in search
    for c in "heart".chars() {
        update(
            &mut model,
            Msg::Input(Event::Key(key_event_fn(
                KeyCode::Char(c),
                KeyModifiers::NONE,
            ))),
        );
    }

    // Draw searched picker
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let rendered_search = buffer_to_string(terminal.backend().buffer());
    settings.bind(|| {
        insta::assert_snapshot!("emoji_picker_search_heart", rendered_search);
    });

    // 3. Navigate (Right, Down)
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Right, KeyModifiers::NONE))),
    );
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Down, KeyModifiers::NONE))),
    );

    // Draw navigated picker
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let rendered_nav = buffer_to_string(terminal.backend().buffer());
    settings.bind(|| {
        insta::assert_snapshot!("emoji_picker_navigated", rendered_nav);
    });

    // 4. Select (Enter)
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Enter, KeyModifiers::NONE))),
    );
    assert!(
        model.ui.emoji_picker.is_none(),
        "Emoji picker should be closed"
    );

    // Draw result in input box
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let rendered_result = buffer_to_string(terminal.backend().buffer());
    settings.bind(|| {
        insta::assert_snapshot!("emoji_picker_selection_result", rendered_result);
    });
}
