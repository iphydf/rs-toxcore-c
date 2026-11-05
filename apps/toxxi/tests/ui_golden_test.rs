use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};
use toxcore::tox::Connection;
use toxcore::types::{MessageType, PublicKey};
use toxxi::model::{InputMode, Model};
use toxxi::msg::Msg;
use toxxi::time::FakeTimeProvider;
use toxxi::ui::draw;
use toxxi::update::update;
use toxxi_testing::{self as testing, buffer_to_string, configure_insta};

fn create_test_model() -> Model {
    // Fixed time: 2023-01-01 12:00:00 UTC (1672574400)
    let fixed_system_time = UNIX_EPOCH + Duration::from_secs(1672574400);
    let fixed_instant = Instant::now();

    let tp = Arc::new(FakeTimeProvider::new(fixed_instant, fixed_system_time));

    testing::create_test_model().with_time_provider(tp)
}

#[test]
fn test_ui_initial_state_snapshot() {
    let mut model = create_test_model();

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
    let pk = PublicKey([1u8; 32]);

    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk),
            status_message: "Happy".to_string(),
            connection: Connection::Tcp,
            is_typing: false,
        },
    );
    model.add_friend_message(pk, MessageType::Normal, "Hello there!".to_string());

    model.set_active_window(1);

    model.ui.input_state.insert_str("General Kenobi!");

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
    let pk = PublicKey([1u8; 32]);

    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(pk),
            status_message: "Reading".to_string(),
            connection: Connection::Tcp,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
    model.set_active_window(1);

    let lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";
    model.ui.input_state.insert_str(lorem);

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

    let key_event = KeyEvent {
        code: KeyCode::Enter,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(key_event)));

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
    let pk = PublicKey([1u8; 32]);

    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(pk),
            status_message: "Reading".to_string(),
            connection: Connection::Tcp,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
    model.set_active_window(1);

    let key_event = KeyEvent {
        code: KeyCode::Char('t'),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(key_event)));

    model.ui.input_state.insert_str("Line 1");
    let enter_event = KeyEvent {
        code: KeyCode::Enter,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(enter_event)));
    model.ui.input_state.insert_str("Line 2");

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

    let send_event = KeyEvent {
        code: KeyCode::Enter,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(send_event)));

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
    let pk_bob = PublicKey([1u8; 32]);
    model.domain.friends.insert(
        pk_bob,
        toxxi::model::FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(pk_bob),
            status_message: "".to_string(),
            connection: Connection::Tcp,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_bob);

    // Add Charlie (2)
    let pk_charlie = PublicKey([2u8; 32]);
    model.domain.friends.insert(
        pk_charlie,
        toxxi::model::FriendInfo {
            name: "Charlie".to_string(),
            public_key: Some(pk_charlie),
            status_message: "Busy".to_string(),
            connection: Connection::Udp,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_charlie);

    // Add Dave (3)
    let pk_dave = PublicKey([3u8; 32]);
    model.domain.friends.insert(
        pk_dave,
        toxxi::model::FriendInfo {
            name: "Dave".to_string(),
            public_key: Some(pk_dave),
            status_message: "".to_string(),
            connection: Connection::None,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_dave);

    // Add Eve (4)
    let pk_eve = PublicKey([4u8; 32]);
    model.domain.friends.insert(
        pk_eve,
        toxxi::model::FriendInfo {
            name: "Eve".to_string(),
            public_key: Some(pk_eve),
            status_message: "".to_string(),
            connection: Connection::Tcp,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_eve);

    // Add Frank (5)
    let pk_frank = PublicKey([5u8; 32]);
    model.domain.friends.insert(
        pk_frank,
        toxxi::model::FriendInfo {
            name: "Frank".to_string(),
            public_key: Some(pk_frank),
            status_message: "".to_string(),
            connection: Connection::Tcp,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_frank);

    // Charlie's message is unread, as another window is shown.
    model.add_friend_message(pk_charlie, MessageType::Normal, "Hey everyone!".to_string());

    model.set_active_window(1);

    let width = 80;
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

    let key_event_fn = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };

    let ctrl_t = KeyEvent {
        code: KeyCode::Char('t'),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(ctrl_t)));
    assert_eq!(model.ui.input_mode, InputMode::MultiLine);

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

    for c in "how are you :".chars() {
        update(
            &mut model,
            Msg::Input(Event::Key(key_event_fn(KeyCode::Char(c)))),
        );
    }

    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Tab))),
    );
    assert!(model.ui.completion.active, "Completion should be active");

    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Right))),
    );
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Down))),
    );
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Down))),
    );

    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Enter))),
    );
    assert!(!model.ui.completion.active, "Completion should be closed");

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
    let pk = PublicKey([1u8; 32]);

    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk),
            status_message: "Happy".to_string(),
            connection: Connection::Tcp,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
    model.set_active_window(1);

    let slash = KeyEvent {
        code: KeyCode::Char('/'),
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    update(&mut model, Msg::Input(Event::Key(slash)));

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

    let pk = PublicKey([1u8; 32]);
    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk),
            status_message: "Happy".to_string(),
            connection: Connection::Tcp,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
    model.set_active_window(1);

    for c in "Hello A".chars() {
        update(
            &mut model,
            Msg::Input(Event::Key(key_event_fn(KeyCode::Char(c)))),
        );
    }

    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Tab))),
    );

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

    for c in "heart".chars() {
        update(
            &mut model,
            Msg::Input(Event::Key(key_event_fn(
                KeyCode::Char(c),
                KeyModifiers::NONE,
            ))),
        );
    }

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let rendered_search = buffer_to_string(terminal.backend().buffer());
    settings.bind(|| {
        insta::assert_snapshot!("emoji_picker_search_heart", rendered_search);
    });

    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Right, KeyModifiers::NONE))),
    );
    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Down, KeyModifiers::NONE))),
    );

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let rendered_nav = buffer_to_string(terminal.backend().buffer());
    settings.bind(|| {
        insta::assert_snapshot!("emoji_picker_navigated", rendered_nav);
    });

    update(
        &mut model,
        Msg::Input(Event::Key(key_event_fn(KeyCode::Enter, KeyModifiers::NONE))),
    );
    assert!(
        model.ui.emoji_picker.is_none(),
        "Emoji picker should be closed"
    );

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let rendered_result = buffer_to_string(terminal.backend().buffer());
    settings.bind(|| {
        insta::assert_snapshot!("emoji_picker_selection_result", rendered_result);
    });
}
