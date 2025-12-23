use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use toxcore::tox::{Address, GroupNumber, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, PeerId, PeerInfo, WindowId};
use toxxi::msg::Msg;
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

fn key_event(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn get_input_text(model: &Model) -> String {
    model.ui.input_state.text.clone()
}

#[test]
fn test_ui_popup_completion_flow() {
    let mut model = create_test_model();

    // 1. Setup Group with 5 peers
    let group_number = GroupNumber(1);
    let chat_id = toxcore::types::ChatId([1u8; 32]);
    model.session.group_numbers.insert(group_number, chat_id);
    model.ensure_group_window(chat_id);

    // Using dummy PKs
    let peers = [
        ("Alice", [1u8; 32]),
        ("Billy", [2u8; 32]), // Starts with B
        ("bob", [3u8; 32]),   // Starts with b
        ("Charlie", [4u8; 32]),
        ("David", [5u8; 32]),
    ];

    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Group(chat_id))
    {
        for (name, pk_bytes) in peers.iter() {
            conv.peers.push(PeerInfo {
                id: PeerId(PublicKey(*pk_bytes)),
                name: name.to_string(),
                role: None,
                status: ToxUserStatus::TOX_USER_STATUS_NONE,
                is_ignored: false,
                seen_online: true,
            });
        }
    }

    model.set_active_window(1); // Assuming 0 is Console, 1 is Group(1)
    assert_eq!(model.active_window_id(), WindowId::Group(chat_id));

    // 2. Type "b"
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Char('b')))),
    );
    assert_eq!(get_input_text(&model), "b");
    assert!(!model.ui.completion.active);

    // 3. Type Tab -> Should trigger completion
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Tab))),
    );

    // Verify completion state
    assert!(model.ui.completion.active, "Completion should be active");

    let candidates = model.ui.completion.candidates.clone();
    assert_eq!(
        candidates.len(),
        2,
        "Should have 2 candidates: Billy, bob. Got: {:?}",
        candidates
    );
    assert!(candidates.contains(&"Billy".to_string()));
    assert!(candidates.contains(&"bob".to_string()));

    // Based on default sorting (ASCII/Unicode): "Billy" < "bob" ('B' < 'b')
    // So candidates should be ["Billy", "bob"]
    let first = candidates[0].clone();
    let second = candidates[1].clone();

    // Verify text update: "Billy: "
    let text = get_input_text(&model);
    assert_eq!(text, format!("{}: ", first));

    // Verify cursor position
    model.ui.input_state.ensure_layout(80, "> ");
    let (cursor_x, cursor_y) = model.ui.input_state.cursor();
    assert_eq!(
        cursor_x,
        text.len() + 2,
        "Cursor x should be at end of text + prompt"
    );
    assert_eq!(cursor_y, 0, "Cursor y should be 0");

    // 4. Type Tab again -> Cycle to second
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Tab))),
    );
    let text_second = get_input_text(&model);
    assert_eq!(text_second, format!("{}: ", second));

    model.ui.input_state.ensure_layout(80, "> ");
    let (cursor_x_second, _cursor_y_second) = model.ui.input_state.cursor();
    assert_eq!(
        cursor_x_second,
        text_second.len() + 2,
        "Cursor x should be at end of text + prompt"
    );

    // 5. Type Tab again -> Cycle back to first
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Tab))),
    );
    assert_eq!(get_input_text(&model), format!("{}: ", first));

    // 6. Test Up/Down
    // Down -> Cycle to second
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Down))),
    );
    assert_eq!(get_input_text(&model), format!("{}: ", second));

    // Up -> Cycle back to first
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Up))),
    );
    assert_eq!(get_input_text(&model), format!("{}: ", first));

    // 7. Type a character -> Should dismiss popup
    assert!(
        model.ui.completion.active,
        "Completion should be active before typing"
    );
    update(
        &mut model,
        Msg::Input(crossterm::event::Event::Key(key_event(KeyCode::Char('x')))),
    );

    // Popup should be closed
    assert!(
        !model.ui.completion.active,
        "Completion should be dismissed after typing"
    );

    // Text should include the new char
    // "Billy: " + "x" -> "Billy: x"
    let expected_text = format!("{}: x", first);
    assert_eq!(get_input_text(&model), expected_text);
}
