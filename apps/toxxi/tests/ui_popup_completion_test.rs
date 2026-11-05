use crossterm::event::{KeyCode, KeyModifiers};
use toxcore::tox::{GroupNumber, UserStatus};
use toxcore::types::PublicKey;
use toxxi::model::{Model, PeerId, PeerInfo, WindowId};
use toxxi_testing::{create_test_model, send_key};

fn get_input_text(model: &Model) -> String {
    model.ui.input_state.text.clone()
}

#[test]
fn test_ui_popup_completion_flow() {
    let mut model = create_test_model();

    let group_number = GroupNumber(1);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(group_number, chat_id);
    model.ensure_group_window(chat_id);

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
                status: UserStatus::None,
                is_ignored: false,
                seen_online: true,
            });
        }
    }

    model.set_active_window(1); // 0 is the console, 1 the group.
    assert_eq!(model.active_window_id(), WindowId::Group(chat_id));

    send_key(&mut model, KeyCode::Char('b'), KeyModifiers::NONE);
    assert_eq!(get_input_text(&model), "b");
    assert!(!model.ui.completion.active);

    send_key(&mut model, KeyCode::Tab, KeyModifiers::NONE);

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

    // Sorted by byte value: "Billy" < "bob" ('B' < 'b').
    let first = candidates[0].clone();
    let second = candidates[1].clone();

    let text = get_input_text(&model);
    assert_eq!(text, format!("{}: ", first));

    model.ui.input_state.ensure_layout(80, "> ");
    let (cursor_x, cursor_y) = model.ui.input_state.cursor();
    assert_eq!(
        cursor_x,
        text.len() + 2,
        "Cursor x should be at end of text + prompt"
    );
    assert_eq!(cursor_y, 0, "Cursor y should be 0");

    // Tab again cycles to the second.
    send_key(&mut model, KeyCode::Tab, KeyModifiers::NONE);
    let text_second = get_input_text(&model);
    assert_eq!(text_second, format!("{}: ", second));

    model.ui.input_state.ensure_layout(80, "> ");
    let (cursor_x_second, _cursor_y_second) = model.ui.input_state.cursor();
    assert_eq!(
        cursor_x_second,
        text_second.len() + 2,
        "Cursor x should be at end of text + prompt"
    );

    // And back to the first.
    send_key(&mut model, KeyCode::Tab, KeyModifiers::NONE);
    assert_eq!(get_input_text(&model), format!("{}: ", first));

    // Down cycles to the second.
    send_key(&mut model, KeyCode::Down, KeyModifiers::NONE);
    assert_eq!(get_input_text(&model), format!("{}: ", second));

    // Up cycles back.
    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);
    assert_eq!(get_input_text(&model), format!("{}: ", first));

    // Typing closes the popup.
    assert!(
        model.ui.completion.active,
        "Completion should be active before typing"
    );
    send_key(&mut model, KeyCode::Char('x'), KeyModifiers::NONE);

    assert!(
        !model.ui.completion.active,
        "Completion should be dismissed after typing"
    );

    let expected_text = format!("{}: x", first);
    assert_eq!(get_input_text(&model), expected_text);
}
