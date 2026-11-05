use crossterm::event::{KeyCode, KeyModifiers};
use toxcore::types::PublicKey;
use toxxi::model::{ConsoleMessageType, WindowId};
use toxxi::msg::{Cmd, ToxAction};
use toxxi_testing::{add_test_friend, create_test_model, send_key};

fn get_text(input: &toxxi::widgets::InputBoxState) -> String {
    input.text.clone()
}

#[test]
fn test_block_feature() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);

    add_test_friend(&mut model, pk);
    model.set_active_window(1);
    assert_eq!(model.active_window_id(), WindowId::Friend(pk));

    for c in "/block add hunter2".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());
    assert!(
        model
            .config
            .blocked_strings
            .contains(&"hunter2".to_string())
    );

    for c in "don't say hunter2!".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(cmds.is_empty());
    assert!(!model.ui.input_blocked_indices.is_empty());
    assert_eq!(get_text(&model.ui.input_state), "don't say hunter2!");

    let last_msg = model.domain.console_messages.last().unwrap();
    assert_eq!(last_msg.msg_type, ConsoleMessageType::Error);

    // Editing again clears the blocked marks.
    send_key(&mut model, KeyCode::Left, KeyModifiers::empty());
    assert!(model.ui.input_blocked_indices.is_empty());

    model.ui.input_state.clear();
    for c in "/block remove hunter2".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());
    assert!(
        !model
            .config
            .blocked_strings
            .contains(&"hunter2".to_string())
    );

    for c in "now I can say hunter2".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(!cmds.is_empty());
    let found = cmds.iter().any(|c| {
        if let Cmd::Tox(ToxAction::SendMessage(f, _, msg, _)) = c {
            *f == pk && msg == b"now I can say hunter2"
        } else {
            false
        }
    });
    if !found {
        panic!("Expected SendMessage command, got: {:?}", cmds);
    }
    assert!(get_text(&model.ui.input_state).is_empty());
}

#[test]
fn test_block_case_insensitive() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);
    model.set_active_window(1);

    model.config.blocked_strings.push("HUNTER2".to_string());

    for c in "I love hunter2".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());
    assert!(
        !cmds
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Tox(ToxAction::SendMessage(..))))
    );
    assert!(!model.ui.input_blocked_indices.is_empty());
}

/// Lowercase letters can take more bytes than their capitals (İ is 2 bytes,
/// i̇ is 3), so where a blocked string is in the lowercased line isn't where
/// it is in the line.
#[test]
fn a_blocked_string_after_a_letter_that_lowercases_longer_is_found() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);
    model.set_active_window(1);
    model.config.blocked_strings.push("éa".to_owned());

    for c in "İÉA!".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(
        !cmds
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Tox(ToxAction::SendMessage(..)))),
        "sent a blocked string"
    );
    assert_eq!(model.ui.input_blocked_indices, vec![(1, 3)]);
}

#[test]
fn a_blocked_string_isnt_sent_with_msg() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);
    model.config.blocked_strings.push("hunter2".to_owned());

    let line = format!(
        "/msg {} my password is hunter2",
        toxxi::utils::short_key(&pk)
    );
    let cmds = toxxi::update::handle_enter(&mut model, &line);

    assert!(
        !cmds
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Tox(ToxAction::SendMessage(..)))),
        "sent a blocked string"
    );
    assert_eq!(get_text(&model.ui.input_state), line);
}
