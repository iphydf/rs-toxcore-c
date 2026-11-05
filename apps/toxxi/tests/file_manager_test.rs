use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use toxcore::types::{FileId, PublicKey};
use toxxi::model::WindowId;
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
use toxxi::update::{handle_enter, update};
use toxxi_testing::{add_test_friend, create_test_model, send_key};

#[test]
fn test_file_list_command_opens_window() {
    let mut model = create_test_model();
    assert!(!model.ui.window_ids.contains(&WindowId::Files));

    handle_enter(&mut model, "/file list");

    assert!(model.ui.window_ids.contains(&WindowId::Files));
    assert_eq!(model.active_window_id(), WindowId::Files);
}

#[test]
fn test_ctrl_f_opens_window() {
    let mut model = create_test_model();

    let key = KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL);
    update(&mut model, Msg::Input(Event::Key(key)));

    assert!(model.ui.window_ids.contains(&WindowId::Files));
    assert_eq!(model.active_window_id(), WindowId::Files);
}

#[test]
fn test_file_manager_navigation() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);

    for i in 1..=3 {
        let mut id = [0u8; 32];
        id[0] = i as u8;
        update(
            &mut model,
            Msg::Tox(ToxEvent::FileRecv(
                pk,
                FileId(id),
                toxcore::types::FileKind::DATA,
                1024,
                format!("file{}.txt", i),
            )),
        );
    }

    assert_eq!(
        model.domain.file_transfers.len(),
        3,
        "File transfers not added"
    );

    handle_enter(&mut model, "/file list");
    send_key(&mut model, KeyCode::Esc, KeyModifiers::NONE); // Navigation mode

    let state = model.ui.window_state.get(&WindowId::Files).unwrap();
    assert_eq!(state.msg_list_state.selected_index, Some(2)); // Last item selected by default

    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);
    let state = model.ui.window_state.get(&WindowId::Files).unwrap();
    assert_eq!(state.msg_list_state.selected_index, Some(1));

    let cmds = send_key(&mut model, KeyCode::Char('p'), KeyModifiers::NONE);
    assert!(
        cmds.iter()
            .any(|c| matches!(c, Cmd::Tox(ToxAction::FileControl(..))))
    );
}
