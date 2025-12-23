use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use toxcore::tox::Address;
use toxcore::tox::{FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::{FileId, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, Model, WindowId};
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
use toxxi::update::{handle_enter, update};

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

fn add_test_friend(model: &mut Model, fid: FriendNumber, pk: PublicKey) {
    model.session.friend_numbers.insert(fid, pk);
    model.domain.friends.insert(
        pk,
        FriendInfo {
            name: format!("Friend {}", fid.0),
            public_key: Some(pk),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
}

fn key_event(code: KeyCode) -> Msg {
    Msg::Input(Event::Key(KeyEvent::new(code, KeyModifiers::empty())))
}

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
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);

    // Add some transfers
    for i in 1..=3 {
        let mut id = [0u8; 32];
        id[0] = i as u8;
        update(
            &mut model,
            Msg::Tox(ToxEvent::FileRecv(
                fid,
                FileId(id),
                0,
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
    update(&mut model, key_event(KeyCode::Esc)); // Navigation mode

    let state = model.ui.window_state.get(&WindowId::Files).unwrap();
    assert_eq!(state.msg_list_state.selected_index, Some(2)); // Last item selected by default

    update(&mut model, key_event(KeyCode::Up));
    let state = model.ui.window_state.get(&WindowId::Files).unwrap();
    assert_eq!(state.msg_list_state.selected_index, Some(1));

    // Test 'p' in File Manager
    let cmds = update(&mut model, key_event(KeyCode::Char('p')));
    assert!(
        cmds.iter()
            .any(|c| matches!(c, Cmd::Tox(ToxAction::FileControl(..))))
    );
}
