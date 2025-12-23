use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use toxcore::tox::Address;
use toxcore::tox::{FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::{FileId, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, MessageContent, Model, TransferStatus, UiMode};
use toxxi::msg::{Cmd, IOAction, IOEvent, Msg, ToxAction, ToxEvent};
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
fn test_esc_switches_to_navigation_mode() {
    let mut model = create_test_model();
    assert_eq!(model.ui.ui_mode, UiMode::Chat);

    update(&mut model, key_event(KeyCode::Esc));

    assert_eq!(model.ui.ui_mode, UiMode::Navigation);
}

#[test]
fn test_accept_file_in_navigation_mode() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, fid, pk);

    // 1. Receive file
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            fid,
            file_id,
            0,
            1024,
            "test.txt".to_string(),
        )),
    );
    model.set_active_window(1);

    // 2. Switch to Navigation mode
    update(&mut model, key_event(KeyCode::Esc));

    // 3. Select the file transfer message (it's the last one)
    // We might need to implement selection movement in update.rs
    update(&mut model, key_event(KeyCode::Up));

    // 4. Press 'a' to accept
    let cmds = update(&mut model, key_event(KeyCode::Char('a')));

    // 5. Verify commands
    let has_io_accept = cmds.iter().any(|c| matches!(c, Cmd::IO(IOAction::OpenFileForReceiving(f, n, ..)) if *f == pk && *n == file_id));
    let has_tox_control = cmds.iter().any(
        |c| matches!(c, Cmd::Tox(ToxAction::FileControl(f, n, ..)) if *f == pk && *n == file_id),
    );

    assert!(has_io_accept, "Missing IOAction::OpenFileForReceiving");
    assert!(has_tox_control, "Missing ToxAction::FileControl");
}

#[test]
fn test_cancel_file_in_navigation_mode() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, fid, pk);

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            fid,
            file_id,
            0,
            1024,
            "test.txt".to_string(),
        )),
    );
    model.set_active_window(1);
    update(&mut model, key_event(KeyCode::Esc));
    update(&mut model, key_event(KeyCode::Up));

    let cmds = update(&mut model, key_event(KeyCode::Char('x')));

    let has_cancel = cmds.iter().any(|c| matches!(c, Cmd::Tox(ToxAction::FileControl(f, n, control))
        if *f == pk && *n == file_id && *control == toxcore::types::ToxFileControl::TOX_FILE_CONTROL_CANCEL));

    assert!(has_cancel, "Missing ToxAction::FileControl CANCEL");
}

#[test]
fn test_toggle_pause_file_in_navigation_mode() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, fid, pk);

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            fid,
            file_id,
            0,
            1024,
            "test.txt".to_string(),
        )),
    );
    model.set_active_window(1);
    update(&mut model, key_event(KeyCode::Esc));
    update(&mut model, key_event(KeyCode::Up));

    // Initially not paused
    let p = model.domain.file_transfers.get(&file_id).unwrap();
    assert!(p.status == TransferStatus::Active);

    // Press 'p' to pause
    let cmds = update(&mut model, key_event(KeyCode::Char('p')));
    let has_pause = cmds.iter().any(|c| matches!(c, Cmd::Tox(ToxAction::FileControl(f, n, control))
        if *f == pk && *n == file_id && *control == toxcore::types::ToxFileControl::TOX_FILE_CONTROL_PAUSE));
    assert!(has_pause);

    // Simulate pause from worker
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecvControl(
            fid,
            file_id,
            toxcore::types::ToxFileControl::TOX_FILE_CONTROL_PAUSE,
        )),
    );
    assert_eq!(
        model.domain.file_transfers.get(&file_id).unwrap().status,
        TransferStatus::Paused
    );

    // Press 'p' again to resume
    let cmds = update(&mut model, key_event(KeyCode::Char('p')));
    let has_resume = cmds.iter().any(|c| matches!(c, Cmd::Tox(ToxAction::FileControl(f, n, control))
        if *f == pk && *n == file_id && *control == toxcore::types::ToxFileControl::TOX_FILE_CONTROL_RESUME));
    assert!(has_resume);
}

#[test]
fn test_change_dest_prefills_command() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, fid, pk);

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            fid,
            file_id,
            0,
            1024,
            "test.txt".to_string(),
        )),
    );
    model.set_active_window(1);
    update(&mut model, key_event(KeyCode::Esc));
    update(&mut model, key_event(KeyCode::Up));

    update(&mut model, key_event(KeyCode::Char('o')));

    assert_eq!(model.ui.ui_mode, UiMode::Chat);
    assert!(
        model
            .ui
            .input_state
            .text
            .starts_with(&format!("/file accept 1 {} test.txt", file_id))
    );
}

#[test]
fn test_outgoing_file_transfer_hides_path() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);

    add_test_friend(&mut model, fid, pk);

    // Simulate IOEvent::FileStarted with a full path
    let full_path = "/home/user/documents/secret_plans.pdf";
    let file_id = FileId([100u8; 32]);

    let event = IOEvent::FileStarted(pk, file_id, full_path.to_string(), 1024);
    let _ = update(&mut model, Msg::IO(event));

    // Check message content
    let window_id = toxxi::model::WindowId::Friend(pk);
    let conv = model.domain.conversations.get(&window_id).unwrap();
    let msg = conv.messages.last().unwrap();

    if let MessageContent::FileTransfer { name, .. } = &msg.content {
        assert_eq!(
            name, "secret_plans.pdf",
            "Message should show only filename"
        );
    } else {
        panic!("Message content is not FileTransfer");
    }

    // Check FileTransferProgress
    let progress = model.domain.file_transfers.get(&file_id).unwrap();
    assert_eq!(
        progress.filename, "secret_plans.pdf",
        "Progress should store only filename"
    );
}
