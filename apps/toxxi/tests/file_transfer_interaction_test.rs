use crossterm::event::{KeyCode, KeyModifiers};
use toxcore::types::{FileId, PublicKey};
use toxxi::model::{MessageContent, TransferStatus, UiMode};
use toxxi::msg::{Cmd, IOAction, IOEvent, Msg, ToxAction, ToxEvent};
use toxxi::update::update;
use toxxi_testing::{add_test_friend, create_test_model, send_key};

#[test]
fn test_esc_switches_to_navigation_mode() {
    let mut model = create_test_model();
    assert_eq!(model.ui.ui_mode, UiMode::Chat);

    send_key(&mut model, KeyCode::Esc, KeyModifiers::NONE);

    assert_eq!(model.ui.ui_mode, UiMode::Navigation);
}

#[test]
fn test_accept_file_in_navigation_mode() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, pk);

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            pk,
            file_id,
            toxcore::types::FileKind::DATA,
            1024,
            "test.txt".to_string(),
        )),
    );
    model.set_active_window(1);

    send_key(&mut model, KeyCode::Esc, KeyModifiers::NONE);

    // Select the file transfer message, the last one.
    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);

    let cmds = send_key(&mut model, KeyCode::Char('a'), KeyModifiers::NONE);

    let has_io_accept = cmds.iter().any(|c| matches!(c, Cmd::IO(IOAction::OpenFileForReceiving(f, n, ..)) if *f == pk && *n == file_id));
    assert!(has_io_accept, "Missing IOAction::OpenFileForReceiving");
}

#[test]
fn test_cancel_file_in_navigation_mode() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, pk);

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            pk,
            file_id,
            toxcore::types::FileKind::DATA,
            1024,
            "test.txt".to_string(),
        )),
    );
    model.set_active_window(1);
    send_key(&mut model, KeyCode::Esc, KeyModifiers::NONE);
    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);

    let cmds = send_key(&mut model, KeyCode::Char('x'), KeyModifiers::NONE);

    let has_cancel = cmds.iter().any(|c| {
        matches!(c, Cmd::Tox(ToxAction::FileControl(f, n, control))
        if *f == pk && *n == file_id && *control == toxcore::types::FileControl::Cancel)
    });

    assert!(has_cancel, "Missing ToxAction::FileControl CANCEL");
}

#[test]
fn test_toggle_pause_file_in_navigation_mode() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, pk);

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            pk,
            file_id,
            toxcore::types::FileKind::DATA,
            1024,
            "test.txt".to_string(),
        )),
    );
    model.set_active_window(1);
    send_key(&mut model, KeyCode::Esc, KeyModifiers::NONE);
    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);

    let p = model.domain.file_transfers.get(&file_id).unwrap();
    assert!(p.status == TransferStatus::Active);

    let cmds = send_key(&mut model, KeyCode::Char('p'), KeyModifiers::NONE);
    let has_pause = cmds.iter().any(|c| {
        matches!(c, Cmd::Tox(ToxAction::FileControl(f, n, control))
        if *f == pk && *n == file_id && *control == toxcore::types::FileControl::Pause)
    });
    assert!(has_pause);

    // The worker confirms the pause.
    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecvControl(
            pk,
            file_id,
            toxcore::types::FileControl::Pause,
        )),
    );
    assert_eq!(
        model.domain.file_transfers.get(&file_id).unwrap().status,
        TransferStatus::Paused
    );

    let cmds = send_key(&mut model, KeyCode::Char('p'), KeyModifiers::NONE);
    let has_resume = cmds.iter().any(|c| {
        matches!(c, Cmd::Tox(ToxAction::FileControl(f, n, control))
        if *f == pk && *n == file_id && *control == toxcore::types::FileControl::Resume)
    });
    assert!(has_resume);
}

#[test]
fn test_change_dest_prefills_command() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, pk);

    update(
        &mut model,
        Msg::Tox(ToxEvent::FileRecv(
            pk,
            file_id,
            toxcore::types::FileKind::DATA,
            1024,
            "test.txt".to_string(),
        )),
    );
    model.set_active_window(1);
    send_key(&mut model, KeyCode::Esc, KeyModifiers::NONE);
    send_key(&mut model, KeyCode::Up, KeyModifiers::NONE);

    send_key(&mut model, KeyCode::Char('o'), KeyModifiers::NONE);

    assert_eq!(model.ui.ui_mode, UiMode::Chat);
    assert!(
        model
            .ui
            .input_state
            .text
            .starts_with(&format!("/file accept 01010101 {} test.txt", file_id))
    );
}

#[test]
fn test_outgoing_file_transfer_hides_path() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);

    add_test_friend(&mut model, pk);

    let full_path = "/home/user/documents/secret_plans.pdf";
    let file_id = FileId([100u8; 32]);

    let event = IOEvent::FileStarted(pk, file_id, full_path.into(), 1024);
    let _ = update(&mut model, Msg::IO(event));

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

    let progress = model.domain.file_transfers.get(&file_id).unwrap();
    assert_eq!(
        progress.filename, "secret_plans.pdf",
        "Progress should store only filename"
    );
}
