use toxcore::tox::{Address, FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::{FileId, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, Model};
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
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

#[test]
fn test_ignores_non_data_file_transfers() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, fid, pk);

    // Simulate Avatar transfer (kind = 1)
    let event = ToxEvent::FileRecv(
        fid,
        file_id,
        1, // Avatar
        1024,
        "avatar.png".to_string(),
    );

    let cmds = update(&mut model, Msg::Tox(event));

    // Should verify:
    // 1. Transfer NOT added to model
    assert!(!model.domain.file_transfers.contains_key(&file_id));

    // 2. CANCEL command sent
    let has_cancel = cmds.iter().any(|c| matches!(c, Cmd::Tox(ToxAction::FileControl(f, n, control))
        if *f == pk && *n == file_id && *control == toxcore::types::ToxFileControl::TOX_FILE_CONTROL_CANCEL));

    assert!(has_cancel, "Should send CANCEL for avatar transfer");
}

#[test]
fn test_accepts_data_file_transfers() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([101u8; 32]);

    add_test_friend(&mut model, fid, pk);

    // Simulate Data transfer (kind = 0)
    let event = ToxEvent::FileRecv(
        fid,
        file_id,
        0, // Data
        1024,
        "doc.pdf".to_string(),
    );

    let cmds = update(&mut model, Msg::Tox(event));

    // Should verify:
    // 1. Transfer ADDED to model
    assert!(model.domain.file_transfers.contains_key(&file_id));

    // 2. NO cancel command (it waits for user to accept)
    let has_cancel = cmds.iter().any(|c| {
        matches!(c, Cmd::Tox(ToxAction::FileControl(_, _, control))
        if *control == toxcore::types::ToxFileControl::TOX_FILE_CONTROL_CANCEL)
    });

    assert!(!has_cancel, "Should NOT auto-cancel data transfer");
}
