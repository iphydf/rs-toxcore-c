use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use toxcore::tox::{FriendNumber, ToxConnection};
use toxcore::types::{FileId, MessageType, PublicKey, ToxFileControl};
use toxxi::model::{
    FileTransferProgress, FriendInfo, MessageStatus, TransferStatus, UiMode, WindowId,
};
use toxxi::msg::{Cmd, IOAction, ToxAction};

// Helper to setup a basic test environment
fn setup_test_env() -> (toxxi::model::Model, ()) {
    use toxcore::tox::{Address, ToxUserStatus};
    use toxxi::config::Config;
    use toxxi::model::DomainState;

    // Create a dummy model
    let pk = PublicKey([0; 32]);
    let tox_id = Address::from_public_key(pk, 0);
    let self_pk = tox_id.public_key();
    let domain = DomainState::new(
        tox_id,
        self_pk,
        "Test User".to_string(),
        "".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let config = Config::default();
    let model = toxxi::model::Model::new(domain, config.clone(), config.clone());

    (model, ())
}

fn add_test_friend(model: &mut toxxi::model::Model, fid: FriendNumber, pk: PublicKey) {
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

#[tokio::test]
async fn test_chat_window_file_accept() {
    let (mut model, _ctx) = setup_test_env();

    // 1. Setup: Simulate an incoming file transfer and a corresponding chat message
    let friend = FriendNumber(0);
    let pk = PublicKey([1u8; 32]);
    let file = FileId([0u8; 32]);

    add_test_friend(&mut model, friend, pk);

    // Find the index of the new window
    let win_idx = model
        .ui
        .window_ids
        .iter()
        .position(|&w| w == WindowId::Friend(pk))
        .unwrap();
    model.set_active_window(win_idx);

    // Add the file transfer progress state
    model.domain.file_transfers.insert(
        file,
        FileTransferProgress {
            filename: "chat_accept.txt".to_string(),
            total_size: 2048,
            transferred: 0,
            is_receiving: true,
            status: TransferStatus::Active,
            file_kind: 0,
            file_path: None,
            speed: 0.0,
            last_update: std::time::Instant::now(),
            last_transferred: 0,
            friend_pk: pk,
        },
    );

    // Add the chat message representing this transfer
    if let Some(conv) = model.domain.conversations.get_mut(&WindowId::Friend(pk)) {
        conv.messages.push(toxxi::model::Message {
            internal_id: model.domain.next_internal_id,
            sender: "Friend 0".to_string(),
            sender_pk: None,
            is_self: false,
            content: toxxi::model::MessageContent::FileTransfer {
                file_id: Some(file),
                name: "chat_accept.txt".to_string(),
                size: 2048,
                progress: 0.0,
                speed: "0 B/s".to_string(),
                is_incoming: true,
            },
            timestamp: model.time_provider.now_local(),
            status: MessageStatus::Incoming,
            message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
            highlighted: false,
        });
    }

    // 2. Action: Switch to Navigation Mode and Select the Message
    model.ui.ui_mode = UiMode::Navigation;
    let state = model
        .ui
        .window_state
        .entry(WindowId::Friend(pk))
        .or_default();
    state.msg_list_state.selected_index = Some(0); // Select the first (and only) message

    // 3. Action: Press 'a' to accept
    let cmds = toxxi::update::update(
        &mut model,
        toxxi::msg::Msg::Input(ratatui::crossterm::event::Event::Key(KeyEvent::new(
            KeyCode::Char('a'),
            KeyModifiers::NONE,
        ))),
    );

    // 4. Verify: We should get IOAction::OpenFileForReceiving and ToxAction::FileControl(Resume)
    let has_io = cmds.iter().any(|c| {
        matches!(c, Cmd::IO(IOAction::OpenFileForReceiving(f, n, name, _))
        if *f == pk && *n == file && name == "chat_accept.txt")
    });
    let has_tox = cmds.iter().any(|c| {
        matches!(c, Cmd::Tox(ToxAction::FileControl(f, n, ToxFileControl::TOX_FILE_CONTROL_RESUME))
        if *f == pk && *n == file)
    });

    assert!(
        has_io,
        "Should generate OpenFileForReceiving when pressing 'a' in Chat"
    );
    assert!(
        has_tox,
        "Should generate FileControl Resume when pressing 'a' in Chat"
    );
}
