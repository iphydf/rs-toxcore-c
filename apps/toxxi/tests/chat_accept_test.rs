use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use toxcore::types::{FileId, MessageType, PublicKey};
use toxxi::model::{FileTransferProgress, MessageStatus, TransferStatus, UiMode, WindowId};
use toxxi::msg::{Cmd, IOAction};
use toxxi_testing::add_test_friend;

fn setup_test_env() -> (toxxi::model::Model, ()) {
    use toxcore::tox::{Address, UserStatus};
    use toxxi::config::Config;
    use toxxi::model::DomainState;

    let pk = PublicKey([0; 32]);
    let tox_id = Address::from_public_key(pk, 0);
    let domain = DomainState::new(
        tox_id,
        "Test User".to_string(),
        "".to_string(),
        UserStatus::None,
    );
    let config = Config::default();
    let model = toxxi::model::Model::new(domain, config.clone(), config.clone());

    (model, ())
}

#[tokio::test]
async fn test_chat_window_file_accept() {
    let (mut model, _ctx) = setup_test_env();

    // An incoming file transfer and its chat message.
    let pk = PublicKey([1u8; 32]);
    let file = FileId([0u8; 32]);

    add_test_friend(&mut model, pk);

    let win_idx = model
        .ui
        .window_ids
        .iter()
        .position(|&w| w == WindowId::Friend(pk))
        .unwrap();
    model.set_active_window(win_idx);

    model.domain.file_transfers.insert(
        file,
        FileTransferProgress {
            filename: "chat_accept.txt".to_string(),
            total_size: 2048,
            transferred: 0,
            is_receiving: true,
            status: TransferStatus::Active,
            speed: 0.0,
            last_update: std::time::Instant::now(),
            last_transferred: 0,
            friend_pk: pk,
        },
    );

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
                blob: None,
            },
            timestamp: model.time_provider.now_local(),
            status: MessageStatus::Incoming,
            message_type: MessageType::Normal,
            highlighted: false,
            privately: None,
        });
    }

    // Select the message in navigation mode.
    model.ui.ui_mode = UiMode::Navigation;
    let state = model
        .ui
        .window_state
        .entry(WindowId::Friend(pk))
        .or_default();
    state.msg_list_state.selected_index = Some(0);

    let cmds = toxxi::update::update(
        &mut model,
        toxxi::msg::Msg::Input(ratatui::crossterm::event::Event::Key(KeyEvent::new(
            KeyCode::Char('a'),
            KeyModifiers::NONE,
        ))),
    );

    // The I/O thread opens the download, then starts it.
    let has_io = cmds.iter().any(|c| {
        matches!(c, Cmd::IO(IOAction::OpenFileForReceiving(f, n, name, _))
        if *f == pk && *n == file && name == "chat_accept.txt")
    });
    assert!(
        has_io,
        "Should generate OpenFileForReceiving when pressing 'a' in Chat"
    );
}
