use toxcore::tox::Address;
use toxcore::tox::{FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::{FileId, MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, MessageContent as DomainContent, Model, WindowId};
use toxxi::msg::{Msg, ToxEvent};
use toxxi::update::update;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
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
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
}

#[test]
fn test_file_recv_adds_inline_message() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, fid, pk);

    let event = ToxEvent::FileRecv(fid, file_id, 0, 1024, "test.txt".to_string());
    let _cmds = update(&mut model, Msg::Tox(event));

    let window_id = WindowId::Friend(pk);
    let conv = model
        .domain
        .conversations
        .get(&window_id)
        .expect("Conversation not found");

    // Check if a message was added
    assert!(!conv.messages.is_empty(), "No message added on FileRecv");

    let last_msg = conv.messages.last().unwrap();

    match &last_msg.content {
        DomainContent::FileTransfer {
            name,
            size,
            file_id: f_id,
            ..
        } => {
            assert_eq!(name, "test.txt");
            assert_eq!(*size, 1024);
            assert_eq!(*f_id, Some(file_id));
        }
        _ => panic!(
            "Expected FileTransfer message content, got {:?}",
            last_msg.content
        ),
    }

    // Simulate sending a chunk
    let event = ToxEvent::FileChunkSent(fid, file_id, 0, 512);
    let _cmds = update(&mut model, Msg::Tox(event));

    let conv = model.domain.conversations.get(&window_id).unwrap();
    let last_msg = conv.messages.last().unwrap();
    if let DomainContent::FileTransfer { progress, .. } = &last_msg.content {
        assert_eq!(*progress, 0.5);
    } else {
        panic!("Expected FileTransfer content");
    }

    // Simulate finishing
    let event = toxxi::msg::IOEvent::FileFinished(pk, file_id, None);
    let _cmds = update(&mut model, Msg::IO(event));

    let conv = model.domain.conversations.get(&window_id).unwrap();
    let last_msg = conv.messages.last().unwrap();
    assert_eq!(last_msg.status, toxxi::model::MessageStatus::Received);
}

#[test]
fn test_file_cancel_updates_status() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, fid, pk);

    // Start transfer
    let event = ToxEvent::FileRecv(fid, file_id, 0, 1024, "test.txt".to_string());
    update(&mut model, Msg::Tox(event));

    // Cancel transfer
    let event = ToxEvent::FileRecvControl(
        fid,
        file_id,
        toxcore::types::ToxFileControl::TOX_FILE_CONTROL_CANCEL,
    );
    update(&mut model, Msg::Tox(event));

    let window_id = WindowId::Friend(pk);
    let conv = model.domain.conversations.get(&window_id).unwrap();
    let last_msg = conv.messages.last().unwrap();
    assert_eq!(last_msg.status, toxxi::model::MessageStatus::Failed);
}

#[test]
fn test_file_started_outgoing_adds_inline_message() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([200u8; 32]);

    add_test_friend(&mut model, fid, pk);

    let event = toxxi::msg::IOEvent::FileStarted(pk, file_id, "outgoing.pdf".to_string(), 2048);
    let _cmds = update(&mut model, Msg::IO(event));

    let window_id = WindowId::Friend(pk);
    let conv = model.domain.conversations.get(&window_id).unwrap();
    let last_msg = conv.messages.last().unwrap();

    assert!(last_msg.is_self);
    match &last_msg.content {
        DomainContent::FileTransfer {
            name,
            size,
            is_incoming,
            ..
        } => {
            assert_eq!(name, "outgoing.pdf");
            assert_eq!(*size, 2048);
            assert!(!*is_incoming);
        }
        _ => panic!("Expected FileTransfer content"),
    }
}

#[test]
fn test_game_invite_adds_inline_message() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);

    add_test_friend(&mut model, fid, pk);

    // Manually add a game invite until event support is implemented.
    let window_id = WindowId::Friend(pk);
    if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
        let internal_id = model.domain.next_internal_id;
        model.domain.next_internal_id.0 += 1;
        conv.messages.push(toxxi::model::Message {
            internal_id,
            sender: "Bob".to_string(),
            sender_pk: None,
            is_self: false,
            content: toxxi::model::MessageContent::GameInvite {
                game_type: "Chess".to_string(),
                challenger: "Bob".to_string(),
            },
            timestamp: model.time_provider.now_local(),
            status: toxxi::model::MessageStatus::Incoming,
            message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
            highlighted: false,
        });
    }

    let conv = model.domain.conversations.get(&window_id).unwrap();
    let last_msg = conv.messages.last().unwrap();

    match &last_msg.content {
        DomainContent::GameInvite {
            game_type,
            challenger,
        } => {
            assert_eq!(game_type, "Chess");
            assert_eq!(challenger, "Bob");
        }
        _ => panic!("Expected GameInvite content"),
    }
}

#[test]
fn test_multiple_concurrent_transfers_progress() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);

    add_test_friend(&mut model, fid, pk);

    // File 1
    let file1 = FileId([1u8; 32]);
    let event1 = ToxEvent::FileRecv(fid, file1, 0, 1000, "file1.bin".to_string());
    update(&mut model, Msg::Tox(event1));

    // File 2
    let file2 = FileId([2u8; 32]);
    let event2 = ToxEvent::FileRecv(fid, file2, 0, 2000, "file2.bin".to_string());
    update(&mut model, Msg::Tox(event2));

    // Update File 2
    let update2 = ToxEvent::FileChunkSent(fid, file2, 0, 1000);
    update(&mut model, Msg::Tox(update2));

    let window_id = WindowId::Friend(pk);
    let conv = model.domain.conversations.get(&window_id).unwrap();

    // File 1 (second to last message) should be at 0%
    if let DomainContent::FileTransfer { progress, name, .. } =
        &conv.messages[conv.messages.len() - 2].content
    {
        assert_eq!(name, "file1.bin");
        assert_eq!(*progress, 0.0);
    } else {
        panic!("Expected FileTransfer for file 1");
    }

    // File 2 (last message) should be at 50%
    if let DomainContent::FileTransfer { progress, name, .. } =
        &conv.messages.last().unwrap().content
    {
        assert_eq!(name, "file2.bin");
        assert_eq!(*progress, 0.5);
    } else {
        panic!("Expected FileTransfer for file 2");
    }
}
