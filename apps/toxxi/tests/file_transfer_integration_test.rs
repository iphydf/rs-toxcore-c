use toxcore::types::{FileId, PublicKey};
use toxxi::model::{MessageContent as DomainContent, WindowId};
use toxxi::msg::{Msg, ToxEvent};
use toxxi::update::update;
use toxxi_testing::{add_test_friend, create_test_model};

#[test]
fn test_file_recv_adds_inline_message() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, pk);

    let event = ToxEvent::FileRecv(
        pk,
        file_id,
        toxcore::types::FileKind::DATA,
        1024,
        "test.txt".to_string(),
    );
    let _cmds = update(&mut model, Msg::Tox(event));

    let window_id = WindowId::Friend(pk);
    let conv = model
        .domain
        .conversations
        .get(&window_id)
        .expect("Conversation not found");

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

    let event = ToxEvent::FileChunkSent(pk, file_id, 0, 512);
    let _cmds = update(&mut model, Msg::Tox(event));

    let conv = model.domain.conversations.get(&window_id).unwrap();
    let last_msg = conv.messages.last().unwrap();
    if let DomainContent::FileTransfer { progress, .. } = &last_msg.content {
        assert_eq!(*progress, 0.5);
    } else {
        panic!("Expected FileTransfer content");
    }

    let event = toxxi::msg::IOEvent::FileFinished(pk, file_id, None);
    let _cmds = update(&mut model, Msg::IO(event));

    let conv = model.domain.conversations.get(&window_id).unwrap();
    let last_msg = conv.messages.last().unwrap();
    assert_eq!(last_msg.status, toxxi::model::MessageStatus::Received);
}

#[test]
fn test_file_cancel_updates_status() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([100u8; 32]);

    add_test_friend(&mut model, pk);

    let event = ToxEvent::FileRecv(
        pk,
        file_id,
        toxcore::types::FileKind::DATA,
        1024,
        "test.txt".to_string(),
    );
    update(&mut model, Msg::Tox(event));

    let event = ToxEvent::FileRecvControl(pk, file_id, toxcore::types::FileControl::Cancel);
    update(&mut model, Msg::Tox(event));

    let window_id = WindowId::Friend(pk);
    let conv = model.domain.conversations.get(&window_id).unwrap();
    let last_msg = conv.messages.last().unwrap();
    assert_eq!(last_msg.status, toxxi::model::MessageStatus::Failed);
}

#[test]
fn test_file_started_outgoing_adds_inline_message() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file_id = FileId([200u8; 32]);

    add_test_friend(&mut model, pk);

    let event = toxxi::msg::IOEvent::FileStarted(pk, file_id, "outgoing.pdf".into(), 2048);
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
fn test_multiple_concurrent_transfers_progress() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);

    add_test_friend(&mut model, pk);

    let file1 = FileId([1u8; 32]);
    let event1 = ToxEvent::FileRecv(
        pk,
        file1,
        toxcore::types::FileKind::DATA,
        1000,
        "file1.bin".to_string(),
    );
    update(&mut model, Msg::Tox(event1));

    let file2 = FileId([2u8; 32]);
    let event2 = ToxEvent::FileRecv(
        pk,
        file2,
        toxcore::types::FileKind::DATA,
        2000,
        "file2.bin".to_string(),
    );
    update(&mut model, Msg::Tox(event2));

    let update2 = ToxEvent::FileChunkSent(pk, file2, 0, 1000);
    update(&mut model, Msg::Tox(update2));

    let window_id = WindowId::Friend(pk);
    let conv = model.domain.conversations.get(&window_id).unwrap();

    // File 1 (second to last message) is at 0%.
    if let DomainContent::FileTransfer { progress, name, .. } =
        &conv.messages[conv.messages.len() - 2].content
    {
        assert_eq!(name, "file1.bin");
        assert_eq!(*progress, 0.0);
    } else {
        panic!("Expected FileTransfer for file 1");
    }

    // File 2 (last message) is at 50%.
    if let DomainContent::FileTransfer { progress, name, .. } =
        &conv.messages.last().unwrap().content
    {
        assert_eq!(name, "file2.bin");
        assert_eq!(*progress, 0.5);
    } else {
        panic!("Expected FileTransfer for file 2");
    }
}
