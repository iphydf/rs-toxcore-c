use toxcore::types::{FileId, MessageType, PublicKey};
use toxxi::model::{
    FileTransferProgress, InternalMessageId, MessageStatus, TransferStatus, WindowId,
};
use toxxi::msg::{Cmd, IOAction, IOEvent, Msg};
use toxxi::sync::event::{Content, Event};
use toxxi::update::update;
use toxxi_testing::TestContext;

fn recorded(cmds: &[Cmd], f: impl Fn(&Content) -> bool) -> bool {
    cmds.iter().any(|cmd| match cmd {
        Cmd::IO(IOAction::AppendEvents(records, _)) => records
            .iter()
            .any(|r| Event::decode(r).is_ok_and(|event| f(&event.content))),
        _ => false,
    })
}

#[test]
fn test_file_transfer_status_persistence() {
    let ctx = TestContext::new();
    let mut model = ctx.create_model();

    let friend_pk = PublicKey([1u8; 32]);
    let file_id = FileId([2u8; 32]);
    let internal_id = InternalMessageId(456);

    model.ensure_friend_window(friend_pk);
    let win_id = WindowId::Friend(friend_pk);

    {
        let conv = model.domain.conversations.get_mut(&win_id).unwrap();
        conv.messages.push(toxxi::model::Message {
            internal_id,
            sender: "Alice".to_string(),
            sender_pk: Some(friend_pk),
            is_self: false,
            content: toxxi::model::MessageContent::FileTransfer {
                file_id: Some(file_id),
                name: "test.txt".to_string(),
                size: 1024,
                progress: 0.0,
                speed: "0 B/s".to_string(),
                is_incoming: true,
                blob: None,
            },
            timestamp: chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap()),
            status: MessageStatus::Incoming,
            message_type: MessageType::Normal,
            highlighted: false,
            privately: None,
        });

        // Some handlers look the transfer up in the domain state.
        model.domain.file_transfers.insert(
            file_id,
            FileTransferProgress {
                filename: "test.txt".to_string(),
                total_size: 1024,
                transferred: 0,
                is_receiving: true,
                status: TransferStatus::Active,
                speed: 0.0,
                last_update: model.time_provider.now(),
                last_transferred: 0,
                friend_pk,
            },
        );
    }

    let msg = Msg::IO(IOEvent::FileFinished(friend_pk, file_id, None));
    let cmds = update(&mut model, msg);

    {
        let conv = model.domain.conversations.get(&win_id).unwrap();
        assert_eq!(conv.messages[0].status, MessageStatus::Received);
    }

    assert!(
        recorded(&cmds, |content| matches!(
            content,
            Content::FileEnded { ok: true, .. }
        )),
        "File completion status should be persisted"
    );

    // A failed download.
    let err_internal_id = InternalMessageId(457);
    let err_file_id = FileId([3u8; 32]);
    {
        let conv = model.domain.conversations.get_mut(&win_id).unwrap();
        conv.messages.push(toxxi::model::Message {
            internal_id: err_internal_id,
            sender: "Alice".to_string(),
            sender_pk: Some(friend_pk),
            is_self: false,
            content: toxxi::model::MessageContent::FileTransfer {
                file_id: Some(err_file_id),
                name: "error.txt".to_string(),
                size: 1024,
                progress: 0.0,
                speed: "0 B/s".to_string(),
                is_incoming: true,
                blob: None,
            },
            timestamp: chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap()),
            status: MessageStatus::Incoming,
            message_type: MessageType::Normal,
            highlighted: false,
            privately: None,
        });
        model.domain.file_transfers.insert(
            err_file_id,
            FileTransferProgress {
                filename: "error.txt".to_string(),
                total_size: 1024,
                transferred: 0,
                is_receiving: true,
                status: TransferStatus::Active,
                speed: 0.0,
                last_update: model.time_provider.now(),
                last_transferred: 0,
                friend_pk,
            },
        );
    }

    let msg = Msg::IO(IOEvent::FileError(
        friend_pk,
        err_file_id,
        "disk full".to_string(),
    ));
    let cmds = update(&mut model, msg);

    assert!(
        recorded(&cmds, |content| matches!(
            content,
            Content::FileEnded { ok: false, .. }
        )),
        "File error status should be persisted"
    );
}
