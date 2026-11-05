use toxcore::tox::GroupNumber;
use toxcore::types::{GroupChatId, MessageType};
use toxxi::model::{InternalMessageId, MessageStatus, WindowId};
use toxxi::msg::{Cmd, IOAction, Msg, ToxEvent};
use toxxi::sync::event::{Content, Event};
use toxxi::testing::TestContext;
use toxxi::update::update;

#[test]
fn test_group_message_sent_persistence() {
    let ctx = TestContext::new();
    let mut model = ctx.create_model();

    let group_number = GroupNumber(0);
    let chat_id = GroupChatId([1u8; 32]);
    let internal_id = InternalMessageId(123);

    // Setup session mapping
    model.session.group_numbers.insert(group_number, chat_id);
    model.ensure_group_window(chat_id);

    // Add a pending message to the conversation
    {
        let win_id = WindowId::Group(chat_id);
        let me = model.domain.self_public_key();
        let conv = model.domain.conversations.get_mut(&win_id).unwrap();
        conv.messages.push(toxxi::model::Message {
            internal_id,
            sender: "Me".to_string(),
            sender_pk: Some(me),
            is_self: true,
            content: toxxi::model::MessageContent::Text("Hello".to_string()),
            timestamp: chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap()),
            status: MessageStatus::Pending,
            message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
            highlighted: false,
            privately: None,
        });
    }

    // 1. Simulate GroupMessageSent event from Tox
    let msg = Msg::Tox(ToxEvent::GroupMessageSent(group_number, internal_id));
    let cmds = update(&mut model, msg);

    // 2. Verify that the message status was updated in memory
    let win_id = WindowId::Group(chat_id);
    let conv = model.domain.conversations.get(&win_id).unwrap();
    assert_eq!(conv.messages[0].status, MessageStatus::Received);

    // 3. Verify that the status change is persisted
    assert!(
        cmds.iter().any(|cmd| matches!(cmd, Cmd::IO(IOAction::AppendEvents(records, _))
            if records.iter().any(|r| matches!(Event::decode(r), Ok(Event { content: Content::Sent { .. }, .. }))))),
        "Marking a group message as sent should persist the status update"
    );
}
