use std::fs;
use toxcore::tox::{GroupNumber, ToxUserStatus};
use toxcore::types::{Address, ChatId, MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{MessageStatus, ToxSelfInfo, WindowId, load_or_initialize};
use toxxi::msg::{Cmd, Msg, SystemEvent, ToxAction};
use toxxi::update::update;

#[tokio::test]
async fn test_resend_pending_message_after_reboot() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path();

    let self_pk = PublicKey([0u8; 32]);
    let group_id = ChatId([4u8; 32]);
    let tox_id = Address([0u8; 38]);

    // 1. Create a log file with an outgoing PENDING message
    let logs_dir = config_dir.join("logs");
    fs::create_dir_all(&logs_dir).unwrap();
    let log_path = logs_dir.join(format!(
        "group_{}.jsonl",
        toxxi::utils::encode_hex(&group_id.0)
    ));

    let timestamp = chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap());
    let internal_id = toxxi::model::InternalMessageId(42);

    let msg = toxxi::model::Message {
        internal_id,
        sender: "Me".to_string(),
        sender_pk: Some(self_pk),
        is_self: true,
        content: toxxi::model::MessageContent::Text("Message to be resent".to_string()),
        timestamp,
        status: MessageStatus::Pending,
        message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
        highlighted: false,
    };

    let json = serde_json::to_string(&msg).unwrap();
    fs::write(log_path, format!("{}\n", json)).unwrap();

    // 2. Re-initialize the model
    let self_info = ToxSelfInfo {
        tox_id,
        public_key: self_pk,
        name: "Me".to_string(),
        status_msg: "".to_string(),
        status_type: ToxUserStatus::TOX_USER_STATUS_NONE,
    };

    let mut reloaded_model = load_or_initialize(
        config_dir,
        self_info,
        vec![],
        vec![toxxi::model::GroupReconcileInfo {
            number: GroupNumber(0),
            chat_id: group_id,
            name: Some("Test Group".to_string()),
            role: None,
            self_name: None,
        }],
        vec![],
        Config::default(),
        Config::default(),
    );

    // Verify it's loaded as Pending
    let win_id = WindowId::Group(group_id);
    {
        let conv = reloaded_model.domain.conversations.get(&win_id).unwrap();
        assert_eq!(conv.messages.len(), 1);
        assert_eq!(conv.messages[0].status, MessageStatus::Pending);
    }

    // 3. Trigger ticks to trigger resend logic (25 ticks)
    let mut all_cmds = Vec::new();
    for _ in 0..25 {
        let cmds = update(&mut reloaded_model, Msg::System(SystemEvent::Tick));
        all_cmds.extend(cmds);
    }

    // 4. Verify that a resend command was generated
    let resend_cmd = all_cmds.iter().find(|cmd| {
        matches!(cmd, Cmd::Tox(ToxAction::SendGroupMessage(id, _, content, iid))
            if id == &group_id && content == "Message to be resent" && iid == &internal_id)
    });

    assert!(
        resend_cmd.is_some(),
        "Resend command should have been generated after 25 ticks"
    );

    // Verify message status updated to Sending
    let conv = reloaded_model.domain.conversations.get(&win_id).unwrap();
    assert_eq!(conv.messages[0].status, MessageStatus::Sending);
}
