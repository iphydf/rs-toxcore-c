use std::fs;
use toxcore::tox::{GroupNumber, ToxUserStatus};
use toxcore::types::{Address, ChatId, MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{MessageStatus, ToxSelfInfo, WindowId, load_or_initialize};

#[tokio::test]
async fn test_load_corrupted_log_recovery() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path();

    let self_pk = PublicKey([0u8; 32]);
    let group_id = ChatId([4u8; 32]);
    let tox_id = Address([0u8; 38]);

    let logs_dir = config_dir.join("logs");
    fs::create_dir_all(&logs_dir).unwrap();
    let log_path = logs_dir.join(format!(
        "group_{}.jsonl",
        toxxi::utils::encode_hex(&group_id.0)
    ));

    let timestamp = chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap());
    let internal_id = toxxi::model::InternalMessageId(42);

    let msg_pending = toxxi::model::Message {
        internal_id,
        sender: "Me".to_string(),
        sender_pk: Some(self_pk),
        is_self: true,
        content: toxxi::model::MessageContent::Text("Corrupted message".to_string()),
        timestamp,
        status: MessageStatus::Pending,
        message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
        highlighted: false,
    };

    let mut msg_received = msg_pending.clone();
    msg_received.status = MessageStatus::Received;

    let json_pending = serde_json::to_string(&msg_pending).unwrap();
    let json_received = serde_json::to_string(&msg_received).unwrap();

    // Create a corrupted line: two JSON objects smashed together
    fs::write(log_path, format!("{}{}\n", json_pending, json_received)).unwrap();

    let self_info = ToxSelfInfo {
        tox_id,
        public_key: self_pk,
        name: "Me".to_string(),
        status_msg: "".to_string(),
        status_type: ToxUserStatus::TOX_USER_STATUS_NONE,
    };

    let reloaded_model = load_or_initialize(
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

    let win_id = WindowId::Group(group_id);
    let conv = reloaded_model.domain.conversations.get(&win_id).unwrap();

    assert_eq!(conv.messages.len(), 1, "Should have loaded one message");
    assert_eq!(
        conv.messages[0].status,
        MessageStatus::Received,
        "Should have recovered the 'Received' status despite log corruption"
    );
}
