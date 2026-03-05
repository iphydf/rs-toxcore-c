use std::fs;
use toxcore::tox::{FriendNumber, GroupNumber, ToxUserStatus};
use toxcore::types::{Address, MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, ToxSelfInfo, WindowId, load_or_initialize, save_state};

#[tokio::test]
async fn test_history_loading_on_startup() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path();

    let self_pk = PublicKey([0u8; 32]);
    let friend_pk = PublicKey([1u8; 32]);
    let tox_id = Address([0u8; 38]);

    // 1. Create a log file with some messages
    let logs_dir = config_dir.join("logs");
    fs::create_dir_all(&logs_dir).unwrap();
    let log_path = logs_dir.join(format!(
        "friend_{}.jsonl",
        toxxi::utils::encode_hex(&friend_pk.0)
    ));

    let msg = toxxi::model::Message {
        internal_id: toxxi::model::InternalMessageId(0),
        sender: "Friend".to_string(),
        sender_pk: Some(friend_pk),
        is_self: false,
        content: toxxi::model::MessageContent::Text("Historical Message".to_string()),
        timestamp: chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap()),
        status: toxxi::model::MessageStatus::Incoming,
        message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
        highlighted: false,
    };

    let json = serde_json::to_string(&msg).unwrap();
    fs::write(log_path, format!("{}\n", json)).unwrap();

    // 2. Create a state.json that has this friend window
    let domain = DomainState::new(
        tox_id,
        self_pk,
        "Me".to_string(),
        "".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, Config::default(), Config::default());
    model.ensure_friend_window(friend_pk);
    save_state(config_dir, &model).unwrap();

    // 3. Re-initialize the model (as the app does on startup)
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
        vec![(
            FriendNumber(0),
            toxxi::model::FriendInfo {
                name: "Friend".to_string(),
                public_key: Some(friend_pk),
                status_message: "".to_string(),
                connection: toxcore::tox::ToxConnection::TOX_CONNECTION_NONE,
                last_sent_message_id: None,
                last_read_receipt: None,
                is_typing: false,
            },
        )],
        vec![],
        vec![],
        Config::default(),
        Config::default(),
    );

    // 4. Verify that the message was loaded into the conversation
    let win_id = WindowId::Friend(friend_pk);
    let conv = reloaded_model
        .domain
        .conversations
        .get(&win_id)
        .expect("Conversation should exist");

    assert_eq!(
        conv.messages[0].content.as_text().unwrap(),
        "Historical Message"
    );
}

#[tokio::test]
async fn test_outgoing_pending_message_is_marked_received_on_load() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path();

    let self_pk = PublicKey([0u8; 32]);
    let group_id = toxcore::types::GroupChatId([2u8; 32]);
    let tox_id = Address([0u8; 38]);

    // 1. Create a log file with an outgoing PENDING message
    let logs_dir = config_dir.join("logs");
    fs::create_dir_all(&logs_dir).unwrap();
    let log_path = logs_dir.join(format!(
        "group_{}.jsonl",
        toxxi::utils::encode_hex(&group_id.0)
    ));

    let msg = toxxi::model::Message {
        internal_id: toxxi::model::InternalMessageId(0),
        sender: "Me".to_string(),
        sender_pk: Some(self_pk),
        is_self: true,
        content: toxxi::model::MessageContent::Text("Outgoing Pending Message".to_string()),
        timestamp: chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap()),
        status: toxxi::model::MessageStatus::Pending,
        message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
        highlighted: false,
    };

    let json_pending = serde_json::to_string(&msg).unwrap();

    let mut msg_received = msg.clone();
    msg_received.status = toxxi::model::MessageStatus::Received;
    let json_received = serde_json::to_string(&msg_received).unwrap();

    fs::write(log_path, format!("{}\n{}\n", json_pending, json_received)).unwrap();

    // 2. Re-initialize the model
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

    // 3. Verify that the message was deduplicated and has the latest status
    let win_id = WindowId::Group(group_id);
    let conv = reloaded_model
        .domain
        .conversations
        .get(&win_id)
        .expect("Conversation should exist");

    assert_eq!(
        conv.messages.len(),
        1,
        "Should have deduplicated the message"
    );
    assert_eq!(
        conv.messages[0].content.as_text().unwrap(),
        "Outgoing Pending Message"
    );
    assert_eq!(
        conv.messages[0].status,
        toxxi::model::MessageStatus::Received
    );
}

#[tokio::test]
async fn test_truly_pending_message_is_preserved_on_load() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path();

    let self_pk = PublicKey([0u8; 32]);
    let group_id = toxcore::types::GroupChatId([3u8; 32]);
    let tox_id = Address([0u8; 38]);

    let logs_dir = config_dir.join("logs");
    fs::create_dir_all(&logs_dir).unwrap();
    let log_path = logs_dir.join(format!(
        "group_{}.jsonl",
        toxxi::utils::encode_hex(&group_id.0)
    ));

    let msg = toxxi::model::Message {
        internal_id: toxxi::model::InternalMessageId(10),
        sender: "Me".to_string(),
        sender_pk: Some(self_pk),
        is_self: true,
        content: toxxi::model::MessageContent::Text("Truly Pending Message".to_string()),
        timestamp: chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap()),
        status: toxxi::model::MessageStatus::Pending,
        message_type: MessageType::TOX_MESSAGE_TYPE_NORMAL,
        highlighted: false,
    };

    let json = serde_json::to_string(&msg).unwrap();
    fs::write(log_path, format!("{}\n", json)).unwrap();

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
    let conv = reloaded_model
        .domain
        .conversations
        .get(&win_id)
        .expect("Conversation should exist");

    assert_eq!(conv.messages.len(), 1);
    assert_eq!(
        conv.messages[0].status,
        toxxi::model::MessageStatus::Pending,
        "Truly pending messages should remain pending"
    );
}
