use std::{env, fs};
use toxcore::tox::{Address, ConferenceNumber, Connection, GroupNumber, UserStatus};
use toxxi_testing::create_test_model;

use toxcore::types::{ConferenceId, GroupChatId, MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{
    ConferenceReconcileInfo, ConsoleMessageType, GroupReconcileInfo, MAX_CONSOLE_MESSAGES,
    MessageContent, MessageStatus, TransferStatus, WindowId, save_state,
};
use toxxi::utils::decode_hex;

#[test]
fn test_window_navigation() {
    let mut model = create_test_model();

    assert_eq!(model.ui.active_window_index, 0);
    assert_eq!(model.ui.window_ids, vec![WindowId::Console]);

    let pk1 = PublicKey([1u8; 32]);
    let pk2 = PublicKey([2u8; 32]);
    model.domain.friends.insert(
        pk1,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk1),
            status_message: "".to_string(),
            connection: Connection::None,
            is_typing: false,
        },
    );
    model.domain.friends.insert(
        pk2,
        toxxi::model::FriendInfo {
            name: "Friend 2".to_string(),
            public_key: Some(pk2),
            status_message: "".to_string(),
            connection: Connection::None,
            is_typing: false,
        },
    );

    // Adding friends creates their windows.
    model.ensure_friend_window(pk1);
    model.ensure_friend_window(pk2);

    assert_eq!(
        model.ui.window_ids,
        vec![
            WindowId::Console,
            WindowId::Friend(pk1),
            WindowId::Friend(pk2)
        ]
    );

    model.set_active_window(1);
    assert_eq!(model.ui.active_window_index, 1);

    model.set_active_window(2);
    assert_eq!(model.ui.active_window_index, 2);

    model.set_active_window(0);
    assert_eq!(model.ui.active_window_index, 0);
}

#[test]
fn test_console_keeps_the_newest_messages() {
    let mut model = create_test_model();
    for i in 0..=MAX_CONSOLE_MESSAGES {
        model.add_console_message(ConsoleMessageType::Info, i.to_string());
    }
    let console = &model.domain.console_messages;
    assert_eq!(console.len(), MAX_CONSOLE_MESSAGES);
    assert_eq!(
        console.last().unwrap().content.as_text(),
        Some(MAX_CONSOLE_MESSAGES.to_string().as_str())
    );
}

#[test]
fn test_unread_count() {
    let mut model = create_test_model();
    let pk1 = PublicKey([1u8; 32]);
    model.domain.friends.insert(
        pk1,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk1),
            status_message: "".to_string(),
            connection: Connection::None,
            is_typing: false,
        },
    );

    model.add_friend_message(pk1, MessageType::Normal, "msg 1".to_string());

    let window_id = WindowId::Friend(pk1);
    assert_eq!(
        model.ui.window_state.get(&window_id).unwrap().unread_count,
        1
    );

    model.add_friend_message(pk1, MessageType::Normal, "msg 2".to_string());
    assert_eq!(
        model.ui.window_state.get(&window_id).unwrap().unread_count,
        2
    );

    model.set_active_window(1);
    assert_eq!(
        model.ui.window_state.get(&window_id).unwrap().unread_count,
        0
    );

    // A new message in the active window isn't unread.
    model.add_friend_message(pk1, MessageType::Normal, "msg 3".to_string());
    assert_eq!(
        model.ui.window_state.get(&window_id).unwrap().unread_count,
        0
    );
}

#[test]
fn test_config_requires_restart() {
    let cfg1 = Config::default();
    let mut cfg2 = cfg1.clone();

    assert!(!cfg1.requires_restart(&cfg2));

    cfg2.ipv6_enabled = !cfg1.ipv6_enabled;
    assert!(cfg1.requires_restart(&cfg2));

    cfg2 = cfg1.clone();
    cfg2.start_port += 1;
    assert!(cfg1.requires_restart(&cfg2));
}

#[test]
fn test_friend_message_attribution() {
    let mut model = create_test_model();
    let pk1 = PublicKey([1u8; 32]);
    model.domain.friends.insert(
        pk1,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk1),
            status_message: "".to_string(),
            connection: Connection::None,
            is_typing: false,
        },
    );

    model.add_friend_message(pk1, MessageType::Normal, "incoming".to_string());
    let window_id = WindowId::Friend(pk1);
    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(conv.messages.len(), 1);
    assert_eq!(conv.messages[0].sender, "Friend 1");
    assert_eq!(
        conv.messages[0].content,
        MessageContent::Text("incoming".to_string())
    );
    assert_eq!(conv.messages[0].status, MessageStatus::Incoming);

    model.add_outgoing_friend_message(pk1, MessageType::Normal, "outgoing".to_string());
    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(conv.messages.len(), 2);
    assert_eq!(conv.messages[1].sender, "Tester");
    assert_eq!(
        conv.messages[1].content,
        MessageContent::Text("outgoing".to_string())
    );
    assert_eq!(conv.messages[1].status, MessageStatus::Pending);
}

#[test]
fn test_utils_decode_hex() {
    assert_eq!(decode_hex("4142"), Some(vec![0x41, 0x42]));
    assert_eq!(decode_hex("414"), None); // Odd length
    assert_eq!(decode_hex("ZZ"), None); // Invalid hex
    assert_eq!(decode_hex("aéa"), None); // Not ASCII
    assert_eq!(decode_hex("+f"), None); // A sign isn't a digit
}

#[test]
fn test_load_or_initialize_profile_switch() {
    let temp_dir = env::temp_dir().join(format!(
        "toxxi_test_load_init_switch_{}",
        rand::random::<u32>()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let config = Config::default();
    let addr1 = Address([1u8; 38]);
    let addr2 = Address([2u8; 38]);

    let model1 = toxxi::model::initialize_model(
        toxxi::model::ToxSelfInfo {
            tox_id: addr1,
            name: "P1".to_string(),
            status_msg: "S1".to_string(),
            status_type: UserStatus::None,
        },
        vec![],
        vec![],
        vec![],
        config.clone(),
        config.clone(),
    );
    save_state(&temp_dir, &model1).unwrap();

    let model2 = toxxi::model::load_or_initialize(
        &temp_dir,
        toxxi::model::ToxSelfInfo {
            tox_id: addr2,
            name: "P2".to_string(),
            status_msg: "S2".to_string(),
            status_type: UserStatus::None,
        },
        vec![],
        vec![],
        vec![],
        config.clone(),
        config,
    );

    // It ignored profile 1's state and started fresh.
    assert_eq!(model2.domain.tox_id, addr2);
    assert_eq!(model2.domain.self_name, "P2");

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_load_or_initialize_new_nospam() {
    let temp_dir = env::temp_dir().join(format!(
        "toxxi_test_load_init_nospam_{}",
        rand::random::<u32>()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let config = Config::default();
    let pk = PublicKey([1u8; 32]);
    let self_info = |nospam| toxxi::model::ToxSelfInfo {
        tox_id: Address::from_public_key(pk, nospam),
        name: "P".to_string(),
        status_msg: "S".to_string(),
        status_type: UserStatus::None,
    };

    let mut model = toxxi::model::initialize_model(
        self_info(1),
        vec![],
        vec![],
        vec![],
        config.clone(),
        config.clone(),
    );
    model.ui.input_history.push("/nospam".to_string());
    save_state(&temp_dir, &model).unwrap();

    // The same profile, with a new nospam saved before the state was.
    let model = toxxi::model::load_or_initialize(
        &temp_dir,
        self_info(2),
        vec![],
        vec![],
        vec![],
        config.clone(),
        config,
    );

    assert_eq!(model.ui.input_history, vec!["/nospam".to_string()]);
    assert_eq!(model.domain.tox_id, Address::from_public_key(pk, 2));

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_load_corrupt_state() {
    let temp_dir =
        env::temp_dir().join(format!("toxxi_test_load_corrupt_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();

    let state_path = temp_dir.join("state.json");
    fs::write(&state_path, "this is not json").unwrap();

    let config = Config::default();
    let addr = Address([0u8; 38]);

    let model = toxxi::model::load_or_initialize(
        &temp_dir,
        toxxi::model::ToxSelfInfo {
            tox_id: addr,
            name: "P".to_string(),
            status_msg: "S".to_string(),
            status_type: UserStatus::None,
        },
        vec![],
        vec![],
        vec![],
        config.clone(),
        config,
    );

    assert_eq!(model.domain.tox_id, addr);
    assert!(!model.domain.console_messages.is_empty());
    let error_found = model.domain.console_messages.iter().any(|m| {
        matches!(m.msg_type, ConsoleMessageType::Error)
            && m.content
                .as_text()
                .unwrap()
                .contains("Failed to parse state file")
    });
    assert!(
        error_found,
        "Expected error message not found in console messages"
    );

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_initialize_model_preserves_default_names() {
    let config = Config::default();
    let addr = Address([0u8; 38]);

    // Tox starts with empty names.
    let groups = vec![GroupReconcileInfo {
        number: GroupNumber(0),
        chat_id: GroupChatId([0u8; 32]),
        name: Some("".to_string()),
        role: None,
        self_name: None,
    }];
    let conferences = vec![ConferenceReconcileInfo {
        number: ConferenceNumber(0),
        id: ConferenceId([0u8; 32]),
        title: Some("".to_string()),
    }];

    let model = toxxi::model::initialize_model(
        toxxi::model::ToxSelfInfo {
            tox_id: addr,
            name: "Self".to_string(),
            status_msg: "Status".to_string(),
            status_type: UserStatus::None,
        },
        vec![],
        groups,
        conferences,
        config.clone(),
        config,
    );

    // Unnamed chats show Tox's numbers, but keep no name.
    let chat_id = GroupChatId([0u8; 32]);
    let group_win = WindowId::Group(chat_id);
    let conf_id = ConferenceId([0u8; 32]);
    let conf_win = WindowId::Conference(conf_id);

    assert_eq!(model.window_name(group_win), "Group 0");
    assert_eq!(model.window_name(conf_win), "Conference 0");
    assert_eq!(model.domain.conversations[&group_win].name, "");
    assert_eq!(model.domain.conversations[&conf_win].name, "");
}

#[test]
fn test_file_transfer_speed_calculation() {
    use std::time::{Duration, Instant};
    use toxxi::model::FileTransferProgress;

    let mut progress = FileTransferProgress {
        filename: "test.bin".to_string(),
        total_size: 1000000,
        transferred: 0,
        is_receiving: true,
        status: TransferStatus::Active,
        speed: 0.0,
        last_update: Instant::now(),
        last_transferred: 0,
        friend_pk: toxcore::types::PublicKey([0u8; 32]),
    };

    let now = Instant::now();
    progress.last_update = now - Duration::from_secs(1);

    // Update with 1MB transferred over 1 second
    progress.update_speed(now, 1024 * 1024);

    assert!(progress.speed >= 1024.0 * 1024.0);
    assert_eq!(progress.last_transferred, 1024 * 1024);
}

#[test]
fn test_formatting_utils() {
    use toxxi::utils::{format_duration, format_size, format_speed};

    assert_eq!(format_size(500), "500 B");
    assert_eq!(format_size(1024), "1.0 KB");
    assert_eq!(format_size(1024 * 1024), "1.0 MB");

    assert_eq!(format_speed(1024.0), "1.0 KB/s");

    assert_eq!(format_duration(30.0), "30s");
    assert_eq!(format_duration(65.0), "1m 5s");
    assert_eq!(format_duration(3665.0), "1h 1m");
}
