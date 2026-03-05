use ratatui::{Terminal, backend::TestBackend};
use std::{env, fs};
use toxcore::tox::{
    Address, ConferenceNumber, FriendNumber, GroupNumber, ToxConnection, ToxUserStatus,
};

use toxcore::types::{GroupChatId, ConferenceId, MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{
    ConferenceReconcileInfo, ConsoleMessageType, DomainState, GroupReconcileInfo, MessageContent,
    MessageStatus, Model, TransferStatus, WindowId, load_state, save_state,
};
use toxxi::ui::draw;
use toxxi::utils::decode_hex;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "I am a test".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

#[test]
fn test_window_navigation() {
    let mut model = create_test_model();

    // Initial state: just console
    assert_eq!(model.ui.active_window_index, 0);
    assert_eq!(model.ui.window_ids, vec![WindowId::Console]);

    let pk1 = PublicKey([1u8; 32]);
    let pk2 = PublicKey([2u8; 32]);
    model.session.friend_numbers.insert(FriendNumber(1), pk1);
    model.session.friend_numbers.insert(FriendNumber(2), pk2);
    // Add friend info
    model.domain.friends.insert(
        pk1,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk1),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.domain.friends.insert(
        pk2,
        toxxi::model::FriendInfo {
            name: "Friend 2".to_string(),
            public_key: Some(pk2),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    // Add two friends (this creates windows)
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
fn test_unread_count() {
    let mut model = create_test_model();
    let pk1 = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(FriendNumber(1), pk1);
    model.domain.friends.insert(
        pk1,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk1),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    // Active window is 0 (console)
    model.add_friend_message(
        pk1,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "msg 1".to_string(),
    );

    let window_id = WindowId::Friend(pk1);
    assert_eq!(
        model.ui.window_state.get(&window_id).unwrap().unread_count,
        1
    );

    model.add_friend_message(
        pk1,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "msg 2".to_string(),
    );
    assert_eq!(
        model.ui.window_state.get(&window_id).unwrap().unread_count,
        2
    );

    // Switch to friend 1's window
    model.set_active_window(1);
    assert_eq!(
        model.ui.window_state.get(&window_id).unwrap().unread_count,
        0
    );

    // New message while window is active should NOT increment unread
    model.add_friend_message(
        pk1,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "msg 3".to_string(),
    );
    assert_eq!(
        model.ui.window_state.get(&window_id).unwrap().unread_count,
        0
    );
}

#[test]
fn test_scrolling() {
    let mut model = create_test_model();
    for i in 0..100 {
        model.add_console_message(ConsoleMessageType::Log, format!("message {}", i));
    }

    let id = WindowId::Console;
    let backend = TestBackend::new(80, 13);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    model.scroll_up(1);
    assert_eq!(
        model
            .ui
            .window_state
            .get(&id)
            .unwrap()
            .msg_list_state
            .scroll,
        1
    );

    model.scroll_down(1);
    assert_eq!(
        model
            .ui
            .window_state
            .get(&id)
            .unwrap()
            .msg_list_state
            .scroll,
        0
    );

    model.scroll_down(1); // Should stay at 0
    assert_eq!(
        model
            .ui
            .window_state
            .get(&id)
            .unwrap()
            .msg_list_state
            .scroll,
        0
    );

    // Test friend window scrolling
    let pk1 = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(FriendNumber(1), pk1);
    model.domain.friends.insert(
        pk1,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk1),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    for i in 0..100 {
        model.add_friend_message(
            pk1,
            MessageType::TOX_MESSAGE_TYPE_NORMAL,
            format!("hi {}", i),
        );
    }
    model.set_active_window(1);

    let fid = WindowId::Friend(pk1);
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    model.scroll_up(1);
    assert_eq!(
        model
            .ui
            .window_state
            .get(&fid)
            .unwrap()
            .msg_list_state
            .scroll,
        1
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
fn test_save_load_state() {
    let temp_dir = env::temp_dir().join(format!("toxxi_test_state_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();

    let mut model = create_test_model();
    let pk1 = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(FriendNumber(1), pk1);
    model.domain.friends.insert(
        pk1,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk1),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk1);
    model.add_console_message(ConsoleMessageType::Info, "Log".to_string());

    save_state(&temp_dir, &model).unwrap();
    let state = load_state(&temp_dir)
        .expect("Failed to load state")
        .expect("State not found");

    assert_eq!(state.window_ids.len(), 2);
    assert_eq!(state.window_ids[1], WindowId::Friend(pk1));
    assert_eq!(state.domain.conversations.len(), 1);
    assert_eq!(state.domain.console_messages.len(), 1);
    assert_eq!(
        state.domain.console_messages[0].content,
        MessageContent::Text("Log".to_owned())
    );

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_friend_message_attribution() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk1 = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk1);
    model.domain.friends.insert(
        pk1,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk1),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    // Test incoming message
    model.add_friend_message(
        pk1,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "incoming".to_string(),
    );
    let window_id = WindowId::Friend(pk1);
    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(conv.messages.len(), 1);
    assert_eq!(conv.messages[0].sender, "Friend 1");
    assert_eq!(
        conv.messages[0].content,
        MessageContent::Text("incoming".to_string())
    );
    assert_eq!(conv.messages[0].status, MessageStatus::Incoming);

    // Test outgoing message
    model.add_outgoing_friend_message(
        pk1,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "outgoing".to_string(),
    );
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
    let pk1 = PublicKey([11u8; 32]);
    let addr2 = Address([2u8; 38]);
    let pk2 = PublicKey([22u8; 32]);

    // Save state for profile 1
    let model1 = toxxi::model::initialize_model(
        toxxi::model::ToxSelfInfo {
            tox_id: addr1,
            public_key: pk1,
            name: "P1".to_string(),
            status_msg: "S1".to_string(),
            status_type: ToxUserStatus::TOX_USER_STATUS_NONE,
        },
        vec![],
        vec![],
        vec![],
        config.clone(),
        config.clone(),
    );
    save_state(&temp_dir, &model1).unwrap();

    // Load with profile 2's info
    let model2 = toxxi::model::load_or_initialize(
        &temp_dir,
        toxxi::model::ToxSelfInfo {
            tox_id: addr2,
            public_key: pk2,
            name: "P2".to_string(),
            status_msg: "S2".to_string(),
            status_type: ToxUserStatus::TOX_USER_STATUS_NONE,
        },
        vec![],
        vec![],
        vec![],
        config.clone(),
        config,
    );

    // Should have ignored model1's state and initialized fresh with profile 2
    assert_eq!(model2.domain.tox_id, addr2);
    assert_eq!(model2.domain.self_name, "P2");

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
    let pk = PublicKey([0u8; 32]);

    let model = toxxi::model::load_or_initialize(
        &temp_dir,
        toxxi::model::ToxSelfInfo {
            tox_id: addr,
            public_key: pk,
            name: "P".to_string(),
            status_msg: "S".to_string(),
            status_type: ToxUserStatus::TOX_USER_STATUS_NONE,
        },
        vec![],
        vec![],
        vec![],
        config.clone(),
        config,
    );

    // Should have initialized fresh
    assert_eq!(model.domain.tox_id, addr);
    // AND should have an error message in console
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
    let pk = PublicKey([0u8; 32]);

    // Initial state from Tox core with empty names
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
            public_key: pk,
            name: "Self".to_string(),
            status_msg: "Status".to_string(),
            status_type: ToxUserStatus::TOX_USER_STATUS_NONE,
        },
        vec![],
        groups,
        conferences,
        config.clone(),
        config,
    );

    // Verify names are the defaults, not empty strings
    let chat_id = GroupChatId([0u8; 32]);
    let group_win = WindowId::Group(chat_id);
    let conf_id = ConferenceId([0u8; 32]);
    let conf_win = WindowId::Conference(conf_id);

    assert_eq!(
        model.domain.conversations.get(&group_win).unwrap().name,
        "Group 0"
    );
    assert_eq!(
        model.domain.conversations.get(&conf_win).unwrap().name,
        "Conference 0"
    );
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
        file_kind: 0,
        file_path: None,
        speed: 0.0,
        last_update: Instant::now(), // will be overridden
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

// end of tests
