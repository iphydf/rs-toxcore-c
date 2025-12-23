use std::fs;
use toxcore::tox::{Address, ConferenceNumber, ToxUserStatus};
use toxcore::types::{PublicKey, ToxLogLevel};
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, PeerId, PeerInfo, WindowId, load_state, save_state};

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "Status".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

#[test]
fn test_repro_json_failure() {
    let temp_dir = std::env::temp_dir().join(format!("toxxi_repro_json_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();

    let mut model = create_test_model();

    let conf_num = ConferenceNumber(0);
    let conf_id = toxcore::types::ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(conf_num, conf_id);
    model.ensure_conference_window(conf_id);
    let conf_window_id = WindowId::Conference(conf_id);

    if let Some(conv) = model.domain.conversations.get_mut(&conf_window_id) {
        conv.peers.push(PeerInfo {
            id: PeerId(PublicKey([1u8; 32])),
            name: "Alice".to_string(),
            role: None,
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    }

    // Attempt to save state.
    let save_result = save_state(&temp_dir, &model);
    assert!(
        save_result.is_ok(),
        "save_state failed: {:?}",
        save_result.err()
    );

    let state_path = temp_dir.join("state.json");
    assert!(state_path.exists());

    let load_result = load_state(&temp_dir);
    assert!(
        load_result.as_ref().map(|o| o.is_some()).unwrap_or(false),
        "load_state returned None or Err, likely due to deserialization failure: {:?}",
        load_result.err()
    );

    let loaded_state = load_result.unwrap().unwrap();
    let conv = loaded_state
        .domain
        .conversations
        .get(&conf_window_id)
        .unwrap();
    assert_eq!(conv.peers.len(), 1);

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_active_window_persistence() {
    let temp_dir =
        std::env::temp_dir().join(format!("toxxi_test_active_win_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();

    let mut model = create_test_model();

    let conf_num = ConferenceNumber(0);
    let conf_id = toxcore::types::ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(conf_num, conf_id);
    model.ensure_conference_window(conf_id);
    model.set_active_window(1); // 0 is status, 1 is conference

    save_state(&temp_dir, &model).unwrap();

    let state = load_state(&temp_dir).unwrap().unwrap();
    assert_eq!(state.active_window_index, 1);

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_log_filters_persistence() {
    let temp_dir =
        std::env::temp_dir().join(format!("toxxi_test_log_filters_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();

    let mut model = create_test_model();
    model.ui.log_filters.levels = vec![ToxLogLevel::TOX_LOG_LEVEL_ERROR];
    model.ui.log_filters.msg_pattern = Some("critical".to_string());
    model.ui.log_filters.paused = true;

    save_state(&temp_dir, &model).unwrap();

    let state = load_state(&temp_dir)
        .expect("Failed to load state")
        .expect("State not found");
    let loaded_filters = state.log_filters;

    assert_eq!(
        loaded_filters.levels,
        vec![toxcore::types::ToxLogLevel::TOX_LOG_LEVEL_ERROR]
    );
    assert_eq!(loaded_filters.msg_pattern, Some("critical".to_string()));
    assert!(loaded_filters.paused);

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_window_state_persistence() {
    let temp_dir =
        std::env::temp_dir().join(format!("toxxi_test_win_state_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();

    let mut model = create_test_model();
    let fid = toxcore::tox::FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk);
    // Add friend info so ensure_friend_window works correctly with name
    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk),
            status_message: "".to_string(),
            connection: toxcore::tox::ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    model.ensure_friend_window(pk);
    let win_id = WindowId::Friend(pk);

    {
        let state = model.ui.window_state.entry(win_id).or_default();
        state.unread_count = 5;
        state.show_peers = true;
    }

    save_state(&temp_dir, &model).unwrap();

    let state = load_state(&temp_dir)
        .expect("Failed to load state")
        .expect("State not found");
    let loaded_win_state = state.window_state.get(&WindowId::Friend(pk)).unwrap();

    assert_eq!(loaded_win_state.unread_count, 5);
    assert!(loaded_win_state.show_peers);

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_group_persistence_repro() {
    let temp_dir =
        std::env::temp_dir().join(format!("toxxi_test_group_pers_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();

    let mut model = create_test_model();

    let gnum = toxcore::tox::GroupNumber(0);
    let chat_id = toxcore::types::ChatId([1u8; 32]);
    model.session.group_numbers.insert(gnum, chat_id);
    model.ensure_group_window(chat_id);
    let win_id = WindowId::Group(chat_id);

    // Set as active window
    model.set_active_window(1); // 0 is Status, 1 is Group 0
    assert_eq!(model.active_window_id(), win_id);

    // Add a peer to the group
    if let Some(conv) = model.domain.conversations.get_mut(&win_id) {
        conv.peers.push(PeerInfo {
            id: PeerId(PublicKey([2u8; 32])),
            name: "Bob".to_string(),
            role: Some(toxcore::types::ToxGroupRole::TOX_GROUP_ROLE_USER),
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    }

    save_state(&temp_dir, &model).unwrap();

    let state = load_state(&temp_dir)
        .expect("Failed to load state")
        .expect("State not found");
    assert_eq!(state.active_window_index, 1);
    assert!(state.domain.conversations.contains_key(&win_id));

    let loaded_model = Model::new(state.domain, Config::default(), Config::default());
    assert!(loaded_model.domain.conversations.contains_key(&win_id));

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_message_persistence() {
    let temp_dir =
        std::env::temp_dir().join(format!("toxxi_test_msg_pers_{}", rand::random::<u32>()));
    fs::create_dir_all(&temp_dir).unwrap();

    let mut model = create_test_model();
    let fid = toxcore::tox::FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk);
    model.domain.friends.insert(
        pk,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk),
            status_message: "".to_string(),
            connection: toxcore::tox::ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    model.ensure_friend_window(pk);
    let win_id = WindowId::Friend(pk);

    model.add_friend_message(
        pk,
        toxcore::types::MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "Hello, this is a persisted message!".to_string(),
    );

    save_state(&temp_dir, &model).expect("Failed to save state");

    let state = load_state(&temp_dir)
        .expect("Failed to load state")
        .expect("State not found");
    let conv = state
        .domain
        .conversations
        .get(&win_id)
        .expect("Conversation not found");

    // Messages should be skipped in state.json
    assert_eq!(conv.messages.len(), 0);

    fs::remove_dir_all(&temp_dir).unwrap();
}

// end of tests
