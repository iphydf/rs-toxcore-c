use toxcore::tox::{Address, ConferenceNumber, GroupNumber, ToxUserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, MessageContent, Model, WindowId};

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
fn test_group_messages() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = toxcore::types::ChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);

    model.add_group_message(
        chat_id,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "Peer A".to_string(),
        "hello group".to_string(),
        None,
    );

    let window_id = WindowId::Group(chat_id);
    assert!(model.ui.window_ids.contains(&window_id));

    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(conv.messages.len(), 1);
    assert_eq!(conv.messages[0].sender, "Peer A");
    assert_eq!(
        conv.messages[0].content,
        MessageContent::Text("hello group".to_string())
    );
    assert_eq!(
        model.ui.window_state.get(&window_id).unwrap().unread_count,
        1
    );
}

#[test]
fn test_conference_messages() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(2);
    let conf_id = toxcore::types::ConferenceId([2u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    model.add_conference_message(
        conf_id,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "Peer B".to_string(),
        "hello conf".to_string(),
        None,
    );

    let window_id = WindowId::Conference(conf_id);
    assert!(model.ui.window_ids.contains(&window_id));

    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(conv.messages.len(), 1);
    assert_eq!(conv.messages[0].sender, "Peer B");
    assert_eq!(
        conv.messages[0].content,
        MessageContent::Text("hello conf".to_string())
    );
    assert_eq!(
        model.ui.window_state.get(&window_id).unwrap().unread_count,
        1
    );
}

#[test]
fn test_window_topic_group_conference() {
    let mut model = create_test_model();

    let gid = GroupNumber(1);
    let chat_id = toxcore::types::ChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);

    let cid = ConferenceNumber(2);
    let conf_id = toxcore::types::ConferenceId([2u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    model.add_group_message(
        chat_id,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "System".to_string(),
        "init".to_string(),
        None,
    );
    model.add_conference_message(
        conf_id,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "System".to_string(),
        "init".to_string(),
        None,
    );

    // Console topic
    model.set_active_window(0);
    assert!(
        model.active_window_topic().contains(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000"
        )
    );

    // Group topic
    model.set_active_window(1);
    assert_eq!(model.active_window_topic(), "Group 1");

    // Conference topic
    model.set_active_window(2);
    assert_eq!(model.active_window_topic(), "Conference 2");
}

// end of tests
