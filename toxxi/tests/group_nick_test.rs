use crossterm::event::Event as CrosstermEvent;
use crossterm::event::KeyEvent;
use crossterm::event::{KeyCode, KeyModifiers};
use toxcore::tox::{Address, GroupNumber, ToxUserStatus};
use toxcore::types::ChatId;
use toxcore::types::PublicKey;
use toxcore::types::ToxGroupRole;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, WindowId};
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
use toxxi::update::update;

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

fn add_test_group(model: &mut Model, gnum: GroupNumber, chat_id: ChatId) {
    model.session.group_numbers.insert(gnum, chat_id);
    model.ensure_group_window(chat_id);
}

fn send_key(model: &mut Model, code: KeyCode, modifiers: KeyModifiers) -> Vec<Cmd> {
    let event = CrosstermEvent::Key(KeyEvent::new(code, modifiers));
    update(model, Msg::Input(event))
}

#[test]
fn test_group_nick() {
    let mut model = create_test_model();

    // 1. Add a group
    let group_num = GroupNumber(0);
    let chat_id = ChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);

    model.set_active_window(1);
    assert_eq!(model.active_window_id(), WindowId::Group(chat_id));

    // 2. Mock ourselves in the group
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Group(chat_id))
    {
        conv.peers.push(toxxi::model::PeerInfo {
            id: toxxi::model::PeerId(model.domain.self_public_key),
            name: "Tester".to_string(),
            role: Some(ToxGroupRole::TOX_GROUP_ROLE_FOUNDER),
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    }

    // 3. Change nick in group
    for c in "/nick NewGroupNick".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    // 4. Verify ToxAction::SetGroupNickname is issued
    assert_eq!(cmds.len(), 1);
    if let Cmd::Tox(ToxAction::SetGroupNickname(g, name)) = &cmds[0] {
        assert_eq!(*g, chat_id);
        assert_eq!(name, "NewGroupNick");
    } else {
        panic!("Expected SetGroupNickname command, got {:?}", cmds[0]);
    }

    // 5. Mock the event from Tox worker
    let event = ToxEvent::GroupPeerName(
        group_num,
        toxcore::tox::GroupPeerNumber(0),
        "NewGroupNick".to_string(),
        ToxGroupRole::TOX_GROUP_ROLE_FOUNDER,
        model.domain.self_public_key,
    );
    update(&mut model, Msg::Tox(event));

    // 6. Verify name change is in the log
    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();
    let last_msg = conv.messages.last().unwrap();
    assert_eq!(last_msg.sender, "System");
    if let toxxi::model::MessageContent::Text(text) = &last_msg.content {
        assert_eq!(text, "* Tester is now known as NewGroupNick");
    } else {
        panic!("Expected text message");
    }

    // 7. Verify self name is updated
    assert_eq!(conv.self_name, Some("NewGroupNick".to_string()));
}

#[test]
fn test_per_group_nick() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = ChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);
    model.set_active_window(1);

    // Initial state: global name is "Tester"
    assert_eq!(model.domain.self_name, "Tester");
    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();
    assert_eq!(conv.self_name, None);

    // Change nick in group
    for c in "/nick GroupTester".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    // Verify local model NOT updated yet (waiting for roundtrip)
    {
        let conv = model
            .domain
            .conversations
            .get(&WindowId::Group(chat_id))
            .unwrap();
        assert_eq!(conv.self_name, None);
    }

    // Receive PeerName event from Tox (roundtrip)
    let event = ToxEvent::GroupPeerName(
        group_num,
        toxcore::tox::GroupPeerNumber(0),
        "GroupTester".to_string(),
        ToxGroupRole::TOX_GROUP_ROLE_FOUNDER,
        model.domain.self_public_key,
    );
    update(&mut model, Msg::Tox(event));

    {
        let conv = model
            .domain
            .conversations
            .get(&WindowId::Group(chat_id))
            .unwrap();
        assert_eq!(conv.self_name, Some("GroupTester".to_string()));

        // Verify system message shows correct "from" name (previous nick)
        let last_msg = conv.messages.last().unwrap();
        if let toxxi::model::MessageContent::Text(text) = &last_msg.content {
            assert_eq!(text, "* Tester is now known as GroupTester");
        }
    }

    // Change nick again
    for c in "/nick Toxxy".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    // Receive second event
    let event = ToxEvent::GroupPeerName(
        group_num,
        toxcore::tox::GroupPeerNumber(0),
        "Toxxy".to_string(),
        ToxGroupRole::TOX_GROUP_ROLE_FOUNDER,
        model.domain.self_public_key,
    );
    update(&mut model, Msg::Tox(event));

    {
        let conv = model
            .domain
            .conversations
            .get(&WindowId::Group(chat_id))
            .unwrap();
        assert_eq!(conv.self_name, Some("Toxxy".to_string()));

        let last_msg = conv.messages.last().unwrap();
        if let toxxi::model::MessageContent::Text(text) = &last_msg.content {
            assert_eq!(text, "* GroupTester is now known as Toxxy");
        }
    }
}

#[test]
fn test_group_peer_join_leave_log() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = ChatId([5u8; 32]);
    model.session.group_numbers.insert(group_num, chat_id);
    model.ensure_group_window(chat_id);

    // Join
    let join_event = ToxEvent::GroupPeerJoin(
        group_num,
        toxcore::tox::GroupPeerNumber(1),
        "Bob".to_string(),
        ToxGroupRole::TOX_GROUP_ROLE_USER,
        PublicKey([1u8; 32]),
    );
    update(&mut model, Msg::Tox(join_event));

    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();
    let last_msg = conv.messages.last().unwrap();
    if let toxxi::model::MessageContent::Text(text) = &last_msg.content {
        assert_eq!(text, "* Bob joined the group");
    }

    // Leave
    let leave_event = ToxEvent::GroupPeerLeave(group_num, toxcore::tox::GroupPeerNumber(1));
    update(&mut model, Msg::Tox(leave_event));

    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();
    let last_msg = conv.messages.last().unwrap();
    if let toxxi::model::MessageContent::Text(text) = &last_msg.content {
        assert_eq!(text, "* Bob left the group");
    }
}

#[test]
fn test_disable_system_messages() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = ChatId([5u8; 32]);
    model.session.group_numbers.insert(group_num, chat_id);
    model.ensure_group_window(chat_id);

    // Disable Join messages
    model
        .config
        .enabled_system_messages
        .retain(|&t| t != toxxi::config::SystemMessageType::Join);

    let join_event = ToxEvent::GroupPeerJoin(
        group_num,
        toxcore::tox::GroupPeerNumber(1),
        "Bob".to_string(),
        ToxGroupRole::TOX_GROUP_ROLE_USER,
        PublicKey([1u8; 32]),
    );
    update(&mut model, Msg::Tox(join_event));

    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();
    assert!(
        conv.messages.is_empty(),
        "Join message should have been disabled"
    );

    // Enable it back
    model
        .config
        .enabled_system_messages
        .push(toxxi::config::SystemMessageType::Join);
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            group_num,
            toxcore::tox::GroupPeerNumber(2),
            "Alice".to_string(),
            ToxGroupRole::TOX_GROUP_ROLE_USER,
            PublicKey([2u8; 32]),
        )),
    );

    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();
    assert!(
        !conv.messages.is_empty(),
        "Join message should have been enabled"
    );
}
