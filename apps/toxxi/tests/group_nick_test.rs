use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{GroupNumber, UserStatus};
use toxcore::types::GroupChatId;
use toxcore::types::GroupRole;
use toxcore::types::PublicKey;
use toxxi::model::{Model, PeerId, PeerInfo, WindowId};
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
use toxxi::sync::event::{Content, GraphId};
use toxxi::ui::draw;
use toxxi::update::update;
use toxxi_testing::{create_test_model, send_key};

fn add_test_group(model: &mut Model, gnum: GroupNumber, chat_id: GroupChatId) {
    model.session.group_numbers.insert(gnum, chat_id);
    model.ensure_group_window(chat_id);
}

#[test]
fn test_group_nick() {
    let mut model = create_test_model();

    let group_num = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);

    model.set_active_window(1);
    assert_eq!(model.active_window_id(), WindowId::Group(chat_id));

    let me = model.domain.self_public_key();
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Group(chat_id))
    {
        conv.peers.push(PeerInfo {
            id: PeerId(me),
            name: "Tester".to_string(),
            role: Some(GroupRole::Founder),
            status: UserStatus::None,
            is_ignored: false,
            seen_online: true,
        });
    }

    for c in "/nick NewGroupNick".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(cmds.iter().any(|cmd| matches!(
        cmd,
        Cmd::Tox(ToxAction::SetGroupNickname(g, name)) if *g == chat_id && name == "NewGroupNick"
    )));

    let event = ToxEvent::GroupPeerName(
        group_num,
        toxcore::tox::GroupPeerNumber(0),
        "NewGroupNick".to_string(),
        GroupRole::Founder,
        model.domain.self_public_key(),
    );
    update(&mut model, Msg::Tox(event));

    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();
    // Message 0: "Group nickname set to: NewGroupNick" (immediate)
    assert!(!conv.messages.is_empty());
    let last_msg = conv.messages.last().unwrap();
    assert_eq!(last_msg.sender, "System");
    if let toxxi::model::MessageContent::Text(text) = &last_msg.content {
        assert!(text.contains("NewGroupNick"));
    } else {
        panic!("Expected text message");
    }

    assert_eq!(conv.self_name, Some("NewGroupNick".to_string()));
}

#[test]
fn test_per_group_nick() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);
    model.set_active_window(1);

    // The global name is "Tester".
    assert_eq!(model.domain.self_name, "Tester");
    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();
    assert_eq!(conv.self_name, None);

    for c in "/nick GroupTester".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    // The model is updated at once.
    {
        let conv = model
            .domain
            .conversations
            .get(&WindowId::Group(chat_id))
            .unwrap();
        assert_eq!(conv.self_name, Some("GroupTester".to_string()));
    }

    // Tox confirms it with a PeerName event.
    let event = ToxEvent::GroupPeerName(
        group_num,
        toxcore::tox::GroupPeerNumber(0),
        "GroupTester".to_string(),
        GroupRole::Founder,
        model.domain.self_public_key(),
    );
    update(&mut model, Msg::Tox(event));

    {
        let conv = model
            .domain
            .conversations
            .get(&WindowId::Group(chat_id))
            .unwrap();
        assert_eq!(conv.self_name, Some("GroupTester".to_string()));

        assert!(!conv.messages.is_empty());
        let last_msg = conv.messages.last().unwrap();
        if let toxxi::model::MessageContent::Text(text) = &last_msg.content {
            assert!(text.contains("GroupTester"));
        }
    }

    for c in "/nick Toxxy".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let event = ToxEvent::GroupPeerName(
        group_num,
        toxcore::tox::GroupPeerNumber(0),
        "Toxxy".to_string(),
        GroupRole::Founder,
        model.domain.self_public_key(),
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
            assert!(text.contains("Toxxy"));
        }
    }
}

#[test]
fn test_group_peer_join_leave_log() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);

    let join_event = ToxEvent::GroupPeerJoin(
        group_num,
        toxcore::tox::GroupPeerNumber(1),
        "Bob".to_string(),
        GroupRole::User,
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
fn test_members_we_know_meeting_us_again_are_not_joins() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);
    // A member from before toxxi started again.
    let window_id = WindowId::Group(chat_id);
    model
        .domain
        .conversations
        .get_mut(&window_id)
        .unwrap()
        .peers
        .push(PeerInfo {
            id: PeerId(PublicKey([1u8; 32])),
            name: "Bob".to_owned(),
            role: None,
            status: UserStatus::None,
            is_ignored: false,
            seen_online: false,
        });
    for (n, (name, key)) in [("Bob", 1u8), ("Carol", 2)].into_iter().enumerate() {
        update(
            &mut model,
            Msg::Tox(ToxEvent::GroupPeerJoin(
                group_num,
                toxcore::tox::GroupPeerNumber(n as u32),
                name.to_owned(),
                GroupRole::User,
                PublicKey([key; 32]),
            )),
        );
    }

    let joins: Vec<_> = model
        .events
        .graph(&GraphId::group(&chat_id))
        .into_iter()
        .map(|(_, event)| event.content.clone())
        .collect();
    assert_eq!(
        joins,
        [Content::PeerJoined {
            peer: PublicKey([2u8; 32]),
            name: "Carol".to_owned(),
        }]
    );
    assert!(model.domain.conversations[&window_id].peers[0].seen_online);
}

#[test]
fn test_disable_system_messages() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);

    // Hide join messages.
    model
        .config
        .enabled_system_messages
        .retain(|&t| t != toxxi::config::SystemMessageType::Join);

    let join_event = ToxEvent::GroupPeerJoin(
        group_num,
        toxcore::tox::GroupPeerNumber(1),
        "Bob".to_string(),
        GroupRole::User,
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
    // The devices still get it.
    let joins: Vec<_> = model
        .events
        .graph(&GraphId::group(&chat_id))
        .into_iter()
        .map(|(_, event)| event.content.clone())
        .collect();
    assert_eq!(
        joins,
        [Content::PeerJoined {
            peer: PublicKey([1u8; 32]),
            name: "Bob".to_owned(),
        }]
    );

    // Show them again.
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
            GroupRole::User,
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

#[test]
fn test_nick_feedback_visibility() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);
    model.set_active_window(1); // Group chat is index 1

    for c in "/nick GroupTester".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();

    let has_confirmation = conv.messages.iter().any(|msg| {
        if let toxxi::model::MessageContent::Text(text) = &msg.content {
            text.contains("Group nickname set to")
        } else {
            false
        }
    });

    assert!(
        has_confirmation,
        "Confirmation message 'Group nickname set to' should be in the group chat window. Current messages: {:?}",
        conv.messages
    );
}

#[test]
fn test_nick_show_feedback_visibility() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);
    model.set_active_window(1);

    for c in "/nick".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();

    let has_feedback = conv.messages.iter().any(|msg| {
        if let toxxi::model::MessageContent::Text(text) = &msg.content {
            text.contains("Your current name:")
        } else {
            false
        }
    });

    assert!(
        has_feedback,
        "Current name info should be in the group chat window. Current messages: {:?}",
        conv.messages
    );
}

#[test]
fn test_group_nick_status_bar_update() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);
    model.set_active_window(1); // Group window

    let backend = TestBackend::new(100, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    // Status bar is at y=6
    let status_row: String = (0..100).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(
        status_row.contains("Tester"),
        "Should show initial name 'Tester'"
    );
    assert!(
        !status_row.contains("GroupNick"),
        "Should not show 'GroupNick' yet"
    );

    for c in "/nick GroupNick".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let event = ToxEvent::GroupPeerName(
        group_num,
        toxcore::tox::GroupPeerNumber(0),
        "GroupNick".to_string(),
        GroupRole::Founder,
        model.domain.self_public_key(),
    );
    update(&mut model, Msg::Tox(event));

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row: String = (0..100).map(|x| buffer[(x, 6)].symbol()).collect();

    assert!(
        status_row.contains("GroupNick (Tester)"),
        "Status bar should show 'GroupNick (Tester)'. Current: {}",
        status_row
    );

    model.set_active_window(0);
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row: String = (0..100).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(
        status_row.contains("Tester"),
        "Status bar in Console should show global name 'Tester'"
    );
    assert!(
        !status_row.contains("GroupNick"),
        "Status bar in Console should NOT show group nick"
    );

    for c in "/nick NewGlobal".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row: String = (0..100).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(
        status_row.contains("NewGlobal"),
        "Status bar in Console should show 'NewGlobal'"
    );

    model.set_active_window(1);
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row: String = (0..100).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(
        status_row.contains("GroupNick (NewGlobal)"),
        "Status bar in Group should now show 'GroupNick (NewGlobal)'. Current: {}",
        status_row
    );
}

#[test]
fn test_group_nick_immediate_status_bar_update() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);
    model.set_active_window(1); // Group window

    let backend = TestBackend::new(100, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row: String = (0..100).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(
        status_row.contains("Tester"),
        "Should show initial name 'Tester'"
    );

    for c in "/nick ImmediateNick".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    // Redraw before any events from the worker.
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row: String = (0..100).map(|x| buffer[(x, 6)].symbol()).collect();

    assert!(
        status_row.contains("ImmediateNick (Tester)"),
        "Status bar should update IMMEDIATELY after command. Current: {}",
        status_row
    );
}

#[test]
fn test_hidden_notices_come_and_go_in_the_history() {
    let mut model = create_test_model();
    let group_num = GroupNumber(0);
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, group_num, chat_id);
    let texts = |model: &Model| -> Vec<String> {
        model.domain.conversations[&WindowId::Group(chat_id)]
            .messages
            .iter()
            .map(|msg| format!("{:?}", msg.content))
            .collect()
    };

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            group_num,
            toxcore::tox::GroupPeerNumber(1),
            "Bob".to_string(),
            GroupRole::User,
            PublicKey([1u8; 32]),
        )),
    );
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupMessage(
            group_num,
            toxcore::tox::GroupPeerNumber(1),
            toxcore::types::MessageType::Normal,
            b"hi".to_vec(),
            Some(PublicKey([1u8; 32])),
        )),
    );
    let shown = texts(&model);
    assert_eq!(shown.len(), 2, "{shown:?}");
    let hi_id = model.domain.conversations[&WindowId::Group(chat_id)].messages[1].internal_id;

    toxxi::update::handle_enter(&mut model, "/set system_messages join");
    let hidden = texts(&model);
    assert_eq!(hidden, shown[1..], "the join is gone");

    toxxi::update::handle_enter(&mut model, "/set system_messages join");
    assert_eq!(texts(&model), shown, "the join is back");
    // The message keeps its ID, which sends and receipts find it by.
    assert_eq!(
        model.domain.conversations[&WindowId::Group(chat_id)].messages[1].internal_id,
        hi_id
    );
}
