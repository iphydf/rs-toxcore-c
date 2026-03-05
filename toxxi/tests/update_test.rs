use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use toxcore::tox::{
    Address, ConferenceNumber, FriendNumber, GroupNumber, GroupPeerNumber, ToxConnection,
    ToxUserStatus,
};
use toxcore::types::{GroupChatId, ConferenceId, MessageType, PublicKey, ToxGroupRole};
use toxxi::config::Config;
use toxxi::model::{ConsoleMessageType, DomainState, FriendInfo, Model, PeerId, WindowId};
use toxxi::msg::{AppCmd, Cmd, Msg, ToxAction, ToxEvent};
use toxxi::ui::draw;
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

fn add_test_friend(model: &mut Model, fid: FriendNumber, pk: PublicKey) {
    model.domain.friends.insert(
        pk,
        FriendInfo {
            name: format!("Friend {}", fid.0),
            public_key: Some(pk),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.session.friend_numbers.insert(fid, pk);
    model.ensure_friend_window(pk);
}

fn add_test_group(model: &mut Model, gnum: GroupNumber, chat_id: GroupChatId) {
    model.session.group_numbers.insert(gnum, chat_id);
    model.ensure_group_window(chat_id);
}

fn add_test_conference(model: &mut Model, cnum: ConferenceNumber, cid: ConferenceId) {
    model.session.conference_numbers.insert(cnum, cid);
    model.ensure_conference_window(cid);
}

fn send_key(model: &mut Model, code: KeyCode, modifiers: KeyModifiers) -> Vec<Cmd> {
    let event = CrosstermEvent::Key(KeyEvent::new(code, modifiers));
    let cmds = update(model, Msg::Input(event));
    model.ui.input_state.ensure_layout(80, "> ");
    cmds
}

fn get_text(input: &toxxi::widgets::InputBoxState) -> String {
    input.text.clone()
}

#[test]
fn test_update_enter_command() {
    let mut model = create_test_model();

    // Type "/quit" and Enter
    for c in "/quit".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());
    assert!(cmds.contains(&Cmd::App(AppCmd::Quit)));
}

#[test]
fn test_update_control_keys() {
    let mut model = create_test_model();

    // Ctrl+N -> next window
    send_key(&mut model, KeyCode::Char('n'), KeyModifiers::CONTROL);
    assert_eq!(model.ui.active_window_index, 0); // Still 0 because no friends added

    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(FriendNumber(1), pk);
    model.add_friend_message(pk, MessageType::TOX_MESSAGE_TYPE_NORMAL, "hi".to_string());
    send_key(&mut model, KeyCode::Char('n'), KeyModifiers::CONTROL);
    assert_eq!(model.ui.active_window_index, 1);

    // Ctrl+C -> clear input (TODO: re-implement Ctrl+C in update.rs)
    // Send Ctrl+U instead (kill to start)
    for c in "hello".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "hello");
    send_key(&mut model, KeyCode::Char('u'), KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), "");

    // Ctrl+L -> Redraw
    let cmds = send_key(&mut model, KeyCode::Char('l'), KeyModifiers::CONTROL);
    assert!(cmds.contains(&Cmd::App(AppCmd::Redraw)));
}

#[test]
fn test_update_ctrl_c_behavior() {
    let mut model = create_test_model();

    // 1. Set some input
    for c in "partial command".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "partial command");

    // 2. Mock some completion candidates
    model.ui.completion.active = true;
    model.ui.completion.candidates = vec!["completion".to_string()];

    // 3. Press Ctrl+C
    let cmds = send_key(&mut model, KeyCode::Char('c'), KeyModifiers::CONTROL);

    // 4. Verify input is cleared, completion is inactive, and NO quit command is issued
    assert_eq!(get_text(&model.ui.input_state), "");
    assert!(!model.ui.completion.active);
    assert!(
        cmds.is_empty(),
        "Ctrl+C should not produce any commands (like Quit)"
    );
}

#[test]
fn test_update_tox_events() {
    let mut model = create_test_model();
    let f5 = FriendNumber(5);
    let pk5 = PublicKey([5u8; 32]);
    model.session.friend_numbers.insert(f5, pk5);

    // Test receiving a message
    update(
        &mut model,
        Msg::Tox(ToxEvent::Message(
            f5,
            MessageType::TOX_MESSAGE_TYPE_NORMAL,
            "hello from 5".to_string(),
        )),
    );
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Friend(pk5))
    );
    assert_eq!(
        model
            .domain
            .conversations
            .get(&WindowId::Friend(pk5))
            .unwrap()
            .messages
            .len(),
        1
    );

    // Test log message
    update(
        &mut model,
        Msg::Tox(ToxEvent::Log(
            toxcore::types::ToxLogLevel::TOX_LOG_LEVEL_INFO,
            "file".to_owned(),
            1,
            "func".to_owned(),
            "system error".to_string(),
        )),
    );
    assert!(
        model
            .domain
            .tox_logs
            .get(&toxcore::types::ToxLogLevel::TOX_LOG_LEVEL_INFO)
            .unwrap()
            .back()
            .unwrap()
            .message
            .contains("system error")
    );
}

#[test]
fn test_handle_msg_command() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);

    for c in "/msg 1 hello".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    // Should result in a ToxAction::SendMessage
    let mut found = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::SendMessage(f, t, msg, _)) = cmd {
            assert_eq!(f, pk);
            assert_eq!(t, MessageType::TOX_MESSAGE_TYPE_NORMAL);
            assert_eq!(msg, "hello");
            found = true;
        }
    }
    assert!(found);

    // The active window should now be Friend 1
    let window_id = WindowId::Friend(pk);
    assert!(model.ui.window_ids.contains(&window_id));
    assert_eq!(model.active_window_id(), window_id);
}
#[test]
fn test_handle_group_create() {
    let mut model = create_test_model();

    for c in "/group create My Group".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let mut found = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::CreateGroup(name)) = cmd {
            assert_eq!(name, "My Group");
            found = true;
        }
    }
    assert!(found);
}

#[test]
fn test_handle_conference_create() {
    let mut model = create_test_model();

    for c in "/conference create".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(cmds.contains(&Cmd::Tox(ToxAction::CreateConference)));
}

#[test]
fn test_handle_win_command() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    model
        .session
        .friend_numbers
        .insert(toxcore::tox::FriendNumber(1), pk);
    model.add_friend_message(pk, MessageType::TOX_MESSAGE_TYPE_NORMAL, "hi".to_string());

    // Switch to window 1
    for c in "/win 1".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert_eq!(model.ui.active_window_index, 1);
}

#[test]
fn test_handle_close_command() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    add_test_group(&mut model, gid, chat_id);

    model.add_group_message(
        chat_id,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "System".to_string(),
        "init".to_string(),
        None,
    );
    model.set_active_window(1);

    // Switch to window 1 and /close it
    for c in "/close".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(cmds.contains(&Cmd::Tox(ToxAction::LeaveGroup(chat_id))));
    assert_eq!(model.ui.window_ids.len(), 1); // Only console left
    assert_eq!(model.ui.active_window_index, 0);
}

#[test]
fn test_handle_query_command() {
    let mut model = create_test_model();
    let fid = FriendNumber(5);
    let pk = PublicKey([5u8; 32]);
    model.domain.friends.insert(
        pk,
        FriendInfo {
            name: "Friend 5".to_string(),
            public_key: Some(pk),
            status_message: "".to_string(),
            connection: toxcore::tox::ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.session.friend_numbers.insert(fid, pk);

    // /query 5
    for c in "/query 5".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let window_id = WindowId::Friend(pk);
    assert!(model.ui.window_ids.contains(&window_id));
    assert_eq!(model.ui.window_ids[model.ui.active_window_index], window_id);
}

#[test]
fn test_handle_group_created_msg() {
    let mut model = create_test_model();
    let gid = GroupNumber(7);
    let chat_id = GroupChatId([0u8; 32]);

    // Simulate worker sending GroupCreated message
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupCreated(gid, chat_id, None)),
    );

    let window_id = WindowId::Group(chat_id);
    assert!(model.ui.window_ids.contains(&window_id));
    assert_eq!(model.ui.window_ids[model.ui.active_window_index], window_id);
}

#[test]
fn test_handle_group_created_no_steal_focus() {
    let mut model = create_test_model();
    let gid1 = GroupNumber(1);
    let chat_id1 = GroupChatId([1u8; 32]);
    let gid2 = GroupNumber(2);
    let chat_id2 = GroupChatId([2u8; 32]);

    // Initial population (simulating load from state)
    model.session.group_numbers.insert(gid1, chat_id1);
    model.session.group_numbers.insert(gid2, chat_id2);
    model.ensure_group_window(chat_id1);
    model.ensure_group_window(chat_id2);
    model.set_active_window(1); // Set focus to gid1

    assert_eq!(model.ui.active_window_index, 1);

    // Simulate worker sending GroupCreated message for gid1
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupCreated(gid1, chat_id1, None)),
    );
    assert_eq!(model.ui.active_window_index, 1); // Focus should NOT change

    // Simulate worker sending GroupCreated message for gid2
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupCreated(gid2, chat_id2, None)),
    );
    assert_eq!(model.ui.active_window_index, 1); // Focus should NOT change

    // Simulate worker sending GroupCreated message for a NEW group gid3
    let gid3 = GroupNumber(3);
    let chat_id3 = GroupChatId([3u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupCreated(gid3, chat_id3, None)),
    );
    assert_eq!(model.ui.active_window_index, 3); // Focus SHOULD change to new group
}

#[test]
fn test_handle_conference_created_msg() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(42);
    let conf_id = ConferenceId([0u8; 32]);

    // Simulate worker sending ConferenceCreated message
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceCreated(cid, conf_id)),
    );

    let window_id = WindowId::Conference(conf_id);
    assert!(model.ui.window_ids.contains(&window_id));
    assert_eq!(model.ui.window_ids[model.ui.active_window_index], window_id);
}

#[test]
fn test_handle_conference_created_no_steal_focus() {
    let mut model = create_test_model();
    let cid1 = ConferenceNumber(1);
    let conf_id1 = ConferenceId([1u8; 32]);
    let cid2 = ConferenceNumber(2);
    let conf_id2 = ConferenceId([2u8; 32]);

    // Initial population (simulating load from state)
    model.session.conference_numbers.insert(cid1, conf_id1);
    model.session.conference_numbers.insert(cid2, conf_id2);
    model.ensure_conference_window(conf_id1);
    model.ensure_conference_window(conf_id2);
    model.set_active_window(1); // Set focus to cid1

    assert_eq!(model.ui.active_window_index, 1);

    // Simulate worker sending ConferenceCreated message for cid1
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceCreated(cid1, conf_id1)),
    );
    assert_eq!(model.ui.active_window_index, 1); // Focus should NOT change

    // Simulate worker sending ConferenceCreated message for cid2
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceCreated(cid2, conf_id2)),
    );
    assert_eq!(model.ui.active_window_index, 1); // Focus should NOT change

    // Simulate worker sending ConferenceCreated message for a NEW conference cid3
    let cid3 = ConferenceNumber(3);
    let conf_id3 = ConferenceId([3u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceCreated(cid3, conf_id3)),
    );
    assert_eq!(model.ui.active_window_index, 3); // Focus SHOULD change to new conference
}

#[test]
fn test_handle_group_msg_sending() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    add_test_group(&mut model, gid, chat_id);

    model.add_group_message(
        chat_id,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "System".to_string(),
        "init".to_string(),
        None,
    );
    model.set_active_window(1); // Group 1 window

    for c in "hello group".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let mut found = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::SendGroupMessage(g, t, msg, _)) = cmd {
            assert_eq!(g, chat_id);
            assert_eq!(t, MessageType::TOX_MESSAGE_TYPE_NORMAL);
            assert_eq!(msg, "hello group");
            found = true;
        }
    }
    assert!(found);
}

#[test]
fn test_handle_conference_msg_sending() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(2);
    let conf_id = ConferenceId([2u8; 32]);
    add_test_conference(&mut model, cid, conf_id);

    model.add_conference_message(
        conf_id,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "System".to_string(),
        "init".to_string(),
        None,
    );
    model.set_active_window(1); // Conference 2 window

    for c in "hello conf".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let mut found = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::SendConferenceMessage(c, t, msg, _)) = cmd {
            assert_eq!(c, conf_id);
            assert_eq!(t, MessageType::TOX_MESSAGE_TYPE_NORMAL);
            assert_eq!(msg, "hello conf");
            found = true;
        }
    }
    assert!(found);
}

#[test]
fn test_handle_whois_command() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk);
    model.domain.friends.insert(
        pk,
        FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk),
            status_message: "Testing".to_string(),
            connection: toxcore::tox::ToxConnection::TOX_CONNECTION_TCP,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    for c in "/whois 1".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(
        model
            .domain
            .console_messages
            .iter()
            .any(|m| m.content.contains("Alice"))
    );
    assert!(
        model
            .domain
            .console_messages
            .iter()
            .any(|m| m.content.contains("Testing"))
    );
    assert!(
        model
            .domain
            .console_messages
            .iter()
            .any(|m| m.content.contains("Online (TCP)"))
    );
}

#[test]
fn test_handle_topic_command() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    add_test_group(&mut model, gid, chat_id);

    model.add_group_message(
        chat_id,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "System".to_string(),
        "init".to_string(),
        None,
    );
    model.set_active_window(1);

    for c in "/topic New Group Topic".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let mut found = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::SetGroupTopic(g, topic)) = cmd {
            assert_eq!(g, chat_id);
            assert_eq!(topic, "New Group Topic");
            found = true;
        }
    }
    assert!(found);
}

#[test]
fn test_handle_me_command() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);

    model.add_friend_message(pk, MessageType::TOX_MESSAGE_TYPE_NORMAL, "hi".to_string());
    model.set_active_window(1);

    for c in "/me is coding".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let mut found = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::SendMessage(f, t, msg, _)) = cmd {
            assert_eq!(f, pk);
            assert_eq!(t, MessageType::TOX_MESSAGE_TYPE_ACTION);
            assert_eq!(msg, "is coding");
            found = true;
        }
    }
    assert!(found);
}

#[test]
fn test_handle_friend_add_multiword() {
    let mut model = create_test_model();
    let tox_id = "56A1AA2D01452D792B607E92A2875149363B346F41E5D571936A69666497B3431D80054F7F80";

    for c in format!("/friend add {} Hello from Toxxi!", tox_id).chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let mut found = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::AddFriend(id, msg)) = cmd {
            assert_eq!(id, tox_id);
            assert_eq!(msg, "Hello from Toxxi!");
            found = true;
        }
    }
    assert!(found);
}

#[test]
fn test_handle_nick_show() {
    let mut model = create_test_model();
    model.domain.self_name = "MyNick".to_string();

    for c in "/nick".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(
        model
            .domain
            .console_messages
            .iter()
            .any(|m| m.content.contains("MyNick"))
    );
}

#[test]
fn test_handle_status_show() {
    let mut model = create_test_model();
    model.domain.self_status_message = "My Status".to_string();

    for c in "/status".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(
        model
            .domain
            .console_messages
            .iter()
            .any(|m| m.content.contains("My Status"))
    );
}

#[test]
fn test_handle_topic_events() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    let cid = ConferenceNumber(2);
    let conf_id = ConferenceId([2u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    model.ensure_group_window(chat_id);
    model.ensure_conference_window(conf_id);

    // Group topic event
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupTopic(gid, "New Group Topic".to_string())),
    );
    let group_window = WindowId::Group(chat_id);
    assert_eq!(
        model.domain.conversations.get(&group_window).unwrap().topic,
        Some("New Group Topic".to_string())
    );
    assert_eq!(
        model.domain.conversations.get(&group_window).unwrap().name,
        "Group 1".to_string()
    );

    // Conference title event
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(
            cid,
            "New Conference Title".to_owned(),
        )),
    );
    let conf_window = WindowId::Conference(conf_id);
    assert_eq!(
        model.domain.conversations.get(&conf_window).unwrap().topic,
        Some("New Conference Title".to_string())
    );
    assert_eq!(
        model.domain.conversations.get(&conf_window).unwrap().name,
        "New Conference Title".to_string()
    );
}

#[test]
fn test_update_scroll_keys() {
    let mut model = create_test_model();
    for i in 0..100 {
        model.add_console_message(ConsoleMessageType::Log, format!("msg {}", i));
    }

    let id = WindowId::Console;
    let backend = TestBackend::new(80, 13);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    // PageUp (scrolled 8 messages)
    send_key(&mut model, KeyCode::PageUp, KeyModifiers::empty());
    assert_eq!(
        model
            .ui
            .window_state
            .get(&id)
            .unwrap()
            .msg_list_state
            .scroll,
        8
    );

    // Shift+PageUp (scroll to top)
    send_key(&mut model, KeyCode::PageUp, KeyModifiers::SHIFT);
    assert_eq!(
        model
            .ui
            .window_state
            .get(&id)
            .unwrap()
            .msg_list_state
            .scroll,
        92
    );

    // PageDown (scrolled 8 messages down)
    send_key(&mut model, KeyCode::PageDown, KeyModifiers::empty());
    assert_eq!(
        model
            .ui
            .window_state
            .get(&id)
            .unwrap()
            .msg_list_state
            .scroll,
        84
    );

    // Shift+PageDown (scroll to bottom)
    send_key(&mut model, KeyCode::PageDown, KeyModifiers::SHIFT);
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

    // Ctrl+Home (scroll to top)
    send_key(&mut model, KeyCode::Home, KeyModifiers::CONTROL);
    assert_eq!(
        model
            .ui
            .window_state
            .get(&id)
            .unwrap()
            .msg_list_state
            .scroll,
        92
    );

    // Ctrl+End (scroll to bottom)
    send_key(&mut model, KeyCode::End, KeyModifiers::CONTROL);
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
}

#[test]
fn test_handle_clear_and_pop_commands() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    model.session.friend_numbers.insert(fid, pk);
    model.add_friend_message(pk, MessageType::TOX_MESSAGE_TYPE_NORMAL, "hi".to_string());
    model.set_active_window(1);

    // Add some system messages
    for i in 0..3 {
        model.add_info_message(toxxi::model::MessageContent::Text(format!(
            "System message {}",
            i
        )));
    }

    let window_id = WindowId::Friend(pk);
    assert_eq!(
        model
            .domain
            .conversations
            .get(&window_id)
            .unwrap()
            .messages
            .len(),
        4
    ); // 1 normal + 3 system

    // Test /pop
    for c in "/pop".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());
    assert_eq!(
        model
            .domain
            .conversations
            .get(&window_id)
            .unwrap()
            .messages
            .len(),
        3
    ); // Last system removed

    // Test /clear (defaults to system)
    for c in "/clear".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());
    assert_eq!(
        model
            .domain
            .conversations
            .get(&window_id)
            .unwrap()
            .messages
            .len(),
        1
    ); // All system removed, only "hi" left

    // Add system message again
    model.add_info_message(toxxi::model::MessageContent::Text("noise".to_owned()));
    assert_eq!(
        model
            .domain
            .conversations
            .get(&window_id)
            .unwrap()
            .messages
            .len(),
        2
    );

    // Test /clear all
    for c in "/clear all".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());
    assert_eq!(
        model
            .domain
            .conversations
            .get(&window_id)
            .unwrap()
            .messages
            .len(),
        0
    );
}

#[test]
fn test_update_ctrl_w_behavior() {
    let mut model = create_test_model();

    // 1. Simple ASCII case
    for c in "hello world".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "hello world");
    send_key(&mut model, KeyCode::Char('w'), KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), "hello ");

    // 2. Multi-byte character case (Unicode)
    model.ui.input_state.set_value("".to_string());
    model.ui.input_state.set_cursor(0, 0);
    for c in "🦀 🦀 🦀".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "🦀 🦀 🦀");
    // Currently this might panic or behave incorrectly due to byte/char index mismatch
    send_key(&mut model, KeyCode::Char('w'), KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), "🦀 🦀 ");
}

#[test]
fn test_update_ctrl_backspace_delete_behavior() {
    let mut model = create_test_model();

    // 1. Test Ctrl+Backspace
    for c in "hello world".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "hello world");
    send_key(&mut model, KeyCode::Backspace, KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), "hello ");

    // 2. Test Ctrl+Delete
    model.ui.input_state.set_value("".to_string());
    model.ui.input_state.set_cursor(0, 0);
    for c in "hello world".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    model.ui.input_state.set_cursor(0, 0);
    send_key(&mut model, KeyCode::Delete, KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), " world");
}

#[test]
fn test_update_ctrl_left_right_unicode() {
    let mut model = create_test_model();

    // Input: "🦀 🦀 🦀"
    // Indices: 🦀(0), space(1), 🦀(2), space(3), 🦀(4)
    // InputBox uses visual width columns for the cursor.

    // "🦀 🦀 🦀"
    for c in "🦀 🦀 🦀".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    // Expected cursor position at end.
    let end_pos = model.ui.input_state.cursor().0;
    assert_eq!(end_pos, 10); // 3 crabs(6) + 2 spaces(2) + prompt(2) = 10

    // 1. Move left: jumps over last crab to position 8
    send_key(&mut model, KeyCode::Left, KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.cursor().0, 8);

    // 2. Move left again: jumps over space (7) and middle crab (5) to position 5
    send_key(&mut model, KeyCode::Left, KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.cursor().0, 5);

    // 3. Move left again: jumps over space (4) and first crab (2) to position 2
    send_key(&mut model, KeyCode::Left, KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.cursor().0, 2);

    // 4. Move right: jumps over first crab to position 4
    send_key(&mut model, KeyCode::Right, KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.cursor().0, 4);

    // 5. Move right again: jumps over space (5) and middle crab (7) to position 7
    send_key(&mut model, KeyCode::Right, KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.cursor().0, 7);
}

#[test]
fn test_friend_remove_command_displays_info() {
    let mut model = create_test_model();
    let fid = FriendNumber(5);
    let pk = "5555555555555555555555555555555555555555555555555555555555555555";

    // Add a friend manually
    let pk_arr = [0x55u8; 32];
    let pk_obj = PublicKey(pk_arr);
    model.domain.friends.insert(
        pk_obj,
        FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk_obj),
            status_message: "Online".to_string(),
            connection: toxcore::tox::ToxConnection::TOX_CONNECTION_UDP,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.session.friend_numbers.insert(fid, pk_obj);
    model.ensure_friend_window(pk_obj);

    // Execute "/friend remove 5"
    let input = "/friend remove 5";
    for c in input.chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    // Verify friend is removed
    assert!(!model.domain.friends.contains_key(&pk_obj));

    // Verify console message contains name and public key
    let last_msg = model
        .domain
        .console_messages
        .last()
        .expect("Should have a console message");
    let content = last_msg.content.as_text().expect("Message should be text");
    assert!(content.contains("Removed friend Alice"));
    assert!(content.contains(pk));
}

#[test]
fn test_conference_title_update_non_empty() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(1);
    let conf_id = ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);
    model.ensure_conference_window(conf_id);
    let window_id = WindowId::Conference(conf_id);

    // Update with non-empty title
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(cid, "My Conference".to_string())),
    );

    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(conv.name, "My Conference");
    assert_eq!(conv.topic, Some("My Conference".to_string()));
}

#[test]
fn test_conference_title_update_empty_preserves_name() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(1);
    let conf_id = ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);
    model.ensure_conference_window(conf_id);
    let window_id = WindowId::Conference(conf_id);

    // Initial name should be default
    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        assert_eq!(conv.name, "Conference 1");
    }

    // Update with empty title
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(cid, "".to_string())),
    );

    let conv = model.domain.conversations.get(&window_id).unwrap();
    // Name should stay "Conference 1", but topic should be updated to empty
    assert_eq!(conv.name, "Conference 1");
    assert_eq!(conv.topic, Some("".to_string()));
}

#[test]
fn test_group_name_update() {
    let mut model = create_test_model();
    let gnum = GroupNumber(0);
    let chat_id = GroupChatId([0u8; 32]);
    model.session.group_numbers.insert(gnum, chat_id);
    model.ensure_group_window(chat_id);
    let window_id = WindowId::Group(chat_id);

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupName(gnum, "My Group".to_string())),
    );

    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(conv.name, "My Group");
}

#[test]
fn test_group_topic_update() {
    let mut model = create_test_model();
    let gnum = GroupNumber(0);
    let chat_id = GroupChatId([0u8; 32]);
    model.session.group_numbers.insert(gnum, chat_id);
    model.ensure_group_window(chat_id);
    let window_id = WindowId::Group(chat_id);

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupTopic(gnum, "New Topic".to_string())),
    );

    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(conv.topic, Some("New Topic".to_string()));
}

#[test]
fn test_events_ensure_windows() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    let cid = ConferenceNumber(2);
    let conf_id = ConferenceId([2u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    // GroupName event
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupName(gid, "Group Name".to_string())),
    );
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Group(chat_id))
    );

    // Reset model
    let mut model = create_test_model();
    model.session.group_numbers.insert(gid, chat_id);
    model.session.conference_numbers.insert(cid, conf_id);
    // GroupTopic event
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupTopic(gid, "Group Topic".to_string())),
    );
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Group(chat_id))
    );

    // Reset model
    let mut model = create_test_model();
    model.session.group_numbers.insert(gid, chat_id);
    model.session.conference_numbers.insert(cid, conf_id);
    // GroupSelfRole event
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupSelfRole(
            gid,
            toxcore::types::ToxGroupRole::TOX_GROUP_ROLE_FOUNDER,
        )),
    );
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Group(chat_id))
    );

    // Reset model
    let mut model = create_test_model();
    model.session.group_numbers.insert(gid, chat_id);
    model.session.conference_numbers.insert(cid, conf_id);
    // ConferenceTitle event
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(cid, "Conf Title".to_string())),
    );
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Conference(conf_id))
    );
}

#[test]
fn test_handle_group_peer_status_event() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    let pid = toxcore::tox::GroupPeerNumber(5);

    model.ensure_group_window(chat_id);

    // Join peer
    let pk = PublicKey([5u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            gid,
            pid,
            "Peer5".to_string(),
            toxcore::types::ToxGroupRole::TOX_GROUP_ROLE_USER,
            pk,
        )),
    );

    // Initial status should be NONE
    let window_id = WindowId::Group(chat_id);
    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        let peer = conv.peers.iter().find(|p| p.id == PeerId(pk)).unwrap();
        assert_eq!(peer.status, ToxUserStatus::TOX_USER_STATUS_NONE);
    }

    // Update status to AWAY
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerStatus(
            gid,
            pid,
            ToxUserStatus::TOX_USER_STATUS_AWAY,
        )),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        let peer = conv.peers.iter().find(|p| p.id == PeerId(pk)).unwrap();
        assert_eq!(peer.status, ToxUserStatus::TOX_USER_STATUS_AWAY);
    }
}

#[test]
fn test_no_duplicate_group_peers() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    let pid = GroupPeerNumber(5);
    let pk = PublicKey([5u8; 32]);

    model.ensure_group_window(chat_id);
    let window_id = WindowId::Group(chat_id);

    // Join peer once
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            gid,
            pid,
            "Peer5".to_string(),
            ToxGroupRole::TOX_GROUP_ROLE_USER,
            pk,
        )),
    );

    // Join same peer again (simulating duplicate event)
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            gid,
            pid,
            "Peer5".to_string(),
            ToxGroupRole::TOX_GROUP_ROLE_USER,
            pk,
        )),
    );

    let conv = model.domain.conversations.get(&window_id).unwrap();
    let peer_count = conv.peers.len();
    assert_eq!(
        peer_count, 1,
        "Should only have one peer, found {}",
        peer_count
    );
}

#[test]
fn test_group_peer_join_filters_self() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    let self_pk = model.domain.self_public_key;

    model.ensure_group_window(chat_id);
    let window_id = WindowId::Group(chat_id);

    // Join ourselves
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            gid,
            GroupPeerNumber(0),
            "Tester".to_string(),
            ToxGroupRole::TOX_GROUP_ROLE_FOUNDER,
            self_pk,
        )),
    );

    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert!(
        conv.peers.is_empty(),
        "Self should be filtered out from group peer list"
    );
}

#[test]
fn test_reconcile_deduplicates_peers() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);
    let pk = PublicKey([5u8; 32]);

    model.ensure_group_window(chat_id);
    let window_id = WindowId::Group(chat_id);

    if let Some(conv) = model.domain.conversations.get_mut(&window_id) {
        // Add duplicate peers manually (simulating loaded state with duplicates)
        for i in 0..3 {
            conv.peers.push(toxxi::model::PeerInfo {
                id: PeerId(pk),
                name: format!("Peer {}", i),
                role: None,
                status: ToxUserStatus::TOX_USER_STATUS_NONE,
                is_ignored: false,
                seen_online: false,
            });
        }
    }

    assert_eq!(
        model
            .domain
            .conversations
            .get(&window_id)
            .unwrap()
            .peers
            .len(),
        3
    );

    // Reconcile should deduplicate
    model.reconcile(vec![], vec![], vec![]);

    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(
        conv.peers.len(),
        1,
        "Reconcile should have deduplicated the peers"
    );
    assert_eq!(conv.peers[0].name, "Peer 0"); // Keeps the first one
}

#[test]
fn test_no_duplicate_conference_peers() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(1);
    let conf_id = ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);
    let pk = PublicKey([5u8; 32]);

    model.ensure_conference_window(conf_id);
    let window_id = WindowId::Conference(conf_id);

    // Join peer once
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(
            cid,
            toxcore::tox::ConferencePeerNumber(0),
            "Peer5".to_string(),
            pk,
        )),
    );

    // Join same peer again
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(
            cid,
            toxcore::tox::ConferencePeerNumber(0),
            "Peer5".to_string(),
            pk,
        )),
    );

    let conv = model.domain.conversations.get(&window_id).unwrap();
    let peer_count = conv.peers.len();
    assert_eq!(
        peer_count, 1,
        "Should only have one peer, found {}",
        peer_count
    );
}

#[test]
fn test_bracketed_paste_single_line() {
    let mut model = create_test_model();

    // Simulate paste event
    let paste_text = "Hello, Paste!".to_string();
    let cmds = update(
        &mut model,
        Msg::Input(CrosstermEvent::Paste(paste_text.clone())),
    );

    // Should contain the text
    assert_eq!(get_text(&model.ui.input_state), paste_text);
    // Cursor should be at end
    assert_eq!(model.ui.input_state.cursor_pos, paste_text.len());
    // Should NOT have sent the message yet (no Enter)
    assert!(
        cmds.is_empty() || matches!(cmds[0], Cmd::Tox(ToxAction::SetTyping(..))),
        "Should not produce commands other than typing status"
    );
}

#[test]
fn test_bracketed_paste_multi_line() {
    let mut model = create_test_model();

    // Simulate multi-line paste event
    let paste_text = "Line 1\nLine 2\nLine 3".to_string();
    let cmds = update(
        &mut model,
        Msg::Input(CrosstermEvent::Paste(paste_text.clone())),
    );
    model.ui.input_state.ensure_layout(80, "> ");

    // Should contain the text with newlines
    assert_eq!(get_text(&model.ui.input_state), paste_text);
    // Cursor should be at end.
    // Line 1: "Line 1" (6)
    // Line 2: "Line 2" (6)
    // Line 3: "Line 3" (6)
    // cursor.y should be 2. cursor.x should be 8 (6 chars + 2 prompt).
    assert_eq!(model.ui.input_state.cursor().1, 2);
    assert_eq!(model.ui.input_state.cursor().0, 8);

    // Should NOT have sent the message yet
    for cmd in cmds {
        if let Cmd::Tox(
            ToxAction::SendMessage(..)
            | ToxAction::SendGroupMessage(..)
            | ToxAction::SendConferenceMessage(..),
        ) = cmd
        {
            panic!("Paste event triggered message sending!");
        }
    }
}

#[test]
fn test_alt_enter_inserts_newline() {
    let mut model = create_test_model();

    // Type "Line 1"
    for c in "Line 1".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    // Press Alt+Enter
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::ALT);

    // Verify newline is inserted (2 lines, first line "Line 1")
    assert_eq!(model.ui.input_state.lines.len(), 2);
    // Note: line_at was a bit different, but we can check graphemes or text
    assert_eq!(get_text(&model.ui.input_state), "Line 1\n");

    // Verify no commands were generated (i.e. message not sent)
    for cmd in cmds {
        if let Cmd::Tox(
            ToxAction::SendMessage(..)
            | ToxAction::SendGroupMessage(..)
            | ToxAction::SendConferenceMessage(..),
        ) = cmd
        {
            panic!("Alt+Enter triggered message sending!");
        }
    }

    // Type "Line 2"
    for c in "Line 2".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    assert_eq!(get_text(&model.ui.input_state), "Line 1\nLine 2");
}

#[test]
fn test_ctrl_o_inserts_newline() {
    let mut model = create_test_model();

    // Type "Line 1"
    for c in "Line 1".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    // Press Ctrl+O
    send_key(&mut model, KeyCode::Char('o'), KeyModifiers::CONTROL);

    // Verify newline is inserted
    assert_eq!(model.ui.input_state.lines.len(), 2);
    assert_eq!(get_text(&model.ui.input_state), "Line 1\n");

    // Type "Line 2"
    for c in "Line 2".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    assert_eq!(get_text(&model.ui.input_state), "Line 1\nLine 2");
}

#[test]
fn test_multiline_command_execution() {
    let mut model = create_test_model();

    // 1. Switch to MultiLine mode (Ctrl+T)
    send_key(&mut model, KeyCode::Char('t'), KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_mode, toxxi::model::InputMode::MultiLine);

    // 2. Type "/help"
    for c in "/help".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    // 3. Send (Ctrl+Enter)
    send_key(&mut model, KeyCode::Enter, KeyModifiers::CONTROL);

    // 4. Verify help message in console
    let help_msg = model.domain.console_messages.last().unwrap();
    if let toxxi::model::MessageContent::List(items) = &help_msg.content {
        assert!(items[0].contains("Available commands:"));
    } else {
        panic!("Expected help message list, got {:?}", help_msg.content);
    }
}

#[test]
fn test_update_clipboard_integration() {
    let mut model = create_test_model();

    // 1. Type "hello world"
    for c in "hello world".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    // 2. Select "world" (last 5 chars)
    // cursor is at index 11. Select 6..11
    model.ui.input_state.selection = Some((6, 11));

    // 3. Copy (Ctrl+C)
    send_key(&mut model, KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.clipboard, "world");
    assert_eq!(get_text(&model.ui.input_state), "hello world");

    // 4. Cut (Ctrl+X)
    send_key(&mut model, KeyCode::Char('x'), KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.clipboard, "world");
    assert_eq!(get_text(&model.ui.input_state), "hello ");

    // 5. Paste (Ctrl+V)
    send_key(&mut model, KeyCode::Char('v'), KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), "hello world");
}

#[test]
fn test_command_menu_activation() {
    let mut model = create_test_model();

    // Initially None
    assert!(model.ui.command_menu.is_none());

    // Type "/"
    send_key(&mut model, KeyCode::Char('/'), KeyModifiers::empty());

    // Should be active
    assert!(model.ui.command_menu.is_some());
    let state = model.ui.command_menu.as_ref().unwrap();
    assert_eq!(state.filter, "");
    assert!(!state.filtered_commands().is_empty());

    // Type more characters
    send_key(&mut model, KeyCode::Char('q'), KeyModifiers::empty());
    let state = model.ui.command_menu.as_ref().unwrap();
    assert_eq!(state.filter, "q");
    assert!(state.filtered_commands().iter().any(|c| c.name == "quit"));

    // Backspace the "/"
    send_key(&mut model, KeyCode::Backspace, KeyModifiers::empty());
    send_key(&mut model, KeyCode::Backspace, KeyModifiers::empty());
    assert!(model.ui.command_menu.is_none());
}

#[test]
fn test_command_menu_navigation_keys() {
    let mut model = create_test_model();

    // Type "/"
    send_key(&mut model, KeyCode::Char('/'), KeyModifiers::empty());
    let initial_selection = model
        .ui
        .command_menu
        .as_ref()
        .unwrap()
        .list_state
        .selected();

    // Press Down
    send_key(&mut model, KeyCode::Down, KeyModifiers::empty());
    let next_selection = model
        .ui
        .command_menu
        .as_ref()
        .unwrap()
        .list_state
        .selected();
    assert_ne!(initial_selection, next_selection);

    // Press Up
    send_key(&mut model, KeyCode::Up, KeyModifiers::empty());
    assert_eq!(
        model
            .ui
            .command_menu
            .as_ref()
            .unwrap()
            .list_state
            .selected(),
        initial_selection
    );

    // Press Esc
    send_key(&mut model, KeyCode::Esc, KeyModifiers::empty());
    assert!(model.ui.command_menu.is_none());
}

#[test]
fn test_command_menu_dismissal_on_enter() {
    let mut model = create_test_model();

    // 1. Type "/" to activate menu
    send_key(&mut model, KeyCode::Char('/'), KeyModifiers::empty());
    assert!(model.ui.command_menu.is_some());

    // 2. Type "help"
    for c in "help".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert!(model.ui.command_menu.is_some());

    // 3. Press Enter
    let _cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    // 4. Verify command was "executed" (produced output in console)
    assert!(
        model
            .domain
            .console_messages
            .iter()
            .any(|m| m.content.contains("Available commands:"))
    );

    // 5. Verify menu is closed
    assert!(
        model.ui.command_menu.is_none(),
        "Command menu should be closed after Enter"
    );
}

#[test]
fn test_command_menu_dismissal_on_ctrl_c() {
    let mut model = create_test_model();

    // 1. Type "/" to activate menu
    send_key(&mut model, KeyCode::Char('/'), KeyModifiers::empty());
    assert!(model.ui.command_menu.is_some());

    // 2. Press Ctrl+C
    send_key(&mut model, KeyCode::Char('c'), KeyModifiers::CONTROL);

    // 3. Verify input is cleared and menu is closed
    assert_eq!(get_text(&model.ui.input_state), "");
    assert!(
        model.ui.command_menu.is_none(),
        "Command menu should be closed after Ctrl+C"
    );
}

#[test]
fn test_update_file_command_completion() {
    let mut model = create_test_model();

    // 1. Type "/file s"
    for c in "/file s".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "/file s");

    // The command menu should be active
    assert!(model.ui.command_menu.is_some());

    // 2. Press Tab
    send_key(&mut model, KeyCode::Tab, KeyModifiers::empty());

    // 3. Verify auto-completion to "/file send " (Note the trailing space)
    assert_eq!(get_text(&model.ui.input_state), "/file send ");
}
