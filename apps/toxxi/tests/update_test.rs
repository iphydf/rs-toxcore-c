use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use toxcore::tox::{
    ConferenceNumber, ConferencePeerNumber, GroupNumber, GroupPeerNumber, UserStatus,
};
use toxcore::types::{ConferenceId, GroupChatId, GroupRole, LogLevel, MessageType, PublicKey};
use toxxi::model::{ConsoleMessageType, FriendInfo, Model, PeerId, WindowId};
use toxxi::msg::{AppCmd, Cmd, Msg, SystemEvent, ToxAction, ToxEvent};
use toxxi::ui::draw;
use toxxi::update::{shows, update};
use toxxi_testing as testing;

fn create_test_model() -> Model {
    let mut model = testing::create_test_model();
    model.record_account();
    model
}

fn add_test_friend(model: &mut Model, pk: PublicKey) {
    testing::add_test_friend(model, pk);
    model.record_account();
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
    let cmds = testing::send_key(model, code, modifiers);
    model.ui.input_state.ensure_layout(80, "> ");
    cmds
}

fn get_text(input: &toxxi::widgets::InputBoxState) -> String {
    input.text.clone()
}

#[test]
fn test_update_enter_command() {
    let mut model = create_test_model();

    for c in "/quit".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());
    assert!(cmds.contains(&Cmd::App(AppCmd::Quit)));
}

#[test]
fn test_update_control_keys() {
    let mut model = create_test_model();

    // Ctrl+N: next window.
    send_key(&mut model, KeyCode::Char('n'), KeyModifiers::CONTROL);
    assert_eq!(model.ui.active_window_index, 0); // No friends, so still 0.

    let pk = PublicKey([1u8; 32]);
    model.add_friend_message(pk, MessageType::Normal, "hi".to_string());
    send_key(&mut model, KeyCode::Char('n'), KeyModifiers::CONTROL);
    assert_eq!(model.ui.active_window_index, 1);

    // Ctrl+U kills to the start of the line.
    for c in "hello".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "hello");
    send_key(&mut model, KeyCode::Char('u'), KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), "");

    let cmds = send_key(&mut model, KeyCode::Char('l'), KeyModifiers::CONTROL);
    assert!(cmds.contains(&Cmd::App(AppCmd::Redraw)));
}

#[test]
fn test_update_ctrl_c_behavior() {
    let mut model = create_test_model();

    for c in "partial command".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "partial command");

    model.ui.completion.active = true;
    model.ui.completion.candidates = vec!["completion".to_string()];

    let cmds = send_key(&mut model, KeyCode::Char('c'), KeyModifiers::CONTROL);

    // Ctrl+C clears the input and the completion, and doesn't quit.
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
    let pk5 = PublicKey([5u8; 32]);

    update(
        &mut model,
        Msg::Tox(ToxEvent::Message(
            pk5,
            MessageType::Normal,
            b"hello from 5".to_vec(),
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

    update(
        &mut model,
        Msg::Tox(ToxEvent::Log {
            level: toxcore::types::LogLevel::Info,
            file: "file".to_owned(),
            line: 1,
            func: "func".to_owned(),
            message: "system error".to_string(),
        }),
    );
    assert!(
        model
            .domain
            .tox_logs
            .get(&toxcore::types::LogLevel::Info)
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
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);

    for c in "/msg 01010101 hello".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let mut found = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::SendMessage(f, t, msg, _)) = cmd {
            assert_eq!(f, pk);
            assert_eq!(t, MessageType::Normal);
            assert_eq!(msg, b"hello");
            found = true;
        }
    }
    assert!(found);

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
    model.add_friend_message(pk, MessageType::Normal, "hi".to_string());

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
        MessageType::Normal,
        "System".to_string(),
        "init".to_string(),
        None,
    );
    model.set_active_window(1);

    for c in "/close".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(cmds.contains(&Cmd::Tox(ToxAction::LeaveGroup(chat_id))));
    assert_eq!(model.ui.window_ids.len(), 1); // Only the console is left.
    assert_eq!(model.ui.active_window_index, 0);
}

#[test]
fn test_handle_query_command() {
    let mut model = create_test_model();
    let pk = PublicKey([5u8; 32]);
    model.domain.friends.insert(
        pk,
        FriendInfo {
            name: "Friend 5".to_string(),
            public_key: Some(pk),
            status_message: "".to_string(),
            connection: toxcore::tox::Connection::None,
            is_typing: false,
        },
    );

    for c in "/query 05050505".chars() {
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

    // As if loaded from the saved state.
    model.session.group_numbers.insert(gid1, chat_id1);
    model.session.group_numbers.insert(gid2, chat_id2);
    model.ensure_group_window(chat_id1);
    model.ensure_group_window(chat_id2);
    model.set_active_window(1);

    assert_eq!(model.ui.active_window_index, 1);

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupCreated(gid1, chat_id1, None)),
    );
    assert_eq!(model.ui.active_window_index, 1);

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupCreated(gid2, chat_id2, None)),
    );
    assert_eq!(model.ui.active_window_index, 1);

    let gid3 = GroupNumber(3);
    let chat_id3 = GroupChatId([3u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupCreated(gid3, chat_id3, None)),
    );
    assert_eq!(model.ui.active_window_index, 3);
}

#[test]
fn test_handle_conference_created_msg() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(42);
    let conf_id = ConferenceId([0u8; 32]);

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

    // As if loaded from the saved state.
    model.session.conference_numbers.insert(cid1, conf_id1);
    model.session.conference_numbers.insert(cid2, conf_id2);
    model.ensure_conference_window(conf_id1);
    model.ensure_conference_window(conf_id2);
    model.set_active_window(1);

    assert_eq!(model.ui.active_window_index, 1);

    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceCreated(cid1, conf_id1)),
    );
    assert_eq!(model.ui.active_window_index, 1);

    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceCreated(cid2, conf_id2)),
    );
    assert_eq!(model.ui.active_window_index, 1);

    let cid3 = ConferenceNumber(3);
    let conf_id3 = ConferenceId([3u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceCreated(cid3, conf_id3)),
    );
    assert_eq!(model.ui.active_window_index, 3);
}

#[test]
fn test_handle_group_msg_sending() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    add_test_group(&mut model, gid, chat_id);

    model.add_group_message(
        chat_id,
        MessageType::Normal,
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
            assert_eq!(t, MessageType::Normal);
            assert_eq!(msg, b"hello group");
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
        MessageType::Normal,
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
            assert_eq!(t, MessageType::Normal);
            assert_eq!(msg, b"hello conf");
            found = true;
        }
    }
    assert!(found);
}

#[test]
fn test_handle_whois_command() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    model.domain.friends.insert(
        pk,
        FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk),
            status_message: "Testing".to_string(),
            connection: toxcore::tox::Connection::Tcp,
            is_typing: false,
        },
    );

    for c in "/whois alice".chars() {
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
        MessageType::Normal,
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
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);

    model.add_friend_message(pk, MessageType::Action, "waves".to_string());
    model.set_active_window(1);

    for c in "/me is   coding".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());
    let actions = |cmds: Vec<Cmd>| -> Vec<Vec<u8>> {
        cmds.into_iter()
            .filter_map(|cmd| match cmd {
                Cmd::Tox(ToxAction::SendMessage(f, MessageType::Action, msg, _)) if f == pk => {
                    Some(msg)
                }
                _ => None,
            })
            .collect()
    };
    assert_eq!(actions(cmds), vec![b"is   coding".to_vec()]);

    // Theirs and ours read as actions.
    let mut terminal = Terminal::new(TestBackend::new(80, 13)).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let screen: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(screen.contains("Friend 1 waves"), "{screen}");
    assert!(screen.contains("Tester is   coding"), "{screen}");

    // Too long for one message, it goes in parts as messages do.
    let long = "x".repeat(toxcore::types::MAX_MESSAGE_LENGTH + 1);
    let parts = actions(toxxi::update::handle_enter(
        &mut model,
        &format!("/me {long}"),
    ));
    assert_eq!(parts.concat(), long.into_bytes());
    assert_eq!(parts.len(), 2);
}

#[test]
fn test_handle_friend_add_multiword() {
    let mut model = create_test_model();
    let tox_id = "56A1AA2D01452D792B607E92A2875149363B346F41E5D571936A69666497B3431D80054FD55B";

    for c in format!("/friend add {} Hello from Toxxi!", tox_id).chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let mut found = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::AddFriend(id, msg)) = cmd {
            assert_eq!(id.to_string(), tox_id.to_lowercase());
            assert_eq!(msg, "Hello from Toxxi!");
            found = true;
        }
    }
    assert!(found);
}

#[test]
fn test_bad_ids_are_refused() {
    let mut model = create_test_model();
    for line in [
        "/friend add nothex",
        "/friend add aéa",
        "/friend add 56A1",
        "/group join nothex",
        "/group join aéa",
        "/group join 56A1",
    ] {
        let cmds = toxxi::update::handle_enter(&mut model, line);
        assert!(
            !cmds.iter().any(|cmd| matches!(
                cmd,
                Cmd::Tox(ToxAction::AddFriend(..) | ToxAction::JoinGroup(..))
            )),
            "{line}"
        );
    }
}

#[test]
fn test_friends_of_one_name_need_their_key() {
    let mut model = create_test_model();
    for key in [[1u8; 32], [2u8; 32]] {
        let pk = PublicKey(key);
        add_test_friend(&mut model, pk);
        model.domain.friends.get_mut(&pk).unwrap().name = "Alice".to_owned();
    }
    model.set_active_window(0);
    assert_eq!(model.active_window_id(), WindowId::Console);
    let sends = |cmds: &[Cmd]| {
        cmds.iter()
            .filter_map(|cmd| match cmd {
                Cmd::Tox(ToxAction::SendMessage(pk, ..)) => Some(*pk),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    let cmds = toxxi::update::handle_enter(&mut model, "/msg alice hi");
    assert!(sends(&cmds).is_empty());
    let error = model.domain.console_messages.last().unwrap();
    assert!(error.content.contains("01010101 Alice"));
    assert!(error.content.contains("02020202 Alice"));

    let cmds = toxxi::update::handle_enter(&mut model, "/msg 0202 hi");
    assert_eq!(sends(&cmds), vec![PublicKey([2u8; 32])]);
}

#[test]
fn test_file_send_in_a_chat_goes_to_its_friend() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);
    model.set_active_window(
        model
            .ui
            .window_ids
            .iter()
            .position(|w| *w == WindowId::Friend(pk))
            .unwrap(),
    );
    let file = tempfile::NamedTempFile::new().unwrap();

    let cmds =
        toxxi::update::handle_enter(&mut model, &format!("/file send {}", file.path().display()));
    assert!(cmds.iter().any(|cmd| matches!(
        cmd,
        Cmd::Tox(ToxAction::FileSend { friend, .. }) if *friend == pk
    )));
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
fn test_tox_logs_show_only_in_the_logs_window() {
    let mut model = create_test_model();
    model.ui.window_ids = vec![WindowId::Console, WindowId::Logs];
    let log = Msg::Tox(ToxEvent::Log {
        level: LogLevel::Trace,
        file: String::new(),
        line: 0,
        func: String::new(),
        message: String::new(),
    });
    assert!(!shows(&model, &log));
    assert!(shows(&model, &Msg::System(SystemEvent::Tick)));
    model.set_active_window(1);
    assert!(shows(&model, &log));
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

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            gid,
            GroupPeerNumber(3),
            "Alice".to_owned(),
            GroupRole::User,
            PublicKey([3u8; 32]),
        )),
    );
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupTopic(
            gid,
            "New Group Topic".to_string(),
            Some(PublicKey([3u8; 32])),
        )),
    );
    let group_window = WindowId::Group(chat_id);
    let group = model.domain.conversations.get(&group_window).unwrap();
    assert_eq!(group.topic, Some("New Group Topic".to_string()));
    assert_eq!(
        group.messages.last().unwrap().content.as_text(),
        Some("* Alice changed the topic to: New Group Topic")
    );
    assert_eq!(model.window_name(group_window), "Group 1");

    for (n, name) in [(4, "Bob"), (5, "")] {
        update(
            &mut model,
            Msg::Tox(ToxEvent::ConferencePeerJoin(
                cid,
                ConferencePeerNumber(n),
                name.to_owned(),
                PublicKey([n as u8; 32]),
            )),
        );
    }
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(
            cid,
            "New Conference Title".to_owned(),
            Some(PublicKey([4u8; 32])),
        )),
    );
    let conf_window = WindowId::Conference(conf_id);
    assert_eq!(
        model.domain.conversations[&conf_window]
            .messages
            .last()
            .unwrap()
            .content
            .as_text(),
        Some("* Bob changed the title to: New Conference Title")
    );
    assert_eq!(
        model.domain.conversations.get(&conf_window).unwrap().topic,
        None
    );
    assert_eq!(
        model.domain.conversations.get(&conf_window).unwrap().name,
        "New Conference Title".to_string()
    );

    // Conference peers can go unnamed.
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(
            cid,
            "Unnamed".to_owned(),
            Some(PublicKey([5u8; 32])),
        )),
    );
    assert_eq!(
        model.domain.conversations[&conf_window]
            .messages
            .last()
            .unwrap()
            .content
            .as_text(),
        Some("* Title changed to: Unnamed")
    );
}

#[test]
fn test_update_scroll_keys() {
    let mut model = create_test_model();
    for i in 0..100 {
        model.add_console_message(ConsoleMessageType::Info, format!("msg {}", i));
    }

    let id = WindowId::Console;
    let backend = TestBackend::new(80, 13);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

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

    send_key(&mut model, KeyCode::PageDown, KeyModifiers::empty());
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
    let pk = PublicKey([1u8; 32]);
    model.add_friend_message(pk, MessageType::Normal, "hi".to_string());
    model.set_active_window(1);

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

    // /clear defaults to system messages.
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

    // ASCII.
    for c in "hello world".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "hello world");
    send_key(&mut model, KeyCode::Char('w'), KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), "hello ");

    // Multi-byte characters.
    model.ui.input_state.set_value("".to_string());
    model.ui.input_state.set_cursor(0, 0);
    for c in "🦀 🦀 🦀".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "🦀 🦀 🦀");
    send_key(&mut model, KeyCode::Char('w'), KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), "🦀 🦀 ");
}

#[test]
fn test_update_ctrl_backspace_delete_behavior() {
    let mut model = create_test_model();

    for c in "hello world".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "hello world");
    send_key(&mut model, KeyCode::Backspace, KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), "hello ");

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

    for c in "🦀 🦀 🦀".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let end_pos = model.ui.input_state.cursor().0;
    assert_eq!(end_pos, 10); // 3 crabs(6) + 2 spaces(2) + prompt(2) = 10

    // Move left: jumps over the last crab to position 8.
    send_key(&mut model, KeyCode::Left, KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.cursor().0, 8);

    // Move left again: jumps over the space (7) and the middle crab (5) to position 5.
    send_key(&mut model, KeyCode::Left, KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.cursor().0, 5);

    // Move left again: jumps over the space (4) and the first crab (2) to position 2.
    send_key(&mut model, KeyCode::Left, KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.cursor().0, 2);

    // Move right: jumps over the first crab to position 4.
    send_key(&mut model, KeyCode::Right, KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.cursor().0, 4);

    // Move right again: jumps over the space (5) and the middle crab (7) to position 7.
    send_key(&mut model, KeyCode::Right, KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.cursor().0, 7);
}

#[test]
fn test_friend_remove_command_displays_info() {
    let mut model = create_test_model();
    let pk = "5555555555555555555555555555555555555555555555555555555555555555";

    let pk_arr = [0x55u8; 32];
    let pk_obj = PublicKey(pk_arr);
    model.domain.friends.insert(
        pk_obj,
        FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk_obj),
            status_message: "Online".to_string(),
            connection: toxcore::tox::Connection::Udp,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk_obj);

    let input = "/friend remove Alice";
    for c in input.chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(!model.domain.friends.contains_key(&pk_obj));

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

    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(
            cid,
            "My Conference".to_string(),
            None,
        )),
    );

    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(conv.name, "My Conference");
    assert_eq!(conv.topic, None);

    // Reconnecting, with no title and then the same one again, says nothing.
    let said = conv.messages.len();
    for title in ["", "My Conference"] {
        update(
            &mut model,
            Msg::Tox(ToxEvent::ConferenceTitle(cid, title.to_string(), None)),
        );
    }
    let conv = model.domain.conversations.get(&window_id).unwrap();
    assert_eq!(conv.messages.len(), said);
}

#[test]
fn test_conference_title_update_empty_preserves_name() {
    let mut model = create_test_model();
    let cid = ConferenceNumber(1);
    let conf_id = ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);
    model.ensure_conference_window(conf_id);
    let window_id = WindowId::Conference(conf_id);

    assert_eq!(model.window_name(window_id), "Conference 1");

    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(cid, "".to_string(), None)),
    );

    let conv = model.domain.conversations.get(&window_id).unwrap();
    // A conference has no topic.
    assert_eq!(model.window_name(window_id), "Conference 1");
    assert_eq!(conv.topic, None);
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
    // The first name isn't a rename.
    assert!(conv.messages.is_empty());
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
        Msg::Tox(ToxEvent::GroupTopic(gnum, "New Topic".to_string(), None)),
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

    let mut model = create_test_model();
    model.session.group_numbers.insert(gid, chat_id);
    model.session.conference_numbers.insert(cid, conf_id);
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupTopic(gid, "Group Topic".to_string(), None)),
    );
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Group(chat_id))
    );

    let mut model = create_test_model();
    model.session.group_numbers.insert(gid, chat_id);
    model.session.conference_numbers.insert(cid, conf_id);
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupSelfRole(
            gid,
            toxcore::types::GroupRole::Founder,
        )),
    );
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Group(chat_id))
    );

    let mut model = create_test_model();
    model.session.group_numbers.insert(gid, chat_id);
    model.session.conference_numbers.insert(cid, conf_id);
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(
            cid,
            "Conf Title".to_string(),
            None,
        )),
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

    let pk = PublicKey([5u8; 32]);
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            gid,
            pid,
            "Peer5".to_string(),
            toxcore::types::GroupRole::User,
            pk,
        )),
    );

    let window_id = WindowId::Group(chat_id);
    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        let peer = conv.peers.iter().find(|p| p.id == PeerId(pk)).unwrap();
        assert_eq!(peer.status, UserStatus::None);
    }

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerStatus(gid, pid, UserStatus::Away)),
    );

    {
        let conv = model.domain.conversations.get(&window_id).unwrap();
        let peer = conv.peers.iter().find(|p| p.id == PeerId(pk)).unwrap();
        assert_eq!(peer.status, UserStatus::Away);
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

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            gid,
            pid,
            "Peer5".to_string(),
            GroupRole::User,
            pk,
        )),
    );

    // The same peer joins again, as in a duplicate event.
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            gid,
            pid,
            "Peer5".to_string(),
            GroupRole::User,
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
    let self_pk = model.domain.self_public_key();

    model.ensure_group_window(chat_id);
    let window_id = WindowId::Group(chat_id);

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPeerJoin(
            gid,
            GroupPeerNumber(0),
            "Tester".to_string(),
            GroupRole::Founder,
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
        // Duplicate peers, as in a saved state with duplicates.
        for i in 0..3 {
            conv.peers.push(toxxi::model::PeerInfo {
                id: PeerId(pk),
                name: format!("Peer {}", i),
                role: None,
                status: UserStatus::None,
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

    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferencePeerJoin(
            cid,
            toxcore::tox::ConferencePeerNumber(0),
            "Peer5".to_string(),
            pk,
        )),
    );

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

    let paste_text = "Hello, Paste!".to_string();
    let cmds = update(
        &mut model,
        Msg::Input(CrosstermEvent::Paste(paste_text.clone())),
    );

    assert_eq!(get_text(&model.ui.input_state), paste_text);
    assert_eq!(model.ui.input_state.cursor_pos, paste_text.len());
    assert!(
        cmds.is_empty() || matches!(cmds[0], Cmd::Tox(ToxAction::SetTyping(..))),
        "Should not produce commands other than typing status"
    );
}

#[test]
fn test_bracketed_paste_multi_line() {
    let mut model = create_test_model();

    let paste_text = "Line 1\nLine 2\nLine 3".to_string();
    let cmds = update(
        &mut model,
        Msg::Input(CrosstermEvent::Paste(paste_text.clone())),
    );
    model.ui.input_state.ensure_layout(80, "> ");

    assert_eq!(get_text(&model.ui.input_state), paste_text);
    // The cursor is at the end: line 3, after 6 characters and the 2-column prompt.
    assert_eq!(model.ui.input_state.cursor().1, 2);
    assert_eq!(model.ui.input_state.cursor().0, 8);

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

    for c in "Line 1".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::ALT);

    assert_eq!(model.ui.input_state.lines.len(), 2);
    assert_eq!(get_text(&model.ui.input_state), "Line 1\n");

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

    for c in "Line 2".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    assert_eq!(get_text(&model.ui.input_state), "Line 1\nLine 2");
}

#[test]
fn test_ctrl_o_inserts_newline() {
    let mut model = create_test_model();

    for c in "Line 1".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    send_key(&mut model, KeyCode::Char('o'), KeyModifiers::CONTROL);

    assert_eq!(model.ui.input_state.lines.len(), 2);
    assert_eq!(get_text(&model.ui.input_state), "Line 1\n");

    for c in "Line 2".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    assert_eq!(get_text(&model.ui.input_state), "Line 1\nLine 2");
}

#[test]
fn test_multiline_command_execution() {
    let mut model = create_test_model();

    send_key(&mut model, KeyCode::Char('t'), KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_mode, toxxi::model::InputMode::MultiLine);

    for c in "/help".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    send_key(&mut model, KeyCode::Enter, KeyModifiers::CONTROL);

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

    for c in "hello world".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }

    // Select "world".
    model.ui.input_state.selection = Some((6, 11));

    send_key(&mut model, KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.clipboard, "world");
    assert_eq!(get_text(&model.ui.input_state), "hello world");

    send_key(&mut model, KeyCode::Char('x'), KeyModifiers::CONTROL);
    assert_eq!(model.ui.input_state.clipboard, "world");
    assert_eq!(get_text(&model.ui.input_state), "hello ");

    send_key(&mut model, KeyCode::Char('v'), KeyModifiers::CONTROL);
    assert_eq!(get_text(&model.ui.input_state), "hello world");
}

#[test]
fn test_command_menu_activation() {
    let mut model = create_test_model();

    assert!(model.ui.command_menu.is_none());

    send_key(&mut model, KeyCode::Char('/'), KeyModifiers::empty());

    assert!(model.ui.command_menu.is_some());
    let state = model.ui.command_menu.as_ref().unwrap();
    assert_eq!(state.filter, "");
    assert!(!state.filtered_commands().is_empty());

    send_key(&mut model, KeyCode::Char('q'), KeyModifiers::empty());
    let state = model.ui.command_menu.as_ref().unwrap();
    assert_eq!(state.filter, "q");
    assert!(state.filtered_commands().iter().any(|c| c.name == "quit"));

    send_key(&mut model, KeyCode::Backspace, KeyModifiers::empty());
    send_key(&mut model, KeyCode::Backspace, KeyModifiers::empty());
    assert!(model.ui.command_menu.is_none());
}

#[test]
fn test_command_menu_navigation_keys() {
    let mut model = create_test_model();

    send_key(&mut model, KeyCode::Char('/'), KeyModifiers::empty());
    let initial_selection = model
        .ui
        .command_menu
        .as_ref()
        .unwrap()
        .list_state
        .selected();

    send_key(&mut model, KeyCode::Down, KeyModifiers::empty());
    let next_selection = model
        .ui
        .command_menu
        .as_ref()
        .unwrap()
        .list_state
        .selected();
    assert_ne!(initial_selection, next_selection);

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

    send_key(&mut model, KeyCode::Esc, KeyModifiers::empty());
    assert!(model.ui.command_menu.is_none());
}

#[test]
fn test_command_menu_dismissal_on_enter() {
    let mut model = create_test_model();

    send_key(&mut model, KeyCode::Char('/'), KeyModifiers::empty());
    assert!(model.ui.command_menu.is_some());

    for c in "help".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert!(model.ui.command_menu.is_some());

    let _cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    assert!(
        model
            .domain
            .console_messages
            .iter()
            .any(|m| m.content.contains("Available commands:"))
    );

    assert!(
        model.ui.command_menu.is_none(),
        "Command menu should be closed after Enter"
    );
}

#[test]
fn test_command_menu_dismissal_on_ctrl_c() {
    let mut model = create_test_model();

    send_key(&mut model, KeyCode::Char('/'), KeyModifiers::empty());
    assert!(model.ui.command_menu.is_some());

    send_key(&mut model, KeyCode::Char('c'), KeyModifiers::CONTROL);

    assert_eq!(get_text(&model.ui.input_state), "");
    assert!(
        model.ui.command_menu.is_none(),
        "Command menu should be closed after Ctrl+C"
    );
}

#[test]
fn test_update_file_command_completion() {
    let mut model = create_test_model();

    for c in "/file s".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    assert_eq!(get_text(&model.ui.input_state), "/file s");

    assert!(model.ui.command_menu.is_some());

    send_key(&mut model, KeyCode::Tab, KeyModifiers::empty());

    assert_eq!(get_text(&model.ui.input_state), "/file send ");
}

#[test]
fn test_nospam_command() {
    let mut model = create_test_model();
    let nospam = |model: &mut Model, line: &str| -> Option<u32> {
        toxxi::update::handle_command(model, line)
            .into_iter()
            .find_map(|cmd| match cmd {
                Cmd::Tox(ToxAction::SetNospam(n)) => Some(n),
                _ => None,
            })
    };
    assert_eq!(nospam(&mut model, "/nospam 0A0B0c0D"), Some(0x0a0b0c0d));
    assert!(nospam(&mut model, "/nospam new").is_some());
    for wrong in [
        "/nospam",
        "/nospam 0A0B0C",
        "/nospam +A0B0C0D",
        "/nospam xyz",
    ] {
        assert_eq!(nospam(&mut model, wrong), None, "{wrong}");
    }
}

#[test]
fn test_private_messages_read_as_private() {
    let mut model = create_test_model();
    let chat_id = GroupChatId([5u8; 32]);
    add_test_group(&mut model, GroupNumber(0), chat_id);
    let bob = PublicKey([2u8; 32]);
    model
        .domain
        .conversations
        .get_mut(&WindowId::Group(chat_id))
        .unwrap()
        .peers
        .push(toxxi::model::PeerInfo {
            id: PeerId(bob),
            name: "Bob".to_owned(),
            role: Some(GroupRole::User),
            status: UserStatus::None,
            is_ignored: false,
            seen_online: true,
        });
    model.set_active_window(1);
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupPrivateMessage(
            GroupNumber(0),
            GroupPeerNumber(1),
            MessageType::Normal,
            b"psst".to_vec(),
            bob,
        )),
    );
    toxxi::update::handle_command(&mut model, "/whisper Bob hi");

    let mut terminal = Terminal::new(TestBackend::new(80, 13)).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let screen: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(screen.contains("(privately) psst"), "{screen}");
    assert!(screen.contains("(privately to Bob) hi"), "{screen}");
}
