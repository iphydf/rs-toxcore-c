use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{ConferenceNumber, GroupNumber};
use toxcore::types::MessageType;
use toxxi::model::{MessageContent, Model, WindowId};
use toxxi::ui::draw;
use toxxi_testing::create_test_model;

fn topic_bar(model: &mut Model) -> String {
    let mut terminal = Terminal::new(TestBackend::new(200, 10)).unwrap();
    terminal.draw(|f| draw(f, model)).unwrap();
    let buffer = terminal.backend().buffer();
    (0..buffer.area.width)
        .map(|x| buffer[(x, 0)].symbol())
        .collect()
}

#[test]
fn test_group_messages() {
    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);

    model.add_group_message(
        chat_id,
        MessageType::Normal,
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
        MessageType::Normal,
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
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gid, chat_id);

    let cid = ConferenceNumber(2);
    let conf_id = toxcore::types::ConferenceId([2u8; 32]);
    model.session.conference_numbers.insert(cid, conf_id);

    model.add_group_message(
        chat_id,
        MessageType::Normal,
        "System".to_string(),
        "init".to_string(),
        None,
    );
    model.add_conference_message(
        conf_id,
        MessageType::Normal,
        "System".to_string(),
        "init".to_string(),
        None,
    );

    // Console topic
    model.set_active_window(0);
    assert!(topic_bar(&mut model).contains(
        "Tox ID: 0000000000000000000000000000000000000000000000000000000000000000000000000000"
    ));

    // Group topic
    model.set_active_window(1);
    assert!(topic_bar(&mut model).contains("Group 1"));

    // Conference topic
    model.set_active_window(2);
    assert!(topic_bar(&mut model).contains("Conference 2"));
}
