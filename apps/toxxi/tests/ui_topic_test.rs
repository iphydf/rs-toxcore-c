use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::GroupNumber;
use toxcore::types::{GroupChatId, PublicKey};
use toxxi::model::WindowId;
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
use toxxi::ui::draw;
use toxxi::update::update;
use toxxi_testing::{create_test_model, send_key};

#[test]
fn test_ui_topic_update_flow() {
    let mut model = create_test_model();
    let gnum = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gnum, chat_id);

    // A group window with no topic.
    model.ensure_group_window(chat_id);
    let window_id = WindowId::Group(chat_id);
    let window_index = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == window_id)
        .unwrap();
    model.set_active_window(window_index);

    // Hide the peer list, so lines don't wrap.
    model
        .ui
        .window_state
        .entry(window_id)
        .or_default()
        .show_peers = false;

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let topic_part: String = (25..80).map(|x| buffer[(x, 0)].symbol()).collect();

    assert!(
        topic_part.contains("Group 1"),
        "Topic bar should contain 'Group 1' initially, got: '{}'",
        topic_part
    );

    for c in "/topic New Topic".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let mut found_cmd = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::SetGroupTopic(id, topic)) = cmd {
            assert_eq!(id, chat_id);
            assert_eq!(topic, "New Topic");
            found_cmd = true;
        }
    }
    assert!(found_cmd);

    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupTopic(gnum, "New Topic".to_string(), None)),
    );

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let topic_part_after: String = (25..80).map(|x| buffer[(x, 0)].symbol()).collect();
    assert!(
        topic_part_after.contains("New Topic"),
        "Topic bar should contain 'New Topic' after event, got: '{}'",
        topic_part_after
    );

    // The topic change also shows in the chat,
    // on row 5, the last before the status bar (y=6).
    let chat_row: String = (25..80).map(|x| buffer[(x, 5)].symbol()).collect();
    assert!(
        chat_row.contains("* Topic changed to: New Topic"),
        "Chat row 5 should contain topic change system message, got: '{}'",
        chat_row
    );

    // The same event again, e.g. on reconnecting.
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupTopic(gnum, "New Topic".to_string(), None)),
    );

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();

    // Row 5 is still the same message, and row 4 isn't another topic message.
    let chat_row_prev: String = (25..80).map(|x| buffer[(x, 4)].symbol()).collect();
    assert!(
        !chat_row_prev.contains("* Topic changed to"),
        "Should not show redundant topic message"
    );
}

#[test]
fn test_ui_conference_topic_update_flow() {
    let mut model = create_test_model();
    let cnum = toxcore::tox::ConferenceNumber(1);
    let conf_id = toxcore::types::ConferenceId([1u8; 32]);
    model.session.conference_numbers.insert(cnum, conf_id);

    model.ensure_conference_window(conf_id);
    let window_id = WindowId::Conference(conf_id);
    let window_index = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == window_id)
        .unwrap();
    model.set_active_window(window_index);

    // Hide the peer list.
    model
        .ui
        .window_state
        .entry(window_id)
        .or_default()
        .show_peers = false;

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let topic_part: String = (25..80).map(|x| buffer[(x, 0)].symbol()).collect();
    assert!(
        topic_part.contains("Conference 1"),
        "Topic bar should contain 'Conference 1' initially, got: '{}'",
        topic_part
    );

    for c in "/topic New Conf Title".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    let mut found_cmd = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::SetConferenceTopic(id, topic)) = cmd {
            assert_eq!(id, conf_id);
            assert_eq!(topic, "New Conf Title");
            found_cmd = true;
        }
    }
    assert!(found_cmd);

    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(
            cnum,
            "New Conf Title".to_string(),
            Some(PublicKey([0u8; 32])),
        )),
    );

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let topic_part_after: String = (25..80).map(|x| buffer[(x, 0)].symbol()).collect();
    assert!(
        topic_part_after.contains("New Conf Title"),
        "Topic bar should contain 'New Conf Title' after event, got: '{}'",
        topic_part_after
    );

    let conv = &model.domain.conversations[&window_id];
    assert_eq!(
        conv.messages.last().unwrap().content.as_text(),
        Some("* Tester changed the title to: New Conf Title")
    );
}
