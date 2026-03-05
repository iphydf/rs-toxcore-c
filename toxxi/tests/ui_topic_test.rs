use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, GroupNumber, ToxUserStatus};
use toxcore::types::{GroupChatId, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, WindowId};
use toxxi::msg::{Cmd, Msg, ToxAction, ToxEvent};
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

fn send_key(model: &mut Model, code: KeyCode, mods: KeyModifiers) -> Vec<Cmd> {
    update(
        model,
        Msg::Input(crossterm::event::Event::Key(
            crossterm::event::KeyEvent::new(code, mods),
        )),
    )
}

#[test]
fn test_ui_topic_update_flow() {
    let mut model = create_test_model();
    let gnum = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(gnum, chat_id);

    // 1. Initial state: Group window exists but no topic set
    model.ensure_group_window(chat_id);
    let window_id = WindowId::Group(chat_id);
    let window_index = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == window_id)
        .unwrap();
    model.set_active_window(window_index);

    // Disable peer list to make room and avoid wrapping surprises
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
    // Row 0 contains Sidebar (with borders) and Topic Bar
    let topic_part: String = (25..80).map(|x| buffer[(x, 0)].symbol()).collect();

    assert!(
        topic_part.contains("Group 1"),
        "Topic bar should contain 'Group 1' initially, got: '{}'",
        topic_part
    );

    // 2. Simulate typing /topic New Topic
    for c in "/topic New Topic".chars() {
        send_key(&mut model, KeyCode::Char(c), KeyModifiers::empty());
    }
    let cmds = send_key(&mut model, KeyCode::Enter, KeyModifiers::empty());

    // Verify command generated
    let mut found_cmd = false;
    for cmd in cmds {
        if let Cmd::Tox(ToxAction::SetGroupTopic(id, topic)) = cmd {
            assert_eq!(id, chat_id);
            assert_eq!(topic, "New Topic");
            found_cmd = true;
        }
    }
    assert!(found_cmd);

    // 3. Simulate Tox event arriving
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupTopic(gnum, "New Topic".to_string())),
    );

    // 4. Draw again and verify topic bar AND message list
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let topic_part_after: String = (25..80).map(|x| buffer[(x, 0)].symbol()).collect();
    assert!(
        topic_part_after.contains("New Topic"),
        "Topic bar should contain 'New Topic' after event, got: '{}'",
        topic_part_after
    );

    // Also check if system message appears in chat
    // In a 10-row terminal, row 5 is usually the last message row before status bar (y=6).
    let chat_row: String = (25..80).map(|x| buffer[(x, 5)].symbol()).collect();
    assert!(
        chat_row.contains("* Topic changed to: New Topic"),
        "Chat row 5 should contain topic change system message, got: '{}'",
        chat_row
    );

    // 5. Simulate the SAME Tox event arriving again (e.g. on reconn/reconcile)
    update(
        &mut model,
        Msg::Tox(ToxEvent::GroupTopic(gnum, "New Topic".to_string())),
    );

    // Draw again
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();

    // Chat row 5 should still be the SAME message, and row 4 should NOT contain another topic message
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

    // Disable peer list to make room
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

    // Simulate typing /topic New Conf Title
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

    // Simulate event
    update(
        &mut model,
        Msg::Tox(ToxEvent::ConferenceTitle(
            cnum,
            "New Conf Title".to_string(),
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

    // Check system message
    let chat_row: String = (25..80).map(|x| buffer[(x, 5)].symbol()).collect();
    assert!(
        chat_row.contains("* Topic changed to: New Conf Title"),
        "Chat row should contain system message, got: '{}'",
        chat_row
    );
}
