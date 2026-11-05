use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::GroupNumber;
use toxcore::types::PublicKey;
use toxxi::model::WindowId;
use toxxi::ui::draw;
use toxxi_testing::{create_test_model, send_key};

#[test]
fn test_ui_navigation_rendering() {
    let mut model = create_test_model();

    let f1_pk = PublicKey([1u8; 32]);

    // ensure_friend_window only makes the conversation, so add the friend for the name "Alice".
    model.domain.friends.insert(
        f1_pk,
        toxxi::model::FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(f1_pk),
            status_message: "".to_string(),
            connection: toxcore::tox::Connection::None,
            is_typing: false,
        },
    );

    model.ensure_friend_window(f1_pk);
    // ensure_friend_window may have named the conversation before the friend info was set.
    if let Some(conv) = model.domain.conversations.get_mut(&WindowId::Friend(f1_pk)) {
        conv.name = "Alice".to_string();
    }

    let g1_num = GroupNumber(1);
    let g1_chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(g1_num, g1_chat_id);

    model.ensure_group_window(g1_chat_id);
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Group(g1_chat_id))
    {
        conv.name = "Rustacean Station".to_string();
    }

    let backend = TestBackend::new(80, 20);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let header_row: String = (0..80).map(|x| buffer[(x, 0)].symbol()).collect();
    assert!(
        header_row.contains("Tox ID:"),
        "Should be on Console window, got header: {}",
        header_row
    );

    // Ctrl+N: Alice.
    send_key(&mut model, KeyCode::Char('n'), KeyModifiers::CONTROL);
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let header_row: String = (0..80).map(|x| buffer[(x, 0)].symbol()).collect();
    assert!(
        header_row.contains("Alice"),
        "Should be on Friend window 'Alice', got header: {}",
        header_row
    );

    // Ctrl+N: the group.
    send_key(&mut model, KeyCode::Char('n'), KeyModifiers::CONTROL);
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let header_row: String = (0..80).map(|x| buffer[(x, 0)].symbol()).collect();
    assert!(
        header_row.contains("Rustacean Station"),
        "Should be on Group window, got header: {}",
        header_row
    );

    // Ctrl+P: back to Alice.
    send_key(&mut model, KeyCode::Char('p'), KeyModifiers::CONTROL);

    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let header_row: String = (0..80).map(|x| buffer[(x, 0)].symbol()).collect();
    assert!(
        header_row.contains("Alice"),
        "Should be back on Alice, got header: {}",
        header_row
    );

    // Alt+0: the console.
    send_key(&mut model, KeyCode::Char('0'), KeyModifiers::ALT);
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let header_row: String = (0..80).map(|x| buffer[(x, 0)].symbol()).collect();
    assert!(
        header_row.contains("Tox ID:"),
        "Should jump to Console, got header: {}",
        header_row
    );
}
