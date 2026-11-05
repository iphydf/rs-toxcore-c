use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::Connection;
use toxcore::types::{MessageType, PublicKey};
use toxxi::model::{PendingItem, WindowId};
use toxxi::ui::draw;
use toxxi_testing::create_test_model;

#[test]
fn test_status_bar_connection_indicators() {
    let mut model = create_test_model();
    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    // Offline.
    model.domain.self_connection_status = Connection::None;
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    // The status bar is at y=6: topic (0), messages (1-5), status (6), input (7-9).
    let status_row: String = (0..80).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(status_row.contains("Offline"), "Should show Offline status");

    // TCP.
    model.domain.self_connection_status = Connection::Tcp;
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row: String = (0..80).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(status_row.contains("TCP"), "Should show TCP status");

    // UDP.
    model.domain.self_connection_status = Connection::Udp;
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row: String = (0..80).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(status_row.contains("UDP"), "Should show UDP status");
}

#[test]
fn test_status_bar_unread_notifications() {
    let mut model = create_test_model();

    let pk1 = PublicKey([1u8; 32]);
    let pk2 = PublicKey([2u8; 32]);

    model.domain.friends.insert(
        pk1,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk1),
            status_message: "".to_string(),
            connection: Connection::None,
            is_typing: false,
        },
    );
    model.domain.friends.insert(
        pk2,
        toxxi::model::FriendInfo {
            name: "Friend 2".to_string(),
            public_key: Some(pk2),
            status_message: "".to_string(),
            connection: Connection::None,
            is_typing: false,
        },
    );

    model.ensure_friend_window(pk1);
    model.ensure_friend_window(pk2);

    // Show F1's window (1, after the console).
    model.set_active_window(1);

    // A message to F2, not shown.
    model.add_friend_message(pk2, MessageType::Normal, "Hello".to_string());

    let backend = TestBackend::new(100, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let status_row: String = (0..100).map(|x| buffer[(x, 6)].symbol()).collect();

    // F2 shows the unread count.
    assert!(
        status_row.contains("Friend 2"),
        "Friend 2 should be in status bar"
    );
    assert!(
        status_row.contains("(1)"),
        "Should show unread count (1) in status bar: {}",
        status_row
    );

    assert_eq!(
        model.ui.window_state[&WindowId::Friend(pk2)].unread_count,
        1
    );
    assert_eq!(
        model.ui.window_state[&WindowId::Friend(pk1)].unread_count,
        0
    );
}

#[test]
fn test_status_bar_pending_requests() {
    let mut model = create_test_model();

    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row_empty: String = (0..80).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(
        !status_row_empty.contains("PENDING"),
        "Should not show PENDING when empty"
    );

    model.domain.pending_items.push(PendingItem::FriendRequest {
        pk: PublicKey([1u8; 32]),
        message: "Hi".to_string(),
    });

    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row_pending: String = (0..80).map(|x| buffer[(x, 6)].symbol()).collect();

    assert!(
        status_row_pending.contains("PENDING: 1"),
        "Should show PENDING: 1"
    );
}
