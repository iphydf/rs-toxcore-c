use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, PendingItem, WindowId};
use toxxi::ui::draw;

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
fn test_status_bar_connection_indicators() {
    let mut model = create_test_model();
    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();

    // 1. Offline
    model.domain.self_connection_status = ToxConnection::TOX_CONNECTION_NONE;
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    // Status bar is at y=6 (height 10, layout: topic(1), msg(min1), status(1), input(3)) -> 0, 1..5, 6, 7..9
    let status_row: String = (0..80).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(status_row.contains("Offline"), "Should show Offline status");

    // 2. TCP
    model.domain.self_connection_status = ToxConnection::TOX_CONNECTION_TCP;
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row: String = (0..80).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(status_row.contains("TCP"), "Should show TCP status");

    // 3. UDP
    model.domain.self_connection_status = ToxConnection::TOX_CONNECTION_UDP;
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row: String = (0..80).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(status_row.contains("UDP"), "Should show UDP status");
}

#[test]
fn test_status_bar_unread_notifications() {
    let mut model = create_test_model();

    // Create two friends
    let f1 = FriendNumber(1);
    let f2 = FriendNumber(2);
    let pk1 = PublicKey([1u8; 32]);
    let pk2 = PublicKey([2u8; 32]);

    model.session.friend_numbers.insert(f1, pk1);
    model.session.friend_numbers.insert(f2, pk2);

    // Populate domain friends for names
    model.domain.friends.insert(
        pk1,
        toxxi::model::FriendInfo {
            name: "Friend 1".to_string(),
            public_key: Some(pk1),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.domain.friends.insert(
        pk2,
        toxxi::model::FriendInfo {
            name: "Friend 2".to_string(),
            public_key: Some(pk2),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    model.ensure_friend_window(pk1);
    model.ensure_friend_window(pk2);

    // Set active window to F1 (index 1, since Console is 0)
    model.set_active_window(1);

    // Add message to F2 (inactive)
    model.add_friend_message(
        pk2,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "Hello".to_string(),
    );

    let backend = TestBackend::new(100, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();

    let buffer = terminal.backend().buffer();
    let status_row: String = (0..100).map(|x| buffer[(x, 6)].symbol()).collect();

    // We expect Friend 2 entry to show unread count
    assert!(
        status_row.contains("Friend 2"),
        "Friend 2 should be in status bar"
    );
    assert!(
        status_row.contains("(1)"),
        "Should show unread count (1) in status bar: {}",
        status_row
    );

    // Verify internal state
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

    // No pending
    let backend = TestBackend::new(80, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, &mut model)).unwrap();
    let buffer = terminal.backend().buffer();
    let status_row_empty: String = (0..80).map(|x| buffer[(x, 6)].symbol()).collect();
    assert!(
        !status_row_empty.contains("PENDING"),
        "Should not show PENDING when empty"
    );

    // Add pending request
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
