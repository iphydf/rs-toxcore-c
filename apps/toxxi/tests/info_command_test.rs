use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use toxcore::tox::Connection;
use toxcore::types::PublicKey;
use toxxi::model::{FriendInfo, Model, PendingItem};
use toxxi::msg::Msg;
use toxxi::update::update;
use toxxi_testing::create_test_model;

fn send_command(model: &mut Model, command: &str) {
    for c in command.chars() {
        update(
            model,
            Msg::Input(CrosstermEvent::Key(KeyEvent::new(
                KeyCode::Char(c),
                KeyModifiers::empty(),
            ))),
        );
    }
    update(
        model,
        Msg::Input(CrosstermEvent::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::empty(),
        ))),
    );
}

#[test]
fn test_friends_command_output() {
    let mut model = create_test_model();

    let pk1 = PublicKey([1u8; 32]);
    let pk2 = PublicKey([2u8; 32]);

    model.domain.friends.insert(
        pk1,
        FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk1),
            status_message: "Hi".to_string(),
            connection: Connection::Tcp,
            is_typing: false,
        },
    );
    model.domain.friends.insert(
        pk2,
        FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(pk2),
            status_message: "Busy".to_string(),
            connection: Connection::None,
            is_typing: false,
        },
    );

    send_command(&mut model, "/friends");

    let last_msg = model.domain.console_messages.last().unwrap();
    if let toxxi::model::MessageContent::List(lines) = &last_msg.content {
        assert!(lines[0].contains("Friend List"));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("[01010101] Alice") && l.contains("TCP") && l.contains("Hi"))
        );
        assert!(
            lines.iter().any(|l| l.contains("[02020202] Bob")
                && l.contains("Offline")
                && l.contains("Busy"))
        );
    } else {
        panic!("Expected List content");
    }
}

#[test]
fn test_pending_command_output() {
    let mut model = create_test_model();

    let pk = PublicKey([0xAA; 32]);
    model.domain.pending_items.push(PendingItem::FriendRequest {
        pk,
        message: "Let's be friends".to_string(),
    });

    send_command(&mut model, "/pending");

    let last_msg = model.domain.console_messages.last().unwrap();
    if let toxxi::model::MessageContent::List(lines) = &last_msg.content {
        assert!(lines[0].contains("Pending Items"));
        assert!(lines.iter().any(|l| l.contains("[0] Friend Request")
            && l.contains("aaaaaaaa")
            && l.contains("Let's be friends")));
    } else {
        panic!("Expected List content");
    }
}

#[test]
fn test_pending_empty_output() {
    let mut model = create_test_model();

    send_command(&mut model, "/pending");

    let last_msg = model.domain.console_messages.last().unwrap();
    if let toxxi::model::MessageContent::List(lines) = &last_msg.content {
        assert!(lines.iter().any(|l| l.contains("No pending items")));
    } else {
        panic!("Expected List content");
    }
}
