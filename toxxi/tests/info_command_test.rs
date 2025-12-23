use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use toxcore::tox::{Address, FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, Model, PendingItem};
use toxxi::msg::Msg;
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

    // Add friends
    let pk1 = PublicKey([1u8; 32]);
    let pk2 = PublicKey([2u8; 32]);
    model.session.friend_numbers.insert(FriendNumber(1), pk1);
    model.session.friend_numbers.insert(FriendNumber(2), pk2);

    model.domain.friends.insert(
        pk1,
        FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk1),
            status_message: "Hi".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.domain.friends.insert(
        pk2,
        FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(pk2),
            status_message: "Busy".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    send_command(&mut model, "/friends");

    let last_msg = model.domain.console_messages.last().unwrap();
    if let toxxi::model::MessageContent::List(lines) = &last_msg.content {
        assert!(lines[0].contains("Friend List"));
        // Friend 1
        assert!(
            lines
                .iter()
                .any(|l| l.contains("[1] Alice") && l.contains("TCP") && l.contains("Hi"))
        );
        // Friend 2
        assert!(
            lines
                .iter()
                .any(|l| l.contains("[2] Bob") && l.contains("Offline") && l.contains("Busy"))
        );
    } else {
        panic!("Expected List content");
    }
}

#[test]
fn test_pending_command_output() {
    let mut model = create_test_model();

    // Add pending item
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
