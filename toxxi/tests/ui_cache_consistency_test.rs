use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, FriendNumber, ToxUserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{ConsoleMessageType, DomainState, FriendInfo, MessageContent, Model, WindowId};
use toxxi::ui;
use toxxi::update;

fn setup_model() -> (Model, FriendNumber, PublicKey) {
    let mut domain = DomainState::new(
        Address([0; 38]),
        PublicKey([0; 32]),
        "Self".into(),
        "Status".into(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );

    let fid = FriendNumber(0);
    let pk = PublicKey([0; 32]);
    domain.friends.insert(
        pk,
        FriendInfo {
            name: "Friend 0".into(),
            public_key: Some(pk),
            status_message: "Status".into(),
            connection: toxcore::tox::ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    let mut model = Model::new(domain, Config::default(), Config::default());
    model.session.friend_numbers.insert(fid, pk);

    model.ensure_friend_window(pk);
    let wid = WindowId::Friend(pk);

    // Switch to the window so draw_messages is called for it
    model.set_active_window(model.ui.window_ids.iter().position(|&w| w == wid).unwrap());

    (model, fid, pk)
}

#[test]
fn test_cache_consistency_after_mid_removal() {
    let (mut model, _fid, pk) = setup_model();
    let backend = TestBackend::new(100, 50);
    let mut terminal = Terminal::new(backend).unwrap();

    // 1. Add messages: User1, System, User2
    model.add_friend_message(pk, MessageType::TOX_MESSAGE_TYPE_NORMAL, "User 1".into());
    model.add_system_message_to(
        WindowId::Friend(pk),
        ConsoleMessageType::Info,
        MessageContent::Text("System Msg".into()),
    );
    model.add_friend_message(pk, MessageType::TOX_MESSAGE_TYPE_NORMAL, "User 2".into());

    // 2. Initial Draw (Populate Cache)
    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let wid = WindowId::Friend(pk);
    let state = model.ui.window_state.get(&wid).unwrap();
    let cached = state.cached_messages.as_ref().unwrap();
    assert_eq!(cached.len(), 3);
    assert_eq!(cached[0].sender, "Friend 0");
    assert_eq!(cached[1].sender, "System");
    assert_eq!(cached[2].sender, "Friend 0");

    // 3. Invoke /pop (Removes last System message from the middle)
    update::handle_command(&mut model, "/pop");

    // 4. Verify Domain State
    let conv = model.domain.conversations.get(&wid).unwrap();
    assert_eq!(conv.messages.len(), 2);
    assert_eq!(conv.messages[0].content.as_text().unwrap(), "User 1");
    assert_eq!(conv.messages[1].content.as_text().unwrap(), "User 2");

    // 5. Draw Again (Should update cache)
    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    // 6. Verify Cache State
    let state = model.ui.window_state.get(&wid).unwrap();
    let cached = state.cached_messages.as_ref().unwrap();

    // With the bug, truncation removes last element ("User 2"), keeping ["User 1", "System"]
    assert_eq!(cached.len(), 2);

    // Expectation: [User 1, User 2]
    // Bug Reality: [User 1, System Msg]
    assert_eq!(cached[0].sender, "Friend 0");
    assert_eq!(
        cached[1].sender, "Friend 0",
        "Cache desynchronized! Expected 'Friend 0' (User 2) but found '{}'",
        cached[1].sender
    );

    match &cached[1].content {
        toxxi::widgets::MessageContent::Text(t) => assert_eq!(t, "User 2"),
        _ => panic!("Unexpected content type"),
    }
}
