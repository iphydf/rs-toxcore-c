use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, UserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{ConsoleMessageType, DomainState, FriendInfo, MessageContent, Model, WindowId};
use toxxi::ui;
use toxxi::update;

fn setup_model() -> (Model, PublicKey) {
    let mut domain = DomainState::new(
        Address([0; 38]),
        "Self".into(),
        "Status".into(),
        UserStatus::None,
    );

    let pk = PublicKey([0; 32]);
    domain.friends.insert(
        pk,
        FriendInfo {
            name: "Friend 0".into(),
            public_key: Some(pk),
            status_message: "Status".into(),
            connection: toxcore::tox::Connection::None,
            is_typing: false,
        },
    );

    let mut model = Model::new(domain, Config::default(), Config::default());

    model.ensure_friend_window(pk);
    let wid = WindowId::Friend(pk);

    // Show the window, so draw_messages runs for it.
    model.set_active_window(model.ui.window_ids.iter().position(|&w| w == wid).unwrap());

    (model, pk)
}

#[test]
fn test_cache_consistency_after_mid_removal() {
    let (mut model, pk) = setup_model();
    let backend = TestBackend::new(100, 50);
    let mut terminal = Terminal::new(backend).unwrap();

    // User 1, a system message, User 2.
    model.add_friend_message(pk, MessageType::Normal, "User 1".into());
    model.add_system_message_to(
        WindowId::Friend(pk),
        ConsoleMessageType::Info,
        MessageContent::Text("System Msg".into()),
    );
    model.add_friend_message(pk, MessageType::Normal, "User 2".into());

    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let wid = WindowId::Friend(pk);
    let state = model.ui.window_state.get(&wid).unwrap();
    let cached = state.cached_messages.as_ref().unwrap();
    assert_eq!(cached.len(), 3);
    assert_eq!(cached[0].sender, "Friend 0");
    assert_eq!(cached[1].sender, "System");
    assert_eq!(cached[2].sender, "Friend 0");

    // /pop removes the system message, from the middle.
    update::handle_command(&mut model, "/pop");

    let conv = model.domain.conversations.get(&wid).unwrap();
    assert_eq!(conv.messages.len(), 2);
    assert_eq!(conv.messages[0].content.as_text().unwrap(), "User 1");
    assert_eq!(conv.messages[1].content.as_text().unwrap(), "User 2");

    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let state = model.ui.window_state.get(&wid).unwrap();
    let cached = state.cached_messages.as_ref().unwrap();

    // Truncating would remove User 2 instead, keeping User 1 and the system message.
    assert_eq!(cached.len(), 2);

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
