use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, UserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, MessageStatus, Model, WindowId};
use toxxi::ui;
use toxxi::widgets::MessageStatus as WidgetStatus;

fn setup_model() -> (Model, PublicKey) {
    let mut domain = DomainState::new(
        Address([0; 38]),
        "Self".into(),
        "Status".into(),
        UserStatus::None,
    );

    let pk = PublicKey([1u8; 32]);
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
fn test_incremental_append() {
    let (mut model, pk) = setup_model();
    let backend = TestBackend::new(100, 50);
    let mut terminal = Terminal::new(backend).unwrap();

    for i in 0..10 {
        model.add_friend_message(pk, MessageType::Normal, format!("Message {}", i));
    }

    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let wid = WindowId::Friend(pk);
    let state = model.ui.window_state.get(&wid).unwrap();

    assert_eq!(state.cached_messages.as_ref().unwrap().len(), 10);
    assert_eq!(state.layout.processed_count, 10);

    model.add_friend_message(pk, MessageType::Normal, "Message 10".into());

    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let state = model.ui.window_state.get(&wid).unwrap();
    assert_eq!(state.cached_messages.as_ref().unwrap().len(), 11);
    assert_eq!(state.layout.processed_count, 11);
}

#[test]
fn test_dirty_update_preserves_cache() {
    let (mut model, pk) = setup_model();
    let backend = TestBackend::new(100, 50);
    let mut terminal = Terminal::new(backend).unwrap();

    let (id, _) = model.add_outgoing_friend_message(pk, MessageType::Normal, "Hello".into());
    // Pending by default.
    model.mark_message_status(WindowId::Friend(pk), id, MessageStatus::Sending);

    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let wid = WindowId::Friend(pk);
    let state = model.ui.window_state.get(&wid).unwrap();
    let cached = state.cached_messages.as_ref().unwrap();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].status, WidgetStatus::Sending);

    // Delivered: this updates dirty_indices.
    model.mark_message_status(
        WindowId::Friend(pk),
        id,
        MessageStatus::Sent(Some(toxcore::tox::FriendMessageId(1))),
    );

    let state = model.ui.window_state.get(&wid).unwrap();
    assert!(state.dirty_indices.contains(&0));

    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let state = model.ui.window_state.get(&wid).unwrap();
    let cached = state.cached_messages.as_ref().unwrap();

    assert_eq!(cached[0].status, WidgetStatus::Delivered);
    assert!(state.dirty_indices.is_empty());
}

#[test]
fn test_layout_invalidation_on_resize() {
    let (mut model, pk) = setup_model();
    let backend = TestBackend::new(100, 50);
    let mut terminal = Terminal::new(backend).unwrap();

    model.add_friend_message(
        pk,
        MessageType::Normal,
        "A very long message that might wrap differently depending on width".into(),
    );

    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let wid = WindowId::Friend(pk);
    let state_before = model.ui.window_state.get(&wid).unwrap().clone();
    assert_eq!(state_before.layout.last_width, 75); // 100 - 25 sidebar

    let backend_small = TestBackend::new(50, 50);
    let mut terminal_small = Terminal::new(backend_small).unwrap();

    terminal_small.draw(|f| ui::draw(f, &mut model)).unwrap();

    let state_after = model.ui.window_state.get(&wid).unwrap();
    assert_ne!(
        state_before.layout.last_width,
        state_after.layout.last_width
    );
    assert_eq!(state_after.layout.processed_count, 1);
}
