use ratatui::{Terminal, backend::TestBackend};
use toxcore::tox::{Address, FriendNumber, ToxUserStatus};
use toxcore::types::{MessageType, PublicKey};
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, MessageStatus, Model, WindowId};
use toxxi::ui;
use toxxi::widgets::MessageStatus as WidgetStatus;

fn setup_model() -> (Model, FriendNumber, PublicKey) {
    let mut domain = DomainState::new(
        Address([0; 38]),
        "Self".into(),
        "Status".into(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );

    let fid = FriendNumber(0);
    let pk = PublicKey([1u8; 32]);
    domain.friends.insert(
        pk,
        FriendInfo {
            name: "Friend 0".into(),
            public_key: Some(pk),
            status_message: "Status".into(),
            connection: toxcore::tox::ToxConnection::TOX_CONNECTION_NONE,
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
fn test_incremental_append() {
    let (mut model, _fid, pk) = setup_model();
    let backend = TestBackend::new(100, 50);
    let mut terminal = Terminal::new(backend).unwrap();

    // 1. Add 10 messages
    for i in 0..10 {
        model.add_friend_message(
            pk,
            MessageType::TOX_MESSAGE_TYPE_NORMAL,
            format!("Message {}", i),
        );
    }

    // 2. Initial Draw
    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let wid = WindowId::Friend(pk);
    let state = model.ui.window_state.get(&wid).unwrap();

    // Verify cache is populated
    assert_eq!(state.cached_messages.as_ref().unwrap().len(), 10);
    // Verify layout processed count
    assert_eq!(state.layout.processed_count, 10);

    // 3. Add one more message (append)
    model.add_friend_message(
        pk,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "Message 10".into(),
    );

    // 4. Draw again
    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let state = model.ui.window_state.get(&wid).unwrap();
    assert_eq!(state.cached_messages.as_ref().unwrap().len(), 11);
    assert_eq!(state.layout.processed_count, 11);
}

#[test]
fn test_dirty_update_preserves_cache() {
    let (mut model, _fid, pk) = setup_model();
    let backend = TestBackend::new(100, 50);
    let mut terminal = Terminal::new(backend).unwrap();

    // 1. Add a message that is "Sending"
    let (id, _) =
        model.add_outgoing_friend_message(pk, MessageType::TOX_MESSAGE_TYPE_NORMAL, "Hello".into());
    // Explicitly mark as sending (default is pending).
    model.mark_message_status(WindowId::Friend(pk), id, MessageStatus::Sending);

    // 2. Draw
    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let wid = WindowId::Friend(pk);
    let state = model.ui.window_state.get(&wid).unwrap();
    let cached = state.cached_messages.as_ref().unwrap();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].status, WidgetStatus::Sending);

    // 3. Mark as Delivered (updates dirty_indices)
    model.mark_message_status(WindowId::Friend(pk), id, MessageStatus::Sent(1));

    let state = model.ui.window_state.get(&wid).unwrap();
    assert!(state.dirty_indices.contains(&0));

    // 4. Draw again
    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let state = model.ui.window_state.get(&wid).unwrap();
    let cached = state.cached_messages.as_ref().unwrap();

    // Verify status updated
    assert_eq!(cached[0].status, WidgetStatus::Delivered);
    // Verify dirty indices cleared
    assert!(state.dirty_indices.is_empty());
}

#[test]
fn test_layout_invalidation_on_resize() {
    let (mut model, _fid, pk) = setup_model();
    // Start with width 100
    let backend = TestBackend::new(100, 50);
    let mut terminal = Terminal::new(backend).unwrap();

    model.add_friend_message(
        pk,
        MessageType::TOX_MESSAGE_TYPE_NORMAL,
        "A very long message that might wrap differently depending on width".into(),
    );

    terminal.draw(|f| ui::draw(f, &mut model)).unwrap();

    let wid = WindowId::Friend(pk);
    let state_before = model.ui.window_state.get(&wid).unwrap().clone();
    assert_eq!(state_before.layout.last_width, 75); // 100 - 25 sidebar

    // Resize terminal to 50 width
    let backend_small = TestBackend::new(50, 50);
    let mut terminal_small = Terminal::new(backend_small).unwrap();

    terminal_small.draw(|f| ui::draw(f, &mut model)).unwrap();

    let state_after = model.ui.window_state.get(&wid).unwrap();
    assert_ne!(
        state_before.layout.last_width,
        state_after.layout.last_width
    );
    // Check that processed_count is still correct (1)
    assert_eq!(state_after.layout.processed_count, 1);
}
