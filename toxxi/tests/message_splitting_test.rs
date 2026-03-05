use toxcore::tox::{Address, FriendNumber, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, Model, WindowId};
use toxxi::update::handle_enter;

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

fn add_test_friend(model: &mut Model, fid: FriendNumber, pk: PublicKey) {
    model.session.friend_numbers.insert(fid, pk);
    model.domain.friends.insert(
        pk,
        FriendInfo {
            name: format!("Friend {}", fid.0),
            public_key: Some(pk),
            status_message: "".to_string(),
            connection: toxcore::tox::ToxConnection::TOX_CONNECTION_TCP,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
}

#[test]
fn test_message_splitting() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);
    model.set_active_window(1);

    // Create a message that is definitely longer than the limit.
    // Use 2000 chars to exceed the typical Tox limit (~1372).
    let long_msg = "a".repeat(2000);

    let cmds = handle_enter(&mut model, &long_msg);

    // We expect multiple commands.
    assert!(
        cmds.len() > 1,
        "Should generate multiple commands for long message, got {}",
        cmds.len()
    );

    // Also verify internal model state has multiple messages
    let conv = model
        .domain
        .conversations
        .get(&WindowId::Friend(pk))
        .unwrap();
    assert!(
        conv.messages.len() > 1,
        "Should add multiple messages to conversation, got {}",
        conv.messages.len()
    );
}

#[test]
fn test_group_message_splitting() {
    use toxcore::tox::GroupNumber;
    use toxcore::types::GroupChatId;

    let mut model = create_test_model();
    let gid = GroupNumber(1);
    let chat_id = GroupChatId([1u8; 32]);

    model.session.group_numbers.insert(gid, chat_id);
    model.ensure_group_window(chat_id);

    model.set_active_window(1);

    // Create a message that is definitely longer than the group limit.
    // Assuming limit is somewhere around 1000-2000. 3000 chars is safe.
    let long_msg = "b".repeat(3000);

    let cmds = handle_enter(&mut model, &long_msg);

    // We expect multiple commands.
    assert!(
        cmds.len() > 1,
        "Should generate multiple commands for long group message, got {}",
        cmds.len()
    );

    let conv = model
        .domain
        .conversations
        .get(&WindowId::Group(chat_id))
        .unwrap();
    assert!(
        conv.messages.len() > 1,
        "Should add multiple messages to group conversation, got {}",
        conv.messages.len()
    );
}
