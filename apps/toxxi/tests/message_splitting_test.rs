use toxcore::types::PublicKey;
use toxxi::model::WindowId;
use toxxi::update::handle_enter;
use toxxi_testing::{add_test_friend, create_test_model};

#[test]
fn test_message_splitting() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);
    model.set_active_window(1);

    // Longer than Tox's limit (1372 bytes).
    let long_msg = "a".repeat(2000);

    let cmds = handle_enter(&mut model, &long_msg);

    assert!(
        cmds.len() > 1,
        "Should generate multiple commands for long message, got {}",
        cmds.len()
    );

    // Each part is its own message here too.
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

    // Longer than the group limit.
    let long_msg = "b".repeat(3000);

    let cmds = handle_enter(&mut model, &long_msg);

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
