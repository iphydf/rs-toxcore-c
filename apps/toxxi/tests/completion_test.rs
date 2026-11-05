use toxcore::tox::{ConferenceNumber, Connection, GroupNumber, UserStatus};
use toxcore::types::PublicKey;
use toxxi::completion::{self, complete_command_arguments, complete_text};
use toxxi::model::{FriendInfo, Model, PeerId, PeerInfo, WindowId};
use toxxi_testing as testing;

fn create_test_model() -> Model {
    let mut model = testing::create_test_model();

    let pk_alice = PublicKey([10u8; 32]);
    let pk_bob = PublicKey([11u8; 32]);

    model.domain.friends.insert(
        pk_alice,
        FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk_alice),
            status_message: "".to_string(),
            connection: Connection::None,
            is_typing: false,
        },
    );

    model.domain.friends.insert(
        pk_bob,
        FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(pk_bob),
            status_message: "".to_string(),
            connection: Connection::None,
            is_typing: false,
        },
    );

    model
}

#[test]
fn test_command_completion() {
    let model = create_test_model();

    let candidates = complete_command_arguments("/q", &model);
    assert!(
        candidates.is_empty(),
        "Command name completion should be empty (handled by UI)"
    );

    let candidates = complete_command_arguments("/f", &model);
    assert!(
        candidates.is_empty(),
        "Command name completion should be empty (handled by UI)"
    );
}

#[test]
fn test_set_completion() {
    let model = create_test_model();

    // Complete key immediately after space (arguments)
    let candidates = complete_command_arguments("/set ", &model);
    assert!(candidates.iter().any(|(s, _)| s == "ipv6_enabled"));

    // Complete key with prefix
    let candidates = complete_command_arguments("/set i", &model);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "ipv6_enabled");

    // Complete value
    let candidates = complete_command_arguments("/set ipv6_enabled t", &model);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "true");
}

#[test]
fn test_set_completion_only_offers_settable_keys() {
    let model = create_test_model();
    let keys: Vec<String> = complete_command_arguments("/set ", &model)
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    // blocked_strings is managed by /block, and /set rejects it.
    assert!(!keys.contains(&"blocked_strings".to_owned()));
    assert!(keys.contains(&"ipv6_enabled".to_owned()));
}

#[test]
fn test_friend_command_completion() {
    let model = create_test_model();

    let candidates = complete_command_arguments("/friend ", &model);
    assert!(candidates.iter().any(|(s, _)| s == "add"));
    assert!(candidates.iter().any(|(s, _)| s == "remove"));

    // Friends by name, which becomes their key
    let candidates = complete_command_arguments("/friend remove ", &model);
    assert!(candidates.contains(&("0a0a0a0a".to_owned(), "Alice".to_owned())));
    assert!(candidates.contains(&("0b0b0b0b".to_owned(), "Bob".to_owned())));

    let candidates = complete_command_arguments("/friend remove al", &model);
    assert_eq!(
        candidates,
        vec![("0a0a0a0a".to_owned(), "Alice".to_owned())]
    );

    // Or by the start of their key
    let candidates = complete_command_arguments("/friend remove 0b", &model);
    assert_eq!(candidates, vec![("0b0b0b0b".to_owned(), "Bob".to_owned())]);
}

#[test]
fn test_friend_completion() {
    let model = create_test_model();

    let candidates = complete_text("A", &model);
    assert_eq!(candidates, vec!["Alice"]);

    let candidates = complete_text("Hello B", &model);
    assert_eq!(candidates, vec!["Bob"]);
}

#[test]
fn test_file_command_completion() {
    let model = create_test_model();

    let candidates = complete_command_arguments("/file ", &model);
    assert!(candidates.iter().any(|(s, _)| s == "send"));
    assert!(candidates.iter().any(|(s, _)| s == "accept"));
    assert!(candidates.iter().any(|(s, _)| s == "cancel"));

    let candidates = complete_command_arguments("/file s", &model);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "send");

    // Complete the friend to send to
    let candidates = complete_command_arguments("/file send ", &model);
    assert!(candidates.iter().any(|(_, name)| name == "Alice"));
    assert!(candidates.iter().any(|(_, name)| name == "Bob"));

    let candidates = complete_command_arguments("/file send bo", &model);
    assert_eq!(candidates, vec![("0b0b0b0b".to_owned(), "Bob".to_owned())]);
}

#[test]
fn test_group_peer_completion() {
    let mut model = create_test_model();
    let group_id = GroupNumber(0);
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.session.group_numbers.insert(group_id, chat_id);
    model.ensure_group_window(chat_id);

    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Group(chat_id))
    {
        conv.peers.push(PeerInfo {
            id: PeerId(PublicKey([1u8; 32])),
            name: "Dave".to_string(),
            role: None,
            status: UserStatus::None,
            is_ignored: false,
            seen_online: true,
        });
    }

    let group_window_index = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == WindowId::Group(chat_id))
        .unwrap();
    model.set_active_window(group_window_index);

    // Dave is in the group but not a friend.
    let candidates = complete_text("D", &model);
    assert!(candidates.contains(&"Dave".to_string()));

    // Our own name.
    let candidates = complete_text("T", &model);
    assert!(candidates.contains(&"Tester".to_string()));
}

#[test]
fn test_conference_peer_completion() {
    let mut model = create_test_model();
    let conference_id = ConferenceNumber(0);
    let conf_stable_id = toxcore::types::ConferenceId([1u8; 32]);
    model
        .session
        .conference_numbers
        .insert(conference_id, conf_stable_id);
    model.ensure_conference_window(conf_stable_id);

    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Conference(conf_stable_id))
    {
        conv.peers.push(PeerInfo {
            id: PeerId(PublicKey([2u8; 32])),
            name: "Eve".to_string(),
            role: None,
            status: UserStatus::None,
            is_ignored: false,
            seen_online: true,
        });
    }

    let conf_window_index = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == WindowId::Conference(conf_stable_id))
        .unwrap();
    model.set_active_window(conf_window_index);

    let candidates = complete_text("E", &model);
    assert!(candidates.contains(&"Eve".to_string()));
}

#[test]
fn test_replacement_logic() {
    // Command replacement
    let rep = completion::get_replacement("/q", "/quit");
    assert_eq!(rep, "/quit ");

    let rep = completion::get_replacement("/file s", "send");
    assert_eq!(rep, "/file send");

    // Set key replacement
    let rep = completion::get_replacement("/set i", "ipv6_enabled");
    assert_eq!(rep, "/set ipv6_enabled");

    // Set value replacement
    let rep = completion::get_replacement("/set ipv6_enabled t", "true");
    assert_eq!(rep, "/set ipv6_enabled true");

    // Word replacement
    let rep = completion::get_replacement("Hello A", "Alice");
    assert_eq!(rep, "Hello Alice");

    // First word mention replacement
    let rep = completion::get_replacement("A", "Alice");
    assert_eq!(rep, "Alice: ");

    // First word emoji replacement (no colon)
    let rep = completion::get_replacement(":", "😊");
    assert_eq!(rep, "😊");
}

#[test]
fn test_path_completion() {
    use std::fs::File;
    use tempfile::tempdir;
    let model = create_test_model();

    let tmp_dir = tempdir().unwrap();
    let dir_path = tmp_dir.path();

    File::create(dir_path.join("test_file.txt")).unwrap();
    std::fs::create_dir(dir_path.join("test_dir")).unwrap();
    File::create(dir_path.join("test_dir").join("inner.txt")).unwrap();

    let base = dir_path.to_str().unwrap();

    let prefix = format!("/file send 1 {}/test_", base);
    let candidates = complete_command_arguments(&prefix, &model);
    assert!(
        candidates
            .iter()
            .any(|(s, _)| s == &format!("{}/test_file.txt", base))
    );
    assert!(
        candidates
            .iter()
            .any(|(s, _)| s == &format!("{}/test_dir/", base))
    );

    let prefix = format!("/file send 1 {}/test_dir/i", base);
    let candidates = complete_command_arguments(&prefix, &model);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, format!("{}/test_dir/inner.txt", base));
}

/// Completing a name in a chat is for someone in it: friends who aren't
/// there aren't offered.
#[test]
fn completion_offers_only_whos_in_the_chat() {
    let mut model = create_test_model();
    let chat_id = toxcore::types::GroupChatId([1u8; 32]);
    model.ensure_group_window(chat_id);
    let group = WindowId::Group(chat_id);
    model
        .domain
        .conversations
        .get_mut(&group)
        .unwrap()
        .peers
        .push(PeerInfo {
            id: PeerId(PublicKey([1u8; 32])),
            name: "Alan".to_string(),
            role: None,
            status: UserStatus::None,
            is_ignored: false,
            seen_online: true,
        });
    let show = |model: &mut Model, window: WindowId| {
        let index = model.ui.window_ids.iter().position(|&w| w == window);
        model.set_active_window(index.unwrap());
    };

    show(&mut model, group);
    assert_eq!(complete_text("A", &model), vec!["Alan"]);

    let alice = PublicKey([10u8; 32]);
    model.ensure_friend_window(alice);
    show(&mut model, WindowId::Friend(alice));
    assert_eq!(complete_text("A", &model), vec!["Alice"]);
    assert!(complete_text("B", &model).is_empty());
}
