use toxcore::tox::{
    Address, ConferenceNumber, FriendNumber, GroupNumber, ToxConnection, ToxUserStatus,
};
use toxcore::types::PublicKey;
use toxxi::completion::{self, complete_command_arguments, complete_text};
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, Model, PeerId, PeerInfo, WindowId};

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "I am a test".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    let mut model = Model::new(domain, config.clone(), config);

    let pk_alice = PublicKey([10u8; 32]);
    let pk_bob = PublicKey([11u8; 32]);

    model.domain.friends.insert(
        pk_alice,
        FriendInfo {
            name: "Alice".to_string(),
            public_key: Some(pk_alice),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model
        .session
        .friend_numbers
        .insert(FriendNumber(1), pk_alice);

    model.domain.friends.insert(
        pk_bob,
        FriendInfo {
            name: "Bob".to_string(),
            public_key: Some(pk_bob),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.session.friend_numbers.insert(FriendNumber(2), pk_bob);

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
fn test_friend_command_completion() {
    let mut model = create_test_model();

    // Complete subcommands
    let candidates = complete_command_arguments("/friend ", &model);
    assert!(candidates.iter().any(|(s, _)| s == "add"));
    assert!(candidates.iter().any(|(s, _)| s == "remove"));

    // Complete remove ID
    let candidates = complete_command_arguments("/friend remove ", &model);
    assert!(candidates.iter().any(|(s, _)| s == "1"));
    assert!(candidates.iter().any(|(s, _)| s == "2"));

    let candidates = complete_command_arguments("/friend remove 1", &model);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "1");

    // Test for a friend with a higher ID
    let pk_charlie = PublicKey([12u8; 32]);
    model.domain.friends.insert(
        pk_charlie,
        FriendInfo {
            name: "Charlie".to_string(),
            public_key: Some(pk_charlie),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model
        .session
        .friend_numbers
        .insert(FriendNumber(100), pk_charlie);

    let candidates = complete_command_arguments("/friend remove 10", &model);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "100");
}

#[test]
fn test_friend_completion() {
    let model = create_test_model();

    // Basic completion
    let candidates = complete_text("A", &model);
    assert_eq!(candidates, vec!["Alice"]);

    // Completion after prefix
    let candidates = complete_text("Hello B", &model);
    assert_eq!(candidates, vec!["Bob"]);
}

#[test]
fn test_file_command_completion() {
    let model = create_test_model();

    // Complete sub-commands
    let candidates = complete_command_arguments("/file ", &model);
    assert!(candidates.iter().any(|(s, _)| s == "send"));
    assert!(candidates.iter().any(|(s, _)| s == "accept"));
    assert!(candidates.iter().any(|(s, _)| s == "cancel"));

    // Complete sub-command with prefix
    let candidates = complete_command_arguments("/file s", &model);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "send");

    // Complete friend ID for send
    let candidates = complete_command_arguments("/file send ", &model);
    assert!(candidates.iter().any(|(s, _)| s == "1")); // Alice
    assert!(candidates.iter().any(|(s, _)| s == "2")); // Bob

    // Complete friend ID with prefix
    let candidates = complete_command_arguments("/file send 1", &model);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "1");
}

#[test]
fn test_group_peer_completion() {
    let mut model = create_test_model();
    let group_id = GroupNumber(0);
    let chat_id = toxcore::types::ChatId([1u8; 32]);
    model.session.group_numbers.insert(group_id, chat_id);
    model.ensure_group_window(chat_id);

    // Add a peer to the group
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Group(chat_id))
    {
        conv.peers.push(PeerInfo {
            id: PeerId(PublicKey([1u8; 32])),
            name: "Dave".to_string(),
            role: None,
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    }

    // Set active window to the group
    let group_window_index = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == WindowId::Group(chat_id))
        .unwrap();
    model.set_active_window(group_window_index);

    // Should complete "Dave" who is in the group but not a friend
    let candidates = complete_text("D", &model);
    assert!(candidates.contains(&"Dave".to_string()));

    // Should complete "Tester" (self name)
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

    // Add a peer to the conference
    if let Some(conv) = model
        .domain
        .conversations
        .get_mut(&WindowId::Conference(conf_stable_id))
    {
        conv.peers.push(PeerInfo {
            id: PeerId(PublicKey([2u8; 32])),
            name: "Eve".to_string(),
            role: None,
            status: ToxUserStatus::TOX_USER_STATUS_NONE,
            is_ignored: false,
            seen_online: true,
        });
    }

    // Set active window to the conference
    let conf_window_index = model
        .ui
        .window_ids
        .iter()
        .position(|&id| id == WindowId::Conference(conf_stable_id))
        .unwrap();
    model.set_active_window(conf_window_index);

    // Should complete "Eve"
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

    // Create some files and directories
    File::create(dir_path.join("test_file.txt")).unwrap();
    std::fs::create_dir(dir_path.join("test_dir")).unwrap();
    File::create(dir_path.join("test_dir").join("inner.txt")).unwrap();

    let base = dir_path.to_str().unwrap();

    // Complete filename in temp dir
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

    // Complete inner file
    let prefix = format!("/file send 1 {}/test_dir/i", base);
    let candidates = complete_command_arguments(&prefix, &model);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, format!("{}/test_dir/inner.txt", base));
}

// end of tests
