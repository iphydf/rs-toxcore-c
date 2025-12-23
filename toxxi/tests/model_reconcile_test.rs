use std::collections::HashMap;
use toxcore::tox::{FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, Model, WindowId};

#[test]
fn test_reconcile_removes_duplicates_and_migrates_conversations() {
    let pk1 = PublicKey([1; 32]);
    let pk2 = PublicKey([2; 32]);
    let pk3 = PublicKey([3; 32]);

    // Initial state: 3 friends loaded from stale state.json
    let mut friends = HashMap::new();
    friends.insert(
        pk1,
        FriendInfo {
            name: "Friend 1".into(),
            public_key: Some(pk1),
            status_message: "".into(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    friends.insert(
        pk2,
        FriendInfo {
            name: "Friend 2 (To Be Deleted)".into(),
            public_key: Some(pk2),
            status_message: "".into(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    friends.insert(
        pk3,
        FriendInfo {
            name: "Friend 3 (To Be Shifted)".into(),
            public_key: Some(pk3),
            status_message: "".into(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    let dummy_address = toxcore::tox::Address([0u8; 38]);

    let domain = DomainState {
        friends,
        ..DomainState::new(
            dummy_address,
            PublicKey([0; 32]),
            "Me".into(),
            "".into(),
            ToxUserStatus::TOX_USER_STATUS_NONE,
        )
    };

    let mut model = Model::new(domain, Config::default(), Config::default());

    // Create conversations/windows
    model.ensure_friend_window(pk1);
    model.ensure_friend_window(pk2);
    model.ensure_friend_window(pk3);

    // Simulate reload: Friend 2 (pk2) deleted. Friend 3 (pk3) shifts to FID 1.
    // New list from c-toxcore:
    let new_friends = vec![
        (
            FriendNumber(0),
            FriendInfo {
                name: "Friend 1".into(),
                public_key: Some(pk1),
                status_message: "Online".into(),
                connection: ToxConnection::TOX_CONNECTION_TCP,
                last_sent_message_id: None,
                last_read_receipt: None,
                is_typing: false,
            },
        ),
        (
            FriendNumber(1),
            FriendInfo {
                name: "Friend 3".into(),
                public_key: Some(pk3), // Was FID 2
                status_message: "Online".into(),
                connection: ToxConnection::TOX_CONNECTION_TCP,
                last_sent_message_id: None,
                last_read_receipt: None,
                is_typing: false,
            },
        ),
    ];

    model.reconcile(new_friends, vec![], vec![]);

    // Verify Friends
    assert_eq!(
        model.domain.friends.len(),
        2,
        "Should have exactly 2 friends"
    );
    assert!(model.domain.friends.contains_key(&pk1), "Should have PK 1");
    assert!(model.domain.friends.contains_key(&pk3), "Should have PK 3");
    assert!(
        !model.domain.friends.contains_key(&pk2),
        "Should NOT have PK 2"
    );

    // Verify Friend 1 data
    assert_eq!(model.domain.friends[&pk1].public_key, Some(pk1));

    // Verify Friend 3 data
    assert_eq!(model.domain.friends[&pk3].public_key, Some(pk3));

    // Verify Conversations
    // WindowId::Friend(pk1) should exist
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Friend(pk1)),
        "Conv 1 should exist"
    );

    // WindowId::Friend(pk3) should exist
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Friend(pk3)),
        "Conv 3 should exist"
    );

    // WindowId::Friend(pk2) SHOULD exist (preserved for history)
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Friend(pk2)),
        "Conv 2 should exist (preserved history)"
    );

    // Verify UI Window IDs
    assert!(
        model.ui.window_ids.contains(&WindowId::Friend(pk1)),
        "Window 1 should exist"
    );
    assert!(
        model.ui.window_ids.contains(&WindowId::Friend(pk3)),
        "Window 3 should exist"
    );
    assert!(
        model.ui.window_ids.contains(&WindowId::Friend(pk2)),
        "Window 2 should exist (preserved history)"
    );
}

#[test]
fn test_reconcile_syncs_friend_names() {
    let pk1 = PublicKey([1; 32]);

    // Initial state: Friend 1 loaded with default name "Friend 0"
    let mut friends = HashMap::new();
    friends.insert(
        pk1,
        FriendInfo {
            name: "Friend 0".into(),
            public_key: Some(pk1),
            status_message: "".into(),
            connection: ToxConnection::TOX_CONNECTION_NONE,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );

    let dummy_address = toxcore::tox::Address([0u8; 38]);

    let domain = DomainState {
        friends,
        ..DomainState::new(
            dummy_address,
            PublicKey([0; 32]),
            "Me".into(),
            "".into(),
            ToxUserStatus::TOX_USER_STATUS_NONE,
        )
    };

    let mut model = Model::new(domain, Config::default(), Config::default());

    // Create conversation/window with old name
    model.ensure_friend_window(pk1);

    // Verify initial name
    assert_eq!(
        model.domain.conversations[&WindowId::Friend(pk1)].name,
        "Friend 0"
    );

    // Simulate reload: Friend 0 has a new name "green_potato"
    let new_friends = vec![(
        FriendNumber(0),
        FriendInfo {
            name: "green_potato".into(),
            public_key: Some(pk1),
            status_message: "".into(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    )];

    model.reconcile(new_friends, vec![], vec![]);

    // Verify Name Updated
    assert_eq!(
        model.domain.conversations[&WindowId::Friend(pk1)].name,
        "green_potato",
        "Conversation name should be updated to match FriendInfo name"
    );
}
