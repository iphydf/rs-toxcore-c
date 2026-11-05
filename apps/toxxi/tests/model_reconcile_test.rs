use std::collections::HashMap;
use toxcore::tox::{Connection, UserStatus};
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, FriendInfo, Model, WindowId};

#[test]
fn test_reconcile_removes_duplicates_and_migrates_conversations() {
    let pk1 = PublicKey([1; 32]);
    let pk2 = PublicKey([2; 32]);
    let pk3 = PublicKey([3; 32]);

    // 3 friends, from an outdated state.json.
    let mut friends = HashMap::new();
    friends.insert(
        pk1,
        FriendInfo {
            name: "Friend 1".into(),
            public_key: Some(pk1),
            status_message: "".into(),
            connection: Connection::None,
            is_typing: false,
        },
    );
    friends.insert(
        pk2,
        FriendInfo {
            name: "Friend 2 (To Be Deleted)".into(),
            public_key: Some(pk2),
            status_message: "".into(),
            connection: Connection::None,
            is_typing: false,
        },
    );
    friends.insert(
        pk3,
        FriendInfo {
            name: "Friend 3 (To Be Shifted)".into(),
            public_key: Some(pk3),
            status_message: "".into(),
            connection: Connection::None,
            is_typing: false,
        },
    );

    let dummy_address = toxcore::tox::Address([0u8; 38]);

    let domain = DomainState {
        friends,
        ..DomainState::new(dummy_address, "Me".into(), "".into(), UserStatus::None)
    };

    let mut model = Model::new(domain, Config::default(), Config::default());

    model.ensure_friend_window(pk1);
    model.ensure_friend_window(pk2);
    model.ensure_friend_window(pk3);

    // Reload with friend 2 (pk2) deleted:
    let new_friends = vec![
        FriendInfo {
            name: "Friend 1".into(),
            public_key: Some(pk1),
            status_message: "Online".into(),
            connection: Connection::Tcp,
            is_typing: false,
        },
        FriendInfo {
            name: "Friend 3".into(),
            public_key: Some(pk3),
            status_message: "Online".into(),
            connection: Connection::Tcp,
            is_typing: false,
        },
    ];

    model.reconcile(new_friends, vec![], vec![]);

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

    assert_eq!(model.domain.friends[&pk1].public_key, Some(pk1));

    assert_eq!(model.domain.friends[&pk3].public_key, Some(pk3));

    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Friend(pk1)),
        "Conv 1 should exist"
    );

    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Friend(pk3)),
        "Conv 3 should exist"
    );

    // pk2's conversation stays, for its history.
    assert!(
        model
            .domain
            .conversations
            .contains_key(&WindowId::Friend(pk2)),
        "Conv 2 should exist (preserved history)"
    );

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

    // Friend 1 loaded with the default name "Friend 0".
    let mut friends = HashMap::new();
    friends.insert(
        pk1,
        FriendInfo {
            name: "Friend 0".into(),
            public_key: Some(pk1),
            status_message: "".into(),
            connection: Connection::None,
            is_typing: false,
        },
    );

    let dummy_address = toxcore::tox::Address([0u8; 38]);

    let domain = DomainState {
        friends,
        ..DomainState::new(dummy_address, "Me".into(), "".into(), UserStatus::None)
    };

    let mut model = Model::new(domain, Config::default(), Config::default());

    model.ensure_friend_window(pk1);

    assert_eq!(
        model.domain.conversations[&WindowId::Friend(pk1)].name,
        "Friend 0"
    );

    // Reload with the new name "green_potato".
    let new_friends = vec![FriendInfo {
        name: "green_potato".into(),
        public_key: Some(pk1),
        status_message: "".into(),
        connection: Connection::Tcp,
        is_typing: false,
    }];

    model.reconcile(new_friends, vec![], vec![]);

    assert_eq!(
        model.domain.conversations[&WindowId::Friend(pk1)].name,
        "green_potato",
        "Conversation name should be updated to match FriendInfo name"
    );
}
