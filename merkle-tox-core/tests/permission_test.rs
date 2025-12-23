use ed25519_dalek::SigningKey;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::crypto::ConversationKeys;
use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, KConv, LogicalIdentityPk, Permissions, PhysicalDevicePk,
};
use merkle_tox_core::engine::{Conversation, ConversationData, MerkleToxEngine, conversation};
use merkle_tox_core::testing::{
    InMemoryStore, create_admin_node, create_signed_content_node, make_cert,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_permission_denied_message() {
    let alice_master_sk = SigningKey::from_bytes(&[1u8; 32]);
    let alice_master_pk = LogicalIdentityPk::from(alice_master_sk.verifying_key().to_bytes());
    let alice_device_sk = SigningKey::from_bytes(&[2u8; 32]);
    let alice_device_pk = PhysicalDevicePk::from(alice_device_sk.verifying_key().to_bytes());
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::new(
        alice_device_pk,
        alice_master_pk,
        StdRng::seed_from_u64(0),
        tp,
    );

    let store = InMemoryStore::new();

    let sync_key = ConversationId::from([0u8; 32]);
    let k_conv = KConv::from([0xAAu8; 32]);
    engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key,
            k_conv.clone(),
            0,
        )),
    );

    // Authorize device with ONLY ADMIN (no MESSAGE)
    let cert = make_cert(
        &alice_master_sk,
        alice_device_pk,
        Permissions::ADMIN,
        2000000000000,
    );
    engine
        .identity_manager
        .authorize_device(sync_key, alice_master_pk, &cert, 1000, 0)
        .unwrap();

    // Try to send a message (Unauthorized sender_pk)
    let msg = create_signed_content_node(
        &sync_key,
        &ConversationKeys::derive(&k_conv),
        alice_master_pk,
        alice_device_pk,
        vec![],
        Content::Text("Hello".to_string()),
        0,
        1,
        1100,
    );

    let res = engine.handle_node(sync_key, msg, &store, None);
    assert!(
        matches!(
            res.unwrap_err(),
            merkle_tox_core::error::MerkleToxError::PermissionDenied { .. }
        ),
        "Expected PermissionDenied error"
    );
}

#[test]
fn test_permission_granted_message() {
    let alice_master_sk = SigningKey::from_bytes(&[1u8; 32]);
    let alice_master_pk = LogicalIdentityPk::from(alice_master_sk.verifying_key().to_bytes());
    let alice_device_sk = SigningKey::from_bytes(&[2u8; 32]);
    let alice_device_pk = PhysicalDevicePk::from(alice_device_sk.verifying_key().to_bytes());
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::new(
        alice_device_pk,
        alice_master_pk,
        StdRng::seed_from_u64(0),
        tp,
    );

    let store = InMemoryStore::new();

    let sync_key = ConversationId::from([0u8; 32]);
    let k_conv = KConv::from([0xAAu8; 32]);
    engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key,
            k_conv.clone(),
            0,
        )),
    );

    // Authorize device with MESSAGE
    let cert = make_cert(
        &alice_master_sk,
        alice_device_pk,
        Permissions::MESSAGE,
        2000000000000,
    );
    engine
        .identity_manager
        .authorize_device(sync_key, alice_master_pk, &cert, 1000, 0)
        .unwrap();

    // Try to send a message
    let msg = create_signed_content_node(
        &sync_key,
        &ConversationKeys::derive(&k_conv),
        alice_master_pk,
        alice_device_pk,
        vec![],
        Content::Text("Hello".to_string()),
        0,
        1,
        1100,
    );

    let res = engine.handle_node(sync_key, msg, &store, None);
    assert!(res.is_ok());
}

#[test]
fn test_revocation_enforcement() {
    let alice_master_sk = SigningKey::from_bytes(&[1u8; 32]);
    let alice_master_pk = LogicalIdentityPk::from(alice_master_sk.verifying_key().to_bytes());
    let alice_device_pk = PhysicalDevicePk::from([11u8; 32]);
    let bob_pk = PhysicalDevicePk::from([2u8; 32]);
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine =
        MerkleToxEngine::new(bob_pk, bob_pk.to_logical(), StdRng::seed_from_u64(0), tp);
    let store = InMemoryStore::new();

    let sync_key = ConversationId::from([0u8; 32]);
    let k_conv = KConv::from([0xAAu8; 32]);
    engine.conversations.insert(
        sync_key,
        Conversation::Established(ConversationData::<conversation::Established>::new(
            sync_key,
            k_conv.clone(),
            0,
        )),
    );

    // 1. Authorize Alice's device
    let cert = make_cert(
        &alice_master_sk,
        alice_device_pk,
        Permissions::MESSAGE | Permissions::ADMIN,
        2000000000000,
    );
    engine
        .identity_manager
        .authorize_device(sync_key, alice_master_pk, &cert, 1000, 0)
        .unwrap();

    assert!(engine.identity_manager.is_authorized(
        sync_key,
        &alice_device_pk,
        &alice_master_pk,
        1100,
        0
    ));

    // 2. Process a RevokeDevice node signed by Master
    let revoke_node = create_admin_node(
        &sync_key,
        alice_master_pk,
        &alice_master_sk,
        vec![],
        ControlAction::RevokeDevice {
            target_device_pk: alice_device_pk,
            reason: "Lost phone".to_string(),
        },
        0,
        1,
        1200,
    );

    let effects = engine
        .handle_node(sync_key, revoke_node, &store, None)
        .expect("Should handle revocation");
    assert!(merkle_tox_core::testing::is_verified_in_effects(&effects));

    // 3. Verify Alice's device is no longer authorized
    assert!(!engine.identity_manager.is_authorized(
        sync_key,
        &alice_device_pk,
        &alice_master_pk,
        1300,
        0
    ));
}

#[test]
fn test_self_authorization() {
    let alice_master_sk = SigningKey::from_bytes(&[1u8; 32]);
    let alice_master_pk = LogicalIdentityPk::from(alice_master_sk.verifying_key().to_bytes());
    let alice_device_sk = SigningKey::from_bytes(&[2u8; 32]);
    let alice_device_pk = PhysicalDevicePk::from(alice_device_sk.verifying_key().to_bytes());
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::new(
        alice_device_pk,
        alice_master_pk,
        StdRng::seed_from_u64(0),
        tp,
    );

    let store = InMemoryStore::new();

    let sync_key = ConversationId::from([0u8; 32]);

    // Cert signed by Master for the Device
    let cert = make_cert(
        &alice_master_sk,
        alice_device_pk,
        Permissions::MESSAGE,
        2000000000000,
    );

    // Authorization node signed by the DEVICE itself (which is NOT YET authorized)
    let auth_node = create_admin_node(
        &sync_key,
        alice_master_pk,
        &alice_device_sk,
        vec![],
        ControlAction::AuthorizeDevice { cert },
        0,
        1,
        1000,
    );

    // This should work because handle_node has a special case for AuthorizeDevice
    let effects = engine
        .handle_node(sync_key, auth_node, &store, None)
        .unwrap();
    assert!(merkle_tox_core::testing::is_verified_in_effects(&effects));
    assert!(engine.identity_manager.is_authorized(
        sync_key,
        &alice_device_pk,
        &alice_master_pk,
        1100,
        0
    ));
}

#[test]
fn test_self_authorization_unauthorized_content() {
    let alice_master_sk = SigningKey::from_bytes(&[1u8; 32]);
    let alice_master_pk = LogicalIdentityPk::from(alice_master_sk.verifying_key().to_bytes());
    let alice_device_sk = SigningKey::from_bytes(&[2u8; 32]);
    let alice_device_pk = PhysicalDevicePk::from(alice_device_sk.verifying_key().to_bytes());
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::new(
        alice_device_pk,
        alice_master_pk,
        StdRng::seed_from_u64(0),
        tp,
    );

    let store = InMemoryStore::new();
    let sync_key = ConversationId::from([0u8; 32]);

    // Node signed by the DEVICE, but trying to set a topic instead of AuthorizeDevice
    let auth_node = create_admin_node(
        &sync_key,
        alice_master_pk,
        &alice_device_sk,
        vec![],
        ControlAction::SetTopic("I am an admin now".to_string()),
        0,
        1,
        1000,
    );

    // This should be Speculative because the sender is not authorized
    // and it's not an AuthorizeDevice node that would trigger the special bypass.
    let effects = engine
        .handle_node(sync_key, auth_node, &store, None)
        .unwrap();
    assert!(!merkle_tox_core::testing::is_verified_in_effects(&effects));
}

#[test]
fn test_self_authorization_invalid_signature() {
    let alice_master_sk = SigningKey::from_bytes(&[1u8; 32]);
    let alice_master_pk = LogicalIdentityPk::from(alice_master_sk.verifying_key().to_bytes());
    let alice_device_pk = PhysicalDevicePk::from([11u8; 32]);
    let rogue_sk = SigningKey::from_bytes(&[3u8; 32]);

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::new(
        PhysicalDevicePk::from([0u8; 32]),
        LogicalIdentityPk::from([0u8; 32]),
        StdRng::seed_from_u64(0),
        tp,
    );
    let store = InMemoryStore::new();
    let sync_key = ConversationId::from([0u8; 32]);

    let cert = make_cert(
        &alice_master_sk,
        alice_device_pk,
        Permissions::MESSAGE,
        2000000000000,
    );

    // Authorization node where sender_pk is alice_device_pk, but it's signed by rogue_sk
    let auth_node = create_admin_node(
        &sync_key,
        alice_master_pk,
        &rogue_sk,
        vec![],
        ControlAction::AuthorizeDevice { cert },
        0,
        1,
        1000,
    );

    let mut corrupted_node = auth_node;
    corrupted_node.sender_pk = alice_device_pk; // Claims to be alice_device_pk but signed by rogue_sk

    // This should FAIL because the signature check fails
    let res = engine.handle_node(sync_key, corrupted_node, &store, None);
    assert!(res.is_err());
}

#[test]
fn test_unauthorized_leave_bug() {
    let alice_master_sk = SigningKey::from_bytes(&[1u8; 32]);
    let alice_master_pk = LogicalIdentityPk::from(alice_master_sk.verifying_key().to_bytes());
    let alice_device_sk = SigningKey::from_bytes(&[2u8; 32]);
    let alice_device_pk = PhysicalDevicePk::from(alice_device_sk.verifying_key().to_bytes());

    let bob_master_sk = SigningKey::from_bytes(&[3u8; 32]);
    let bob_master_pk = LogicalIdentityPk::from(bob_master_sk.verifying_key().to_bytes());
    let bob_device_sk = SigningKey::from_bytes(&[4u8; 32]);
    let bob_device_pk = PhysicalDevicePk::from(bob_device_sk.verifying_key().to_bytes());

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::new(
        alice_device_pk,
        alice_master_pk,
        StdRng::seed_from_u64(0),
        tp,
    );
    let store = InMemoryStore::new();
    let sync_key = ConversationId::from([0u8; 32]);

    // 1. Setup room: Alice is Owner, Bob is Member
    engine
        .identity_manager
        .add_member(sync_key, alice_master_pk, 0, 1000);
    engine
        .identity_manager
        .add_member(sync_key, bob_master_pk, 1, 1000);

    // Authorize Alice's device (Admin)
    let alice_cert = make_cert(
        &alice_master_sk,
        alice_device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        2000000000000,
    );
    engine
        .identity_manager
        .authorize_device(sync_key, alice_master_pk, &alice_cert, 1000, 0)
        .unwrap();

    // Authorize Bob's device (Member only, NO ADMIN)
    let bob_cert = make_cert(
        &bob_master_sk,
        bob_device_pk,
        Permissions::MESSAGE,
        2000000000000,
    );
    engine
        .identity_manager
        .authorize_device(sync_key, bob_master_pk, &bob_cert, 1000, 0)
        .unwrap();

    // 2. Bob tries to kick Alice using Leave(Alice_PK)
    let kick_node = create_admin_node(
        &sync_key,
        bob_master_pk,
        &bob_device_sk,
        vec![],
        ControlAction::Leave(alice_master_pk),
        0,
        1,
        1100,
    );

    // Bob shouldn't be allowed to kick others.
    // He should only be allowed to Leave himself, or Leave should require ADMIN.
    let res = engine.handle_node(sync_key, kick_node, &store, None);

    // This assertion SHOULD pass if the system is secure, but it will FAIL currently.
    assert!(
        res.is_err(),
        "Non-admin Bob should not be able to kick Alice"
    );
}

#[test]
fn test_authorized_self_leave() {
    let alice_master_sk = SigningKey::from_bytes(&[1u8; 32]);
    let alice_master_pk = LogicalIdentityPk::from(alice_master_sk.verifying_key().to_bytes());
    let alice_device_sk = SigningKey::from_bytes(&[2u8; 32]);
    let alice_device_pk = PhysicalDevicePk::from(alice_device_sk.verifying_key().to_bytes());

    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let mut engine = MerkleToxEngine::new(
        alice_device_pk,
        alice_master_pk,
        StdRng::seed_from_u64(0),
        tp,
    );
    let store = InMemoryStore::new();
    let sync_key = ConversationId::from([0u8; 32]);

    // Setup room: Alice is Member (no admin)
    engine
        .identity_manager
        .add_member(sync_key, alice_master_pk, 1, 1000);

    let alice_cert = make_cert(
        &alice_master_sk,
        alice_device_pk,
        Permissions::MESSAGE, // No ADMIN
        2000000000000,
    );
    engine
        .identity_manager
        .authorize_device(sync_key, alice_master_pk, &alice_cert, 1000, 0)
        .unwrap();

    // Alice leaves the room
    let leave_node = create_admin_node(
        &sync_key,
        alice_master_pk,
        &alice_device_sk,
        vec![],
        ControlAction::Leave(alice_master_pk),
        0,
        1,
        1100,
    );

    let res = engine.handle_node(sync_key, leave_node, &store, None);
    assert!(res.is_ok(), "Alice should be allowed to leave herself");

    // Verify Alice is GONE
    let members = engine.identity_manager.list_members(sync_key);
    assert!(
        !members.iter().any(|m| m.0 == alice_master_pk),
        "Alice should have been removed"
    );
}
