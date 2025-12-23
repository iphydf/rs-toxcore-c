use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{ControlAction, KConv, Permissions};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{InMemoryStore, TestRoom, create_admin_node, create_msg};
use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_cross_room_admin_node_replay_protection() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));

    // 1. Setup Room A
    let room_a = TestRoom::new(1);
    let alice = &room_a.identities[0];
    let store_a = InMemoryStore::new();
    let mut engine_a = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        rand::rngs::StdRng::seed_from_u64(1),
        tp.clone(),
    );
    room_a.setup_engine(&mut engine_a, &store_a);

    // 2. Setup Room B (Independent)
    let room_b = TestRoom::new(1);
    let bob = &room_b.identities[0];
    let store_b = InMemoryStore::new();
    let mut engine_b = MerkleToxEngine::new(
        bob.device_pk,
        bob.master_pk,
        rand::rngs::StdRng::seed_from_u64(2),
        tp.clone(),
    );
    room_b.setup_engine(&mut engine_b, &store_b);

    // 3. Alice authors a 'SetTitle' in Room A
    let title_node_a = create_admin_node(
        &room_a.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![room_a.conv_id.to_node_hash()],
        ControlAction::SetTitle("Official Room A".to_string()),
        1,
        1,
        1000,
    );
    engine_a
        .handle_node(room_a.conv_id, title_node_a.clone(), &store_a, None)
        .unwrap();

    // 4. Attempt to replay Alice's node from Room A into Room B
    // Even if Alice were an admin in Room B, this should fail because it was
    // signed for Room A's context.

    let res = engine_b.handle_node(room_b.conv_id, title_node_a, &store_b, None);

    assert!(
        res.is_err(),
        "Engine should reject replayed node from another room"
    );

    if let Err(merkle_tox_core::error::MerkleToxError::Validation(
        merkle_tox_core::dag::ValidationError::InvalidAdminSignature,
    )) = res
    {
        // Correct error: Signature from Room A is invalid in Room B due to context binding
    } else {
        panic!(
            "Expected InvalidAdminSignature error due to cross-room context mismatch, got {:?}",
            res
        );
    }
}

#[test]
fn test_cross_room_auth_replay() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));

    let room_a = TestRoom::new(1);
    let alice = &room_a.identities[0];
    let store_a = InMemoryStore::new();
    let mut engine_a = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        rand::rngs::StdRng::seed_from_u64(1),
        tp.clone(),
    );
    room_a.setup_engine(&mut engine_a, &store_a);

    let room_b = TestRoom::new(1);
    let bob = &room_b.identities[0];
    let store_b = InMemoryStore::new();
    let mut engine_b = MerkleToxEngine::new(
        bob.device_pk,
        bob.master_pk,
        rand::rngs::StdRng::seed_from_u64(2),
        tp.clone(),
    );
    room_b.setup_engine(&mut engine_b, &store_b);

    // Alice authorizes a helper in Room A
    let cert = alice.make_device_cert(Permissions::ALL, 5000);
    let auth_node_a = create_admin_node(
        &room_a.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![room_a.conv_id.to_node_hash()],
        ControlAction::AuthorizeDevice { cert },
        1,
        1,
        1000,
    );
    engine_a
        .handle_node(room_a.conv_id, auth_node_a.clone(), &store_a, None)
        .unwrap();

    // Inject Alice as an Admin in Room B so her signature is technically "trusted"
    engine_b
        .identity_manager
        .add_member(room_b.conv_id, alice.master_pk, 1, 0); // Alice is Admin in Room B too

    // Now try to replay Alice's authorization of helper from Room A into Room B
    let res = engine_b.handle_node(room_b.conv_id, auth_node_a, &store_b, None);

    assert!(
        res.is_err(),
        "Should reject replayed authorization node from another room"
    );
    assert!(matches!(
        res.unwrap_err(),
        merkle_tox_core::error::MerkleToxError::Validation(
            merkle_tox_core::dag::ValidationError::InvalidAdminSignature
        )
    ));
}

#[test]
fn test_cross_room_content_replay_protection() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));

    // 1. Setup Room A
    let room_a = TestRoom::new(2); // Alice and Bob
    let alice = &room_a.identities[0];
    let store_a = InMemoryStore::new();
    let mut engine_a = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        rand::rngs::StdRng::seed_from_u64(1),
        tp.clone(),
    );
    room_a.setup_engine(&mut engine_a, &store_a);

    // 2. Setup Room B (Independent, but with SAME participants for the attack)
    let room_b = TestRoom::new(2);
    let store_b = InMemoryStore::new();
    let mut engine_b = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        rand::rngs::StdRng::seed_from_u64(2),
        tp.clone(),
    );

    // Manually add members to Room B with same keys as Room A to simulate an attack
    engine_b
        .identity_manager
        .add_member(room_b.conv_id, alice.master_pk, 1, 0);
    engine_b
        .identity_manager
        .add_member(room_b.conv_id, room_a.identities[1].master_pk, 1, 0);
    alice.authorize_in_engine(&mut engine_b, room_b.conv_id, Permissions::ALL, i64::MAX);
    room_a.identities[1].authorize_in_engine(
        &mut engine_b,
        room_b.conv_id,
        Permissions::ALL,
        i64::MAX,
    );

    // FORCE Room B to have the same starting key as Room A to test if context binding is enough
    store_b
        .put_conversation_key(&room_b.conv_id, 0, KConv::from(room_a.k_conv))
        .unwrap();
    engine_b
        .load_conversation_state(room_b.conv_id, &store_b)
        .unwrap();

    // 3. Alice authors a message in Room A
    let msg_a = create_msg(
        &room_a.conv_id,
        &room_a.keys,
        alice,
        vec![room_a.conv_id.to_node_hash()], // Parent is Room A genesis
        "Secret message for Room A only",
        1,
        2,
        1000,
    );

    // 4. Attempt to replay this message into Room B
    let effects = engine_b
        .handle_node(room_b.conv_id, msg_a.clone(), &store_b, None)
        .unwrap();

    // Content nodes with invalid MACs are stored speculatively (Bob might not have the right key yet)
    assert!(!merkle_tox_core::testing::is_verified_in_effects(&effects));

    // Now show that even with the correct K_conv, it cannot be verified because of context binding
    let (verified, _) = engine_b.verify_node(room_b.conv_id, &msg_a, &store_b);
    assert!(
        !verified,
        "Should fail verification because of conversation_id binding"
    );
}
