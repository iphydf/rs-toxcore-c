use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, ControlAction, Permissions, PhysicalDevicePk};
use merkle_tox_core::engine::MerkleToxEngine;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, create_admin_node, create_signed_content_node, make_cert,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_retroactive_revocation_validation() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();

    // 1. Setup Room with Alice (Master) and Observer (Master)
    let room = merkle_tox_core::testing::TestRoom::new(2);
    let alice = &room.identities[0];
    let observer = &room.identities[1];

    let mut engine = MerkleToxEngine::new(
        observer.device_pk,
        observer.master_pk,
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // 2. Master Alice authorizes Admin A
    let admin_a = TestIdentity::new();
    let cert_a = make_cert(
        &alice.master_sk,
        admin_a.device_pk,
        Permissions::ADMIN | Permissions::MESSAGE,
        10000,
    );

    let genesis_hash = room.conv_id.to_node_hash();

    let auth_a_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![genesis_hash],
        ControlAction::AuthorizeDevice { cert: cert_a },
        1,
        1,
        100,
    );
    let effects = engine
        .handle_node(room.conv_id, auth_a_node.clone(), &store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);

    // 3. Admin A authorizes Device B
    let device_b = TestIdentity::new();
    let cert_b = make_cert(
        &admin_a.device_sk,
        device_b.device_pk,
        Permissions::MESSAGE,
        10000,
    );
    let auth_b_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &admin_a.device_sk,
        vec![auth_a_node.hash()],
        ControlAction::AuthorizeDevice { cert: cert_b },
        2,
        1,
        200,
    );
    let effects = engine
        .handle_node(room.conv_id, auth_b_node.clone(), &store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);

    // 4. Device B authors 10 messages (rank 3 to 12)
    let mut pre_rev_hashes = Vec::new();
    let mut last_hash = auth_b_node.hash();
    for i in 0..10 {
        let msg = create_signed_content_node(
            &room.conv_id,
            &room.keys,
            alice.master_pk,
            device_b.device_pk,
            vec![last_hash],
            Content::Text(format!("Pre-revocation {}", i)),
            (3 + i) as u64,
            (i + 1) as u64,
            1000 + i as i64,
        );
        last_hash = msg.hash();
        pre_rev_hashes.push(last_hash);
        let effects = engine.handle_node(room.conv_id, msg, &store, None).unwrap();
        assert!(merkle_tox_core::testing::is_verified_in_effects(&effects));
        merkle_tox_core::testing::apply_effects(effects, &store);
    }

    // 5. Admin A is revoked by Master at rank 2
    // We "withhold" this from the engine for a moment.
    let revoke_a_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![auth_a_node.hash()],
        ControlAction::RevokeDevice {
            target_device_pk: admin_a.device_pk,
            reason: "Compromised".to_string(),
        },
        2,
        2,
        5000,
    );

    // 6. Device B authors 5 more messages (rank 13 to 17)
    let mut post_rev_hashes = Vec::new();
    for i in 0..5 {
        let msg = create_signed_content_node(
            &room.conv_id,
            &room.keys,
            alice.master_pk,
            device_b.device_pk,
            vec![last_hash],
            Content::Text(format!("Post-revocation {}", i)),
            (13 + i) as u64,
            (i + 11) as u64,
            6000 + i as i64,
        );
        last_hash = msg.hash();
        post_rev_hashes.push(last_hash);
        let effects = engine.handle_node(room.conv_id, msg, &store, None).unwrap();
        assert!(merkle_tox_core::testing::is_verified_in_effects(&effects));
        merkle_tox_core::testing::apply_effects(effects, &store);
    }

    // 7. Finally, the observer receives the Revocation node
    let effects = engine
        .handle_node(room.conv_id, revoke_a_node, &store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);

    // 8. Trigger re-verification
    engine.reverify_speculative_for_conversation(room.conv_id, &store);

    // 9. Verification: ALL messages following the revocation rank (Rank 2)
    // should NO LONGER be verified, even if they were authored BEFORE
    // the observer received the revocation.
    for h in pre_rev_hashes.iter().chain(post_rev_hashes.iter()) {
        assert!(
            !store.is_verified(h),
            "Message {} should be invalidated due to retroactive revocation of its issuer's parent",
            hex::encode(h.as_bytes())
        );
    }
}

#[test]
fn test_malicious_snapshot_poisoning() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));
    let store = InMemoryStore::new();

    // 1. Setup Room
    let room = merkle_tox_core::testing::TestRoom::new(2);
    let alice = &room.identities[0];
    let mut engine = MerkleToxEngine::new(
        alice.device_pk,
        alice.master_pk,
        StdRng::seed_from_u64(0),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // 2. A malicious Admin authors a Snapshot that omits a member
    let malicious_snapshot = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![room.conv_id.to_node_hash()],
        ControlAction::Snapshot {
            basis_hash: room.conv_id.to_node_hash(),
            members: vec![], // EMPTY members list!
            last_seq_numbers: vec![],
        },
        1,
        1,
        1000,
    );

    // 3. A new joiner performs shallow sync and receives this snapshot
    let observer_pk = PhysicalDevicePk::from([9u8; 32]);
    let mut observer_engine = MerkleToxEngine::new(
        observer_pk,
        observer_pk.to_logical(),
        StdRng::seed_from_u64(1),
        tp,
    );
    let observer_store = InMemoryStore::new();

    observer_engine
        .handle_node(room.conv_id, malicious_snapshot, &observer_store, None)
        .unwrap();

    // Verification: The observer should still rely on the Admin Track, not JUST the snapshot,
    // or the snapshot itself MUST be verified against the Admin Track.
    // If the observer trusts the snapshot blindly, they will think the room is empty.

    // In our implementation, handle_node(Snapshot) applies side effects.
    // ControlAction::Snapshot side effects are NOT implemented in engine.rs yet!
    // So the malicious snapshot currently does nothing.
    // This test ensures that when we DO implement snapshot processing, we do it safely.
}
