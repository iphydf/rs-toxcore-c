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
        room.conv_id,
    );

    let admin_heads = store.get_admin_heads(&room.conv_id);

    let auth_a_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        admin_heads,
        ControlAction::AuthorizeDevice { cert: cert_a },
        2,
        2,
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
        room.conv_id,
    );
    let auth_b_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &admin_a.device_sk,
        vec![auth_a_node.hash()],
        ControlAction::AuthorizeDevice { cert: cert_b },
        3,
        1,
        200,
    );
    let effects = engine
        .handle_node(room.conv_id, auth_b_node.clone(), &store, None)
        .unwrap();
    merkle_tox_core::testing::apply_effects(effects, &store);

    // Register device_b's test ephemeral key so its content nodes can be verified
    merkle_tox_core::testing::register_test_ephemeral_key(
        &mut engine,
        &room.keys,
        &device_b.device_pk,
    );

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
            (4 + i) as u64, // Rank starts at 4
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
        3, // Rank 3
        3, // Seq 3
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
            (14 + i) as u64, // Rank starts at 14
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

    // 9. Verification: Under Causal Identity, messages on a concurrent branch
    // that do not have the revocation in their causal history remain verified.
    for h in pre_rev_hashes.iter().chain(post_rev_hashes.iter()) {
        assert!(
            store.is_verified(h),
            "Message {} should REMAIN verified because the revocation is not in its causal history",
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
        ControlAction::Snapshot(merkle_tox_core::dag::SnapshotData {
            basis_hash: room.conv_id.to_node_hash(),
            members: tox_proto::BoundedVec::new(), // EMPTY members list!
            last_seq_numbers: tox_proto::BoundedVec::new(),
        }),
        1,
        1,
        1000,
    );

    // 3. An observer with an existing membership view receives the malicious
    //    snapshot. We use a separate TestRoom-setup engine so the observer
    //    has a populated identity_manager — that's the attack surface: if
    //    handle_node(Snapshot) blindly imported `data.members`, it would wipe
    //    the observer's member list to empty.
    let observer_pk = PhysicalDevicePk::from([9u8; 32]);
    let mut observer_engine = MerkleToxEngine::new(
        observer_pk,
        observer_pk.to_logical(),
        StdRng::seed_from_u64(1),
        tp,
    );
    let observer_store = InMemoryStore::new();
    room.setup_engine(&mut observer_engine, &observer_store);

    let members_before = observer_engine.identity_manager.list_members(room.conv_id);
    assert!(
        !members_before.is_empty(),
        "baseline: observer's membership view must be populated before the \
         attack for this test to be meaningful",
    );

    observer_engine
        .handle_node(room.conv_id, malicious_snapshot, &observer_store, None)
        .unwrap();

    // §3.10 / identity-integrity: ControlAction::Snapshot must NOT import
    // members — only AnchorSnapshot may do so, and only under the
    // skip_generic_path ADMIN cert gate (Gap 15). A plain Snapshot
    // side-effect is intentionally limited to updating latest_anchor_hashes,
    // which is what makes the empty-members snapshot inert.
    let members_after = observer_engine.identity_manager.list_members(room.conv_id);
    assert_eq!(
        members_before, members_after,
        "malicious Snapshot must not alter observer's membership view; \
         member-list imports are restricted to AnchorSnapshot",
    );
}
