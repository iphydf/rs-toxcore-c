use ed25519_dalek::Signer;
use merkle_tox_core::clock::ManualTimeProvider;
use merkle_tox_core::dag::{Content, ControlAction, Ed25519Signature, NodeAuth, PhysicalDeviceSk};
use merkle_tox_core::engine::{Effect, MerkleToxEngine};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::testing::{
    InMemoryStore, TestIdentity, TestRoom, apply_effects, create_admin_node, create_msg,
    is_verified_in_effects, random_signing_key, sign_content_node_with_key,
    transfer_ephemeral_keys, transfer_wire_nodes,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Test 1: Admin node with mismatched signature and sender_pk rejected by `validate() -> verify_admin_signature()`.
///
/// Gap: `test_validate_auth_mismatch` tests wrong auth TYPE but never tests an
/// admin node whose Signature was produced by a key that doesn't match sender_pk.
#[test]
fn test_forged_admin_signature_rejected() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));

    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let bob = &room.identities[1];
    let store = InMemoryStore::new();
    let mut engine = MerkleToxEngine::new(
        bob.device_pk,
        bob.master_pk,
        StdRng::seed_from_u64(1),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // Build SetTitle node with Alice's sender_pk, sign with forger's key.
    // verify_admin_signature() checks signature against sender_pk, creating
    // a mismatch: sender_pk says "Alice" but signature is from someone else.
    let forger_sk = random_signing_key();
    let mut node = merkle_tox_core::testing::test_node();
    node.author_pk = alice.master_pk;
    node.sender_pk = alice.device_pk;
    node.parents = tox_proto::bounded_vec![room.conv_id.to_node_hash()];
    node.topological_rank = 1;
    node.sequence_number = 2;
    node.network_timestamp = 1000;
    node.content = Content::Control(ControlAction::Snapshot(
        merkle_tox_core::dag::SnapshotData {
            basis_hash: merkle_tox_core::dag::NodeHash::from([0u8; 32]),
            members: tox_proto::BoundedVec::new(),
            last_seq_numbers: tox_proto::BoundedVec::new(),
        },
    ));
    // Sign serialization with forger's key.
    let auth_data = node.serialize_for_auth();
    let sig = forger_sk.sign(&auth_data).to_bytes();
    node.authentication = NodeAuth::Signature(Ed25519Signature::from(sig));

    let result = engine.handle_node(room.conv_id, node, &store, None);
    assert!(
        matches!(
            result,
            Err(merkle_tox_core::error::MerkleToxError::Validation(
                merkle_tox_core::dag::ValidationError::InvalidAdminSignature
            ))
        ),
        "Admin node signed with wrong key must fail with InvalidAdminSignature, got: {:?}",
        result,
    );
}

/// Test 2: Content node signed with WRONG ephemeral key must not be verified.
///
/// Gap: No test that a content node with an incorrect ephemeral signature stays
/// speculative rather than being verified.
#[test]
fn test_forged_ephemeral_signature_stays_speculative() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));

    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let bob = &room.identities[1];

    // Author legitimate content node.
    let store_alice = InMemoryStore::new();
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        StdRng::seed_from_u64(1),
        tp.clone(),
    );
    room.setup_engine(&mut alice_engine, &store_alice);

    let effects = alice_engine
        .author_node(
            room.conv_id,
            Content::Text("Legitimate message".to_string()),
            vec![],
            &store_alice,
        )
        .unwrap();
    apply_effects(effects.clone(), &store_alice);

    let mut node = effects
        .iter()
        .find_map(|e| {
            if let Effect::WriteStore(_, node, _) = e
                && matches!(node.content, Content::Text(_))
            {
                return Some(node.clone());
            }
            None
        })
        .expect("Should have authored a text node");

    // Attacker replaces ephemeral signature with forged one.
    // Node's content and parents remain valid; only signature is forged.
    let attacker_eph_sk = random_signing_key();
    sign_content_node_with_key(&mut node, &room.conv_id, &attacker_eph_sk);

    // Bob is observer. He has Alice's REAL ephemeral signing key (from
    // transfer_ephemeral_keys), so attacker's signature won't match.
    let store_bob = InMemoryStore::new();
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        StdRng::seed_from_u64(2),
        tp.clone(),
    );
    room.setup_engine(&mut bob_engine, &store_bob);
    transfer_ephemeral_keys(&alice_engine, &mut bob_engine);

    // Transfer wire node (for encrypt-then-sign) and preceding nodes
    // (JIT SKDs, etc.) so parent chain is valid.
    let all_nodes = merkle_tox_core::testing::get_all_nodes_from_effects(&effects);
    for n in &all_nodes {
        if n.hash() != node.hash() {
            // Transfer unmodified nodes.
            let eff = bob_engine
                .handle_node(room.conv_id, n.clone(), &store_bob, None)
                .unwrap();
            apply_effects(eff, &store_bob);
        }
    }
    transfer_wire_nodes(&effects, &store_bob);

    // Bob receives tampered node. Ephemeral signature won't match because
    // it was forged. Wire node has original signature, so wire auth check
    // also fails. Node stays speculative.
    let effects = bob_engine
        .handle_node(room.conv_id, node, &store_bob, None)
        .unwrap();
    assert!(
        !is_verified_in_effects(&effects),
        "Content node with forged ephemeral signature must remain speculative"
    );
}

/// Test 3: Tampering with wire node ciphertext post-signing causes
/// signature verification failure under encrypt-then-sign.
///
/// Gap: Encrypt-then-sign pipeline tested via roundtrips, but no test
/// verifies modifying ciphertext post-signing breaks verification.
#[test]
fn test_encrypt_then_sign_wire_tampering() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));

    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let bob = &room.identities[1];

    let store_alice = InMemoryStore::new();
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        StdRng::seed_from_u64(1),
        tp.clone(),
    );
    room.setup_engine(&mut alice_engine, &store_alice);

    let store_bob = InMemoryStore::new();
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        StdRng::seed_from_u64(2),
        tp.clone(),
    );
    room.setup_engine(&mut bob_engine, &store_bob);

    // Author content node.
    let effects = alice_engine
        .author_node(
            room.conv_id,
            Content::Text("Secret message".to_string()),
            vec![],
            &store_alice,
        )
        .unwrap();
    apply_effects(effects.clone(), &store_alice);

    // Transfer ephemeral signing keys.
    transfer_ephemeral_keys(&alice_engine, &mut bob_engine);

    // Extract authored node.
    let authored_node = effects
        .iter()
        .find_map(|e| {
            if let Effect::WriteStore(_, node, _) = e
                && matches!(node.content, Content::Text(_))
            {
                return Some(node.clone());
            }
            None
        })
        .expect("Should have authored a text node");

    // Transfer tampered wire nodes.
    for effect in &effects {
        if let Effect::WriteWireNode(cid, hash, wire) = effect {
            let mut tampered_wire = wire.clone();
            if !tampered_wire.payload_data.is_empty() {
                tampered_wire.payload_data[0] ^= 0xFF;
            }
            let _ = store_bob.put_wire_node(cid, hash, tampered_wire);
        }
    }

    // Tampered ciphertext fails wire signature verification. Node remains speculative.
    let effects = bob_engine
        .handle_node(room.conv_id, authored_node, &store_bob, None)
        .unwrap();
    assert!(
        !is_verified_in_effects(&effects),
        "Node with tampered wire ciphertext must remain speculative (encrypt-then-sign)"
    );
}

/// Test 4: Out-of-order delivery succeeds; consumed message replay rejected.
///
/// Gap: Confirms if seq=3 arrives first, seq=2 still works, and replaying
/// seq=2 again is rejected (deduplicated).
#[test]
fn test_out_of_order_sequence_accepted_replay_rejected() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));

    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let bob = &room.identities[1];

    // Observer setup.
    let store = InMemoryStore::new();
    let mut engine = MerkleToxEngine::new(
        bob.device_pk,
        bob.master_pk,
        StdRng::seed_from_u64(2),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // Get current heads.
    let heads = store.get_heads(&room.conv_id);
    let admin_heads = store.get_admin_heads(&room.conv_id);
    let mut all_parents = heads.clone();
    for h in &admin_heads {
        if !all_parents.contains(h) {
            all_parents.push(*h);
        }
    }
    all_parents.sort_unstable();
    let max_rank = all_parents
        .iter()
        .filter_map(|h| store.get_node(h).map(|n| n.topological_rank))
        .max()
        .unwrap_or(0);

    // Create independent messages with same parents, different sequences.
    // Both reference same parent set so they process independently.
    let msg1 = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        all_parents.clone(),
        "Message 1",
        max_rank + 1,
        2, // seq=2
        1000,
    );
    let msg2 = create_msg(
        &room.conv_id,
        &room.keys,
        alice,
        all_parents,
        "Message 2",
        max_rank + 1,
        3, // seq=3
        1001,
    );

    // Receive msg2 out-of-order.
    let effects = engine
        .handle_node(room.conv_id, msg2.clone(), &store, None)
        .unwrap();
    assert!(
        is_verified_in_effects(&effects),
        "Out-of-order msg2 (seq=3) should be verified"
    );
    apply_effects(effects, &store);

    // Receive msg1 out-of-order.
    let effects = engine
        .handle_node(room.conv_id, msg1.clone(), &store, None)
        .unwrap();
    assert!(
        is_verified_in_effects(&effects),
        "msg1 (seq=2) should be verified even though it arrived after msg2 (seq=3)"
    );
    apply_effects(effects, &store);

    // Replay msg1.
    let result = engine.handle_node(room.conv_id, msg1.clone(), &store, None);
    match result {
        Ok(effects) => {
            let has_write = effects
                .iter()
                .any(|e| matches!(e, Effect::WriteStore(_, _, _)));
            assert!(
                !has_write,
                "Replayed msg1 must be deduplicated (no WriteStore)"
            );
        }
        Err(_) => {
            // Also acceptable: explicit rejection
        }
    }
}

/// Test 5: PCS gate blocks revoked device after two epoch rotations.
///
/// Device-signed SKD (epoch 0->1) bypasses PCS (allows new devices to bootstrap).
/// Ephemeral-signed SKD (epoch 1->2) enforces PCS, requiring k_conv to
/// store ephemeral signing key.
#[test]
fn test_revoked_device_skd_blocked_by_pcs_gate() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));

    let room = TestRoom::new(3);
    let alice = &room.identities[0];
    let bob = &room.identities[1];
    let mallory = &room.identities[2];

    let store_alice = InMemoryStore::new();
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        StdRng::seed_from_u64(1),
        tp.clone(),
    );
    room.setup_engine(&mut alice_engine, &store_alice);

    let store_bob = InMemoryStore::new();
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        StdRng::seed_from_u64(2),
        tp.clone(),
    );
    room.setup_engine(&mut bob_engine, &store_bob);

    let store_mallory = InMemoryStore::new();
    let mut mallory_engine = MerkleToxEngine::with_sk(
        mallory.device_pk,
        mallory.master_pk,
        PhysicalDeviceSk::from(mallory.device_sk.to_bytes()),
        StdRng::seed_from_u64(3),
        tp.clone(),
    );
    room.setup_engine(&mut mallory_engine, &store_mallory);

    // Start at Epoch 0.
    assert_eq!(alice_engine.get_current_generation(&room.conv_id), 0);

    // === Auto-rotation: Epoch 0 -> 1 (device-signed SKD) ===
    // RevokeDevice triggers auto-rotation.
    let effects = alice_engine
        .author_node(
            room.conv_id,
            Content::Control(ControlAction::RevokeDevice {
                target_device_pk: mallory.device_pk,
                reason: "Compromised".to_string(),
            }),
            vec![],
            &store_alice,
        )
        .unwrap();
    // Extract nodes.
    let all_revoke_nodes: Vec<_> = effects
        .iter()
        .filter_map(|e| {
            if let Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect();
    apply_effects(effects, &store_alice);

    // Receive effects.
    for node in &all_revoke_nodes {
        let effects = bob_engine
            .handle_node(room.conv_id, node.clone(), &store_bob, None)
            .unwrap();
        apply_effects(effects, &store_bob);
    }
    for node in &all_revoke_nodes {
        let effects = mallory_engine
            .handle_node(room.conv_id, node.clone(), &store_mallory, None)
            .unwrap();
        apply_effects(effects, &store_mallory);
    }

    assert_eq!(bob_engine.get_current_generation(&room.conv_id), 1);
    assert_eq!(mallory_engine.get_current_generation(&room.conv_id), 0);

    // Mallory lacks k_conv for epoch 1 despite device-signed bypass.

    // === Explicit rotation: Epoch 1 -> 2 (ephemeral-signed SKD) ===
    let effects = alice_engine
        .rotate_conversation_key(room.conv_id, &store_alice)
        .unwrap();
    let rotation2_nodes: Vec<_> = effects
        .iter()
        .filter_map(|e| {
            if let Effect::WriteStore(_, node, _) = e {
                Some(node.clone())
            } else {
                None
            }
        })
        .collect();
    apply_effects(effects, &store_alice);

    for node in &rotation2_nodes {
        let effects = bob_engine
            .handle_node(room.conv_id, node.clone(), &store_bob, None)
            .unwrap();
        apply_effects(effects, &store_bob);
    }
    for node in &rotation2_nodes {
        let effects = mallory_engine
            .handle_node(room.conv_id, node.clone(), &store_mallory, None)
            .unwrap();
        apply_effects(effects, &store_mallory);
    }

    // Check epochs.
    assert_eq!(bob_engine.get_current_generation(&room.conv_id), 2);
    assert_eq!(
        mallory_engine.get_current_generation(&room.conv_id),
        0,
        "Mallory (revoked) must not advance past Epoch 0"
    );

    // PCS gate blocks Mallory from storing epoch 2 ephemeral signing key.
    // SKD for epoch 2 is ephemeral-signed (not device-signed), so PCS
    // gate checks `has_epoch_key` which is false for Mallory (no k_conv).
    let has_epoch2_key = mallory_engine
        .peer_ephemeral_signing_keys
        .contains_key(&(alice.device_pk, 2));
    assert!(
        !has_epoch2_key,
        "PCS gate must block Mallory from learning Alice's epoch 2 ephemeral signing key"
    );

    // Author epoch 2 content.
    let effects = alice_engine
        .author_node(
            room.conv_id,
            Content::Text("Epoch 2 secret".to_string()),
            vec![],
            &store_alice,
        )
        .unwrap();
    let msg_e2 = effects
        .iter()
        .find_map(|e| {
            if let Effect::WriteStore(_, node, _) = e
                && matches!(node.content, Content::Text(_))
            {
                return Some(node.clone());
            }
            None
        })
        .unwrap();
    transfer_wire_nodes(&effects, &store_mallory);
    apply_effects(effects, &store_alice);

    let effects = mallory_engine
        .handle_node(room.conv_id, msg_e2, &store_mallory, None)
        .unwrap();
    assert!(
        !is_verified_in_effects(&effects),
        "Mallory must not verify Epoch 2 content (no ephemeral signing key, no k_conv)"
    );
}

/// Test 6: Vouching does not bypass permission checks for admin content.
///
/// Gap: VOUCH_THRESHOLD=1 allows unauthorized node structurally. Admin
/// operations must still be blocked by permission checks, not blindly verified.
#[test]
fn test_vouching_does_not_bypass_permission_check() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 0));

    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let bob = &room.identities[1];
    let store = InMemoryStore::new();
    let mut engine = MerkleToxEngine::new(
        bob.device_pk,
        bob.master_pk,
        StdRng::seed_from_u64(1),
        tp.clone(),
    );
    room.setup_engine(&mut engine, &store);

    // Charlie is unauthorized.
    let charlie = TestIdentity::new();

    // Create unauthorized admin node.
    let charlie_node = create_admin_node(
        &room.conv_id,
        charlie.master_pk,
        &charlie.device_sk,
        vec![room.conv_id.to_node_hash()],
        ControlAction::Snapshot(merkle_tox_core::dag::SnapshotData {
            basis_hash: merkle_tox_core::dag::NodeHash::from([0u8; 32]),
            members: tox_proto::BoundedVec::new(),
            last_seq_numbers: tox_proto::BoundedVec::new(),
        }),
        1,
        1,
        1000,
    );
    let charlie_hash = charlie_node.hash();

    // Node stored speculatively.
    let effects = engine
        .handle_node(room.conv_id, charlie_node.clone(), &store, None)
        .unwrap();
    assert!(
        !is_verified_in_effects(&effects),
        "Unauthorized Charlie's SetTitle must not be verified on first pass"
    );
    apply_effects(effects, &store);

    // Alice authors node referencing Charlie's hash as parent (vouch).
    // Provides VOUCH_THRESHOLD=1, but missing authorization chain prevents verification.
    let alice_vouch_node = create_admin_node(
        &room.conv_id,
        alice.master_pk,
        &alice.master_sk,
        vec![room.conv_id.to_node_hash(), charlie_hash],
        ControlAction::Snapshot(merkle_tox_core::dag::SnapshotData {
            basis_hash: merkle_tox_core::dag::NodeHash::from([0u8; 32]),
            members: tox_proto::BoundedVec::new(),
            last_seq_numbers: tox_proto::BoundedVec::new(),
        }),
        2,
        2,
        1001,
    );
    let effects = engine
        .handle_node(room.conv_id, alice_vouch_node, &store, None)
        .unwrap();
    apply_effects(effects, &store);

    // Reverification fails due to missing authorization record.
    let (verified, _) = engine.verify_node(room.conv_id, &charlie_node, &store);
    assert!(
        !verified,
        "Charlie's unauthorized SetTitle must not pass verification even with a vouch"
    );
}

/// Test 7: Late out-of-order message fails verification after ratchet key TTL expires.
///
/// Gap: No test of the TTL eviction path at conversation.rs:188.
#[test]
fn test_skipped_key_ttl_expiry_rejects_late_message() {
    let _ = tracing_subscriber::fmt::try_init();
    let tp = Arc::new(ManualTimeProvider::new(Instant::now(), 1000));

    let room = TestRoom::new(2);
    let alice = &room.identities[0];
    let bob = &room.identities[1];

    let store_alice = InMemoryStore::new();
    let mut alice_engine = MerkleToxEngine::with_sk(
        alice.device_pk,
        alice.master_pk,
        PhysicalDeviceSk::from(alice.device_sk.to_bytes()),
        StdRng::seed_from_u64(1),
        tp.clone(),
    );
    room.setup_engine(&mut alice_engine, &store_alice);

    let store_bob = InMemoryStore::new();
    let mut bob_engine = MerkleToxEngine::with_sk(
        bob.device_pk,
        bob.master_pk,
        PhysicalDeviceSk::from(bob.device_sk.to_bytes()),
        StdRng::seed_from_u64(2),
        tp.clone(),
    );
    room.setup_engine(&mut bob_engine, &store_bob);

    // Author messages.
    let effects1 = alice_engine
        .author_node(
            room.conv_id,
            Content::Text("Message 1".to_string()),
            vec![],
            &store_alice,
        )
        .unwrap();
    let msg1 = effects1
        .iter()
        .find_map(|e| {
            if let Effect::WriteStore(_, node, _) = e
                && matches!(node.content, Content::Text(_))
            {
                return Some(node.clone());
            }
            None
        })
        .unwrap();
    transfer_wire_nodes(&effects1, &store_bob);
    apply_effects(effects1, &store_alice);

    let effects2 = alice_engine
        .author_node(
            room.conv_id,
            Content::Text("Message 2".to_string()),
            vec![],
            &store_alice,
        )
        .unwrap();
    let msg2 = effects2
        .iter()
        .find_map(|e| {
            if let Effect::WriteStore(_, node, _) = e
                && matches!(node.content, Content::Text(_))
            {
                return Some(node.clone());
            }
            None
        })
        .unwrap();
    transfer_wire_nodes(&effects2, &store_bob);
    apply_effects(effects2, &store_alice);

    // Transfer ephemeral signing keys AFTER authoring
    transfer_ephemeral_keys(&alice_engine, &mut bob_engine);

    // Receive msg2 out-of-order.
    let effects = bob_engine
        .handle_node(room.conv_id, msg2.clone(), &store_bob, None)
        .unwrap();
    assert!(
        is_verified_in_effects(&effects),
        "msg2 should be verified (ratchet skip caches key for msg1)"
    );
    apply_effects(effects, &store_bob);

    // Advance clock beyond TTL.
    tp.advance(Duration::from_secs(25 * 3600));

    // Receive msg1.
    let effects = bob_engine
        .handle_node(room.conv_id, msg1.clone(), &store_bob, None)
        .unwrap();

    // Skipped key evicted by TTL cleanup in peek_keys.
    // Without cached key, ratchet can't produce message key for past sequence
    // number. Node remains speculative.
    assert!(
        !is_verified_in_effects(&effects),
        "msg1 should fail verification after skipped key TTL expiry (25h > 24h limit)"
    );
}
