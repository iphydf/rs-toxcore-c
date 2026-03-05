use merkle_tox_core::dag::{
    Content, ConversationId, Ed25519Signature, LogicalIdentityPk, MerkleNode, NodeAuth,
    PhysicalDevicePk,
};
use merkle_tox_core::engine::session::{Handshake, SyncSession};
use merkle_tox_core::sync::{DecodingResult, NodeStore, SyncRange, Tier};
use merkle_tox_core::testing::InMemoryStore;
use std::time::Instant;

#[test]
fn test_adaptive_tier_scaling() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store = InMemoryStore::new();

    let mut session =
        SyncSession::<Handshake>::new(conversation_id, &store, false, Instant::now()).activate(0);
    let range = SyncRange {
        min_rank: 0,
        max_rank: 100,
    };

    assert_eq!(session.get_iblt_tier(&range), Some(Tier::Small));

    // Fail decoding once
    let mut iblt_huge = tox_reconcile::IbltSketch::new(Tier::Tiny.cell_count());
    for i in 0..50 {
        iblt_huge.insert(&[i as u8; 32]);
    }
    let sketch = tox_reconcile::SyncSketch {
        conversation_id: session.conversation_id,
        cells: tox_proto::BoundedVec::try_from_iter(iblt_huge.into_cells()).expect("Tier-bounded"),
        range: range.clone(),
    };

    let res = session.handle_sync_sketch(sketch, &store).unwrap();
    assert!(matches!(res, DecodingResult::Failed));

    // Tier should be promoted
    assert_eq!(session.get_iblt_tier(&range), Some(Tier::Medium));

    // Explicitly fail again
    session.handle_sync_recon_fail(range.clone());
    assert_eq!(session.get_iblt_tier(&range), Some(Tier::Large));
}

#[test]
fn test_iblt_fallback_logic() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store = InMemoryStore::new();
    let mut session =
        SyncSession::<Handshake>::new(conversation_id, &store, false, Instant::now()).activate(0);
    let range = SyncRange {
        min_rank: 0,
        max_rank: 100,
    };

    // Promote all the way to Large
    session.handle_sync_recon_fail(range.clone()); // to Medium
    session.handle_sync_recon_fail(range.clone()); // to Large
    assert_eq!(session.get_iblt_tier(&range), Some(Tier::Large));

    // Fail one more time at Large
    session.handle_sync_recon_fail(range.clone());

    // After Large fails, the session should return None (fallback)
    assert_eq!(session.get_iblt_tier(&range), None);
}

#[test]
fn test_sharded_reconciliation() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store_a = InMemoryStore::new();
    let store_b = InMemoryStore::new();

    // Populate store_a with nodes in Shard 0 and Shard 1
    let node_s0 = MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 10,
        network_timestamp: 100,
        content: Content::Text("s0".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };
    let node_s1 = MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 1500, // Shard 1 starts at 1000
        network_timestamp: 100,
        content: Content::Text("s1".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };

    store_a
        .put_node(&conversation_id, node_s0.clone(), true)
        .unwrap();
    store_a
        .put_node(&conversation_id, node_s1.clone(), true)
        .unwrap();
    store_a
        .set_heads(&conversation_id, vec![node_s1.hash()])
        .unwrap();

    // Bob (store_b) only has node_s0
    store_b
        .put_node(&conversation_id, node_s0.clone(), true)
        .unwrap();
    store_b
        .set_heads(&conversation_id, vec![node_s0.hash()])
        .unwrap();

    let now = Instant::now();
    let session_a =
        SyncSession::<Handshake>::new(conversation_id, &store_a, false, now).activate(0);
    let mut session_b =
        SyncSession::<Handshake>::new(conversation_id, &store_b, false, now).activate(0);

    // Alice sends checksums to Bob
    let checksums_a = session_a.make_sync_shard_checksums(&store_a).unwrap();

    // Bob processes Alice's checksums
    let diff = session_b
        .handle_sync_shard_checksums(checksums_a, &store_b)
        .unwrap();

    // Bob should see that Shard 1 is different (he doesn't have it)
    assert!(diff.iter().any(|r| r.min_rank == 1000));
}

#[test]
fn test_full_reconciliation_loop() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store_a = InMemoryStore::new();
    let store_b = InMemoryStore::new();

    // Populate both with some common nodes
    for i in 0..10 {
        let node = MerkleNode {
            parents: tox_proto::BoundedVec::new(),
            author_pk: LogicalIdentityPk::from([0u8; 32]),
            sender_pk: PhysicalDevicePk::from([0u8; 32]),
            sequence_number: i as u64,
            topological_rank: i as u64,
            network_timestamp: 100,
            content: Content::Text(format!("common {}", i)),
            metadata: tox_proto::BoundedBytes::new(),
            authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
            pow_nonce: 0,
        };
        store_a
            .put_node(&conversation_id, node.clone(), true)
            .unwrap();
        store_b
            .put_node(&conversation_id, node.clone(), true)
            .unwrap();
    }

    // Alice has some unique nodes
    let mut alice_unique = Vec::new();
    for i in 10..15 {
        let node = MerkleNode {
            parents: tox_proto::BoundedVec::new(),
            author_pk: LogicalIdentityPk::from([0u8; 32]),
            sender_pk: PhysicalDevicePk::from([0u8; 32]),
            sequence_number: i as u64,
            topological_rank: i as u64,
            network_timestamp: 100,
            content: Content::Text(format!("alice {}", i)),
            metadata: tox_proto::BoundedBytes::new(),
            authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
            pow_nonce: 0,
        };
        store_a
            .put_node(&conversation_id, node.clone(), true)
            .unwrap();
        alice_unique.push(node.hash());
    }

    // Bob has some unique nodes
    let mut bob_unique = Vec::new();
    for i in 15..20 {
        let node = MerkleNode {
            parents: tox_proto::BoundedVec::new(),
            author_pk: LogicalIdentityPk::from([0u8; 32]),
            sender_pk: PhysicalDevicePk::from([0u8; 32]),
            sequence_number: i as u64,
            topological_rank: i as u64,
            network_timestamp: 100,
            content: Content::Text(format!("bob {}", i)),
            metadata: tox_proto::BoundedBytes::new(),
            authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
            pow_nonce: 0,
        };
        store_b
            .put_node(&conversation_id, node.clone(), true)
            .unwrap();
        bob_unique.push(node.hash());
    }

    let now = Instant::now();
    let mut session_a =
        SyncSession::<Handshake>::new(conversation_id, &store_a, false, now).activate(0);
    let mut session_b =
        SyncSession::<Handshake>::new(conversation_id, &store_b, false, now).activate(0);

    let range = SyncRange {
        min_rank: 0,
        max_rank: 1000,
    };

    // 1. Alice generates a sketch and sends it to Bob
    let sketch_a = session_a
        .make_sync_sketch(range.clone(), Tier::Small, &store_a)
        .unwrap();

    // 2. Bob handles Alice's sketch
    let res = session_b.handle_sync_sketch(sketch_a, &store_b).unwrap();

    if let DecodingResult::Success {
        missing_locally,
        missing_remotely,
    } = res
    {
        // Bob should see that he is missing Alice's unique nodes
        assert_eq!(missing_locally.len(), 5);
        for hash in &alice_unique {
            assert!(missing_locally.contains(hash));
        }

        // Bob should see that Alice is missing his unique nodes
        assert_eq!(missing_remotely.len(), 5);
        for hash in &bob_unique {
            assert!(missing_remotely.contains(hash));
        }

        // 3. Bob responds with his missing nodes (simulated batch response)
        for hash in missing_remotely {
            let node = store_b.get_node(&hash).unwrap();
            session_a.on_node_received(&node, &store_a, None);
            store_a.put_node(&conversation_id, node, true).unwrap();
        }
    } else {
        panic!("Decoding failed");
    }

    // 4. Alice now has Bob's nodes. Verify Alice has Bob's unique nodes.
    for hash in &bob_unique {
        assert!(store_a.has_node(hash));
    }

    // 5. Alice sends heads (including Bob's nodes) to Bob
    let heads_a = session_a.make_sync_heads(0);
    session_b.handle_sync_heads(heads_a, &store_b);

    // 6. Bob fetches missing nodes from Alice
    while let Some(batch) = session_b.next_fetch_batch(10) {
        for hash in batch.hashes {
            let node = store_a.get_node(&hash).unwrap();
            session_b.on_node_received(&node, &store_b, None);
            store_b.put_node(&conversation_id, node, true).unwrap();
        }
    }

    // Final check: both stores should have all 20 nodes
    assert_eq!(store_a.get_node_counts(&conversation_id).0, 20);
    assert_eq!(store_b.get_node_counts(&conversation_id).0, 20);
}

/// Verify that two IBLT sketches with the same key and identical contents
/// subtract to an empty difference.
#[test]
fn test_iblt_keyed_sketch_decodes() {
    let _ = tracing_subscriber::fmt::try_init();

    let key = [42u8; 32];
    let cell_count = tox_reconcile::Tier::Small.cell_count();

    let mut sketch_a = tox_reconcile::IbltSketch::new_keyed(cell_count, Some(key));
    let mut sketch_b = tox_reconcile::IbltSketch::new_keyed(cell_count, Some(key));

    // Insert the same hashes into both
    let hash1 = [1u8; 32];
    let hash2 = [2u8; 32];
    let hash3 = [3u8; 32];

    sketch_a.insert(&hash1);
    sketch_a.insert(&hash2);
    sketch_a.insert(&hash3);

    sketch_b.insert(&hash1);
    sketch_b.insert(&hash2);
    sketch_b.insert(&hash3);

    // Subtract b from a. Identical sets should decode to empty.
    sketch_a.subtract(&sketch_b).unwrap();
    let (in_a_not_b, in_b_not_a, _stats) = sketch_a.decode().unwrap();
    assert!(
        in_a_not_b.is_empty(),
        "Identical keyed sets should produce empty difference (a-b)"
    );
    assert!(
        in_b_not_a.is_empty(),
        "Identical keyed sets should produce empty difference (b-a)"
    );
}

/// Verify that subtracting a keyed sketch from an unkeyed sketch (or vice versa)
/// produces a failed or non-empty decode, since the hash positions differ.
#[test]
fn test_iblt_unkeyed_mismatch() {
    let _ = tracing_subscriber::fmt::try_init();

    let key = [42u8; 32];
    let cell_count = tox_reconcile::Tier::Small.cell_count();

    let mut sketch_keyed = tox_reconcile::IbltSketch::new_keyed(cell_count, Some(key));
    let mut sketch_unkeyed = tox_reconcile::IbltSketch::new_keyed(cell_count, None);

    // Insert the same hashes into both
    let hash1 = [1u8; 32];
    let hash2 = [2u8; 32];

    sketch_keyed.insert(&hash1);
    sketch_keyed.insert(&hash2);

    sketch_unkeyed.insert(&hash1);
    sketch_unkeyed.insert(&hash2);

    // Subtract. The different key derivation should produce garbage.
    sketch_keyed.subtract(&sketch_unkeyed).unwrap();
    let result = sketch_keyed.decode();

    // Either decode fails, or it produces non-empty (incorrect) differences.
    // The key mismatch means the XOR checksums and indices don't cancel out.
    match result {
        Err(_) => {} // Expected: decode failure
        Ok((in_a, in_b, _)) => {
            // If it somehow decodes, the sets should NOT be empty because the
            // keyed hash positions differ
            assert!(
                !in_a.is_empty() || !in_b.is_empty(),
                "Key mismatch should produce non-empty or failed decode"
            );
        }
    }
}
