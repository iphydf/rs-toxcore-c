use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, MerkleNode, NodeAuth, NodeMac, PhysicalDevicePk,
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
        epoch: 0,
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
        cells: iblt_huge.into_cells(),
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
        epoch: 0,
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
        parents: vec![],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 10,
        network_timestamp: 100,
        content: Content::Text("s0".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let node_s1 = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 1500, // Shard 1 starts at 1000
        network_timestamp: 100,
        content: Content::Text("s1".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
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
            parents: vec![],
            author_pk: LogicalIdentityPk::from([0u8; 32]),
            sender_pk: PhysicalDevicePk::from([0u8; 32]),
            sequence_number: i as u64,
            topological_rank: i as u64,
            network_timestamp: 100,
            content: Content::Text(format!("common {}", i)),
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
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
            parents: vec![],
            author_pk: LogicalIdentityPk::from([0u8; 32]),
            sender_pk: PhysicalDevicePk::from([0u8; 32]),
            sequence_number: i as u64,
            topological_rank: i as u64,
            network_timestamp: 100,
            content: Content::Text(format!("alice {}", i)),
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
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
            parents: vec![],
            author_pk: LogicalIdentityPk::from([0u8; 32]),
            sender_pk: PhysicalDevicePk::from([0u8; 32]),
            sequence_number: i as u64,
            topological_rank: i as u64,
            network_timestamp: 100,
            content: Content::Text(format!("bob {}", i)),
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
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
        epoch: 0,
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
