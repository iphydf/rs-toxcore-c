use merkle_tox_core::dag::{
    Content, ControlAction, ConversationId, Ed25519Signature, LogicalIdentityPk, MerkleNode,
    NodeAuth, NodeHash, NodeMac, PhysicalDevicePk,
};
use merkle_tox_core::engine::session::{Handshake, SyncSession};
use merkle_tox_core::sync::{BlobStore, NodeStore, SyncHeads};
use merkle_tox_core::testing::{InMemoryStore, create_available_blob_info};
use std::time::Instant;

#[test]
fn test_blob_discovery() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store = InMemoryStore::new();

    let mut session =
        SyncSession::<Handshake>::new(conversation_id, &store, false, Instant::now()).activate(0);

    let blob_hash = NodeHash::from([0xAAu8; 32]);
    let node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 100,
        content: Content::Blob {
            hash: blob_hash,
            name: "test.png".to_string(),
            mime_type: "image/png".to_string(),
            size: 1024,
            metadata: vec![],
        },
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };

    session.on_node_received(&node, &store, Some(&store));

    assert!(session.common.missing_blobs.contains(&blob_hash));

    // Now mark it as present and receive again
    let blob_info = create_available_blob_info(blob_hash, 1024);
    store.put_blob_info(blob_info).unwrap();

    session.common.missing_blobs.clear();
    session.on_node_received(&node, &store, Some(&store));
    assert!(!session.common.missing_blobs.contains(&blob_hash));
}

#[test]
fn test_sync_reconciliation() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store = InMemoryStore::new();
    let node = merkle_tox_core::testing::create_dummy_node(vec![]);
    let head_hash = node.hash();
    store.put_node(&conversation_id, node, true).unwrap();
    store.set_heads(&conversation_id, vec![head_hash]).unwrap();

    let mut session =
        SyncSession::<Handshake>::new(conversation_id, &store, false, Instant::now()).activate(0);

    let remote_heads = SyncHeads {
        conversation_id,
        heads: vec![NodeHash::from([3u8; 32]), NodeHash::from([4u8; 32])],
        flags: 0,
    };

    session.handle_sync_heads(remote_heads, &store);

    assert_eq!(session.common.remote_heads.len(), 2);
    assert_eq!(session.common.missing_nodes.len(), 2);

    let batch = session.next_fetch_batch(1).unwrap();
    assert_eq!(batch.hashes.len(), 1);
    assert_eq!(session.common.in_flight_fetches.len(), 1);
    assert_eq!(session.common.missing_nodes.len(), 1);
}

#[test]
fn test_shallow_sync_snapshot_stop() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store = InMemoryStore::new();

    // Create a shallow session
    let mut session =
        SyncSession::<Handshake>::new(conversation_id, &store, true, Instant::now()).activate(0);

    // Receive a Snapshot node
    let snapshot = MerkleNode {
        parents: vec![NodeHash::from([0xBBu8; 32])], // This parent is far in history
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 100,
        topological_rank: 100,
        network_timestamp: 1000,
        content: Content::Control(ControlAction::Snapshot {
            basis_hash: NodeHash::from([0xBBu8; 32]),
            members: vec![],
            last_seq_numbers: vec![],
        }),
        metadata: vec![],
        authentication: NodeAuth::Signature(Ed25519Signature::from([0u8; 64])),
    };

    session.on_node_received(&snapshot, &store, None);

    // In shallow mode, we should NOT have added [0xBB; 32] to missing_nodes.
    assert!(
        session.common.missing_nodes.is_empty(),
        "Shallow sync should stop at snapshot"
    );

    // Now create a deep session
    let mut deep_session =
        SyncSession::<Handshake>::new(conversation_id, &store, false, Instant::now()).activate(0);
    deep_session.on_node_received(&snapshot, &store, None);

    // In deep mode, we SHOULD have added [0xBB; 32] to missing_nodes.
    assert!(
        !deep_session.common.missing_nodes.is_empty(),
        "Deep sync should backfill from snapshot"
    );
}

#[test]
fn test_shallow_sync_limits() {
    let conversation_id = ConversationId::from([1u8; 32]);
    let store = InMemoryStore::new();

    // 1. Limit by Rank
    let mut session = SyncSession::<Handshake>::new(conversation_id, &store, true, Instant::now())
        .with_limits(10, 0)
        .activate(0);

    let node_rank_11 = MerkleNode {
        parents: vec![NodeHash::from([0x11u8; 32])],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 11,
        topological_rank: 11,
        network_timestamp: 1100,
        content: Content::Text("hello".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };

    session.on_node_received(&node_rank_11, &store, None);
    // Should NOT stop yet, rank is 11 > 10.
    assert_eq!(session.common.missing_nodes.len(), 1);
    session.common.missing_nodes.clear();

    let node_rank_10 = MerkleNode {
        parents: vec![NodeHash::from([0x10u8; 32])],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 10,
        topological_rank: 10,
        network_timestamp: 1000,
        content: Content::Text("hello".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };

    session.on_node_received(&node_rank_10, &store, None);
    // SHOULD stop, rank is 10 <= 10.
    assert!(
        session.common.missing_nodes.is_empty(),
        "Should stop at rank 10"
    );

    // 2. Limit by Timestamp
    let mut session_time =
        SyncSession::<Handshake>::new(conversation_id, &store, true, Instant::now())
            .with_limits(0, 500)
            .activate(0);

    let node_time_400 = MerkleNode {
        parents: vec![NodeHash::from([0x44u8; 32])],
        author_pk: LogicalIdentityPk::from([0u8; 32]),
        sender_pk: PhysicalDevicePk::from([0u8; 32]),
        sequence_number: 5,
        topological_rank: 5,
        network_timestamp: 400,
        content: Content::Text("hello".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };

    session_time.on_node_received(&node_time_400, &store, None);
    assert!(
        session_time.common.missing_nodes.is_empty(),
        "Should stop at timestamp 400 <= 500"
    );
}

#[test]
fn test_sync_session_iblt() {
    use merkle_tox_core::sync::{SyncRange, Tier};
    let conversation_id = ConversationId::from([1u8; 32]);
    let store = InMemoryStore::new();

    let mut session =
        SyncSession::<Handshake>::new(conversation_id, &store, false, Instant::now()).activate(0);

    // Peer has two nodes we don't have
    let node1_hash = NodeHash::from([0x11u8; 32]);
    let node2_hash = NodeHash::from([0x22u8; 32]);

    let range = SyncRange {
        epoch: 0,
        min_rank: 0,
        max_rank: 100,
    };

    // Create a sketch as if we were the peer who has these nodes
    let _peer_session =
        SyncSession::<Handshake>::new(conversation_id, &store, false, Instant::now()).activate(0);

    // We need to manually populate a sketch
    let mut iblt = tox_reconcile::IbltSketch::new(Tier::Tiny.cell_count());
    iblt.insert(node1_hash.as_ref());
    iblt.insert(node2_hash.as_ref());

    let sketch = tox_reconcile::SyncSketch {
        conversation_id,
        cells: iblt.into_cells(),
        range,
    };

    // Handle the sketch
    session.handle_sync_sketch(sketch, &store).unwrap();

    // Session should now have node1 and node2 in missing_nodes
    assert_eq!(session.common.missing_nodes.len(), 2);
    assert!(session.common.missing_nodes.contains(&node1_hash));
    assert!(session.common.missing_nodes.contains(&node2_hash));
}
