use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, MerkleNode, NodeAuth, NodeHash, NodeMac, NodeType,
    PhysicalDevicePk,
};
use merkle_tox_core::sync::{NodeStore, SyncRange};
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_fs_store_get_verified_nodes_by_type() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([1u8; 32]);

    let admin_node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 100,
        content: Content::Control(merkle_tox_core::dag::ControlAction::SetTitle(
            "Admin".to_string(),
        )),
        metadata: vec![],
        authentication: NodeAuth::Signature(merkle_tox_core::dag::Ed25519Signature::from(
            [0u8; 64],
        )),
    };

    let content_node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 2,
        topological_rank: 1,
        network_timestamp: 101,
        content: Content::Text("Content".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };

    store.put_node(&sync_key, admin_node, true).unwrap();
    store.put_node(&sync_key, content_node, true).unwrap();

    let admin_nodes = store
        .get_verified_nodes_by_type(&sync_key, NodeType::Admin)
        .unwrap();
    assert_eq!(admin_nodes.len(), 1);
    assert!(matches!(admin_nodes[0].content, Content::Control(_)));

    let content_nodes = store
        .get_verified_nodes_by_type(&sync_key, NodeType::Content)
        .unwrap();
    assert_eq!(content_nodes.len(), 1);
    assert!(matches!(content_nodes[0].content, Content::Text(_)));
}

#[test]
fn test_fs_store_get_node_hashes_in_range() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([2u8; 32]);

    let mut hashes = Vec::new();
    for i in 0..10 {
        let node = MerkleNode {
            parents: vec![],
            author_pk: LogicalIdentityPk::from([1u8; 32]),
            sender_pk: PhysicalDevicePk::from([1u8; 32]),
            sequence_number: i + 1,
            topological_rank: i,
            network_timestamp: 100 + i as i64,
            content: Content::Text(format!("Node {}", i)),
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
        };
        hashes.push(node.hash());
        store.put_node(&sync_key, node, true).unwrap();
    }

    let range = SyncRange {
        epoch: 0,
        min_rank: 3,
        max_rank: 7,
    };

    let result = store.get_node_hashes_in_range(&sync_key, &range).unwrap();
    assert_eq!(result.len(), 5);
    for h in &hashes[3..8] {
        assert!(result.contains(h));
    }
}

#[test]
fn test_fs_store_get_opaque_node_hashes() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([3u8; 32]);

    let wire_node = merkle_tox_core::dag::WireNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        encrypted_payload: vec![0u8; 32],
        topological_rank: 0,
        network_timestamp: 100,
        flags: merkle_tox_core::dag::WireFlags::NONE,
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let hash = NodeHash::from([0xDDu8; 32]);

    store.put_wire_node(&sync_key, &hash, wire_node).unwrap();

    let opaque = store.get_opaque_node_hashes(&sync_key).unwrap();
    assert_eq!(opaque.len(), 1);
    assert_eq!(opaque[0], hash);
}

#[test]
fn test_fs_store_node_counts() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([4u8; 32]);

    let n1 = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 100,
        content: Content::Text("V1".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let n2 = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 2,
        topological_rank: 1,
        network_timestamp: 101,
        content: Content::Text("S1".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };

    store.put_node(&sync_key, n1, true).unwrap();
    store.put_node(&sync_key, n2, false).unwrap();

    let (verified, speculative) = store.get_node_counts(&sync_key);
    assert_eq!(verified, 1);
    assert_eq!(speculative, 1);
}
