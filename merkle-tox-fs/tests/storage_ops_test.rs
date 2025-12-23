use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, MerkleNode, NodeAuth, NodeMac, PhysicalDevicePk,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_fs_store_size_calculation() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);

    let node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 100,
        content: Content::Text("Size Test".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };

    store.put_node(&conv_id, node, true).unwrap();
    let size_before = store.size_bytes();
    assert!(size_before > 0);

    store.compact(&conv_id).unwrap();
    let size_after = store.size_bytes();
    assert!(size_after > 0);
}

#[test]
fn test_fs_store_compaction_ops() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([2u8; 32]);

    for i in 1..=10 {
        let node = MerkleNode {
            parents: vec![],
            author_pk: LogicalIdentityPk::from([1u8; 32]),
            sender_pk: PhysicalDevicePk::from([1u8; 32]),
            sequence_number: i,
            topological_rank: i - 1,
            network_timestamp: 100,
            content: Content::Text(format!("Node {}", i)),
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
        };
        store.put_node(&conv_id, node, true).unwrap();
    }

    store.compact(&conv_id).unwrap();

    let (verified, speculative) = store.get_node_counts(&conv_id);
    assert_eq!(verified, 10);
    assert_eq!(speculative, 0);

    // Verify persistence after compaction
    drop(store);
    let store = FsStore::new(root, Arc::new(StdFileSystem)).unwrap();
    let (verified, speculative) = store.get_node_counts(&conv_id);
    assert_eq!(verified, 10);
    assert_eq!(speculative, 0);
}
