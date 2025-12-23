use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, MerkleNode, NodeAuth, NodeMac, PhysicalDevicePk,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_compaction_basic() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let store = FsStore::new(tmp_dir.path().to_path_buf(), fs.clone()).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);

    // 1. Put some verified nodes
    for i in 1..=5 {
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

    assert_eq!(store.get_node_counts(&conv_id), (5, 0));

    // 2. Compact
    store.compact(&conv_id).unwrap();

    // 3. Verify counts and retrievability
    assert_eq!(store.get_node_counts(&conv_id), (5, 0));

    // 4. Verify persistence and retrievability from pack
    drop(store);
    let store = FsStore::new(tmp_dir.path().to_path_buf(), fs).unwrap();
    assert_eq!(store.get_node_counts(&conv_id), (5, 0));

    for i in 1..=5 {
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
        let hash = node.hash();
        assert!(store.has_node(&hash));
        let retrieved = store.get_node(&hash).unwrap();
        assert_eq!(retrieved.sequence_number, i);
    }
}
