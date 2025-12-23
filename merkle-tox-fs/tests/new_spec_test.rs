use merkle_tox_core::dag::{
    Content, ConversationId, KConv, LogicalIdentityPk, MerkleNode, NodeAuth, NodeMac,
    PhysicalDevicePk,
};
use merkle_tox_core::sync::{NodeStore, ReconciliationStore, SyncRange};
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_payload_length_in_index() {
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
        content: Content::Text("Testing payload length".to_string()),
        metadata: vec![0u8; 128], // Add some metadata to ensure non-trivial length
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let hash = node.hash();

    // Put node (stored in journal initially)
    store.put_node(&conv_id, node.clone(), true).unwrap();

    // Compact (moves to pack, populates payload_length)
    store.compact(&conv_id).unwrap();

    // Verify it's retrievable from pack using the index (which now uses payload_length)
    let retrieved = store.get_node(&hash).expect("Node should be in pack");
    assert_eq!(retrieved.hash(), hash);
    if let Content::Text(t) = retrieved.content {
        assert_eq!(t, "Testing payload length");
    } else {
        panic!("Wrong content");
    }
}

#[test]
fn test_conversation_keys_persistence() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([2u8; 32]);

    let k1 = KConv::from([10u8; 32]);
    let k2 = KConv::from([20u8; 32]);

    store.put_conversation_key(&conv_id, 1, k1.clone()).unwrap();
    store.put_conversation_key(&conv_id, 2, k2.clone()).unwrap();

    // Verify immediate retrieval
    let keys = store.get_conversation_keys(&conv_id).unwrap();
    assert_eq!(keys, vec![(1, k1.clone()), (2, k2.clone())]);

    // Verify persistence across restart
    drop(store);
    let store = FsStore::new(root, Arc::new(StdFileSystem)).unwrap();
    let keys = store.get_conversation_keys(&conv_id).unwrap();
    assert_eq!(keys, vec![(1, k1), (2, k2)]);
}

#[test]
fn test_reconciliation_sketches_persistence() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([3u8; 32]);

    let range = SyncRange {
        epoch: 0,
        min_rank: 100,
        max_rank: 200,
    };
    let sketch = b"serialized-iblt-data";

    store.put_sketch(&conv_id, &range, sketch).unwrap();

    // Verify immediate retrieval
    let retrieved = store.get_sketch(&conv_id, &range).unwrap().unwrap();
    assert_eq!(retrieved, sketch);

    // Verify persistence across restart
    drop(store);
    let store = FsStore::new(root, Arc::new(StdFileSystem)).unwrap();
    let retrieved = store.get_sketch(&conv_id, &range).unwrap().unwrap();
    assert_eq!(retrieved, sketch);
}
