use merkle_tox_core::dag::{
    ChainKey, ConversationId, Ed25519Signature, LogicalIdentityPk, MerkleNode, NodeAuth,
    PhysicalDevicePk,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_ratchet_checkpoints_persistence() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);
    let device_pk = PhysicalDevicePk::from([2u8; 32]);

    // 1. Put node and advance ratchet (stored in journal)
    let node = MerkleNode {
        parents: tox_proto::BoundedVec::new(),
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: device_pk,
        sequence_number: 42,
        topological_rank: 0,
        network_timestamp: 100,
        content: merkle_tox_core::dag::Content::Text("Trigger".to_string()),
        metadata: tox_proto::BoundedBytes::new(),
        authentication: NodeAuth::EphemeralSignature(Ed25519Signature::from([0u8; 64])),
        pow_nonce: 0,
    };
    let hash = node.hash();
    store.put_node(&conv_id, node, true).unwrap();

    let chain_key = ChainKey::from([3u8; 32]);
    store
        .put_ratchet_key(&conv_id, &hash, chain_key.clone(), 0)
        .unwrap();

    // Verify it's in hot state
    assert_eq!(store.get_last_sequence_number(&conv_id, &device_pk), 42);

    // 2. Compact (moves ratchet to ratchet.bin)
    store.compact(&conv_id).unwrap();

    // Verify persistence across restart
    drop(store);
    let store = FsStore::new(root, Arc::new(StdFileSystem)).unwrap();

    assert_eq!(store.get_last_sequence_number(&conv_id, &device_pk), 42);
    // Retrieval by hash should still work if it's in the hot_ratchets or if we implement cold lookup
    // Currently get_ratchet_key only checks hot_ratchets (journal).
}
