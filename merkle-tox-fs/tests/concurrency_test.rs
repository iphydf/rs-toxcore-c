use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, MerkleNode, NodeAuth, NodeMac, PhysicalDevicePk,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

#[test]
fn test_fs_store_concurrent_access() {
    let tmp_dir = TempDir::new().unwrap();
    let store =
        Arc::new(FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap());
    let sync_key = ConversationId::from([1u8; 32]);

    let mut handles = vec![];
    for i in 0..10 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            let node = MerkleNode {
                parents: vec![],
                author_pk: LogicalIdentityPk::from([i as u8; 32]),
                sender_pk: PhysicalDevicePk::from([i as u8; 32]),
                sequence_number: 1,
                topological_rank: 0,
                network_timestamp: 100,
                content: Content::Text(format!("Concurrent {}", i)),
                metadata: vec![],
                authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
            };
            store.put_node(&sync_key, node, true).unwrap();
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let (verified, _) = store.get_node_counts(&sync_key);
    assert_eq!(verified, 10);
}
