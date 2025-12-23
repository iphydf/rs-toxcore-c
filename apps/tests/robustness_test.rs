use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, MerkleNode, NodeAuth, NodeMac, PhysicalDevicePk,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::vfs::{FaultInjectingFileSystem, FileSystem, MemFileSystem, StdFileSystem};
use merkle_tox_fs::FsStore;
use merkle_tox_sqlite::Storage as SqliteStore;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

fn create_sqlite(path: &Path) -> SqliteStore {
    SqliteStore::open(path.join("test.db")).unwrap()
}

fn create_fs(path: &Path) -> FsStore {
    FsStore::new(path.join("fs_root"), Arc::new(StdFileSystem)).unwrap()
}

fn make_node(i: usize) -> MerkleNode {
    MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([i as u8; 32]),
        sender_pk: PhysicalDevicePk::from([i as u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 1000,
        content: Content::Text(format!("Node {}", i)),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    }
}

#[test]
fn test_robustness_concurrency_sqlite() {
    let tmp = TempDir::new().unwrap();
    let store = Arc::new(create_sqlite(tmp.path()));
    let conv_id = ConversationId::from([1u8; 32]);

    let mut handles = vec![];
    for i in 0..20 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            let node = make_node(i);
            store.put_node(&conv_id, node, true).unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let (verified, _) = store.get_node_counts(&conv_id);
    assert_eq!(verified, 20);
}

#[test]
fn test_robustness_concurrency_fs() {
    let tmp = TempDir::new().unwrap();
    let store = Arc::new(create_fs(tmp.path()));
    let conv_id = ConversationId::from([2u8; 32]);

    let mut handles = vec![];
    for i in 0..20 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            let node = make_node(i);
            store.put_node(&conv_id, node, true).unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let (verified, _) = store.get_node_counts(&conv_id);
    assert_eq!(verified, 20);
}

#[test]
fn test_robustness_enospc_fs() {
    let mem_vfs = Arc::new(MemFileSystem::new());
    let fault_vfs = Arc::new(FaultInjectingFileSystem::new(mem_vfs.clone()));

    let root = std::path::PathBuf::from("/fs_root");
    let store = FsStore::new(root, fault_vfs.clone()).unwrap();
    let conv_id = ConversationId::from([3u8; 32]);

    // Set limit such that it fails after some writes
    fault_vfs.set_enospc_at(1024); // Very small limit

    let mut failed = false;
    for i in 0..100 {
        let node = make_node(i);
        if store.put_node(&conv_id, node, true).is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed, "Should have failed with ENOSPC");

    // Verify consistency: we should still be able to read what was written
    let (verified, _) = store.get_node_counts(&conv_id);
    assert!(verified > 0);
    assert!(verified < 100);
}

#[test]
fn test_robustness_corruption_detection_fs() {
    let tmp = TempDir::new().unwrap();
    let vfs = Arc::new(StdFileSystem);
    let root = tmp.path().join("fs_root");
    let store = FsStore::new(root.clone(), vfs.clone()).unwrap();
    let conv_id = ConversationId::from([4u8; 32]);

    let node = make_node(42);
    let hash = node.hash();
    store.put_node(&conv_id, node, true).unwrap();

    // Manually corrupt the journal file
    let conv_id_str = hex::encode(conv_id.as_bytes());
    let journal_path = root
        .join("conversations")
        .join(conv_id_str)
        .join("journal.bin");

    let mut data = std::fs::read(&journal_path).expect("Journal file should exist");
    // Offset 60 should be well within the first node's payload
    // (16 byte journal header + 4 byte len + 32 byte hash + 1 byte type = 53 bytes)
    if data.len() > 60 {
        data[60] ^= 0xFF; // Flip some bits in the record payload
    } else {
        panic!("Journal file too small: {}", data.len());
    }
    std::fs::write(&journal_path, data).unwrap();

    // Now try to read it
    let retrieved = store.get_node(&hash);
    assert!(
        retrieved.is_none(),
        "Corrupted node should fail to deserialize and return None"
    );
}

#[test]
fn test_robustness_atomicity_fs() {
    let mem_vfs = Arc::new(MemFileSystem::new());
    let fault_vfs = Arc::new(FaultInjectingFileSystem::new(mem_vfs.clone()));
    let root = std::path::PathBuf::from("/fs_root");
    let conv_id = ConversationId::from([5u8; 32]);

    // 1. Write one node successfully
    {
        let store = FsStore::new(root.clone(), fault_vfs.clone()).unwrap();
        store.put_node(&conv_id, make_node(0), true).unwrap();
    }

    // 2. Try to write another node but fail halfway
    // We set enospc to fail exactly during the second node write
    fault_vfs.set_enospc_at(
        fault_vfs
            .metadata(
                &root
                    .join("conversations")
                    .join(hex::encode(conv_id.as_bytes()))
                    .join("journal.bin"),
            )
            .unwrap()
            .len
            + 10,
    );

    {
        let store = FsStore::new(root.clone(), fault_vfs.clone()).unwrap();
        let _ = store.put_node(&conv_id, make_node(1), true);
    }

    // 3. Disable failures and check consistency
    fault_vfs.set_enospc_at(u64::MAX);
    let store = FsStore::new(root.clone(), fault_vfs.clone()).unwrap();
    let (verified, _) = store.get_node_counts(&conv_id);
    assert_eq!(
        verified, 1,
        "Should only have the first node, partial write should be ignored/truncated"
    );
}
