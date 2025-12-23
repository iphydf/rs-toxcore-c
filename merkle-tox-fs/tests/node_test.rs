use merkle_tox_core::dag::{
    Content, ConversationId, LogicalIdentityPk, MerkleNode, NodeAuth, NodeHash, NodeLookup,
    NodeMac, PhysicalDevicePk,
};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[test]
fn test_fs_store_put_get_node() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();

    let node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 12345,
        content: Content::Text("Hello FS Store".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let hash = node.hash();
    let sync_key = ConversationId::from([0u8; 32]);

    store.put_node(&sync_key, node.clone(), true).unwrap();

    assert!(store.has_node(&hash));
    let retrieved = store.get_node(&hash).expect("Node should be retrievable");
    assert_eq!(retrieved.sequence_number, 1);

    if let Content::Text(text) = retrieved.content {
        assert_eq!(text, "Hello FS Store");
    } else {
        panic!("Wrong content type");
    }
}

#[test]
fn test_fs_store_sharding_layout() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([1u8; 32]);

    let node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 100,
        content: Content::Text("test".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    store.put_node(&sync_key, node, true).unwrap();

    let conv_hex = encode_hex_32(sync_key.as_bytes());

    // In the new spec, hot nodes are in journal.bin, not sharded objects
    let journal_path = root
        .join("conversations")
        .join(conv_hex)
        .join("journal.bin");

    assert!(
        journal_path.exists(),
        "Journal path should exist: {:?}",
        journal_path
    );
}

#[test]
fn test_fs_store_persistence_restart() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let sync_key = ConversationId::from([0x55u8; 32]);
    let node_hash: NodeHash;

    {
        let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();
        let node = MerkleNode {
            parents: vec![],
            author_pk: LogicalIdentityPk::from([1u8; 32]),
            sender_pk: PhysicalDevicePk::from([1u8; 32]),
            sequence_number: 42,
            topological_rank: 0,
            network_timestamp: 100,
            content: Content::Text("Persisted Restart".to_string()),
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
        };
        node_hash = node.hash();
        store.put_node(&sync_key, node, true).unwrap();
        store.set_heads(&sync_key, vec![node_hash]).unwrap();
    }

    // Re-open store
    {
        let store = FsStore::new(root, Arc::new(StdFileSystem)).unwrap();
        // Trigger lazy load
        let _ = store.get_heads(&sync_key);

        assert!(
            store.has_node(&node_hash),
            "Node should be found after restart"
        );
        let retrieved = store.get_node(&node_hash).unwrap();
        assert_eq!(retrieved.sequence_number, 42);

        let heads = store.get_heads(&sync_key);
        assert_eq!(heads, vec![node_hash]);
    }
}

#[test]
fn test_fs_store_speculative_handling() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([1u8; 32]);

    let node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 100,
        content: Content::Text("Speculative".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let hash = node.hash();

    // 1. Put as speculative
    store.put_node(&sync_key, node, false).unwrap();

    assert!(store.has_node(&hash));
    let spec = store.get_speculative_nodes(&sync_key);
    assert_eq!(spec.len(), 1);
    assert_eq!(spec[0].hash(), hash);

    // 2. Mark as verified
    store.mark_verified(&sync_key, &hash).unwrap();

    let spec = store.get_speculative_nodes(&sync_key);
    assert!(spec.is_empty());

    // Verify it's still retrievable
    assert!(store.has_node(&hash));
}

#[test]
fn test_fs_store_conversation_discovery() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let conv1 = ConversationId::from([0xAAu8; 32]);
    let conv2 = ConversationId::from([0xBBu8; 32]);

    let hash1: NodeHash;
    let hash2: NodeHash;

    {
        let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();
        let node1 = MerkleNode {
            parents: vec![],
            author_pk: LogicalIdentityPk::from([1u8; 32]),
            sender_pk: PhysicalDevicePk::from([1u8; 32]),
            sequence_number: 1,
            topological_rank: 0,
            network_timestamp: 100,
            content: Content::Text("C1 Discovery".to_string()),
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
        };
        let node2 = MerkleNode {
            parents: vec![],
            author_pk: LogicalIdentityPk::from([2u8; 32]),
            sender_pk: PhysicalDevicePk::from([2u8; 32]),
            sequence_number: 1,
            topological_rank: 0,
            network_timestamp: 200,
            content: Content::Text("C2 Discovery".to_string()),
            metadata: vec![],
            authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
        };
        hash1 = node1.hash();
        hash2 = node2.hash();
        store.put_node(&conv1, node1, true).unwrap();
        store.put_node(&conv2, node2, true).unwrap();
    }

    // New store instance should discover both conversations
    let store = FsStore::new(root, Arc::new(StdFileSystem)).unwrap();
    // Trigger lazy load for both
    let _ = store.get_heads(&conv1);
    let _ = store.get_heads(&conv2);

    assert!(store.has_node(&hash1), "Node 1 should be discovered");
    assert!(store.has_node(&hash2), "Node 2 should be discovered");

    assert_eq!(
        store.get_node(&hash1).unwrap().author_pk,
        LogicalIdentityPk::from([1u8; 32])
    );
    assert_eq!(
        store.get_node(&hash2).unwrap().author_pk,
        LogicalIdentityPk::from([2u8; 32])
    );
}

#[test]
fn test_fs_store_node_lookup_trait() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([1u8; 32]);

    let node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 5,
        network_timestamp: 100,
        content: Content::Text("test".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let hash = node.hash();
    let node_type = node.node_type();

    store.put_node(&sync_key, node, true).unwrap();

    assert!(store.contains_node(&hash));
    assert_eq!(store.get_node_type(&hash), Some(node_type));
    assert_eq!(store.get_rank(&hash), Some(5));

    let unknown_hash = NodeHash::from([0xEEu8; 32]);
    assert!(!store.contains_node(&unknown_hash));
    assert_eq!(store.get_node_type(&unknown_hash), None);
    assert_eq!(store.get_rank(&unknown_hash), None);
}

#[test]
fn test_fs_store_corrupt_node_file() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([1u8; 32]);

    let node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 100,
        content: Content::Text("test".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let hash = node.hash();
    store.put_node(&sync_key, node, true).unwrap();

    // Corrupt the journal file
    let path = tmp_dir
        .path()
        .join("conversations")
        .join(encode_hex_32(sync_key.as_bytes()))
        .join("journal.bin");

    fs::write(path, b"not a valid journal header").unwrap();

    drop(store);

    // Re-open store to clear cache
    let store = FsStore::new(root, Arc::new(StdFileSystem)).unwrap();
    assert!(store.get_node(&hash).is_none());
}

#[test]
fn test_fs_store_corrupt_heads_file() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let sync_key = ConversationId::from([1u8; 32]);
    let conv_hex = encode_hex_32(sync_key.as_bytes());
    let state_path = root.join("conversations").join(conv_hex).join("state.bin");

    fs::create_dir_all(state_path.parent().unwrap()).unwrap();
    fs::write(&state_path, "not msgpack").unwrap();

    let store = FsStore::new(root, Arc::new(StdFileSystem)).unwrap();
    // Should not crash and heads should be empty
    assert!(store.get_heads(&sync_key).is_empty());
}

#[test]
fn test_fs_store_empty_conversation_discovery() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let conv_id = ConversationId::from([0x99u8; 32]);
    let conv_path = root
        .join("conversations")
        .join(encode_hex_32(conv_id.as_bytes()));

    fs::create_dir_all(&conv_path).unwrap();
    // No heads, no objects, no packs.

    let store = FsStore::new(root, Arc::new(StdFileSystem)).unwrap();
    assert!(store.get_heads(&conv_id).is_empty());
}

#[test]
fn test_fs_store_get_node_across_conversations() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let conv1 = ConversationId::from([1u8; 32]);
    let conv2 = ConversationId::from([2u8; 32]);

    let node1 = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 100,
        content: Content::Text("C1".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let hash1 = node1.hash();

    store.put_node(&conv1, node1, true).unwrap();

    // Query for node1 - should be found even if we don't specify the conversation
    // (since get_node doesn't take conversation_id)
    assert!(store.has_node(&hash1));
    assert!(store.get_node(&hash1).is_some());

    // Now add another node in conv2
    let node2 = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([2u8; 32]),
        sender_pk: PhysicalDevicePk::from([2u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 100,
        content: Content::Text("C2".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let hash2 = node2.hash();
    store.put_node(&conv2, node2, true).unwrap();

    assert!(store.has_node(&hash2));
    assert!(store.get_node(&hash1).is_some());
    assert!(store.get_node(&hash2).is_some());
}

#[test]
fn test_fs_store_node_lookup_packed() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([1u8; 32]);

    let node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 123,
        network_timestamp: 100,
        content: Content::Text("packed lookup".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let hash = node.hash();
    let node_type = node.node_type();

    store.put_node(&sync_key, node, true).unwrap();
    store.compact(&sync_key).unwrap();

    assert!(store.contains_node(&hash));
    assert_eq!(store.get_node_type(&hash), Some(node_type));
    assert_eq!(store.get_rank(&hash), Some(123));
}

#[test]
fn test_fs_store_mark_verified_non_existent() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([1u8; 32]);
    let hash = NodeHash::from([2u8; 32]);

    store.mark_verified(&sync_key, &hash).unwrap();
    assert!(!store.has_node(&hash));
}

#[test]
fn test_fs_store_mark_verified_idempotency() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([1u8; 32]);

    let node = MerkleNode {
        parents: vec![],
        author_pk: LogicalIdentityPk::from([1u8; 32]),
        sender_pk: PhysicalDevicePk::from([1u8; 32]),
        sequence_number: 1,
        topological_rank: 0,
        network_timestamp: 100,
        content: Content::Text("test".to_string()),
        metadata: vec![],
        authentication: NodeAuth::Mac(NodeMac::from([0u8; 32])),
    };
    let hash = node.hash();

    store.put_node(&sync_key, node, false).unwrap();

    // Mark verified twice
    store.mark_verified(&sync_key, &hash).unwrap();
    store.mark_verified(&sync_key, &hash).unwrap();

    assert!(store.has_node(&hash));
    let spec = store.get_speculative_nodes(&sync_key);
    assert!(spec.is_empty());
}
