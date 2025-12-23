use merkle_tox_core::dag::{NodeAuth, NodeHash, WireFlags, WireNode};
use merkle_tox_core::vfs::{FileSystem, MemFileSystem, StdFileSystem};
use merkle_tox_fs::opaque::{OPAQUE_SEGMENT_MAX_SIZE, OPAQUE_TOTAL_MAX_SIZE, OpaqueStore};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_opaque_eviction_logic() {
    let fs = Arc::new(MemFileSystem::new());
    let root = PathBuf::from("/opaque-test");
    let store = OpaqueStore::new(root.clone(), fs.clone());

    // Fill beyond 100MB
    let big_data = vec![0u8; 1024 * 1024]; // 1MB
    for i in 0..110 {
        let hash = NodeHash::from([i as u8; 32]);
        store.put_node(&hash, &big_data).unwrap();
    }

    // Verify oldest segment is gone
    let first_segment = root.join(format!("{:020}.bin", 1));
    assert!(
        !fs.exists(&first_segment),
        "Oldest segment should have been evicted"
    );

    // Calculate actual size on disk
    let mut total_size = 0;
    if let Ok(entries) = fs.read_dir(&root) {
        for path in entries {
            if path.extension().is_some_and(|ext| ext == "bin")
                && path.file_name().unwrap() != "index.bin"
            {
                total_size += fs.metadata(&path).unwrap().len;
            }
        }
    }
    assert!(
        total_size <= OPAQUE_TOTAL_MAX_SIZE,
        "Total size {} exceeded limit {}",
        total_size,
        OPAQUE_TOTAL_MAX_SIZE
    );
}

#[test]
fn test_opaque_anchor_preservation() {
    let fs = Arc::new(MemFileSystem::new());
    let root = PathBuf::from("/opaque-anchor-test");
    let store = OpaqueStore::new(root.clone(), fs.clone());

    // 1. Put an Admin node (Anchor) in the first segment
    let admin_wire = WireNode {
        parents: vec![],
        author_pk: merkle_tox_core::dag::LogicalIdentityPk::from([0u8; 32]),
        encrypted_payload: vec![0x80], // Padded empty
        topological_rank: 0,
        network_timestamp: 0,
        flags: WireFlags::NONE,
        authentication: NodeAuth::Signature(merkle_tox_core::dag::Ed25519Signature::from(
            [1u8; 64],
        )),
    };
    let admin_data = tox_proto::serialize(&admin_wire).unwrap();
    let admin_hash = NodeHash::from(*blake3::hash(&admin_data).as_bytes());
    store.put_node(&admin_hash, &admin_data).unwrap();

    // 2. Fill with junk to trigger eviction of segment 1
    let big_data = vec![0u8; 1024 * 1024];
    for i in 1..110 {
        let hash = NodeHash::from([i as u8; 32]);
        store.put_node(&hash, &big_data).unwrap();
    }

    // 3. Verify Admin node was promoted and still exists
    assert!(
        store.get_node(&admin_hash).unwrap().is_some(),
        "Admin node (Anchor) should have been preserved during eviction"
    );
}

#[test]
fn test_opaque_store_segmentation() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let store = OpaqueStore::new(tmp_dir.path().to_path_buf(), fs.clone());

    // Write enough data to force multiple segments
    // Each record is 4 bytes length + payload
    let payload = vec![0u8; (OPAQUE_SEGMENT_MAX_SIZE / 2) as usize + 1];

    let h1 = NodeHash::from([1u8; 32]);
    store.put_node(&h1, &payload).unwrap();

    let h2 = NodeHash::from([2u8; 32]);
    store.put_node(&h2, &payload).unwrap();

    let h3 = NodeHash::from([3u8; 32]);
    store.put_node(&h3, &payload).unwrap();

    // Verify segments 1 and 2 exist (since 3 payloads of > 5MB won't fit in one 10MB segment)
    assert!(tmp_dir.path().join(format!("{:020}.bin", 1)).exists());
    assert!(tmp_dir.path().join(format!("{:020}.bin", 2)).exists());

    // Verify retrieval
    let r1 = store.get_node(&h1).unwrap().unwrap();
    assert_eq!(r1.len(), payload.len());

    let r3 = store.get_node(&h3).unwrap().unwrap();
    assert_eq!(r3.len(), payload.len());
}

#[test]
fn test_opaque_index_persistence() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let root = tmp_dir.path().to_path_buf();

    let h = NodeHash::from([0xAAu8; 32]);
    {
        let store = OpaqueStore::new(root.clone(), fs.clone());
        store.put_node(&h, b"opaque-data").unwrap();
    }

    // Re-open
    let store = OpaqueStore::new(root, fs);
    let r = store.get_node(&h).unwrap().unwrap();
    assert_eq!(r, b"opaque-data");
}

#[test]
fn test_opaque_remove_node() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let store = OpaqueStore::new(tmp_dir.path().to_path_buf(), fs.clone());

    let h = NodeHash::from([1u8; 32]);
    store.put_node(&h, b"data").unwrap();
    assert!(store.get_node(&h).unwrap().is_some());

    store.remove_node(&h).unwrap();
    assert!(store.get_node(&h).unwrap().is_none());
}
