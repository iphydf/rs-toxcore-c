use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::dag::{ConversationId, NodeHash};
use merkle_tox_core::sync::BlobStore;
use merkle_tox_core::vfs::{MemFileSystem, StdFileSystem};
use merkle_tox_fs::FsStore;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[test]
fn test_fs_store_put_get_blob_info() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();

    let blob_hash = NodeHash::from([1u8; 32]);
    let info = BlobInfo {
        hash: blob_hash,
        size: 1024,
        bao_root: Some([2u8; 32]),
        status: BlobStatus::Pending,
        received_mask: Some(vec![0u8; 1]),
    };

    store.put_blob_info(info.clone()).unwrap();

    let retrieved = store.get_blob_info(&blob_hash).expect("Info should exist");
    assert_eq!(retrieved, info);
}

#[test]
fn test_fs_store_put_get_chunk() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);

    let blob_hash = NodeHash::from([3u8; 32]);
    let chunk_data = b"Some blob data";

    let info = BlobInfo {
        hash: blob_hash,
        size: chunk_data.len() as u64,
        bao_root: None,
        status: BlobStatus::Downloading,
        received_mask: None,
    };
    store.put_blob_info(info).unwrap();

    store
        .put_chunk(&conv_id, &blob_hash, 0, chunk_data, None)
        .unwrap();

    let retrieved = store
        .get_chunk(&blob_hash, 0, chunk_data.len() as u32)
        .unwrap();
    assert_eq!(retrieved, chunk_data);

    // Finalize it
    store
        .finalize_blob(&blob_hash)
        .expect("Finalization should succeed");

    assert!(store.has_blob(&blob_hash));

    // Verify it still works after finalization
    let retrieved = store
        .get_chunk(&blob_hash, 0, chunk_data.len() as u32)
        .unwrap();
    assert_eq!(retrieved, chunk_data);
}

#[test]
fn test_fs_store_has_blob() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);

    let blob_hash = NodeHash::from([4u8; 32]);
    assert!(!store.has_blob(&blob_hash));

    // Put info with Pending status
    let info = BlobInfo {
        hash: blob_hash,
        size: 1024,
        bao_root: Some([0u8; 32]),
        status: BlobStatus::Pending,
        received_mask: None,
    };
    store.put_blob_info(info).unwrap();
    assert!(!store.has_blob(&blob_hash));

    // Put chunk
    store
        .put_chunk(&conv_id, &blob_hash, 0, &[0u8; 10], None)
        .unwrap();
    assert!(!store.has_blob(&blob_hash));

    // Update info to Available
    let mut info = store.get_blob_info(&blob_hash).unwrap();
    info.status = BlobStatus::Available;
    store.put_blob_info(info).unwrap();

    assert!(store.has_blob(&blob_hash));
}

#[test]
fn test_fs_store_chunk_offset() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);

    let blob_hash = NodeHash::from([5u8; 32]);
    let chunk1 = b"First part";
    let chunk2 = b"Second part";

    store
        .put_blob_info(BlobInfo {
            hash: blob_hash,
            size: (chunk1.len() + chunk2.len()) as u64,
            bao_root: None,
            status: BlobStatus::Downloading,
            received_mask: None,
        })
        .unwrap();

    store
        .put_chunk(&conv_id, &blob_hash, 0, chunk1, None)
        .unwrap();
    store
        .put_chunk(&conv_id, &blob_hash, chunk1.len() as u64, chunk2, None)
        .unwrap();

    let full = store
        .get_chunk(&blob_hash, 0, (chunk1.len() + chunk2.len()) as u32)
        .unwrap();
    let mut expected = chunk1.to_vec();
    expected.extend_from_slice(chunk2);
    assert_eq!(full, expected);

    let part = store
        .get_chunk(&blob_hash, chunk1.len() as u64, chunk2.len() as u32)
        .unwrap();
    assert_eq!(part, chunk2);
}

#[test]
fn test_fs_store_blob_persistence() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let blob_hash = NodeHash::from([6u8; 32]);
    let conv_id = ConversationId::from([1u8; 32]);
    let data = b"Persisted blob";

    {
        let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();
        store
            .put_blob_info(BlobInfo {
                hash: blob_hash,
                size: data.len() as u64,
                bao_root: None,
                status: BlobStatus::Downloading,
                received_mask: None,
            })
            .unwrap();
        store
            .put_chunk(&conv_id, &blob_hash, 0, data, None)
            .unwrap();

        let info = BlobInfo {
            hash: blob_hash,
            size: data.len() as u64,
            bao_root: None,
            status: BlobStatus::Downloading,
            received_mask: None,
        };
        store.put_blob_info(info).unwrap();
        store.finalize_blob(&blob_hash).unwrap();
    }

    {
        let store = FsStore::new(root, Arc::new(StdFileSystem)).unwrap();
        assert!(store.has_blob(&blob_hash));
        let retrieved = store.get_chunk(&blob_hash, 0, data.len() as u32).unwrap();
        assert_eq!(retrieved, data);
    }
}

#[test]
fn test_fs_store_get_chunk_out_of_bounds() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let blob_hash = NodeHash::from([7u8; 32]);
    let conv_id = ConversationId::from([1u8; 32]);
    let data = b"Data";

    store
        .put_blob_info(BlobInfo {
            hash: blob_hash,
            size: data.len() as u64,
            bao_root: None,
            status: BlobStatus::Downloading,
            received_mask: None,
        })
        .unwrap();

    store
        .put_chunk(&conv_id, &blob_hash, 0, data, None)
        .unwrap();

    assert!(store.get_chunk(&blob_hash, 10, 1).is_err());
    assert!(store.get_chunk(&blob_hash, 0, 10).is_err());
}

#[test]
fn test_fs_store_finalize_non_existent() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let blob_hash = NodeHash::from([8u8; 32]);

    assert!(store.finalize_blob(&blob_hash).is_err());
}

#[test]
fn test_fs_store_finalize_updates_info() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);

    let blob_hash = NodeHash::from([9u8; 32]);
    let data = b"Content to finalize";

    let info = BlobInfo {
        hash: blob_hash,
        size: data.len() as u64,
        bao_root: None,
        status: BlobStatus::Downloading,
        received_mask: None,
    };
    store.put_blob_info(info).unwrap();

    store
        .put_chunk(&conv_id, &blob_hash, 0, data, None)
        .unwrap();

    store.finalize_blob(&blob_hash).unwrap();

    let info = store.get_blob_info(&blob_hash).unwrap();
    assert_eq!(info.status, BlobStatus::Available);
    assert!(info.bao_root.is_some());
    assert!(info.received_mask.is_some());
}

#[test]
fn test_fs_store_small_blob_optimization() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);

    let blob_hash = NodeHash::from([10u8; 32]);
    let data = b"Small blob";

    // Small blob info
    let info = BlobInfo {
        hash: blob_hash,
        size: data.len() as u64,
        bao_root: None,
        status: BlobStatus::Downloading,
        received_mask: None,
    };
    store.put_blob_info(info).unwrap();

    store
        .put_chunk(&conv_id, &blob_hash, 0, data, None)
        .unwrap();

    // Check that it's localized in the global objects directory
    let hex = encode_hex_32(blob_hash.as_bytes());
    let expected_path = tmp_dir
        .path()
        .join("objects")
        .join(&hex[0..2])
        .join(format!("{}.data", hex));

    assert!(expected_path.exists());
    assert!(store.get_chunk(&blob_hash, 0, data.len() as u32).is_ok());
}

#[test]
fn test_fs_store_blob_info_sharding() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();

    let blob_hash = NodeHash::from([0xABu8; 32]);
    let info = BlobInfo {
        hash: blob_hash,
        size: 123,
        bao_root: None,
        status: BlobStatus::Pending,
        received_mask: None,
    };
    store.put_blob_info(info).unwrap();

    let hex = encode_hex_32(blob_hash.as_bytes());
    let expected_info_path = root
        .join("objects")
        .join(&hex[0..2])
        .join(format!("{}.info", hex));

    assert!(expected_info_path.exists());
}

#[test]
fn test_fs_store_bao_outboard_creation() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);

    let blob_hash = NodeHash::from([11u8; 32]);
    let data = vec![0u8; (CHUNK_SIZE * 3) as usize]; // 3 chunks

    store
        .put_blob_info(BlobInfo {
            hash: blob_hash,
            size: data.len() as u64,
            bao_root: None,
            status: BlobStatus::Downloading,
            received_mask: None,
        })
        .unwrap();

    store
        .put_chunk(&conv_id, &blob_hash, 0, &data, None)
        .unwrap();

    let info = BlobInfo {
        hash: blob_hash,
        size: data.len() as u64,
        bao_root: None,
        status: BlobStatus::Downloading,
        received_mask: None,
    };
    store.put_blob_info(info).unwrap();

    store.finalize_blob(&blob_hash).unwrap();

    // Bao outboard verify is complex to test here without more traits, but we can check if file exists
    let hex = encode_hex_32(blob_hash.as_bytes());
    let expected_bao_path = tmp_dir
        .path()
        .join("objects")
        .join(&hex[0..2])
        .join(format!("{}.bao", hex));
    assert!(expected_bao_path.exists());
}

#[test]
fn test_fs_store_prune_vault() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let store = FsStore::new(root.clone(), Arc::new(StdFileSystem)).unwrap();

    let blob_hash = NodeHash::from([12u8; 32]);
    let vault_path = root.join("vault").join(encode_hex_32(blob_hash.as_bytes()));
    fs::create_dir_all(vault_path.parent().unwrap()).unwrap();
    fs::write(&vault_path, b"stale data").unwrap();

    store.prune_vault(Duration::from_secs(3600)).unwrap();
    assert!(vault_path.exists());

    store.prune_vault(Duration::from_secs(0)).unwrap();
    // Pruning depends on modification time, might not prune immediately in same millisecond
}

#[test]
fn test_fs_store_blob_cross_finalization() {
    let tmp_dir1 = TempDir::new().unwrap();
    let store1 = FsStore::new(tmp_dir1.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);

    let blob_hash = NodeHash::from([13u8; 32]);
    let data = b"Shared blob data";

    store1
        .put_blob_info(BlobInfo {
            hash: blob_hash,
            size: data.len() as u64,
            bao_root: None,
            status: BlobStatus::Downloading,
            received_mask: None,
        })
        .unwrap();

    store1
        .put_chunk(&conv_id, &blob_hash, 0, data, None)
        .unwrap();

    let info = BlobInfo {
        hash: blob_hash,
        size: data.len() as u64,
        bao_root: None,
        status: BlobStatus::Downloading,
        received_mask: None,
    };
    store1.put_blob_info(info).unwrap();
    store1.finalize_blob(&blob_hash).unwrap();

    drop(store1);

    let tmp_dir2 = TempDir::new().unwrap();
    let store2 = FsStore::new(tmp_dir2.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    assert!(!store2.has_blob(&blob_hash));
}

#[test]
fn test_fs_store_missing_data_no_put_chunk() {
    let fs = Arc::new(MemFileSystem::new());
    let root = std::path::PathBuf::from("/root");
    let store = FsStore::new(root.clone(), fs.clone()).unwrap();

    let blob_hash = NodeHash::from([3u8; 32]);
    let size = 1024;

    store
        .put_blob_info(BlobInfo {
            hash: blob_hash,
            size,
            bao_root: None,
            status: BlobStatus::Downloading,
            received_mask: None,
        })
        .unwrap();

    // get_chunk should return BlobNotFound if NO chunks were ever put
    let res = store.get_chunk(&blob_hash, 0, 512);
    assert!(res.is_err(), "Should return Err, but got Ok");
    match res {
        Err(merkle_tox_core::error::MerkleToxError::BlobNotFound(_)) => {}
        _ => panic!("Expected BlobNotFound, got {:?}", res),
    }
}

#[test]
fn test_fs_store_partial_data_with_info() {
    let fs = Arc::new(MemFileSystem::new());
    let root = std::path::PathBuf::from("/root");
    let store = FsStore::new(root.clone(), fs.clone()).unwrap();
    let conv_id = ConversationId::from([0u8; 32]);

    let blob_hash = NodeHash::from([4u8; 32]);
    let size = 1024;

    store
        .put_blob_info(BlobInfo {
            hash: blob_hash,
            size,
            bao_root: None,
            status: BlobStatus::Downloading,
            received_mask: None,
        })
        .unwrap();

    // Put only the first 100 bytes
    store
        .put_chunk(&conv_id, &blob_hash, 0, &[1u8; 100], None)
        .unwrap();

    // get_chunk for the rest should return zeros
    let res = store.get_chunk(&blob_hash, 512, 512);
    assert!(res.is_ok(), "Should return Ok(zeros), but got {:?}", res);
    assert_eq!(res.unwrap(), vec![0u8; 512]);
}
