use merkle_tox_core::dag::ConversationId;
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::vfs::{FileSystem, MemFileSystem, StdFileSystem};
use merkle_tox_fs::{FsStore, decode_hex_32, encode_hex_32};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_conversation_lock_creation() {
    let fs = Arc::new(MemFileSystem::new());
    let root = PathBuf::from("/storage");
    let store = FsStore::new(root.clone(), fs.clone()).unwrap();
    let conv_id = ConversationId::from([1u8; 32]);

    // Trigger conversation creation
    store
        .put_conversation_key(&conv_id, 0, merkle_tox_core::dag::KConv::from([0u8; 32]))
        .unwrap();

    // SPEC: Section 3.2.2 mandates /conversations/[conv_id]/.lock
    let lock_path = root
        .join("conversations")
        .join(merkle_tox_fs::encode_hex_32(conv_id.as_bytes()))
        .join(".lock");

    assert!(
        fs.exists(&lock_path),
        "Spec Section 3.2.2 mandates conversation-level advisory locks (.lock file)."
    );
}

#[test]
fn test_hex_utilities() {
    let bytes = [0xAAu8; 32];
    let hex = encode_hex_32(&bytes);
    assert_eq!(hex.len(), 64);
    assert_eq!(&hex[0..2], "aa");

    let decoded = decode_hex_32(&hex).unwrap();
    assert_eq!(decoded, bytes);

    assert!(decode_hex_32("invalid").is_none());
    assert!(decode_hex_32(&hex[0..63]).is_none());
}

#[test]
fn test_fs_store_new_with_non_directory() {
    let tmp_dir = TempDir::new().unwrap();
    let file_path = tmp_dir.path().join("not-a-dir");
    std::fs::write(&file_path, b"hello").unwrap();

    let store = FsStore::new(file_path, Arc::new(StdFileSystem));
    assert!(store.is_err());
}

#[test]
fn test_fs_store_locking() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs = Arc::new(StdFileSystem);

    let _store1 = FsStore::new(root.clone(), fs.clone()).expect("First store should open");

    // Second store with same root should SUCCEED now because we use Shared Global Lock
    let store2 = FsStore::new(root.clone(), fs.clone());
    assert!(
        store2.is_ok(),
        "Second store should be able to open with shared lock"
    );

    drop(_store1);
    drop(store2);

    // Test exclusive lock blocking
    use merkle_tox_core::vfs::FileSystem;
    let lock_file = fs.open(&root.join(".lock"), true, false, false).unwrap();
    lock_file
        .try_lock_exclusive()
        .expect("Should be able to get exclusive lock if we are the only process");

    // Now FsStore::new should fail because it tries to get try_lock_shared() which is blocked by LOCK_EX
    let store3 = FsStore::new(root.clone(), fs.clone());
    assert!(
        store3.is_err(),
        "Store should fail to open if global lock is held exclusively"
    );
}
