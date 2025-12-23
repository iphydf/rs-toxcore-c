use merkle_tox_core::dag::{ChainKey, ConversationId, KConv, NodeHash};
use merkle_tox_core::sync::NodeStore;
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_fs_store_conversation_keys() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([1u8; 32]);

    let k1 = KConv::from([10u8; 32]);
    let k2 = KConv::from([20u8; 32]);

    store
        .put_conversation_key(&sync_key, 1, k1.clone())
        .unwrap();
    store
        .put_conversation_key(&sync_key, 2, k2.clone())
        .unwrap();

    let keys = store.get_conversation_keys(&sync_key).unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], (1, k1));
    assert_eq!(keys[1], (2, k2));
}

#[test]
fn test_fs_store_epoch_metadata() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([2u8; 32]);

    assert!(store.get_epoch_metadata(&sync_key).unwrap().is_none());

    store
        .update_epoch_metadata(&sync_key, 100, 123456789)
        .unwrap();
    let meta = store.get_epoch_metadata(&sync_key).unwrap().unwrap();
    assert_eq!(meta, (100, 123456789));

    store
        .update_epoch_metadata(&sync_key, 101, 123456790)
        .unwrap();
    let meta = store.get_epoch_metadata(&sync_key).unwrap().unwrap();
    assert_eq!(meta, (101, 123456790));
}

#[test]
fn test_fs_store_ratchet_keys() {
    let tmp_dir = TempDir::new().unwrap();
    let store = FsStore::new(tmp_dir.path().to_path_buf(), Arc::new(StdFileSystem)).unwrap();
    let sync_key = ConversationId::from([3u8; 32]);

    let node_hash = NodeHash::from([0xAAu8; 32]);
    let chain_key = ChainKey::from([0xCCu8; 32]);

    assert!(
        store
            .get_ratchet_key(&sync_key, &node_hash)
            .unwrap()
            .is_none()
    );

    store
        .put_ratchet_key(&sync_key, &node_hash, chain_key.clone())
        .unwrap();
    let retrieved = store
        .get_ratchet_key(&sync_key, &node_hash)
        .unwrap()
        .unwrap();
    assert_eq!(retrieved, chain_key);

    store.remove_ratchet_key(&sync_key, &node_hash).unwrap();
    assert!(
        store
            .get_ratchet_key(&sync_key, &node_hash)
            .unwrap()
            .is_none()
    );
}
