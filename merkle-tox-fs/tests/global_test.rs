use merkle_tox_core::sync::GlobalStore;
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::FsStore;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_global_offset_persistence() {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs = Arc::new(StdFileSystem);

    {
        let store = FsStore::new(root.clone(), fs.clone()).unwrap();
        assert_eq!(store.get_global_offset(), None);

        store.set_global_offset(123456789).unwrap();
        assert_eq!(store.get_global_offset(), Some(123456789));
    }

    // Re-open
    {
        let store = FsStore::new(root, fs).unwrap();
        assert_eq!(store.get_global_offset(), Some(123456789));
    }
}
