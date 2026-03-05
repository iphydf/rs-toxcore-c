use merkle_tox_core::cas::{BlobInfo, BlobStatus};
use merkle_tox_core::dag::{ConversationId, NodeHash};
use merkle_tox_core::sync::BlobStore;
use merkle_tox_sqlite::Storage;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn test_large_blob_fs_fallback() {
    let db_dir = tempdir().unwrap();
    let blob_dir = tempdir().unwrap();
    let db_path = db_dir.path().join("test.db");

    let storage = Storage::open(&db_path)
        .unwrap()
        .with_blob_dir(blob_dir.path());

    let hash = NodeHash::from([0xAAu8; 32]);
    let size = 2 * 1024 * 1024; // 2MB, should trigger FS fallback

    let info = BlobInfo {
        hash,
        size,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };

    storage.put_blob_info(info).unwrap();

    let chunk_data = vec![0xBBu8; 64 * 1024];
    let conv_id = ConversationId::from([0u8; 32]);

    // Put first chunk
    storage
        .put_chunk(&conv_id, &hash, 0, &chunk_data, None)
        .unwrap();

    // Verify it's not in DB data column but file_path is set
    {
        let conn = storage.connection().lock().unwrap();
        let (data, file_path): (Option<Vec<u8>>, Option<String>) = conn
            .query_row(
                "SELECT data, file_path FROM cas_blobs WHERE hash = ?1",
                params![hash.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();

        assert!(data.is_none());
        assert!(file_path.is_some());
        let path = Path::new(file_path.as_ref().unwrap());
        assert!(path.exists());
    }

    // Put last chunk to make it available
    let last_offset = size - (64 * 1024);
    storage
        .put_chunk(&conv_id, &hash, last_offset, &chunk_data, None)
        .unwrap();

    // Note: for 2MB, there are 32 chunks. We only put 2.
    // In our current simple implementation, it only becomes 'Available' if ALL chunks are present.
    // Verify status is 'Downloading'.
    assert_eq!(
        storage.get_blob_info(&hash).unwrap().status,
        BlobStatus::Downloading
    );

    // Verify we can read back the chunk
    let read_data = storage.get_chunk(&hash, 0, 64 * 1024).unwrap();
    assert_eq!(read_data, chunk_data);

    let read_last = storage.get_chunk(&hash, last_offset, 64 * 1024).unwrap();
    assert_eq!(read_last, chunk_data);
}

#[test]
fn test_small_blob_db_storage() {
    let storage = Storage::open_in_memory().unwrap();

    let hash = NodeHash::from([0xBBu8; 32]);
    let size = 100;

    let info = BlobInfo {
        hash,
        size,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };

    storage.put_blob_info(info).unwrap();

    let data = vec![0xCCu8; 100];
    let conv_id = ConversationId::from([0u8; 32]);

    storage.put_chunk(&conv_id, &hash, 0, &data, None).unwrap();

    // Verify it's in DB data column
    {
        let conn = storage.connection().lock().unwrap();
        let (db_data, file_path): (Option<Vec<u8>>, Option<String>) = conn
            .query_row(
                "SELECT data, file_path FROM cas_blobs WHERE hash = ?1",
                params![hash.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();

        assert_eq!(db_data.unwrap(), data);
        assert!(file_path.is_none());
    }

    assert_eq!(
        storage.get_blob_info(&hash).unwrap().status,
        BlobStatus::Available
    );
    assert_eq!(storage.get_chunk(&hash, 0, 100).unwrap(), data);
}

use rusqlite::params;
