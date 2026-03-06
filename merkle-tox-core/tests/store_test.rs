use merkle_tox_core::cas::{BlobInfo, BlobStatus, CHUNK_SIZE};
use merkle_tox_core::dag::{ConversationId, NodeHash};
use merkle_tox_core::sync::BlobStore;
use merkle_tox_core::testing::InMemoryStore;

/// Regression test: get_chunk must not panic when called on a blob whose
/// BlobInfo has been registered but no chunk data has been written yet.
/// This happens in normal CAS protocol operation when a node discovers a
/// blob hash from a content node and registers the BlobInfo before any
/// chunks have been transferred.
#[test]
fn get_chunk_on_empty_blob_returns_error() {
    let store = InMemoryStore::new();
    let hash = NodeHash::from([0xAA; 32]);

    // Register blob info without writing any chunk data — simulates a
    // receiving node that just learned about a blob from a content node.
    let info = BlobInfo {
        hash,
        size: 1024 * 1024, // 1 MB
        bao_root: None,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    store.put_blob_info(info).unwrap();

    // get_chunk at a non-zero offset must return an error, not panic.
    let result = store.get_chunk(&hash, 65536, 65536);
    assert!(
        result.is_err(),
        "Expected error for chunk read on empty blob buffer"
    );
}

/// Same as above, but for offset 0 — the buffer is empty so even offset 0
/// should fail gracefully.
#[test]
fn get_chunk_at_zero_offset_on_empty_blob_returns_error() {
    let store = InMemoryStore::new();
    let hash = NodeHash::from([0xBB; 32]);

    let info = BlobInfo {
        hash,
        size: 256 * 1024, // 256 KB
        bao_root: None,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    store.put_blob_info(info).unwrap();

    // Even at offset 0, the buffer is empty — should not panic.
    let result = store.get_chunk(&hash, 0, 1024);
    assert!(
        result.is_err(),
        "Expected error for chunk read on empty blob buffer at offset 0"
    );
}

/// Regression test: when a BlobInfo is cloned from a seeder (which has a fully
/// populated received_mask), writing a single chunk must NOT mark the blob as
/// Available. This simulates the BlobAvail protocol message where the seeder's
/// BlobInfo (with all mask bits set) is cloned to the receiver.
#[test]
fn put_chunk_with_seeder_mask_does_not_mark_complete() {
    let conv_id = ConversationId::from([0x01; 32]);
    let hash = NodeHash::from([0xCC; 32]);
    let blob_size = CHUNK_SIZE * 4; // 4 chunks

    // Build a fully-set received_mask like the seeder would have.
    let num_chunks = blob_size.div_ceil(CHUNK_SIZE);
    let mask_len = (num_chunks as usize).div_ceil(8);
    let mut full_mask = vec![0xFFu8; mask_len];
    // Clear any excess high bits in the last byte (not needed for 4 chunks
    // since 4 fits in one byte, but good practice).
    let excess = (mask_len * 8) as u64 - num_chunks;
    if excess > 0 {
        full_mask[mask_len - 1] &= (1u8 << (8 - excess)) - 1;
    }

    // Register BlobInfo as the receiver would after cloning the seeder's info
    // via BlobAvail — status is Pending but received_mask is fully set.
    let info = BlobInfo {
        hash,
        size: blob_size,
        bao_root: None,
        status: BlobStatus::Pending,
        received_mask: Some(full_mask),
        decryption_key: None,
    };
    let store = InMemoryStore::new();
    store.put_blob_info(info).unwrap();

    // Write just one chunk — the blob is NOT complete.
    let chunk_data = vec![0xAB; CHUNK_SIZE as usize];
    store
        .put_chunk(&conv_id, &hash, 0, &chunk_data, None)
        .unwrap();

    // The blob must NOT be reported as available.
    assert!(
        !store.has_blob(&hash),
        "Blob should not be Available after receiving only 1 of 4 chunks"
    );
    let info = store.get_blob_info(&hash).unwrap();
    assert_ne!(
        info.status,
        BlobStatus::Available,
        "Status should not be Available with only 1 chunk written"
    );
}
