//! Conversation-lock spec-conformance regression tests.
//!
//! Per `doc/merkle-tox-storage-format.md` §3.2.2, every conversation-level
//! write operation MUST acquire `LOCK_EX` on `/conversations/[conv_id]/.lock`
//! for the duration of the write. Until this regression suite landed, only
//! `put_node` and `compact` upgraded to `LOCK_EX`; the other six conversation
//! write paths (`put_conversation_key`, `update_epoch_metadata`,
//! `put_ratchet_key`, `put_wire_node`, `remove_wire_node`, `put_sketch`)
//! wrote without coordination, allowing two processes that both held
//! `LOCK_SH` to race on `state.bin`, the journal append cursor, and the
//! `keys/{epoch}.key` files.
//!
//! Each test below holds an external `LOCK_SH` on the conversation lock
//! file (simulating a second process that has the store open) and asserts
//! that the corresponding write call fails because it cannot upgrade to
//! `LOCK_EX`. Without these tests, a future refactor that drops the
//! upgrade ceremony would silently re-introduce the multi-writer race.

use merkle_tox_core::dag::{
    ChainKey, ConversationId, Ed25519Signature, KConv, NodeAuth, NodeHash, WireFlags, WireNode,
};
use merkle_tox_core::sync::{NodeStore, ReconciliationStore, SyncRange};
use merkle_tox_core::vfs::{FileSystem, StdFileSystem};
use merkle_tox_fs::{FsStore, encode_hex_32};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

fn empty_wire_node() -> WireNode {
    WireNode {
        parents: tox_proto::BoundedVec::new(),
        sender_hint: [0u8; 4],
        encrypted_routing: vec![0u8; 40],
        payload_data: vec![0x80],
        topological_rank: 0,
        flags: WireFlags::NONE,
        authentication: NodeAuth::Signature(Ed25519Signature::from([1u8; 64])),
    }
}

/// Open the conversation `.lock` file directly and take `LOCK_SH` on it.
/// While this fd is alive, the store cannot upgrade its own internal fd
/// to `LOCK_EX` — every spec-compliant write path must observe this
/// and return an error rather than racing with the external holder.
fn external_shared_holder(
    fs: &StdFileSystem,
    conv_lock_path: &std::path::Path,
) -> Box<dyn merkle_tox_core::vfs::FileHandle> {
    let fd = fs.open(conv_lock_path, true, false, false).unwrap();
    fd.try_lock_shared()
        .expect("external shared lock must acquire (multi-shared is allowed)");
    fd
}

fn conv_lock_path(root: &std::path::Path, conv_id: &ConversationId) -> PathBuf {
    root.join("conversations")
        .join(encode_hex_32(conv_id.as_bytes()))
        .join(".lock")
}

fn setup_store_with_conv() -> (TempDir, FsStore<StdFileSystem>, ConversationId, PathBuf) {
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path().to_path_buf();
    let fs = Arc::new(StdFileSystem);
    let store = FsStore::new(root.clone(), fs.clone()).expect("first store opens");
    let conv_id = ConversationId::from([7u8; 32]);
    // Trigger conversation creation by doing one put under our exclusive
    // ownership (no external holder yet).
    store
        .put_conversation_key(&conv_id, 0, KConv::from([0u8; 32]))
        .expect("bootstrap conv creation");
    let lock_path = conv_lock_path(&root, &conv_id);
    (tmp_dir, store, conv_id, lock_path)
}

#[test]
fn test_put_conversation_key_requires_exclusive_lock() {
    let (_tmp, store, conv_id, lock_path) = setup_store_with_conv();
    let fs = StdFileSystem;
    let _holder = external_shared_holder(&fs, &lock_path);
    let result = store.put_conversation_key(&conv_id, 1, KConv::from([1u8; 32]));
    assert!(
        result.is_err(),
        "put_conversation_key must upgrade to LOCK_EX per spec §3.2.2; \
         a passing test means two processes holding LOCK_SH can both race \
         on conversations/<id>/keys/<epoch>.key writes"
    );
}

#[test]
fn test_update_epoch_metadata_requires_exclusive_lock() {
    let (_tmp, store, conv_id, lock_path) = setup_store_with_conv();
    let fs = StdFileSystem;
    let _holder = external_shared_holder(&fs, &lock_path);
    let result = store.update_epoch_metadata(&conv_id, 5, 1000);
    assert!(
        result.is_err(),
        "update_epoch_metadata writes state.bin and must upgrade to LOCK_EX; \
         a passing test means two processes can race on state.bin tmp+rename"
    );
}

#[test]
fn test_put_ratchet_key_requires_exclusive_lock() {
    let (_tmp, store, conv_id, lock_path) = setup_store_with_conv();
    let fs = StdFileSystem;
    let _holder = external_shared_holder(&fs, &lock_path);
    let result = store.put_ratchet_key(
        &conv_id,
        &NodeHash::from([0xAAu8; 32]),
        ChainKey::from([0xBBu8; 32]),
        1,
    );
    assert!(
        result.is_err(),
        "put_ratchet_key appends to journal.bin and must upgrade to LOCK_EX; \
         a passing test means two processes can interleave journal record writes"
    );
}

#[test]
fn test_put_wire_node_requires_exclusive_lock() {
    let (_tmp, store, conv_id, lock_path) = setup_store_with_conv();
    let fs = StdFileSystem;
    let _holder = external_shared_holder(&fs, &lock_path);
    // Build a minimal WireNode by way of NodeStore::put_wire_node trait method.
    let wire = empty_wire_node();
    let hash = NodeHash::from([0x01u8; 32]);
    let result = store.put_wire_node(&conv_id, &hash, wire);
    assert!(
        result.is_err(),
        "put_wire_node writes to opaque store and must upgrade to LOCK_EX"
    );
}

#[test]
fn test_remove_wire_node_requires_exclusive_lock() {
    let (_tmp, store, conv_id, lock_path) = setup_store_with_conv();
    // First insert a wire node under our own ownership (no external holder).
    let wire = empty_wire_node();
    let hash = NodeHash::from([0x02u8; 32]);
    store.put_wire_node(&conv_id, &hash, wire).expect("seed");

    let fs = StdFileSystem;
    let _holder = external_shared_holder(&fs, &lock_path);
    let result = store.remove_wire_node(&conv_id, &hash);
    assert!(
        result.is_err(),
        "remove_wire_node deletes from opaque store and must upgrade to LOCK_EX"
    );
}

#[test]
fn test_put_sketch_requires_exclusive_lock() {
    let (_tmp, store, conv_id, lock_path) = setup_store_with_conv();
    let fs = StdFileSystem;
    let _holder = external_shared_holder(&fs, &lock_path);
    let result = store.put_sketch(
        &conv_id,
        &SyncRange {
            min_rank: 0,
            max_rank: 100,
        },
        &[1, 2, 3, 4],
    );
    assert!(
        result.is_err(),
        "put_sketch writes sketches/<rank>.bin and must upgrade to LOCK_EX"
    );
}

/// Honest baseline: with no external holder, every write succeeds. Guards
/// against a regression where the fix degenerates to "always reject" and
/// trivially passes the negative tests above.
#[test]
fn test_conv_writes_succeed_without_external_holder() {
    let (_tmp, store, conv_id, _lock_path) = setup_store_with_conv();
    store
        .put_conversation_key(&conv_id, 1, KConv::from([1u8; 32]))
        .expect("put_conversation_key must succeed when uncontended");
    store
        .update_epoch_metadata(&conv_id, 5, 1000)
        .expect("update_epoch_metadata must succeed when uncontended");
    store
        .put_ratchet_key(
            &conv_id,
            &NodeHash::from([0x33u8; 32]),
            ChainKey::from([0x44u8; 32]),
            1,
        )
        .expect("put_ratchet_key must succeed when uncontended");
    store
        .put_sketch(
            &conv_id,
            &SyncRange {
                min_rank: 0,
                max_rank: 100,
            },
            &[1, 2, 3, 4],
        )
        .expect("put_sketch must succeed when uncontended");
}
