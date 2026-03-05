//! Crash-recovery durability regression tests.
//!
//! These tests verify that the persistence layer's durability
//! boundaries (state.bin save, journal append/truncate, blob info,
//! ratchet save, pack-data fsync, packs/ dir sync) actually call
//! `sync_data` / `sync_dir`. The mechanism: wrap a real filesystem
//! in `FaultInjectingFileSystem` configured to fail sync_data /
//! sync_dir, and assert that the operation propagates the failure
//! instead of silently succeeding.
//!
//! Without these tests, the fsync calls would be invisible — the
//! existing test suite uses `MemFileSystem` whose sync_data is a
//! no-op (no kernel page cache to flush), so a missing fsync in
//! production code would not show up. The fault-injecting wrapper
//! is the cheapest way to assert "the durability boundary is wired
//! up" without spinning up a real OS-crash test harness.

use merkle_tox_core::cas::{BlobInfo, BlobStatus};
use merkle_tox_core::dag::{ChainKey, NodeHash, PhysicalDevicePk};
use merkle_tox_core::vfs::{FaultInjectingFileSystem, FileSystem, MemFileSystem};
use merkle_tox_fs::blob::BlobStore;
use merkle_tox_fs::state::{ConvState, RatchetFile, RatchetSlot, StateFile};
use std::path::PathBuf;
use std::sync::Arc;

fn fault_fs() -> Arc<FaultInjectingFileSystem> {
    Arc::new(FaultInjectingFileSystem::new(
        Arc::new(MemFileSystem::new()),
    ))
}

/// `StateFile::save` must call `sync_data` before rename, so a
/// fault-injected sync_data failure must propagate. Without this
/// fsync, the rename can land on a file whose contents haven't
/// hit disk yet.
#[test]
fn test_state_save_propagates_sync_data_fault() {
    let fs = fault_fs();
    fs.create_dir_all(&PathBuf::from("/conv")).unwrap();
    let state_path = PathBuf::from("/conv/state.bin");
    let state_file = StateFile::new(fs.clone(), state_path);
    let state = ConvState {
        heads: vec![],
        admin_heads: vec![],
        message_count: 0,
        last_rotation_time: -1,
        active_packs: vec![],
        active_journal_id: 0,
    };
    // Inject a fault on every sync (1.0 probability). Save must fail.
    fs.set_fail_probability(1.0);
    let result = state_file.save(&state);
    assert!(
        result.is_err(),
        "StateFile::save must propagate sync_data / sync_dir errors. \
         If this test passes (i.e. save returned Ok despite injected \
         fault), it means a durability boundary is missing — the \
         tmp-write isn't fsync'd before rename, OR the parent \
         directory isn't sync'd after rename. Either way, a power \
         loss during the rename would leave the filesystem in a \
         visibly-renamed but actually-empty state.",
    );
}

/// `BlobStore::put_info` must call `sync_data` and `sync_dir` for
/// the same reasons as `StateFile::save`.
#[test]
fn test_blob_put_info_propagates_sync_fault() {
    let fs = fault_fs();
    fs.create_dir_all(&PathBuf::from("/conv/blob")).unwrap();
    let store = BlobStore::new(PathBuf::from("/conv/blob"), fs.clone());
    let info = BlobInfo {
        hash: NodeHash::from([0xCDu8; 32]),
        size: 1024,
        status: BlobStatus::Pending,
        received_mask: None,
        decryption_key: None,
    };
    fs.set_fail_probability(1.0);
    let result = store.put_info(&info);
    assert!(
        result.is_err(),
        "BlobStore::put_info must propagate sync_data / sync_dir errors. \
         A passing test means the tmp-write or rename isn't sync'd, \
         leaving BlobInfo subject to torn writes across crashes.",
    );
}

/// `RatchetFile::save` must call `sync_data` between the buffer
/// payload write and the active-pointer flip; otherwise the OS
/// can land the 4-byte pointer write before the larger buffer
/// payload, leaving recovery to load a buffer pointer that points
/// at zeros.
#[test]
fn test_ratchet_save_propagates_sync_fault() {
    let fs = fault_fs();
    let path = PathBuf::from("/ratchet.bin");
    let mut rfile = RatchetFile::open(fs.clone(), path).unwrap();
    let slots = vec![RatchetSlot {
        device_pk: PhysicalDevicePk::from([1u8; 32]),
        chain_key: ChainKey::from([0x11u8; 32]),
        last_sequence_number: 10,
        epoch_id: 0,
    }];
    fs.set_fail_probability(1.0);
    let result = rfile.save(&slots);
    assert!(
        result.is_err(),
        "RatchetFile::save must propagate sync_data errors. A passing \
         test means the buffer payload isn't fsync'd before the \
         active-pointer flip — recovery can load a buffer pointer \
         that points at zeros, silently wiping per-device sequence \
         state and dropping the next batch of inbound packets.",
    );
}

/// Honest baseline: with sync faults disabled, all three save paths
/// succeed and the saved state round-trips. Regression guard against
/// a fix that degenerates to "always fail" and passes the three
/// negative tests trivially.
#[test]
fn test_durability_paths_succeed_without_fault() {
    let fs = fault_fs();
    fs.create_dir_all(&PathBuf::from("/conv")).unwrap();
    fs.create_dir_all(&PathBuf::from("/conv/blob")).unwrap();

    // StateFile
    let state_path = PathBuf::from("/conv/state.bin");
    let state_file = StateFile::new(fs.clone(), state_path);
    let state = ConvState {
        heads: vec![NodeHash::from([1u8; 32])],
        admin_heads: vec![],
        message_count: 1,
        last_rotation_time: 1000,
        active_packs: vec![42],
        active_journal_id: 7,
    };
    state_file.save(&state).expect("save must succeed");
    let loaded = state_file.load().expect("load must succeed");
    assert_eq!(loaded.message_count, 1);
    assert_eq!(loaded.active_packs, vec![42u64]);

    // BlobStore
    let store = BlobStore::new(PathBuf::from("/conv/blob"), fs.clone());
    let info = BlobInfo {
        hash: NodeHash::from([0xCDu8; 32]),
        size: 2048,
        status: BlobStatus::Available,
        received_mask: None,
        decryption_key: None,
    };
    store.put_info(&info).expect("put_info must succeed");
    let loaded_info = store
        .get_info(&info.hash)
        .expect("get_info must succeed")
        .expect("info must exist");
    assert_eq!(loaded_info.size, 2048);

    // RatchetFile
    let path = PathBuf::from("/ratchet.bin");
    let mut rfile = RatchetFile::open(fs.clone(), path.clone()).unwrap();
    let slots = vec![RatchetSlot {
        device_pk: PhysicalDevicePk::from([2u8; 32]),
        chain_key: ChainKey::from([0x22u8; 32]),
        last_sequence_number: 99,
        epoch_id: 3,
    }];
    rfile.save(&slots).expect("ratchet save must succeed");
    drop(rfile);
    let mut rfile = RatchetFile::open(fs.clone(), path).unwrap();
    let loaded_slots = rfile.load().expect("ratchet load must succeed");
    assert_eq!(loaded_slots.len(), 1);
    assert_eq!(loaded_slots[0].last_sequence_number, 99);
}
