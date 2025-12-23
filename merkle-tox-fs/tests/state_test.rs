use merkle_tox_core::dag::{ChainKey, PhysicalDevicePk};
use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::state::{RATCHET_MAGIC, RatchetFile, RatchetSlot};
use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_ratchet_file_double_buffering() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let path = tmp_dir.path().join("ratchet.bin");

    let mut rfile = RatchetFile::open(fs.clone(), path.clone()).unwrap();

    let pk1 = PhysicalDevicePk::from([1u8; 32]);
    let ck1 = ChainKey::from([0x11u8; 32]);
    let slots1 = vec![RatchetSlot {
        device_pk: pk1,
        chain_key: ck1,
        last_sequence_number: 10,
    }];

    // Save to Buffer 1 (starts at active=0, so writes to 1)
    rfile.save(&slots1).unwrap();

    // Verify header says active=1
    let data = std::fs::read(&path).unwrap();
    assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 1);

    // Re-open and load
    drop(rfile);
    let mut rfile = RatchetFile::open(fs.clone(), path.clone()).unwrap();
    let loaded = rfile.load().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].device_pk, pk1);
    assert_eq!(loaded[0].last_sequence_number, 10);

    // Save again, should go to Buffer 0
    let pk2 = PhysicalDevicePk::from([2u8; 32]);
    let slots2 = vec![RatchetSlot {
        device_pk: pk2,
        chain_key: ChainKey::from([0x22u8; 32]),
        last_sequence_number: 20,
    }];
    rfile.save(&slots2).unwrap();

    let data = std::fs::read(&path).unwrap();
    assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 0);

    let loaded = rfile.load().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].device_pk, pk2);
}

#[test]
fn test_ratchet_file_recovery_simulated() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let path = tmp_dir.path().join("ratchet.bin");

    // Manually construct a "corrupt" file where active buffer points to empty one
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&RATCHET_MAGIC.to_le_bytes()).unwrap();
        f.write_all(&1u32.to_le_bytes()).unwrap(); // active = 1
        f.write_all(&1u32.to_le_bytes()).unwrap(); // count0 = 1
        f.write_all(&0u32.to_le_bytes()).unwrap(); // count1 = 0

        // Write one slot to buffer 0
        f.seek(SeekFrom::Start(16)).unwrap();
        let slot = RatchetSlot {
            device_pk: PhysicalDevicePk::from([1u8; 32]),
            chain_key: ChainKey::from([1u8; 32]),
            last_sequence_number: 100,
        };
        let mut buf = [0u8; RatchetSlot::SIZE];
        slot.to_bytes(&mut buf);
        f.write_all(&buf).unwrap();
    }

    let mut rfile = RatchetFile::open(fs.clone(), path).unwrap();
    let loaded = rfile.load().unwrap();

    // It should load Buffer 1 which is empty as per header
    assert_eq!(loaded.len(), 0);
}
