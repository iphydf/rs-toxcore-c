use merkle_tox_core::vfs::StdFileSystem;
use merkle_tox_fs::journal::{Journal, JournalRecordType};
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_journal_basic_append_read() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let path = tmp_dir.path().join("journal.bin");

    let mut journal = Journal::open(fs.clone(), path.clone()).unwrap();
    let gen_id = journal.generation_id();

    let payload1 = b"node-data-1";
    let (hash1, offset1) = journal.append(JournalRecordType::Node, payload1).unwrap();

    let payload2 = b"vouch-data";
    let (hash2, offset2) = journal.append(JournalRecordType::Vouch, payload2).unwrap();

    // Re-open and read
    drop(journal);
    let mut journal = Journal::open(fs.clone(), path).unwrap();
    assert_eq!(journal.generation_id(), gen_id);

    let records = journal.read_all().unwrap();
    assert_eq!(records.len(), 2);

    assert_eq!(records[0].hash, hash1);
    assert_eq!(records[0].offset, offset1);
    assert_eq!(records[0].record_type, JournalRecordType::Node);
    assert_eq!(records[0].payload, payload1);

    assert_eq!(records[1].hash, hash2);
    assert_eq!(records[1].offset, offset2);
    assert_eq!(records[1].record_type, JournalRecordType::Vouch);
    assert_eq!(records[1].payload, payload2);
}

#[test]
fn test_journal_recovery_from_corruption() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let path = tmp_dir.path().join("journal.bin");

    {
        let mut journal = Journal::open(fs.clone(), path.clone()).unwrap();
        journal.append(JournalRecordType::Node, b"valid-1").unwrap();
        journal.append(JournalRecordType::Node, b"valid-2").unwrap();
    }

    // Corrupt the second record's payload
    let mut data = std::fs::read(&path).unwrap();
    let len = data.len();
    data[len - 1] ^= 0xFF; // Flip bits in the last byte
    std::fs::write(&path, data).unwrap();

    let mut journal = Journal::open(fs.clone(), path.clone()).unwrap();
    let records = journal.read_all().unwrap();

    // Should have recovered only the first valid record and truncated the rest
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].payload, b"valid-1");

    // Verify file was actually truncated
    let meta = std::fs::metadata(&path).unwrap();
    assert!(meta.len() < len as u64);
}

#[test]
fn test_journal_recovery_short_read() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let path = tmp_dir.path().join("journal.bin");

    {
        let mut journal = Journal::open(fs.clone(), path.clone()).unwrap();
        journal
            .append(JournalRecordType::Node, b"record-1")
            .unwrap();
    }

    // Clip the file in the middle of the second record header (just length)
    let mut data = std::fs::read(&path).unwrap();
    data.extend_from_slice(&100u32.to_le_bytes()); // add a length prefix for a non-existent record
    std::fs::write(&path, data).unwrap();

    let mut journal = Journal::open(fs.clone(), path).unwrap();
    let records = journal.read_all().unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].payload, b"record-1");
}

#[test]
fn test_journal_truncate_restart() {
    let tmp_dir = TempDir::new().unwrap();
    let fs = Arc::new(StdFileSystem);
    let path = tmp_dir.path().join("journal.bin");

    let mut journal = Journal::open(fs.clone(), path.clone()).unwrap();
    journal
        .append(JournalRecordType::Node, b"old-data")
        .unwrap();

    let new_gen = 12345u64;
    journal.truncate(new_gen).unwrap();
    assert_eq!(journal.generation_id(), new_gen);

    let records = journal.read_all().unwrap();
    assert!(records.is_empty());

    journal
        .append(JournalRecordType::Node, b"new-data")
        .unwrap();
    let records = journal.read_all().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].payload, b"new-data");
}
