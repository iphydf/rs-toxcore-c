use std::io::Write;
use std::sync::mpsc;
use tempfile::TempDir;
use toxxi::io::spawn_io_worker;
use toxxi::msg::{IOAction, ToxAction};

#[tokio::test]
async fn test_resume_file_transfer_truncation() {
    // This test demonstrates that current behavior TRUNCATES existing files
    // instead of allowing resume.

    let temp_dir = TempDir::new().unwrap();
    let downloads_dir = temp_dir.path().join("downloads");
    std::fs::create_dir_all(&downloads_dir).unwrap();

    let file_path = downloads_dir.join("test_file.bin");

    // 1. Create a "partial" file
    {
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(b"partial content").unwrap();
    }

    let initial_len = std::fs::metadata(&file_path).unwrap().len();
    assert_eq!(initial_len, 15);

    // 2. Spawn IO worker
    let (tx_msg, _rx_msg) = mpsc::channel();
    let (tx_tox, _rx_tox) = mpsc::channel();
    let (tx_io, rx_io) = mpsc::channel();

    let _handle = spawn_io_worker(
        tx_msg,
        tx_tox,
        rx_io,
        temp_dir.path().to_path_buf(),
        downloads_dir.clone(),
    );

    // 3. Request to open file for receiving (simulating accept)
    let pk = toxcore::types::PublicKey([0u8; 32]);
    let file_id = toxcore::types::FileId([1u8; 32]);
    let file_size = 100;

    tx_io
        .send(IOAction::OpenFileForReceiving(
            pk,
            file_id,
            "test_file.bin".to_string(), // Same filename
            file_size,
        ))
        .unwrap();

    // Allow some time for IO worker to process
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 4. Verify file size - SHOULD PRESERVE CONTENT
    // The implementation now uses `OpenOptions` to append/write without truncating.
    // So the original content (length 15) should still be there.

    let new_metadata = std::fs::metadata(&file_path).unwrap();

    // This assertion confirms the CORRECT behavior (no truncation)
    assert_eq!(
        new_metadata.len(),
        15,
        "File should NOT be truncated by current implementation (Resumption support)"
    );
}

#[tokio::test]
async fn test_resume_seek_behavior_missing() {
    // This test simulates the need for a SEEK command when resuming.
    // Currently, `io.rs` does not check for existing files and does not issue a seek.

    let temp_dir = TempDir::new().unwrap();
    let downloads_dir = temp_dir.path().join("downloads");
    std::fs::create_dir_all(&downloads_dir).unwrap();
    let file_path = downloads_dir.join("resume.bin");

    // Create existing file
    {
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(vec![0u8; 50].as_slice()).unwrap();
    }

    let (tx_msg, _rx_msg) = mpsc::channel();
    let (tx_tox, rx_tox) = mpsc::channel(); // We will listen to this for seek
    let (tx_io, rx_io) = mpsc::channel();

    let _handle = spawn_io_worker(
        tx_msg,
        tx_tox,
        rx_io,
        temp_dir.path().to_path_buf(),
        downloads_dir.clone(),
    );

    let pk = toxcore::types::PublicKey([0u8; 32]);
    let file_id = toxcore::types::FileId([2u8; 32]);

    // Send Open command
    tx_io
        .send(IOAction::OpenFileForReceiving(
            pk,
            file_id,
            "resume.bin".to_string(),
            100,
        ))
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Check if we received a ToxAction::FileSeek
    // In current implementation, we DO NOT receive this.

    let mut received_seek = false;
    while let Ok(action) = rx_tox.try_recv() {
        if let ToxAction::FileSeek(..) = action {
            received_seek = true;
        }
    }

    assert!(
        !received_seek,
        "Current implementation should NOT send seek"
    );
}
