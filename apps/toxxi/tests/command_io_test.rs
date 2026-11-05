use std::io::Write;
use tempfile::TempDir;
use toxcore::types::{FileId, PublicKey};
use toxxi::model::{FileTransferProgress, TransferStatus};
use toxxi::msg::{Cmd, IOAction, ToxAction};
use toxxi::update::handle_enter;
use toxxi_testing::{add_test_friend, create_test_model};

#[test]
fn test_command_file_send_resume() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);

    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("send_resume.bin");
    {
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(vec![0u8; 1024].as_slice()).unwrap();
    }
    let path_str = file_path.to_string_lossy().to_string();

    // Resume ID (hex of 32 bytes)
    let resume_id = FileId([0xAA; 32]);
    let resume_hex = resume_id.to_string();

    let cmd_str = format!("/file send 01010101 {} {}", path_str, resume_hex);
    let cmds = handle_enter(&mut model, &cmd_str);

    assert_eq!(cmds.len(), 1, "Expected 1 command");
    match &cmds[0] {
        Cmd::Tox(ToxAction::FileSend {
            friend: friend_pk,
            kind,
            size,
            resume: Some(rid),
            ..
        }) => {
            assert_eq!(*friend_pk, pk);
            assert_eq!(*kind, toxcore::types::FileKind::DATA);
            assert_eq!(*size, 1024);
            assert_eq!(*rid, resume_id);
        }
        _ => panic!(
            "Expected ToxAction::FileSend with ResumeID, got {:?}",
            cmds[0]
        ),
    }
}

/// The I/O thread starts the transfer, resuming only from what came of it
/// before (see resume_test): a file of the name someone gives doesn't count.
#[test]
fn test_command_file_accept_opens_the_download() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, pk);

    let file_id = FileId([0xBB; 32]);
    model.domain.file_transfers.insert(
        file_id,
        FileTransferProgress {
            filename: "incoming.bin".to_string(),
            total_size: 2000,
            transferred: 0,
            is_receiving: true,
            status: TransferStatus::Paused,
            speed: 0.0,
            last_update: std::time::Instant::now(),
            last_transferred: 0,
            friend_pk: pk,
        },
    );

    let temp_dir = TempDir::new().unwrap();
    let existing = temp_dir.path().join("incoming_resume.bin");
    std::fs::File::create(&existing)
        .unwrap()
        .write_all(&[0; 500])
        .unwrap();
    let path_str = existing.to_string_lossy().to_string();

    let cmd_str = format!("/file accept 01010101 {} {}", file_id, path_str);
    let cmds = handle_enter(&mut model, &cmd_str);

    assert_eq!(
        cmds,
        vec![Cmd::IO(IOAction::OpenFileForReceiving(
            pk, file_id, path_str, 2000
        ))]
    );
}
