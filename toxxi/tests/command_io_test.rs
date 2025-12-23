use std::io::Write;
use tempfile::TempDir;
use toxcore::tox::{Address, FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::{FileId, PublicKey, ToxFileControl};
use toxxi::config::Config;
use toxxi::model::{DomainState, FileTransferProgress, FriendInfo, Model, TransferStatus};
use toxxi::msg::{Cmd, IOAction, ToxAction};
use toxxi::update::handle_enter;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "Status".to_string(),
        ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

fn add_test_friend(model: &mut Model, fid: FriendNumber, pk: PublicKey) {
    model.session.friend_numbers.insert(fid, pk);
    model.domain.friends.insert(
        pk,
        FriendInfo {
            name: format!("Friend {}", fid.0),
            public_key: Some(pk),
            status_message: "".to_string(),
            connection: ToxConnection::TOX_CONNECTION_TCP,
            last_sent_message_id: None,
            last_read_receipt: None,
            is_typing: false,
        },
    );
    model.ensure_friend_window(pk);
}

#[test]
fn test_command_file_send_resume() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);

    // Create a dummy file to send
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

    // Execute command with resume ID
    let cmd_str = format!("/file send 1 {} {}", path_str, resume_hex);
    let cmds = handle_enter(&mut model, &cmd_str);

    assert_eq!(cmds.len(), 1, "Expected 1 command");
    match &cmds[0] {
        Cmd::Tox(ToxAction::FileSend(friend_pk, kind, size, _filename, _path, Some(rid))) => {
            assert_eq!(*friend_pk, pk);
            assert_eq!(*kind, 0);
            assert_eq!(*size, 1024);
            assert_eq!(*rid, resume_id);
        }
        _ => panic!(
            "Expected ToxAction::FileSend with ResumeID, got {:?}",
            cmds[0]
        ),
    }
}

#[test]
fn test_command_file_accept_resume_seek() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);

    let file_id = FileId([0xBB; 32]);
    let file_id_hex = file_id.to_string();

    // Register incoming transfer in model (usually done by FileRecv event)
    model.domain.file_transfers.insert(
        file_id,
        FileTransferProgress {
            filename: "incoming.bin".to_string(),
            total_size: 2000,
            transferred: 0,
            is_receiving: true,
            status: TransferStatus::Paused, // Initially paused/waiting
            file_kind: 0,
            file_path: None,
            speed: 0.0,
            last_update: std::time::Instant::now(),
            last_transferred: 0,
            friend_pk: pk,
        },
    );

    // Create an existing PARTIAL file (simulating previous download)
    let temp_dir = TempDir::new().unwrap();
    let partial_path = temp_dir.path().join("incoming_resume.bin");
    {
        let mut f = std::fs::File::create(&partial_path).unwrap();
        f.write_all(vec![0u8; 500].as_slice()).unwrap();
    }
    let path_str = partial_path.to_string_lossy().to_string();

    // Execute accept command pointing to this partial file
    let cmd_str = format!("/file accept 1 {} {}", file_id_hex, path_str);
    let cmds = handle_enter(&mut model, &cmd_str);

    // We expect 3 commands: Open, Seek, Resume
    assert_eq!(cmds.len(), 3, "Expected 3 commands for resume");

    // 1. Open
    match &cmds[0] {
        Cmd::IO(IOAction::OpenFileForReceiving(friend_pk, fid, _path, size)) => {
            assert_eq!(*friend_pk, pk);
            assert_eq!(*fid, file_id);
            assert_eq!(*size, 2000);
        }
        _ => panic!("Expected IOAction::OpenFileForReceiving, got {:?}", cmds[0]),
    }

    // 2. Seek (Should be 500 bytes)
    match &cmds[1] {
        Cmd::Tox(ToxAction::FileSeek(friend_pk, fid, offset)) => {
            assert_eq!(*friend_pk, pk);
            assert_eq!(*fid, file_id);
            assert_eq!(*offset, 500);
        }
        _ => panic!("Expected ToxAction::FileSeek, got {:?}", cmds[1]),
    }

    // 3. Resume
    match &cmds[2] {
        Cmd::Tox(ToxAction::FileControl(friend_pk, fid, control)) => {
            assert_eq!(*friend_pk, pk);
            assert_eq!(*fid, file_id);
            assert_eq!(*control, ToxFileControl::TOX_FILE_CONTROL_RESUME);
        }
        _ => panic!("Expected ToxAction::FileControl(RESUME), got {:?}", cmds[2]),
    }
}

#[test]
fn test_command_file_accept_fresh_no_seek() {
    let mut model = create_test_model();
    let fid = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    add_test_friend(&mut model, fid, pk);

    let file_id = FileId([0xCC; 32]);
    let file_id_hex = file_id.to_string();

    model.domain.file_transfers.insert(
        file_id,
        FileTransferProgress {
            filename: "fresh.bin".to_string(),
            total_size: 2000,
            transferred: 0,
            is_receiving: true,
            status: TransferStatus::Paused,
            file_kind: 0,
            file_path: None,
            speed: 0.0,
            last_update: std::time::Instant::now(),
            last_transferred: 0,
            friend_pk: pk,
        },
    );

    let temp_dir = TempDir::new().unwrap();
    let fresh_path = temp_dir.path().join("fresh_download.bin");
    // Ensure file does NOT exist
    if fresh_path.exists() {
        std::fs::remove_file(&fresh_path).unwrap();
    }
    let path_str = fresh_path.to_string_lossy().to_string();

    let cmd_str = format!("/file accept 1 {} {}", file_id_hex, path_str);
    let cmds = handle_enter(&mut model, &cmd_str);

    // We expect 2 commands: Open, Resume (NO Seek)
    assert_eq!(cmds.len(), 2, "Expected 2 commands for fresh download");

    // 1. Open
    match &cmds[0] {
        Cmd::IO(IOAction::OpenFileForReceiving(..)) => {}
        _ => panic!("Expected IOAction::OpenFileForReceiving"),
    }

    // 2. Resume
    match &cmds[1] {
        Cmd::Tox(ToxAction::FileControl(_, _, control)) => {
            assert_eq!(*control, ToxFileControl::TOX_FILE_CONTROL_RESUME);
        }
        _ => panic!("Expected ToxAction::FileControl(RESUME)"),
    }
}
