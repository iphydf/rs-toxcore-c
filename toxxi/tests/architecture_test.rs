use std::sync::mpsc;
use tokio::runtime::Runtime;
use toxcore::tox::{Address, FriendNumber, ToxConnection, ToxUserStatus};
use toxcore::types::{FileId, PublicKey, ToxLogLevel};
use toxxi::app::AppContext;
use toxxi::config::Config;
use toxxi::model::{DomainState, FileTransferProgress, FriendInfo, Model, TransferStatus};
use toxxi::msg::{AppCmd, Cmd, IOAction, IOEvent, Msg, ToxEvent};
use toxxi::update::{handle_command, update};

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        Address([0u8; 38]),
        PublicKey([0u8; 32]),
        "Tester".to_string(),
        "I am a test".to_string(),
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
fn test_file_chunk_request_routing() {
    let mut model = create_test_model();
    let friend = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file = FileId([2u8; 32]);

    add_test_friend(&mut model, friend, pk);

    let event = ToxEvent::FileChunkRequest(friend, file, 1024, 512);
    let cmds = update(&mut model, Msg::Tox(event));

    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0], Cmd::IO(IOAction::ReadChunk(pk, file, 1024, 512)));
}

#[test]
fn test_file_chunk_read_progress_update() {
    let mut model = create_test_model();
    let friend = FriendNumber(1);
    let pk = PublicKey([1u8; 32]);
    let file = FileId([2u8; 32]);

    add_test_friend(&mut model, friend, pk);

    // Setup a fake transfer
    model.domain.file_transfers.insert(
        file,
        FileTransferProgress {
            filename: "test.txt".to_string(),
            total_size: 2048,
            transferred: 0,
            is_receiving: false,
            status: TransferStatus::Active,
            file_kind: 0,
            file_path: None,
            speed: 0.0,
            last_update: model.time_provider.now(),
            last_transferred: 0,
            friend_pk: pk,
        },
    );

    let event = IOEvent::FileChunkRead(pk, file, 1024, 512);
    let cmds = update(&mut model, Msg::IO(event));

    // Should NOT produce any commands (direct worker-to-worker)
    assert!(cmds.is_empty());

    // Progress should be updated
    let progress = model.domain.file_transfers.get(&file).unwrap();
    assert_eq!(progress.transferred, 1536);
}

#[test]
fn test_reload_command_routing() {
    let mut model = create_test_model();

    // Simulate /reload command
    let cmds = handle_command(&mut model, "/reload");

    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0], Cmd::App(AppCmd::ReloadTox));
}

#[test]
fn test_quit_command_saves_state() {
    let rt = Runtime::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let (tx_msg, _) = mpsc::channel();
    let (tx_tox, _) = mpsc::channel();
    let (tx_io, _) = mpsc::channel();

    let mut model = create_test_model();
    model.ui.active_window_index = 42; // Set a recognizable state

    // Mock a JoinHandle that won't panic on await
    let tox_handle = rt.spawn(async {});

    let mut ctx = AppContext {
        tx_tox_action: tx_tox,
        tox_handle,
        nodes: vec![],
        savedata_path: None,
        config_dir: temp_dir.path().to_path_buf(),
        tx_msg,
        quit_at: None,
        tx_io,
        downloads_dir: temp_dir.path().join("downloads"),
        screenshots_dir: temp_dir.path().join("screenshots"),
    };

    let res = rt.block_on(async { ctx.execute(vec![Cmd::App(AppCmd::Quit)], &mut model).await });

    assert!(
        res.should_quit,
        "execute(Quit) should return should_quit = true"
    );

    // In the new architecture, the main loop or test harness handles the final save
    toxxi::model::save_state(temp_dir.path(), &model).unwrap();

    // Verify state was saved to the temp directory
    let state_path = temp_dir.path().join("state.json");
    assert!(state_path.exists(), "state.json should be created on quit");

    let data = std::fs::read_to_string(state_path).unwrap();
    assert!(
        data.contains("42"),
        "Saved state should contain the active window index"
    );
}

#[test]
fn test_state_serialization_includes_log_filters() {
    let rt = Runtime::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let (tx_msg, _) = mpsc::channel();
    let (tx_tox, _) = mpsc::channel();
    let (tx_io, rx_io) = mpsc::channel();

    let mut model = create_test_model();
    // Set a recognizable log filter
    model.ui.log_filters.levels = vec![ToxLogLevel::TOX_LOG_LEVEL_ERROR];

    let tox_handle = rt.spawn(async {});
    let mut ctx = AppContext {
        tx_tox_action: tx_tox,
        tox_handle,
        nodes: vec![],
        savedata_path: None,
        config_dir: temp_dir.path().to_path_buf(),
        tx_msg,
        quit_at: None,
        tx_io,
        downloads_dir: temp_dir.path().join("downloads"),
        screenshots_dir: temp_dir.path().join("screenshots"),
    };

    rt.block_on(async {
        // Trigger SaveState(None) which uses the local FullState serialization logic
        ctx.execute(vec![Cmd::IO(IOAction::SaveState(None))], &mut model)
            .await;

        // The AppContext should have sent the serialized JSON to the IO channel
        let io_action = rx_io.recv().expect("Should have received IO action");
        if let IOAction::SaveState(Some(json)) = io_action {
            assert!(
                json.contains("log_filters"),
                "Serialized state should contain log_filters"
            );
            assert!(
                json.contains("TOX_LOG_LEVEL_ERROR"),
                "Serialized state should contain the specific log level filter"
            );
        } else {
            panic!("Unexpected IO action: {:?}", io_action);
        }
    });
}
