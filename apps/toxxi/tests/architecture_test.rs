use std::sync::mpsc;
use tokio::runtime::Runtime;
use toxcore::types::{FileId, LogLevel, PublicKey};
use toxxi::model::{FileTransferProgress, Model, TransferStatus};
use toxxi::msg::{AppCmd, Cmd, IOAction, IOEvent, Msg, ToxEvent};
use toxxi::update::{handle_command, update};
use toxxi_testing::{self as testing, app_context};

fn create_test_model() -> Model {
    let mut model = testing::create_test_model();
    model.record_account();
    model
}

fn add_test_friend(model: &mut Model, pk: PublicKey) {
    testing::add_test_friend(model, pk);
    model.record_account();
}

#[test]
fn test_file_chunk_request_routing() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file = FileId([2u8; 32]);

    add_test_friend(&mut model, pk);

    let event = ToxEvent::FileChunkRequest(pk, file, 1024, 512);
    let cmds = update(&mut model, Msg::Tox(event));

    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0], Cmd::IO(IOAction::ReadChunk(pk, file, 1024, 512)));
}

#[test]
fn test_file_chunk_read_progress_update() {
    let mut model = create_test_model();
    let pk = PublicKey([1u8; 32]);
    let file = FileId([2u8; 32]);

    add_test_friend(&mut model, pk);

    model.domain.file_transfers.insert(
        file,
        FileTransferProgress {
            filename: "test.txt".to_string(),
            total_size: 2048,
            transferred: 0,
            is_receiving: false,
            status: TransferStatus::Active,
            speed: 0.0,
            last_update: model.time_provider.now(),
            last_transferred: 0,
            friend_pk: pk,
        },
    );

    let event = IOEvent::FileChunkRead(pk, file, 1024, 512);
    let cmds = update(&mut model, Msg::IO(event));

    // No commands: the workers talk to each other directly.
    assert!(cmds.is_empty());

    let progress = model.domain.file_transfers.get(&file).unwrap();
    assert_eq!(progress.transferred, 1536);
}

#[test]
fn test_reload_command_routing() {
    let mut model = create_test_model();

    let cmds = handle_command(&mut model, "/reload");

    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0], Cmd::App(AppCmd::ReloadTox));
}

#[test]
fn test_quit_command_quits() {
    let rt = Runtime::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let mut model = create_test_model();
    let (mut ctx, _) = app_context(&rt, temp_dir.path());

    let res = rt.block_on(async { ctx.execute(vec![Cmd::App(AppCmd::Quit)], &mut model).await });

    assert!(
        res.should_quit,
        "execute(Quit) should return should_quit = true"
    );
}

#[test]
fn test_state_serialization_includes_log_filters() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut model = create_test_model();
    model.ui.log_filters.levels = vec![LogLevel::Error];

    toxxi::model::save_state(temp_dir.path(), &model).unwrap();

    let json = std::fs::read_to_string(temp_dir.path().join("state.json")).unwrap();
    assert!(
        json.contains("log_filters"),
        "Serialized state should contain log_filters"
    );
    assert!(
        json.contains("\"Error\""),
        "Serialized state should contain the specific log level filter"
    );
}

#[test]
fn test_quitting_waits_for_the_files_being_kept() {
    let rt = Runtime::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let (tx_msg, rx_msg) = mpsc::channel();
    let mut model = create_test_model();
    let file = FileId([5u8; 32]);
    model.session.finishing.insert(file);

    let (mut ctx, _rx_io) = app_context(&rt, temp_dir.path());
    // As the IO worker does once a large file is copied.
    let pk = PublicKey([1u8; 32]);
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let _ = tx_msg.send(Msg::IO(IOEvent::FileFinished(pk, file, None)));
    });

    rt.block_on(ctx.drain(&rx_msg, &mut model));
    assert!(model.session.finishing.is_empty());
}

#[test]
fn test_quitting_records_what_waited_for_the_tick() {
    let rt = Runtime::new().unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let (tx_msg, rx_msg) = mpsc::channel();
    let mut model = create_test_model();
    model.domain.self_name = "Renamed".to_owned();

    let (mut ctx, rx_io) = app_context(&rt, temp_dir.path());
    let log = ToxEvent::Log {
        level: LogLevel::Debug,
        file: String::new(),
        line: 0,
        func: String::new(),
        message: String::new(),
    };
    tx_msg.send(Msg::Tox(log)).unwrap();

    rt.block_on(ctx.drain(&rx_msg, &mut model));
    assert!(matches!(rx_io.try_recv(), Ok(IOAction::AppendEvents(..))));
}
