use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use toxxi::app::AppContext;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model};
use toxxi::msg::{AppCmd, Cmd};
use toxxi::update::handle_enter;

fn create_test_model() -> Model {
    let config = Config::default();
    let domain = DomainState::new(
        toxcore::tox::Address([0u8; 38]),
        toxcore::types::PublicKey([0u8; 32]),
        "Tester".to_string(),
        "Status".to_string(),
        toxcore::tox::ToxUserStatus::TOX_USER_STATUS_NONE,
    );
    Model::new(domain, config.clone(), config)
}

#[tokio::test]
async fn test_timeout_command_sets_quit_at() {
    let mut model = create_test_model();

    let (tx_tox, _rx_tox) = mpsc::channel();
    let (tx_msg, _rx_msg) = mpsc::channel();
    let (tx_io, _rx_io) = mpsc::channel();

    let tox_handle = tokio::task::spawn(async {});

    let mut ctx = AppContext {
        tx_tox_action: tx_tox,
        tox_handle,
        nodes: vec![],
        savedata_path: None,
        config_dir: PathBuf::from("."),
        tx_msg,
        quit_at: None,
        tx_io,
        downloads_dir: PathBuf::from("."),
        screenshots_dir: PathBuf::from("."),
    };

    // Execute /timeout 100
    let cmds = handle_enter(&mut model, "/timeout 100");
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0], Cmd::App(AppCmd::SetTimeout(100)));

    ctx.execute(cmds, &mut model).await;

    assert!(ctx.quit_at.is_some());
    let quit_time = ctx.quit_at.unwrap();
    let now = Instant::now();

    // Should be in the future (approx 100ms)
    assert!(quit_time > now);
    assert!(quit_time < now + Duration::from_secs(1));
}
