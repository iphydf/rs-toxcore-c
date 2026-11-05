use std::sync::mpsc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use toxxi::config::Config;
use toxxi::msg::{Msg, SystemEvent, ToxAction, ToxEvent};
use toxxi::worker;

#[tokio::test]
async fn test_a_failed_create_makes_no_group() {
    let temp_dir = TempDir::new().unwrap();
    let config = Config {
        udp_enabled: false,
        ..Default::default()
    };
    let (tx_msg, rx_msg) = mpsc::channel();
    let (tx_tox_action, rx_tox_action) = mpsc::channel();
    let (tx_io, _rx_io) = mpsc::channel();
    let handle = worker::spawn_tox(
        tx_msg,
        tx_io,
        rx_tox_action,
        Some(temp_dir.path().join("savedata.tox")),
        &config,
        vec![],
        temp_dir.path().to_path_buf(),
    );

    // Tox needs our name in the group to create it.
    tx_tox_action
        .send(ToxAction::SetName("Me".to_owned()))
        .unwrap();
    // Longer than Tox takes for a group name.
    tx_tox_action
        .send(ToxAction::CreateGroup("x".repeat(100)))
        .unwrap();
    tx_tox_action
        .send(ToxAction::CreateGroup("fits".to_owned()))
        .unwrap();

    let mut failures = 0;
    let mut created = Vec::new();
    let start = Instant::now();
    while created.is_empty() && start.elapsed() < Duration::from_secs(10) {
        match rx_msg.recv_timeout(Duration::from_millis(50)) {
            Ok(Msg::System(SystemEvent::Log { message, .. }))
                if message.starts_with("Failed to create group") =>
            {
                failures += 1;
            }
            Ok(Msg::Tox(ToxEvent::GroupCreated(_, _, name))) => created.push(name),
            _ => {}
        }
    }
    tx_tox_action.send(ToxAction::Shutdown).unwrap();
    handle.await.unwrap();

    assert_eq!(failures, 1);
    assert_eq!(created, vec![Some("fits".to_owned())]);
}
