use std::sync::mpsc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::msg::{LogSeverity, Msg, SystemEvent, ToxAction, ToxEvent};
use toxxi::worker;

/// Tox can't send an invite to a friend who isn't online.
#[tokio::test]
async fn an_invite_that_fails_says_so() {
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
    let friend = PublicKey([7; 32]);
    for action in [
        ToxAction::SetName("Me".to_owned()),
        ToxAction::AcceptFriend(friend),
        ToxAction::CreateGroup("club".to_owned()),
    ] {
        tx_tox_action.send(action).unwrap();
    }

    let mut failed = None;
    let start = Instant::now();
    while failed.is_none() && start.elapsed() < Duration::from_secs(10) {
        match rx_msg.recv_timeout(Duration::from_millis(50)) {
            Ok(Msg::Tox(ToxEvent::GroupCreated(_, chat_id, _))) => tx_tox_action
                .send(ToxAction::InviteFriendToGroup(chat_id, friend))
                .unwrap(),
            Ok(Msg::System(SystemEvent::Log {
                severity: LogSeverity::Error,
                message,
                ..
            })) => failed = Some(message),
            _ => {}
        }
    }
    tx_tox_action.send(ToxAction::Shutdown).unwrap();
    handle.await.unwrap();

    let failed = failed.expect("the failed invite wasn't reported");
    assert!(
        failed.starts_with("Error inviting to the group"),
        "{failed}"
    );
}
