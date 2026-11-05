use std::sync::mpsc;
use std::time::Duration;
use tempfile::TempDir;
use toxcore::tox::Address;
use toxcore::types::PublicKey;
use toxxi::config::Config;
use toxxi::model::{DomainState, Model, WindowId};
use toxxi::msg::{Cmd, Msg, ToxAction};
use toxxi::update;
use toxxi::worker;

fn run_command(model: &mut Model, cmd: &str, tx_tox_action: &mpsc::Sender<ToxAction>) {
    let cmds = update::handle_command(model, cmd);
    for c in cmds {
        if let Cmd::Tox(a) = c {
            tx_tox_action.send(a).unwrap();
        }
    }
}

fn process_events(
    rx_msg: &mpsc::Receiver<Msg>,
    tx_tox_action: &mpsc::Sender<ToxAction>,
    model: &mut Model,
    condition: impl Fn(&Model) -> bool,
    timeout_secs: u64,
) {
    let start = std::time::Instant::now();
    while !condition(model) {
        if start.elapsed() > Duration::from_secs(timeout_secs) {
            panic!("Timeout waiting for condition");
        }
        if let Ok(msg) = rx_msg.recv_timeout(Duration::from_millis(50)) {
            let cmds = update::update(model, msg);
            for cmd in cmds {
                if let Cmd::Tox(a) = cmd {
                    tx_tox_action.send(a).unwrap();
                }
            }
        }
    }
}

#[tokio::test]
async fn test_persistence_real_tox_instance() {
    let temp_dir = TempDir::new().unwrap();
    let savedata_path = temp_dir.path().join("savedata.tox");
    let config_dir = temp_dir.path().to_path_buf();

    // 3 random addresses to add as friends
    let mut friend_addresses = Vec::new();
    for i in 1..=3 {
        let pk = PublicKey([i as u8; 32]);
        let nospam = 0x12345678;
        let addr = Address::from_public_key(pk, nospam);
        friend_addresses.push(addr);
    }

    // Add friends, delete one, and save.
    {
        let initial_state = worker::get_initial_state(&Some(savedata_path.clone())).unwrap();

        assert!(
            initial_state.friends.is_empty(),
            "Expected no friends in fresh profile"
        );

        let domain = DomainState::new(
            initial_state.tox_id,
            initial_state.name,
            initial_state.status_message,
            initial_state.status_type,
        );
        let config = Config {
            start_port: 33445,
            end_port: 44445,
            udp_enabled: false,
            ..Default::default()
        };

        let mut model = Model::new(domain, config.clone(), config.clone());
        model.reconcile(
            initial_state.friends,
            initial_state.groups,
            initial_state.conferences,
        );

        let (tx_msg, rx_msg) = mpsc::channel();
        let (tx_tox_action, rx_tox_action) = mpsc::channel();
        let (tx_io, _rx_io) = mpsc::channel();

        let handle = worker::spawn_tox(
            tx_msg.clone(),
            tx_io,
            rx_tox_action,
            Some(savedata_path.clone()),
            &config,
            vec![],
            config_dir.clone(),
        );

        // Wait for the worker to start.
        process_events(
            &rx_msg,
            &tx_tox_action,
            &mut model,
            |m| m.domain.tox_id != Address([0; 38]),
            5,
        );

        for (i, addr) in friend_addresses.iter().enumerate() {
            let cmd = format!("/friend add {} Hi {}", addr, i + 1);
            run_command(&mut model, &cmd, &tx_tox_action);
        }

        process_events(
            &rx_msg,
            &tx_tox_action,
            &mut model,
            |m| m.domain.friends.len() == 3,
            5,
        );

        let pk2 = friend_addresses[1].public_key();
        let cmd = format!("/friend remove {}", toxxi::utils::short_key(&pk2));
        run_command(&mut model, &cmd, &tx_tox_action);

        process_events(
            &rx_msg,
            &tx_tox_action,
            &mut model,
            |m| m.domain.friends.len() == 2,
            5,
        );

        // Send Shutdown directly, not through /quit.
        tx_tox_action.send(ToxAction::Shutdown).unwrap();
        handle.await.unwrap();
    }

    // Reload and check.
    {
        let initial_state = worker::get_initial_state(&Some(savedata_path)).unwrap();

        assert_eq!(
            initial_state.friends.len(),
            2,
            "Expected exactly 2 friends after reloading"
        );

        let pk1 = friend_addresses[0].public_key();
        let pk2 = friend_addresses[1].public_key();
        let pk3 = friend_addresses[2].public_key();

        let has_friend1 = initial_state
            .friends
            .iter()
            .any(|f| f.public_key == Some(pk1));
        assert!(has_friend1, "Should contain Friend 1");

        let has_friend3 = initial_state
            .friends
            .iter()
            .any(|f| f.public_key == Some(pk3));
        assert!(has_friend3, "Should contain Friend 3");

        let has_friend2 = initial_state
            .friends
            .iter()
            .any(|f| f.public_key == Some(pk2));
        assert!(!has_friend2, "Should NOT contain Friend 2 (deleted)");
    }
}

#[tokio::test]
async fn test_conference_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let savedata_path = temp_dir.path().join("savedata.tox");
    let config_dir = temp_dir.path().to_path_buf();

    let expected_title = "Persistent Conference";

    // Create 2 conferences, title one, delete the other, and save.
    {
        let initial_state = worker::get_initial_state(&Some(savedata_path.clone())).unwrap();

        let domain = DomainState::new(
            initial_state.tox_id,
            initial_state.name,
            initial_state.status_message,
            initial_state.status_type,
        );
        let config = Config {
            start_port: 33446,
            end_port: 44446,
            udp_enabled: false,
            ..Default::default()
        };

        let mut model = Model::new(domain, config.clone(), config.clone());
        model.reconcile(
            initial_state.friends,
            initial_state.groups,
            initial_state.conferences,
        );

        let (tx_msg, rx_msg) = mpsc::channel();
        let (tx_tox_action, rx_tox_action) = mpsc::channel();
        let (tx_io, _rx_io) = mpsc::channel();

        let handle = worker::spawn_tox(
            tx_msg.clone(),
            tx_io,
            rx_tox_action,
            Some(savedata_path.clone()),
            &config,
            vec![],
            config_dir.clone(),
        );

        process_events(
            &rx_msg,
            &tx_tox_action,
            &mut model,
            |m| m.domain.tox_id != Address([0; 38]),
            5,
        );

        run_command(&mut model, "/conference create", &tx_tox_action);
        process_events(
            &rx_msg,
            &tx_tox_action,
            &mut model,
            |m| {
                m.domain
                    .conversations
                    .keys()
                    .filter(|k| matches!(k, WindowId::Conference(_)))
                    .count()
                    == 1
            },
            5,
        );

        run_command(&mut model, "/conference create", &tx_tox_action);
        process_events(
            &rx_msg,
            &tx_tox_action,
            &mut model,
            |m| {
                m.domain
                    .conversations
                    .keys()
                    .filter(|k| matches!(k, WindowId::Conference(_)))
                    .count()
                    == 2
            },
            5,
        );

        let mut conf_ids: Vec<WindowId> = model
            .domain
            .conversations
            .keys()
            .filter(|k| matches!(k, WindowId::Conference(_)))
            .cloned()
            .collect();
        // Sort, so the order is deterministic.
        conf_ids.sort_by_key(|k| {
            if let WindowId::Conference(c) = k {
                c.0
            } else {
                [0u8; 32]
            }
        });

        let conf1_win = conf_ids[0];
        let conf2_win = conf_ids[1];

        let pos2 = model
            .ui
            .window_ids
            .iter()
            .position(|&w| w == conf2_win)
            .expect("Conf 2 window not found");
        model.set_active_window(pos2);

        run_command(
            &mut model,
            &format!("/topic {}", expected_title),
            &tx_tox_action,
        );

        let pos1 = model
            .ui
            .window_ids
            .iter()
            .position(|&w| w == conf1_win)
            .expect("Conf 1 window not found");
        model.set_active_window(pos1);

        run_command(&mut model, "/close", &tx_tox_action);

        process_events(
            &rx_msg,
            &tx_tox_action,
            &mut model,
            |m| !m.domain.conversations.contains_key(&conf1_win),
            5,
        );

        tx_tox_action.send(ToxAction::Shutdown).unwrap();
        handle.await.unwrap();
    }

    // Reload and check.
    {
        let initial_state = worker::get_initial_state(&Some(savedata_path)).unwrap();

        assert_eq!(
            initial_state.conferences.len(),
            1,
            "Expected exactly 1 conference after reloading"
        );

        let title = initial_state.conferences[0]
            .title
            .as_ref()
            .expect("Conference should have a title");
        assert_eq!(title, expected_title, "Conference title should persist");
    }
}
