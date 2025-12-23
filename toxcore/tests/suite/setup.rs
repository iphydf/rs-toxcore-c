use std::thread;
use std::time::{Duration, Instant};
use toxcore::tox::*;

pub struct TestLogger {
    pub index: u32,
}

impl ToxLogger for TestLogger {
    fn log(&mut self, level: ToxLogLevel, file: &str, line: u32, func: &str, message: &str) {
        if level == ToxLogLevel::TOX_LOG_LEVEL_TRACE {
            return;
        }
        eprintln!(
            "[#{}] {:?} {}:{}\t{}:\t{}",
            self.index, level, file, line, func, message
        );
    }
}

pub struct ToxEntry {
    pub tox: Tox,
    pub group: Option<GroupNumber>,
}

pub struct TestHarness {
    pub toxes: Vec<ToxEntry>,
}

impl TestHarness {
    pub fn new() -> Self {
        TestHarness { toxes: Vec::new() }
    }

    pub fn add_tox(&mut self) {
        let index = self.toxes.len() as u32;
        let logger = TestLogger { index };

        let mut opts = Options::new().unwrap();
        opts.set_ipv6_enabled(true);
        opts.set_local_discovery_enabled(false);
        let port = 43445 + index as u16 * 2;
        opts.set_start_port(port);
        opts.set_end_port(port + 10);
        opts.set_tcp_port(port);
        opts.set_logger(logger);

        let tox = Tox::new(opts).unwrap();
        self.toxes.push(ToxEntry { tox, group: None });
    }

    pub fn connect(&mut self, i: usize, j: usize) {
        let pk_i = self.toxes[i].tox.public_key();
        let pk_j = self.toxes[j].tox.public_key();

        self.toxes[i].tox.friend_add_norequest(&pk_j).unwrap();
        self.toxes[j].tox.friend_add_norequest(&pk_i).unwrap();

        let dht_key = self.toxes[i].tox.dht_id();
        let port = self.toxes[i].tox.udp_port().unwrap();

        self.toxes[j]
            .tox
            .add_tcp_relay("127.0.0.1", port, &dht_key)
            .unwrap();
        self.toxes[j]
            .tox
            .bootstrap("127.0.0.1", port, &dht_key)
            .unwrap();
    }

    pub fn setup_groups(&mut self) {
        // 1. Create group on toxes[0]
        let gn0 = self.toxes[0]
            .tox
            .group_new(
                ToxGroupPrivacyState::TOX_GROUP_PRIVACY_STATE_PRIVATE,
                b"MainGroup",
                b"Alice",
            )
            .unwrap()
            .get_number();
        self.toxes[0].group = Some(gn0);

        // 2. Invite others
        use std::sync::{Arc, Mutex};
        type GroupInvite = (FriendNumber, Vec<u8>);
        struct InviteHandler {
            invites: Arc<Mutex<Vec<GroupInvite>>>,
        }
        impl ToxHandler for InviteHandler {
            fn on_group_invite(&mut self, friend: FriendNumber, invite_data: &[u8], _: &[u8]) {
                self.invites
                    .lock()
                    .unwrap()
                    .push((friend, invite_data.to_vec()));
            }
        }

        let invites = Arc::new(Mutex::new(Vec::new()));
        let mut handler = InviteHandler {
            invites: invites.clone(),
        };

        for i in 1..self.toxes.len() {
            let pk = self.toxes[i].tox.public_key();
            let f = self.toxes[0].tox.lookup_friend(&pk).unwrap();
            self.toxes[0].tox.group(gn0).invite_friend(&f).unwrap();

            // Wait for invite
            let start = Instant::now();
            let mut invite_received = None;
            while Instant::now().duration_since(start) < Duration::from_secs(5) {
                self.iterate(&mut handler);
                let mut inv = invites.lock().unwrap();
                if !inv.is_empty() {
                    invite_received = Some(inv.remove(0));
                    break;
                }
            }
            let (friend_num, data) =
                invite_received.expect("Did not receive group invite in setup");
            // Need Friend object for invite_accept
            let friend = self.toxes[i].tox.friend(friend_num);

            // Join
            let name = format!("Peer{}", i);
            let gn = self.toxes[i]
                .tox
                .group_invite_accept(&friend, &data, name.as_bytes(), None)
                .unwrap()
                .get_number();
            self.toxes[i].group = Some(gn);
        }

        // Wait for everyone to be connected to the group and see each other's names
        let expected_count = self.toxes.len();
        let mut expected_names = vec![b"Alice".to_vec()];
        for i in 1..self.toxes.len() {
            expected_names.push(format!("Peer{}", i).into_bytes());
        }

        let start = Instant::now();
        let mut connected = false;
        while Instant::now().duration_since(start) < Duration::from_secs(15) {
            self.iterate(&mut handler);

            let all_connected = self.toxes.iter().all(|t| {
                if let Some(gn) = t.group {
                    let g = t.tox.group(gn);
                    let mut found_names = Vec::new();
                    for i in 0..10 {
                        if let Ok(name) = g.peer_name(GroupPeerNumber(i)) {
                            found_names.push(name);
                        }
                    }

                    // Check if all expected names are present in this tox's view of the group
                    expected_names
                        .iter()
                        .all(|expected| found_names.contains(expected))
                        && found_names.len() >= expected_count
                } else {
                    false
                }
            });

            if all_connected {
                connected = true;
                break;
            }
        }

        if !connected {
            println!(
                "WARNING: setup_groups timed out waiting for full mesh connectivity and names"
            );
        }

        // Let the group stabilize further
        for _ in 0..20 {
            self.iterate(&mut handler);
        }
    }

    pub fn iterate<H: ToxHandler>(&self, handler: &mut H) {
        let mut min_interval = 50;
        for entry in &self.toxes {
            entry.tox.iterate(handler);
            let interval = entry.tox.iteration_interval();
            if interval < min_interval {
                min_interval = interval;
            }
        }
        thread::sleep(Duration::from_millis(min_interval as u64));
    }

    pub fn iterate_specific<H: ToxHandler>(&self, h1: &mut H, h2: &mut H) {
        let mut min_interval = 50;

        for (i, entry) in self.toxes.iter().enumerate() {
            let interval = if i == 0 {
                entry.tox.iterate(h1);
                entry.tox.iteration_interval()
            } else if i == 1 {
                entry.tox.iterate(h2);
                entry.tox.iteration_interval()
            } else {
                struct DummyHandler;
                impl ToxHandler for DummyHandler {}
                let mut dummy = DummyHandler;
                entry.tox.iterate(&mut dummy);
                entry.tox.iteration_interval()
            };
            if interval < min_interval {
                min_interval = interval;
            }
        }

        thread::sleep(Duration::from_millis(min_interval as u64));
    }

    pub fn wait_for_connection(&self, i: usize, j: usize) {
        let pk_j = self.toxes[j].tox.public_key();
        struct ConnHandler {
            connected: bool,
            pk: PublicKey,
        }
        impl ToxHandler for ConnHandler {
            fn on_friend_message(&mut self, _: FriendNumber, _: MessageType, _: &[u8]) {}
        }

        let mut handler = ConnHandler {
            connected: false,
            pk: pk_j,
        };

        let start = Instant::now();
        let timeout = Duration::from_secs(30);
        while Instant::now().duration_since(start) < timeout {
            self.iterate(&mut handler);
            let f_res = self.toxes[i].tox.lookup_friend(&handler.pk);
            if let Ok(friend) = f_res
                && let Ok(conn) = friend.connection_status()
                && conn != ToxConnection::TOX_CONNECTION_NONE
            {
                handler.connected = true;
                break;
            }
        }

        assert!(
            handler.connected,
            "Timeout waiting for connection between {} and {}",
            i, j
        );
    }
}
