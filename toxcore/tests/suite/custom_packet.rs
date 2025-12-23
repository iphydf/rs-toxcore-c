use super::setup::TestHarness;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use toxcore::tox::*;

pub fn subtest_friend_custom_packets(harness: &mut TestHarness) {
    println!("Running subtest_friend_custom_packets...");
    struct PacketHandler {
        lossy: Arc<Mutex<Option<Vec<u8>>>>,
        lossless: Arc<Mutex<Option<Vec<u8>>>>,
    }
    impl ToxHandler for PacketHandler {
        fn on_friend_lossy_packet(&mut self, _: FriendNumber, data: &[u8]) {
            if data[0] == 200 {
                // Check custom ID to filter out AV packets if any
                *self.lossy.lock().unwrap() = Some(data.to_vec());
            }
        }
        fn on_friend_lossless_packet(&mut self, _: FriendNumber, data: &[u8]) {
            if data[0] == 160 {
                *self.lossless.lock().unwrap() = Some(data.to_vec());
            }
        }
    }

    let lossy = Arc::new(Mutex::new(None));
    let lossless = Arc::new(Mutex::new(None));
    let mut handler = PacketHandler {
        lossy: lossy.clone(),
        lossless: lossless.clone(),
    };

    let pk1 = harness.toxes[1].tox.public_key();
    let f0 = harness.toxes[0].tox.lookup_friend(&pk1).unwrap();

    // Packet IDs 160-255 are for custom packets.
    // Lossy: 200-254
    // Lossless: 160-191
    let packet_lossy = vec![200u8, 1, 2, 3];
    let packet_lossless = vec![160u8, 4, 5, 6];

    f0.send_lossy_packet(&packet_lossy).unwrap();
    f0.send_lossless_packet(&packet_lossless).unwrap();

    let start = Instant::now();
    while Instant::now().duration_since(start) < Duration::from_secs(5) {
        harness.iterate(&mut handler);
        if lossy.lock().unwrap().is_some() && lossless.lock().unwrap().is_some() {
            break;
        }
    }

    assert_eq!(*lossy.lock().unwrap(), Some(packet_lossy));
    assert_eq!(*lossless.lock().unwrap(), Some(packet_lossless));
}

pub fn subtest_group_custom_packets(harness: &mut TestHarness) {
    println!("Running subtest_group_custom_packets...");
    struct GroupPacketHandler {
        lossy: Arc<Mutex<Option<Vec<u8>>>>,
        lossless: Arc<Mutex<Option<Vec<u8>>>>,
        private_lossy: Arc<Mutex<Option<Vec<u8>>>>,
        private_lossless: Arc<Mutex<Option<Vec<u8>>>>,
    }
    impl ToxHandler for GroupPacketHandler {
        fn on_group_custom_packet(
            &mut self,
            _group: GroupNumber,
            _peer: GroupPeerNumber,
            data: &[u8],
        ) {
            if data[0] == 200 {
                *self.lossy.lock().unwrap() = Some(data.to_vec());
            } else if data[0] == 160 {
                *self.lossless.lock().unwrap() = Some(data.to_vec());
            }
        }
        fn on_group_custom_private_packet(
            &mut self,
            _group: GroupNumber,
            _peer: GroupPeerNumber,
            data: &[u8],
        ) {
            if data[0] == 200 {
                *self.private_lossy.lock().unwrap() = Some(data.to_vec());
            } else if data[0] == 160 {
                *self.private_lossless.lock().unwrap() = Some(data.to_vec());
            }
        }
    }

    let lossy = Arc::new(Mutex::new(None));
    let lossless = Arc::new(Mutex::new(None));
    let private_lossy = Arc::new(Mutex::new(None));
    let private_lossless = Arc::new(Mutex::new(None));

    let mut handler = GroupPacketHandler {
        lossy: lossy.clone(),
        lossless: lossless.clone(),
        private_lossy: private_lossy.clone(),
        private_lossless: private_lossless.clone(),
    };

    let gn0 = harness.toxes[0].group.expect("Group 0 not setup");
    let g0 = harness.toxes[0].tox.group(gn0);
    let _gn1 = harness.toxes[1].group.expect("Group 1 not setup");
    let _g1 = harness.toxes[1].tox.group(_gn1);

    // Need Bob's peer ID for private packets
    let start_wait = Instant::now();
    let mut bob_peer_id: Option<u32> = None;
    while Instant::now().duration_since(start_wait) < Duration::from_secs(5) {
        harness.iterate(&mut handler);
        for i in 0u32..10 {
            if let Ok(name) = g0.peer_name(GroupPeerNumber(i))
                && name == b"Peer1"
            {
                bob_peer_id = Some(i);
                break;
            }
        }
        if bob_peer_id.is_some() {
            break;
        }
    }
    let bob_peer_id = bob_peer_id.expect("Bob not found in group peer list");

    // 3. Wait for connection (msg check or just sleep/retry)
    // We'll just start sending packets.
    let packet_lossy = vec![200u8, 10, 11, 12];
    let packet_lossless = vec![160u8, 13, 14, 15];

    let start = Instant::now();
    let mut success = false;
    while Instant::now().duration_since(start) < Duration::from_secs(10) {
        harness.iterate(&mut handler);

        // Periodically send broadcast
        let _ = g0.send_custom_packet(false, &packet_lossy);
        let _ = g0.send_custom_packet(true, &packet_lossless);

        // Periodically send private
        let _ = g0.send_custom_private_packet(GroupPeerNumber(bob_peer_id), false, &packet_lossy);
        let _ = g0.send_custom_private_packet(GroupPeerNumber(bob_peer_id), true, &packet_lossless);

        if lossy.lock().unwrap().is_some()
            && lossless.lock().unwrap().is_some()
            && private_lossy.lock().unwrap().is_some()
            && private_lossless.lock().unwrap().is_some()
        {
            success = true;
            break;
        }
    }

    assert!(success, "Group custom packets not received");
    assert_eq!(*lossy.lock().unwrap(), Some(packet_lossy.clone()));
    assert_eq!(*lossless.lock().unwrap(), Some(packet_lossless.clone()));
    assert_eq!(*private_lossy.lock().unwrap(), Some(packet_lossy));
    assert_eq!(*private_lossless.lock().unwrap(), Some(packet_lossless));
}
