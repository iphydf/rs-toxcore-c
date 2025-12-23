use rand::SeedableRng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tox_sequenced::SequenceSession;
use tox_sequenced::protocol::{Packet, TimestampMs};
use tox_sequenced::time::ManualTimeProvider;

#[test]
fn test_transport_layer_time_sync() {
    let now_alice = Instant::now();
    let tp_alice = Arc::new(ManualTimeProvider::new(now_alice, 1000)); // Alice is at T=1000ms
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now_alice, tp_alice.clone(), &mut rng);

    let now_bob = now_alice + Duration::from_millis(50); // Bob starts 50ms later in real time
    let tp_bob = Arc::new(ManualTimeProvider::new(now_bob, 2000)); // Bob is at T=2000ms
    let mut bob = SequenceSession::new_at(now_bob, tp_bob.clone(), &mut rng);

    // 1. Force a Ping from Alice by advancing time past PING_INTERVAL
    let now_alice_ping = now_alice + Duration::from_secs(6);
    tp_alice.set_time(now_alice_ping, 7000);
    let packets = alice.get_packets_to_send(now_alice_ping, 7000);
    let ping = packets
        .iter()
        .find(|p| matches!(p, Packet::Ping { .. }))
        .unwrap();

    if let Packet::Ping { t1 } = ping {
        assert_eq!(*t1, TimestampMs(7000));
    } else {
        panic!("Expected Ping");
    }

    // 2. Bob receives Alice's Ping and replies with Pong
    // Alice pinged at RT=6s. Bob receives at RT=6.05s.
    // Bob's system time at RT=6s was 2000 + (6s - 0.05s) = 7950.
    // At RT=6.05s, Bob's system time is 8000.
    let now_bob_recv = now_bob + Duration::from_secs(6);
    tp_bob.set_time(now_bob_recv, 8000);

    let replies = bob.handle_packet(ping.clone(), now_bob_recv);
    let pong = replies
        .iter()
        .find(|p| matches!(p, Packet::Pong { .. }))
        .unwrap();

    if let Packet::Pong { t1, t2, t3 } = pong {
        assert_eq!(*t1, TimestampMs(7000)); // Alice's t1
        // Bob's t2 and t3 should be jittered by ±5ms
        let diff = t2.0 - 8000;
        assert!((-5..=5).contains(&diff), "Jitter {} out of range", diff);
        assert_eq!(*t2, *t3); // RTT-preserving: t2 and t3 must be shifted by same amount
    } else {
        panic!("Expected Pong");
    }

    // 3. Alice receives Bob's Pong
    // Travel time 50ms. Alice receives at RT=6.05s + 50ms = 6.1s.
    // Alice's system time at RT=6.1s: 1000 + 6.1s = 7100.
    let now_alice_recv = now_alice + Duration::from_millis(6100);
    tp_alice.set_time(now_alice_recv, 7100);

    // Capture jitter from pong for assertion
    let jitter = if let Packet::Pong { t2, .. } = pong {
        t2.0 - 8000
    } else {
        0
    };

    alice.handle_packet(pong.clone(), now_alice_recv);

    // 4. Verify Alice's calculated offset
    // Offset = ((t2 - t1) + (t3 - t4)) / 2
    // t1=7000, t2=8000+j, t3=8000+j, t4=7100
    // Offset = ((8000+j - 7000) + (8000+j - 7100)) / 2
    // Offset = (1000+j + 900+j) / 2 = 950 + j

    // Alice started at 1000 (RT 0). Bob started at 2000 (RT 50ms).
    // Bob's time at RT 0 was 1950.
    // Difference = 1950 - 1000 = 950ms.
    assert_eq!(alice.clock_offset(), 950 + jitter);
}

#[test]
fn test_anti_fingerprinting_jitter_distribution() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 1000));
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let mut session = SequenceSession::new_at(now, tp.clone(), &mut rng);

    let mut jitters = std::collections::HashSet::new();

    for i in 0..100 {
        let ping = Packet::Ping {
            t1: TimestampMs(2000 + i),
        };
        let replies = session.handle_packet(ping, now);
        if let Some(Packet::Pong { t2, .. }) = replies.first() {
            let jitter = t2.0 - 1000;
            assert!((-5..=5).contains(&jitter));
            jitters.insert(jitter);
        }
    }

    // With 100 samples and ±5 range (11 possible values), we should see most of them.
    assert!(
        jitters.len() > 5,
        "Jitter distribution too narrow: {:?}",
        jitters
    );
}
