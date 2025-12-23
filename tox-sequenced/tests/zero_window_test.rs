use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::protocol::{MessageType, Packet};
use tox_sequenced::quota::ReassemblyQuota;
use tox_sequenced::session::SequenceSession;

#[test]
fn test_zero_window_probing() {
    let now_instant = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now_instant, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut now = now_instant;

    // Receiver with enough quota for 3 fragments but not 4
    let quota = ReassemblyQuota::new(4000);
    let mut bob = SequenceSession::with_quota_at(quota, now, tp.clone(), &mut rng);
    let mut alice = SequenceSession::with_congestion_control_at(
        tox_sequenced::congestion::Algorithm::Aimd(tox_sequenced::Aimd::with_cwnd(20.0)),
        now,
        tp,
        &mut rng,
    );

    // 1. Send fragments to Bob until his window is full.
    // Message 1 (3500 bytes, 3 fragments)
    let mid1 = alice
        .send_message_at(MessageType::MerkleNode, &vec![0; 3500], now)
        .unwrap();

    // Deliver fragments 0, 1 to Bob.
    let mut sent = 0;
    for _ in 0..100 {
        let packets = alice.get_packets_to_send(now, 0);
        for p in packets {
            if let Packet::Data {
                message_id,
                fragment_index,
                ..
            } = p
                && message_id == mid1
                && fragment_index.0 < 2
            {
                let replies = bob.handle_packet(p, now);
                for r in replies {
                    alice.handle_packet(r, now);
                }
                sent += 1;
            }
        }
        // Bob delayed ACKs
        for p in bob.get_packets_to_send(now, 0) {
            alice.handle_packet(p, now);
        }
        if sent >= 2 {
            break;
        }
        now += Duration::from_millis(1);
    }

    // Now Bob has 2 fragments of msg 1. Quota used: 3900 (reserved for 3 frags).
    // Avail quota: 4000 - 3900 = 100.
    // Alice is blocked by small rwnd.
    let packets = alice.get_packets_to_send(now, 0);
    let data_packets: Vec<_> = packets
        .iter()
        .filter(|p| matches!(p, Packet::Data { .. }))
        .collect();

    assert!(
        data_packets.is_empty(),
        "Alice should be blocked by small rwnd (100)"
    );

    // 4. Advance time to trigger probe.
    now += Duration::from_secs(2);
    let probe_packets = alice.get_packets_to_send(now, 0);

    assert!(
        !probe_packets.is_empty(),
        "Alice should send a zero-window probe"
    );

    // 5. Open Bob's window for real by delivering EVERYTHING Alice produced.
    for p in probe_packets {
        let replies = bob.handle_packet(p, now);
        for r in replies {
            alice.handle_packet(r, now);
        }
    }

    // Deliver any delayed ACKs from Bob too
    now += Duration::from_millis(100);
    for p in bob.get_packets_to_send(now, 0) {
        alice.handle_packet(p, now);
    }

    // Ensure Bob released quota
    assert!(bob.current_rwnd().0 >= 2);

    // 6. Alice should now be free to send more.
    alice
        .send_message_at(MessageType::MerkleNode, &vec![0; 1000], now)
        .unwrap();
    let final_packets = alice.get_packets_to_send(now, 0);

    assert!(
        final_packets
            .iter()
            .any(|p| matches!(p, Packet::Data { .. })),
        "Alice should resume after window opens"
    );
}
