use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::SequenceSession;
use tox_sequenced::protocol::{MessageType, Packet};

#[test]
fn test_tail_loss_probe() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    // 1. Alice sends a small message (single fragment)
    let data = b"TLP Test".to_vec();
    let _msg_id = alice
        .send_message(MessageType::MerkleNode, &data, Instant::now())
        .unwrap();

    // Alice "sends" it. Might include a Ping.
    let packets = alice.get_packets_to_send(now, 0);
    assert!(!packets.is_empty());
    assert_eq!(
        alice.in_flight(),
        12,
        "In-flight should be 12 after initial send"
    );

    // Find the data packet
    let probe_initial = packets
        .into_iter()
        .find(|p| matches!(p, Packet::Data { .. }))
        .unwrap();

    // We drop it (Tail Loss)
    // bob.handle_packet(probe_initial, now); // DROPPED

    // 2. Alice waits. Standard RTO is 1000ms.
    // TLP should trigger around 1.5 * SRTT.
    // Initial SRTT is 200ms, so TLP at ~300ms.

    let tlp_time = now + Duration::from_millis(400);
    let packets_tlp = alice.get_packets_to_send(tlp_time, 0);
    assert_eq!(
        alice.in_flight(),
        12,
        "In-flight should be 12 after TLP (decrement then increment)"
    );

    // EXPECTATION: Alice sends a probe (the same fragment again) before RTO.
    let probe = packets_tlp
        .into_iter()
        .find(|p| matches!(p, Packet::Data { .. }))
        .expect("Should have sent a Tail Loss Probe at 400ms, well before the 1000ms RTO");

    assert_eq!(
        probe, probe_initial,
        "TLP probe should be identical to the lost packet"
    );

    // 3. Bob receives the probe
    let _replies = bob.handle_packet(probe, tlp_time);

    let mut found = false;
    while let Some(event) = bob.poll_event() {
        if matches!(event, tox_sequenced::SessionEvent::MessageCompleted(..)) {
            found = true;
        }
    }
    assert!(
        found,
        "Bob should have reassembled the message from the probe"
    );

    // Get ACKs from Bob
    let replies = bob.get_packets_to_send(tlp_time, 0);
    assert!(
        !replies.is_empty(),
        "Bob should have produced at least one reply (ACK)"
    );
    assert!(
        replies.iter().any(|p| matches!(p, Packet::Ack(_))),
        "Bob should have produced an ACK"
    );

    // 4. Bob's ACK reaches Alice, clearing in-flight
    for r in replies {
        alice.handle_packet(r, tlp_time);
    }
    assert_eq!(alice.in_flight(), 0, "In-flight should be 0 after ACK");
}

#[test]
fn test_tlp_does_not_collapse_cwnd() {
    use tox_sequenced::{Algorithm, AlgorithmType};
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    // Use AIMD to see CWND clearly (initial CWND is 10)
    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(AlgorithmType::Aimd, rand::SeedableRng::seed_from_u64(0)),
        now,
        tp,
        &mut rng,
    );

    // 1. Alice sends a small message
    alice
        .send_message_at(MessageType::MerkleNode, b"test", now)
        .unwrap();
    let _ = alice.get_packets_to_send(now, 0);
    let initial_cwnd = alice.cwnd();
    assert_eq!(initial_cwnd, 10);

    // 2. Trigger TLP
    let tlp_time = now + Duration::from_millis(400);
    let _ = alice.get_packets_to_send(tlp_time, 0);

    // 3. Verify CWND hasn't collapsed to 1 (which AIMD does on timeout)
    assert_eq!(
        alice.cwnd(),
        10,
        "TLP caused CWND collapse! It should not be treated as a full RTO."
    );
}
