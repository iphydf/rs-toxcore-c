use std::time::{Duration, Instant};
use tox_sequenced::outgoing::OutgoingMessage;
use tox_sequenced::protocol::{FragmentCount, FragmentIndex, MessageType};

#[test]
fn test_outgoing_message_ack_tracking() {
    let now = Instant::now();
    let data = vec![1, 2, 3];
    let mut msg = OutgoingMessage::new(MessageType::MerkleNode, data, 1, now).unwrap();

    assert!(!msg.all_acked());
    assert!(!msg.is_acked(FragmentIndex(0)));

    assert!(msg.set_acked(FragmentIndex(0)));
    assert!(msg.is_acked(FragmentIndex(0)));
    assert!(!msg.set_acked(FragmentIndex(0))); // Already acked
    assert_eq!(msg.acked_count, FragmentCount(1));

    msg.set_acked(FragmentIndex(1));
    msg.set_acked(FragmentIndex(2));
    assert!(msg.all_acked());
}

#[test]
fn test_prepare_fragment_for_send() {
    let now = Instant::now();
    let data = vec![1];
    let mut msg = OutgoingMessage::new(MessageType::MerkleNode, data, 1, now).unwrap();

    let (data, total, is_retrans, was_in_flight) =
        msg.prepare_fragment_for_send(FragmentIndex(0), now, 100, now, false);
    assert_eq!(data, vec![1]);
    assert_eq!(total, FragmentCount(1));
    assert!(!is_retrans);
    assert!(!was_in_flight);
    assert_eq!(msg.in_flight_queue.len(), 1);
    assert_eq!(msg.fragment_states[0].retransmit_count, 0);

    // Retransmit
    let later = now + Duration::from_secs(1);
    let (_, _, is_retrans, was_in_flight) =
        msg.prepare_fragment_for_send(FragmentIndex(0), later, 200, now, false);
    assert!(is_retrans);
    assert!(was_in_flight);
}

#[test]
fn test_bitset_logic_large() {
    let now = Instant::now();
    let data = vec![0; 100]; // 100 fragments if payload_mtu = 1
    let mut msg = OutgoingMessage::new(MessageType::MerkleNode, data, 1, now).unwrap();

    assert!(msg.set_acked(FragmentIndex(0)));
    assert!(msg.set_acked(FragmentIndex(63)));
    assert!(msg.set_acked(FragmentIndex(64)));
    assert!(msg.set_acked(FragmentIndex(99)));

    assert!(msg.is_acked(FragmentIndex(0)));
    assert!(msg.is_acked(FragmentIndex(63)));
    assert!(msg.is_acked(FragmentIndex(64)));
    assert!(msg.is_acked(FragmentIndex(99)));
    assert!(!msg.is_acked(FragmentIndex(1)));
    assert!(!msg.is_acked(FragmentIndex(65)));
}

#[test]
fn test_on_ack_hole_detection() {
    let now = Instant::now();
    let data = vec![0u8; 10000]; // Multi-fragment message
    let payload_mtu = 1000;
    let mut msg = OutgoingMessage::new(MessageType::MerkleNode, data, payload_mtu, now).unwrap();

    // Send fragments 0, 1, 2, 3, 4
    for i in 0..5 {
        msg.prepare_fragment_for_send(FragmentIndex(i), now, 0, now, false);
    }

    // Receive ACK for 0 and 1, then selective ACK for 3 and 4 (Gap at 2)
    let base_index = FragmentIndex(2); // Cumulative ACK up to 1
    // Bitmask for indices after base_index (which is 2)
    // bit 0 -> base_index + 1 = 3
    // bit 1 -> base_index + 2 = 4
    let bitmask = (1 << 0) | (1 << 1);

    let res = msg.on_ack(base_index, bitmask, now, 0);

    assert_eq!(msg.highest_cumulative_ack, FragmentIndex(2));
    assert!(msg.is_acked(FragmentIndex(0)));
    assert!(msg.is_acked(FragmentIndex(1)));
    assert!(!msg.is_acked(FragmentIndex(2)));
    assert!(msg.is_acked(FragmentIndex(3)));
    assert!(msg.is_acked(FragmentIndex(4)));

    // Hole at index 2. We received ACKs for 3 and 4 (2 fragments after hole).
    // Fast retransmit usually triggers after 3 fragments after hole in this implementation.
    assert!(
        !res.loss_detected,
        "Should not detect loss with only 2 fragments after hole"
    );

    // Send more fragments 5, 6
    msg.prepare_fragment_for_send(FragmentIndex(5), now, 0, now, false);
    msg.prepare_fragment_for_send(FragmentIndex(6), now, 0, now, false);

    // Now receive ACK for 5 too.
    // base_index still 2.
    // bitmask bits: 3, 4, 5
    let bitmask_with_5 = (1 << 0) | (1 << 1) | (1 << 2);
    let res2 = msg.on_ack(base_index, bitmask_with_5, now, 0);

    assert!(
        res2.loss_detected,
        "Loss should be detected after 3 fragments after hole"
    );
    assert!(msg.retransmit_queue.contains(&FragmentIndex(2)));
}

#[test]
fn test_fast_retransmit_logic() {
    let now = Instant::now();
    let data = vec![0u8; 10000];
    let mut msg = OutgoingMessage::new(MessageType::MerkleNode, data, 1000, now).unwrap();

    msg.prepare_fragment_for_send(FragmentIndex(0), now, 0, now, false);
    msg.prepare_fragment_for_send(FragmentIndex(1), now, 0, now, false);
    msg.prepare_fragment_for_send(FragmentIndex(2), now, 0, now, false);
    msg.prepare_fragment_for_send(FragmentIndex(3), now, 0, now, false);

    // base_index = 0 means fragment 0 is not cumulative acked.
    // Duplicate ACK 1: Bob received fragment 1
    msg.on_ack(FragmentIndex(0), 1, now, 0);
    assert_eq!(msg.dup_ack_count, 1);

    // Duplicate ACK 2: Bob received fragment 2
    msg.on_ack(FragmentIndex(0), 3, now, 0);
    assert_eq!(msg.dup_ack_count, 2);

    // Duplicate ACK 3: Bob received fragment 3 -> Should trigger fast retransmit
    let res = msg.on_ack(FragmentIndex(0), 7, now, 0);
    assert_eq!(msg.dup_ack_count, 3);
    assert!(res.loss_detected);
    assert!(msg.retransmit_queue.contains(&FragmentIndex(0)));
}

#[test]
fn test_gap_bitmask() {
    let now = Instant::now();
    let mut msg =
        OutgoingMessage::new(MessageType::MerkleNode, vec![0; 100 * 100], 100, now).unwrap();

    for i in 0..100 {
        msg.prepare_fragment_for_send(FragmentIndex(i), now, 0, now, false);
    }

    // Bob receives 0..10 and 60.
    // Bit 48 corresponds to 11 + 1 + 48 = 60.
    msg.on_ack(FragmentIndex(11), 1 << 48, now, 0);

    assert!(
        msg.is_acked(FragmentIndex(60)),
        "Fragment 60 should be marked as acked via bitmask"
    );
}

#[test]
fn test_on_ack_no_double_counting() {
    let now = Instant::now();
    let payload_mtu = 1000;
    let data = vec![0u8; 10000];
    let mut msg = OutgoingMessage::new(MessageType::MerkleNode, data, payload_mtu, now).unwrap();

    for i in 0..10 {
        msg.prepare_fragment_for_send(FragmentIndex(i), now, 0, now, false);
    }

    // base_index = 0
    // bitmask includes 5 (bit 4)
    let bitmask = 1 << 4;
    let res = msg.on_ack(FragmentIndex(0), bitmask, now, 0);

    // Fragment 5 should only be counted once.
    assert_eq!(
        res.newly_delivered_bytes, payload_mtu,
        "Should only count fragment 5 once"
    );
}

#[test]
fn test_on_ack_nack_fill_bug() {
    let now = Instant::now();
    let payload_mtu = 1000;
    let data = vec![0u8; 200 * 1000]; // 200 fragments
    let mut msg = OutgoingMessage::new(MessageType::MerkleNode, data, payload_mtu, now).unwrap();

    for i in 0..200 {
        msg.prepare_fragment_for_send(FragmentIndex(i), now, 0, now, false);
    }

    // Receiver has received 0..10 and 20.
    // base_index = 11.
    // bit 8 is index 11 + 1 + 8 = 20.
    msg.on_ack(FragmentIndex(11), 1 << 8, now, 0);

    // Fragments between 11 and 19 should NOT be acked.
    assert!(
        !msg.is_acked(FragmentIndex(15)),
        "Fragment 15 should NOT be acked"
    );
}

#[test]
fn test_bitmask_triggers_loss_far_ahead() {
    let now = Instant::now();
    let payload_mtu = 1000;
    let data = vec![0u8; 100 * 1000];
    let mut msg = OutgoingMessage::new(MessageType::MerkleNode, data, payload_mtu, now).unwrap();

    // Send 0..50
    for i in 0..50 {
        msg.prepare_fragment_for_send(FragmentIndex(i), now, 0, now, false);
    }

    // ACK: base=10.
    // We receive ACKs for fragments 20, 21, 22.
    // bitmask bits: 8 (idx 19), 9 (idx 20), 10 (idx 21), 11 (idx 22)
    // base_index 10. bit 0 is 11.
    // 20 is bit 8.
    let bitmask = (1 << 8) | (1 << 9) | (1 << 10);
    let res = msg.on_ack(FragmentIndex(10), bitmask, now, 0);

    assert!(
        res.loss_detected,
        "Loss should be detected for fragment 10 because we received 3 fragments (20, 21, 22) after it"
    );
    assert!(msg.retransmit_queue.contains(&FragmentIndex(10)));
}

#[test]
fn test_phantom_ack_bug() {
    let now = Instant::now();
    let payload_mtu = 1000;
    let data = vec![0u8; 200 * 1000];
    let mut msg = OutgoingMessage::new(MessageType::MerkleNode, data, payload_mtu, now).unwrap();

    for i in 0..200 {
        msg.prepare_fragment_for_send(FragmentIndex(i), now, 0, now, false);
    }

    // Receiver has received 11 and 20 only.
    // Logic should NOT mark anything else as Received.
    msg.on_ack(FragmentIndex(11), 1 << 8, now, 0);

    assert!(
        !msg.is_acked(FragmentIndex(15)),
        "Fragment 15 should NOT be acked just because fragment 20 was acked."
    );
}

// Helper to create a dummy message
fn create_dummy_message(num_fragments: u16) -> OutgoingMessage {
    let payload = vec![0u8; num_fragments as usize * 100];
    OutgoingMessage::new(
        MessageType::MerkleNode,
        payload,
        100, // MTU
        Instant::now(),
    )
    .unwrap()
}

// Helper to simulate sending a fragment
fn send_fragment(msg: &mut OutgoingMessage, idx: u16, now: Instant) {
    msg.prepare_fragment_for_send(
        FragmentIndex(idx),
        now,
        0,              // delivered bytes
        Instant::now(), // last delivery
        false,          // app limited
    );
}

#[test]
fn test_fast_retransmit_with_sacks() {
    // Scenario:
    // Message has 5 fragments: 0, 1, 2, 3, 4
    // We send all of them.
    // 0 is lost.
    // We receive SACKs for 1, then 2, then 3.
    // This should trigger Fast Retransmit for 0 on the 3rd duplicate ACK (the ACK for 3).
    //
    // BUG REPRO:
    // If we reset dup_ack_count whenever "newly_delivered_bytes > 0", then:
    // 1. ACK(base=0, SACK=1) -> delivered 1 fragment. dup_ack_count resets to 0?
    // 2. ACK(base=0, SACK=1,2) -> delivered 1 fragment. dup_ack_count resets to 0?
    // 3. ACK(base=0, SACK=1,2,3) -> delivered 1 fragment. dup_ack_count resets to 0?
    // Result: dup_ack_count never reaches 3, 0 is never retransmitted until Timeout.

    let start = Instant::now();
    let mut msg = create_dummy_message(5);

    // Send all 5 fragments
    for i in 0..5 {
        send_fragment(&mut msg, i, start);
    }

    // 1. Receive ACK for Fragment 1 (Fragment 0 is missing)
    // base_index=0, bitmask bit 0 is index 1.
    let now = start + Duration::from_millis(10);
    let res1 = msg.on_ack(
        FragmentIndex(0),
        1, // Bit 0 set (Index 1)
        now,
        0,
    );
    assert_eq!(res1.newly_delivered_bytes, 100, "Should ack frag 1");

    // 2. Receive ACK for Fragment 2 (Cumulative 0, SACK 1, 2)
    // Bitmask: bit 0 (idx 1), bit 1 (idx 2) -> 1 | 2 = 3
    let now = start + Duration::from_millis(20);
    let res2 = msg.on_ack(
        FragmentIndex(0),
        3, // Bits 0, 1 set
        now,
        100,
    );
    assert_eq!(res2.newly_delivered_bytes, 100, "Should ack frag 2");

    // 3. Receive ACK for Fragment 3 (Cumulative 0, SACK 1, 2, 3)
    // Bitmask: 1 | 2 | 4 = 7
    let now = start + Duration::from_millis(30);
    let res3 = msg.on_ack(FragmentIndex(0), 7, now, 200);
    assert_eq!(res3.newly_delivered_bytes, 100, "Should ack frag 3");

    // 4. Receive ACK for Fragment 4 (Cumulative 0, SACK 1, 2, 3, 4)
    // Bitmask: 15
    let now = start + Duration::from_millis(40);
    msg.on_ack(FragmentIndex(0), 15, now, 300);

    // Check if Fragment 0 was queued for retransmission
    let queued_0 = msg.retransmit_queue.contains(&FragmentIndex(0));
    assert!(
        queued_0,
        "Fragment 0 should be fast-retransmitted after 3 dup ACKs with SACKs"
    );
    // res3 should have triggered it. res4 adds to dup_ack_count (making it 4) but doesn't trigger again (threshold == 3).
    assert!(
        res3.loss_detected,
        "Loss should be detected on the 3rd duplicate ACK (res3)"
    );
}

#[test]
fn test_spurious_fast_retransmit_on_duplicate_ack() {
    let now = Instant::now();
    // Helper to create a dummy message
    fn create_dummy_message(num_fragments: u16) -> OutgoingMessage {
        let payload = vec![0u8; num_fragments as usize * 100];
        OutgoingMessage::new(
            MessageType::MerkleNode,
            payload,
            100, // MTU
            Instant::now(),
        )
        .unwrap()
    }

    // Helper to simulate sending a fragment
    fn send_fragment(msg: &mut OutgoingMessage, idx: u16, now: Instant) {
        msg.prepare_fragment_for_send(
            FragmentIndex(idx),
            now,
            0,              // delivered bytes
            Instant::now(), // last delivery
            false,          // app limited
        );
    }

    let mut msg = create_dummy_message(5);

    // Send all 5 fragments
    for i in 0..5 {
        send_fragment(&mut msg, i, now);
    }

    // 1. Receive first duplicate ACK (base=0, SACK=1)
    msg.on_ack(FragmentIndex(0), 1, now, 0);
    assert_eq!(msg.dup_ack_count, 1);

    // 2. Receive exact same ACK again (network duplication)
    msg.on_ack(FragmentIndex(0), 1, now, 0);
    assert_eq!(
        msg.dup_ack_count, 1,
        "Dup ACK count should not increment for identical ACKs with no new info"
    );

    // 3. Receive exact same ACK again -> SHOULD NOT TRIGGER Fast Retransmit
    let res = msg.on_ack(FragmentIndex(0), 1, now, 0);

    assert_eq!(msg.dup_ack_count, 1, "Dup ACK count should still be 1");
    assert!(
        !res.loss_detected,
        "Should not trigger retransmission for duplicated identical ACK packets"
    );
}

#[test]
fn test_in_flight_leak_on_retransmission() {
    let now = Instant::now();
    let mut msg =
        OutgoingMessage::new(MessageType::MerkleNode, vec![0u8; 2000], 1000, now).unwrap();

    // 1. Send fragment 0
    let _ = msg.prepare_fragment_for_send(FragmentIndex(0), now, 0, now, false);
    let mut in_flight = 1000;

    // 2. Retransmit fragment 0 (e.g. after a timeout)
    let later = now + Duration::from_secs(1);
    let (_, _, _, was_in_flight) =
        msg.prepare_fragment_for_send(FragmentIndex(0), later, 0, now, false);
    if !was_in_flight {
        in_flight += 1000;
    }

    assert_eq!(
        msg.in_flight_queue.len(),
        2,
        "Should have 2 entries in in_flight_queue"
    );

    // 3. Receive ACK for fragment 0
    let ack_now = later + Duration::from_millis(100);
    let res = msg.on_ack(FragmentIndex(1), 0, ack_now, 0);

    // newly_completed_in_flight_bytes should be 1000 (unique)
    in_flight -= res.newly_completed_in_flight_bytes;

    // We WANT this to pass now.
    assert_eq!(
        in_flight, 0,
        "In-flight bytes leaked! Expected 0, got {}",
        in_flight
    );
    assert_eq!(msg.in_flight_queue.len(), 0, "Queue should be empty");
}

// end of tests
