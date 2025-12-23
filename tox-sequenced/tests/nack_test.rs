use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::SequenceSession;
use tox_sequenced::protocol::{FragmentCount, FragmentIndex, MessageId, Packet};

#[test]
fn test_nack_generation_on_hole() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);
    let msg_id = MessageId(42);

    // Receive fragment 100, but fragment 0 is missing.
    bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(100),
            total_fragments: FragmentCount(150),
            data: vec![1, 2, 3],
        },
        now,
    );

    // Large holes trigger NACK immediately (in the next get_packets_to_send call)
    let packets = bob.get_packets_to_send(now, 0);

    let nacks: Vec<_> = packets
        .iter()
        .filter_map(|p| {
            if let Packet::Nack(n) = p {
                Some(n)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(nacks.len(), 1, "Should have generated one NACK");
    assert_eq!(nacks[0].message_id, msg_id);
    assert!(nacks[0].missing_indices.contains(&FragmentIndex(0)));
}

#[test]
fn test_nack_cleared_by_completion() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);
    let msg_id = MessageId(42);

    // Hole: 0 missing, 1 received
    bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(1),
            total_fragments: FragmentCount(2),
            data: vec![1],
        },
        now,
    );

    // Fill the hole
    bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(2),
            data: vec![0],
        },
        now,
    );

    // Wait long enough for a NACK if it were still pending
    let later = now + Duration::from_millis(150);
    let packets = bob.get_packets_to_send(later, 0);

    let nacks: Vec<_> = packets
        .iter()
        .filter(|p| matches!(p, Packet::Nack(_)))
        .collect();

    assert!(
        nacks.is_empty(),
        "NACK should have been cleared after message completion"
    );
}

#[test]
fn test_nack_not_sent_too_early() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);
    let msg_id = MessageId(42);

    // Hole: 0 missing, 1 received
    bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(1),
            total_fragments: FragmentCount(5),
            data: vec![1],
        },
        now,
    );

    // Only 10ms passed, too early for NACK (min 20ms or RTT/2)
    let bit_later = now + Duration::from_millis(10);
    let packets = bob.get_packets_to_send(bit_later, 0);

    let nacks: Vec<_> = packets
        .iter()
        .filter(|p| matches!(p, Packet::Nack(_)))
        .collect();

    assert!(
        nacks.is_empty(),
        "NACK should not be sent before the reordering delay"
    );
}
