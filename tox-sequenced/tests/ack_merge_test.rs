use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::SequenceSession;
use tox_sequenced::protocol::{FragmentCount, FragmentIndex, MessageId, Packet};

#[test]
fn test_ack_merging_logic() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);
    let msg_id = MessageId(42);

    // 1. Receive fragment 0.
    bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(150),
            data: vec![1, 2, 3],
        },
        now,
    );

    // 2. Receive fragment 100. (Creates a hole).
    bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(100),
            total_fragments: FragmentCount(150),
            data: vec![4, 5, 6],
        },
        now,
    );

    // Wait long enough for both ACKs and NACKs to be ready (50ms)
    let later = now + Duration::from_millis(50);
    let packets = bob.get_packets_to_send(later, 0);

    // Filter packets for this message_id
    let msg_packets: Vec<_> = packets
        .into_iter()
        .filter(|p| match p {
            Packet::Ack(ack) => ack.message_id == msg_id,
            Packet::Nack(nack) => nack.message_id == msg_id,
            _ => false,
        })
        .collect();

    // EXPECTATION: A single merged packet.
    // CURRENT REALITY: It will likely be 2 packets (one NACK, one ACK).
    assert_eq!(
        msg_packets.len(),
        1,
        "Should have merged ACK and NACK into a single packet for efficiency. Found: {:?}",
        msg_packets
    );
}

// end of tests
