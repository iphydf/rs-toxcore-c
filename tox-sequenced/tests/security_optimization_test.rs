use std::time::Instant;
use tox_sequenced::outgoing::OutgoingMessage;
use tox_sequenced::protocol::{FragmentIndex, MessageType};

#[test]
fn test_bitmask_out_of_bounds_efficiency() {
    let now = Instant::now();
    // Message with only 1 fragment
    let mut msg = OutgoingMessage::new(MessageType::MerkleNode, vec![0u8; 10], 100, now).unwrap();

    // Peer sends ACK with bitmask that points to fragments far beyond.
    // base_index = 0
    // bitmask = u64::MAX (all 64 bits set)
    // This implies fragments 1..64 received.
    // But we only have fragment 0.

    let start = Instant::now();

    msg.on_ack(FragmentIndex(0), u64::MAX, now, 0);

    let duration = start.elapsed();

    // Only fragment 0 is present. is_acked(1) returns true for out-of-bounds.
    assert!(msg.is_acked(FragmentIndex(1)));

    println!("Time taken: {:?}", duration);
}

#[test]
fn test_duplicate_ack_efficiency() {
    let now = Instant::now();
    // Message with 100 fragments
    let mut msg =
        OutgoingMessage::new(MessageType::MerkleNode, vec![0u8; 100 * 100], 100, now).unwrap();

    // Construct many identical ACKs.
    let start = Instant::now();
    for _ in 0..1000 {
        msg.on_ack(FragmentIndex(10), 0, now, 0);
    }
    let duration = start.elapsed();

    assert!(msg.is_acked(FragmentIndex(0)));
    assert!(msg.is_acked(FragmentIndex(9)));

    println!("Time taken for duplicates: {:?}", duration);
}
