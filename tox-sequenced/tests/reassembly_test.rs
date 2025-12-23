use std::time::Instant;
use tox_sequenced::MessageReassembler;
use tox_sequenced::protocol::{FragmentCount, FragmentIndex, MessageId};
use tox_sequenced::quota::Priority;

#[test]
fn test_reassembly_basic() {
    let now = Instant::now();
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(3), Priority::Standard, 0, now)
            .unwrap();

    assert!(
        !reassembler
            .add_fragment(FragmentIndex(0), vec![1], now)
            .unwrap()
    );
    assert!(
        !reassembler
            .add_fragment(FragmentIndex(2), vec![3], now)
            .unwrap()
    );
    assert!(
        reassembler
            .add_fragment(FragmentIndex(1), vec![2], now)
            .unwrap()
    );

    let result = reassembler.assemble().unwrap();
    assert_eq!(result, vec![1, 2, 3]);
}

#[test]
fn test_reassembly_duplicate_fragment() {
    let now = Instant::now();
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(2), Priority::Standard, 0, now)
            .unwrap();

    assert!(
        !reassembler
            .add_fragment(FragmentIndex(0), vec![1], now)
            .unwrap()
    );
    assert!(
        !reassembler
            .add_fragment(FragmentIndex(0), vec![1], now)
            .unwrap()
    ); // Duplicate
    assert_eq!(reassembler.received_count(), FragmentCount(1));

    assert!(
        reassembler
            .add_fragment(FragmentIndex(1), vec![2], now)
            .unwrap()
    );
    assert_eq!(reassembler.received_count(), FragmentCount(2));

    let result = reassembler.assemble().unwrap();
    assert_eq!(result, vec![1, 2]);
}

#[test]
fn test_reassembly_out_of_bounds() {
    let now = Instant::now();
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(2), Priority::Standard, 0, now)
            .unwrap();

    assert!(
        reassembler
            .add_fragment(FragmentIndex(2), vec![3], now)
            .is_err()
    );
    assert_eq!(reassembler.received_count(), FragmentCount(0));
}

#[test]
fn test_reassembly_max_size_limit() {
    let now = Instant::now();
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(2), Priority::Standard, 0, now)
            .unwrap();

    // MAX_MESSAGE_SIZE is 1MB
    let big_data = vec![0u8; 1024 * 1024];
    assert!(
        reassembler
            .add_fragment(FragmentIndex(0), big_data, now)
            .is_err()
            || reassembler
                .add_fragment(FragmentIndex(0), vec![0], now)
                .is_err()
    );

    let slightly_less = vec![0u8; 1024 * 1024 - 1];
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(2), Priority::Standard, 0, now)
            .unwrap();
    assert!(
        !reassembler
            .add_fragment(FragmentIndex(0), slightly_less, now)
            .unwrap()
    );
    assert_eq!(reassembler.received_count(), FragmentCount(1));

    // Adding one more byte should fail if it exceeds limit
    assert!(
        reassembler
            .add_fragment(FragmentIndex(1), vec![0, 0], now)
            .is_err()
    );
}

#[test]
fn test_reassembly_inconsistent_size_allowed() {
    let now = Instant::now();
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(2), Priority::Standard, 0, now)
            .unwrap();
    reassembler
        .add_fragment(FragmentIndex(0), vec![0; 10], now)
        .unwrap();
    // Different size - now allowed
    assert!(
        reassembler
            .add_fragment(FragmentIndex(1), vec![0; 5], now)
            .is_ok()
    );
    assert!(reassembler.assemble().is_some());
}

#[test]
fn test_create_ack_bitmask() {
    let now = Instant::now();
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(100), Priority::Standard, 0, now)
            .unwrap();

    let _ = reassembler.add_fragment(FragmentIndex(0), vec![0], now);
    let _ = reassembler.add_fragment(FragmentIndex(1), vec![0], now);
    let _ = reassembler.add_fragment(FragmentIndex(3), vec![0], now);
    let _ = reassembler.add_fragment(FragmentIndex(5), vec![0], now);

    let ack = reassembler.create_ack(FragmentCount(1000));
    assert_eq!(ack.message_id, MessageId(1));
    assert_eq!(ack.base_index, FragmentIndex(2)); // Fragments 0 and 1 are cumulative
    // Bitmask should have bits for index 3 and 5 set.
    // Index in bitmask is relative to base_index + 1.
    // idx 3 -> bit (3 - (2 + 1)) = 0
    // idx 5 -> bit (5 - (2 + 1)) = 2
    assert_eq!(ack.bitmask, (1 << 0) | (1 << 2));
}

#[test]
fn test_create_nack() {
    let now = Instant::now();
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(10), Priority::Standard, 0, now)
            .unwrap();

    let _ = reassembler.add_fragment(FragmentIndex(0), vec![0], now);
    let _ = reassembler.add_fragment(FragmentIndex(2), vec![0], now);

    let nack = reassembler.create_nack(FragmentIndex(0)).unwrap();
    assert_eq!(nack.message_id, MessageId(1));
    assert!(nack.missing_indices.contains(&FragmentIndex(1)));
    assert!(!nack.missing_indices.contains(&FragmentIndex(3)));
    assert!(!nack.missing_indices.contains(&FragmentIndex(0)));
    assert!(!nack.missing_indices.contains(&FragmentIndex(2)));
}

// end of tests
