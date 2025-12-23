use std::time::Instant;
use tox_sequenced::protocol::{FragmentCount, FragmentIndex, MessageId};
use tox_sequenced::quota::Priority;
use tox_sequenced::reassembly::MessageReassembler;

#[test]
fn test_bitmask_coverage() {
    let now = Instant::now();
    let msg_id = MessageId(1);
    let total_frags = 200;
    let mut reassembler = MessageReassembler::new(
        msg_id,
        FragmentCount(total_frags),
        Priority::Standard,
        0,
        now,
    )
    .unwrap();

    // 1. Receive fragments 0..10 (cumulative)
    for i in 0..10 {
        reassembler
            .add_fragment(FragmentIndex(i), vec![0], now)
            .unwrap();
    }

    // 2. Create a hole at 10.
    // Receive 11..20. This will be in the bitmask.
    for i in 11..21 {
        reassembler
            .add_fragment(FragmentIndex(i), vec![0], now)
            .unwrap();
    }

    // Bitmask covers base_index + 1 up to +64.
    // base_index is 10. Bitmask covers 11..74.

    // 3. Receive fragment 74 (exactly the last bit of the mask)
    reassembler
        .add_fragment(FragmentIndex(74), vec![0], now)
        .unwrap();

    // 4. Receive fragment 75 (Overflows: 10 + 65. Cannot be represented in bitmask)
    reassembler
        .add_fragment(FragmentIndex(75), vec![0], now)
        .unwrap();

    let ack = reassembler.create_ack(FragmentCount(100));

    assert_eq!(ack.base_index, FragmentIndex(10));
    // Bit 0 is idx 11, Bit 63 is idx 74.
    assert!(ack.bitmask & (1 << 0) != 0); // idx 11
    assert!(ack.bitmask & (1 << 63) != 0); // idx 74

    // Fragment 75 is not in the bitmask and cannot be represented in this SelectiveAck
    // because SACK ranges were removed.
}
