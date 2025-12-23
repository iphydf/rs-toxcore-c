use std::time::Instant;
use tox_sequenced::protocol::{FragmentCount, FragmentIndex, MessageId, PACKET_OVERHEAD, Packet};
use tox_sequenced::quota::Priority;
use tox_sequenced::{MessageReassembler, SequencedError};

fn fragment_message(data: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>, SequencedError> {
    let payload_mtu = mtu.saturating_sub(PACKET_OVERHEAD);
    if payload_mtu == 0 {
        return Err(SequencedError::InvalidMtu);
    }

    Ok(data
        .chunks(payload_mtu)
        .map(|chunk| chunk.to_vec())
        .collect())
}

#[test]
fn test_fragmentation_and_reassembly() {
    let original_data = b"Hello, this is a test message that should be fragmented into multiple pieces and then reassembled correctly.".to_vec();
    let message_id = 1234;
    let mtu = 60; // Increased MTU to be larger than overhead

    let data_fragments = fragment_message(&original_data, mtu).unwrap();
    assert!(data_fragments.len() > 1);

    let total_fragments = data_fragments.len() as u16;
    let now = Instant::now();
    let mut reassembler = MessageReassembler::new(
        MessageId(message_id),
        FragmentCount(total_fragments),
        Priority::Standard,
        0,
        now,
    )
    .expect("Failed to create reassembler");

    for (i, data) in data_fragments.into_iter().enumerate() {
        reassembler
            .add_fragment(FragmentIndex(i as u16), data, now)
            .unwrap();
    }

    let assembled_data = reassembler.assemble().expect("Failed to assemble message");
    assert_eq!(assembled_data, original_data);
}

#[test]
fn test_selective_ack_bitmask() {
    let message_id = 1;
    let total_fragments = 10;
    let now = Instant::now();
    let mut reassembler = MessageReassembler::new(
        MessageId(message_id),
        FragmentCount(total_fragments),
        Priority::Standard,
        0,
        now,
    )
    .expect("Failed to create reassembler");

    // Add fragments 0, 1, 3, 5
    reassembler
        .add_fragment(FragmentIndex(0), vec![0], now)
        .unwrap();
    reassembler
        .add_fragment(FragmentIndex(1), vec![1], now)
        .unwrap();
    reassembler
        .add_fragment(FragmentIndex(3), vec![3], now)
        .unwrap();
    reassembler
        .add_fragment(FragmentIndex(5), vec![5], now)
        .unwrap();

    let ack = reassembler.create_ack(FragmentCount(1024));

    // ack is SelectiveAck { message_id, base_index, bitmask, sack_ranges }
    let tox_sequenced::protocol::SelectiveAck {
        message_id: ack_msg_id,
        base_index,
        bitmask,
        rwnd: _,
    } = ack;

    assert_eq!(ack_msg_id, MessageId(message_id));
    // First missing is index 2
    assert_eq!(base_index, FragmentIndex(2));

    // Bitmask: bit 0 is index 3, bit 1 is index 4, bit 2 is index 5
    // Index 3 is present -> bit 0 = 1
    // Index 4 is missing -> bit 1 = 0
    // Index 5 is present -> bit 2 = 1
    assert_eq!(bitmask & 0b101, 0b101);
    assert_eq!(bitmask & 0b010, 0);
}

#[test]
fn test_packet_serialization_size() {
    let packet = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1),
        data: vec![0u8; 100],
    };

    let serialized = tox_proto::serialize(&packet).expect("Failed to serialize");
    // Expected overhead: u32 (index) + u32 (id) + u8 (type) + u16 (idx) + u16 (total) + u32 (len) = 17 bytes
    assert!(
        serialized.len() <= 125,
        "Serialized size too large: {}",
        serialized.len()
    );
}

#[test]
fn test_mtu_boundary_serialization() {
    use tox_sequenced::protocol::{MAX_TOX_PACKET_SIZE, PACKET_OVERHEAD};

    // Use worst-case values for indices (max u32/u16)
    let message_id = 0xFFFF_FFFF;
    let fragment_index = 0xFFFF;
    let total_fragments = 0xFFFF;

    let payload_mtu = MAX_TOX_PACKET_SIZE.saturating_sub(PACKET_OVERHEAD);
    let data = vec![0u8; payload_mtu];

    let packet = Packet::Data {
        message_id: MessageId(message_id),
        fragment_index: FragmentIndex(fragment_index),
        total_fragments: FragmentCount(total_fragments),
        data,
    };

    let serialized = tox_proto::serialize(&packet).expect("Failed to serialize");

    assert!(
        serialized.len() <= MAX_TOX_PACKET_SIZE,
        "MTU VIOLATION: Serialized size {} exceeds Tox limit {}. Actual overhead was {}, but PACKET_OVERHEAD is {}.",
        serialized.len(),
        MAX_TOX_PACKET_SIZE,
        serialized.len() - payload_mtu,
        PACKET_OVERHEAD
    );

    // Also verify that we aren't being TOO conservative (wasting more than 16 bytes)
    assert!(
        PACKET_OVERHEAD - (serialized.len() - payload_mtu) <= 16,
        "PACKET_OVERHEAD ({}) is too conservative. Actual overhead was {}. Consider reducing it to save bandwidth.",
        PACKET_OVERHEAD,
        serialized.len() - payload_mtu
    );
}

#[test]
fn test_reassembler_invalid_new() {
    let now = Instant::now();
    // 0 fragments
    assert!(
        MessageReassembler::new(MessageId(1), FragmentCount(0), Priority::Standard, 0, now)
            .is_err()
    );
    // Too many fragments (limit is 16384)
    assert!(
        MessageReassembler::new(
            MessageId(1),
            FragmentCount(20000),
            Priority::Standard,
            0,
            now
        )
        .is_err()
    );
}

#[test]
fn test_reassembler_duplicate_fragments() {
    let now = Instant::now();
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(2), Priority::Standard, 0, now)
            .unwrap();

    // Add fragment 0
    assert!(
        !reassembler
            .add_fragment(FragmentIndex(0), vec![1, 2, 3], now)
            .unwrap()
    );
    assert_eq!(reassembler.received_count(), FragmentCount(1));
    assert_eq!(reassembler.current_size(), 3);

    // Add fragment 0 again with different data (should still be ignored)
    assert!(
        !reassembler
            .add_fragment(FragmentIndex(0), vec![9, 9, 9, 9, 9], now)
            .unwrap()
    );
    assert_eq!(reassembler.received_count(), FragmentCount(1));
    assert_eq!(reassembler.current_size(), 3);

    // Add fragment 1
    assert!(
        reassembler
            .add_fragment(FragmentIndex(1), vec![4, 5], now)
            .unwrap()
    );
    assert_eq!(reassembler.received_count(), FragmentCount(2));
    assert_eq!(reassembler.current_size(), 5);

    assert_eq!(reassembler.assemble().unwrap(), vec![1, 2, 3, 4, 5]);
}

#[test]
fn test_reassembler_assemble_not_ready() {
    let now = Instant::now();
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(2), Priority::Standard, 0, now)
            .unwrap();
    reassembler
        .add_fragment(FragmentIndex(0), vec![1], now)
        .unwrap();
    assert!(reassembler.assemble().is_none());
}

#[test]
fn test_reassembler_max_size_limit() {
    use tox_sequenced::protocol::MAX_MESSAGE_SIZE;
    let now = Instant::now();
    // 2 fragments, first one is already max size
    let mut reassembler =
        MessageReassembler::new(MessageId(1), FragmentCount(2), Priority::Standard, 0, now)
            .unwrap();
    assert!(
        !reassembler
            .add_fragment(FragmentIndex(0), vec![0u8; MAX_MESSAGE_SIZE], now)
            .unwrap()
    );
    // Second one should be rejected because it would exceed MAX_MESSAGE_SIZE
    assert!(
        reassembler
            .add_fragment(FragmentIndex(1), vec![0u8; 1], now)
            .is_err()
    );
    assert!(reassembler.assemble().is_none());
}

#[test]
fn test_fragment_message_edge_cases() {
    // Empty data
    let empty = fragment_message(&[], 100).unwrap();
    assert_eq!(empty.len(), 0);

    // Data smaller than MTU
    let small = fragment_message(&[1, 2, 3], 100).unwrap();
    assert_eq!(small.len(), 1);
    assert_eq!(small[0], vec![1, 2, 3]);

    // MTU smaller than overhead
    let tiny_mtu = fragment_message(&[1, 2, 3], 10);
    assert!(tiny_mtu.is_err());
}

#[test]
fn test_packet_deserialization_invalid() {
    // Completely random junk
    let junk = vec![0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    let res = tox_proto::deserialize::<Packet>(&junk);
    assert!(res.is_err());
}

// end of tests
