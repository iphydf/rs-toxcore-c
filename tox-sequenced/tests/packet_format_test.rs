use smallvec::smallvec;
use tox_sequenced::protocol::{
    FragmentCount, FragmentIndex, MessageId, MessageType, Nack, Packet, SelectiveAck, TimestampMs,
};

#[test]
fn test_data_packet_format() {
    let packet = Packet::Data {
        message_id: MessageId(0x12345678),
        fragment_index: FragmentIndex(0x1234),
        total_fragments: FragmentCount(0x5678),
        data: vec![0xAA, 0xBB],
    };
    let serialized = tox_proto::serialize(&packet).unwrap();

    // Expected: [0, [0x12345678, 0x1234, 0x5678, bin(2)[0xAA, 0xBB]]]
    // 0x92 (fixarray(2))
    // 0x00 (tag 0)
    // 0x94 (fixarray(4) - the payload)
    // 0xce 0x12 0x34 0x56 0x78 (u32)
    // 0xcd 0x12 0x34 (u16)
    // 0xcd 0x56 0x78 (u16)
    // 0xc4 0x02 0xaa 0xbb (bin 8 length 2)
    let expected = vec![
        0x92, 0x00, 0x94, 0xce, 0x12, 0x34, 0x56, 0x78, 0xcd, 0x12, 0x34, 0xcd, 0x56, 0x78, 0xc4,
        0x02, 0xaa, 0xbb,
    ];

    assert_eq!(serialized, expected, "Data packet must be [tag, [fields]]");
}

#[test]
fn test_ack_packet_format() {
    let ack = SelectiveAck {
        message_id: MessageId(0x01),
        base_index: FragmentIndex(0x02),
        bitmask: 0x03,
        rwnd: FragmentCount(0x04),
    };
    let packet = Packet::Ack(ack);
    let serialized = tox_proto::serialize(&packet).unwrap();

    // Expected: [1, [1, 2, 3, 4]]
    // 0x92 (fixarray(2))
    // 0x01 (tag 1)
    // 0x94 (fixarray(4) - SelectiveAck struct)
    // 0x01, 0x02, 0x03, 0x04 (fixints)
    let expected = vec![0x92, 0x01, 0x94, 0x01, 0x02, 0x03, 0x04];

    assert_eq!(serialized, expected, "Ack packet must be [tag, [fields]]");
}

#[test]
fn test_nack_packet_format() {
    let nack = Nack {
        message_id: MessageId(0x01),
        missing_indices: smallvec![FragmentIndex(0x02), FragmentIndex(0x03)],
    };
    let packet = Packet::Nack(nack);
    let serialized = tox_proto::serialize(&packet).unwrap();

    // Expected: [2, [1, [2, 3]]]
    // 0x92 (fixarray(2))
    // 0x02 (tag 2)
    // 0x92 (fixarray(2) - Nack struct)
    // 0x01 (id 1)
    // 0x92 0x02 0x03 (array(2) indices)
    let expected = vec![0x92, 0x02, 0x92, 0x01, 0x92, 0x02, 0x03];

    assert_eq!(serialized, expected, "Nack packet must be [tag, [fields]]");
}

#[test]
fn test_ping_packet_format() {
    let packet = Packet::Ping {
        t1: TimestampMs(0x123456789ABCDEF0),
    };
    let serialized = tox_proto::serialize(&packet).unwrap();

    // Expected: [3, t1]
    // 0x92 (fixarray(2))
    // 0x03 (tag 3)
    // 0xcf 0x12 0x34 0x56 0x78 0x9a 0xbc 0xde 0xf0 (uint 64)
    let expected = vec![
        0x92, 0x03, 0xcf, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ];

    assert_eq!(serialized, expected, "Ping packet must be [tag, t1]");
}

#[test]
fn test_pong_packet_format() {
    let packet = Packet::Pong {
        t1: TimestampMs(1),
        t2: TimestampMs(2),
        t3: TimestampMs(3),
    };
    let serialized = tox_proto::serialize(&packet).unwrap();

    // Expected: [4, [1, 2, 3]]
    // 0x92 (fixarray(2))
    // 0x04 (tag 4)
    // 0x93 (fixarray(3) - the payload)
    // 0x01, 0x02, 0x03 (fixints)
    let expected = vec![0x92, 0x04, 0x93, 0x01, 0x02, 0x03];

    assert_eq!(
        serialized, expected,
        "Pong packet must be [tag, [t1, t2, t3]]"
    );
}

#[test]
fn test_all_message_type_discriminants() {
    use MessageType::*;
    let cases = vec![
        (CapsAnnounce, 0x01),
        (CapsAck, 0x02),
        (SyncHeads, 0x03),
        (FetchBatchReq, 0x04),
        (MerkleNode, 0x05),
        (BlobQuery, 0x06),
        (BlobAvail, 0x07),
        (BlobReq, 0x08),
        (BlobData, 0x09),
        (SyncSketch, 0x0A),
        (SyncReconFail, 0x0B),
        (SyncShardChecksums, 0x0C),
        (HandshakeError, 0x0D),
        (ReconPowChallenge, 0x0E),
        (ReconPowSolution, 0x0F),
    ];

    for (mtype, expected_id) in cases {
        assert_eq!(
            mtype as u8, expected_id,
            "MessageType {:?} must have discriminant 0x{:02x}",
            mtype, expected_id
        );
    }
}
