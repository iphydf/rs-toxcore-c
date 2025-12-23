use smallvec::smallvec;
use tox_sequenced::protocol::{
    FragmentCount, FragmentIndex, MessageId, MessageType, Nack, Packet, SelectiveAck, TimestampMs,
};

#[test]
fn test_packet_serialization() {
    let packet = Packet::Data {
        message_id: MessageId(123),
        fragment_index: FragmentIndex(5),
        total_fragments: FragmentCount(10),
        data: vec![1, 2, 3, 4],
    };

    let serialized = tox_proto::serialize(&packet).unwrap();
    let deserialized: Packet = tox_proto::deserialize(&serialized).unwrap();

    assert_eq!(packet, deserialized);
}

#[test]
fn test_ack_serialization() {
    let ack = SelectiveAck {
        message_id: MessageId(12345),
        base_index: FragmentIndex(10),
        bitmask: 0xAAAA_BBBB_CCCC_DDDD,
        rwnd: FragmentCount(100),
    };
    let packet = Packet::Ack(ack);

    let serialized = tox_proto::serialize(&packet).unwrap();
    let deserialized: Packet = tox_proto::deserialize(&serialized).unwrap();

    assert_eq!(packet, deserialized);
}

#[test]
fn test_nack_serialization() {
    let nack = Nack {
        message_id: MessageId(789),
        missing_indices: smallvec![FragmentIndex(100), FragmentIndex(101), FragmentIndex(102)],
    };
    let packet = Packet::Nack(nack);

    let serialized = tox_proto::serialize(&packet).unwrap();
    let deserialized: Packet = tox_proto::deserialize(&serialized).unwrap();

    assert_eq!(packet, deserialized);
}

#[test]
fn test_ping_pong_serialization() {
    let ping = Packet::Ping {
        t1: TimestampMs(123456789),
    };
    let pong = Packet::Pong {
        t1: TimestampMs(123456789),
        t2: TimestampMs(123456790),
        t3: TimestampMs(123456791),
    };

    let serialized_ping = tox_proto::serialize(&ping).unwrap();
    let deserialized_ping: Packet = tox_proto::deserialize(&serialized_ping).unwrap();
    assert_eq!(ping, deserialized_ping);

    let serialized_pong = tox_proto::serialize(&pong).unwrap();
    let deserialized_pong: Packet = tox_proto::deserialize(&serialized_pong).unwrap();
    assert_eq!(pong, deserialized_pong);
}

#[test]
fn test_message_type_enum() {
    assert_eq!(MessageType::MerkleNode as u8, 0x05);
}

// end of tests
