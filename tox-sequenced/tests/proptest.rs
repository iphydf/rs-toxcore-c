use proptest::prelude::*;
use std::collections::HashSet;
use std::time::Instant;
use tox_sequenced::outgoing::OutgoingMessage;
use tox_sequenced::protocol::{
    FragmentCount, FragmentIndex, MessageId, MessageType, Nack, Packet, SelectiveAck, TimestampMs,
};

proptest! {
    #[test]
    fn test_packet_roundtrip(
        msg_id in any::<u32>(),
        frag_idx in any::<u16>(),
        total_frags in any::<u16>(),
        data in prop::collection::vec(any::<u8>(), 0..1400),
        base_index in any::<u16>(),
        bitmask in any::<u64>(),
        rwnd in any::<u16>(),
        t1 in any::<i64>(),
        t2 in any::<i64>(),
        t3 in any::<i64>(),
        nack_list in prop::collection::vec(any::<u16>(), 0..20),
    ) {
        let packets = vec![
            Packet::Data {
                message_id: MessageId(msg_id),
                fragment_index: FragmentIndex(frag_idx),
                total_fragments: FragmentCount(total_frags),
                data: data.clone(),
            },
            Packet::Ack(SelectiveAck {
                message_id: MessageId(msg_id),
                base_index: FragmentIndex(base_index),
                bitmask,
                rwnd: FragmentCount(rwnd),
            }),
            Packet::Nack(Nack {
                message_id: MessageId(msg_id),
                missing_indices: nack_list.iter().map(|&i| FragmentIndex(i)).collect(),
            }),
            Packet::Ping { t1: TimestampMs(t1) },
            Packet::Pong {
                t1: TimestampMs(t1),
                t2: TimestampMs(t2),
                t3: TimestampMs(t3),
            },
        ];

        for p in packets {
            let serialized = tox_proto::serialize(&p).unwrap();
            let deserialized: Packet = tox_proto::deserialize(&serialized).unwrap();
            prop_assert_eq!(p, deserialized);
        }
    }

    #[test]
    fn test_outgoing_message_consistency(
        payload_size in 100..2000usize,
        payload_mtu in 50..200usize,
        ack_ops in prop::collection::vec(any::<u16>(), 0..200),
    ) {
        let now = Instant::now();
        let data = vec![0u8; payload_size];
        let mut msg = OutgoingMessage::new(MessageType::MerkleNode, data, payload_mtu, now).unwrap();

        let mut shadow_acked = HashSet::new();
        for &idx in &ack_ops {
            if idx < msg.num_fragments.0 {
                msg.set_acked(FragmentIndex(idx));
                shadow_acked.insert(idx);
            }
        }

        prop_assert_eq!(msg.acked_count, FragmentCount(shadow_acked.len() as u16));
        for i in 0..msg.num_fragments.0 {
            prop_assert_eq!(msg.is_acked(FragmentIndex(i)), shadow_acked.contains(&i));
        }

        if msg.num_fragments.0 > 0 {
            prop_assert_eq!(msg.all_acked(), shadow_acked.len() == msg.num_fragments.0 as usize);
        }
    }
}
