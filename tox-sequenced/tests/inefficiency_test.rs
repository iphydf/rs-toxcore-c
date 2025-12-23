use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::SequenceSession;
use tox_sequenced::protocol::{
    self, FragmentCount, FragmentIndex, MessageId, MessageType, Packet, SelectiveAck,
};

#[test]
fn test_large_gap_integration() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    // 1. Send enough data to Bob to grow Alice's window.
    let data = vec![0u8; 150 * 1300];
    let msg_id = alice
        .send_message(MessageType::MerkleNode, &data, Instant::now())
        .unwrap();

    let mut current_now = now;
    let mut p70 = None;
    let mut all_packets = Vec::new();

    // Simulation loop: Bob receives 0..10 and 100. Alice receives ACKs for 0..10 to keep window moving.
    for _ in 0..1000 {
        let p = alice.get_packets_to_send(current_now, 0);
        for packet in p {
            if let Packet::Data { fragment_index, .. } = &packet {
                let f_idx = *fragment_index;
                all_packets.push(packet.clone());

                if f_idx.0 <= 10 {
                    bob.handle_packet(packet.clone(), current_now);
                    // Cumulative ACK back to Alice
                    let ack = Packet::Ack(SelectiveAck {
                        message_id: msg_id,
                        base_index: FragmentIndex(f_idx.0 + 1),
                        bitmask: 0,
                        rwnd: FragmentCount(100),
                    });
                    alice.handle_packet(ack, current_now);
                } else if f_idx.0 == 70 {
                    p70 = Some(packet.clone());
                    bob.handle_packet(packet.clone(), current_now);
                    // DO NOT ACK 70 to Alice yet
                } else {
                    // Just a gap for Bob. But Alice needs ACKs to grow window past 10.
                    // We send a Selective ACK for f_idx > 10.
                    // To ensure Alice reaches 100, we must advance base_index if f_idx is too far.
                    let base = if f_idx.0 > 70 {
                        FragmentIndex(f_idx.0 - 60)
                    } else {
                        FragmentIndex(11)
                    };
                    let bitmask = if f_idx.0 > base.0 && f_idx.0 < base.0 + 64 {
                        1u64 << (f_idx.0 - base.0 - 1)
                    } else {
                        0
                    };
                    let ack = Packet::Ack(SelectiveAck {
                        message_id: msg_id,
                        base_index: base,
                        bitmask,
                        rwnd: FragmentCount(100),
                    });
                    alice.handle_packet(ack, current_now);
                }
            }
        }
        if p70.is_some() {
            break;
        }
        current_now += Duration::from_millis(1);
    }

    let _ = p70.expect("Alice failed to send fragment 70");

    // 2. Bob sends his REAL state (0..10 and 70 received).
    let later = current_now + Duration::from_millis(50);
    let acks = bob.get_packets_to_send(later, 0);
    let ack_packet = acks
        .into_iter()
        .find(|p| matches!(p, Packet::Ack(_)))
        .expect("Bob didn't send an ACK");

    if let Packet::Ack(ref ack) = ack_packet {
        assert_eq!(ack.message_id, msg_id);
        assert_eq!(ack.base_index, FragmentIndex(11));
    } else {
        panic!("Expected an ACK");
    }

    // 3. Alice receives Bob's ACK
    alice.handle_packet(ack_packet, later);

    // 4. Verify fragment 70 is NOT retransmitted.
    // 11 should be retransmitted (eventually or via NACK).
    let rto_time = later + Duration::from_millis(1500);
    let retrans = alice.get_packets_to_send(rto_time, 0);

    let retransmitted_70 = retrans.iter().any(|p| {
        matches!(
            p,
            Packet::Data {
                fragment_index: FragmentIndex(70),
                ..
            }
        )
    });
    assert!(
        !retransmitted_70,
        "Fragment 70 should NOT have been retransmitted!"
    );
}

#[test]
fn test_protocol_efficiency_wire() {
    // Create a representative packet
    let packet = Packet::Data {
        message_id: MessageId(12345),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1),
        data: vec![1, 2, 3, 4],
    };

    let encoded = protocol::serialize(&packet).expect("Failed to encode packet");

    // Convert encoded bytes to a string for simple searching (case-insensitive)
    let encoded_str = String::from_utf8_lossy(&encoded).to_lowercase();

    // 1. Check for field names (should not be present in positional arrays)
    assert!(
        !encoded_str.contains("message_id"),
        "Encoded packet contains field name 'message_id'"
    );
    assert!(
        !encoded_str.contains("fragment_index"),
        "Encoded packet contains field name 'fragment_index'"
    );

    // 2. Check for variant names (should not be present)
    assert!(
        !encoded_str.contains("data"),
        "Encoded packet contains variant name 'Data'"
    );
}

#[test]
fn test_message_type_efficiency_wire() {
    let msg_type = MessageType::MerkleNode;
    let encoded = protocol::serialize(&msg_type).expect("Failed to encode message type");

    // If serialized as a string, it will contain "merklenode"
    let encoded_str = String::from_utf8_lossy(&encoded).to_lowercase();
    assert!(
        !encoded_str.contains("merklenode"),
        "Encoded MessageType contains string name 'MerkleNode'"
    );

    // If serialized as a u8 (fixint), it should be exactly 1 byte
    assert_eq!(
        encoded.len(),
        1,
        "Encoded MessageType should be 1 byte (optimized unit enum), but was {} bytes",
        encoded.len()
    );
}

// end of tests
