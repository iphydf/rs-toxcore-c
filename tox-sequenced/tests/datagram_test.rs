use rand::SeedableRng;
use std::sync::Arc;
use std::time::Instant;
use tox_sequenced::protocol::{MessageType, Packet};
use tox_sequenced::time::SystemTimeProvider;
use tox_sequenced::{SequenceSession, SessionEvent};

#[test]
fn test_datagram_send_receive() {
    let tp = Arc::new(SystemTimeProvider);
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let now = Instant::now();

    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    let data = b"unreliable gossip".to_vec();
    let msg_type = MessageType::SyncHeads;

    // Alice sends datagram
    alice
        .send_datagram(msg_type, &data)
        .expect("Failed to queue datagram");

    let packets = alice.get_packets_to_send(now, 0);
    // Might include a Ping since last_ping is initialized to now - timeout
    assert!(!packets.is_empty());
    let dg_packet = packets
        .iter()
        .find(|p| matches!(p, Packet::Datagram { .. }))
        .expect("Datagram not found in packets");

    // Verify packet variant
    if let Packet::Datagram {
        message_type,
        data: packet_data,
    } = dg_packet
    {
        assert_eq!(*message_type, msg_type);
        assert_eq!(*packet_data, data);
    } else {
        panic!("Expected Datagram packet");
    }

    // Bob receives datagram
    let responses = bob.handle_packet(dg_packet.clone(), now);
    assert!(
        responses.is_empty(),
        "Datagram should not trigger responses (ACKs)"
    );

    // Bob checks events
    let event = bob.poll_event().expect("Expected event");
    if let SessionEvent::MessageCompleted(id, mtype, payload) = event {
        assert_eq!(
            id,
            tox_sequenced::protocol::MessageId(0),
            "Datagram should have ID 0"
        );
        assert_eq!(mtype, msg_type);
        assert_eq!(payload, data);
    } else {
        panic!("Expected MessageCompleted event");
    }
}

#[test]
fn test_datagram_oversized() {
    let tp = Arc::new(SystemTimeProvider);
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let now = Instant::now();
    let mut alice = SequenceSession::new_at(now, tp, &mut rng);

    let large_data = vec![0u8; 2000]; // Larger than MTU
    let msg_type = MessageType::BlobData;

    let result = alice.send_datagram(msg_type, &large_data);
    assert!(result.is_err(), "Oversized datagram should fail");
}
