use rand::SeedableRng;
use std::time::{Duration, Instant};
use tox_sequenced::protocol::{FragmentCount, FragmentIndex, MessageId, Packet};
use tox_sequenced::{MessageType, SequenceSession};

#[test]
fn test_next_wakeup_pacing() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut session = SequenceSession::new_at(now, tp, &mut rng);

    // Default wakeup should be long (keepalive/idle)
    let wakeup = session.next_wakeup(now);
    assert!(wakeup > now + Duration::from_secs(4));

    // Author a message. Since window is open, it should want immediate poll
    let _ = session.send_message(MessageType::SyncHeads, b"pacing test", now);
    let wakeup = session.next_wakeup(now);
    assert_eq!(wakeup, now);
}

#[test]
fn test_next_wakeup_ack_delay() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut session = SequenceSession::new_at(now, tp, &mut rng);

    // Create a valid reassembled payload (MessageType + Payload)
    use tox_proto::ToxProto;
    #[derive(ToxProto)]
    struct Envelope {
        mtype: MessageType,
        payload: Vec<u8>,
    }
    let env = Envelope {
        mtype: MessageType::SyncHeads,
        payload: b"hello".to_vec(),
    };
    let data = tox_proto::serialize(&env).unwrap();

    // 3. Receive a single-fragment message for Bob.
    let packet = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1),
        data,
    };

    session.handle_packet(packet, now);

    // Verify message was received correctly
    let mut found = false;
    while let Some(event) = session.poll_event() {
        if let tox_sequenced::SessionEvent::MessageCompleted(id, mtype, payload) = event {
            assert_eq!(id, MessageId(1));
            assert_eq!(mtype, MessageType::SyncHeads);
            assert_eq!(payload, b"hello");
            found = true;
        }
    }
    assert!(found);

    // Next wakeup should be the ACK delay (approx 25ms)
    let wakeup = session.next_wakeup(now);
    assert!(wakeup > now);
    assert!(wakeup <= now + Duration::from_millis(30));
}

#[test]
fn test_next_wakeup_rto() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut session = SequenceSession::new_at(now, tp, &mut rng);

    // Send a message
    let _ = session.send_message(MessageType::SyncHeads, b"rto test", now);

    // Initial packet
    let packets = session.get_packets_to_send(now, 0);
    assert!(!packets.is_empty());

    // Advance past pacing delay
    let now_after_pacing = now + Duration::from_millis(100);

    // Next wakeup should be either Tail Loss Probe or Retransmission Timeout.
    // Both are relatively short compared to idle keepalive.
    let wakeup = session.next_wakeup(now_after_pacing);
    assert!(wakeup > now);
    assert!(wakeup <= now + Duration::from_secs(2));
}
