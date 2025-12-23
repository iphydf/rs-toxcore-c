use rand::SeedableRng;
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tox_proto::TimeProvider;
use tox_sequenced::protocol::{
    ESTIMATED_PAYLOAD_SIZE, FragmentCount, FragmentIndex, MessageId, MessageType, OutboundEnvelope,
    Packet,
};
use tox_sequenced::time::ManualTimeProvider;
use tox_sequenced::{Algorithm, AlgorithmType, SequenceSession};

use tox_sequenced::SessionEvent;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

fn has_message_event<C: tox_sequenced::CongestionControl>(
    session: &mut SequenceSession<C>,
) -> bool {
    while let Some(event) = session.poll_event() {
        if matches!(event, SessionEvent::MessageCompleted(..)) {
            return true;
        }
    }
    false
}

#[test]
fn test_sequence_session_delivery() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    let data = b"Important reliable message from Alice to Bob".to_vec();
    let _msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .expect("Failed to send message");

    // 2. Alice sends data to Bob
    let packets = alice.get_packets_to_send(now, 0);
    assert!(!packets.is_empty());

    // Bob receives packets and produces ACKs
    for packet in packets {
        let _replies = bob.handle_packet(packet, now);
        // Verify via event queue
        while let Some(event) = bob.poll_event() {
            if let tox_sequenced::SessionEvent::MessageCompleted(_id, msg_type, received_data) =
                event
            {
                assert_eq!(msg_type, MessageType::MerkleNode);
                assert_eq!(received_data, data);
            }
        }
    }

    let acks = bob.get_packets_to_send(now, 0);
    assert!(!acks.is_empty());

    // Alice receives ACKs and clears her buffer
    for ack in acks {
        alice.handle_packet(ack, now);
    }

    // Alice should have no more packets to send (everything acked)
    let final_packets = alice.get_packets_to_send(now, 0);
    assert!(final_packets.is_empty());
}

#[test]
fn test_retransmission_after_loss() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    let data = vec![0u8; 5000]; // Multi-fragment message
    let _msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .expect("Failed to send message");

    let mut data_packets: SmallVec<Packet, 8> = SmallVec::new();
    let mut current_now = now;
    for _ in 0..100 {
        let p = alice.get_packets_to_send(current_now, 0);
        data_packets.extend(p.into_iter().filter(|p| matches!(p, Packet::Data { .. })));
        if data_packets.len() >= 4 {
            break;
        }
        current_now += Duration::from_millis(20);
    }

    assert!(data_packets.len() > 1);
    // Drop the first DATA packet
    let _dropped = data_packets.remove(0);

    // Bob receives the rest
    for packet in data_packets {
        let _replies = bob.handle_packet(packet, now);
        // Should not be complete yet
        assert!(!has_message_event(&mut bob));
    }

    // Bob sends ACKs (which will be Selective ACKs showing missing first packet)
    let acks = bob.get_packets_to_send(now, 0);
    assert!(!acks.is_empty());
    for ack in acks {
        alice.handle_packet(ack, now);
    }

    // Alice should now want to retransmit the first packet immediately because of NACK
    let mut retransmission = Vec::new();
    let mut current_now = now;
    for _ in 0..100 {
        retransmission = alice.get_packets_to_send(current_now, 0);
        if !retransmission.is_empty() {
            break;
        }
        current_now += Duration::from_millis(20);
    }

    let retransmitted_data = retransmission
        .into_iter()
        .find(|p| {
            matches!(
                p,
                Packet::Data {
                    fragment_index: FragmentIndex(0),
                    ..
                }
            )
        })
        .expect("Should have retransmitted fragment 0");

    // Bob receives the retransmission
    let _replies = bob.handle_packet(retransmitted_data, now);

    let mut found = false;
    while let Some(event) = bob.poll_event() {
        if let tox_sequenced::SessionEvent::MessageCompleted(_eid, msg_type, received_data) = event
        {
            assert_eq!(msg_type, MessageType::MerkleNode);
            assert_eq!(received_data, data);
            found = true;
        }
    }
    assert!(found, "Should be complete now");
}

#[test]
fn test_ping_pong_rtt() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Force a Ping from Alice
    // PING_INTERVAL is 5s. Advance time.
    let later = now + Duration::from_secs(6);
    let packets = alice.get_packets_to_send(later, 0);
    let ping = packets
        .into_iter()
        .find(|p| matches!(p, Packet::Ping { .. }))
        .unwrap();

    // 2. Bob handles Ping and replies with Pong
    let replies = bob.handle_packet(ping, later);
    let pong = replies
        .into_iter()
        .find(|p| matches!(p, Packet::Pong { .. }))
        .unwrap();

    // 3. Alice handles Pong (100ms later)
    let much_later = later + Duration::from_millis(100);
    alice.handle_packet(pong, much_later);

    // 4. Check if Alice updated her SRTT (initial 200ms -> updated towards 100ms)
    // We can't see srtt directly, but rto = srtt + 4*rttvar.
    let next_check = alice.next_check_time();
    // next_check should be much closer than now + 5s (ping) or now + 1s (initial RTO)
    assert!(next_check < much_later + Duration::from_millis(900));
}

#[test]
fn test_session_death() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let alice = SequenceSession::new_at(now, tp.clone(), &mut rng);

    assert!(!alice.is_dead(now));

    // 2. Advance time past CONNECTION_TIMEOUT (300s)
    let later = now + Duration::from_secs(301);
    assert!(alice.is_dead(later));
}

#[test]
fn test_max_concurrent_outgoing() {
    use tox_sequenced::protocol::MAX_CONCURRENT_OUTGOING;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    for _ in 0..MAX_CONCURRENT_OUTGOING {
        assert!(
            alice
                .send_message(MessageType::MerkleNode, b"test", now)
                .is_ok()
        );
    }

    // Next one should fail
    assert!(
        alice
            .send_message(MessageType::MerkleNode, b"fail", now)
            .is_err()
    );

    // Now complete one message and see if a slot opens up
    // We need to simulate Bob receiving and ACKing
    let packets = alice.get_packets_to_send(now, 0);
    for p in packets {
        let _ = bob.handle_packet(p, now);
    }
    let acks = bob.get_packets_to_send(now, 0);
    for a in acks {
        alice.handle_packet(a, now);
    }

    // Alice should now have at least one slot free
    assert!(
        alice
            .send_message(MessageType::MerkleNode, b"success", now)
            .is_ok()
    );
}

#[test]
fn test_pacing_enforcement() {
    pacing_enforcement(AlgorithmType::Bbrv1);
    pacing_enforcement(AlgorithmType::Bbrv2);
}

fn pacing_enforcement(algo: AlgorithmType) {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    // Use BBR as it implements pacing (AIMD/Cubic use f32::INFINITY)
    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(algo, rand::SeedableRng::seed_from_u64(0)),
        now,
        tp.clone(),
        &mut rng,
    );

    // Send a large message to trigger many fragments
    let data = vec![0u8; 10000];
    alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    // Initial packets. BBR in Startup will have a pacing rate.
    let p1 = alice.get_packets_to_send(now, 0);
    assert!(!p1.is_empty());

    // next_check_time should now be in the future because of pacing
    let next_check = alice.next_check_time();
    assert!(next_check > now);

    // Calling it again immediately should return fewer or no packets
    let p2 = alice.get_packets_to_send(now, 0);
    assert!(
        p2.is_empty(),
        "Pacing should have prevented immediate burst"
    );

    // Advance time past pacing delay
    let later = next_check + Duration::from_millis(1);
    let p3 = alice.get_packets_to_send(later, 0);
    assert!(
        !p3.is_empty(),
        "Should be able to send more after pacing delay"
    );
}

#[test]
fn test_fast_retransmit_without_nack() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Send a message that will have multiple fragments
    // Message size 5000 / ~1300 payload = 4 fragments (0, 1, 2, 3)
    let data = vec![0u8; 5000];
    let msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .expect("Send failed");

    // 2. Alice sends all fragments
    let mut data_packets = Vec::new();
    let mut current_now = now;
    for _ in 0..100 {
        let p = alice.get_packets_to_send(current_now, 0);
        data_packets.extend(p.into_iter().filter(|p| matches!(p, Packet::Data { .. })));
        if data_packets.len() >= 4 {
            break;
        }
        current_now += Duration::from_millis(20);
    }
    assert_eq!(data_packets.len(), 4);

    // 3. Drop fragment 0, Bob receives 1, 2, 3
    let _dropped = data_packets.remove(0);
    for p in data_packets {
        bob.handle_packet(p, now);
    }

    // 4. Bob sends ACKs + NACKs.
    // WE DROP THE NACK to simulate loss or a peer that doesn't send them.
    let packets_from_bob = bob.get_packets_to_send(now, 0);
    for p in packets_from_bob {
        if !matches!(p, Packet::Nack(_)) {
            alice.handle_packet(p, now);
        }
    }

    // 5. Alice should have identified fragment 0 as lost due to "Fast Retransmit"
    // (Inferred from ACKs 1, 2, 3) even though RTO (initial 1000ms) hasn't passed.
    let mut retransmissions = Vec::new();
    let mut current_now = now;
    for _ in 0..100 {
        retransmissions = alice.get_packets_to_send(current_now, 0);
        if !retransmissions.is_empty() {
            break;
        }
        current_now += Duration::from_millis(20);
    }

    let frag_0_retransmitted = retransmissions.iter().any(|p| {
        matches!(p, Packet::Data { message_id, fragment_index: FragmentIndex(0), .. } if *message_id == msg_id)
    });

    assert!(
        frag_0_retransmitted,
        "Fragment 0 should be retransmitted via Fast Retransmit (3 dup ACKs) before RTO"
    );
}

#[test]
fn test_ack_bitmask_preservation_on_retransmit() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Large message (10 fragments)
    let data = vec![0u8; 12000];
    let _msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();
    let mut all_packets = Vec::new();
    let mut current_now = now;
    for _ in 0..200 {
        all_packets.extend(alice.get_packets_to_send(current_now, 0));
        if all_packets
            .iter()
            .filter(|p| matches!(p, Packet::Data { .. }))
            .count()
            >= 10
        {
            break;
        }
        current_now += Duration::from_millis(20);
    }

    // 2. Bob receives only 0, 2, 4, 6, 8 (drops 1, 3, 5, 7, 9)
    let data_packets: Vec<_> = all_packets
        .into_iter()
        .filter(|p| matches!(p, Packet::Data { .. }))
        .collect();
    for (i, p) in data_packets.into_iter().enumerate() {
        if i % 2 == 0 {
            bob.handle_packet(p, now);
        }
    }

    // 3. Bob sends Selective ACKs + NACKs
    let packets_from_bob = bob.get_packets_to_send(now, 0);
    for ack in packets_from_bob {
        alice.handle_packet(ack, now);
    }

    // 4. Alice prepares retransmissions
    let mut retrans = Vec::new();
    let mut current_time = now + Duration::from_millis(10);
    for _ in 0..500 {
        let p = alice.get_packets_to_send(current_time, 0);
        retrans.extend(p);
        current_time += Duration::from_millis(10);
        if retrans
            .iter()
            .filter(|p| matches!(p, Packet::Data { .. }))
            .count()
            >= 5
        {
            break;
        }
    }

    // 5. Verify that ONLY the missing fragments are sent
    let sent_indices: Vec<FragmentIndex> = retrans
        .iter()
        .filter_map(|p| {
            if let Packet::Data { fragment_index, .. } = p {
                Some(*fragment_index)
            } else {
                None
            }
        })
        .collect();

    assert!(
        sent_indices.contains(&FragmentIndex(1)),
        "Should retransmit fragment 1 (SACK Gap)"
    );
    assert!(
        sent_indices.contains(&FragmentIndex(3)),
        "Should retransmit fragment 3 (SACK Gap)"
    );
    assert!(
        !sent_indices.contains(&FragmentIndex(0)),
        "Should not retransmit already ACKed fragment 0"
    );
    assert!(
        !sent_indices.contains(&FragmentIndex(2)),
        "Should not retransmit already ACKed fragment 2"
    );
}

#[test]
fn test_receiver_flow_control() {
    receiver_flow_control(AlgorithmType::Bbrv1);
    receiver_flow_control(AlgorithmType::Bbrv2);
}

fn receiver_flow_control(algo: AlgorithmType) {
    use tox_sequenced::protocol::MAX_TOTAL_REASSEMBLY_BUFFER;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::with_congestion_control_at(
        Algorithm::new(algo, rand::SeedableRng::seed_from_u64(0)),
        now,
        tp.clone(),
        &mut rng,
    );
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Send a large message but Bob drops fragments to fill his buffer.
    let data = vec![0u8; 1024 * 1024 - 100]; // 1MB - small overhead
    let _msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    let mut current_time = now;
    let mut last_rwnd = FragmentCount(1000);

    for _ in 0..5000 {
        let mut progress = false;

        let packets = alice.get_packets_to_send(current_time, 0);
        if !packets.is_empty() {
            progress = true;
            for p in packets {
                if let Packet::Data {
                    fragment_index,
                    total_fragments,
                    ..
                } = &p
                {
                    // Drop ONLY the last fragment to keep it in buffer
                    if fragment_index.0 == total_fragments.0 - 1 {
                        continue;
                    }
                }
                bob.handle_packet(p, current_time);
            }
        }

        let acks = bob.get_packets_to_send(current_time, 0);
        if !acks.is_empty() {
            progress = true;
            for ack in acks {
                if let Packet::Ack(selective_ack) = &ack {
                    last_rwnd = selective_ack.rwnd;
                    alice.handle_packet(ack, current_time);
                }
            }
        }

        let max_fragments = (MAX_TOTAL_REASSEMBLY_BUFFER / ESTIMATED_PAYLOAD_SIZE) as u16;
        if last_rwnd.0 < max_fragments {
            break;
        }

        if !progress {
            current_time += Duration::from_millis(1);
        }
    }

    let max_fragments = (MAX_TOTAL_REASSEMBLY_BUFFER / ESTIMATED_PAYLOAD_SIZE) as u16;
    assert!(
        last_rwnd.0 < max_fragments,
        "RWND should be reduced, got {}",
        last_rwnd
    );

    // 2. Alice tries to send another message.
    let data2 = vec![0u8; 512 * 1024];
    alice
        .send_message(MessageType::MerkleNode, &data2, now)
        .unwrap();

    // Advance time to allow sending
    current_time += Duration::from_secs(1);
    let _ = alice.get_packets_to_send(current_time, 0);

    // Alice's in_flight should be limited by RWND.
    assert!(
        alice.in_flight() <= last_rwnd.0 as usize + 5000,
        "Alice ignored RWND! InFlight: {}, RWND: {}",
        alice.in_flight(),
        last_rwnd
    );
}

#[test]
fn test_session_events() {
    use tox_sequenced::SessionEvent;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    let data = b"Event Test".to_vec();
    let msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    // Alice -> Bob
    let packets = alice.get_packets_to_send(now, 0);
    for p in packets {
        let _ = bob.handle_packet(p, now);
    }

    // Check Bob's events
    let mut event = bob.poll_event().expect("Bob should have an event");
    while matches!(event, SessionEvent::CongestionWindowChanged(_)) {
        event = bob.poll_event().expect("Bob should have more events");
    }

    if let SessionEvent::MessageCompleted(id, msg_type, received_data) = event {
        assert_eq!(id, msg_id);
        assert_eq!(msg_type, MessageType::MerkleNode);
        assert_eq!(received_data, data);
    } else {
        panic!("Expected MessageCompleted event, got {:?}", event);
    }

    // Bob -> Alice (ACKs)
    let acks = bob.get_packets_to_send(now, 0);
    for ack in acks {
        alice.handle_packet(ack, now);
    }

    // Check Alice's events
    let mut event = alice.poll_event().expect("Alice should have an event");
    while matches!(event, SessionEvent::CongestionWindowChanged(_)) {
        event = alice.poll_event().expect("Alice should have more events");
    }
    assert_eq!(event, SessionEvent::MessageAcked(msg_id));
}

#[test]
fn test_zero_window_probing() {
    use tox_sequenced::protocol::ESTIMATED_PAYLOAD_SIZE;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Bob advertises zero window
    let mut ack = tox_sequenced::protocol::SelectiveAck {
        message_id: MessageId(0),
        base_index: FragmentIndex(0),
        bitmask: 0,
        rwnd: FragmentCount(0),
    };

    // Alice sends a message (2 fragments)
    let data = vec![0u8; ESTIMATED_PAYLOAD_SIZE + 100];
    alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    // Alice receives the zero window ACK
    alice.handle_packet(Packet::Ack(ack.clone()), now);

    // Alice should not send anything immediately (except maybe a Ping, which we ignore)
    let packets = alice.get_packets_to_send(now, 0);
    let data_packets: Vec<_> = packets
        .into_iter()
        .filter(|p| matches!(p, Packet::Data { .. }))
        .collect();
    assert!(data_packets.is_empty());

    // 2. Advance time past initial RTO for probing
    let later = now + Duration::from_millis(1100);
    let packets = alice.get_packets_to_send(later, 0);

    // Alice should send a probe (Data fragment)
    let probe = packets.iter().find(|p| matches!(p, Packet::Data { .. }));
    assert!(
        probe.is_some(),
        "Alice should have sent a zero-window probe"
    );

    // 3. Bob receives probe and replies with non-zero window
    ack.rwnd = FragmentCount(10);
    alice.handle_packet(Packet::Ack(ack), later);

    // 4. Alice should now resume sending (advance slightly more to avoid pacing)
    let much_later = later + Duration::from_millis(100);
    let packets = alice.get_packets_to_send(much_later, 0);
    assert!(!packets.is_empty());
}

#[test]
fn test_message_timeout() {
    use tox_sequenced::SessionEvent;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Send a message
    let msg_id = alice
        .send_message(MessageType::MerkleNode, b"timeout test", now)
        .unwrap();

    // 2. Advance time past message timeout (default 30s)
    let later = now + Duration::from_secs(31);
    alice.cleanup(later);

    // 3. Check for MessageFailed event
    let mut found = false;
    while let Some(event) = alice.poll_event() {
        if let SessionEvent::MessageFailed(id, reason) = event {
            assert_eq!(id, msg_id);
            assert!(reason.contains("Timed out"));
            found = true;
            break;
        }
    }
    assert!(found, "Should have received MessageFailed event");
}

#[test]
fn test_reassembly_buffer_exhaustion() {
    use tox_sequenced::protocol::MAX_TOTAL_REASSEMBLY_BUFFER;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Bob receives many fragments for different messages to fill buffer
    let chunk_size = 1000;
    let fragments_to_fill = MAX_TOTAL_REASSEMBLY_BUFFER / chunk_size;

    for i in 0..fragments_to_fill {
        let p = Packet::Data {
            message_id: MessageId(i as u32),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(2),
            data: vec![0u8; chunk_size],
        };
        bob.handle_packet(p, now);
    }

    // 2. Next fragment should be rejected if it exceeds MAX_TOTAL_REASSEMBLY_BUFFER
    let p_last = Packet::Data {
        message_id: MessageId(99999),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(2),
        data: vec![0u8; chunk_size * 2],
    };
    let _replies = bob.handle_packet(p_last, now);
    assert!(!has_message_event(&mut bob));
}

#[test]
fn test_session_buffer_accounting_hard_limit() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let quota = tox_sequenced::quota::ReassemblyQuota::new(1000); // Very small
    let mut bob = SequenceSession::with_quota_at(quota, now, tp.clone(), &mut rng);

    // Send a message that takes up 995 bytes (Critical since it's 1 fragment)
    let p = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1),
        data: vec![0u8; 995],
    };
    bob.handle_packet(p, now);

    // Now try to send another 10 bytes. Total 1005 > 1000. Should be rejected.
    let p2 = Packet::Data {
        message_id: MessageId(2),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1),
        data: vec![0u8; 10],
    };
    bob.handle_packet(p2, now);
    assert!(!has_message_event(&mut bob));
}

#[test]
fn test_ack_delay_bug() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // Make bob send something to push next_pacing_time into the future
    bob.send_message(MessageType::MerkleNode, &[0u8; 10000], now)
        .unwrap();
    bob.get_packets_to_send(now, 0);
    let after_send = bob.next_check_time();
    // Pacing for one fragment is ~10ms.
    assert!(
        after_send > now + Duration::from_millis(8),
        "next_check_time should be in the future due to pacing, but it is {:?}",
        after_send.duration_since(now)
    );

    let later = now + Duration::from_millis(2);

    // Receive 2 fragments of a message. This should trigger an immediate ACK.
    let p1 = Packet::Data {
        message_id: MessageId(101),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(3),
        data: vec![0u8; 100],
    };
    let p2 = Packet::Data {
        message_id: MessageId(101),
        fragment_index: FragmentIndex(1),
        total_fragments: FragmentCount(3),
        data: vec![0u8; 100],
    };

    bob.handle_packet(p1, later);
    bob.handle_packet(p2, later);

    // next_check_time should be 'later' because count is 2.
    // If bug exists, it will be 'after_send' (which is far in the future due to pacing).
    let next = bob.next_check_time();
    assert!(
        next <= later,
        "ACK should be due immediately when count >= 2, but next_check_time is {:?} (later is {:?})",
        next,
        later
    );
}

#[test]
fn test_window_deadlock_on_timeout() {
    use tox_sequenced::protocol::ESTIMATED_PAYLOAD_SIZE;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Fill the congestion window.
    // Initial CWND is usually 10.
    let initial_cwnd = alice.cwnd();
    let data_size = initial_cwnd * ESTIMATED_PAYLOAD_SIZE;
    let data = vec![0u8; data_size];

    let msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .expect("Failed to send");

    let mut packets = Vec::new();
    let mut current_time = now;

    // Send until window is full
    for _ in 0..100 {
        let p = alice.get_packets_to_send(current_time, 0);
        if p.is_empty() {
            // Advance time to allow pacing
            current_time += Duration::from_millis(10);
            continue;
        }
        packets.extend(p);
        if alice.in_flight() >= data_size {
            break;
        }
    }

    assert!(
        alice.in_flight() >= data_size,
        "Window should be full, in_flight: {}, data_size: {}",
        alice.in_flight(),
        data_size
    );

    // 2. Wait for RTO.
    // Initial RTO is 1000ms.
    let timeout_time = current_time + Duration::from_millis(1500);

    // 3. Try to get retransmissions.
    // If there is a deadlock, this will return empty because retries == 0 and in_flight >= cwnd.
    let retransmissions = alice.get_packets_to_send(timeout_time, 0);

    let retransmitted_data = retransmissions
        .iter()
        .any(|p| matches!(p, Packet::Data { message_id, .. } if *message_id == msg_id));

    assert!(
        retransmitted_data,
        "Alice should have retransmitted after timeout even if window is full"
    );
    assert!(
        alice.cwnd() < initial_cwnd,
        "CWND should have been reduced after timeout, expected < {}, got {}",
        initial_cwnd,
        alice.cwnd()
    );
}

#[test]
fn test_message_prioritization() {
    use tox_sequenced::protocol::ESTIMATED_PAYLOAD_SIZE;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Send a large BlobData message (Low Priority)
    // 10 fragments
    let data_large = vec![0u8; 10 * ESTIMATED_PAYLOAD_SIZE];
    let _id_low = alice
        .send_message(MessageType::BlobData, &data_large, now)
        .unwrap();

    // 2. Send a small CapsAnnounce message (High Priority)
    let data_small = b"Hi".to_vec();
    let id_high = alice
        .send_message(MessageType::CapsAnnounce, &data_small, now)
        .unwrap();

    // 3. Get packets to send.
    // If prioritization works, the CapsAnnounce packet should be first among DATA packets.
    let packets = alice.get_packets_to_send(now, 0);

    let first_data = packets
        .iter()
        .find(|p| matches!(p, Packet::Data { .. }))
        .expect("Should have data packets");
    match first_data {
        Packet::Data { message_id, .. } => {
            assert_eq!(
                *message_id, id_high,
                "High priority message should be sent first even if added later"
            );
        }
        _ => unreachable!(),
    }
}

#[test]
fn test_serialization_instant_bug() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Send a message and "transmit" it
    alice
        .send_message(MessageType::MerkleNode, b"bug test", now)
        .unwrap();
    let packets = alice.get_packets_to_send(now, 0);
    assert!(!packets.is_empty());
    assert!(alice.in_flight() > 0);

    // Initial timeout might be pacing (short) or RTO (1000ms).
    let initial_timeout = alice.next_check_time();

    // 2. Wait 500ms and serialize
    let ctx = tox_proto::ToxContext::new(tp.clone());
    let serialized = tox_proto::serialize_with_ctx(&alice, &ctx).unwrap();

    // 3. Wait another 500ms and deserialize.
    let reloaded: SequenceSession = tox_proto::deserialize_with_ctx(&serialized, &ctx).unwrap();

    // 4. Check next_check_time of reloaded session.
    // It SHOULD be identical to initial_timeout.
    let reloaded_timeout = reloaded.next_check_time();

    assert!(
        reloaded_timeout <= initial_timeout + Duration::from_millis(1),
        "Reloaded timeout shifted! Original: {:?}, Reloaded: {:?}",
        initial_timeout,
        reloaded_timeout
    );
}

#[test]
fn test_instant_serialization_future_clamp() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let ctx = tox_proto::ToxContext::new(tp.clone());

    // age_micros = 10,000,000 (10 seconds in the future)
    let age_micros: i128 = 10_000_000;
    let system_time_at_send: i64 = 0;

    let mut encoded = Vec::new();
    tox_proto::rmp::encode::write_array_len(&mut encoded, 2).unwrap();
    tox_proto::ToxSerialize::serialize(&age_micros, &mut encoded, &ctx).unwrap();
    tox_proto::ToxSerialize::serialize(&system_time_at_send, &mut encoded, &ctx).unwrap();

    let decoded: Instant = tox_proto::deserialize_with_ctx(&encoded, &ctx).unwrap();

    // The deserialized instant should be clamped to 'now' and not be in the future.
    assert!(
        decoded <= tp.now_instant(),
        "Future instant was not clamped!"
    );
}

#[test]
fn test_completed_incoming_ttl_bug() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Alice sends a message to Bob.
    let _id = alice
        .send_message(MessageType::MerkleNode, b"test", now)
        .unwrap();
    let packets = alice.get_packets_to_send(now, 0);
    let data_packet = packets
        .iter()
        .find(|p| matches!(p, Packet::Data { .. }))
        .unwrap()
        .clone();
    for p in packets {
        bob.handle_packet(p, now);
    }

    // Bob has completed it and emitted MessageCompleted.
    let mut found = false;
    while let Some(event) = bob.poll_event() {
        if matches!(event, tox_sequenced::SessionEvent::MessageCompleted(..)) {
            found = true;
            break;
        }
    }
    assert!(found);

    // 2. Wait for current TTL (30s) to expire on Bob.
    let later = now + Duration::from_secs(31);
    bob.cleanup(later);

    // 3. Alice retransmits because she didn't get the ACK (simulate lost ACK).
    let _replies = bob.handle_packet(data_packet, later);

    let mut found = false;
    while let Some(event) = bob.poll_event() {
        if matches!(event, tox_sequenced::SessionEvent::MessageCompleted(..)) {
            found = true;
            break;
        }
    }

    // Fixed: Bob will reject it as ancient because it was already completed and purged.
    assert!(
        !found,
        "Bob should NOT have returned the same message again after TTL expiry"
    );
}

#[test]
fn test_ready_to_send_event() {
    use tox_sequenced::SessionEvent;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    alice
        .send_message(MessageType::MerkleNode, b"test", now)
        .unwrap();
    let packets = alice.get_packets_to_send(now, 0);
    for p in packets {
        bob.handle_packet(p, now);
    }
    let acks = bob.get_packets_to_send(now, 0);
    for a in acks {
        alice.handle_packet(a, now);
    }

    let mut found = false;
    while let Some(event) = alice.poll_event() {
        if matches!(event, SessionEvent::ReadyToSend) {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "Should have received ReadyToSend event after message completion"
    );
}

#[test]
fn test_rwnd_zero_when_full() {
    use tox_sequenced::protocol::MAX_CONCURRENT_INCOMING;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // Fill up Bob's incoming reassemblers
    for i in 0..MAX_CONCURRENT_INCOMING {
        let p = Packet::Data {
            message_id: MessageId(i as u32),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(10),
            data: vec![0u8; 1000],
        };
        let _replies = bob.handle_packet(p, now);
        assert!(!has_message_event(&mut bob));
    }

    // Now send the (MAX_CONCURRENT_INCOMING + 1)th message. Bob should reject it because he has too many concurrent messages.
    // He SHOULD send an ACK with a low or zero rwnd to tell the sender to wait.
    let next_id = MessageId(MAX_CONCURRENT_INCOMING as u32 + 100);
    let p_next = Packet::Data {
        message_id: next_id,
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(10),
        data: vec![0u8; 1000],
    };

    let replies = bob.handle_packet(p_next, now);

    // This is expected to FAIL currently because Bob returns empty replies (None/empty Vec)
    assert!(
        !replies.is_empty(),
        "Bob should have sent an ACK for the rejected packet"
    );

    let mut found_ack = false;
    for reply in replies {
        if let Packet::Ack(ack) = reply {
            assert_eq!(ack.message_id, next_id);
            found_ack = true;
        }
    }
    assert!(found_ack, "Bob should have sent an ACK");
}

#[test]
fn test_rwnd_zero_when_buffer_full() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Fill up Bob's reassembly buffer using 2-fragment messages.
    // Each slot stays in 'incoming' until completion or timeout.
    let data_1mb = vec![0u8; 1024 * 1024];
    for i in 0..22 {
        let p = Packet::Data {
            message_id: MessageId(i as u32),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(2),
            data: data_1mb.clone(),
        };
        bob.handle_packet(p, now);
    }

    // used is ~22MB. 23rd message (Bulk) would be rejected (> 70% of 32MB = 22.4MB).

    // Now send a Bulk message (1000). It should be rejected.
    let p_over = Packet::Data {
        message_id: MessageId(1000),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(2),
        data: data_1mb.clone(),
    };

    let replies = bob.handle_packet(p_over, now);
    assert!(!has_message_event(&mut bob));
    assert!(!replies.is_empty());

    if let Packet::Ack(ack) = &replies[0] {
        assert_eq!(ack.message_id, MessageId(1000));
        // rwnd is ~10MB (the remaining space until 32MB hard limit)
        assert!(ack.rwnd.0 <= 10000);
    }
}

#[test]
fn test_in_flight_queue_duplication_vulnerability() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Send a message to get something into in_flight_queue
    alice
        .send_message(MessageType::MerkleNode, b"test", now)
        .unwrap();
    let _ = alice.get_packets_to_send(now, 0);

    // 2. Advance time past RTO so a timeout is pending
    let later = now + Duration::from_secs(2);

    // 3. Call get_packets_to_send many times at the SAME time 'later'.
    // The first call will see the timeout, try to transmit, and if pacing (set by the first transmit)
    // or simply the logic in send_timeouts_for_message triggers, it might push_front.

    for _ in 0..100 {
        alice.get_packets_to_send(later, 0);
    }

    // If the bug exists, in_flight_queue has grown.
    let even_later = later + Duration::from_secs(10);
    let packets = alice.get_packets_to_send(even_later, 0);

    let data_count = packets
        .iter()
        .filter(|p| matches!(p, Packet::Data { .. }))
        .count();
    // It should only send it ONCE (the retransmission).
    assert!(
        data_count <= 1,
        "Bug: sent same fragment {} times in one poll due to queue duplication. data_count={}",
        data_count,
        data_count
    );
}

#[test]
fn test_memory_accounting_preallocation_vulnerability() {
    use tox_sequenced::protocol::MAX_TOTAL_REASSEMBLY_BUFFER;
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // Send first fragment of a 1024-fragment message.
    // MTU is ~1300. Allocation will be ~1.3MB.
    let p = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1024),
        data: vec![0u8; 1300],
    };

    let _ = bob.handle_packet(p, now);

    // Advance time to force the delayed ACK
    let later = now + Duration::from_millis(100);
    let replies = bob.get_packets_to_send(later, 0);

    let ack = replies
        .into_iter()
        .find(|p| matches!(p, Packet::Ack(_)))
        .expect("Expected an ACK");
    if let Packet::Ack(ack) = ack {
        let max_expected_rwnd = MAX_TOTAL_REASSEMBLY_BUFFER as u32 - (1300 * 1023) as u32;
        // The current implementation only accounts for the 1300 bytes received.
        assert!(
            u32::from(ack.rwnd.0) <= max_expected_rwnd,
            "RWND {} does not account for pre-allocation (expected <= {})",
            ack.rwnd,
            max_expected_rwnd
        );
    }
}

#[test]
fn test_completed_incoming_limit_enforced() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    let payload = vec![0u8; 10];
    let envelope = OutboundEnvelope {
        message_type: MessageType::BlobData,
        payload: &payload,
    };
    let data = tox_sequenced::protocol::serialize(&envelope).unwrap();

    // Complete 1100 messages to exceed the 1024 limit.
    for i in 0..1100 {
        let p = Packet::Data {
            message_id: MessageId(i),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(1),
            data: data.clone(),
        };
        let _replies = bob.handle_packet(p, now);

        let mut completed = false;
        while let Some(event) = bob.poll_event() {
            if matches!(event, tox_sequenced::SessionEvent::MessageCompleted(..)) {
                completed = true;
            }
        }
        assert!(completed, "Message {} should have completed", i);
    }

    // If a limit (e.g. 1024) is enforced, then message 0 should have been purged.
    let p0_dup = Packet::Data {
        message_id: MessageId(0),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1),
        data: data.clone(),
    };

    let _replies = bob.handle_packet(p0_dup, now);

    let mut completed = false;
    while let Some(event) = bob.poll_event() {
        if matches!(event, tox_sequenced::SessionEvent::MessageCompleted(..)) {
            completed = true;
        }
    }
    // If a limit (e.g. 1024) is enforced AND the ancient window matches,
    // then message 0 should be rejected.
    assert!(
        !completed,
        "Old completed message 0 should have been rejected as ancient"
    );
}

#[test]
fn test_retransmit_deadlock_on_zero_window() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut session = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let data = vec![0u8; 1000 * 10]; // 10 fragments
    let id = session
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    // Send one packet to get things started
    let packets = session.get_packets_to_send(now, 0);
    assert!(!packets.is_empty());

    // Receive an ACK that sets rwnd to 0 (receiver buffer full)
    // but acknowledges nothing (base_index=0).
    session.handle_packet(
        Packet::Ack(tox_sequenced::protocol::SelectiveAck {
            message_id: id,
            base_index: FragmentIndex(0),
            bitmask: 0,
            rwnd: FragmentCount(0), // Zero Window!
        }),
        now,
    );

    // 1. Force a retransmission to be queued.
    // We can simulate a NACK for fragment 0.
    session.handle_packet(
        Packet::Nack(tox_sequenced::protocol::Nack {
            message_id: id,
            missing_indices: smallvec::smallvec![FragmentIndex(0)],
        }),
        now,
    );

    // Verify retransmit queue has 0
    assert!(session.retransmit_queue_len() > 0);

    // 2. Try to send packets.
    // Expected: Fragment 0 should be sent despite rwnd=0, because it's the oldest hole.
    // Without the fix, this returns empty because rwnd is 0.
    let later = now + Duration::from_millis(100);
    let packets = session.get_packets_to_send(later, 0);

    let sent_0 = packets.iter().any(|p| {
        if let Packet::Data { fragment_index, .. } = p {
            fragment_index.0 == 0
        } else {
            false
        }
    });

    assert!(
        sent_0,
        "Should retransmit fragment 0 (hole) even if rwnd is 0"
    );
}

#[test]
fn test_memory_limit_bypass_via_last_fragment() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. We want to exceed MAX_TOTAL_REASSEMBLY_BUFFER (32MB).
    // MAX_CONCURRENT_INCOMING is 32.
    // Each message will be 1MB (the protocol limit).
    // 32 messages * 1MB = 32MB, which reaches the limit.
    // Let's use 34 messages to ensure we exceed 32MB.

    let large_fragment = vec![0u8; 1000]; // 1KB
    let _total_frags = 1000; // Total size ~1MB per message

    // We start 34 messages (IDs 0..33).
    for i in 0..34 {
        // Send Last Fragment (Index 999) - 1 byte
        let p_last = Packet::Data {
            message_id: MessageId(i),
            fragment_index: FragmentIndex(999),
            total_fragments: FragmentCount(1000),
            data: vec![0u8; 1],
        };

        let _replies = bob.handle_packet(p_last, now);
        assert!(!has_message_event(&mut bob));

        // Send First Fragment (Index 0) - 1KB
        let p_first = Packet::Data {
            message_id: MessageId(i),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(1000),
            data: large_fragment.clone(),
        };

        let _replies = bob.handle_packet(p_first, now);
        assert!(!has_message_event(&mut bob));
    }

    // 2. Verify we overshot the buffer.
    // We check if Message 33 is still in memory.
    let p_check = Packet::Data {
        message_id: MessageId(33),
        fragment_index: FragmentIndex(1),
        total_fragments: FragmentCount(1000),
        data: large_fragment.clone(),
    };

    let mut replies = bob.handle_packet(p_check, now);
    let later = now + Duration::from_millis(100);
    replies.extend(bob.get_packets_to_send(later, 0));

    let ack = replies
        .into_iter()
        .find(|p| matches!(p, Packet::Ack(_)))
        .expect("Expected an ACK (either immediate rejection or delayed ACK)");

    if let Packet::Ack(ack) = ack {
        assert_eq!(ack.message_id, MessageId(33));
        // If the vulnerability exists, the message was accepted and bit 0 of the mask
        // (fragment 1) will be set because it's a SACK.
        let has_fragment_1 = (ack.bitmask & 1) != 0;

        assert!(
            !has_fragment_1,
            "Message 33 was accepted despite memory overflow! Vulnerability exists."
        );
    }
}

#[test]
fn test_in_flight_undercount_on_nack() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Send a multi-fragment message
    let data = vec![0u8; 5000]; // ~4 fragments
    alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    // 2. Transmit all fragments (advancing time for pacing)
    let mut packets = Vec::new();
    let mut current_now = now;
    for _ in 0..100 {
        packets.extend(alice.get_packets_to_send(current_now, 0));
        if packets.len() >= 4 {
            break;
        }
        current_now += Duration::from_millis(20);
    }
    assert!(packets.len() >= 4);
    let initial_in_flight = alice.in_flight();
    assert!(initial_in_flight > 0);

    // 3. Simulate a NACK for fragment 0
    let nack = Packet::Nack(tox_sequenced::protocol::Nack {
        message_id: alice.next_message_id().wrapping_add(u32::MAX),
        missing_indices: smallvec::smallvec![FragmentIndex(0)],
    });
    alice.handle_packet(nack, now);

    // 4. Fragment 0 should be removed from in_flight by handle_packet (NACK)
    let in_flight_after_nack = alice.in_flight();
    assert!(in_flight_after_nack < initial_in_flight);

    // 5. Retransmit fragment 0
    let later = now + Duration::from_millis(100);
    let retrans = alice.get_packets_to_send(later, 0);
    assert!(retrans.iter().any(|p| matches!(
        p,
        Packet::Data {
            fragment_index: FragmentIndex(0),
            ..
        }
    )));

    // 6. Check in_flight. It should be back to initial_in_flight.
    // If the bug exists, it will be LOWER than initial_in_flight because it was subtracted twice.
    assert_eq!(
        alice.in_flight(),
        initial_in_flight,
        "In-flight undercounted!"
    );
}

#[test]
fn test_global_memory_quota_backpressure() {
    use tox_sequenced::quota::ReassemblyQuota;

    let global_limit = 200 * 1024; // 200KB (increased from 100KB)
    let quota = ReassemblyQuota::new(global_limit);

    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);

    // 1. Initial state: both should report full global limit as available (or local cap)
    assert!(u32::from(alice.current_rwnd().0) >= (global_limit as u32 / 1400));
    assert!(u32::from(bob.current_rwnd().0) >= (global_limit as u32 / 1400));

    // 2. Alice starts receiving a message to consume memory
    let data = vec![0u8; 60 * 1024]; // 60KB
    let p_alice = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(2),
        data,
    };
    alice.handle_packet(p_alice, now);

    // Alice has planned ~120KB (2 * 60KB). Global free is ~80KB.
    let alice_rwnd = alice.current_rwnd();
    let bob_rwnd = bob.current_rwnd();

    assert!(
        alice_rwnd.0 <= 100,
        "Alice RWND should reflect global usage. Got {}",
        alice_rwnd
    );
    assert!(
        bob_rwnd.0 <= 100,
        "Bob RWND should reflect global usage from Alice. Got {}",
        bob_rwnd
    );

    // 3. Bob tries to receive a message that would exceed the remaining global quota
    let data_too_big = vec![0u8; 90 * 1024]; // 90KB (Total 120+90 = 210 > 200)
    let p_bob = Packet::Data {
        message_id: MessageId(2),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1),
        data: data_too_big,
    };

    let replies = bob.handle_packet(p_bob, now);
    // Should be rejected
    let ack = replies
        .into_iter()
        .find(|p| matches!(p, Packet::Ack(_)))
        .expect("Expected rejection ACK");
    if let Packet::Ack(ack) = ack {
        assert!(ack.rwnd.0 <= 100);
    }
}

#[test]
fn test_quota_release_on_cleanup() {
    use tox_sequenced::quota::ReassemblyQuota;
    let global_limit = 100 * 1024;
    let quota = ReassemblyQuota::new(global_limit);
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);

    // 1. Occupy quota.
    // total_fragments = 2, so potential_allocation = 1 * fragment_size.
    // fragment_size = 30KB. Total 30KB < 100KB.
    let data = vec![0u8; 30 * 1024];
    let p = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(2),
        data,
    };
    alice.handle_packet(p, now);
    assert!(
        quota.used() >= 30 * 1024,
        "Expected quota used to be at least 30KB, got {}",
        quota.used()
    );

    // 2. Wait for timeout
    let later = now + Duration::from_secs(61);
    alice.cleanup(later);

    // 3. Quota should be released
    assert_eq!(
        quota.used(),
        0,
        "Quota should be 0 after cleanup of timed out reassemblies"
    );
}

#[test]
fn test_fair_share_rejection_at_limit() {
    use tox_sequenced::quota::ReassemblyQuota;
    let global_limit = 3000;
    let quota = ReassemblyQuota::new(global_limit);
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    let mut s1 = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);
    let mut s2 = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);

    // s1 takes 1200 bytes. Planned = 2400. Remaining = 600.
    s1.handle_packet(
        Packet::Data {
            message_id: MessageId(1),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(2),
            data: vec![0u8; 1200],
        },
        now,
    );

    // s2 tries to take 1200 bytes -> should be rejected because total 2400+1200 = 3600 > 3000
    let replies = s2.handle_packet(
        Packet::Data {
            message_id: MessageId(2),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(1),
            data: vec![0u8; 1200],
        },
        now,
    );

    assert!(!has_message_event(&mut s2));
    assert!(replies.iter().any(
        |p| matches!(p, Packet::Ack(ack) if ack.message_id == MessageId(2) && ack.rwnd.0 <= 600)
    ));
}

#[test]
fn test_dynamic_quota_reallocation() {
    use tox_sequenced::protocol::{OutboundEnvelope, serialize};
    use tox_sequenced::quota::ReassemblyQuota;

    let global_limit = 200 * 1024; // 200KB (increased from 100KB)
    let quota = ReassemblyQuota::new(global_limit);
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    let mut alice = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);

    // 1. Prepare a valid message that will be ~70KB
    let blob_payload = vec![0u8; 70 * 1024];
    let envelope = OutboundEnvelope {
        message_type: MessageType::BlobData,
        payload: &blob_payload,
    };
    let alice_full_data = serialize(&envelope).unwrap();
    let alice_fragment_0 = alice_full_data[0..60 * 1024].to_vec();
    let alice_fragment_1 = alice_full_data[60 * 1024..].to_vec();

    // Alice starts reassembly
    alice.handle_packet(
        Packet::Data {
            message_id: MessageId(1),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(2),
            data: alice_fragment_0,
        },
        now,
    );

    let used_initially = quota.used();
    assert!(used_initially >= 120 * 1024);

    // 2. Bob tries to start a 50KB message -> Rejected
    let _replies_bob = bob.handle_packet(
        Packet::Data {
            message_id: MessageId(2),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(2),
            data: vec![0u8; 50 * 1024],
        },
        now,
    );

    assert!(!has_message_event(&mut bob));
    assert_eq!(quota.used(), used_initially);

    // 3. Alice completes her message -> Quota released
    let _replies_alice = alice.handle_packet(
        Packet::Data {
            message_id: MessageId(1),
            fragment_index: FragmentIndex(1),
            total_fragments: FragmentCount(2),
            data: alice_fragment_1,
        },
        now,
    );

    let alice_completed = has_message_event(&mut alice);

    assert!(
        alice_completed,
        "Alice should have completed her message with valid data"
    );
    assert_eq!(
        quota.used(),
        0,
        "Alice should have released all quota upon completion"
    );

    // 4. Bob tries again -> Accepted (100KB available)
    let _replies_bob2 = bob.handle_packet(
        Packet::Data {
            message_id: MessageId(2),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(2),
            data: vec![0u8; 50 * 1024],
        },
        now,
    );

    assert!(!has_message_event(&mut bob));
    assert!(quota.used() >= 50 * 1024);
}

#[test]
fn test_replay_attack_vulnerability() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut current_now = now;

    // 1. Alice sends M1 to Bob
    let data = b"Original Message".to_vec();
    let _msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();
    let packets = alice.get_packets_to_send(now, 0);

    // Capture the packets for M1 for later replay
    let m1_packets = packets.clone();

    // Bob receives M1
    let mut received = false;
    for p in packets {
        let _replies = bob.handle_packet(p, now);
        while let Some(event) = bob.poll_event() {
            if matches!(event, tox_sequenced::SessionEvent::MessageCompleted(..)) {
                received = true;
            }
        }
    }
    assert!(received, "Bob should have received M1");

    // 2. Bob acknowledges M1
    let acks = bob.get_packets_to_send(now, 0);
    for ack in acks {
        alice.handle_packet(ack, now);
    }

    // 3. Evict M1 from Bob's duplicate detection cache and ancient window
    // MAX_COMPLETED_INCOMING = 1024, Ancient Window = 2048
    for i in 0..2050 {
        let filler_data = format!("Filler {}", i).into_bytes();
        let filler_id = alice
            .send_message(MessageType::MerkleNode, &filler_data, current_now)
            .unwrap();

        let mut filler_received = false;
        // We might need to step time to allow sending many messages if cwnd is small
        for _ in 0..100 {
            let p = alice.get_packets_to_send(current_now, 0);
            if p.is_empty() {
                current_now += Duration::from_millis(1);
                continue;
            }
            for packet in p {
                let acks = bob.handle_packet(packet, current_now);
                for ack in acks {
                    alice.handle_packet(ack, current_now);
                }

                // Also poll Bob for delayed/completed ACKs
                for ack in bob.get_packets_to_send(current_now, 0) {
                    alice.handle_packet(ack, current_now);
                }

                while let Some(event) = bob.poll_event() {
                    if let tox_sequenced::SessionEvent::MessageCompleted(id, _, _) = event
                        && id == filler_id
                    {
                        filler_received = true;
                    }
                }
            }
            if filler_received {
                break;
            }
        }
        assert!(
            filler_received,
            "Filler message {} should have been received",
            i
        );
    }

    // 4. Replay M1 to Bob
    let mut replay_accepted = false;
    for p in m1_packets {
        let _replies = bob.handle_packet(p, current_now);
        while let Some(event) = bob.poll_event() {
            if matches!(event, tox_sequenced::SessionEvent::MessageCompleted(..)) {
                replay_accepted = true;
            }
        }
    }

    // This assertion SHOULD FAIL if the vulnerability exists
    assert!(
        !replay_accepted,
        "Bob should NOT have accepted a replayed message after eviction"
    );
}

#[test]
fn test_duplicate_completion_notification() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let envelope = tox_sequenced::protocol::OutboundEnvelope {
        message_type: MessageType::CapsAnnounce,
        payload: b"hello",
    };
    let data = tox_sequenced::protocol::serialize(&envelope).unwrap();
    let p = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1),
        data,
    };

    let _replies = bob.handle_packet(p, now);

    let mut event_count = 0;
    while let Some(event) = bob.poll_event() {
        if let tox_sequenced::SessionEvent::MessageCompleted(id, _, _) = event {
            assert_eq!(id, MessageId(1));
            event_count += 1;
        }
    }

    assert_eq!(
        event_count, 1,
        "Exactly one MessageCompleted event should be emitted"
    );
}

#[test]
fn test_quota_bypass_vulnerability() {
    use tox_sequenced::quota::ReassemblyQuota;
    // Set a quota: Bulk threshold (70%) = 70KB. Critical threshold (99%) = 99KB.
    // Fair Share Guarantee is 16KB.
    let quota = ReassemblyQuota::new(100_000);
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::with_quota_at(quota, now, tp.clone(), &mut rng);

    // Multi-fragment message: ~80KB total allocation.
    // 80KB > 16KB (not fair shared).
    // Should be treated as Bulk (rejected > 70KB) but currently defaults to CapsAnnounce (Critical, accepted < 99KB).
    let p = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(80), // ~80KB total (80 * 1000)
        data: vec![0u8; 1000],
    };

    bob.handle_packet(p, now);

    assert!(
        bob.find_incoming(MessageId(1)).is_none(),
        "Multi-fragment message bypassed Bulk quota by defaulting to Critical priority"
    );
}

#[test]
fn test_quota_leak_on_session_limit_exceeded() {
    use tox_sequenced::quota::ReassemblyQuota;
    let global_limit = 64 * 1024 * 1024;
    let quota = ReassemblyQuota::new(global_limit);
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    // Create a session and force a small max_per_session.
    let mut bob = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);
    bob.max_per_session = 10000;

    // 1. Fill some memory (3000 bytes). Planned = 6000.
    let p_init = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(2),
        data: vec![0u8; 3000],
    };
    bob.handle_packet(p_init, now);
    let initial_quota_used = quota.used();
    assert!(initial_quota_used >= 6000);

    // 2. Message 2: Send LAST fragment first (100 bytes)
    // potential_allocation = 1300 + 100 = 1400. 6000 + 1400 = 7400 < 10000. Accepted.
    let p_last = Packet::Data {
        message_id: MessageId(2),
        fragment_index: FragmentIndex(1),
        total_fragments: FragmentCount(2),
        data: vec![0u8; 100],
    };
    bob.handle_packet(p_last, now);
    // new reservation for Msg 2: 1300 (est) + 100 (last) = 1400.
    // Plus overhead for 2 fragments: 2 * 56 = 112. Total = 1512.
    assert_eq!(quota.used(), initial_quota_used + 1512);

    // 3. Message 2: Send FIRST fragment (3000 bytes)
    // New planned for Msg 2 = 3000 + 3000 = 6000.
    // Total session usage = 6000 + 6000 = 12000 > 10000.
    let p_first = Packet::Data {
        message_id: MessageId(2),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(2),
        data: vec![0u8; 3000],
    };

    bob.handle_packet(p_first, now);

    // The message should have been discarded.
    assert!(bob.find_incoming(MessageId(2)).is_none());

    // 4. Check for leak.
    assert_eq!(quota.used(), initial_quota_used, "Memory quota leaked!");
}

#[test]
fn test_critical_fragment_admission_bug() {
    use tox_sequenced::quota::ReassemblyQuota;
    // Set a quota: Bulk threshold (70%) = 70KB. Critical threshold (99%) = 99KB.
    let quota = ReassemblyQuota::new(100_000);
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);

    // 1. Fill quota to 80% (above Bulk threshold 70%, below Critical 99%)
    // We use reserve_guaranteed to simulate existing memory usage without priority constraints.
    assert!(quota.reserve_guaranteed(80_000));

    // 2. Receive a fragmented message that SHOULD be Critical (e.g. SyncHeads)
    // We want to see it accepted.
    let p = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(10), // ~13KB total.
        // Quota: 100KB. Used: 80KB.
        // Critical Threshold: 99KB. Avail: 19KB. -> ACCEPT
        // Standard Threshold: 90KB. Avail: 10KB. -> REJECT (if misidentified)
        data: vec![0u8; 1000],
    };

    let _replies = bob.handle_packet(p, now);

    assert!(
        bob.find_incoming(MessageId(1)).is_some(),
        "Fragmented Critical message (SyncHeads) should be admitted even if quota is > 70%"
    );
}

#[test]
fn test_priority_peeking_enforcement() {
    init_tracing();
    use tox_sequenced::protocol::{MessageType, OutboundEnvelope, serialize};
    use tox_sequenced::quota::ReassemblyQuota;

    // Set a quota where Bulk is rejected but Standard is accepted.
    // Bulk threshold = 70%. Standard = 90%.
    let quota = ReassemblyQuota::new(100_000);
    assert!(quota.reserve_guaranteed(80_000)); // 80% used.

    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::with_quota_at(quota.clone(), now, tp.clone(), &mut rng);

    // 1. Create a payload that is actually a BlobData (Bulk Priority)
    let blob_data = vec![0u8; 20_000];
    let envelope = OutboundEnvelope {
        message_type: MessageType::BlobData,
        payload: &blob_data,
    };
    let data = serialize(&envelope).unwrap();

    // 2. Send it. Session should peek at fragment 0, see BlobData, and REJECT it
    // because 80% > 70% (Bulk threshold).
    let p = Packet::Data {
        message_id: MessageId(1),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(20),
        data,
    };

    bob.handle_packet(p, now);

    assert!(
        bob.find_incoming(MessageId(1)).is_none(),
        "Session admitted a Bulk message when quota was at 80%"
    );

    // 3. Now send a payload that is actually a SyncHeads (Critical Priority)
    let crit_env = OutboundEnvelope {
        message_type: MessageType::SyncHeads,
        payload: b"sync",
    };
    let crit_data = serialize(&crit_env).unwrap();
    let p_crit = Packet::Data {
        message_id: MessageId(2),
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(2),
        data: crit_data,
    };

    bob.handle_packet(p_crit, now);

    assert!(
        bob.find_incoming(MessageId(2)).is_some(),
        "Session rejected a Critical message when quota was at 80% (Critical threshold is 99%)"
    );
}

#[test]
fn test_replay_vulnerability_in_ancient_window() {
    let now = Instant::now();
    let tp = Arc::new(ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);

    // 1. Send M1
    let msg_id = alice
        .send_message(MessageType::MerkleNode, b"vulnerable", now)
        .unwrap();
    let packets = alice.get_packets_to_send(now, 0);
    let m1_packet = packets
        .iter()
        .find(|p| matches!(p, Packet::Data { .. }))
        .unwrap()
        .clone();

    for p in packets {
        bob.handle_packet(p, now);
    }

    // Drain events
    while bob.poll_event().is_some() {}

    // 2. Bob acknowledges M1
    for p in bob.get_packets_to_send(now, 0) {
        alice.handle_packet(p, now);
    }

    // 3. Evict M1 from Bob's cache (1024 messages) but STAY within ancient window (2048)
    let mut current_now = now;
    for _i in 0..1050 {
        let _filler = alice
            .send_message(MessageType::MerkleNode, &[0], current_now)
            .unwrap();
        // Fast forward delivery
        for _ in 0..100 {
            let p = alice.get_packets_to_send(current_now, 0);
            if p.is_empty() {
                current_now += Duration::from_millis(10);
                continue;
            }
            for packet in p {
                bob.handle_packet(packet, current_now);
            }
            while bob.poll_event().is_some() {}
            for p in bob.get_packets_to_send(current_now, 0) {
                alice.handle_packet(p, current_now);
            }
            break;
        }
    }

    // 4. Replay M1
    let _replies = bob.handle_packet(m1_packet, current_now);

    let mut replayed = false;
    while let Some(event) = bob.poll_event() {
        if let tox_sequenced::SessionEvent::MessageCompleted(id, ..) = event
            && id == msg_id
        {
            replayed = true;
        }
    }

    assert!(
        !replayed,
        "M1 was replayed! It was evicted from cache but still within ancient window."
    );
}
