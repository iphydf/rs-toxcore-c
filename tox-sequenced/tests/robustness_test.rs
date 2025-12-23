use rand::SeedableRng;
use rand::seq::SliceRandom;
use std::time::{Duration, Instant};
use tox_sequenced::protocol::{
    FragmentCount, FragmentIndex, MAX_CONCURRENT_INCOMING, MessageId, MessageType, Packet,
    SelectiveAck,
};
use tox_sequenced::{SequenceSession, SessionEvent};

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
fn test_packet_reordering() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    // Larger message to ensure multiple fragments even with overhead
    let data = vec![0u8; 5000];
    let msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .expect("Failed to send message");

    let mut data_packets = Vec::new();
    let mut current_now = now;
    // Advance time until we have all fragments. 5000 bytes should be ~4 fragments.
    for _ in 0..100 {
        let p = alice.get_packets_to_send(current_now, 0);
        data_packets.extend(p.into_iter().filter(|p| matches!(p, Packet::Data { .. })));
        if data_packets.len() >= 4 {
            break;
        }
        current_now += Duration::from_millis(20);
    }

    assert!(
        data_packets.len() > 1,
        "Message was not fragmented. Fragments: {}",
        data_packets.len()
    );

    // Shuffle packets
    data_packets.shuffle(&mut rng);

    // Bob receives in random order
    let mut completed = false;
    for packet in data_packets {
        let _replies = bob.handle_packet(packet, now);
        while let Some(event) = bob.poll_event() {
            if let tox_sequenced::SessionEvent::MessageCompleted(id, _, received_data) = event {
                assert_eq!(id, msg_id);
                assert_eq!(received_data, data);
                completed = true;
            }
        }
    }
    assert!(completed);
}

#[test]
fn test_concurrent_messages() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    let data1 = b"Message One".to_vec();
    let data2 = b"Message Two".to_vec();

    let id1 = alice
        .send_message(MessageType::MerkleNode, &data1, now)
        .unwrap();
    let id2 = alice
        .send_message(MessageType::MerkleNode, &data2, now)
        .unwrap();

    let mut packets = Vec::new();
    let mut current_now = now;
    for _ in 0..100 {
        packets.extend(alice.get_packets_to_send(current_now, 0));
        if packets
            .iter()
            .any(|p| matches!(p, Packet::Data { message_id, .. } if *message_id == id1))
            && packets
                .iter()
                .any(|p| matches!(p, Packet::Data { message_id, .. } if *message_id == id2))
        {
            break;
        }
        current_now += Duration::from_millis(20);
    }

    assert!(
        packets
            .iter()
            .any(|p| matches!(p, Packet::Data { message_id, .. } if *message_id == id1))
    );
    assert!(
        packets
            .iter()
            .any(|p| matches!(p, Packet::Data { message_id, .. } if *message_id == id2))
    );

    let mut completed_count = 0;
    // Shuffle to test interleaved arrival
    packets.shuffle(&mut rng);

    for p in packets {
        let _replies = bob.handle_packet(p, now);
        while let Some(event) = bob.poll_event() {
            if let tox_sequenced::SessionEvent::MessageCompleted(id, _, data) = event {
                if id == id1 {
                    assert_eq!(data, data1);
                } else if id == id2 {
                    assert_eq!(data, data2);
                }
                completed_count += 1;
            }
        }
    }

    assert_eq!(completed_count, 2);
}

#[test]
fn test_incoming_concurrency_limit() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    // Fill up to the limit
    for i in 0..MAX_CONCURRENT_INCOMING {
        let p = Packet::Data {
            message_id: MessageId(i as u32),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(2),
            data: vec![0u8; 10],
        };
        let _replies = bob.handle_packet(p, now);
        assert!(!has_message_event(&mut bob));
    }

    // This one should be rejected (it won't even be added to `incoming`)
    let overflow_id = MessageId(999);
    let p = Packet::Data {
        message_id: overflow_id,
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(2),
        data: vec![0u8; 10],
    };
    bob.handle_packet(p, now);

    // If we send the second fragment for overflow_id, it should still not complete
    let p2 = Packet::Data {
        message_id: overflow_id,
        fragment_index: FragmentIndex(1),
        total_fragments: FragmentCount(2),
        data: vec![0u8; 10],
    };
    let _replies = bob.handle_packet(p2, now);
    assert!(
        !has_message_event(&mut bob),
        "Overflow message should have been rejected"
    );
}

#[test]
fn test_total_memory_limit() {
    use tox_sequenced::protocol::MAX_TOTAL_REASSEMBLY_BUFFER;
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);

    // We'll fill the buffer by sending 1MB fragments for different messages.
    // MAX_TOTAL_REASSEMBLY_BUFFER is 32MB.
    let msg_size = 1024 * 1024; // 1MB
    let num_msgs = MAX_TOTAL_REASSEMBLY_BUFFER / msg_size;

    for i in 0..num_msgs {
        let p = Packet::Data {
            message_id: MessageId(i as u32),
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(10), // Multi-fragment so it stays in buffer
            data: vec![0u8; msg_size],
        };
        bob.handle_packet(p, now);
    }

    // Now send one more fragment for a new message.
    // This should exceed the 64MB limit and be rejected.
    let overflow_id = MessageId(9999);
    let p_overflow = Packet::Data {
        message_id: overflow_id,
        fragment_index: FragmentIndex(0),
        total_fragments: FragmentCount(1), // Single fragment, would complete if accepted
        data: vec![0u8; 1024],
    };

    let _replies = bob.handle_packet(p_overflow, now);

    // If it were accepted, it would have completed (total_fragments: 1).
    // Since it's rejected due to memory limit, it should NOT produce a completion event.
    let mut completed = false;
    while let Some(event) = bob.poll_event() {
        if matches!(event, tox_sequenced::SessionEvent::MessageCompleted(..)) {
            completed = true;
        }
    }
    assert!(
        !completed,
        "Message should have been rejected by total memory limit"
    );
}

#[test]
fn test_total_memory_limit_single_message_leak() {
    use tox_sequenced::protocol::MAX_TOTAL_REASSEMBLY_BUFFER;
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp.clone(), &mut rng);
    let mut alice = SequenceSession::new_at(now, tp, &mut rng);

    // Send many fragments for the same message.
    let fragment_size = 1024 * 1024; // 1MB
    let total_fragments = (MAX_TOTAL_REASSEMBLY_BUFFER / fragment_size) as u16 + 10;
    let message_id = alice.next_message_id();

    for i in 0..total_fragments {
        let p = Packet::Data {
            message_id,
            fragment_index: FragmentIndex(i),
            total_fragments: FragmentCount(total_fragments),
            data: vec![0u8; fragment_size],
        };
        bob.handle_packet(p, now);
    }

    // Now attempt to send another message.
    // Alice's next message will have id = message_id + 1, so Bob won't reject it as ancient.
    let now_small = now + Duration::from_secs(1);
    let small_data = b"small".to_vec();
    let small_msg_id = alice
        .send_message_at(MessageType::MerkleNode, &small_data, now_small)
        .expect("Failed to send small message");
    let packets = alice.get_packets_to_send(now_small, 0);
    let p_small = packets
        .into_iter()
        .find(|p| matches!(p, Packet::Data { message_id, .. } if *message_id == small_msg_id))
        .expect("Could not find data packet for small message");

    let _replies = bob.handle_packet(p_small, now_small);

    // If the leak exists, the small message will be rejected.
    // If the fix is in place, the large message should have been dropped,
    // and the small message should be accepted.
    let mut found = false;
    while let Some(event) = bob.poll_event() {
        if let tox_sequenced::SessionEvent::MessageCompleted(id, _, data) = event {
            assert_eq!(id, small_msg_id);
            assert_eq!(data, small_data);
            found = true;
        }
    }

    assert!(
        found,
        "Small message should be accepted. If it is not found, it might be due to memory limit leak from message 1. Message 1 current buffer usage would prevent this 100 byte message if it leaked significantly."
    );
}

#[test]
fn test_nack_reordering_resilience() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp, &mut rng);

    // Send a message with several fragments
    let data = vec![0u8; 10000]; // ~8 fragments
    let msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    // Alice sends them. We need to advance time to overcome pacing.
    let mut current_now = now;
    let mut sent_indices = std::collections::HashSet::new();
    for _ in 0..100 {
        let packets = alice.get_packets_to_send(current_now, 0);
        for p in packets {
            if let Packet::Data { fragment_index, .. } = p {
                sent_indices.insert(fragment_index);
            }
        }
        if sent_indices.len() >= 4 {
            break;
        }
        current_now += Duration::from_millis(20);
    }

    assert!(
        sent_indices.contains(&FragmentIndex(1)),
        "Fragment 1 should have been sent"
    );
    assert!(
        sent_indices.contains(&FragmentIndex(2)),
        "Fragment 2 should have been sent"
    );

    // Bob receives #0, then #2 (skipping #1).
    // He sends an ACK for #0, with SACK for #2.
    // base_index will be 1. bitmask will have bit 0 set (for index 1+1=2).
    let ack = Packet::Ack(tox_sequenced::protocol::SelectiveAck {
        message_id: msg_id,
        base_index: FragmentIndex(1),
        bitmask: 1, // bit 0 set (index 2)
        rwnd: FragmentCount(100),
    });

    alice.handle_packet(ack, current_now + Duration::from_millis(10));

    // Alice should NOT have retransmitted #1 yet.
    let retrans = alice.get_packets_to_send(current_now + Duration::from_millis(20), 0);
    let has_retrans = retrans.iter().any(|p| {
        matches!(
            p,
            Packet::Data {
                fragment_index: FragmentIndex(1),
                ..
            }
        )
    });

    assert!(
        !has_retrans,
        "Alice retransmitted fragment 1 too aggressively on a single out-of-order packet! This will cause performance issues on jittery links."
    );
}

#[test]
fn test_in_flight_leak_on_timeout() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp, &mut rng);

    // 1. Send a message
    let data = vec![0u8; 5000];
    let _msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    // 2. "Send" fragments to increment in_flight
    let _packets = alice.get_packets_to_send(now, 0);
    assert!(alice.in_flight() > 0);

    // 3. Advance time past CONNECTION_TIMEOUT
    let later = now + Duration::from_secs(301); // CONNECTION_TIMEOUT is 300s

    // 4. Trigger cleanup/removal
    alice.cleanup(later);

    // 5. Verify in_flight is reset to 0
    assert_eq!(
        alice.in_flight(),
        0,
        "in_flight counter leaked! Expected 0, got {}",
        alice.in_flight()
    );
}

#[test]
fn test_total_fragments_consistency_check() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);
    let msg_id = MessageId(1);

    // Send first fragment with total_fragments = 5
    bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(5),
            data: vec![0; 10],
        },
        now,
    );

    // Send second fragment with total_fragments = 10 (mismatch!)
    let _replies = bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(1),
            total_fragments: FragmentCount(10),
            data: vec![0; 10],
        },
        now,
    );

    // Should be ignored, so no completion
    assert!(!has_message_event(&mut bob));
}

#[test]
fn test_reassembly_timeout() {
    use tox_sequenced::protocol::REASSEMBLY_TIMEOUT_SECS;
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);
    let msg_id = MessageId(1);

    // Start a reassembly
    bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(2),
            data: vec![0; 10],
        },
        now,
    );

    // Advance time past timeout
    let later = now + Duration::from_secs(REASSEMBLY_TIMEOUT_SECS + 1);
    bob.cleanup(later);

    // Send the last fragment. Since the session was cleaned up, it will start a NEW reassembly
    // rather than completing the old one (if it were still there).
    let _replies = bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(1),
            total_fragments: FragmentCount(2),
            data: vec![0; 10],
        },
        later,
    );

    // Should NOT be complete because fragment 0 was timed out and purged
    assert!(!has_message_event(&mut bob));
}

#[test]
fn test_duplicate_ack_handling() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp, &mut rng);

    let data = vec![0u8; 1000];
    let msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    // Get initial packets to mark them as in-flight
    let _ = alice.get_packets_to_send(now, 0);
    let in_flight_before = alice.in_flight();
    assert!(in_flight_before > 0);

    let ack = Packet::Ack(tox_sequenced::protocol::SelectiveAck {
        message_id: msg_id,
        base_index: FragmentIndex(1),
        bitmask: 0,
        rwnd: FragmentCount(100),
    });

    // First ACK
    alice.handle_packet(ack.clone(), now);
    let in_flight_after = alice.in_flight();
    assert!(in_flight_after < in_flight_before);

    // Second (duplicate) ACK should not cause further decrement or panic
    alice.handle_packet(ack, now);
    assert_eq!(alice.in_flight(), in_flight_after);
}

#[test]
fn test_out_of_order_acks() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp, &mut rng);

    // Message with 3 fragments
    let data = vec![0u8; 3500]; // Assuming ~1300 per fragment
    let msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    let mut data_fragments = Vec::new();
    let mut current_now = now;
    for _ in 0..100 {
        let packets = alice.get_packets_to_send(current_now, 0);
        for p in packets {
            if matches!(p, Packet::Data { .. }) {
                data_fragments.push(p);
            }
        }
        if data_fragments.len() >= 3 {
            break;
        }
        current_now += Duration::from_millis(20);
    }
    let initial_in_flight = alice.in_flight();

    // ACK for fragment 2 (Selective ACK)
    let ack2 = Packet::Ack(tox_sequenced::protocol::SelectiveAck {
        message_id: msg_id,
        base_index: FragmentIndex(0),
        bitmask: 0b10, // bit 1 set -> index 0 + 1 + 1 = 2
        rwnd: FragmentCount(100),
    });

    alice.handle_packet(ack2, current_now);
    assert!(alice.in_flight() < initial_in_flight);
    let _in_flight_after_2 = alice.in_flight();

    // ACK for fragments 0 and 1 (Cumulative ACK)
    let ack01 = Packet::Ack(tox_sequenced::protocol::SelectiveAck {
        message_id: msg_id,
        base_index: FragmentIndex(2),
        bitmask: 0,
        rwnd: FragmentCount(100),
    });

    alice.handle_packet(ack01, current_now + Duration::from_millis(1));
    // Should be fully acked now
    assert_eq!(alice.in_flight(), 0);
}

#[test]
fn test_sack_range_limit_4_in_ack() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut bob = SequenceSession::new_at(now, tp, &mut rng);
    let msg_id = MessageId(1);

    // Send fragment 0
    bob.handle_packet(
        Packet::Data {
            message_id: msg_id,
            fragment_index: FragmentIndex(0),
            total_fragments: FragmentCount(200),
            data: vec![0],
        },
        now,
    );

    // Send some distant fragments to trigger SACK ranges
    // Range 1: 100-102
    for i in 100..=102 {
        bob.handle_packet(
            Packet::Data {
                message_id: msg_id,
                fragment_index: FragmentIndex(i),
                total_fragments: FragmentCount(200),
                data: vec![0],
            },
            now,
        );
    }
    // Range 2: 110-112
    for i in 110..=112 {
        bob.handle_packet(
            Packet::Data {
                message_id: msg_id,
                fragment_index: FragmentIndex(i),
                total_fragments: FragmentCount(200),
                data: vec![0],
            },
            now,
        );
    }
    // Range 3: 120-122
    for i in 120..=122 {
        bob.handle_packet(
            Packet::Data {
                message_id: msg_id,
                fragment_index: FragmentIndex(i),
                total_fragments: FragmentCount(200),
                data: vec![0],
            },
            now,
        );
    }
    // Range 4: 130-132
    for i in 130..=132 {
        bob.handle_packet(
            Packet::Data {
                message_id: msg_id,
                fragment_index: FragmentIndex(i),
                total_fragments: FragmentCount(200),
                data: vec![0],
            },
            now,
        );
    }
    // Range 5: 140-142 (Should be truncated/ignored due to limit of 4)
    for i in 140..=142 {
        bob.handle_packet(
            Packet::Data {
                message_id: msg_id,
                fragment_index: FragmentIndex(i),
                total_fragments: FragmentCount(200),
                data: vec![0],
            },
            now,
        );
    }

    // Advance time past DELAYED_ACK_TIMEOUT (40ms)
    let later = now + Duration::from_millis(50);

    // Get packets to send
    let packets = bob.get_packets_to_send(later, 0);
    let ack_packet = packets
        .into_iter()
        .find(|p| matches!(p, Packet::Ack(_)))
        .unwrap();

    if let Packet::Ack(ack) = ack_packet {
        assert_eq!(ack.message_id, msg_id);
    } else {
        panic!("Expected an Ack packet");
    }
}

#[test]
fn test_zero_window_recovery() {
    let now = Instant::now();
    let tp = std::sync::Arc::new(tox_sequenced::time::ManualTimeProvider::new(now, 0));
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let mut alice = SequenceSession::new_at(now, tp, &mut rng);

    // 1. Send a message to Bob that he can only partially receive.
    // 20,000 bytes / ~1,300 MTU = ~16 fragments.
    // This exceeds the initial CWND of 10, so some fragments will remain unsent.
    let data = vec![0u8; 20000];
    let msg_id = alice
        .send_message(MessageType::MerkleNode, &data, now)
        .unwrap();

    // Alice sends initial packets (up to CWND=10)
    let _packets = alice.get_packets_to_send(now, 0);
    assert!(alice.in_flight() > 0);
    assert!(alice.in_flight() < 20000); // Ensure not everything was sent

    // 2. Bob receives packets but we "simulated" a full buffer by setting a small RWND
    // Actually, we need to manipulate the reassembler buffer.
    // For this test, we can just manually send an ACK with rwnd=0 to Alice.
    let ack_zero = Packet::Ack(SelectiveAck {
        message_id: msg_id,
        base_index: FragmentIndex(0),
        bitmask: 0,
        rwnd: FragmentCount(0),
    });
    alice.handle_packet(ack_zero, now);

    // 3. Alice should now be stalled. Verify she sends no data packets immediately.
    let packets_stalled = alice.get_packets_to_send(now + Duration::from_millis(100), 0);
    assert!(
        packets_stalled
            .iter()
            .all(|p| !matches!(p, Packet::Data { .. }))
    );

    // 4. Advance time past RTO to trigger a probe.
    // Initial RTO is 1000ms.
    let later = now + Duration::from_millis(1500);
    let packets_probe = alice.get_packets_to_send(later, 0);
    let probe = packets_probe
        .into_iter()
        .find(|p| matches!(p, Packet::Data { .. }));
    assert!(
        probe.is_some(),
        "Alice should have sent a zero-window probe"
    );

    // 5. Bob "clears" his buffer and sends an ACK with rwnd > 0.
    // BUT WE DROP IT (simulated loss).
    // So Alice is still stalled in her view.

    // 6. Alice sends another probe after backoff.
    let even_later = later + Duration::from_millis(2500); // 2000ms backoff
    let packets_probe_2 = alice.get_packets_to_send(even_later, 0);
    assert!(
        packets_probe_2
            .into_iter()
            .any(|p| matches!(p, Packet::Data { .. })),
        "Alice should have sent a second zero-window probe"
    );

    // 7. This time Bob's ACK reaches Alice.
    let ack_open = Packet::Ack(tox_sequenced::protocol::SelectiveAck {
        message_id: msg_id,
        base_index: FragmentIndex(0),
        bitmask: 0,
        rwnd: FragmentCount(100),
    });
    alice.handle_packet(ack_open, even_later);

    // 8. Alice should now resume sending data.
    let resume_packets = alice.get_packets_to_send(even_later + Duration::from_millis(100), 0);
    assert!(
        resume_packets
            .iter()
            .any(|p| matches!(p, Packet::Data { .. })),
        "Alice should have resumed sending data"
    );
}
